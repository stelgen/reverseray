package serverapp

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stelgen/reverseray/server/internal/mtproto"
	"github.com/stelgen/reverseray/server/internal/rrp"
)

// fakePhone is a minimal Go RRP/1 client used by e2e tests.
// It performs the real TLS+auth handshake, then answers OPENs by dialing
// through the provided hook (the "phone" does the actual egress).
// v0.9.3: фейк уважает flow-control как РЕАЛЬНЫЙ APK (Kotlin Semaphore):
// per-stream кредит из HELLO_OK.tunnel_window, пополнение по WINDOW от
// сервера. Без этого фейк льёт неограниченно и честный тест многоканальности
// упирается в анти-абьюз буфер сервера (capIn) — не репрезентативно.
type fakePhone struct {
	conn net.Conn
	// wrap — mtproto2-обёртка (v0.8): nil в обычном режиме RRP/1.
	wrap io.ReadWriteCloser

	wmu sync.Mutex
	mu  sync.Mutex
	dst map[uint32]net.Conn

	// flow-control (v0.9.3): не подтверждённые сервером байты на стрим.
	win int64
	fmu sync.Mutex
	out map[uint32]int64

	dial func(host string, port uint16) (net.Conn, error)
}

func rrpWrite1(w io.Writer, t uint8, payload []byte) error {
	return rrp.WriteFrame(w, t, 0, 0, payload)
}

func rrpWriteS(w io.Writer, t uint8, streamID uint32, payload []byte) error {
	return rrp.WriteFrame(w, t, 0, streamID, payload)
}

func makePhoneTLSConfig(caPinB64 string) (*tls.Config, error) {
	want, err := base64.RawURLEncoding.DecodeString(caPinB64)
	if err != nil || len(want) != sha256.Size {
		return nil, errors.New("bad CA pin in test")
	}
	cfg := &tls.Config{
		InsecureSkipVerify: true, // #nosec G402: тестовый fake-phone; подлинность сервера проверяется SPKI-pin в VerifyPeerCertificate // pin verified manually below
		NextProtos:         []string{"reverseray/1"},
		ServerName:         "reverseray.test",
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			// Pin the CA: the server presents [leaf, CA]; verify the last cert's
			// SPKI hash against the configured pin AND the chain link.
			if len(rawCerts) < 2 {
				return errors.New("expected leaf+CA chain")
			}
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			ca, err := x509.ParseCertificate(rawCerts[len(rawCerts)-1])
			if err != nil {
				return err
			}
			if err := leaf.CheckSignatureFrom(ca); err != nil {
				return errors.New("leaf not signed by presented CA")
			}
			sum := sha256.Sum256(ca.RawSubjectPublicKeyInfo)
			if !bytes.Equal(sum[:], want) {
				return errors.New("CA pin mismatch")
			}
			return nil
		},
	}
	return cfg, nil
}

// DialPhone connects over TLS with CA-SPKI pinning and handshakes RRP/1.
func DialPhone(t *testing.T, serverAddr, caPinB64, token, device string,
	dial func(host string, port uint16) (net.Conn, error)) (*fakePhone, string, error) {
	return DialPhoneProto(t, serverAddr, caPinB64, token, device, "", dial)
}

// DialPhoneProto — как DialPhone, но с согласованием протокола (v0.8:
// "mtproto2" — после READY DH-апгрейд; весь обмен дальше в MTProto-конверте).
func DialPhoneProto(t *testing.T, serverAddr, caPinB64, token, device, proto string,
	dial func(host string, port uint16) (net.Conn, error)) (*fakePhone, string, error) {

	t.Helper()
	cfg, err := makePhoneTLSConfig(caPinB64)
	if err != nil {
		return nil, "", err
	}
	raw, err := net.Dial("tcp", serverAddr)
	if err != nil {
		return nil, "", err
	}
	conn := tls.Client(raw, cfg)
	if err := conn.Handshake(); err != nil {
		raw.Close()
		return nil, "", err
	}
	return DialPhoneOnProto(t, conn, token, device, proto, dial)
}

// DialPhoneOn handshakes RRP/1 over a pre-built transport (TLS, WS-over-TLS,
// net.Pipe — что угодно). Используется транспортными тестами (ws_test).
func DialPhoneOn(t *testing.T, conn net.Conn, token, device string,
	dial func(host string, port uint16) (net.Conn, error)) (*fakePhone, string, error) {
	return DialPhoneOnProto(t, conn, token, device, "", dial)
}

// DialPhoneOnProto — как DialPhoneOn, но с согласованием протокола
// (v0.8: "mtproto2" — после READY выполняет DH-апгрейд, весь дальнейший
// обмен идёт в MTProto-конверте).
func DialPhoneOnProto(t *testing.T, conn net.Conn, token, device, proto string,
	dial func(host string, port uint16) (net.Conn, error)) (*fakePhone, string, error) {

	t.Helper()
	p := &fakePhone{conn: conn, dst: make(map[uint32]net.Conn), dial: dial}
	sid, win, err := clientHandshake(p.conn, token, device, proto)
	if err != nil {
		conn.Close()
		return nil, "", err
	}
	p.win = int64(win)
	p.out = make(map[uint32]int64)
	if proto == "mtproto2" {
		p.wrap, err = mtproto.UpgradeClient(conn, sid, nil)
		if err != nil {
			conn.Close()
			return nil, "", err
		}
	}
	go p.loop()
	return p, sid, nil
}

func clientHandshake(conn net.Conn, token, device, proto string) (string, uint32, error) {
	hb, _ := json.Marshal(&rrp.Hello{Agent: "fake-phone", Ver: "1.0", Device: device, MaxStreams: 64, Proto: rrp.FlexString(proto)})
	if err := rrpWrite1(conn, rrp.TypeHello, hb); err != nil {
		return "", 0, err
	}
	f, err := rrp.ReadFrame(conn)
	if err != nil {
		return "", 0, err
	}
	if f.Type != rrp.TypeHelloOK {
		return "", 0, errors.New("expected HELLO_OK")
	}
	var hok rrp.HelloOK
	if err := json.Unmarshal(f.Payload, &hok); err != nil {
		return "", 0, err
	}
	code := rrp.AuthCode(token, hok.Nonce, hok.SessionID)
	ab, _ := json.Marshal(&rrp.Auth{Mode: "token-hmac", HMAC: code})
	if err := rrpWrite1(conn, rrp.TypeAuth, ab); err != nil {
		return "", 0, err
	}
	f, err = rrp.ReadFrame(conn)
	if err != nil {
		return "", 0, err
	}
	if f.Type != rrp.TypeReady {
		_, msg := rrp.DecodeError(f.Payload)
		return "", 0, errors.New("handshake rejected: " + msg)
	}
	// Кредит — из READY (сервер может уточнить после HELLO_OK).
	win := hok.TunnelWindow
	var ready rrp.Ready
	_ = json.Unmarshal(f.Payload, &ready)
	if ready.TunnelWindow > 0 {
		win = ready.TunnelWindow
	}
	return hok.SessionID, win, nil
}

// WritePing отправляет PING-кадр от лица телефона (для flood-тестов).
func (p *fakePhone) WritePing(nonce []byte) error {
	return p.write(rrp.TypePing, 0, nonce)
}

func (p *fakePhone) write(t uint8, streamID uint32, payload []byte) error {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	if p.wrap != nil {
		return rrpWriteS(p.wrap, t, streamID, payload)
	}
	return rrpWriteS(p.conn, t, streamID, payload)
}

func (p *fakePhone) loop() {
	// keyrace-тесты конструируют fakePhone литералом — лениво создаём карту.
	p.fmu.Lock()
	if p.out == nil {
		p.out = make(map[uint32]int64)
	}
	p.fmu.Unlock()
	defer func() {
		p.mu.Lock()
		for _, c := range p.dst {
			c.Close()
		}
		p.mu.Unlock()
		p.conn.Close()
	}()
	for {
		src := io.Reader(p.conn)
		if p.wrap != nil {
			src = p.wrap
		}
		f, err := rrp.ReadFrame(src)
		if err != nil {
			return
		}
		switch f.Type {
		case rrp.TypeOpen:
			atyp, addr, port, derr2 := rrp.DecodeOpen(f.Payload)
			if derr2 != nil {
				p.write(rrp.TypeOpenOK, f.StreamID, []byte{1})
				continue
			}
			host := string(addr)
			if atyp == rrp.ATYPIPv4 {
				host = net.IP(addr).String()
			} else if atyp == rrp.ATYPIPv6 {
				host = net.IP(addr).String()
			}
			dst, derr := p.dial(host, port)
			if derr != nil {
				p.write(rrp.TypeOpenOK, f.StreamID, []byte{1})
				continue
			}
			p.write(rrp.TypeOpenOK, f.StreamID, []byte{0})
			p.mu.Lock()
			p.dst[f.StreamID] = dst
			p.mu.Unlock()
			go p.pumpToPhone(f.StreamID, dst)
		case rrp.TypeData:
			p.mu.Lock()
			dst := p.dst[f.StreamID]
			p.mu.Unlock()
			if dst != nil && len(f.Payload) > 0 {
				if _, err := dst.Write(f.Payload); err != nil {
					p.write(rrp.TypeClose, f.StreamID, []byte{1})
				}
			}
		case rrp.TypeClose:
			p.mu.Lock()
			dst := p.dst[f.StreamID]
			delete(p.dst, f.StreamID)
			p.mu.Unlock()
			if dst != nil {
				dst.Close()
			}
		case rrp.TypeWindow:
			// v0.9.3: сервер подтвердил потребление — возвращаем кредит.
			inc, derr := rrp.DecodeWindow(f.Payload)
			if derr == nil {
				p.fmu.Lock()
				if p.out != nil {
					p.out[f.StreamID] -= int64(inc)
				}
				p.fmu.Unlock()
			}
		case rrp.TypePing:
			p.write(rrp.TypePong, 0, f.Payload)
		}
	}
}

func (p *fakePhone) pumpToPhone(id uint32, dst net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		n, err := dst.Read(buf)
		if n > 0 {
			if werr := p.writePaced(id, buf[:n]); werr != nil {
				dst.Close()
				return
			}
		}
		if err != nil {
			p.write(rrp.TypeClose, id, []byte{0})
			p.mu.Lock()
			delete(p.dst, id)
			p.mu.Unlock()
			return
		}
	}
}

// writePaced отправляет DATA с уважением к flow-control (как Kotlin-клиент):
// ждём, пока не подтверждённые байты стрима не влезут в кредит win.
// win == 0 — старое поведение без пейсинга (транспортные тесты net.Pipe).
func (p *fakePhone) writePaced(id uint32, b []byte) error {
	if p.win <= 0 {
		return p.write(rrp.TypeData, id, b)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		p.fmu.Lock()
		unacked := p.out[id]
		p.fmu.Unlock()
		if unacked+int64(len(b)) <= p.win {
			if err := p.write(rrp.TypeData, id, b); err != nil {
				return err
			}
			p.fmu.Lock()
			p.out[id] += int64(len(b))
			p.fmu.Unlock()
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("fake-phone: flow-control wait timeout")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (p *fakePhone) Close() {
	p.conn.Close()
}

var _ = bytes.Equal // reserved
