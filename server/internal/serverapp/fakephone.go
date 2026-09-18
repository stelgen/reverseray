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

	"github.com/stelgen/reverseray/server/internal/rrp"
)

// fakePhone is a minimal Go RRP/1 client used by e2e tests.
// It performs the real TLS+auth handshake, then answers OPENs by dialing
// through the provided hook (the "phone" does the actual egress).
type fakePhone struct {
	conn net.Conn

	wmu sync.Mutex
	mu  sync.Mutex
	dst map[uint32]net.Conn

	dial func(host string, port uint16) (net.Conn, error)
}

func rrpWrite1(w io.Writer, t uint8, payload []byte) error {
	return rrp.WriteFrame(w, t, 0, 0, payload)
}

func rrpWriteS(w io.Writer, t uint8, streamID uint32, payload []byte) error {
	return rrp.WriteFrame(w, t, 0, streamID, payload)
}

// DialPhone connects over TLS with CA-SPKI pinning and handshakes RRP/1.
func DialPhone(t *testing.T, serverAddr, caPinB64, token, device string,
	dial func(host string, port uint16) (net.Conn, error)) (*fakePhone, string, error) {

	t.Helper()
	want, err := base64.RawURLEncoding.DecodeString(caPinB64)
	if err != nil || len(want) != sha256.Size {
		return nil, "", errors.New("bad CA pin in test")
	}
	cfg := &tls.Config{
		InsecureSkipVerify: true, // pin verified manually below
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
	raw, err := net.Dial("tcp", serverAddr)
	if err != nil {
		return nil, "", err
	}
	conn := tls.Client(raw, cfg)
	if err := conn.Handshake(); err != nil {
		raw.Close()
		return nil, "", err
	}
	p := &fakePhone{conn: conn, dst: make(map[uint32]net.Conn), dial: dial}
	sid, err := clientHandshake(p.conn, token, device)
	if err != nil {
		conn.Close()
		return nil, "", err
	}
	go p.loop()
	return p, sid, nil
}

func clientHandshake(conn net.Conn, token, device string) (string, error) {
	hb, _ := json.Marshal(&rrp.Hello{Agent: "fake-phone", Ver: "1.0", Device: device, MaxStreams: 64})
	if err := rrpWrite1(conn, rrp.TypeHello, hb); err != nil {
		return "", err
	}
	f, err := rrp.ReadFrame(conn)
	if err != nil {
		return "", err
	}
	if f.Type != rrp.TypeHelloOK {
		return "", errors.New("expected HELLO_OK")
	}
	var hok rrp.HelloOK
	if err := json.Unmarshal(f.Payload, &hok); err != nil {
		return "", err
	}
	code := rrp.AuthCode(token, hok.Nonce, hok.SessionID)
	ab, _ := json.Marshal(&rrp.Auth{Mode: "token-hmac", HMAC: code})
	if err := rrpWrite1(conn, rrp.TypeAuth, ab); err != nil {
		return "", err
	}
	f, err = rrp.ReadFrame(conn)
	if err != nil {
		return "", err
	}
	if f.Type != rrp.TypeReady {
		_, msg := rrp.DecodeError(f.Payload)
		return "", errors.New("handshake rejected: " + msg)
	}
	return hok.SessionID, nil
}

func (p *fakePhone) write(t uint8, streamID uint32, payload []byte) error {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	return rrpWriteS(p.conn, t, streamID, payload)
}

func (p *fakePhone) loop() {
	defer func() {
		p.mu.Lock()
		for _, c := range p.dst {
			c.Close()
		}
		p.mu.Unlock()
		p.conn.Close()
	}()
	for {
		f, err := rrp.ReadFrame(p.conn)
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
			if werr := p.write(rrp.TypeData, id, buf[:n]); werr != nil {
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

func (p *fakePhone) Close() {
	p.conn.Close()
}

var _ = bytes.Equal // reserved
