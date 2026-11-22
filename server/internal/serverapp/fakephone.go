package serverapp

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stelgen/reverseray/server/internal/bt"
	"github.com/stelgen/reverseray/server/internal/mtproto"
	"github.com/stelgen/reverseray/server/internal/rrp"
	"github.com/stelgen/reverseray/server/internal/wg"
)

// debugf — диагностика в stderr под RR_DEBUG_LOG (тестовый хелпер фейка).
func debugf(format string, args ...any) {
	if os.Getenv("RR_DEBUG_LOG") != "" {
		fmt.Fprintf(os.Stderr, "FAKE: "+format+"\n", args...)
	}
}

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

	// v1.8.6 e2e-матрица протоколов: envMu охраняет wrap/env — свитч меняет
	// их из loop-горутины, pump'ы читают при каждой записи. env — WG/BT
	// конверт payload-кадров; wrap — MT-обёртка (семантика идентична:
	// контроль-кадры насквозь, DATA/UDP_DATA запечатаны).
	envMu sync.RWMutex

	// wm сериализует записи в коннект (loop-p.write против pump-writePaced):
	// rrpWriteS пишет кадр двумя Write-вызовами (header+payload) — без
	// блокировки конкурентные записи чередуются и корраптят поток (WS).
	wm  sync.Mutex
	env envelope

	// состояние mid-session свитча (v1.8.6): ack и результат установки
	// нового конверта. Поля создаются в dialPhoneOnCapsParked; литеральные
	// конструкторы (keyrace) получают nil — select/default страхует.
	sid   string
	token string

	wmu sync.Mutex
	mu  sync.Mutex
	dst map[uint32]net.Conn

	// v1.3.0 «буфер трафика»: телефон поддерживает резюме стримов
	// (HELLO caps stream-resume): хранит токены, паркует сокеты при потере
	// транспорта и привязывает их заново по OPEN_RESUME.
	resume bool
	tokens map[[16]byte]uint32
	parked map[[16]byte]net.Conn
	// dead: транспорт умер — pump'ы обязаны выйти БЕЗ закрытия сокетов
	// (читают с коротким дедлайном, чтобы увидеть флаг).
	dead atomic.Bool

	// v1.9.9 self-heal: обмен ключами в полёте (async, как реальный телефон:
	// KEY_REQ → INIT уходит сразу, loop продолжает диспетчить кадры — DATA
	// старым конвертом ходят до RESP; RESP → setCrypto, pend = nil).
	// Поле живёт только в loop-горутине — гонок нет.
	pend *pendHs

	loopErr  atomic.Value // диагностика смерти loop-горутины (тесты)
	lastSeen atomic.Value // трассировка: последний кадр, дошедший до loop

	// flow-control (v0.9.3): не подтверждённые сервером байты на стрим.
	win int64
	fmu sync.Mutex
	out map[uint32]int64

	dial func(host string, port uint16) (net.Conn, error)
}

// envelope — активный конверт payload'ов DATA/UDP_DATA (v1.8.6, e2e-матрица
// протоколов): WG transport-пакеты и MSE/PE piece-сообщения. Контроль-кадры
// всегда идут насквозь (сервер так же шифрует только payload-кадры).
type envelope interface {
	seal(payload []byte) ([]byte, error)
	open(payload []byte) ([]byte, error)
}

type wgEnvelope struct{ tr *wg.Transport }

func (e *wgEnvelope) seal(b []byte) ([]byte, error) { return e.tr.Seal(b) }
func (e *wgEnvelope) open(b []byte) ([]byte, error) { return e.tr.Open(b) }

type btEnvelope struct{ tr *bt.Transport }

func (e *btEnvelope) seal(b []byte) ([]byte, error) { return e.tr.Seal(b) }
func (e *btEnvelope) open(b []byte) ([]byte, error) { return e.tr.Open(b) }

func (p *fakePhone) currentEnv() envelope {
	p.envMu.RLock()
	defer p.envMu.RUnlock()
	return p.env
}

func (p *fakePhone) setCrypto(w io.ReadWriteCloser, e envelope) {
	p.envMu.Lock()
	p.wrap = w
	p.env = e
	p.envMu.Unlock()
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

// DialPhoneResume — как DialPhone, но телефон объявляет cap «stream-resume»:
// сервер выдаёт RESUME_TOKEN, а при потере связи телефон паркует сокеты.
func DialPhoneResume(t *testing.T, serverAddr, caPinB64, token, device string,
	dial func(host string, port uint16) (net.Conn, error)) (*fakePhone, string, error) {
	return dialPhoneCaps(t, serverAddr, caPinB64, token, device, "", dial, true)
}

// DialPhoneResumeWith — как DialPhoneResume, но паркинг сокетов загружается
// ДО хендшейка (сервер шлёт OPEN_RESUME сразу после Attach — реальный телефон
// держит паркинг в том же экземпляре клиента, тест переносит их заранее).
func DialPhoneResumeWith(t *testing.T, serverAddr, caPinB64, token, device string,
	dial func(host string, port uint16) (net.Conn, error),
	parked map[[16]byte]net.Conn) (*fakePhone, string, error) {

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
	if parked == nil {
		parked = make(map[[16]byte]net.Conn)
	}
	return dialPhoneOnCapsParked(t, conn, token, device, "", dial, true, parked)
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
	return dialPhoneCaps(t, serverAddr, caPinB64, token, device, proto, dial, false)
}

func dialPhoneCaps(t *testing.T, serverAddr, caPinB64, token, device, proto string,
	dial func(host string, port uint16) (net.Conn, error), resume bool) (*fakePhone, string, error) {

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
	return dialPhoneOnCaps(t, conn, token, device, proto, dial, resume)
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
	return dialPhoneOnCaps(t, conn, token, device, proto, dial, false)
}

func dialPhoneOnCaps(t *testing.T, conn net.Conn, token, device, proto string,
	dial func(host string, port uint16) (net.Conn, error), resume bool) (*fakePhone, string, error) {
	return dialPhoneOnCapsParked(t, conn, token, device, proto, dial, resume, nil)
}

func dialPhoneOnCapsParked(t *testing.T, conn net.Conn, token, device, proto string,
	dial func(host string, port uint16) (net.Conn, error), resume bool,
	parked map[[16]byte]net.Conn) (*fakePhone, string, error) {

	t.Helper()
	p := &fakePhone{conn: conn, dst: make(map[uint32]net.Conn), dial: dial, resume: resume}
	if resume {
		p.tokens = make(map[[16]byte]uint32)
		if parked != nil {
			p.parked = parked
		} else {
			p.parked = make(map[[16]byte]net.Conn)
		}
	}
	sid, win, err := clientHandshake(p.conn, token, device, proto, p.capsList())
	if err != nil {
		conn.Close()
		return nil, "", err
	}
	p.win = int64(win)
	p.out = make(map[uint32]int64)
	p.sid = sid
	p.token = token
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

func (p *fakePhone) capsList() []string {
	if p.resume {
		return []string{"stream-resume"}
	}
	return nil
}

func clientHandshake(conn net.Conn, token, device, proto string, caps []string) (string, uint32, error) {
	hb, _ := json.Marshal(&rrp.Hello{Agent: "fake-phone", Ver: "1.0", Device: device, MaxStreams: 64, Proto: rrp.FlexString(proto), Caps: caps})
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
	debugf("FAKE out type=0x%02x sid=%d len=%d", t, streamID, len(payload))
	p.wm.Lock()
	defer p.wm.Unlock()
	p.wmu.Lock()
	defer p.wmu.Unlock()
	// MT-обёртка (wrap) сама запечатывает DATA/UDP_DATA — кадр идёт целиком.
	p.envMu.RLock()
	wrap := p.wrap
	p.envMu.RUnlock()
	if wrap != nil {
		return rrpWriteS(wrap, t, streamID, payload)
	}
	// v1.8.6: активный WG/BT-конверт — payload-кадры запечатываются.
	if t == rrp.TypeData || t == rrp.TypeUdpData {
		if env := p.currentEnv(); env != nil && len(payload) > 0 {
			sealed, err := env.seal(payload)
			if err != nil {
				return err
			}
			payload = sealed
		}
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
		if p.resume {
			// Паркинг: сокеты таргетов переживают потерю связи (TCP end-to-end).
			for tok, id := range p.tokens {
				if c, ok := p.dst[id]; ok && c != nil {
					p.parked[tok] = c
					delete(p.dst, id)
				}
			}
			for _, c := range p.dst {
				c.Close()
			}
		} else {
			for _, c := range p.dst {
				c.Close()
			}
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
			if p.resume {
				p.dead.Store(true)
			}
			p.loopErr.Store(fmt.Sprintf("loop read: %v", err))
			return
		}
		p.lastSeen.Store(fmt.Sprintf("0x%02x sid=%d len=%d", f.Type, f.StreamID, len(f.Payload)))
		debugf("FAKE frame type=0x%02x sid=%d len=%d", f.Type, f.StreamID, len(f.Payload))
		// v1.9.9: первичный обмен ключами в полёте (pend != nil, env == nil):
		// DATA/UDP_DATA уйдут незапечатанными — дроп; OPEN отклоняем err=1
		// (mixed-релей повторит — waitEchoOK-ритриты в тестах). После RESP
		// pend=nil, env=новый — кадры идут как обычно (ре-кей: старым конвертом).
		if p.pend != nil && p.currentEnv() == nil {
			// Глотаем ТОЛЬКО payload-кадры (незапечатанные DATA нельзя); прочие
			// (BT_RESP/WG_RESP/PING...) идут дальше в диспетчер!
			switch f.Type {
			case rrp.TypeOpen:
				_ = p.write(rrp.TypeOpenOK, f.StreamID, []byte{1})
				continue
			case rrp.TypeData, rrp.TypeUdpData:
				continue
			}
		}
		// v1.8.6: активный WG/BT-конверт — расшифровка payload-кадров.
		if p.wrap == nil {
			if env := p.currentEnv(); env != nil &&
				(f.Type == rrp.TypeData || f.Type == rrp.TypeUdpData) && len(f.Payload) > 0 {
				plain, oerr := env.open(f.Payload)
				if oerr != nil {
					debugf("FAKE env.open fail type=%d len=%d err=%v", f.Type, len(f.Payload), oerr)
					// v1.9.9: кадр не расшифровался активным конвертом — НЕ убиваем loop
					// (ре-кей в полёте: BT_RESP уже в пути и переключит конверт; сервер,
					// в свою очередь, дропает такие кадры в noise-окно). Голый return
					// здесь ронял фейк на echo-ответе, запечатанном уже новым конвертом.
					continue
				}
				f.Payload = plain
			}
		}
		switch f.Type {
		case rrp.TypeOpen:
			atyp, addr, port, derr2 := rrp.DecodeOpen(f.Payload)
			if derr2 != nil {
				_ = p.write(rrp.TypeOpenOK, f.StreamID, []byte{1})
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
				_ = p.write(rrp.TypeOpenOK, f.StreamID, []byte{1})
				continue
			}
			_ = p.write(rrp.TypeOpenOK, f.StreamID, []byte{0})
			p.mu.Lock()
			p.dst[f.StreamID] = dst
			p.mu.Unlock()
			go p.pumpToPhone(f.StreamID, dst)
		case rrp.TypeResumeToken:
			if !p.resume || len(f.Payload) != 16 {
				continue
			}
			var tok [16]byte
			copy(tok[:], f.Payload)
			p.mu.Lock()
			p.tokens[tok] = f.StreamID
			p.mu.Unlock()
		case rrp.TypeOpenResume:
			if !p.resume || len(f.Payload) != 16 {
				continue
			}
			var tok [16]byte
			copy(tok[:], f.Payload)
			p.mu.Lock()
			conn2, ok := p.parked[tok]
			if ok {
				delete(p.parked, tok)
				p.dst[f.StreamID] = conn2
			}
			p.mu.Unlock()
			if ok {
				_ = p.write(rrp.TypeOpenOK, f.StreamID, []byte{0})
				go p.pumpToPhone(f.StreamID, conn2)
			} else {
				_ = p.write(rrp.TypeOpenOK, f.StreamID, []byte{5})
			}
		case rrp.TypeData:
			p.mu.Lock()
			dst := p.dst[f.StreamID]
			p.mu.Unlock()
			if dst != nil && len(f.Payload) > 0 {
				if _, err := dst.Write(f.Payload); err != nil {
					// code 0: цель недоступна — обычное закрытие стрима.
					// code 1 зарезервирован за «транспорт умер» (v1.3.0:
					// сервер запаркует сокет и переоткроет фантомный стрим).
					_ = p.write(rrp.TypeClose, f.StreamID, []byte{0})
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
			_ = p.write(rrp.TypePong, 0, f.Payload)
		case rrp.TypeBtResp:
			if err := p.btFinish(f); err != nil {
				p.loopErr.Store("key exchange: bt resp: " + err.Error())
				return
			}
		case rrp.TypeWgResp:
			if err := p.wgFinish(f); err != nil {
				p.loopErr.Store("key exchange: wg resp: " + err.Error())
				return
			}
		case rrp.TypeKeyReq:
			// v1.9.3: обмен ключами протокола — единственная механика согласования
			// конверта (первичный хендшейк при подключении; бесшовные свитчи
			// 0x2C удалены). v1.9.9: плюс ре-кей self-heal в живой сессии.
			// Для mtproto2 KEY_REQ потребляет UpgradeClient до
			// старта loop — сюда доходит только WG/BT.
			p.handleKeyReq(f)
		}
	}
}

func (p *fakePhone) pumpToPhone(id uint32, dst net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		// Короткий дедлайн чтения: pump обязан периодически просыпаться и
		// проверять dead-флаг, чтобы при потере транспорта ОСВОБОДИТЬ сокет
		// для паркинга (два читателя на резюмированном сокете недопустимы).
		_ = dst.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, err := dst.Read(buf)
		if n > 0 {
			if werr := p.writePaced(id, buf[:n]); werr != nil {
				// Смерть транспорта НЕ закрывает сокет таргета — он паркуется
				// (loop-defer переносит его в parked) и привязывается заново
				// по OPEN_RESUME. Закрытие = потеря TCP-сессии сайта.
				if !p.resume {
					dst.Close()
				}
				return
			}
		}
		if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					// Таймаут чтения таргета ≠ смерть стрима: проснулись только чтобы
					// проверить dead-флаг (паркинг). v1.9.9: раньше при !resume таймаут
					// падал в закрытие стрима — медленный раунд-трип после ре-кея
					// (>250ms) убивал каждый echo-ретрай (TypeClose → socks EOF).
					if p.dead.Load() {
						return // паркинг: выходим БЕЗ закрытия сокета
					}
					continue
				}
				// Сокет таргета закрылся по-настоящему (сайт/сеть) —
				// штатное закрытие стрима, сокет уже мёртв.
			_ = p.write(rrp.TypeClose, id, []byte{0})
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
	defer func() { /* debug hook */ }()
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
		debugf("FAKE writePaced WAIT sid=%d unacked=%d win=%d", id, p.out[id], p.win)
		time.Sleep(2 * time.Millisecond)
	}
}

// TokenCount — race-safe доступ для тестов.
func (p *fakePhone) TokenCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.tokens)
}

// ParkedConns возвращает припаркованные сокеты (для переноса на новый
// экземпляр фейка при переподключении в тестах резюме).
func (p *fakePhone) ParkedConns() map[[16]byte]net.Conn {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[[16]byte]net.Conn, len(p.parked))
	maps.Copy(out, p.parked)
	return out
}

// readExpect — чтение кадров до ожидаемого типа (v1.8.6): во время обмена
// ключами свитча по каналу идут и «мирские» контрольные кадры (CLOSE/
// WINDOW/PING завершающихся стримов) — их пропускаем, на Ping отвечаем.
func (p *fakePhone) readExpect(want uint8) (*rrp.Frame, error) {
	for {
		f, err := rrp.ReadFrame(p.conn)
		if err != nil {
			return nil, err
		}
		if f.Type == want {
			return f, nil
		}
		switch f.Type {
		case rrp.TypePing:
			_ = p.write(rrp.TypePong, 0, f.Payload)
		case rrp.TypeClose, rrp.TypeWindow, rrp.TypeOpenOK,
			rrp.TypePong, rrp.TypeOpenResume, rrp.TypeResumeToken, rrp.TypeError:
			// фоновые контрольные кадры — не наша цель
		default:
			return nil, fmt.Errorf("switch: ждали 0x%02x, получили 0x%02x", want, f.Type)
		}
	}
}

// pendHs — состояние async-обмена ключами bt/wg (v1.9.9).
type pendHs struct {
	bt  *bt.ClientHandshake
	wg  *wg.ClientHandshake
	psk [wg.KeySize]byte
}

// handleKeyReq — обмен ключами протокола (выполняется В loop-горутине —
// единственном читателе conn). v1.9.9: bt/wg — асинхронно (INIT уходит,
// loop НЕ блокируется — DATA старым конвертом ходят до RESP, как у
// реального телефона); mtproto2 — синхронно (ответ серверу не нужен).
// Провал — в loopErr (тест увидит смерть цикла), сессию добьёт
// серверный key-deadline.
func (p *fakePhone) handleKeyReq(f *rrp.Frame) {
	var probe struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(f.Payload, &probe); err != nil {
		p.loopErr.Store("key exchange: KEY_REQ не JSON: " + err.Error())
		return
	}
	switch probe.Kind {
	case "bittorrent":
		ch, err := p.btBegin(f.Payload)
		if err != nil {
			p.loopErr.Store("key exchange: " + err.Error())
			return
		}
		p.pend = &pendHs{bt: ch}
	case "wireguard":
		ch, psk, err := p.wgBegin(f.Payload)
		if err != nil {
			p.loopErr.Store("key exchange: " + err.Error())
			return
		}
		p.pend = &pendHs{wg: ch, psk: *psk}
	default: // mtproto2 (kind отсутствует; p/g/g_a)
		w, err := mtproto.ClientExchange(p.conn, f, p.sid)
		if err != nil {
			p.loopErr.Store("key exchange: " + err.Error())
			return
		}
		p.setCrypto(w, nil)
	}
}

// btBegin — канонный MSE packet1||packet3 → BT_INIT (реализация ниже,
// рядом с btFinish — обе вызываются только из loop-горутины).

// wgBegin — канонный WG msg1 → WG_INIT (без чтения ответа; ответ читает
// loop — TypeWgResp). PSK возвращается вызывающему (нужен на финише).
func (p *fakePhone) wgBegin(req []byte) (*wg.ClientHandshake, *[wg.KeySize]byte, error) {
	var kw struct {
		SPub string `json:"spub"`
	}
	if err := json.Unmarshal(req, &kw); err != nil {
		return nil, nil, err
	}
	raw, err := base64.RawURLEncoding.DecodeString(kw.SPub)
	if err != nil || len(raw) != wg.KeySize {
		return nil, nil, fmt.Errorf("wg: bad spub (len=%d)", len(raw))
	}
	var spub [wg.KeySize]byte
	copy(spub[:], raw)
	psk := wg.TokenPSK(p.token)
	msg1, ch, err := wg.NewClientHandshake(&spub, &psk)
	if err != nil {
		return nil, nil, err
	}
	if err := rrpWriteS(p.conn, rrp.TypeWgInit, 0, msg1); err != nil {
		return nil, nil, err
	}
	return ch, &psk, nil
}

// wgFinish — WG msg2 → ConsumeResponse → активируем конверт.
// Вызывается только из loop-горутины.
func (p *fakePhone) wgFinish(f *rrp.Frame) error {
	if p.pend == nil || p.pend.wg == nil {
		return nil // не наш WG_RESP — игнор (анти-мусор, как сервер)
	}
	if err := p.pend.wg.ConsumeResponse(f.Payload, &p.pend.psk); err != nil {
		return err
	}
	p.setCrypto(nil, &wgEnvelope{tr: wg.NewTransport(true, p.pend.wg)})
	p.pend = nil
	return nil
}

// btBegin — канонный MSE packet1||packet3 → BT_INIT (без чтения ответа; ответ
// читает loop — TypeBtResp).
func (p *fakePhone) btBegin(req []byte) (*bt.ClientHandshake, error) {
	var kb struct {
		YB string `json:"yb"`
	}
	if err := json.Unmarshal(req, &kb); err != nil {
		return nil, err
	}
	yb, err := base64.RawURLEncoding.DecodeString(kb.YB)
	if err != nil || len(yb) != bt.KeySize {
		return nil, fmt.Errorf("bt: bad yb (len=%d)", len(yb))
	}
	skey := bt.TokenSKEY(p.token)
	pkt1, ch, err := bt.NewClientInit(skey, nil)
	if err != nil {
		return nil, err
	}
	pkt3, err := ch.BuildPacket3(yb)
	if err != nil {
		return nil, err
	}
	if err := rrpWriteS(p.conn, rrp.TypeBtInit, 0, ch.Init(pkt3, pkt1)); err != nil {
		return nil, err
	}
	return ch, nil
}

// btFinish — packet4 → BT_RESP: ConsumeResponse → активируем конверт.
// Вызывается только из loop-горутины.
func (p *fakePhone) btFinish(f *rrp.Frame) error {
	if p.pend == nil || p.pend.bt == nil {
		return nil // не наш BT_RESP — игнор (анти-мусор, как сервер)
	}
	if err := p.pend.bt.ConsumeResponse(f.Payload); err != nil {
		return err
	}
	p.setCrypto(nil, &btEnvelope{tr: p.pend.bt.Transport()})
	debugf("FAKE btFinish OK: конверт переключён")
	p.pend = nil
	return nil
}

func (p *fakePhone) Close() {
	p.conn.Close()
}

var _ = bytes.Equal // reserved
