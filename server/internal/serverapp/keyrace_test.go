package serverapp

// keyrace_test.go — v0.9.2: главные регрессии переключения/согласования
// протоколов.
//
// 1. TestMTProto2ProbeKeyRespRace — воспроизводит прод-баг 81.25.59.194:
//    клиент после READY отправляет PROBE-валидацию ДО ответа на KEY_REQ.
//    Старая серверная схема (UpgradeServer в рукопожатии) читала кадры
//    конкурентно с Session.Run: PROBE съедался апгрейдом → «ждали KEY_RESP,
//    получили 0x23» → reject «protocol error» → на APK «PROBE not answered»
//    + «server ERROR 2». Новая схема: KEY_REQ уходит из сессии, единственный
//    читатель — Run; PROBE и KEY_RESP обрабатываются в handle().
// 2. TestNegotiateExecutableOnly — новый протокол из манифеста виден
//    в реестре (реклама), но согласуется только если исполняется кодом.

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stelgen/reverseray/server/internal/mtproto"
	"github.com/stelgen/reverseray/server/internal/rrp"
)

// TestMTProto2ProbeKeyRespRace — PROBE сразу после READY, до KEY_RESP.
func TestMTProto2ProbeKeyRespRace(t *testing.T) {
	app, cfg, token := startTestServer(t)
	_ = app

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_, _ = io.Copy(c, c)
				_ = c.Close()
			}(c)
		}
	}()
	echoAddr := echoLn.Addr().String()

	raw, err := net.Dial("tcp", cfg.Listen.Tunnels)
	if err != nil {
		t.Fatal(err)
	}
	tlsC, tlsCfgErr := makePhoneTLSConfig(app.CAPin())
	if tlsCfgErr != nil {
		t.Fatal(tlsCfgErr)
	}
	conn := tlsClientWrap(t, raw, tlsC)
	sid, err := clientHandshake(conn, token, "phone-1", "mtproto2")
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}

	// ГОНКА v0.8: PROBE уходит СРАЗУ после READY — раньше KEY_RESP.
	probeJSON, _ := json.Marshal(map[string]any{"target": echoAddr, "timeout_ms": 3000})
	if err := rrpWrite1(conn, rrp.TypeProbe, probeJSON); err != nil {
		t.Fatalf("probe send: %v", err)
	}

	// KEY_REQ должен прийти первым на проводе (ушёл при старте сессии),
	// апгрейд выполняется как раньше (клиентская обёртка fakephone).
	wrap, err := mtproto.UpgradeClient(conn, sid, nil)
	if err != nil {
		t.Fatalf("апгрейд упал — регрессия гонки PROBE/KEY_RESP: %v", err)
	}

	// Ответ PROBE обязан прийти (крипто не затрагивает control-кадры).
	f := readFrameTimeout(t, wrap, 3*time.Second)
	if f.Type != rrp.TypeProbe {
		t.Fatalf("ждали PROBE-ответ, получили 0x%02x", f.Type)
	}
	var resp struct {
		OK    bool   `json:"ok"`
		Err   string `json:"err"`
		Proto string `json:"proto"`
	}
	if err := json.Unmarshal(f.Payload, &resp); err != nil {
		t.Fatalf("probe resp json: %v", err)
	}
	if !resp.OK {
		t.Fatalf("PROBE не прошёл: %s", resp.Err)
	}
	if resp.Proto != "mtproto2" {
		t.Fatalf("probe resp proto=%q", resp.Proto)
	}

	// Дальше — крипта должна реально работать: SOCKS5-эхо сквозь туннель.
	echoHost, echoPortS, _ := net.SplitHostPort(echoAddr)
	var echoPort uint16
	_, _ = fmt.Sscanf(echoPortS, "%d", &echoPort)
	p := &fakePhone{conn: conn, wrap: wrap, dst: map[uint32]net.Conn{}, dial: func(host string, port uint16) (net.Conn, error) {
		if host != echoHost || port != echoPort {
			return nil, fmt.Errorf("неожиданная цель: %s:%d", host, port)
		}
		return net.Dial("tcp", echoAddr)
	}}
	go p.loop()

	// SOCKS5-эхо сквозь шифрованный туннель — крипта реально работает.
	c, err := net.Dial("tcp", cfg.Listen.Mixed)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	br := bufio.NewReader(c)
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	mresp := make([]byte, 2)
	if _, err := io.ReadFull(br, mresp); err != nil {
		t.Fatal(err)
	}
	req := []byte{5, 1, 0, 3, byte(len(echoHost))}
	req = append(req, echoHost...)
	req = append(req, byte(echoPort>>8), byte(echoPort))
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(br, rep); err != nil {
		t.Fatal(err)
	}
	if rep[1] != 0 {
		t.Fatalf("socks connect через mtproto2: код %d", rep[1])
	}
	msg := []byte("keyrace-secret-echo")
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg) {
		t.Fatalf("эхо исказилось: %q", got)
	}
}

// tlsClientWrap — TLS-клиент поверх сырого коннекта (тестовый телефон).
func tlsClientWrap(t *testing.T, raw net.Conn, cfg *tls.Config) net.Conn {
	t.Helper()
	c := tls.Client(raw, cfg)
	if err := c.Handshake(); err != nil {
		raw.Close()
		t.Fatalf("tls handshake: %v", err)
	}
	return c
}

// readFrameTimeout — чтение одного кадра с дедлайном.
func readFrameTimeout(t *testing.T, r io.Reader, d time.Duration) *rrp.Frame {
	t.Helper()
	type deadliner interface{ SetReadDeadline(time.Time) error }
	if ds, ok := r.(deadliner); ok {
		_ = ds.SetReadDeadline(time.Now().Add(d))
		defer func() { _ = ds.SetReadDeadline(time.Time{}) }()
	}
	f, err := rrp.ReadFrame(r)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	return f
}

// TestNegotiateExecutableOnly — заявленный в реестре, но не исполняемый
// сервером протокол согласуется в честный дефолт (rrp1).
func TestNegotiateExecutableOnly(t *testing.T) {
	defer rrp.SetRegistry(rrp.SupportedProtocols(), "")
	// «Реклама» нового протокола из манифеста: в списках виден…
	rrp.SetRegistry([]rrp.Protocol{
		rrp.ProtocolRRP1,
		rrp.ProtocolMTProto2,
		{ID: "future9", Name: "Future/9", Ver: "9"},
	}, "test")
	if !rrp.IsSupported("future9") {
		t.Fatal("future9 должен быть в реестре (реклама для клиентов)")
	}
	if rrp.IsExecutable("future9") {
		t.Fatal("future9 не исполняется кодом — IsExecutable обязан быть false")
	}
	// …но согласование — только исполняемые.
	if got := rrp.Negotiate("future9", nil, "rrp1"); got != "rrp1" {
		t.Fatalf("future9 не должен согласовываться: got %q", got)
	}
	if got := rrp.Negotiate("mtproto2", nil, "rrp1"); got != "mtproto2" {
		t.Fatalf("mtproto2 обязан согласовываться: got %q", got)
	}
	if got := rrp.Negotiate("", []string{"future9", "mtproto2"}, "rrp1"); got != "mtproto2" {
		t.Fatalf("из offers выбирается первый исполняемый: got %q", got)
	}
	if got := rrp.Negotiate("мусор", nil, "rrp1"); got != "rrp1" {
		t.Fatalf("мусор → дефолт: got %q", got)
	}
}

// TestExecutableIDsCanonical — rrp1 и mtproto2 всегда исполняемы.
func TestExecutableIDsCanonical(t *testing.T) {
	ids := rrp.ExecutableIDs()
	hasRRP1, hasMT := false, false
	for _, id := range ids {
		if id == "rrp1" {
			hasRRP1 = true
		}
		if id == "mtproto2" {
			hasMT = true
		}
	}
	if !hasRRP1 || !hasMT {
		t.Fatalf("ExecutableIDs обязан содержать rrp1 и mtproto2: %v", ids)
	}
}
