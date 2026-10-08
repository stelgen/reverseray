package rrp

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"
)

// v0.7.4: APK 0.7.3 слал "ver":1 ЧИСЛОМ — сервер падал с «bad HELLO»
// (ERROR 2 protocol error на проде 81.25.59.194:4433). FlexString обязан
// принимать и число, и строку.
func TestFlexStringAcceptsNumberAndString(t *testing.T) {
	var h Hello
	if err := json.Unmarshal([]byte(`{"agent":"a","ver":1,"device":"phone-1","max_streams":64}`), &h); err != nil {
		t.Fatalf("ver как число не разобрался: %v", err)
	}
	if h.Ver.String() != "1" || h.Device != "phone-1" {
		t.Fatalf("unexpected: ver=%q device=%q", h.Ver, h.Device)
	}
	var h2 Hello
	if err := json.Unmarshal([]byte(`{"agent":"a","ver":"1.0","device":"d"}`), &h2); err != nil {
		t.Fatalf("ver как строка не разобрался: %v", err)
	}
	if h2.Ver.String() != "1.0" {
		t.Fatalf("ver строка потерялась: %q", h2.Ver)
	}
	// marshaling → канон-строка
	b, _ := json.Marshal(&h2)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if _, ok := m["ver"].(string); !ok {
		t.Fatalf("маршалинг ver должен быть строкой, got %v", m["ver"])
	}
}

// v0.7.4: APK 0.7.3 слал HMAC в std-base64 (с '+/' и '=') — сервер декодировал
// только RawURLEncoding → «auth failed». Канон base64url, но принимаем все три
// кодировки одних и тех же байтов.
func TestVerifyAuthAcceptsAllBase64Variants(t *testing.T) {
	key := TokenHash("token")
	nonce, _ := NewNonce()
	nonceBytes, _ := base64.RawURLEncoding.DecodeString(nonce)
	sid := "session-1"
	mac := hmacSHA256ForTest(key, nonceBytes, sid)
	url := base64.RawURLEncoding.EncodeToString(mac)
	urlPad := base64.URLEncoding.EncodeToString(mac)
	std := base64.StdEncoding.EncodeToString(mac)
	if !VerifyAuth(key, nonce, sid, url) {
		t.Error("base64url без паддинга (канон) не принят")
	}
	if !VerifyAuth(key, nonce, sid, urlPad) {
		t.Error("base64url с паддингом не принят")
	}
	if !VerifyAuth(key, nonce, sid, std) {
		t.Error("стандартный base64 не принят")
	}
	if VerifyAuth(key, nonce, sid, url[:len(url)-2]+"AA") {
		t.Error("битый HMAC принят")
	}
	if VerifyAuth(key, nonce, "other-session", url) {
		t.Error("HMAC от другой сессии принят")
	}
}

// ---- протоколы: реестр, нормализация мусора, согласование ----

func TestNormalizeProtoGarbage(t *testing.T) {
	cases := map[string]string{
		"":             DefaultProtocolID,
		"  ":           DefaultProtocolID,
		"rrp1":         "rrp1",
		"RRP1":         "rrp1",
		"\"rrp1\"":     "rrp1",
		"garbage":      DefaultProtocolID,
		"vless":        DefaultProtocolID, // неизвестен → дефолт, никогда не ошибка
		"\x00rrp1\x00": DefaultProtocolID,
		"null":         DefaultProtocolID,
	}
	for in, want := range cases {
		if got := NormalizeProto(in); got != want {
			t.Errorf("NormalizeProto(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNegotiate(t *testing.T) {
	// 1) явный валидный id клиента
	if got := Negotiate("rrp1", nil, "rrp1"); got != "rrp1" {
		t.Errorf("explicit: %q", got)
	}
	// 2) мусор от клиента → дефолт (не ошибка)
	if got := Negotiate("junk-protocol", []string{"rrp1"}, "rrp1"); got != DefaultProtocolID {
		t.Errorf("junk: %q", got)
	}
	// 3) пусто, но клиент предлагает список — берём первый поддерживаемый
	if got := Negotiate("", []string{"future-proto", "rrp1"}, "rrp1"); got != "rrp1" {
		t.Errorf("offers: %q", got)
	}
	// 4) ничего общего → серверный дефолт
	if got := Negotiate("", []string{"future-proto"}, "rrp1"); got != DefaultProtocolID {
		t.Errorf("default: %q", got)
	}
}

func TestSupportedIDsHasDefault(t *testing.T) {
	ids := SupportedIDs()
	if len(ids) == 0 {
		t.Fatal("реестр протоколов пуст")
	}
	found := false
	for _, id := range ids {
		if id == DefaultProtocolID {
			found = true
		}
		if !IsSupported(id) {
			t.Errorf("id %q из реестра не проходит IsSupported", id)
		}
	}
	if !found {
		t.Fatalf("дефолтный протокол %q отсутствует в реестре", DefaultProtocolID)
	}
}

// ---- PROBE: валидация реального egress ----

func TestSessionProbeOK(t *testing.T) {
	// локальный TCP-приёмник как «реальный хост»
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
		}
	}()

	var cfg SessionConfig = DefaultSessionConfig()
	cfg.Protocol = "rrp1"
	cfg.ProbeDialer = func(ctx context.Context, target string, timeout time.Duration) error {
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", target)
		if err != nil {
			return err
		}
		_ = c.Close()
		return nil
	}
	s := NewSession("id", "dev", newNopConn(), cfg)
	defer s.Close()

	s.handleProbe(&Frame{Type: TypeProbe, Payload: mustJSON(t, map[string]any{
		"target": ln.Addr().String(), "timeout_ms": 2000,
	})})
	// ответ вылетел в writeAsync → даём writer'у время
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := s.readLastProbeResponse(); got != nil {
			if !got.OK {
				t.Fatalf("probe не удался: %s", got.Err)
			}
			if got.Proto != "rrp1" {
				t.Fatalf("probe ответ без proto: %+v", got)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("ответ PROBE не получен")
}

func TestSessionProbeDisabled(t *testing.T) {
	cfg := DefaultSessionConfig()
	cfg.Protocol = "rrp1"
	s := NewSession("id", "dev", newNopConn(), cfg)
	defer s.Close()
	s.handleProbe(&Frame{Type: TypeProbe, Payload: []byte(`{"target":"1.2.3.4:80"}`)})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := s.readLastProbeResponse(); got != nil {
			if got.OK {
				t.Fatal("probe без dialer'а не должен проходить")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("ответ PROBE не получен")
}

func TestSessionProbeBadTarget(t *testing.T) {
	cfg := DefaultSessionConfig()
	cfg.Protocol = "rrp1"
	cfg.ProbeDialer = func(context.Context, string, time.Duration) error { return nil }
	s := NewSession("id", "dev", newNopConn(), cfg)
	defer s.Close()
	s.handleProbe(&Frame{Type: TypeProbe, Payload: []byte(`{"target":"no-port-here"}`)})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := s.readLastProbeResponse(); got != nil {
			if got.OK {
				t.Fatal("probe без порта не должен проходить")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("ответ PROBE не получен")
}

// ---- helpers ----

type nopConn struct {
	reads  chan []byte
	writes chan []byte
	closed bool
	last   []byte
}

func newNopConn() *nopConn {
	return &nopConn{reads: make(chan []byte, 64), writes: make(chan []byte, 64)}
}

func (c *nopConn) Read(p []byte) (int, error) {
	b, ok := <-c.reads
	if !ok {
		return 0, errors.New("closed")
	}
	n := copy(p, b)
	return n, nil
}

func (c *nopConn) Write(p []byte) (int, error) {
	c.last = append([]byte(nil), p...)
	select {
	case c.writes <- c.last:
	default:
	}
	return len(p), nil
}

func (c *nopConn) Close() error {
	c.closed = true
	select {
	case <-c.writes:
	default:
		close(c.reads)
	}
	return nil
}

// readLastProbeResponse достаёт последнюю PROBE-запись из очереди записи.
func (s *Session) readLastProbeResponse() *probeResponse {
	for {
		select {
		case it := <-s.outq:
			if it.frame.Type == TypeProbe {
				var r probeResponse
				if err := json.Unmarshal(it.frame.Payload, &r); err == nil {
					return &r
				}
				return nil
			}
			continue
		default:
			return nil
		}
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// hmacSHA256ForTest — HMAC(key=SHA256(token), nonce||session_id), как AuthCode.
func hmacSHA256ForTest(key, nonce []byte, sid string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(nonce)
	mac.Write([]byte(sid))
	return mac.Sum(nil)
}
