package wg

// session_e2e_test.go — e2e через настоящий rrp.Session: KEY_REQ(kind=wg) →
// WG_INIT(msg1) → WG_RESP(msg2) → крипта DATA (WG transport-конверты).

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stelgen/reverseray/server/internal/rrp"
)

type pipeRW struct {
	net.Conn
}

func TestSessionE2EWireGuard(t *testing.T) {
	cA, cB := net.Pipe()
	defer cA.Close()
	defer cB.Close()

	tokenHash := TokenPSK("e2e-token")
	plan, err := NewServerPlan("sess-e2e", tokenHash[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	scfg := rrp.DefaultSessionConfig()
	scfg.Protocol = ProtoID
	scfg.KeyPlan = plan
	scfg.Logf = func(format string, args ...any) { t.Logf("server: "+format, args...) }
	sess := rrp.NewSession("sess-e2e", "phone-e2e", pipeRW{cB}, scfg)
	done := make(chan struct{})
	go func() { sess.Run(); close(done) }()

	// 1) KEY_REQ с WG static сервера.
	if err := cA.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	f, err := rrp.ReadFrame(cA)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != rrp.TypeKeyReq {
		t.Fatalf("ждали KEY_REQ, получили 0x%02x", f.Type)
	}
	var req struct {
		Kind string `json:"kind"`
		SPub string `json:"spub"`
	}
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		t.Fatal(err)
	}
	if req.Kind != ProtoID {
		t.Fatalf("kind = %q", req.Kind)
	}
	spub, err := base64.RawURLEncoding.DecodeString(req.SPub)
	if err != nil || len(spub) != KeySize {
		t.Fatalf("spub bad: %v %d", err, len(spub))
	}
	var serverPub [KeySize]byte
	copy(serverPub[:], spub)

	// 2) Клиент: настоящий WG msg1 (PSK = SHA256(token) — наш ключ доверия).
	psk := TokenPSK("e2e-token")
	msg1, ch, err := NewClientHandshake(&serverPub, &psk)
	if err != nil {
		t.Fatal(err)
	}
	if err := rrp.WriteFrame(cA, rrp.TypeWgInit, 0, 0, msg1); err != nil {
		t.Fatal(err)
	}

	// 3) WG_RESP от сервера → клиентские ключи.
	f, err = rrp.ReadFrame(cA)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != rrp.TypeWgResp {
		t.Fatalf("ждали WG_RESP, получили 0x%02x", f.Type)
	}
	if err := ch.ConsumeResponse(f.Payload, &psk); err != nil {
		t.Fatal(err)
	}
	ct := NewTransport(true, ch)

	// 4) Сервер открывает стрим (hub.Open) — клиент подтверждает OpenOK.
	openCh := make(chan *rrp.Frame, 1)
	go func() {
		ff, err := rrp.ReadFrame(cA)
		if err != nil {
			return
		}
		// Клиент подтверждает открытие СРАЗУ (иначе Open ждёт OpenOK,
		// а мы ждём Open — дедлок теста).
		if ff.Type == rrp.TypeOpen {
			_ = rrp.WriteFrame(cA, rrp.TypeOpenOK, 0, ff.StreamID, []byte{0})
		}
		openCh <- ff
	}()
	stream, err := sess.Open(context.Background(), rrp.DialRequest{ATYP: rrp.ATYPDomain, Addr: []byte("example.test"), Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	var of *rrp.Frame
	select {
	case of = <-openCh:
	case <-time.After(10 * time.Second):
		t.Fatal("Open frame не пришёл")
	}
	if of.Type != rrp.TypeOpen {
		t.Fatalf("ждали OPEN, получили 0x%02x", of.Type)
	}
	// Открытые данные стрима: сервер пишет → клиент видит В WG-КОНВЕРТЕ.
	// Проверим: кадр DATA на проводе начинается с type=4 (WG-пакет).
	go func() {
		if _, err := stream.Write([]byte("hello-wg")); err != nil {
			t.Logf("write: %v", err)
		}
	}()
	f2, err := rrp.ReadFrame(cA)
	if err != nil {
		t.Fatal(err)
	}
	if f2.Type != rrp.TypeData {
		t.Fatalf("ждали DATA, получили 0x%02x", f2.Type)
	}
	if f2.Payload[0] != 4 {
		t.Fatalf("payload DATA — не WG transport-пакет (type=%d)", f2.Payload[0])
	}
	plain, err := ct.Open(f2.Payload)
	if err != nil || string(plain) != "hello-wg" {
		t.Fatalf("расшифровка: %v %q", err, plain)
	}
	// Клиент шлёт WG-пакет → сервер читает открытые данные стрима.
	box, err := ct.Seal([]byte("pong-wg"))
	if err != nil {
		t.Fatal(err)
	}
	if err := rrp.WriteFrame(cA, rrp.TypeData, 0, of.StreamID, box); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 7)
	if err := stream.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "pong-wg" {
		t.Fatalf("сервер прочитал %q", buf)
	}
	// 5) Управление камуфляжем (0x2A): валидный кадр не рвёт сессию
	// (персистенцию проверяют serverapp-тесты).
	if err := rrp.WriteFrame(cA, rrp.TypeCamCtl, 0, 0, []byte(`{"enabled":false}`)); err != nil {
		t.Fatal(err)
	}
	_ = stream.Close()
	_ = sess.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
}
