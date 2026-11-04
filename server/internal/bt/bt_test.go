package bt

// bt_test.go — канонные тесты MSE/PE: раундтрип, форма пакетов (BEP 8 §3),
// отказ на чужом SKEY, форма piece-конверта, e2e через настоящий rrp.Session
// и детерминированный KAT-вектор для Kotlin-теста TorrentKATTest.

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/stelgen/reverseray/server/internal/rrp"
)

// detRand — детерминированный источник (KAT/воспроизводимость).
func detRand(seed uint64) func([]byte) (int, error) {
	r := rand.New(rand.NewSource(int64(seed)))
	return func(b []byte) (int, error) { return r.Read(b) }
}

// pipeRW — net.Conn как io.ReadWriteCloser (границы кадров читает rrp).
type pipeRW struct{ net.Conn }

func runHandshake(t *testing.T, skey [20]byte, crnd, srnd func([]byte) (int, error)) (*Transport, *Transport) {
	t.Helper()
	yb, sh, err := NewServerHandshake(skey, srnd)
	if err != nil {
		t.Fatal(err)
	}
	p1, ch, err := NewClientInit(skey, crnd)
	if err != nil {
		t.Fatal(err)
	}
	p3, err := ch.BuildPacket3(yb[:])
	if err != nil {
		t.Fatal(err)
	}
	resp, sTr, err := sh.Respond(ch.Init(p3, p1), srnd)
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.ConsumeResponse(resp); err != nil {
		t.Fatal(err)
	}
	return ch.Transport(), sTr
}

func TestMSEHandshakeRoundtrip(t *testing.T) {
	skey := SKEY(bytes.Repeat([]byte{7}, 32))
	cTr, sTr := runHandshake(t, skey, detRand(1), detRand(2))
	sizes := []int{1, 13, 100, 4096, MaxPlainData}
	for _, n := range sizes {
		plain := make([]byte, n)
		if _, err := crand.Read(plain); err != nil {
			t.Fatal(err)
		}
		box, err := cTr.Seal(plain)
		if err != nil {
			t.Fatalf("seal(%d): %v", n, err)
		}
		got, err := sTr.Open(box)
		if err != nil {
			t.Fatalf("open(%d): %v", n, err)
		}
		if !bytes.Equal(plain, got) {
			t.Fatalf("C→S size %d: данные исказились", n)
		}
		back, err := sTr.Seal(got)
		if err != nil {
			t.Fatalf("seal back(%d): %v", n, err)
		}
		got2, err := cTr.Open(back)
		if err != nil {
			t.Fatalf("open back(%d): %v", n, err)
		}
		if !bytes.Equal(plain, got2) {
			t.Fatalf("S→C size %d: данные исказились", n)
		}
	}
}

func TestMSECanonicalShapes(t *testing.T) {
	skey := SKEY(bytes.Repeat([]byte{9}, 32))
	yb, sh, err := NewServerHandshake(skey, detRand(2))
	if err != nil {
		t.Fatal(err)
	}
	p1, ch, err := NewClientInit(skey, detRand(1))
	if err != nil {
		t.Fatal(err)
	}
	// packet1: [Ya 96Б][pad 16..512] — канонные границы.
	if len(p1) < KeySize+PadMin || len(p1) > KeySize+PadMax {
		t.Fatalf("packet1 len %d вне [96+16, 96+512]", len(p1))
	}
	p3, err := ch.BuildPacket3(yb[:])
	if err != nil {
		t.Fatal(err)
	}
	init := append(append([]byte{}, p1...), p3...)
	// req1 = SHA1("req1"+S) лежит ОТКРЫТЫМ текстом ровно на 96+len(pad1)
	// (сервер находит его сканом — канон).
	s := sharedSecret(new(big.Int).SetBytes(yb[:]), ch.pair.X)
	req1Want := sha1Sum([]byte("req1"), s[:])
	found := -1
	for o := KeySize; o+40 <= len(init) && o <= KeySize+PadMax; o++ {
		if bytes.Equal(init[o:o+20], req1Want) {
			found = o
			break
		}
	}
	if found != len(p1) {
		t.Fatalf("req1 на смещении %d, ожидалось %d (96+pad1)", found, len(p1))
	}
	resp, _, err := sh.Respond(init, detRand(3))
	if err != nil {
		t.Fatal(err)
	}
	// packet4 ≥ VC(8)+select(4)+len(PadD)(2)+PadD(16); VC проверяется клиентом.
	if len(resp) < VCLen+4+2+PadMin {
		t.Fatalf("packet4 len %d слишком мал", len(resp))
	}
	if err := ch.ConsumeResponse(resp); err != nil {
		t.Fatal(err)
	}
}

func TestMSEWrongSKEYRejected(t *testing.T) {
	right := SKEY(bytes.Repeat([]byte{1}, 32))
	wrong := SKEY(bytes.Repeat([]byte{2}, 32))
	yb, sh, err := NewServerHandshake(right, detRand(2))
	if err != nil {
		t.Fatal(err)
	}
	p1, ch, err := NewClientInit(wrong, detRand(1)) // клиент с ЧУЖИМ SKEY
	if err != nil {
		t.Fatal(err)
	}
	p3, err := ch.BuildPacket3(yb[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := sh.Respond(ch.Init(p3, p1), detRand(3)); err == nil {
		t.Fatal("сервер принял хендшейк с чужим SKEY — нарушение канона req2")
	}
}

func TestPieceEnvelopePlausible(t *testing.T) {
	skey := SKEY(bytes.Repeat([]byte{3}, 32))
	cTr, sTr := runHandshake(t, skey, detRand(11), detRand(12))
	for i := 0; i < 5; i++ {
		plain := bytes.Repeat([]byte{0xEE}, 1000+i)
		box, err := cTr.Seal(plain)
		if err != nil {
			t.Fatal(err)
		}
		got, err := sTr.Open(box)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatal("payload исказился")
		}
	}
	// Слишком большой plaintext — отказ (лимит конверта).
	if _, err := cTr.Seal(make([]byte, MaxPlainData+1)); err == nil {
		t.Fatal("Seal принял plaintext больше MaxPlainData")
	}
}

func TestSKEYDeterministic(t *testing.T) {
	a := TokenSKEY("token-x")
	b := TokenSKEY("token-x")
	c := TokenSKEY("token-y")
	if a != b {
		t.Fatal("SKEY недетерминирован")
	}
	if a == c {
		t.Fatal("SKEY не зависит от токена")
	}
}

// TestSessionE2EBitTorrent — e2e через настоящий rrp.Session:
// KEY_REQ(kind=bittorrent) → BT_INIT(packet1||packet3) → BT_RESP(packet4) →
// крипта DATA (peer-wire piece-сообщения).
func TestSessionE2EBitTorrent(t *testing.T) {
	cA, cB := net.Pipe()
	defer cA.Close()
	defer cB.Close()

	tokenHash := sha256.Sum256([]byte("e2e-token"))
	plan, err := NewServerPlan("sess-bt", tokenHash[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	scfg := rrp.DefaultSessionConfig()
	scfg.Protocol = ProtoID
	scfg.KeyPlan = plan
	scfg.Logf = func(format string, args ...any) { t.Logf("server: "+format, args...) }
	sess := rrp.NewSession("sess-bt", "phone-bt", pipeRW{cB}, scfg)
	done := make(chan struct{})
	go func() { sess.Run(); close(done) }()

	if err := cA.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// 1) KEY_REQ с Yb сервера.
	f, err := rrp.ReadFrame(cA)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != rrp.TypeKeyReq {
		t.Fatalf("ждали KEY_REQ, получили 0x%02x", f.Type)
	}
	var req struct {
		Kind string `json:"kind"`
		YB   string `json:"yb"`
	}
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		t.Fatal(err)
	}
	if req.Kind != ProtoID {
		t.Fatalf("kind = %q", req.Kind)
	}
	yb, err := base64.RawURLEncoding.DecodeString(req.YB)
	if err != nil || len(yb) != KeySize {
		t.Fatalf("yb bad: %v %d", err, len(yb))
	}
	// 2) Клиент: канонный MSE packet1||packet3 (SKEY из токена).
	skey := SKEY(tokenHash[:])
	p1, ch, err := NewClientInit(skey, crand.Read)
	if err != nil {
		t.Fatal(err)
	}
	p3, err := ch.BuildPacket3(yb)
	if err != nil {
		t.Fatal(err)
	}
	if err := rrp.WriteFrame(cA, rrp.TypeBtInit, 0, 0, ch.Init(p3, p1)); err != nil {
		t.Fatal(err)
	}
	// 3) BT_RESP (packet4) от сервера → клиентские ключи.
	f, err = rrp.ReadFrame(cA)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != rrp.TypeBtResp {
		t.Fatalf("ждали BT_RESP, получили 0x%02x", f.Type)
	}
	if err := ch.ConsumeResponse(f.Payload); err != nil {
		t.Fatal(err)
	}
	ct := ch.Transport()

	// 4) Открытые данные стрима идут В PIECE-КОНВЕРТЕ (peer-wire форма).
	openCh := make(chan *rrp.Frame, 1)
	go func() {
		ff, err := rrp.ReadFrame(cA)
		if err != nil {
			return
		}
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
	go func() {
		if _, err := stream.Write([]byte("hello-bt")); err != nil {
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
	plain, err := ct.Open(f2.Payload)
	if err != nil || string(plain) != "hello-bt" {
		t.Fatalf("расшифровка piece: %v %q", err, plain)
	}
	// Клиент шлёт piece-сообщение → сервер читает открытые данные стрима.
	box, err := ct.Seal([]byte("pong-bt"))
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
	if string(buf) != "pong-bt" {
		t.Fatalf("сервер прочитал %q", buf)
	}
	_ = stream.Close()
	_ = sess.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
}

// TestSessionProtoSwitchLive — бесшовная смена протокола БЕЗ разрыва связи:
// сессия работает как rrp1, клиент шлёт 0x2C {proto:bittorrent}, сервер
// соглашается, идёт перехендшейк MSE, DATA продолжают ходить уже в BT-конверте.
func TestSessionProtoSwitchLive(t *testing.T) {
	cA, cB := net.Pipe()
	defer cA.Close()
	defer cB.Close()

	tokenHash := sha256.Sum256([]byte("sw-token"))
	scfg := rrp.DefaultSessionConfig()
	scfg.Protocol = rrp.DefaultProtocolID
	scfg.Switchable = true
	scfg.TokenHash = tokenHash[:]
	scfg.SwitchPlanner = func(target string) (rrp.KeyPlan, error) {
		if target != ProtoID {
			return nil, fmt.Errorf("%w: target %q", rrp.ErrKeyPlan, target)
		}
		return NewServerPlan("sess-sw", tokenHash[:], nil)
	}
	scfg.Logf = func(format string, args ...any) { t.Logf("server: "+format, args...) }
	sess := rrp.NewSession("sess-sw", "phone-sw", pipeRW{cB}, scfg)
	done := make(chan struct{})
	go func() { sess.Run(); close(done) }()
	defer func() {
		_ = sess.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	}()

	if err := cA.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// 1) Клиент просит сменить протокол на bittorrent.
	if err := rrp.WriteFrame(cA, rrp.TypeProtoSwitch, 0, 0, []byte(`{"proto":"bittorrent","nonce":"n1"}`)); err != nil {
		t.Fatal(err)
	}
	f, err := rrp.ReadFrame(cA)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != rrp.TypeProtoSwitch {
		t.Fatalf("ждали PROTO_SWITCH ok, получили 0x%02x", f.Type)
	}
	var ack struct {
		Proto string `json:"proto"`
		Nonce string `json:"nonce"`
		OK    bool   `json:"ok"`
	}
	if err := json.Unmarshal(f.Payload, &ack); err != nil || !ack.OK || ack.Proto != ProtoID || ack.Nonce != "n1" {
		t.Fatalf("ack bad: %+v %v", ack, err)
	}
	// 2) KEY_REQ целевого протокола (bittorrent, с Yb).
	f, err = rrp.ReadFrame(cA)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != rrp.TypeKeyReq {
		t.Fatalf("ждали KEY_REQ, получили 0x%02x", f.Type)
	}
	var kreq struct {
		Kind string `json:"kind"`
		YB   string `json:"yb"`
	}
	if err := json.Unmarshal(f.Payload, &kreq); err != nil {
		t.Fatal(err)
	}
	if kreq.Kind != ProtoID {
		t.Fatalf("kind = %q", kreq.Kind)
	}
	yb, err := base64.RawURLEncoding.DecodeString(kreq.YB)
	if err != nil || len(yb) != KeySize {
		t.Fatalf("yb bad: %v %d", err, len(yb))
	}
	// 3) Клиент: MSE-хендшейк.
	skey := SKEY(tokenHash[:])
	p1, ch, err := NewClientInit(skey, crand.Read)
	if err != nil {
		t.Fatal(err)
	}
	p3, err := ch.BuildPacket3(yb)
	if err != nil {
		t.Fatal(err)
	}
	if err := rrp.WriteFrame(cA, rrp.TypeBtInit, 0, 0, ch.Init(p3, p1)); err != nil {
		t.Fatal(err)
	}
	f, err = rrp.ReadFrame(cA)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != rrp.TypeBtResp {
		t.Fatalf("ждали BT_RESP, получили 0x%02x", f.Type)
	}
	if err := ch.ConsumeResponse(f.Payload); err != nil {
		t.Fatal(err)
	}
	ct := ch.Transport()

	// 4) Соединение живо: сервер открывает стрим ПОСЛЕ смены — DATA
	// приходят уже в BT-конверте.
	openCh := make(chan *rrp.Frame, 1)
	go func() {
		ff, err := rrp.ReadFrame(cA)
		if err != nil {
			return
		}
		if ff.Type == rrp.TypeOpen {
			_ = rrp.WriteFrame(cA, rrp.TypeOpenOK, 0, ff.StreamID, []byte{0})
		}
		openCh <- ff
	}()
	stream, err := sess.Open(context.Background(), rrp.DialRequest{ATYP: rrp.ATYPDomain, Addr: []byte("example.test"), Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-openCh:
	case <-time.After(10 * time.Second):
		t.Fatal("Open frame не пришёл после смены протокола")
	}
	go func() {
		if _, err := stream.Write([]byte("after-switch")); err != nil {
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
	plain, err := ct.Open(f2.Payload)
	if err != nil || string(plain) != "after-switch" {
		t.Fatalf("DATA после смены не в BT-конверте: %v %q", err, plain)
	}
	if got, want := sess.Proto, ProtoID; got != want {
		t.Fatalf("sess.Proto = %q, want %q", got, want)
	}
}

// TestProtoSwitchRejectsGarbage — мусор/чужой протокол: отказ без разрыва.
func TestProtoSwitchRejectsGarbage(t *testing.T) {
	cA, cB := net.Pipe()
	defer cA.Close()
	defer cB.Close()

	scfg := rrp.DefaultSessionConfig()
	scfg.Protocol = rrp.DefaultProtocolID
	scfg.Switchable = true
	scfg.SwitchPlanner = func(target string) (rrp.KeyPlan, error) {
		return nil, fmt.Errorf("%w: target %q", rrp.ErrKeyPlan, target)
	}
	sess := rrp.NewSession("sess-g", "phone-g", pipeRW{cB}, scfg)
	done := make(chan struct{})
	go func() { sess.Run(); close(done) }()
	defer func() {
		_ = sess.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	}()

	if err := cA.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// неизвестный протокол → ok=false, сессия жива
	if err := rrp.WriteFrame(cA, rrp.TypeProtoSwitch, 0, 0, []byte(`{"proto":"future9"}`)); err != nil {
		t.Fatal(err)
	}
	f, err := rrp.ReadFrame(cA)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != rrp.TypeProtoSwitch {
		t.Fatalf("ждали 0x2C, получили 0x%02x", f.Type)
	}
	var ack struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(f.Payload, &ack); err != nil || ack.OK {
		t.Fatalf("мусор не отклонён: %+v", ack)
	}
	// мусорный JSON → тихий игнор, сессия жива (PING/PONG отвечает)
	if err := rrp.WriteFrame(cA, rrp.TypeProtoSwitch, 0, 0, []byte("garbage")); err != nil {
		t.Fatal(err)
	}
	if err := rrp.WriteFrame(cA, rrp.TypePing, 0, 0, []byte{1, 2, 3, 4, 5, 6, 7, 8}); err != nil {
		t.Fatal(err)
	}
	pong, err := rrp.ReadFrame(cA)
	if err != nil {
		t.Fatal(err)
	}
	if pong.Type != rrp.TypePong {
		t.Fatalf("сессия умерла от мусора: 0x%02x", pong.Type)
	}
}

// ---- KAT: детерминированный вектор для Kotlin TorrentKATTest ----

// TestKATVector — фиксированные Xa/Xb/pad дают байт-в-байт воспроизводимый
// вектор. Меняя канон — обновляй вектор ОБЕИХ сторон (Go↔Kotlin).
func TestKATVector(t *testing.T) {
	skey := TokenSKEY("kat-token-2026")
	// фиксированные приватные ключи (160 бит), оба < P
	xa := mustBig(t, "3B1C0A2E5D7F9B1D3E5F7A9C1B3D5F7E9A1C3E5B7D9F1A3C5E7B9D1F3A5C7E9B1D3F5A7C9E1B3D5F7A9C1B")
	xb := mustBig(t, "5C3E7A9B1D3F5E7C9A1B3D5F7E9A1C3E5B7D9F1A3C5E7B9D1F3A5C7E9B1D3F5A7C9E1B3D5F7A9C1B3D5F7E9A")
	ya := be96(new(big.Int).Exp(dhG, xa, dhPrime))
	yb := be96(new(big.Int).Exp(dhG, xb, dhPrime))

	ch := &ClientHandshake{skey: skey, pair: &DHPair{X: xa, Y: new(big.Int).SetBytes(ya[:])}}
	p3, err := ch.BuildPacket3(yb[:])
	if err != nil {
		t.Fatal(err)
	}
	// packet1 без паддинга канонен (pad может быть 0 — фиксированный вектор)
	init := ch.Init(p3, ya[:])
	sh := &ServerHandshake{skey: skey, pair: &DHPair{X: xb, Y: new(big.Int).SetBytes(yb[:])}}
	resp, sTr, err := sh.Respond(init, fixedFill(0x5A))
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.ConsumeResponse(resp); err != nil {
		t.Fatal(err)
	}
	cTr := ch.Transport()
	box, err := cTr.Seal([]byte("kat"))
	if err != nil {
		t.Fatal(err)
	}
	back, err := sTr.Open(box)
	if err != nil || string(back) != "kat" {
		t.Fatalf("KAT roundtrip: %v %q", err, back)
	}
	t.Logf("KAT s=%s", hex.EncodeToString(ch.s[:]))
	t.Logf("KAT init(%d)=%s", len(init), hex.EncodeToString(init))
	t.Logf("KAT resp(%d)=%s", len(resp), hex.EncodeToString(resp))
	t.Logf("KAT box(%d)=%s", len(box), hex.EncodeToString(box))
}

// fixedFill — rnd-заглушка: любой запрос длины возвращает fill-байты
// (длина паддинга packet4 становится детерминированной).
func fixedFill(fill byte) func([]byte) (int, error) {
	return func(b []byte) (int, error) {
		for j := range b {
			b[j] = fill
		}
		return len(b), nil
	}
}

func mustBig(t *testing.T, h string) *big.Int {
	t.Helper()
	v, ok := new(big.Int).SetString(h, 16)
	if !ok {
		t.Fatal("bad hex")
	}
	return v
}
