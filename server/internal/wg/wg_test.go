package wg

// wg_test.go — канон-тесты WireGuard-стека (roundtrip, mac1, анти-реплей,
// sliding window) + генератор межъязыковых KAT-векторов (Go → Kotlin).
// RR_KAT_OUT=/tmp/wg-kat.json — записать детерминированные векторы.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func mustPair(t *testing.T) *KeyPair {
	t.Helper()
	kp, err := GeneratePair()
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func TestHandshakeRoundtrip(t *testing.T) {
	server := mustPair(t)
	psk := TokenPSK("unit-test-token")
	msg1, ch, err := NewClientHandshake(&server.Pub, &psk)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg1) != MsgInitSize {
		t.Fatalf("msg1 = %d Б, канон WG %d", len(msg1), MsgInitSize)
	}
	if binary.LittleEndian.Uint32(msg1[0:4]) != 1 {
		t.Fatal("msg1 type ≠ 1")
	}
	last := [StampSize]byte{}
	msg2, sh, err := HandshakeRespond(&server.Priv, &server.Pub, &psk, msg1, &last)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg2) != MsgRespSize {
		t.Fatalf("msg2 = %d Б, канон WG %d", len(msg2), MsgRespSize)
	}
	if err := ch.ConsumeResponse(msg2, &psk); err != nil {
		t.Fatal(err)
	}
	if ch.RecvIdx != sh.Sender || sh.RecvIdx != ch.Sender {
		t.Fatal("sender/receiver индексы не сцепились")
	}
	// Транспорт в обе стороны + точность данных.
	ct := NewTransport(true, ch)
	st := NewTransportServer(sh)
	for i := 0; i < 50; i++ {
		payload := bytes.Repeat([]byte{byte(i)}, 1000+i)
		pkt, err := ct.Seal(payload)
		if err != nil {
			t.Fatal(err)
		}
		got, err := st.Open(pkt)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("C→S iter %d: %v", i, err)
		}
		pkt, err = st.Seal(payload)
		if err != nil {
			t.Fatal(err)
		}
		got, err = ct.Open(pkt)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("S→C iter %d: %v", i, err)
		}
	}
}

func TestMac1Reject(t *testing.T) {
	server := mustPair(t)
	psk := TokenPSK("mac1-test")
	msg1, _, err := NewClientHandshake(&server.Pub, &psk)
	if err != nil {
		t.Fatal(err)
	}
	msg1[120] ^= 0x01 // портим mac1
	if _, _, err := HandshakeRespond(&server.Priv, &server.Pub, &psk, msg1, nil); err == nil {
		t.Fatal("битый mac1 должен отклоняться")
	}
}

func TestTimestampReplay(t *testing.T) {
	server := mustPair(t)
	psk := TokenPSK("replay-test")
	msg1, _, err := NewClientHandshake(&server.Pub, &psk)
	if err != nil {
		t.Fatal(err)
	}
	var last [StampSize]byte
	if _, _, err := HandshakeRespond(&server.Priv, &server.Pub, &psk, msg1, &last); err != nil {
		t.Fatal(err)
	}
	// Тот же msg1 (та же метка) — реплей рукопожатия обязан быть отклонён.
	if _, _, err := HandshakeRespond(&server.Priv, &server.Pub, &psk, msg1, &last); err == nil {
		t.Fatal("replay timestamp должен отклоняться")
	}
}

func TestReplayWindow(t *testing.T) {
	server := mustPair(t)
	psk := TokenPSK("window-test")
	msg1, ch, err := NewClientHandshake(&server.Pub, &psk)
	if err != nil {
		t.Fatal(err)
	}
	msg2, sh, err := HandshakeRespond(&server.Priv, &server.Pub, &psk, msg1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.ConsumeResponse(msg2, &psk); err != nil {
		t.Fatal(err)
	}
	st := NewTransportServer(sh)
	var boxes [][]byte
	for i := 0; i < 10; i++ {
		pkt, _ := st.Seal([]byte{byte(i)})
		boxes = append(boxes, pkt)
	}
	// Порядок/повторы: сначала неупорядоченный приём (в пределах окна),
	// затем повтор — обязан отвергаться.
	if _, err := st.Open(boxes[5]); err != nil { // зашев: сервер сам себе шлёт — тест окна на ct
		_ = err
	}
	ct := NewTransport(true, ch)
	var fromClient [][]byte
	for i := 0; i < 10; i++ {
		pkt, _ := ct.Seal([]byte{byte(i)})
		fromClient = append(fromClient, pkt)
	}
	// 5, затем 5 повтор (отверг), затем 7, 6 — всё в пределах окна.
	for _, i := range []int{5, 7, 6, 0, 9} {
		if _, err := st.Open(fromClient[i]); err != nil {
			t.Fatalf("packet %d rejected: %v", i, err)
		}
	}
	if _, err := st.Open(fromClient[5]); err == nil {
		t.Fatal("повтор пакета должен отвергаться (анти-реплей канона WG)")
	}
	// Дальний сдвиг окна: пакет 0 уже позади окна после прыжка вперёд.
	for i := 0; i < ReplayWindowSize+5; i++ {
		pkt, _ := ct.Seal([]byte{byte(i % 256)})
		if _, err := st.Open(pkt); err != nil {
			t.Fatalf("stream at %d: %v", i, err)
		}
	}
	if _, err := st.Open(fromClient[1]); err == nil {
		t.Fatal("пакет позади sliding window должен отвергаться")
	}
}

// ---- межъязыковой KAT (Go → Kotlin), зеркально mtproto katgen ----

type wgKAT struct {
	Construction string `json:"construction"`
	Identifier   string `json:"identifier"`
	LabelMac1    string `json:"label_mac1"`
	// фиксированные ключи (hex)
	ServerPriv string `json:"server_priv"`
	ServerPub  string `json:"server_pub"`
	ClientPriv string `json:"client_priv"`
	ClientPub  string `json:"client_pub"`
	EphPriv    string `json:"eph_priv"`
	Psk        string `json:"psk"`
	SenderC    uint32 `json:"sender_client"`
	SenderS    uint32 `json:"sender_server"`
	StampHex   string `json:"stamp"`
	// векторы
	Msg1Hex    string   `json:"msg1"`
	Msg2Hex    string   `json:"msg2"`
	SendKeyC2S string   `json:"send_key_c2s"`
	SendKeyS2C string   `json:"send_key_s2c"`
	Boxes      []boxVec `json:"boxes"`
}

type boxVec struct {
	Dir       string `json:"dir"` // c2s | s2c
	Counter   uint64 `json:"counter"`
	PlainHex  string `json:"plain"`
	CipherHex string `json:"cipher"` // полный WG-пакет (type4-заголовок+AEAD)
}

func fixedPair(seed byte) *KeyPair {
	kp := &KeyPair{}
	for i := range kp.Priv {
		kp.Priv[i] = seed + byte(i)
	}
	pub, err := curve255X(kp.Priv[:])
	if err != nil {
		panic(err)
	}
	copy(kp.Pub[:], pub)
	return kp
}

func TestGenerateKAT(t *testing.T) {
	out := os.Getenv("RR_KAT_OUT")
	if out == "" {
		t.Skip("RR_KAT_OUT не задан — межъязыковой прогон запускается вручную")
	}
	server := fixedPair(0x21)
	client := fixedPair(0x01)
	eph := fixedPair(0x41)
	psk := TokenPSK("reverseray-wg-kat")
	var stamp [StampSize]byte
	for i := range stamp {
		stamp[i] = byte(0xA0 + i)
	}
	msg1, ch, err := katClientHandshake(server, client, eph, &psk, &stamp, 0x01020304)
	if err != nil {
		t.Fatal(err)
	}
	msg2, sh, err := katServerHandshake(server, &psk, msg1, 0x0A0B0C0D, nil) // первый хендшейк: анти-реплей-состояния нет
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.ConsumeResponse(msg2, &psk); err != nil {
		t.Fatal(err)
	}
	ct := NewTransport(true, ch)
	st := NewTransportServer(sh)
	// Детерминированные счётчики: обнуляем send-счётчики.
	ct.sendCtr = 0
	st.sendCtr = 0
	kat := wgKAT{
		Construction: Construction, Identifier: Identifier, LabelMac1: LabelMac1,
		ServerPriv: hex.EncodeToString(server.Priv[:]), ServerPub: hex.EncodeToString(server.Pub[:]),
		ClientPriv: hex.EncodeToString(client.Priv[:]), ClientPub: hex.EncodeToString(client.Pub[:]),
		EphPriv: hex.EncodeToString(eph.Priv[:]), Psk: hex.EncodeToString(psk[:]),
		SenderC: ch.Sender, SenderS: sh.Sender, StampHex: hex.EncodeToString(stamp[:]),
		Msg1Hex: hex.EncodeToString(msg1), Msg2Hex: hex.EncodeToString(msg2),
		SendKeyC2S: hex.EncodeToString(ch.SendKey[:]), SendKeyS2C: hex.EncodeToString(ch.RecvKey[:]),
	}
	plain1 := []byte("reverseray-wg-kat-c2s-0001")
	box1, err := ct.Seal(plain1)
	if err != nil {
		t.Fatal(err)
	}
	plain2 := []byte("reverseray-wg-kat-s2c-0001")
	box2, err := st.Seal(plain2)
	if err != nil {
		t.Fatal(err)
	}
	kat.Boxes = []boxVec{
		{Dir: "c2s", Counter: 0, PlainHex: hex.EncodeToString(plain1), CipherHex: hex.EncodeToString(box1)},
		{Dir: "s2c", Counter: 0, PlainHex: hex.EncodeToString(plain2), CipherHex: hex.EncodeToString(box2)},
	}
	b, _ := json.MarshalIndent(kat, "", "  ")
	if err := os.WriteFile(out, b, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("KAT записан: %s (%d байт), msg1=%s…", out, len(b), base64.RawURLEncoding.EncodeToString(msg1)[:16])
}

// sha256Goodness — проверка TokenPSK.
func TestTokenPSK(t *testing.T) {
	psk := TokenPSK("abc")
	want := sha256.Sum256([]byte("abc"))
	if !bytes.Equal(psk[:], want[:]) {
		t.Fatal("TokenPSK ≠ SHA256(token)")
	}
}
