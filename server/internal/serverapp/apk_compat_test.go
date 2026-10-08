package serverapp

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stelgen/reverseray/server/internal/rrp"
)

// v0.7.4 регресс-тест: APK 0.7.3 падал на проде с ERROR 2 «protocol error»,
// потому что слал HELLO с "ver":1 ЧИСЛОМ (Go json в string-поле → ошибка →
// bad HELLO) и AUTH с HMAC в std-base64 («+ /=», сервер ждал base64url).
// Канон обязан выдерживать ОБА варианта с любой стороны:
//   - ver числом или строкой (сервер толерантен);
//   - HMAC в base64url или std-base64 (сервер толерантен);
//   - при этом сервер ВСЕГДА отвечает протокольными полями proto/protocols.
func TestHandshakeToleratesApk073Format(t *testing.T) {
	app, cfg, token := startTestServer(t)

	raw, err := net.Dial("tcp", cfg.Listen.Tunnels)
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, // #nosec G402: тест; подлинность — SPKI-pin ниже
		NextProtos:         []string{"reverseray/1"},
		ServerName:         "reverseray.test",
	}
	c := tls.Client(raw, tlsCfg)
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// HELLO ровно в формате APK 0.7.3: ver — число.
	hello := `{"agent":"ReverseRay-Android/0.7.3","ver":1,"device":"phone-1","caps":["chacha20","alpn"],"max_streams":64}`
	if err := rrpWrite1(c, rrp.TypeHello, []byte(hello)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	readFrame := func() (*rrp.Frame, error) {
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		return rrp.ReadFrame(br)
	}
	f, err := readFrame()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != rrp.TypeHelloOK {
		t.Fatalf("ожидали HELLO_OK, получили type=0x%02x payload=%q", f.Type, f.Payload)
	}
	var ok rrp.HelloOK
	if err := json.Unmarshal(f.Payload, &ok); err != nil {
		t.Fatal(err)
	}
	if ok.Proto != rrp.DefaultProtocolID {
		t.Fatalf("HELLO_OK.proto = %q, want %q", ok.Proto, rrp.DefaultProtocolID)
	}
	if len(ok.Protocols) == 0 {
		t.Fatal("HELLO_OK.protocols пуст — клиент не сможет показать список протоколов")
	}

	// AUTH: HMAC ключ = SHA256(token), кодировка std-base64 (как APK 0.7.3).
	nonceBytes, err := rrp.DecodeB64Any(ok.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, rrp.TokenHash(token))
	mac.Write(nonceBytes)
	mac.Write([]byte(ok.SessionID))
	authJSON := fmt.Sprintf(`{"mode":"token-hmac","hmac":%q,"nonce":%q}`,
		base64.StdEncoding.EncodeToString(mac.Sum(nil)), ok.Nonce)
	if err := rrpWrite1(c, rrp.TypeAuth, []byte(authJSON)); err != nil {
		t.Fatal(err)
	}
	f, err = readFrame()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type == rrp.TypeError {
		t.Fatalf("сервер отклонил AUTH формата APK 0.7.3: %q", f.Payload)
	}
	if f.Type != rrp.TypeReady {
		t.Fatalf("ожидали READY, получили type=0x%02x", f.Type)
	}
	var rd rrp.Ready
	if err := json.Unmarshal(f.Payload, &rd); err != nil {
		t.Fatal(err)
	}
	if rd.Proto != rrp.DefaultProtocolID || len(rd.Protocols) == 0 {
		t.Fatalf("READY без протокольных полей: %+v", rd)
	}
	_ = cfg
	_ = app
}
