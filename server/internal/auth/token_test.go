package auth

import (
	"encoding/base64"
	"os"
	"testing"
	"time"

	"github.com/stelgen/reverseray/server/internal/rrp"
)

func writeFile(path, content string) {
	_ = os.WriteFile(path, []byte(content), 0o600)
}

func TestVerifyAndNonce(t *testing.T) {
	s := New()
	token := "secret-token-32-bytes-aaaaaaaaaaaa"
	s.tokens["phone-1"] = HashToken(token)

	nonce, _ := rrp.NewNonce()
	s.PutNonce(nonce, time.Minute)
	code := rrp.AuthCode(token, nonce, "sess-9")

	dev, ok := s.Verify(nonce, "sess-9", code)
	if !ok || dev != "phone-1" {
		t.Fatalf("verify failed: %q %v", dev, ok)
	}
	if !s.TakeNonce(nonce) {
		t.Fatal("nonce must be consumable")
	}
	if s.TakeNonce(nonce) {
		t.Fatal("nonce replay must fail")
	}
	// NOTE: nonce consumption is enforced by the server (TakeNonce before use);
	// Verify itself only checks the HMAC.
}

func TestWrongTokenFails(t *testing.T) {
	s := New()
	s.tokens["a"] = HashToken("token-a")
	nonce, _ := rrp.NewNonce()
	s.PutNonce(nonce, time.Minute)
	if _, ok := s.Verify(nonce, "s", rrp.AuthCode("token-b", nonce, "s")); ok {
		t.Fatal("wrong token must fail")
	}
}

func TestRateLimitAndLockout(t *testing.T) {
	s := New()
	ip := "203.0.113.7"
	for i := 0; i < maxHandshakesPerMin; i++ {
		if !s.AllowHandshake(ip) {
			t.Fatalf("attempt %d must pass", i)
		}
	}
	if s.AllowHandshake(ip) {
		t.Fatal("11th attempt must be rejected")
	}

	locked := false
	for i := 0; i < maxFailsBeforeLock; i++ {
		locked = s.ReportFailure(ip)
	}
	if !locked {
		t.Fatal("lockout must trigger")
	}
	if s.AllowHandshake(ip) {
		t.Fatal("locked IP must not handshake")
	}
	s.ResetFailures(ip)
	s2 := New()
	_ = s2
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/tokens.json"
	writeFile(p, `{"devices":{"phone-1":"`+base64.RawURLEncoding.EncodeToString(HashToken("t1"))+`"}}`)
	s := New()
	if err := s.LoadFile(p); err != nil {
		t.Fatal(err)
	}
	if len(s.Devices()) != 1 {
		t.Fatalf("devices: %v", s.Devices())
	}
	nonce, _ := rrp.NewNonce()
	s.PutNonce(nonce, time.Minute)
	if _, ok := s.Verify(nonce, "x", rrp.AuthCode("t1", nonce, "x")); !ok {
		t.Fatal("loaded token must verify")
	}
	writeFile(p, `{"devices":{}}`)
	if err := New().LoadFile(p); err == nil {
		t.Fatal("empty devices must error")
	}
}

func TestDecodeHash(t *testing.T) {
	raw := HashToken("x")
	b64 := base64.RawURLEncoding.EncodeToString(raw)
	got, err := DecodeHash(b64)
	if err != nil || len(got) != 32 {
		t.Fatalf("b64: %v", err)
	}
	hexStr := ""
	for _, b := range raw {
		hexStr += string("0123456789abcdef"[b>>4]) + string("0123456789abcdef"[b&15])
	}
	if _, err := DecodeHash(hexStr); err != nil {
		t.Fatalf("hex: %v", err)
	}
	if _, err := DecodeHash("short"); err == nil {
		t.Fatal("bad hash must fail")
	}
}
