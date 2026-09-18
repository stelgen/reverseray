package rrp

import (
	"bytes"
	"net"
	"testing"
)

func TestFrameRoundtrip(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("hello world")
	if err := WriteFrame(&buf, TypeData, 0x42, 7, payload); err != nil {
		t.Fatal(err)
	}
	f, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != TypeData || f.Flags != 0x42 || f.StreamID != 7 || !bytes.Equal(f.Payload, payload) {
		t.Fatalf("roundtrip mismatch: %+v", f)
	}
}

func TestFrameOversizedRejected(t *testing.T) {
	big := make([]byte, MaxDataPayload+1)
	if err := WriteFrame(&bytes.Buffer{}, TypeData, 0, 1, big); err == nil {
		t.Fatal("write should reject oversized DATA")
	}
	// Craft raw header claiming oversized payload.
	raw := []byte{1, TypeData, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0} // len 65536+... 0x00010000
	if _, err := ReadFrame(bytes.NewReader(raw)); err == nil {
		t.Fatal("read should reject oversized DATA")
	}
	// Control frames have a tighter limit.
	if MaxPayloadFor(TypeAuth) != MaxControlPayload {
		t.Fatal("control limit wrong")
	}
}

func TestFrameTruncated(t *testing.T) {
	raw := []byte{1, TypeData, 0, 0, 0, 0, 0, 1}
	if _, err := ReadFrame(bytes.NewReader(raw)); err == nil {
		t.Fatal("short header must fail")
	}
	full := []byte{1, TypeData, 0, 0, 0, 0, 0, 1, 0, 0, 0, 3, 1, 2}
	if _, err := ReadFrame(bytes.NewReader(full)); err == nil {
		t.Fatal("short payload must fail")
	}
}

func TestOpenPayloadRoundtrip(t *testing.T) {
	p := EncodeOpen(ATYPDomain, []byte("example.com"), 443)
	atyp, addr, port, err := DecodeOpen(p)
	if err != nil || atyp != ATYPDomain || string(addr) != "example.com" || port != 443 {
		t.Fatalf("domain roundtrip: %v %q %d", err, addr, port)
	}
	ip := EncodeOpen(ATYPIPv4, []byte{8, 8, 8, 8}, 53)
	atyp, addr, port, err = DecodeOpen(ip)
	if err != nil || atyp != ATYPIPv4 || net.IP(addr).String() != "8.8.8.8" || port != 53 {
		t.Fatalf("ipv4 roundtrip: %v %q %d", err, addr, port)
	}
	// Malformed payloads must not panic.
	for _, bad := range [][]byte{nil, {1}, {3, 255}, {4, 1, 2}, {9, 1, 2, 3, 4, 5, 6}} {
		if _, _, _, err := DecodeOpen(bad); err == nil && len(bad) > 3 {
			t.Fatalf("expected error for %v", bad)
		}
	}
}

func TestErrorPayload(t *testing.T) {
	p := EncodeError(0x10, "boom")
	code, msg := DecodeError(p)
	if code != 0x10 || msg != "boom" {
		t.Fatalf("got %d %q", code, msg)
	}
	long := make([]byte, 400)
	p = EncodeError(1, string(long))
	_, msg = DecodeError(p)
	if len(msg) != 256 {
		t.Fatalf("msg should be capped to 256, got %d", len(msg))
	}
}

func TestAuthCode(t *testing.T) {
	tok := "test-token"
	nonce, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	code := AuthCode(tok, nonce, "sess-1")
	if !VerifyAuth(TokenHash(tok), nonce, "sess-1", code) {
		t.Fatal("valid auth rejected")
	}
	if VerifyAuth(TokenHash("other"), nonce, "sess-1", code) {
		t.Fatal("wrong token accepted")
	}
	if VerifyAuth(TokenHash(tok), nonce, "sess-2", code) {
		t.Fatal("HMAC must be bound to session id")
	}
}
