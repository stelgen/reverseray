package rrp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"
)

// ---- shared JSON payloads ----

type Hello struct {
	Agent      string   `json:"agent"`
	Ver        string   `json:"ver"`
	Device     string   `json:"device"`
	Caps       []string `json:"caps,omitempty"`
	MaxStreams int      `json:"max_streams"`
}

type HelloOK struct {
	SessionID    string `json:"session_id"`
	ServerVer    string `json:"server_ver"`
	Nonce        string `json:"nonce"` // base64url, single-use, TTL 60s
	TunnelWindow uint32 `json:"tunnel_window"`
}

type Auth struct {
	Mode string `json:"mode"` // "token-hmac"
	HMAC string `json:"hmac"` // base64url(HMAC-SHA256(key=SHA256(token), nonce||session_id))
}

type Ready struct {
	TunnelID     string `json:"tunnel_id"`
	Role         string `json:"role"`
	MaxStreams   int    `json:"max_streams"`
	TunnelWindow uint32 `json:"tunnel_window"`
}

// TokenHash derives the server-side stored value and the HMAC key for a token.
// The server never stores raw tokens — only SHA256(token), which doubles as the
// HMAC key (hardening: DB leak does not leak tokens).
func TokenHash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// AuthCode computes the client-side AUTH value.
func AuthCode(token, nonceB64, sessionID string) string {
	nonce, err := base64.RawURLEncoding.DecodeString(nonceB64)
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, TokenHash(token))
	mac.Write(nonce)
	mac.Write([]byte(sessionID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// VerifyAuth is constant-time per candidate; server iterates its (few) tokens.
func VerifyAuth(tokenHash []byte, nonceB64, sessionID, provided string) bool {
	nonce, err := base64.RawURLEncoding.DecodeString(nonceB64)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, tokenHash)
	mac.Write(nonce)
	mac.Write([]byte(sessionID))
	want := mac.Sum(nil)
	got, err := base64.RawURLEncoding.DecodeString(provided)
	if err != nil {
		return false
	}
	return hmac.Equal(want, got)
}

// NewNonce returns a fresh 128-bit nonce (base64url).
func NewNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func NewID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x-%d", b, time.Now().UnixNano()&0xFFFF)
}
