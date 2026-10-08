package rrp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// ---- shared JSON payloads ----

type Hello struct {
	Agent      string     `json:"agent"`
	Ver        FlexString `json:"ver"` // tolerant: и строка, и число (APK 0.7.3 слал число — см. CHANGELOG 0.7.4)
	Device     string     `json:"device"`
	Caps       []string   `json:"caps,omitempty"`
	MaxStreams int        `json:"max_streams"`
	// Proto — желаемый протокол клиента (значение &proto= из ссылки).
	// Пусто/мусор → сервер сводит к дефолту (см. Negotiate), никогда не ошибка.
	Proto FlexString `json:"proto,omitempty"`
	// Protocols — опциональный список протоколов, которые клиент поддерживает.
	Protocols []string `json:"protocols,omitempty"`
}

type HelloOK struct {
	SessionID    string `json:"session_id"`
	ServerVer    string `json:"server_ver"`
	Nonce        string `json:"nonce"` // base64url, single-use, TTL 60s
	TunnelWindow uint32 `json:"tunnel_window"`
	// Proto — выбранный протокол сессии; Protocols — полный реестр сервера
	// (клиент показывает список и может переключиться в настройках).
	Proto     string   `json:"proto"`
	Protocols []string `json:"protocols"`
}

type Auth struct {
	Mode string `json:"mode"` // "token-hmac"
	HMAC string `json:"hmac"` // base64url(HMAC-SHA256(key=SHA256(token), nonce||session_id))
}

type Ready struct {
	TunnelID     string   `json:"tunnel_id"`
	Role         string   `json:"role"`
	MaxStreams   int      `json:"max_streams"`
	TunnelWindow uint32   `json:"tunnel_window"`
	Proto        string   `json:"proto"`
	Protocols    []string `json:"protocols"`
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
// base64url — канон, но принимается и стандартный base64 (с паддингом и
// '+/'-алфавитом): старые клиенты 0.7.3 шляли HMAC в std-base64 и падали с
// «auth failed». Толерантность НЕ ослабляет безопасность: это лишь три
// кодировки одних и тех же байтов, сравнение остаётся constant-time.
func VerifyAuth(tokenHash []byte, nonceB64, sessionID, provided string) bool {
	nonce, err := decodeB64Any(nonceB64)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, tokenHash)
	mac.Write(nonce)
	mac.Write([]byte(sessionID))
	want := mac.Sum(nil)
	got, err := decodeB64Any(provided)
	if err != nil {
		return false
	}
	return hmac.Equal(want, got)
}

// DecodeB64Any декодирует base64url (с/без паддинга) или стандартный base64.
// Экспортирован для клиентов/тестов: канон — RawURLEncoding, но принимаем все кодировки.
func DecodeB64Any(s string) ([]byte, error) { return decodeB64Any(s) }

func decodeB64Any(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// NewNonce returns a fresh 128-bit nonce (base64url).
func NewNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// FlexString — JSON-строка, принимающая и число (клиент 0.7.3 слал
// "ver":1 числом — сервер 0.7.2/0.7.3 падал с «bad HELLO»), и строку.
// Маршалинг — всегда строка (канон для новых клиентов).
type FlexString string

func (f *FlexString) UnmarshalJSON(b []byte) error {
	s := string(b)
	// строка — снимаем кавычки и обрабатываем escape-ы через json
	if len(s) >= 2 && s[0] == '"' {
		var v string
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		*f = FlexString(v)
		return nil
	}
	// число/null/bool/мусор — берём литерал как текст ("1" → "1", null → "")
	if s == "null" {
		*f = ""
		return nil
	}
	*f = FlexString(s)
	return nil
}

func (f FlexString) MarshalJSON() ([]byte, error) { return json.Marshal(string(f)) }

// String returns the value as a plain string.
func (f FlexString) String() string { return string(f) }

func NewID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x-%d", b, time.Now().UnixNano()&0xFFFF)
}
