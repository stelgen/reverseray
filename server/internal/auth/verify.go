package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

// v0.7.4: толерантность кодировок. Канон — base64url без паддинга
// (RawURLEncoding), но APK 0.7.3 слал HMAC в стандартном base64 (с «+ /»
// и «=») и получал «auth failed». Это по-прежнему ТО ЖЕ САМОЕ значение:
// принимаем все три кодировки, сравнение остаётся constant-time.
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

func verifyHash(tokenHash []byte, nonceB64, sessionID, provided string) bool {
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
