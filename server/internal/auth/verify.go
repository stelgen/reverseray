package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

func verifyHash(tokenHash []byte, nonceB64, sessionID, provided string) bool {
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
