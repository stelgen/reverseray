// kdf.go — MTProto 2.0 KDF (канон, Security Guidelines):
//
//	msg_key_large = SHA256(auth_key[88+x : 120+x] + plaintext)
//	msg_key       = msg_key_large[8:24]
//	sha256_a      = SHA256(msg_key + auth_key[x : x+36])
//	sha256_b      = SHA256(auth_key[40+x : 40+x+52] + msg_key)
//	aes_key       = sha256_a[0:8] + sha256_b[8:24] + sha256_a[24:32]
//	aes_iv        = sha256_b[0:8] + sha256_a[8:24] + sha256_b[24:32]
//
// x = 0 — сообщения клиента серверу, x = 8 — сервера клиенту.
package mtproto

import "crypto/sha256"

const (
	kdfXClient = 0 // клиент → сервер
	kdfXServer = 8 // сервер → клиент
)

func kdfParams(authKey []byte, msgKey []byte, x int) (aesKey [32]byte, aesIV [32]byte) {
	ha := sha256.Sum256(append(append([]byte{}, msgKey...), authKey[x:x+36]...))
	hb := sha256.Sum256(append(append([]byte{}, authKey[40+x:40+x+52]...), msgKey...))
	copy(aesKey[0:8], ha[0:8])
	copy(aesKey[8:24], hb[8:24])
	copy(aesKey[24:32], ha[24:32])
	copy(aesIV[0:8], hb[0:8])
	copy(aesIV[8:24], ha[8:24])
	copy(aesIV[24:32], hb[24:32])
	return
}

// MsgKey computes MTProto 2.0 msg_key for a plaintext (with padding).
func msgKey(authKey []byte, x int, plaintext []byte) []byte {
	acc := append([]byte{}, authKey[88+x:120+x]...)
	sum := sha256.Sum256(append(acc, plaintext...))
	return sum[8:24]
}
