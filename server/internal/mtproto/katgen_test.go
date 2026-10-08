package mtproto

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// TestGenKAT — НЕ регресс-тест, а генератор кросс-языкового вектора:
// `go test -run TestGenKAT` пишет /tmp/mtproto-kat.json для Kotlin-тестов.
// В обычных прогонах skip (файл уже закоммичен в testdata).
func TestGenKAT(t *testing.T) {
	out := os.Getenv("RR_KAT_OUT")
	if out == "" {
		t.Skip("RR_KAT_OUT не задан — генерация вектора не нужна")
	}
	key := sha256.Sum256([]byte("cross-lang-kat"))
	authKey := make([]byte, 256)
	for i := 0; i < 256; i += len(key) {
		copy(authKey[i:], key[:])
	}
	salt := []byte("SALT1234")
	sid := []byte("SESSID88")
	payload := []byte("ReverseRay MTProto 2.0 cross-language test vector 0123456789")

	build := func(x int, msgID uint64) []byte {
		total := 32 + len(payload)
		padLen := 16 - total%16
		if padLen < 16 {
			padLen += 16
		}
		inner := make([]byte, 0, total+padLen)
		inner = append(inner, salt...)
		inner = append(inner, sid...)
		var mid [8]byte
		binary.BigEndian.PutUint64(mid[:], msgID)
		inner = append(inner, mid[:]...)
		var sq [4]byte
		binary.BigEndian.PutUint32(sq[:], 2)
		inner = append(inner, sq[:]...)
		var ln [4]byte
		binary.BigEndian.PutUint32(ln[:], uint32(len(payload)))
		inner = append(inner, ln[:]...)
		inner = append(inner, payload...)
		inner = append(inner, make([]byte, padLen)...) // нулевой паддинг (детерминизм)
		mk := msgKey(authKey, x, inner)
		aesKey, aesIV := kdfParams(authKey, mk, x)
		c, err := newIGE(aesKey[:])
		if err != nil {
			t.Fatal(err)
		}
		enc := c.encryptIGE(inner, aesIV[:])
		env := append([]byte{}, AuthKeyID(authKey)...)
		env = append(env, mk...)
		return append(env, enc...)
	}

	doc := map[string]string{
		"auth_key":   hex.EncodeToString(authKey),
		"salt":       hex.EncodeToString(salt),
		"session_id": hex.EncodeToString(sid),
		"payload":    string(payload),
		"env_client": hex.EncodeToString(build(kdfXClient, 4)),
		"env_server": hex.EncodeToString(build(kdfXServer, 5)),
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	if err := os.WriteFile(out, b, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("KAT written: %s", out)
}
