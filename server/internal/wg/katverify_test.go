package wg

// katverify_test.go — Go-сторона проверяет СВОИ же KAT-векторы из файла
// (межъязыковой санитари: если файл есть — векторы самосогласованы).
import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestKATFileSelfVerify(t *testing.T) {
	b, err := os.ReadFile("/tmp/wg-kat.json")
	if err != nil {
		t.Skip("нет /tmp/wg-kat.json")
	}
	var k wgKAT
	if err := json.Unmarshal(b, &k); err != nil {
		t.Fatal(err)
	}
	// случайные ключи → нельзя сравнить с вектором; проверяем только боксы по ключам из вектора
	for _, box := range k.Boxes {
		keyHex := k.SendKeyC2S
		if box.Dir == "s2c" {
			keyHex = k.SendKeyS2C
		}
		key := mustHex(t, keyHex)
		plain, err := open(key, box.Counter, nil, mustHex(t, box.CipherHex)[MsgDataHeader:])
		if err != nil {
			t.Fatalf("box %s open: %v", box.Dir, err)
		}
		if hex.EncodeToString(plain) != box.PlainHex {
			t.Fatalf("box %s plain mismatch", box.Dir)
		}
		// детерминированный seal: шифртекст (после заголовка) обязан совпасть
		sealed, err := seal(key, box.Counter, nil, mustHex(t, box.PlainHex))
		if err != nil {
			t.Fatal(err)
		}
		wantCipher := mustHex(t, box.CipherHex)[MsgDataHeader:]
		if hex.EncodeToString(sealed) != hex.EncodeToString(wantCipher) {
			t.Fatalf("box %s seal mismatch", box.Dir)
		}
	}
	t.Log("KAT самосогласован (Go)")
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
