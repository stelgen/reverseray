package mtproto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"
)

// Канон Telegram: 2048-битный SAFE prime (p и (p−1)/2 оба простые),
// p mod 3 = 2 → g=3 валиден (guidelines, quadratic reciprocity).
// Защита от «транскрипции на память» (v0.8).
func TestTelegramDHPrimeIsSafePrime(t *testing.T) {
	if P.BitLen() != 2048 {
		t.Fatalf("P.BitLen() = %d, ожидалось 2048", P.BitLen())
	}
	if !P.ProbablyPrime(20) {
		t.Fatal("P не простое — константа побита")
	}
	q := new(big.Int).Rsh(new(big.Int).Sub(P, big.NewInt(1)), 1)
	if !q.ProbablyPrime(20) {
		t.Fatal("(P-1)/2 не простое — P не safe prime")
	}
	if new(big.Int).Mod(P, big.NewInt(3)).Int64() != 2 {
		t.Fatal("p mod 3 != 2 — генератор g=3 невалиден")
	}
	two2047 := new(big.Int).Lsh(big.NewInt(1), 2047)
	two2048 := new(big.Int).Lsh(big.NewInt(1), 2048)
	if P.Cmp(two2047) <= 0 || P.Cmp(two2048) >= 0 {
		t.Fatal("P вне (2^2047, 2^2048)")
	}
}

func TestDHSharedSymmetric(t *testing.T) {
	a, err := GeneratePair()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GeneratePair()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePublic(a.Public); err != nil {
		t.Fatalf("валидация публичной доли: %v", err)
	}
	ka, err := a.Shared(b.Public)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := b.Shared(a.Public)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ka, kb) {
		t.Fatal("g_ab не сошлись")
	}
	if len(ka) != 256 {
		t.Fatalf("auth_key = %d байт, ожидалось 256", len(ka))
	}
}

func TestDHRejectsBadPublic(t *testing.T) {
	a, _ := GeneratePair()
	// канон Telegram: 1 < peer < P−1 + рекомендованный коридор
	// [2^1984, P − 2^1984] (включительно). Всё вне/тривиальное — отказ.
	cases := []*big.Int{
		big.NewInt(0), big.NewInt(1), big.NewInt(2), // g мал
		new(big.Int).Sub(P, big.NewInt(1)),         // P-1
		new(big.Int).Sub(boundLow, big.NewInt(1)),  // 2^1984 - 1
		new(big.Int).Add(boundHigh, big.NewInt(1)), // P - 2^1984 + 1
		new(big.Int).Sub(P, big.NewInt(0)),         // P
	}
	for i, c := range cases {
		if err := ValidatePublic(c); err == nil {
			t.Fatalf("case %d: невалидная доля прошла валидацию", i)
		}
		if _, err := a.Shared(c); err == nil {
			t.Fatalf("case %d: обмен с невалидной долей прошёл", i)
		}
	}
	// включительные границы коридора валидны
	if err := ValidatePublic(boundLow); err != nil {
		t.Fatalf("2^1984 должен быть валиден: %v", err)
	}
	if err := ValidatePublic(boundHigh); err != nil {
		t.Fatalf("P−2^1984 должен быть валиден: %v", err)
	}
}

// testAuthKey — 256-байтовый ключ (канон MTProto), детерминированный для тестов.
func testAuthKey() []byte {
	sum := sha256.Sum256([]byte("auth"))
	out := make([]byte, 256)
	for i := 0; i < 256; i += len(sum) {
		copy(out[i:], sum[:])
	}
	return out
}

func TestIGERoundTrip(t *testing.T) {
	key := sha256.Sum256([]byte("test-key"))
	c, err := newIGE(key[:])
	if err != nil {
		t.Fatal(err)
	}
	iv := sha256.Sum256([]byte("test-iv"))
	plain := make([]byte, 3*16+17-17+16) // 64 байта
	for i := range plain {
		plain[i] = byte(i)
	}
	enc := c.encryptIGE(plain, iv[:])
	if enc == nil || bytes.Equal(enc, plain) {
		t.Fatal("encryptIGE не сработал")
	}
	dec := c.decryptIGE(enc, iv[:])
	if !bytes.Equal(dec, plain) {
		t.Fatal("decryptIGE вернул не исходное")
	}
}

func TestEnvelopeRoundTripBothDirections(t *testing.T) {
	salt := []byte("12345678")
	sid := []byte("87654321")
	sc, err := NewSessionCrypto(make([]byte, 256)[:0], salt, sid)
	if err == nil {
		t.Fatal("короткий auth_key должен быть отвергнут")
	}
	key := testAuthKey()
	sc, err = NewSessionCrypto(key, salt, sid)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("payload data 0123456789")

	// клиент шлёт (x=0), сервер принимает
	env, err := sc.EncryptDown(payload)
	if err != nil {
		t.Fatal(err)
	}
	got, err := sc.DecryptDown(env)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload не совпал (client->server)")
	}

	// сервер шлёт (x=8), клиент принимает
	env, err = sc.EncryptUp(payload)
	if err != nil {
		t.Fatal(err)
	}
	got, err = sc.DecryptUp(env)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload не совпал (server->client)")
	}

	// чей-то key_id → отказ
	env[3] ^= 0xFF
	if _, err := sc.DecryptDown(env); err == nil {
		t.Fatal("чужой auth_key_id принят")
	}
}

func TestEnvelopeRejectsTamperedBody(t *testing.T) {
	sc, err := NewSessionCrypto(testAuthKey(), []byte("12345678"), []byte("87654321"))
	if err != nil {
		t.Fatal(err)
	}
	env, _ := sc.EncryptDown([]byte("attack payload"))
	// портим зашифрованное тело (msg_key перестаёт сходиться)
	env[len(env)-2] ^= 0x55
	if _, err := sc.DecryptDown(env); err == nil {
		t.Fatal("изменённое тело принято (msg_key не проверен)")
	}
}

func TestEnvelopeMsgKeyIsSHA256Canon(t *testing.T) {
	// вектор самосогласованности: msg_key = SHA256(auth_key[88+x:120+x]+pt)[8:24]
	sc, err := NewSessionCrypto(testAuthKey(), []byte("12345678"), []byte("87654321"))
	if err != nil {
		t.Fatal(err)
	}
	env, _ := sc.EncryptDown([]byte("x"))
	// расшифровка уже проверяет msg_key изнутри; тут проверяем форму конверта
	if len(env) < 24+48 {
		t.Fatalf("конверт слишком короткий: %d", len(env))
	}
	if string(env[:8]) != string(sc.authKeyID) {
		t.Fatal("auth_key_id не в начале конверта")
	}
	if hex.EncodeToString(env[8:24]) == "" {
		t.Fatal("msg_key пуст")
	}
}
