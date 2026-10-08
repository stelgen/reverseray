// dh.go — DH-обмен для mtproto2: канон MTProto.
//
// ПАРАМЕТРЫ — официальный dh_prime Telegram (опубликован в MTProto
// Security Guidelines как «known good», сами guidelines рекомендуют
// вшивать его в клиента): 2048-битный SAFE prime (p и (p−1)/2 оба простые,
// проверено тестом TestTelegramDHPrimeIsSafePrime), p mod 3 = 2 →
// генератор g = 3 порождает подгруппу квадратичных вычетов порядка (p−1)/2.
//
// ВАЛИДАЦИЯ ПУБЛИЧНЫХ ДОЛЕЙ — по канону guidelines: g_peer > 1 и
// g_peer < p−1 (обязательно) + рекомендованный коридор
// [2^(2048−64), p − 2^(2048−64)] = [2^1984, p − 2^1984].
package mtproto

import (
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"
	"math/big"
)

// dhPrimeHex — официальный dh_prime Telegram (без изменений, байт-в-байт
// из core.telegram.org/mtproto/security_guidelines).
const dhPrimeHex = "C71CAEB9C6B1C9048E6C522F70F13F73980D40238E3E21C14934D037563D930F" +
	"48198A0AA7C14058229493D22530F4DBFA336F6E0AC925139543AED44CCE7C37" +
	"20FD51F69458705AC68CD4FE6B6B13ABDC9746512969328454F18FAF8C595F64" +
	"2477FE96BB2A941D5BCD1D4AC8CC49880708FA9B378E3C4F3A9060BEE67CF9A4" +
	"A4A695811051907E162753B56B0F6B410DBA74D8A84B2A14B3144E0EF1284754" +
	"FD17ED950D5965B4B9DD46582DB1178D169C6BC465B0D6FF9CA3928FEF5B9AE4" +
	"E418FC15E83EBEA0F87FA9FF5EED70050DED2849F47BF959D956850CE929851F" +
	"0D8115F635B105EE2E4E15D04B2454BF6F4FADF034B10403119CD8E3B92FCC5B"

var (
	// P — 2048-битный safe prime (канон Telegram).
	P = mustHexBig(dhPrimeHex)
	// G — генератор 3 (guidelines: p mod 3 = 2 → g=3 — квадратичный вычет).
	G = big.NewInt(3)

	// Границы канона: 1 < peer < P−1 и (рекомендация guidelines) peer ∈
	// [2^1984, P − 2^1984], где 1984 = 2048−64.
	boundLow  = new(big.Int).Lsh(big.NewInt(1), 2048-64)
	boundHigh = new(big.Int).Sub(P, new(big.Int).Lsh(big.NewInt(1), 2048-64))
)

func mustHexBig(h string) *big.Int {
	v, ok := new(big.Int).SetString(h, 16)
	if !ok {
		panic("mtproto: bad dh_prime constant")
	}
	return v
}

// KeyPair — приватная/публичная доли DH.
type KeyPair struct {
	Priv   *big.Int
	Public *big.Int // g^priv mod P
}

// GeneratePair генерирует пару, повторяя до попадания ПУБЛИЧНОЙ доли
// в канонический коридор (guidelines требуют его и для своей доли).
func GeneratePair() (*KeyPair, error) {
	for i := 0; i < 64; i++ {
		// приватная доля: 2048 бит (256 байт), нормирована в коридор
		buf := make([]byte, 256)
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		x := new(big.Int).SetBytes(buf)
		x.Mod(x, new(big.Int).Sub(P, boundLow))
		x.Add(x, boundLow)
		pub := new(big.Int).Exp(G, x, P)
		if ValidatePublic(pub) == nil {
			return &KeyPair{Priv: x, Public: pub}, nil
		}
	}
	return nil, errors.New("mtproto: не удалось сгенерировать валидную пару")
}

// ValidatePublic проверяет публичную долю пира по канону guidelines:
//
//	1 < peer < P−1 (обязательно) и peer ∈ [2^1984, P − 2^1984] (рекомендация).
func ValidatePublic(pub *big.Int) error {
	if pub == nil {
		return errors.New("mtproto: пустая публичная доля")
	}
	one := big.NewInt(1)
	if pub.Cmp(one) <= 0 {
		return errors.New("mtproto: g_peer <= 1")
	}
	if pub.Cmp(new(big.Int).Sub(P, one)) >= 0 {
		return errors.New("mtproto: g_peer >= P-1")
	}
	if pub.Cmp(boundLow) < 0 {
		return errors.New("mtproto: g_peer < 2^1984 (вне рекомендованного коридора)")
	}
	if pub.Cmp(boundHigh) > 0 {
		return errors.New("mtproto: g_peer > P - 2^1984 (вне рекомендованного коридора)")
	}
	return nil
}

// Shared computes g_ab = peer^priv mod P и возвращает 256-байтовый
// auth_key (big-endian g_ab, левое дополнение нулями).
func (kp *KeyPair) Shared(peer *big.Int) ([]byte, error) {
	if err := ValidatePublic(peer); err != nil {
		return nil, err
	}
	gab := new(big.Int).Exp(peer, kp.Priv, P)
	if gab.Cmp(boundLow) < 0 || gab.Cmp(boundHigh) > 0 {
		return nil, errors.New("mtproto: g_ab вне рекомендованного коридора")
	}
	return padded256(gab), nil
}

func padded256(v *big.Int) []byte {
	b := v.Bytes()
	if len(b) > 256 {
		b = b[len(b)-256:] // не должно случиться (g_ab < P)
	}
	out := make([]byte, 256)
	copy(out[256-len(b):], b)
	return out
}

// AuthKeyID — маркер ключа: SHA1(auth_key)[0:8] (канон MTProto).
func AuthKeyID(authKey []byte) []byte {
	sum := sha1.Sum(authKey) // #nosec G401: предписан спецификацией MTProto как маркер ключа
	return sum[:8]
}

// PublicBytes — публичная доля как ровно 256 байт big-endian.
func PublicBytes(pub *big.Int) []byte { return padded256(pub) }

// PublicFromBytes — парс публичной доли (ровно 256 байт).
func PublicFromBytes(b []byte) (*big.Int, error) {
	if len(b) != 256 {
		return nil, fmt.Errorf("mtproto: публичная доля должна быть 256 байт, получили %d", len(b))
	}
	return new(big.Int).SetBytes(b), nil
}
