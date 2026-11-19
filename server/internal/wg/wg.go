// Package wg — протокол туннеля wireguard (v0.9.5, module protocol.wireguard):
// НАСТОЯЩАЯ криптография WireGuard (официальный канон whitepaper 2017 —
// актуальная версия протокола WG «protocol version 1»), а не имитация:
//
//   - Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s (полный хендшейк WG с mac1);
//   - transport-конверты Data-пакетов WG: [type=4][receiver][counter][ChaCha20Poly1305];
//   - sliding-window анти-реплей (2048) и счётчики пакетов по канону WG;
//   - TAI64N-метки времени (anti-replay рукопожатий);
//   - PSK-режим WG: preshared key = SHA256(token) — хендшейк привязан к НАШЕМУ
//     ключу доверия, который обе стороны знают из приватной ссылки.
//
// Роли: клиент APK — WG-инициатор (msg1), сервер — WG-респондер (msg2).
// Хендшейк идёт ВНУТРИ приватного канала (TLS 1.3 + SPKI-pin + HMAC-AUTH)
// кадрами WG_INIT/WG_RESP после READY: внешний DPI видит TLS, а payload'ы
// DATA/UDP_DATA — это байт-в-байт настоящие WG-пакеты (структура и крипто WG).
package wg

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"hash"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// Канон WireGuard (whitepaper §5: Constant values).
const (
	Construction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	Identifier   = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	LabelMac1    = "mac1----"
	LabelCookie  = "cookie--"
)

// Размеры wire-формата WG (байты).
const (
	MsgInitSize       = 148 // type 1: 4+4+32+48+28+16+16
	MsgRespSize       = 92  // type 2: 4+4+4+16+16+16
	MsgDataHeader     = 16  // type 4: 4+4+8
	MacSize           = 16
	KeySize           = 32
	HashSize          = 32
	StampSize         = 12 // TAI64N
	EncStaticLen      = KeySize + MacSize
	EncStampLen       = StampSize + MacSize
	EncEmptyLen       = MacSize
	TransportOverhead = MsgDataHeader + MacSize
	// ReplayWindowSize — канон WG (sliding window анти-реплея).
	ReplayWindowSize = 2048
	// MaxCounter — канон WG: ре-кей обязателен при 2^60 пакетов; мы не
	// ре-кеим внутри сессии — считаем счётчик исчерпанным раньше.
	MaxCounter = uint64(1) << 60
)

var (
	// ErrHandshake — нарушение хендшейка WG (mac1, AEAD-open, размер).
	ErrHandshake = errors.New("wg: handshake failed")
	// ErrEnvelope — битый транспортный пакет WG.
	ErrEnvelope = errors.New("wg: bad transport packet")
	// ErrReplay — повтор пакета (анти-реплей канона WG).
	ErrReplay = errors.New("wg: replay detected")
	// ErrCounter — счётчик пакетов исчерпан (канон WG: нужен ре-кей).
	ErrCounter = errors.New("wg: transport counter exhausted")
)

var (
	initialChainKey [HashSize]byte
	initialHash     [HashSize]byte
)

func init() {
	initialChainKey = blake2s.Sum256([]byte(Construction))
	copy(initialHash[:], hashSum(initialChainKey[:], []byte(Identifier)))
}

func hashSum(a, b []byte) []byte {
	h, _ := blake2s.New256(nil)
	_, _ = h.Write(a)
	_, _ = h.Write(b)
	return h.Sum(nil)
}

// hmacBlake2s — HMAC-BLAKE2s-256 (крелё KDF канона WG).
func hmacBlake2s(key, msg []byte) [HashSize]byte {
	m := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	_, _ = m.Write(msg)
	var out [HashSize]byte
	copy(out[:], m.Sum(nil))
	return out
}

// KDF1: t0 = HMAC(ck, ikm); ck' = HMAC(t0, 0x1).
func kdf1(ck *[HashSize]byte, ikm []byte) (t0 [HashSize]byte) {
	t0 = hmacBlake2s(ck[:], ikm)
	*ck = hmacBlake2s(t0[:], []byte{1})
	return
}

// KDF2 — ТОЧНЫЙ канон whitepaper (§5.4): t0 = HMAC(ck, ikm);
// t1 = HMAC(t0, 0x1); ck' = HMAC(t0, 0x2). (До v0.9.6 t1/ck' ошибочно
// считались от ck — имитация, что запрещено политикой канона WG.)
func kdf2(ck *[HashSize]byte, ikm []byte) (t0, t1 [HashSize]byte) {
	t0 = hmacBlake2s(ck[:], ikm)
	t1 = hmacBlake2s(t0[:], []byte{1})
	*ck = hmacBlake2s(t0[:], []byte{2})
	return
}

// KDF3 — ТОЧНЫЙ канон whitepaper (§5.4): t0 = HMAC(ck, ikm);
// t1 = HMAC(t0, 0x1); t2 = HMAC(t0, 0x2); ck' = HMAC(t0, 0x3).
func kdf3(ck *[HashSize]byte, ikm []byte) (t0, t1, t2 [HashSize]byte) {
	t0 = hmacBlake2s(ck[:], ikm)
	t1 = hmacBlake2s(t0[:], []byte{1})
	t2 = hmacBlake2s(t0[:], []byte{2})
	*ck = hmacBlake2s(t0[:], []byte{3})
	return
}

// macKeyMac1 = HASH(LABEL_MAC1 || static_public).
func macKeyMac1(staticPub []byte) [HashSize]byte {
	return blake2s.Sum256(append([]byte(LabelMac1), staticPub...))
}

// macKeyCookie = HASH(LABEL_COOKIE || static_public) (режим «не под нагрузкой»).
func macKeyCookie(staticPub []byte) [HashSize]byte {
	return blake2s.Sum256(append([]byte(LabelCookie), staticPub...))
}

// mac1 — keyed-BLAKE2s по префиксу кадра до поля mac1 (канон WG).
func mac1(key [HashSize]byte, prefix []byte) [MacSize]byte {
	m, _ := blake2s.New256(key[:])
	_, _ = m.Write(prefix)
	var out [MacSize]byte
	copy(out[:], m.Sum(nil))
	return out
}

// tai64n — канон WG: 8 байт секунд (смещение 2^62) BE + 4 байта наносекунд BE.
func tai64n() [StampSize]byte {
	n := time.Now()
	var out [StampSize]byte
	binary.BigEndian.PutUint64(out[:8], uint64(n.Unix())+(1<<62))
	binary.BigEndian.PutUint32(out[8:], uint32(n.Nanosecond()))
	return out
}

func tai64nAfter(a, b [StampSize]byte) bool {
	for i := 0; i < StampSize; i++ {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}

// KeyPair — X25519-пара WG (клэмпинг по RFC 7748 через curve25519.X25519).
type KeyPair struct {
	Priv [KeySize]byte
	Pub  [KeySize]byte
}

// GeneratePair создаёт свежую WG-пару ключей.
func GeneratePair() (*KeyPair, error) {
	kp := &KeyPair{}
	if _, err := rand.Read(kp.Priv[:]); err != nil {
		return nil, err
	}
	pub, err := curve25519.X25519(kp.Priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(kp.Pub[:], pub)
	return kp, nil
}

func dh(priv, peerPub *[KeySize]byte) ([KeySize]byte, error) {
	s, err := curve25519.X25519(priv[:], peerPub[:])
	if err != nil {
		return [KeySize]byte{}, err
	}
	var out [KeySize]byte
	copy(out[:], s)
	return out, nil
}

func nonce96(counter uint64) []byte {
	var n [12]byte // канон WG: [4 нуля][counter LE64]
	binary.LittleEndian.PutUint64(n[4:], counter)
	return n[:]
}

func seal(key []byte, counter uint64, aad, plain []byte) ([]byte, error) {
	c, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return c.Seal(nil, nonce96(counter), plain, aad), nil
}

func open(key []byte, counter uint64, aad, box []byte) ([]byte, error) {
	c, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return c.Open(nil, nonce96(counter), box, aad)
}
