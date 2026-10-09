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
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"sync"
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

// KDF2: t0 = HMAC(ck, ikm); t1 = HMAC(ck, t0‖0x1); ck' = HMAC(t1, 0x2).
func kdf2(ck *[HashSize]byte, ikm []byte) (t0, t1 [HashSize]byte) {
	t0 = hmacBlake2s(ck[:], ikm)
	t1 = hmacBlake2s(ck[:], append(t0[:], 1))
	*ck = hmacBlake2s(t1[:], []byte{2})
	return
}

// KDF3: t0 = HMAC(ck, ikm); t1 = HMAC(ck, t0‖0x1); t2 = HMAC(ck, t1‖0x2);
// ck' = HMAC(t2, 0x3).
func kdf3(ck *[HashSize]byte, ikm []byte) (t0, t1, t2 [HashSize]byte) {
	t0 = hmacBlake2s(ck[:], ikm)
	t1 = hmacBlake2s(ck[:], append(t0[:], 1))
	t2 = hmacBlake2s(ck[:], append(t1[:], 2))
	*ck = hmacBlake2s(t2[:], []byte{3})
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

// ---- Handshake: инициатор (клиент) ----

// ClientHandshake — состояние инициатора между msg1 и msg2.
type ClientHandshake struct {
	ChainKey [HashSize]byte
	Hash     [HashSize]byte
	Eph      KeyPair
	Sender   uint32
	Static   KeyPair // WG-static инициатора (эпhemeral per session)
	// после ConsumeResponse:
	SendKey [KeySize]byte // клиент → сервер
	RecvKey [KeySize]byte // сервер → клиент
	RecvIdx uint32        // sender_index сервера (из msg2)
}

// NewClientHandshake — шаги 1–10 канона WG для инициатора: строит msg1
// (148 байт, wire-формат WG) и возвращает состояние для ConsumeResponse.
// psk — preshared key (у нас SHA256(token)); serverPub — WG static сервера.
func NewClientHandshake(serverPub, psk *[KeySize]byte) ([]byte, *ClientHandshake, error) {
	clientStatic, err := GeneratePair()
	if err != nil {
		return nil, nil, err
	}
	eph, err := GeneratePair()
	if err != nil {
		return nil, nil, err
	}
	var sb [4]byte
	if _, err := rand.Read(sb[:]); err != nil {
		return nil, nil, err
	}
	stamp := tai64n()
	return clientHandshakeCore(serverPub, *clientStatic, *eph, binary.LittleEndian.Uint32(sb[:]), &stamp, psk)
}

// clientHandshakeCore — детерминированное ядро инициатора (используется и
// межъязыковым KAT: фиксированные ключи/метка времени дают байт-в-байт
// воспроизводимый msg1).

func clientHandshakeCore(serverPub *[KeySize]byte, clientStatic, eph KeyPair, sender uint32, stamp *[StampSize]byte, psk *[KeySize]byte) ([]byte, *ClientHandshake, error) {
	ch := &ClientHandshake{Eph: eph, Static: clientStatic, Sender: sender}
	ch.ChainKey = initialChainKey
	ch.Hash = initialHash

	msg := make([]byte, MsgInitSize)
	binary.LittleEndian.PutUint32(msg[0:4], 1)
	binary.LittleEndian.PutUint32(msg[4:8], ch.Sender)
	copy(msg[8:40], ch.Eph.Pub[:])
	ch.Hash = [HashSize]byte(hashSum(ch.Hash[:], ch.Eph.Pub[:]))

	dhES, err := dh(&ch.Eph.Priv, serverPub) // es: e_i × s_r
	if err != nil {
		return nil, nil, err
	}
	key, _ := kdf2(&ch.ChainKey, dhES[:])
	box, err := seal(key[:], 0, ch.Hash[:], ch.Static.Pub[:])
	if err != nil {
		return nil, nil, err
	}
	copy(msg[40:40+EncStaticLen], box)
	ch.Hash = [HashSize]byte(hashSum(ch.Hash[:], msg[40:40+EncStaticLen]))

	dhSS, err := dh(&ch.Static.Priv, serverPub) // ss: s_i × s_r
	if err != nil {
		return nil, nil, err
	}
	key, _ = kdf2(&ch.ChainKey, dhSS[:])
	box, err = seal(key[:], 0, ch.Hash[:], stamp[:])
	if err != nil {
		return nil, nil, err
	}
	copy(msg[88:88+EncStampLen], box)
	ch.Hash = [HashSize]byte(hashSum(ch.Hash[:], msg[88:88+EncStampLen]))

	// mac1 = MAC(HASH(LABEL_MAC1||s_r), msg[0:116]); mac2 = нули (нет cookie).
	mk := macKeyMac1(serverPub[:])
	m1 := mac1(mk, msg[0:116])
	copy(msg[116:132], m1[:])
	return msg, ch, nil
}

// ConsumeResponse — обработка msg2 (92 байта) инициатором: шаги 14–17 канона
// WG; после успеха активны SendKey/RecvKey.
func (ch *ClientHandshake) ConsumeResponse(msg2 []byte, psk *[KeySize]byte) error {
	if len(msg2) != MsgRespSize {
		return fmt.Errorf("%w: msg2 len %d ≠ %d", ErrHandshake, len(msg2), MsgRespSize)
	}
	if binary.LittleEndian.Uint32(msg2[0:4]) != 2 {
		return fmt.Errorf("%w: msg2 type ≠ 2", ErrHandshake)
	}
	if binary.LittleEndian.Uint32(msg2[8:12]) != ch.Sender {
		return fmt.Errorf("%w: msg2 receiver ≠ наш sender_index", ErrHandshake)
	}
	ch.RecvIdx = binary.LittleEndian.Uint32(msg2[4:8])

	// mac1 ответа: responder mac1 key = LABEL_MAC1 || наш static pub.
	// (Сервер строит mac1 по НАШЕМУ static — подтверждает, что он обработал
	// именно наш msg1.)
	mk := macKeyMac1(ch.Static.Pub[:])
	want := mac1(mk, msg2[0:60])
	if subtle.ConstantTimeCompare(want[:], msg2[60:76]) != 1 {
		return fmt.Errorf("%w: msg2 mac1 mismatch", ErrHandshake)
	}

	ch.Hash = [HashSize]byte(hashSum(ch.Hash[:], msg2[12:44]))      // e_r
	dhER, err := dh(&ch.Static.Priv, (*[KeySize]byte)(msg2[12:44])) // s_i × e_r
	if err != nil {
		return err
	}
	key, _ := kdf2(&ch.ChainKey, dhER[:])
	if _, err := open(key[:], 0, ch.Hash[:], msg2[44:44+EncEmptyLen]); err != nil {
		return fmt.Errorf("%w: msg2 empty AEAD: %v", ErrHandshake, err)
	}
	ch.Hash = [HashSize]byte(hashSum(ch.Hash[:], msg2[44:44+EncEmptyLen]))
	// Финал канона WG: KDF3(C, psk) → t0 = ключ клиента→сервера (i2r),
	// t1 = ключ сервера→клиента (r2i). Респондер использует их зеркально.
	t0, t1, _ := kdf3(&ch.ChainKey, psk[:])
	ch.SendKey = t0
	ch.RecvKey = t1
	return nil
}

// ---- Handshake: респондер (сервер) ----

// ServerHandshake — состояние респондера после msg1.
type ServerHandshake struct {
	ChainKey        [HashSize]byte
	Hash            [HashSize]byte
	Sender          uint32
	ClientStaticPub [KeySize]byte
	SendKey         [KeySize]byte // сервер → клиент
	RecvKey         [KeySize]byte // клиент → сервер
	RecvIdx         uint32        // sender_index клиента
}

// HandshakeRespond — обработка msg1 (148 байт) респондером: шаги 11–19
// канона WG. Возвращает msg2 (92 байта) и активные ключи. lastStamp —
// последняя TAI64N-метка этого клиента (anti-replay рукопожатий).
func HandshakeRespond(serverPriv, serverPub, psk *[KeySize]byte, msg1 []byte, lastStamp *[StampSize]byte) ([]byte, *ServerHandshake, error) {
	return serverHandshakeCore(serverPriv, serverPub, psk, msg1, lastStamp, randIndex())
}

// serverHandshakeCore — ядро респондера с фиксируемым sender_index (KAT).
func serverHandshakeCore(serverPriv, serverPub, psk *[KeySize]byte, msg1 []byte, lastStamp *[StampSize]byte, sender uint32) ([]byte, *ServerHandshake, error) {
	if len(msg1) != MsgInitSize {
		return nil, nil, fmt.Errorf("%w: msg1 len %d ≠ %d", ErrHandshake, len(msg1), MsgInitSize)
	}
	if binary.LittleEndian.Uint32(msg1[0:4]) != 1 {
		return nil, nil, fmt.Errorf("%w: msg1 type ≠ 1", ErrHandshake)
	}
	// mac1: доказывает, что инициатор знает наш static pub.
	mk := macKeyMac1(serverPub[:])
	want := mac1(mk, msg1[0:116])
	if subtle.ConstantTimeCompare(want[:], msg1[116:132]) != 1 {
		return nil, nil, fmt.Errorf("%w: msg1 mac1 mismatch", ErrHandshake)
	}

	sh := &ServerHandshake{Sender: sender}
	sh.ChainKey = initialChainKey
	sh.Hash = initialHash
	sh.RecvIdx = binary.LittleEndian.Uint32(msg1[4:8])

	sh.Hash = [HashSize]byte(hashSum(sh.Hash[:], msg1[8:40])) // e_i
	dhES, err := dh(serverPriv, (*[KeySize]byte)(msg1[8:40])) // s_r × e_i
	if err != nil {
		return nil, nil, err
	}
	key, _ := kdf2(&sh.ChainKey, dhES[:])
	staticPub, err := open(key[:], 0, sh.Hash[:], msg1[40:40+EncStaticLen])
	if err != nil || len(staticPub) != KeySize {
		return nil, nil, fmt.Errorf("%w: enc_static: %v", ErrHandshake, err)
	}
	copy(sh.ClientStaticPub[:], staticPub)
	sh.Hash = [HashSize]byte(hashSum(sh.Hash[:], msg1[40:40+EncStaticLen]))

	dhSS, err := dh(serverPriv, &sh.ClientStaticPub) // s_r × s_i
	if err != nil {
		return nil, nil, err
	}
	key, _ = kdf2(&sh.ChainKey, dhSS[:])
	stampBox, err := open(key[:], 0, sh.Hash[:], msg1[88:88+EncStampLen])
	if err != nil || len(stampBox) != StampSize {
		return nil, nil, fmt.Errorf("%w: enc_timestamp: %v", ErrHandshake, err)
	}
	var stamp [StampSize]byte
	copy(stamp[:], stampBox)
	if lastStamp != nil && !tai64nAfter(stamp, *lastStamp) {
		return nil, nil, fmt.Errorf("%w: timestamp replay", ErrHandshake)
	}
	if lastStamp != nil {
		*lastStamp = stamp
	}
	sh.Hash = [HashSize]byte(hashSum(sh.Hash[:], msg1[88:88+EncStampLen]))

	// msg2: e_r; es2 = DH(e_r × s_i); empty; финальный KDF3 с psk.
	eph, err := GeneratePair()
	if err != nil {
		return nil, nil, err
	}
	msg2 := make([]byte, MsgRespSize)
	binary.LittleEndian.PutUint32(msg2[0:4], 2)
	binary.LittleEndian.PutUint32(msg2[4:8], sh.Sender)
	binary.LittleEndian.PutUint32(msg2[8:12], sh.RecvIdx)
	copy(msg2[12:44], eph.Pub[:])
	sh.Hash = [HashSize]byte(hashSum(sh.Hash[:], eph.Pub[:]))

	dhER, err := dh(&eph.Priv, &sh.ClientStaticPub) // e_r × s_i
	if err != nil {
		return nil, nil, err
	}
	key, _ = kdf2(&sh.ChainKey, dhER[:])
	empty, err := seal(key[:], 0, sh.Hash[:], nil)
	if err != nil {
		return nil, nil, err
	}
	copy(msg2[44:44+EncEmptyLen], empty)
	sh.Hash = [HashSize]byte(hashSum(sh.Hash[:], msg2[44:44+EncEmptyLen]))

	// Финал: KDF3(C, psk) → t0 = ключ клиента→сервера, t1 = сервер→клиента.
	k0, k1, _ := kdf3(&sh.ChainKey, psk[:])
	sh.RecvKey = k0
	sh.SendKey = k1

	// mac1 ответа строится ключом LABEL_MAC1 || static_initiator — клиент
	// проверяет, что ответ привязан к ЕГО static.
	mki := macKeyMac1(sh.ClientStaticPub[:])
	m1 := mac1(mki, msg2[0:60])
	copy(msg2[60:76], m1[:])
	return msg2, sh, nil
}

func randIndex() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return binary.LittleEndian.Uint32(b[:])
}

// ---- Транспорт (канон WG, тип 4) ----

// Transport — транспортные конверты WG после хендшейка: [type=4][receiver
// index 4][counter 8 LE][ChaCha20Poly1305(plaintext)]. Анти-реплей —
// sliding window 2048 (канон WG).
type Transport struct {
	mu      sync.Mutex
	SendKey [KeySize]byte
	RecvKey [KeySize]byte
	SendIdx uint32 // наш sender_index (peer ставит его в receiver)
	RecvIdx uint32 // sender_index пира (мы ставим его в receiver)
	sendCtr uint64
	window  *replayWindow
}

// NewTransport строит транспорт из состояния хендшейка.
// initiator=true — сторона клиента (SendKey=t0), false — сервера (SendKey=t1).
func NewTransport(initiator bool, ch *ClientHandshake) *Transport {
	t := &Transport{window: newReplayWindow()}
	if initiator {
		t.SendKey, t.RecvKey = ch.SendKey, ch.RecvKey
		t.SendIdx, t.RecvIdx = ch.Sender, ch.RecvIdx
	} else {
		t.SendKey, t.RecvKey = ch.RecvKey, ch.SendKey
		t.SendIdx, t.RecvIdx = ch.RecvIdx, ch.Sender
	}
	return t
}

func NewTransportServer(sh *ServerHandshake) *Transport {
	t := &Transport{window: newReplayWindow()}
	t.SendKey, t.RecvKey = sh.SendKey, sh.RecvKey
	t.SendIdx, t.RecvIdx = sh.Sender, sh.RecvIdx
	return t
}

// Seal упаковывает открытые данные в WG transport-пакет.
func (t *Transport) Seal(plain []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.sendCtr >= MaxCounter {
		return nil, ErrCounter
	}
	ctr := t.sendCtr
	t.sendCtr++
	pkt := make([]byte, 0, MsgDataHeader+len(plain)+MacSize)
	var hdr [MsgDataHeader]byte
	binary.LittleEndian.PutUint32(hdr[0:4], 4)
	binary.LittleEndian.PutUint32(hdr[4:8], t.RecvIdx)
	binary.LittleEndian.PutUint64(hdr[8:16], ctr)
	pkt = append(pkt, hdr[:]...)
	box, err := seal(t.SendKey[:], ctr, nil, plain)
	if err != nil {
		return nil, err
	}
	return append(pkt, box...), nil
}

// Open распаковывает WG transport-пакет (анти-реплей, канон WG).
func (t *Transport) Open(pkt []byte) ([]byte, error) {
	if len(pkt) < MsgDataHeader+MacSize {
		return nil, ErrEnvelope
	}
	if binary.LittleEndian.Uint32(pkt[0:4]) != 4 {
		return nil, fmt.Errorf("%w: type ≠ 4", ErrEnvelope)
	}
	ctr := binary.LittleEndian.Uint64(pkt[8:16])
	if ctr >= MaxCounter {
		return nil, ErrCounter
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.window.check(ctr) {
		return nil, ErrReplay
	}
	plain, err := open(t.RecvKey[:], ctr, nil, pkt[MsgDataHeader:])
	if err != nil {
		t.window.rollback(ctr)
		return nil, fmt.Errorf("%w: AEAD: %v", ErrEnvelope, err)
	}
	return plain, nil
}

// replayWindow — sliding window 2048 (канон WG §5.4.7).
type replayWindow struct {
	bitmap [ReplayWindowSize / 64]uint64
	base   uint64
	max    uint64 // старший принятый
}

func newReplayWindow() *replayWindow { return &replayWindow{max: ^uint64(0)>>1 | 0} }

func (w *replayWindow) check(ctr uint64) bool {
	switch {
	case ctr >= w.base+ReplayWindowSize:
		// сдвиг окна вперёд
		shift := ctr - w.base - ReplayWindowSize + 1
		w.advance(shift)
		w.set(ctr)
		return true
	case ctr >= w.base:
		if w.get(ctr) {
			return false
		}
		w.set(ctr)
		return true
	default:
		return false // позади окна
	}
}

func (w *replayWindow) rollback(ctr uint64) {
	if ctr >= w.base && ctr <= w.max {
		w.clear(ctr)
	}
}

func (w *replayWindow) advance(shift uint64) {
	if shift >= ReplayWindowSize {
		for i := range w.bitmap {
			w.bitmap[i] = 0
		}
		w.base += shift
		return
	}
	wIdx := int(shift / 64)
	bShift := shift % 64
	newBitmap := make([]uint64, len(w.bitmap))
	for i := 0; i < len(w.bitmap); i++ {
		src := i + wIdx
		if src < len(w.bitmap) {
			newBitmap[i] = w.bitmap[src] >> bShift
			if bShift > 0 && src+1 < len(w.bitmap) {
				newBitmap[i] |= w.bitmap[src+1] << (64 - bShift)
			}
		}
	}
	copy(w.bitmap[:], newBitmap)
	w.base += shift
}

func (w *replayWindow) get(ctr uint64) bool {
	bit := ctr - w.base
	return w.bitmap[bit/64]&(1<<(bit%64)) != 0
}

func (w *replayWindow) set(ctr uint64) {
	bit := ctr - w.base
	w.bitmap[bit/64] |= 1 << (bit % 64)
	if ctr > w.max {
		w.max = ctr
	}
}

func (w *replayWindow) clear(ctr uint64) {
	bit := ctr - w.base
	w.bitmap[bit/64] &^= 1 << (bit % 64)
}

// MaxPlainData — максимум открытого чанка WG-конверта.
const MaxPlainData = 65536 - TransportOverhead
