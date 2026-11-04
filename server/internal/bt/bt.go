// Package bt — протокол туннеля bittorrent (v0.10, module protocol.bittorrent):
// payload'ы DATA/UDP_DATA выглядят для DPI как НАСТОЯЩИЙ BitTorrent-трафик —
// Message Stream Encryption / Protocol Encryption (MSE/PE), де-факто канон
// зашифрованных P2P-соединений (libtorrent/qBittorrent/Deluge/Vuze).
//
// Канон (MSE/PE, docs/protocol.md §BT/1; сводка — jwodder/kbits «The BitTorrent
// Encryption Protocol», wire format BEP 8 §3):
//
//   - DH: 768-битная группа RFC 2409 group 1 (та же, что у всех BT-клиентов),
//     G = 2; приватный ключ Xa/Xb — 160 бит (рекомендация канона);
//   - SKEY — 20-байтовый общий секрет «торрента»: у нас SHA1("reverseray-bt:"+tokenHash),
//     обе стороны считают его независимо из токена (аналог info-hash);
//   - req1 = HASH("req1"+S); req2⊕req3 = HASH("req2"+SKEY)⊕HASH("req3"+S);
//   - RC4-ключи: A→B = SHA1("keyA"+S+SKEY), B→A = SHA1("keyB"+S+SKEY),
//     первые 1024 байта каждого кейстрима отбрасываются (канон RC4-drop1024);
//   - packet1 = Ya(96Б)+pad(0..512); packet3 = req1 + req2⊕req3 +
//     RC4(VC+crypto_provide+len(PadC)+PadC+len(IA)+IA);
//   - packet4 = RC4(VC+crypto_select+len(PadD)+PadD); VC = 8 нулевых байт;
//   - после хендшейка тот же RC4-кейстрим шифрует весь поток без реинициализации;
//   - транспортные сообщения = peer-wire-формат: [len BE4][type u8] — мы
//     используем piece (type 7): [index BE4][begin BE4][block], keep-alive (len 0).
//
// Роли: клиент APK — инициатор MSE (A, packet1/3), сервер — респондер (B,
// packet2/4). Хендшейк идёт ВНУТРИ приватного канала (TLS 1.3 + SPKI-pin +
// HMAC-AUTH) кадрами BT_INIT/BT_RESP; KEY_REQ несёт Yb сервера заранее
// (отклонение от канонного порядка пакетов — фреймы снимают проблему
// «неизвестной длины паддинга», математика неизменна).
//
// Крипто-замечание (честно, как в SECURITY.md): RC4 — слабый шифр, это
// канон MSE. Конфиденциальность payload'ов обеспечивается TLS 1.3 с SPKI-pin;
// конверт MSE — DPI-маска, делающая статистику байтов идентичной реальному
// зашифрованному BitTorrent. Ключ — свежий DH-секрет на каждую сессию.
package bt

import (
	"crypto/rand"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sync"
)

// Канон MSE (BEP 8 wire format; prime = RFC 2409 group 1, 768 бит).
const (
	KeySize = 96 // Ya/Yb/S — 96 байт BE
	VCLen   = 8  // verification constant: 8 нулевых байт
	// KeyDrop — канон RC4-drop1024: первые 1024 байта кейстрима discard.
	KeyDrop = 1024
	// CryptoPlain/CryptoRC4 — биты crypto_provide (канон MSE).
	CryptoPlain uint32 = 0x01
	CryptoRC4   uint32 = 0x02
	// PadMin/PadMax — канонный диапазон паддингов 0..512; мы 16..512
	// (0 разрешён каноном, но случайная длина лучше маскирует).
	PadMin = 16
	PadMax = 512
	// Peer-wire сообщения (BEP 3): keep-alive len=0, piece type=7.
	MsgPiece      = 0x07
	PieceOverhead = 4 + 1 + 4 + 4 // len + type + index + begin
	BlockLen      = 0x4000        // канонный блок запроса 16 KiB
	PieceLen      = 128 * BlockLen
	MaxPlainData  = 65536 - PieceOverhead
	// skeyLabel — доменное разделение: SKEY никогда не совпадёт с чужим SHA1.
	skeyLabel = "reverseray-bt:"
)

// dhPrime — 768-битное простое MSE (RFC 2409 group 1; примечание: в копиях
// статьи/пакета cbluth встречается typo «C234» вместо «C23B» — канон
// libtorrent/qBittorrent/Deluge именно C23B).
var dhPrime, _ = new(big.Int).SetString(
	"FFFFFFFFFFFFFFFFC90FDAA22168C23BC4C6628B80DC1CD1"+
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
		"E485B576625E7EC6F44C42E9A63A36210000000000090563", 16)
var dhG = big.NewInt(2)

var (
	// ErrHandshake — нарушение хендшейка MSE (req1, VC, select, размер).
	ErrHandshake = errors.New("bt: handshake failed")
	// ErrEnvelope — битое транспортное сообщение.
	ErrEnvelope = errors.New("bt: bad envelope")
)

func sha1Sum(parts ...[]byte) []byte {
	h := sha1.New()
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	return h.Sum(nil)
}

// SKEY — «инфо-хеш торрента» сессии: SHA1(label || tokenHash) (20 Б).
func SKEY(tokenHash []byte) [20]byte {
	var s [20]byte
	copy(s[:], sha1Sum([]byte(skeyLabel), tokenHash))
	return s
}

// DHPair — пара ключей MSE (приватный 160 бит — рекомендация канона).
type DHPair struct {
	X, Y *big.Int
}

func generatePair(rnd func([]byte) (int, error)) (*DHPair, error) {
	b := make([]byte, 20) // 160 бит
	if _, err := rnd(b); err != nil {
		return nil, err
	}
	x := new(big.Int).SetBytes(b)
	if x.Sign() == 0 {
		x.SetInt64(1)
	}
	y := new(big.Int).Exp(dhG, x, dhPrime)
	return &DHPair{X: x, Y: y}, nil
}

// sharedSecret — S = (peerY)^priv mod P, как 96-байтовое BE.
func sharedSecret(peerY *big.Int, priv *big.Int) [KeySize]byte {
	s := new(big.Int).Exp(peerY, priv, dhPrime)
	var out [KeySize]byte
	b := s.Bytes()
	copy(out[KeySize-len(b):], b)
	return out
}

// be96 — big.Int в 96-байтовое BE.
func be96(v *big.Int) [KeySize]byte {
	var out [KeySize]byte
	b := v.Bytes()
	copy(out[KeySize-len(b):], b)
	return out
}

// rc4Stream — RC4-кейстрим с канонным drop и мьютексом (потоки Seal/Open
// могут приходить параллельно — как WG Transport).
type rc4Stream struct {
	c  *rc4.Cipher
	mu sync.Mutex
}

func newRC4Stream(key []byte) (*rc4Stream, error) {
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	st := &rc4Stream{c: c}
	// канон: drop первых KeyDrop байт кейстрима
	st.c.XORKeyStream(make([]byte, KeyDrop), make([]byte, KeyDrop))
	return st, nil
}

func (r *rc4Stream) xor(dst, src []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.c.XORKeyStream(dst, src)
}

// rc4Key — канонный вывод ключей MSE: SHA1(label + S + SKEY),
// label = "keyA" (инициатор→респондер) / "keyB" (респондер→инициатор).
func rc4Key(label string, s, skey []byte) []byte {
	return sha1Sum(append([]byte(label), append(s, skey...)...))
}

// ---- инициатор (клиент APK) ----

// ClientHandshake — состояние инициатора MSE: packet1 → packet3 → packet4.
type ClientHandshake struct {
	skey [20]byte
	pair *DHPair
	s    [KeySize]byte
	out  *rc4Stream // keyA: клиент → сервер
	in   *rc4Stream // keyB: сервер → клиент
	done bool
}

// NewClientInit строит packet1 = Ya(96Б BE) + pad(rand 16..512).
// rnd — источник случайности (crypto/rand в проде, фиксированный в KAT).
func NewClientInit(skey [20]byte, rnd func([]byte) (int, error)) ([]byte, *ClientHandshake, error) {
	if rnd == nil {
		rnd = rand.Read
	}
	pair, err := generatePair(rnd)
	if err != nil {
		return nil, nil, err
	}
	pad1 := make([]byte, PadMin+rndInt(rnd, PadMax-PadMin+1))
	if _, err := rnd(pad1); err != nil {
		return nil, nil, err
	}
	ch := &ClientHandshake{skey: skey, pair: pair}
	ya := be96(pair.Y)
	buf := make([]byte, 0, KeySize+len(pad1))
	buf = append(buf, ya[:]...)
	buf = append(buf, pad1...)
	return buf, ch, nil
}

// BuildPacket3 — канонный packet3 после получения Yb сервера (KEY_REQ):
// req1 + req2⊕req3 + RC4(keyA)(VC + crypto_provide + len(PadC) + PadC + len(IA) + IA).
// У нас PadC=0 и IA пусто (начальные данные уходят обычными DATA-кадрами).
func (ch *ClientHandshake) BuildPacket3(yb []byte) ([]byte, error) {
	if ch.done || ch.out != nil {
		return nil, fmt.Errorf("%w: packet3 already built", ErrHandshake)
	}
	if len(yb) != KeySize {
		return nil, fmt.Errorf("%w: Yb len %d ≠ %d", ErrHandshake, len(yb), KeySize)
	}
	peerY := new(big.Int).SetBytes(yb)
	ch.s = sharedSecret(peerY, ch.pair.X)
	keyA := rc4Key("keyA", ch.s[:], ch.skey[:])
	out, err := newRC4Stream(keyA)
	if err != nil {
		return nil, err
	}
	keyB := rc4Key("keyB", ch.s[:], ch.skey[:])
	in, err := newRC4Stream(keyB)
	if err != nil {
		return nil, err
	}
	ch.out, ch.in = out, in

	req1 := sha1Sum([]byte("req1"), ch.s[:])
	req2 := sha1Sum([]byte("req2"), ch.skey[:])
	req3 := sha1Sum([]byte("req3"), ch.s[:])
	x := make([]byte, 20)
	for i := range x {
		x[i] = req2[i] ^ req3[i]
	}
	plain := make([]byte, 0, VCLen+4+2+2)
	plain = append(plain, make([]byte, VCLen)...) // VC = нули
	prov := make([]byte, 4)
	binary.BigEndian.PutUint32(prov, CryptoRC4)
	plain = append(plain, prov...) // crypto_provide = RC4
	plain = append(plain, 0, 0)    // len(PadC) = 0
	plain = append(plain, 0, 0)    // len(IA) = 0
	enc := make([]byte, len(plain))
	out.xor(enc, plain)
	buf := make([]byte, 0, 40+len(enc))
	buf = append(buf, req1...)
	buf = append(buf, x...)
	buf = append(buf, enc...)
	return buf, nil
}

// Init — канонная конкатенация packet1||packet3 для кадра BT_INIT.
func (ch *ClientHandshake) Init(packet3 []byte, yaWithPad []byte) []byte {
	return append(append([]byte{}, yaWithPad...), packet3...)
}

// ConsumeResponse — обработка packet4 респондера: RC4(keyB) открыть
// VC(8 нулей) + crypto_select(4) + len(PadD)(2) + PadD (паддинг декодировать
// ОБЯЗАТЕЛЬНО — кейстрим должен остаться в синхронизации).
func (ch *ClientHandshake) ConsumeResponse(resp []byte) error {
	if ch.in == nil || ch.done {
		return fmt.Errorf("%w: handshake state invalid", ErrHandshake)
	}
	minLen := VCLen + 4 + 2
	if len(resp) < minLen {
		return fmt.Errorf("%w: packet4 len %d < %d", ErrHandshake, len(resp), minLen)
	}
	dec := make([]byte, len(resp))
	ch.in.xor(dec, resp)
	if !allZero(dec[:VCLen]) {
		return fmt.Errorf("%w: VC mismatch", ErrHandshake)
	}
	sel := binary.BigEndian.Uint32(dec[VCLen : VCLen+4])
	if sel != CryptoRC4 {
		return fmt.Errorf("%w: crypto_select=0x%x", ErrHandshake, sel)
	}
	padD := int(binary.BigEndian.Uint16(dec[VCLen+4 : VCLen+6]))
	if VCLen+6+padD > len(dec) {
		return fmt.Errorf("%w: PadD overflow", ErrHandshake)
	}
	// Кейстрим уже продвинут ровно по len(resp) — dec покрывает весь packet4
	// (VC+select+len(PadD)+PadD), доп. прогона не требуется.
	ch.done = true
	return nil
}

// Transport — клиентский транспорт (после ConsumeResponse).
func (ch *ClientHandshake) Transport() *Transport {
	return &Transport{out: ch.out, in: ch.in}
}

// ---- респондер (сервер) ----

// ServerHandshake — состояние респондера MSE.
type ServerHandshake struct {
	skey [20]byte
	pair *DHPair
	s    [KeySize]byte
	out  *rc4Stream // keyB: сервер → клиент
	in   *rc4Stream // keyA: клиент → сервер
}

// NewServerHandshake — генерирует DH-пару респондера; возвращает Yb
// (96 Б BE) для KEY_REQ. rnd — инъекция для KAT.
func NewServerHandshake(skey [20]byte, rnd func([]byte) (int, error)) (yb [KeySize]byte, sh *ServerHandshake, err error) {
	if rnd == nil {
		rnd = rand.Read
	}
	pair, err := generatePair(rnd)
	if err != nil {
		return yb, nil, err
	}
	yb = be96(pair.Y)
	return yb, &ServerHandshake{skey: skey, pair: pair}, nil
}

// Respond — обработка packet1||packet3: находит req1 сканом (канон: длина
// паддинга packet1 неизвестна), проверяет req2⊕req3 против известного SKEY,
// открывает RC4(keyA)-часть, отвечает packet4 = RC4(keyB)(VC+select+len(PadD)+PadD).
func (sh *ServerHandshake) Respond(init []byte, rnd func([]byte) (int, error)) ([]byte, *Transport, error) {
	if rnd == nil {
		rnd = rand.Read
	}
	if sh.out != nil {
		return nil, nil, fmt.Errorf("%w: handshake already done", ErrHandshake)
	}
	// 1) Ya = первые 96 Б; S = DH(Ya, xb) — одинаков для всех смещений скана.
	if len(init) < KeySize+20+20+VCLen+4+2 {
		return nil, nil, fmt.Errorf("%w: INIT len %d too short", ErrHandshake, len(init))
	}
	ya := new(big.Int).SetBytes(init[:KeySize])
	sh.s = sharedSecret(ya, sh.pair.X)
	req1Want := sha1Sum([]byte("req1"), sh.s[:])
	// 2) канонный скан req1 по паддингу packet1 (смещения 96..96+512).
	off := -1
	for o := KeySize; o+40 <= len(init) && o <= KeySize+PadMax; o++ {
		if subtle.ConstantTimeCompare(init[o:o+20], req1Want) == 1 {
			off = o
			break
		}
	}
	if off < 0 {
		return nil, nil, fmt.Errorf("%w: req1 not found", ErrHandshake)
	}
	// 3) req2⊕req3 → сверка с известным SKEY (constant-time; канон:
	// сервер «узнаёт торрент» по HASH("req2"+SKEY) среди известных).
	req3 := sha1Sum([]byte("req3"), sh.s[:])
	req2Want := sha1Sum([]byte("req2"), sh.skey[:])
	got := make([]byte, 20)
	for i := 0; i < 20; i++ {
		got[i] = init[off+20+i] ^ req3[i]
	}
	if subtle.ConstantTimeCompare(got, req2Want) != 1 {
		return nil, nil, fmt.Errorf("%w: req2 mismatch (unknown SKEY)", ErrHandshake)
	}
	// 4) RC4(keyA) — входящий кейстрим сервера: VC+provide+len(PadC)+PadC+len(IA)+IA.
	keyA := rc4Key("keyA", sh.s[:], sh.skey[:])
	in, err := newRC4Stream(keyA)
	if err != nil {
		return nil, nil, err
	}
	keyB := rc4Key("keyB", sh.s[:], sh.skey[:])
	out, err := newRC4Stream(keyB)
	if err != nil {
		return nil, nil, err
	}
	rest := init[off+40:]
	dec := make([]byte, len(rest))
	in.xor(dec, rest)
	if len(dec) < VCLen+4+2+2 {
		return nil, nil, fmt.Errorf("%w: packet3 truncated", ErrHandshake)
	}
	if !allZero(dec[:VCLen]) {
		return nil, nil, fmt.Errorf("%w: VC mismatch", ErrHandshake)
	}
	provide := binary.BigEndian.Uint32(dec[VCLen : VCLen+4])
	if provide&CryptoRC4 == 0 {
		return nil, nil, fmt.Errorf("%w: no RC4 in crypto_provide 0x%x", ErrHandshake, provide)
	}
	padC := int(binary.BigEndian.Uint16(dec[VCLen+4 : VCLen+6]))
	if VCLen+6+padC+2 > len(dec) {
		return nil, nil, fmt.Errorf("%w: PadC overflow", ErrHandshake)
	}
	// len(IA) = dec[VCLen+6+padC:VCLen+8+padC] — IA пустой по нашей спеке;
	// входящий кейстрим уже прогнан ровно по всем байтам packet3.
	sh.in, sh.out = in, out

	// 5) packet4 = RC4(keyB)(VC + crypto_select + len(PadD) + PadD).
	padD := make([]byte, PadMin+rndInt(rnd, PadMax-PadMin+1))
	if _, err := rnd(padD); err != nil {
		return nil, nil, err
	}
	plain := make([]byte, 0, VCLen+4+2+len(padD))
	plain = append(plain, make([]byte, VCLen)...)
	sel := make([]byte, 4)
	binary.BigEndian.PutUint32(sel, CryptoRC4)
	plain = append(plain, sel...)
	var pl [2]byte
	binary.BigEndian.PutUint16(pl[:], uint16(len(padD))) // #nosec G115: ≤512
	plain = append(plain, pl[:]...)
	plain = append(plain, padD...)
	enc := make([]byte, len(plain))
	out.xor(enc, plain)
	return enc, &Transport{out: sh.out, in: sh.in}, nil
}

// ---- транспорт (канонный peer-wire формат) ----

// Transport — конверт payload'ов: каждое DATA/UDP_DATA-сообщение —
// полный BT peer-wire пакет [len BE4][type 7][index BE4][begin BE4][block],
// весь пакет (включая length-префикс) зашифрован продолжением RC4-кейстрима
// хендшейка (канон MSE: кейстрим не реинициализируется).
type Transport struct {
	out, in *rc4Stream
	mu      sync.Mutex
	ctr     uint64 // счётчик блоков piece (для правдоподобных index/begin)
}

// Seal — открытые данные → зашифрованное piece-сообщение.
func (t *Transport) Seal(plain []byte) ([]byte, error) {
	if len(plain) > MaxPlainData {
		return nil, fmt.Errorf("%w: plain %d > %d", ErrEnvelope, len(plain), MaxPlainData)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	msg := make([]byte, PieceOverhead+len(plain))
	binary.BigEndian.PutUint32(msg[0:4], uint32(len(msg))) // #nosec G115: ≤65536
	msg[4] = MsgPiece
	idx := uint32(t.ctr / (PieceLen / BlockLen))
	begin := uint32(t.ctr%(PieceLen/BlockLen)) * BlockLen
	t.ctr++
	binary.BigEndian.PutUint32(msg[5:9], idx)
	binary.BigEndian.PutUint32(msg[9:13], begin)
	copy(msg[13:], plain)
	box := make([]byte, len(msg))
	t.out.xor(box, msg)
	return box, nil
}

// Open — piece-сообщение → открытые данные (проверка канонной формы).
func (t *Transport) Open(box []byte) ([]byte, error) {
	if len(box) < PieceOverhead {
		return nil, fmt.Errorf("%w: len %d < %d", ErrEnvelope, len(box), PieceOverhead)
	}
	msg := make([]byte, len(box))
	t.in.xor(msg, box)
	ml := binary.BigEndian.Uint32(msg[0:4])
	if int(ml) != len(box) {
		return nil, fmt.Errorf("%w: msg len %d ≠ frame %d", ErrEnvelope, ml, len(box))
	}
	if msg[4] != MsgPiece {
		return nil, fmt.Errorf("%w: msg type 0x%02x", ErrEnvelope, msg[4])
	}
	return msg[PieceOverhead:], nil
}

// ---- helpers ----

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// rndInt — безопасный [0,n) из rnd (детерминированный при фиксированном rnd).
func rndInt(rnd func([]byte) (int, error), n int) int {
	if n <= 0 {
		return 0
	}
	var b [4]byte
	if _, err := rnd(b[:]); err != nil {
		return 0
	}
	return int(binary.BigEndian.Uint32(b[:]) % uint32(n)) // #nosec G115: n>0
}
