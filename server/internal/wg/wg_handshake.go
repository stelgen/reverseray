// wg_handshake.go — зона «Рукопожатие Noise-IK» (инициатор/респондер) — pure move из wg.go (v1.8.3, дробление по зонам; поведение не меняется).
package wg

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
)

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
