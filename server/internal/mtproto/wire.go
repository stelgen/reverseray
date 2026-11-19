// wire.go — транспортная обвязка mtproto2: обёртка framed-транспорта,
// шифрующая payload'ы DATA/UDP_DATA в MTProto 2.0-конверт.
package mtproto

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/stelgen/reverseray/server/internal/rrp"
)

// maxPlainData — потолок открытого DATA-чанка: конверт добавляет
// 24 (auth_key_id+msg_key) + 32 (внутренний заголовок) + паддинг ≥16,
// а кадр на проводе ограничен rrp.MaxDataPayload.
const maxPlainData = rrp.MaxDataPayload - 128

var (
	// ErrEnvelope — битый MTProto-конверт (плохой key_id/msg_key/размер).
	ErrEnvelope = errors.New("mtproto: битый конверт")
	// ErrKeyExchange — нарушение обмена ключами.
	ErrKeyExchange = errors.New("mtproto: обмен ключами не удался")
)

// SessionCrypto — крипто-контекст одной сессии mtproto2.
// Используется и сервером, и Go-клиентом (fakephone) в тестах.
type SessionCrypto struct {
	authKey   []byte // 256 байт
	authKeyID []byte // 8 байт
	salt      [8]byte
	sessionID [8]byte

	mu       sync.Mutex
	msgIDEnc [2]uint64 // счётчики msg_id по направлениям: [x=0, x=8]
}

// NewSessionCrypto строит контекст: authKey 256 байт, salt/sessionID 8 байт.
func NewSessionCrypto(authKey, salt, sessionID []byte) (*SessionCrypto, error) {
	if len(authKey) != 256 {
		return nil, fmt.Errorf("mtproto: auth_key должен быть 256 байт, получили %d", len(authKey))
	}
	if len(salt) != 8 || len(sessionID) != 8 {
		return nil, errors.New("mtproto: salt/session_id должны быть 8 байт")
	}
	sc := &SessionCrypto{authKey: append([]byte(nil), authKey...)}
	sc.authKeyID = AuthKeyID(sc.authKey)
	copy(sc.salt[:], salt)
	copy(sc.sessionID[:], sessionID)
	return sc, nil
}

func xIndex(x int) int {
	if x == kdfXServer {
		return 1
	}
	return 0
}

// encryptEnvelope: открытый payload → [key_id 8][msg_key 16][IGE(inner)].
// x — направление (0: клиент→сервер, 8: сервер→клиент).
func (sc *SessionCrypto) encryptEnvelope(x int, payload []byte) ([]byte, error) {
	if len(payload) > maxPlainData {
		return nil, errors.New("mtproto: payload превышает лимит DATA")
	}
	sc.mu.Lock()
	idx := xIndex(x)
	sc.msgIDEnc[idx]++
	msgID := sc.msgIDEnc[idx] * 4
	// канон guidelines: msg_id ЧЁТНЫЙ для клиент→сервер, НЕЧЁТНЫЙ для сервер→клиент
	if x == kdfXServer {
		msgID++
	}
	seqNo := uint32(sc.msgIDEnc[idx] * 2)
	sc.mu.Unlock()

	// inner: [salt 8][session 8][msg_id 8][seq 4][len 4][payload][pad]
	total := 32 + len(payload)
	padLen := 16 - total%16
	if padLen < 16 {
		padLen += 16
	}
	pad := make([]byte, padLen)
	_, _ = rand.Read(pad) // канон: паддинг 16..1024 случайных байт
	inner := make([]byte, 0, total+padLen)
	inner = append(inner, sc.salt[:]...)
	inner = append(inner, sc.sessionID[:]...)
	var mid [8]byte
	binary.BigEndian.PutUint64(mid[:], msgID)
	inner = append(inner, mid[:]...)
	var sq [4]byte
	binary.BigEndian.PutUint32(sq[:], seqNo)
	inner = append(inner, sq[:]...)
	var ln [4]byte
	binary.BigEndian.PutUint32(ln[:], uint32(len(payload))) // #nosec G115: payload <= maxPlainData (64КБ-128)
	inner = append(inner, ln[:]...)
	inner = append(inner, payload...)
	inner = append(inner, pad...)

	mk := msgKey(sc.authKey, x, inner)
	aesKey, aesIV := kdfParams(sc.authKey, mk, x)
	c, err := newIGE(aesKey[:])
	if err != nil {
		return nil, err
	}
	enc := c.encryptIGE(inner, aesIV[:])
	if enc == nil {
		return nil, errors.New("mtproto: IGE encrypt: длина не кратна блоку")
	}
	out := make([]byte, 0, 24+len(enc))
	out = append(out, sc.authKeyID...)
	out = append(out, mk...)
	return append(out, enc...), nil
}

// decryptEnvelope: конверт → открытый payload. Проверяет key_id
// (constant-time), расшифровывает, валидирует salt/session/msg_key.
func (sc *SessionCrypto) decryptEnvelope(x int, env []byte) ([]byte, error) {
	// env = [key_id 8][msg_key 16][IGE-тело, кратное 16]: (len-24) % 16 == 0
	if len(env) < 24+16 || (len(env)-24)%16 != 0 {
		return nil, ErrEnvelope
	}
	if !hmac.Equal(sc.authKeyID, env[:8]) {
		return nil, fmt.Errorf("%w: чужой auth_key_id", ErrEnvelope)
	}
	mk := append([]byte(nil), env[8:24]...)
	aesKey, aesIV := kdfParams(sc.authKey, mk, x)
	c, err := newIGE(aesKey[:])
	if err != nil {
		return nil, err
	}
	inner := c.decryptIGE(env[24:], aesIV[:])
	if inner == nil {
		return nil, fmt.Errorf("%w: длина не кратна блоку", ErrEnvelope)
	}
	if len(inner) < 32 {
		return nil, ErrEnvelope
	}
	if !hmac.Equal(inner[:8], sc.salt[:]) || !hmac.Equal(inner[8:16], sc.sessionID[:]) {
		return nil, fmt.Errorf("%w: salt/session_id не совпали", ErrEnvelope)
	}
	msgLen := binary.BigEndian.Uint32(inner[28:32])
	rest := uint64(len(inner)) - 32
	if uint64(msgLen) > rest {
		return nil, fmt.Errorf("%w: msg_len %d > тела %d", ErrEnvelope, msgLen, rest)
	}
	// канон guidelines: длина паддинга — 12..1024 байта
	padLen := rest - uint64(msgLen)
	if padLen < 12 || padLen > 1024 {
		return nil, fmt.Errorf("%w: паддинг %d байт вне 12..1024", ErrEnvelope, padLen)
	}
	// msg_key должен воспроизводиться из расшифрованного тела (целостность)
	expect := msgKey(sc.authKey, x, inner)
	if !hmac.Equal(expect, mk) {
		return nil, fmt.Errorf("%w: msg_key не сошёлся (битое тело)", ErrEnvelope)
	}
	return append([]byte(nil), inner[32:32+msgLen]...), nil
}

// MaxPlainData — максимум открытого чанка для конверта (rrp.PayloadCrypto).
func (sc *SessionCrypto) MaxPlainData() int { return maxPlainData }

// ---- направления-обёртки ----

// EncryptUp — сервер → клиент (x=8). EncryptDown — клиент → сервер (x=0).
func (sc *SessionCrypto) EncryptUp(payload []byte) ([]byte, error) {
	return sc.encryptEnvelope(kdfXServer, payload)
}
func (sc *SessionCrypto) EncryptDown(payload []byte) ([]byte, error) {
	return sc.encryptEnvelope(kdfXClient, payload)
}
func (sc *SessionCrypto) DecryptUp(env []byte) ([]byte, error) {
	return sc.decryptEnvelope(kdfXServer, env)
}
func (sc *SessionCrypto) DecryptDown(env []byte) ([]byte, error) {
	return sc.decryptEnvelope(kdfXClient, env)
}
