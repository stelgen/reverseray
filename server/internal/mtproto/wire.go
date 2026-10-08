// wire.go — транспортная обвязка mtproto2: обёртка framed-транспорта,
// шифрующая payload'ы DATA/UDP_DATA в MTProto 2.0-конверт.
package mtproto

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

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

// ---- обмен ключами (после READY, внутри приватного хендшейка) ----

type keyReqJSON struct {
	P  string `json:"p"`
	G  int    `json:"g"`
	GA string `json:"g_a"`
}

type keyRespJSON struct {
	GB string `json:"g_b"`
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func sessionID8(sid string) []byte {
	sum := sha256.Sum256([]byte("mtproto2:" + sid))
	return sum[:8]
}

func saltFor(sid string, ga, gb []byte) []byte {
	sum := sha256.Sum256(append(append([]byte("mtproto2-salt:"+sid), ga...), gb...))
	return sum[:8]
}

// UpgradeServer — серверная сторона апгрейда: KEY_REQ → KEY_RESP → crypto.
func UpgradeServer(framed io.ReadWriteCloser, sid string, log *slog.Logger) (io.ReadWriteCloser, error) {
	pair, err := GeneratePair()
	if err != nil {
		return nil, err
	}
	ga := PublicBytes(pair.Public)
	req, _ := json.Marshal(keyReqJSON{P: b64(P.Bytes()), G: int(G.Int64()), GA: b64(ga)})
	if err := rrp.WriteFrame(framed, rrp.TypeKeyReq, 0, 0, req); err != nil {
		return nil, err
	}
	f, err := readFrameWithTimeout(framed, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("%w: KEY_RESP не получен: %v", ErrKeyExchange, err)
	}
	if f.Type != rrp.TypeKeyResp {
		return nil, fmt.Errorf("%w: ждали KEY_RESP (0x25), получили 0x%02x", ErrKeyExchange, f.Type)
	}
	var resp keyRespJSON
	if err := json.Unmarshal(f.Payload, &resp); err != nil {
		return nil, fmt.Errorf("%w: KEY_RESP не JSON: %v", ErrKeyExchange, err)
	}
	gbRaw, err := base64.RawURLEncoding.DecodeString(resp.GB)
	if err != nil {
		return nil, fmt.Errorf("%w: g_b не base64", ErrKeyExchange)
	}
	gb, err := PublicFromBytes(gbRaw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyExchange, err)
	}
	if err := ValidatePublic(gb); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyExchange, err)
	}
	authKey, err := pair.Shared(gb)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyExchange, err)
	}
	sc, err := NewSessionCrypto(authKey, saltFor(sid, ga, gbRaw), sessionID8(sid))
	if err != nil {
		return nil, err
	}
	if log != nil {
		log.Info("mtproto2: ключи согласованы", "session", sid)
	}
	return newWrapper(framed, sc, true), nil
}

// UpgradeClient — клиентская сторона (Go; используется fakephone в тестах).
func UpgradeClient(framed io.ReadWriteCloser, sid string, log *slog.Logger) (io.ReadWriteCloser, error) {
	f, err := readFrameWithTimeout(framed, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("%w: KEY_REQ не получен: %v", ErrKeyExchange, err)
	}
	if f.Type != rrp.TypeKeyReq {
		return nil, fmt.Errorf("%w: ждали KEY_REQ (0x24), получили 0x%02x", ErrKeyExchange, f.Type)
	}
	var req keyReqJSON
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		return nil, fmt.Errorf("%w: KEY_REQ не JSON: %v", ErrKeyExchange, err)
	}
	pRaw, err := base64.RawURLEncoding.DecodeString(req.P)
	if err != nil || !bytes.Equal(pRaw, P.Bytes()) {
		return nil, fmt.Errorf("%w: p не равен RFC 3526 (anti-logjam)", ErrKeyExchange)
	}
	if req.G != int(G.Int64()) {
		return nil, fmt.Errorf("%w: g = %d, ожидали 2", ErrKeyExchange, req.G)
	}
	gaRaw, err := base64.RawURLEncoding.DecodeString(req.GA)
	if err != nil {
		return nil, fmt.Errorf("%w: g_a не base64", ErrKeyExchange)
	}
	ga, err := PublicFromBytes(gaRaw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyExchange, err)
	}
	if err := ValidatePublic(ga); err != nil {
		return nil, fmt.Errorf("%w: g_a: %v", ErrKeyExchange, err)
	}
	pair, err := GeneratePair()
	if err != nil {
		return nil, err
	}
	gb := PublicBytes(pair.Public)
	resp, _ := json.Marshal(keyRespJSON{GB: b64(gb)})
	if err := rrp.WriteFrame(framed, rrp.TypeKeyResp, 0, 0, resp); err != nil {
		return nil, err
	}
	authKey, err := pair.Shared(ga)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyExchange, err)
	}
	sc, err := NewSessionCrypto(authKey, saltFor(sid, gaRaw, gb), sessionID8(sid))
	if err != nil {
		return nil, err
	}
	if log != nil {
		log.Info("mtproto2: клиент применил ключи", "session", sid)
	}
	return newWrapper(framed, sc, false), nil
}

func readFrameWithTimeout(r io.Reader, d time.Duration) (*rrp.Frame, error) {
	type deadliner interface{ SetReadDeadline(time.Time) error }
	if ds, ok := r.(deadliner); ok {
		_ = ds.SetReadDeadline(time.Now().Add(d))
		defer func() { _ = ds.SetReadDeadline(time.Time{}) }()
	}
	return rrp.ReadFrame(r)
}

// ---- wrapper: framed-транспорт с MTProto-конвертом на DATA/UDP_DATA ----

type wrapper struct {
	inner  io.ReadWriteCloser
	sc     *SessionCrypto
	server bool // true — серверная сторона (шифруем x=8, расшифровываем x=0)

	wmu  sync.Mutex
	wbuf []byte

	rmu  sync.Mutex
	rbuf []byte
}

func newWrapper(inner io.ReadWriteCloser, sc *SessionCrypto, server bool) io.ReadWriteCloser {
	return &wrapper{inner: inner, sc: sc, server: server}
}

func isPayloadFrame(t uint8) bool { return t == rrp.TypeData || t == rrp.TypeUdpData }

// Write принимает сериализованные кадры (WriteFrame пишет заголовок и
// payload отдельными вызовами) — буферизуем и перепаковываем целиком.
func (w *wrapper) Write(p []byte) (int, error) {
	w.wmu.Lock()
	w.wbuf = append(w.wbuf, p...)
	written := len(p)
	var ferr error
	for {
		f, rest, ok := parseBufferedFrame(w.wbuf)
		if !ok {
			break
		}
		w.wbuf = rest
		if err := w.emit(f); err != nil {
			ferr = err
			break
		}
	}
	w.wmu.Unlock()
	if ferr != nil {
		return 0, ferr
	}
	return written, nil
}

// parseBufferedFrame — аккуратный парсер кадров из буфера записи.
func parseBufferedFrame(buf []byte) (*rrp.Frame, []byte, bool) {
	if len(buf) < rrp.HeaderLen {
		return nil, nil, false
	}
	if buf[0] != rrp.Version1 {
		// протокол испорчен — такого не бывает от WriteFrame; сигнализируем
		// нулевой длиной кадра (emit вернёт ошибку через MaxPayloadFor)
		return nil, nil, false
	}
	t := buf[1]
	n := int(binary.BigEndian.Uint32(buf[8:12]))
	if n < 0 || n > rrp.MaxPayloadFor(t) {
		return nil, nil, false
	}
	total := rrp.HeaderLen + n
	if len(buf) < total {
		return nil, nil, false
	}
	f := &rrp.Frame{
		Type:     t,
		Flags:    binary.BigEndian.Uint16(buf[2:4]),
		StreamID: binary.BigEndian.Uint32(buf[4:8]),
		Payload:  append([]byte(nil), buf[rrp.HeaderLen:total]...),
	}
	return f, buf[total:], true
}

// emit — один кадр наружу: DATA/UDP_DATA в конверт, остальные — как есть.
// Большой DATA режется на чанки ≤ maxPlainData (поток DATA это позволяет);
// слишком большой UDP_DATA дропается (семантика UDP).
func (w *wrapper) emit(f *rrp.Frame) error {
	if w.sc == nil || !isPayloadFrame(f.Type) {
		return rrp.WriteFrame(w.inner, f.Type, f.Flags, f.StreamID, f.Payload)
	}
	if f.Type == rrp.TypeUdpData {
		if len(f.Payload) > maxPlainData {
			return nil // дроп, UDP — без гарантий
		}
		env, err := w.encryptPayload(f.Payload)
		if err != nil {
			return err
		}
		return rrp.WriteFrame(w.inner, f.Type, f.Flags, f.StreamID, env)
	}
	// DATA: разрезаем на чанки
	payload := f.Payload
	for len(payload) > 0 {
		chunk := payload
		if len(chunk) > maxPlainData {
			chunk = chunk[:maxPlainData]
		}
		payload = payload[len(chunk):]
		env, err := w.encryptPayload(chunk)
		if err != nil {
			return err
		}
		if err := rrp.WriteFrame(w.inner, f.Type, f.Flags, f.StreamID, env); err != nil {
			return err
		}
	}
	return nil
}

func (w *wrapper) encryptPayload(payload []byte) ([]byte, error) {
	if w.server {
		return w.sc.EncryptUp(payload)
	}
	return w.sc.EncryptDown(payload)
}

func (w *wrapper) Read(p []byte) (int, error) {
	w.rmu.Lock()
	defer w.rmu.Unlock()
	for len(w.rbuf) == 0 {
		f, err := rrp.ReadFrame(w.inner)
		if err != nil {
			return 0, err
		}
		if w.sc != nil && isPayloadFrame(f.Type) {
			var plain []byte
			if w.server {
				plain, err = w.sc.DecryptDown(f.Payload)
			} else {
				plain, err = w.sc.DecryptUp(f.Payload)
			}
			if err != nil {
				return 0, err
			}
			f.Payload = plain
		}
		var buf bytes.Buffer
		if err := rrp.WriteFrame(&buf, f.Type, f.Flags, f.StreamID, f.Payload); err != nil {
			return 0, err
		}
		w.rbuf = append(w.rbuf, buf.Bytes()...)
	}
	n := copy(p, w.rbuf)
	w.rbuf = w.rbuf[n:]
	return n, nil
}

func (w *wrapper) Close() error { return w.inner.Close() }

// SetReadDeadline/SetWriteDeadline делегируются (сессия ставит idle-таймаут).
func (w *wrapper) SetReadDeadline(t time.Time) error {
	type d interface{ SetReadDeadline(time.Time) error }
	if ds, ok := w.inner.(d); ok {
		return ds.SetReadDeadline(t)
	}
	return nil
}

func (w *wrapper) SetWriteDeadline(t time.Time) error {
	type d interface{ SetWriteDeadline(time.Time) error }
	if ds, ok := w.inner.(d); ok {
		return ds.SetWriteDeadline(t)
	}
	return nil
}
