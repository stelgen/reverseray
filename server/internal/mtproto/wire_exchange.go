// wire_exchange.go — зона «Обмен ключами внутри сессии» (Upgrade client/server, ServerPlan) — pure move из wire.go (v1.8.3, дробление по зонам; поведение не меняется).
package mtproto

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/stelgen/reverseray/server/internal/rrp"
)

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

// ---- ServerPlan (v0.9.2): обмен ключами ВНУТРИ сессии ----
//
// Замена UpgradeServer-в-рукопожатии: сервер шлёт KEY_REQ из сессии
// (Session.Run — единственный читатель сокета), KEY_RESP приходит как
// control-кадр. Гонка с PROBE/PING невозможна by design (см. rrp/crypto.go).

// ServerPlan — rrp.KeyPlan серверной стороны mtproto2.
type ServerPlan struct {
	sid  string
	log  *slog.Logger
	pair *KeyPair
	ga   []byte
}

// NewServerPlan строит план обмена ключами для сессии sid.
func NewServerPlan(sid string, log *slog.Logger) *ServerPlan {
	return &ServerPlan{sid: sid, log: log}
}

// RequestPayload генерирует DH-пару и возвращает payload кадра KEY_REQ.
func (p *ServerPlan) RequestPayload() ([]byte, error) {
	pair, err := GeneratePair()
	if err != nil {
		return nil, err
	}
	p.pair = pair
	p.ga = PublicBytes(pair.Public)
	req, _ := json.Marshal(keyReqJSON{P: b64(P.Bytes()), G: int(G.Int64()), GA: b64(p.ga)})
	return req, nil
}

// Complete валидирует KEY_RESP (g_b) и возвращает крипто-контекст сессии.
func (p *ServerPlan) Complete(payload []byte) (rrp.PayloadCrypto, error) {
	if p.pair == nil {
		return nil, fmt.Errorf("%w: KEY_REQ не отправлялся", ErrKeyExchange)
	}
	var resp keyRespJSON
	if err := json.Unmarshal(payload, &resp); err != nil {
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
	authKey, err := p.pair.Shared(gb)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyExchange, err)
	}
	sc, err := NewSessionCrypto(authKey, saltFor(p.sid, p.ga, gbRaw), sessionID8(p.sid))
	if err != nil {
		return nil, err
	}
	if p.log != nil {
		p.log.Info("mtproto2: ключи согласованы", "session", p.sid)
	}
	return sc, nil
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
