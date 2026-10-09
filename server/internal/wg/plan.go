// plan.go — серверный план обмена ключами wireguard (rrp.KeyPlan +
// rrp.InitResponder) и крипто-контекст сессии (rrp.PayloadCrypto).
//
// Поток v0.9.5: после READY сервер шлёт KEY_REQ (JSON {kind:"wg",spub}) —
// WG static сервера этой сессии (эphemeral per session); клиент отвечает
// WG_INIT (настоящий WG msg1, 148 Б); сервер обрабатывает его по канону
// Noise_IKpsk2 (mac1, enc_static, enc_timestamp, anti-replay TAI64N) и
// отвечает WG_RESP (msg2, 92 Б). PSK хендшейка = SHA256(token) — наш ключ
// доверия из приватной ссылки: хендшейк WG привязан к нашему токену.
package wg

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/stelgen/reverseray/server/internal/rrp"
)

// ProtoID — канонический id протокола в реестре и ссылке.
const ProtoID = "wireguard"

var ErrKeyExchange = fmt.Errorf("%w: wg key exchange", rrp.ErrKeyPlan)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

type keyReqJSON struct {
	Kind string `json:"kind"` // "wireguard"
	SPub string `json:"spub"` // WG static public сервера (b64url, 32 Б)
}

// SessionCrypto — rrp.PayloadCrypto поверх WG transport-конвертов:
// payload DATA/UDP_DATA = полный WG-пакет [type=4][receiver][counter][AEAD].
type SessionCrypto struct{ tr *Transport }

// DecryptDown — клиент → сервер (WG-пакет → открытые данные).
func (c *SessionCrypto) DecryptDown(payload []byte) ([]byte, error) {
	return c.tr.Open(payload)
}

// EncryptUp — сервер → клиент (данные → WG-пакет).
func (c *SessionCrypto) EncryptUp(payload []byte) ([]byte, error) {
	return c.tr.Seal(payload)
}

// MaxPlainData — максимум открытого чанка (заголовок WG + тег Poly1305).
func (c *SessionCrypto) MaxPlainData() int { return MaxPlainData }

// ServerPlan — серверная сторона обмена ключами wireguard внутри сессии.
type ServerPlan struct {
	sid  string
	log  *slog.Logger
	psk  [KeySize]byte // SHA256(token) — наш ключ доверия
	pair *KeyPair      // WG static сервера (ephemeral per session)
	// lastStamp — последняя TAI64N-метка клиента (anti-replay канона WG).
	lastStamp [StampSize]byte
}

// NewServerPlan строит план: psk = хеш токена устройства (32 Б).
func NewServerPlan(sid string, tokenHash []byte, log *slog.Logger) (*ServerPlan, error) {
	if len(tokenHash) != KeySize {
		return nil, fmt.Errorf("%w: token hash не 32 Б", ErrKeyExchange)
	}
	p := &ServerPlan{sid: sid, log: log}
	copy(p.psk[:], tokenHash)
	return p, nil
}

// RequestPayload — payload кадра KEY_REQ: WG static public сервера.
func (p *ServerPlan) RequestPayload() ([]byte, error) {
	pair, err := GeneratePair()
	if err != nil {
		return nil, err
	}
	p.pair = pair
	return json.Marshal(keyReqJSON{Kind: ProtoID, SPub: b64(pair.Pub[:])})
}

// Complete — для WG не используется (обмен идёт INIT/RESP-кадрами):
// клиент никогда не шлёт KEY_RESP в этом протоколе.
func (p *ServerPlan) Complete([]byte) (rrp.PayloadCrypto, error) {
	return nil, fmt.Errorf("%w: wireguard использует WG_INIT/WG_RESP", ErrKeyExchange)
}

// ClientInitFrameType — кадр 0x27 WG_INIT маршрутизируется сюда.
func (p *ServerPlan) ClientInitFrameType() uint8 { return rrp.TypeWgInit }

// OnClientInit — обработка настоящего WG msg1 по канону Noise_IKpsk2:
// mac1 → enc_static → enc_timestamp (TAI64N anti-replay) → msg2 → KDF3(psk).
func (p *ServerPlan) OnClientInit(payload []byte) (uint8, []byte, rrp.PayloadCrypto, error) {
	if p.pair == nil {
		return 0, nil, nil, fmt.Errorf("%w: KEY_REQ не отправлялся", ErrKeyExchange)
	}
	msg2, sh, err := HandshakeRespond(&p.pair.Priv, &p.pair.Pub, &p.psk, payload, &p.lastStamp)
	if err != nil {
		return 0, nil, nil, err
	}
	if p.log != nil {
		p.log.Info("wireguard: handshake OK (Noise_IKpsk2 + PSK=SHA256(token))",
			"session", p.sid, "transport_keys", "ChaCha20-Poly1305 ×2, window 2048")
	}
	return rrp.TypeWgResp, msg2, &SessionCrypto{tr: NewTransportServer(sh)}, nil
}

// TokenPSK — наш ключ доверия для клиентской стороны (KAT/тесты):
// PSK хендшейка WG = SHA256(token) — обе стороны считают независимо.
func TokenPSK(token string) [KeySize]byte {
	sum := sha256.Sum256([]byte(token))
	return sum
}
