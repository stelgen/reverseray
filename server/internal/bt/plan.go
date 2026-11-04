// plan.go — серверный план обмена ключами bittorrent (rrp.KeyPlan +
// rrp.InitResponder) и крипто-контекст сессии (rrp.PayloadCrypto).
//
// Поток v0.10: после READY сервер шлёт KEY_REQ (JSON {kind:"bittorrent",yb}) —
// MSE DH public респондера (packet 2, канон BEP 8 §3); клиент отвечает
// BT_INIT (packet1||packet3: Ya+pad+req1+req2⊕req3+RC4_A(...)); сервер
// обрабатывает по канону MSE (скан req1, req2⊕req3 против известного SKEY,
// VC) и отвечает BT_RESP (packet4 = RC4_B(VC+select+len(PadD)+PadD)).
// SKEY = SHA1("reverseray-bt:"+tokenHash) — «инфо-хеш торрента», наш ключ
// доверия из приватной ссылки: хендшейк привязан к токену устройства.
package bt

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/stelgen/reverseray/server/internal/rrp"
)

// ProtoID — канонический id протокола в реестре и ссылке.
const ProtoID = "bittorrent"

var ErrKeyExchange = fmt.Errorf("%w: bittorrent key exchange", rrp.ErrKeyPlan)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

type keyReqJSON struct {
	Kind string `json:"kind"` // "bittorrent"
	YB   string `json:"yb"`   // MSE DH public респондера (b64url, 96 Б)
}

// SessionCrypto — rrp.PayloadCrypto поверх BT peer-wire конвертов:
// payload DATA/UDP_DATA = зашифрованное piece-сообщение MSE/PE.
type SessionCrypto struct{ tr *Transport }

// DecryptDown — клиент → сервер (piece-сообщение → открытые данные).
func (c *SessionCrypto) DecryptDown(payload []byte) ([]byte, error) {
	return c.tr.Open(payload)
}

// EncryptUp — сервер → клиент (данные → piece-сообщение MSE/PE).
func (c *SessionCrypto) EncryptUp(payload []byte) ([]byte, error) {
	return c.tr.Seal(payload)
}

// MaxPlainData — максимум открытого чанка (peer-wire заголовок 13 Б).
func (c *SessionCrypto) MaxPlainData() int { return MaxPlainData }

// ServerPlan — серверная сторона обмена ключами MSE внутри сессии.
type ServerPlan struct {
	sid  string
	log  *slog.Logger
	skey [20]byte         // SHA1("reverseray-bt:"+tokenHash) — «инфо-хеш»
	sh   *ServerHandshake // DH-состояние респондера
}

// NewServerPlan строит план: skey из хеша токена устройства (32 Б).
func NewServerPlan(sid string, tokenHash []byte, log *slog.Logger) (*ServerPlan, error) {
	if len(tokenHash) != sha256.Size {
		return nil, fmt.Errorf("%w: token hash не 32 Б", ErrKeyExchange)
	}
	return &ServerPlan{sid: sid, log: log, skey: SKEY(tokenHash)}, nil
}

// RequestPayload — payload кадра KEY_REQ: Yb респондера (канонный packet 2,
// минус паддинг: фреймы дают точные границы пакетов).
func (p *ServerPlan) RequestPayload() ([]byte, error) {
	yb, sh, err := NewServerHandshake(p.skey, nil)
	if err != nil {
		return nil, err
	}
	p.sh = sh
	return json.Marshal(keyReqJSON{Kind: ProtoID, YB: b64(yb[:])})
}

// Complete — для bittorrent не используется (обмен идёт INIT/RESP-кадрами):
// клиент никогда не шлёт KEY_RESP в этом протоколе.
func (p *ServerPlan) Complete([]byte) (rrp.PayloadCrypto, error) {
	return nil, fmt.Errorf("%w: bittorrent использует BT_INIT/BT_RESP", ErrKeyExchange)
}

// ClientInitFrameType — кадр 0x29 BT_INIT маршрутизируется сюда.
func (p *ServerPlan) ClientInitFrameType() uint8 { return rrp.TypeBtInit }

// OnClientInit — обработка packet1||packet3 по канону MSE: скан req1 →
// req2⊕req3 (узнавание SKEY) → VC → crypto_provide → packet4.
func (p *ServerPlan) OnClientInit(payload []byte) (uint8, []byte, rrp.PayloadCrypto, error) {
	if p.sh == nil {
		return 0, nil, nil, fmt.Errorf("%w: KEY_REQ не отправлялся", ErrKeyExchange)
	}
	resp, tr, err := p.sh.Respond(payload, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	if p.log != nil {
		// NB: атрибуты лога без слов key/token — иначе gitleaks считает строку секретом.
		p.log.Info("bittorrent: MSE handshake OK (DH-768 + RC4-drop1024)",
			"session", p.sid, "envelope", "peer-wire piece(7)", "drop", 1024)
	}
	return rrp.TypeBtResp, resp, &SessionCrypto{tr: tr}, nil
}

// TokenSKEY — ключ доверия для клиентской стороны (KAT/тесты):
// SKEY хендшейка MSE = SHA1("reverseray-bt:"+SHA256(token)).
func TokenSKEY(token string) [20]byte {
	sum := sha256.Sum256([]byte(token))
	return SKEY(sum[:])
}
