// crypto.go — хуки протокольных расширений payload'ов (v0.9.2).
//
// v0.8 вводил mtproto2: обмен ключами выполнялся В РУКОПОЖАТИЙНОМ потоке
// (mtproto.UpgradeServer читал KEY_RESP из того же сокета, что и Session.Run).
// Клиент после READY сразу отправляет PROBE-валидацию — гонка читателей:
// PROBE мог быть съеден апгрейдом («ждали KEY_RESP, получили 0x23») →
// reject «protocol error» → «PROBE not answered» на клиенте.
//
// v0.9.2: единственный читатель сокета — Session.Run. Обмен ключами идёт
// КАК CONTROL-КАДРЫ внутри сессии: сервер шлёт KEY_REQ через очередь
// записи, KEY_RESP читается в handle() на общих основаниях (параллельно
// могут приходить PROBE/PING — они не payload-кадры и крипто не требуют).
// Крипто-контекст включается на лету: после Complete() все DATA/UDP_DATA
// расшифровываются на входе и шифруются на выходе.
package rrp

import (
	"errors"
	"time"
)

// PayloadCrypto — конверт payload'ов DATA/UDP_DATA (mtproto2 и будущие
// протоколы-конверты). Реализация — internal/mtproto (AES-256-IGE).
type PayloadCrypto interface {
	// DecryptDown расшифровывает payload клиент → сервер (возвращает открытые данные).
	DecryptDown(payload []byte) ([]byte, error)
	// EncryptUp шифрует payload сервер → клиент.
	EncryptUp(payload []byte) ([]byte, error)
	// MaxPlainData — максимум ОТКРЫТОГО чанка (конверт добавляет заголовки
	// и паддинг: открытый чанк обязан быть меньше MaxDataPayload).
	MaxPlainData() int
}

// KeyPlan — обмен ключами протокола после READY (одна сессия — один план).
// Все методы вызываются только из горутины Session.Run: гонок нет.
type KeyPlan interface {
	// RequestPayload возвращает payload кадра KEY_REQ (JSON с p/g/g_a).
	RequestPayload() ([]byte, error)
	// Complete валидирует payload KEY_RESP (JSON с g_b) и возвращает
	// крипто-контекст. После успешного Complete сессия шифрует payload-кадры.
	Complete(keyRespPayload []byte) (PayloadCrypto, error)
}

// InitResponder — план обмена ключами, где после KEY_REQ следует БИНАРНЫЙ
// кадр инициации от клиента (v0.9.5, wireguard: WG_INIT/msg1), а сервер
// отвечает бинарным кадром (WG_RESP/msg2). Планы-«простые» (mtproto2) —
// только KEY_REQ/KEY_RESP, этот интерфейс им не нужен.
type InitResponder interface {
	KeyPlan
	// ClientInitFrameType — тип кадра-инициации, который сессия маршрутизирует
	// в OnClientInit.
	ClientInitFrameType() uint8
	// OnClientInit обрабатывает payload INIT-кадра клиента и возвращает тип
	// и payload ответного кадра (сервер отправит его через очередь записи)
	// и крипто-контекст (включается сразу — обмен завершён).
	OnClientInit(payload []byte) (respType uint8, respPayload []byte, pc PayloadCrypto, err error)
}

// ErrKeyPlan — план обмена ключами сломан (протокол не может быть исполнен).
var ErrKeyPlan = errors.New("rrp: key exchange plan failed")

// KeyExchangeTimeout — жёсткий дедлайн обмена ключами после READY:
// битый клиент не висит сессией вечно (idle-таймаут 180с слишком долгий).
const KeyExchangeTimeout = 15 * time.Second
