package rrp

import (
	"strings"
	"sync"
)

// Протоколы туннеля ReverseRay.
//
// Архитектура рассчитана на МНОГО протоколов: идентификатор — короткая
// строка-токен [a-z0-9]{1,16}, согласовывается в рукопожатии (HELLO →
// HELLO_OK/READY) и передаётся в ссылке как &proto=<id>.
//
// Правила согласования (см. Negotiate):
//  1. клиент прислал валидный id, поддерживаемый сервером → берём его;
//  2. клиент прислал мусор/пустоту/неподдерживаемый id → первый id из
//     списка клиента, который сервер поддерживает;
//  3. ничего общего нет → серверный дефолт (стабильный RRP/1).
//
// Любое мусорное значение НЕ должно ломать ни сервер, ни клиент:
// NormalizeProto сводит всё к дефолту.
type Protocol struct {
	// ID — канонический идентификатор в ссылке и в рукопожатии ("rrp1").
	ID string
	// Name — человекочитаемое имя для GUI/логов (содержит публичную версию:
	// "RRP/1", "MTProto/2"). Новые протоколы обязаны нести версию в Name.
	Name string
	// Ver — публичная версия протокола ("1", "2.0"). v0.8.1: пробрасывается
	// во весь стек (GUI/логи/статусы). Если публичной версии в природе нет —
	// пустая строка: тогда нигде ничего не показываем (канон «пусто»).
	Ver string
	// Default — true для одного стабильного протокола по умолчанию.
	Default bool
}

// ProtocolRRP1 — текущий стабильный протокол: RRP/1 кадры поверх TLS
// (сырой TCP или WebSocket-апгрейд /rrp).
var ProtocolRRP1 = Protocol{ID: "rrp1", Name: "RRP/1", Ver: "1", Default: true}

// ProtocolMTProto2 — MTProto 2.0-конверт payload'ов DATA/UDP_DATA поверх
// RRP/1 (v0.8, модуль protocol.mtproto2): после приватного хендшейка
// (TLS+HMAC) ключи перегенерируются DH-обменом, телом сообщения становится
// AES-256-IGE конверт MTProto 2.0 (auth_key_id/msg_key/IGE).
var ProtocolMTProto2 = Protocol{ID: "mtproto2", Name: "MTProto/2", Ver: "2.0", Default: false}

// regMu защищает реестр: модули (modules.Syncer) применяют манифест
// на горячую, параллельно идут хендшейки (v0.8).
var regMu sync.RWMutex

// supportedProtocols — реестр протоколов, которые сервер УМЕЕТ и принимает
// по умолчанию (пользовательский запрос: «сервер должен принимать все
// протоколы по умолчанию»). Наполняется встроенными + манифестом модулей
// (SetRegistry). rrp1 присутствует ВСЕГДА — это фундамент.
var supportedProtocols = []Protocol{ProtocolRRP1, ProtocolMTProto2}

// registryVersion — версия реестра (берётся из манифеста модулей; пусто = встроенная).
var registryVersion = ""

// DefaultProtocolID — самый стабильный протокол (имплементирован у нас всегда).
const DefaultProtocolID = "rrp1"

// RegistryVersion возвращает версию активного реестра ("" — встроенный).
func RegistryVersion() string {
	regMu.RLock()
	defer regMu.RUnlock()
	return registryVersion
}

// SetRegistry заменяет реестр протоколов (манифест модулей).
// Гарантии: rrp1 остаётся и остаётся дефолтом; пустой/битый список НЕ
// применён (возвращается false); «enabled:false» записи не попадают.
func SetRegistry(ps []Protocol, version string) bool {
	regMu.Lock()
	defer regMu.Unlock()
	out := make([]Protocol, 0, len(ps)+1)
	hasDefault := false
	for _, p := range ps {
		p.ID = NormalizeID(p.ID)
		if p.ID == "" {
			continue
		}
		p.Ver = SanitizeVer(p.Ver)
		if p.ID == DefaultProtocolID {
			hasDefault = true
			p.Default = true
		}
		out = append(out, p)
	}
	if !hasDefault {
		out = append(out, ProtocolRRP1)
	}
	// дубликаты не допустимы
	seen := map[string]bool{}
	final := out[:0]
	for _, p := range out {
		if seen[p.ID] {
			continue
		}
		seen[p.ID] = true
		final = append(final, p)
	}
	supportedProtocols = final
	registryVersion = version
	return true
}

// SupportedProtocols returns the full registry.
func SupportedProtocols() []Protocol {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]Protocol, len(supportedProtocols))
	copy(out, supportedProtocols)
	return out
}

// SupportedIDs returns protocol IDs in registry order.
func SupportedIDs() []string {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]string, 0, len(supportedProtocols))
	for _, p := range supportedProtocols {
		out = append(out, p.ID)
	}
	return out
}

// IsSupported reports whether id is in the registry.
func IsSupported(id string) bool {
	regMu.RLock()
	defer regMu.RUnlock()
	for _, p := range supportedProtocols {
		if strings.EqualFold(p.ID, id) {
			return true
		}
	}
	return false
}

// NormalizeID валидирует id протокола: [a-z0-9]{1,16}; мусор → "".
func NormalizeID(id string) string {
	s := strings.ToLower(strings.TrimSpace(id))
	if s == "" || len(s) > 16 {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return ""
		}
	}
	return s
}

// SanitizeVer чистит версию протокола: печатные символы без пробелов/кавычек,
// максимум 16 — иначе "" (мусорная версия = «версии нет», не ошибка; канон:
// мусор никогда не ломает стек).
func SanitizeVer(v string) string {
	s := strings.TrimSpace(v)
	if s == "" || len(s) > 16 {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
			c == '.' || c == '-' || c == '_' || c == '+' || c == '/'
		if !ok {
			return ""
		}
	}
	return s
}

// Label возвращает человекочитаемое имя протокола с версией ("RRP/1",
// "MTProto/2") из реестра. Имя приходит из манифеста модулей (общего для
// APK и сервера), поэтому обе стороны показывают ОДИННАКОВЫЕ метки.
// Неизвестный id → сам id (версии нет — ничего не приписываем).
func Label(id string) string {
	regMu.RLock()
	defer regMu.RUnlock()
	for _, p := range supportedProtocols {
		if p.ID == id {
			if p.Name != "" {
				return p.Name
			}
			return p.ID
		}
	}
	return id
}

// Ver возвращает публичную версию протокола ("1", "2.0") или "" —
// «версии нет, нигде не показываем» (канон v0.8.1).
func Ver(id string) string {
	regMu.RLock()
	defer regMu.RUnlock()
	for _, p := range supportedProtocols {
		if p.ID == id {
			return p.Ver
		}
	}
	return ""
}

// Labels — метки всех протоколов реестра (id → имя), для /status и /ui.
func Labels() map[string]string {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make(map[string]string, len(supportedProtocols))
	for _, p := range supportedProtocols {
		out[p.ID] = p.Name
	}
	return out
}

// Vers — публичные версии всех протоколов реестра (id → ver, "" = нет).
func Vers() map[string]string {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make(map[string]string, len(supportedProtocols))
	for _, p := range supportedProtocols {
		out[p.ID] = p.Ver
	}
	return out
}

// NormalizeProto canonicalizes any user/env/link value to a registry ID.
// Unknown, empty or garbage input → DefaultProtocolID (никогда не ошибка).
func NormalizeProto(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.Trim(s, "\"'`«»“”„‘’")
	if !IsSupported(s) {
		return DefaultProtocolID
	}
	// возвращаем канонический регистр из реестра
	for _, p := range supportedProtocols {
		if p.ID == s {
			return p.ID
		}
	}
	return DefaultProtocolID
}

// Negotiate picks the protocol for a session.
//
// clientProto — значение &proto= из ссылки клиента (может быть мусором);
// clientOffers — список, который клиент готов поддерживать; serverDefault —
// дефолт сервера (RR_PROTOCOL). Возвращает канонический id.
func Negotiate(clientProto string, clientOffers []string, serverDefault string) string {
	// 1) клиент явно попросил протокол (даже мусор сводится к дефолту, а не к ошибке)
	if strings.TrimSpace(clientProto) != "" {
		return NormalizeProto(clientProto)
	}
	// 2) первый общий протокол из списка клиента
	for _, offer := range clientOffers {
		if IsSupported(offer) {
			return NormalizeProto(offer)
		}
	}
	// 3) серверный дефолт — стабильный протокол
	return NormalizeProto(serverDefault)
}
