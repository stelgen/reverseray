package rrp

import "strings"

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
	// Name — человекочитаемое имя для GUI/логов.
	Name string
	// Default — true для одного стабильного протокола по умолчанию.
	Default bool
}

// ProtocolRRP1 — текущий стабильный протокол: RRP/1 кадры поверх TLS
// (сырой TCP или WebSocket-апгрейд /rrp).
var ProtocolRRP1 = Protocol{ID: "rrp1", Name: "RRP/1", Default: true}

// supportedProtocols — реестр протоколов, которые сервер УМЕЕТ и принимает
// по умолчанию (пользовательский запрос: «сервер должен принимать все
// протоколы по умолчанию»). Новые протоколы добавляются сюда.
var supportedProtocols = []Protocol{ProtocolRRP1}

// DefaultProtocolID — самый стабильный протокол (имплементирован у нас всегда).
const DefaultProtocolID = "rrp1"

// SupportedProtocols returns the full registry.
func SupportedProtocols() []Protocol {
	out := make([]Protocol, len(supportedProtocols))
	copy(out, supportedProtocols)
	return out
}

// SupportedIDs returns protocol IDs in registry order.
func SupportedIDs() []string {
	out := make([]string, 0, len(supportedProtocols))
	for _, p := range supportedProtocols {
		out = append(out, p.ID)
	}
	return out
}

// IsSupported reports whether id is in the registry.
func IsSupported(id string) bool {
	for _, p := range supportedProtocols {
		if strings.EqualFold(p.ID, id) {
			return true
		}
	}
	return false
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
