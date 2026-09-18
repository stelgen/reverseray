# Security Policy

## Threat model

| Угроза | Митигация |
|---|---|
| Открытый прокси | inbound auth (user/pass) + IP allowlist + rate-limit |
| MitM | TLS 1.3 + SPKI-pin (CA), ALPN обязателен, запрет downgrade |
| Replay аутентификации | одноразовый nonce (TTL 60 с) + HMAC-SHA256 |
| Кража хранилища токенов | сервер хранит только SHA256(token); HMAC-ключ = хэш |
| SSRF в домашнюю сеть телефона | блэклист приватных диапазонов на клиенте (по умолч. on) |
| OOM/DoS сервера | frame-limits по типам, окно 512КБ/стрим, бюджет 16МБ/устройство, max streams |
| Брутфорс AUTH | 10 handshakes/min/IP, lockout 30с·2^n до 10 мин |
| Утечка приватности в логах | хосты назначения не логируются (redaction default) |
| Подмена APK | подпись релиза + SHA256SUMS + fingerprint в README |
| Компрометация телефона | per-device токены, revoke, kick, ротация CA через re-enroll |

## Ответственность

Весь egress-трафик идёт с резидентного IP телефона. Владелец телефона отвечает
за исходящий трафик. Используй per-device токены и мгновенный revoke.

## Хранение секретов на сервере

- `state/` — 0700; `ca.key`, `leaf*.key` — 0600, только non-root пользователь контейнера.
- Токены — только хэши. Бэкап `state/` перед апгрейдом (см. README deploy).

## Сообщение об уязвимостях

Приватно: security@ (см. профиль GitHub) или GitHub Security Advisory. Ответ ≤72 ч.
