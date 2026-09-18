# RRP/1 — ReverseRay Protocol v1

Транспорт: TCP + **TLS 1.3** (MinVersion), ALPN `reverseray/1`.
Клиент (телефон) всегда инициирует соединение — серверу не нужны входящие порты из мобильных сетей.

## Кадры

Заголовок 12 байт, big-endian:

```
[u8 version=1][u8 type][u16 flags][u32 stream_id][u32 payload_len]
```

| Тип | Код | Направление | Payload |
|---|---|---|---|
| HELLO | 0x01 | C→S | JSON `{agent, ver, device, caps?, max_streams}` |
| HELLO_OK | 0x02 | S→C | JSON `{session_id, server_ver, nonce, tunnel_window}` |
| AUTH | 0x03 | C→S | JSON `{mode:"token-hmac", hmac}` |
| READY | 0x04 | S→C | JSON `{tunnel_id, role:"active", max_streams, tunnel_window}` |
| OPEN | 0x10 | S→C | `[u8 atyp][addr][u16 port]`; домен: `[3][len][name][port]` |
| OPEN_OK | 0x17 | C→S | `[u8 err_code]` (0 = дial успешен) |
| DATA | 0x11 | оба | сырые байты стрима |
| CLOSE | 0x12 | оба | `[u8 err_code]` |
| WINDOW | 0x13 | оба | `[u32be increment]` |
| PING/PONG | 0x14/0x15 | оба | 8 байт nonce |
| STATS | 0x20 | C→S | JSON `{bytes_in, bytes_out, rtt_ms}` |
| ERROR | 0x7F | оба | `[u16be code][utf8 msg]` |

Лимиты payload (hardening): DATA ≤ 65535; **все остальные ≤ 4096**. Нарушение → ERROR + закрытие сессии.

## Аутентификация

- Токен: 32 байта, base64url (`rrp://TOKEN@host:443/?pin=CA_PIN&name=phone-1`).
- Сервер хранит **только SHA256(token)**; утечка хранилища не раскрывает токены.
- `hmac = base64url(HMAC-SHA256(key = SHA256(token), msg = nonce ‖ session_id))`.
- `nonce` — 128 бит crypto/rand из HELLO_OK, **одноразовый**, TTL 60 с (анти-replay).
- Сравнение constant-time; перебор всех токенов сервера (их единицы).
- Rate-limit: ≤10 handshakes/min/IP; 5 неудач → lockout 30 c·2^n (макс 10 мин).

## TLS / PKI

- При первом старте сервер генерирует **self-signed Ed25519 Root CA** (10 лет) и leaf-сертификат (90 дней, автопере выпуск).
- Клиент пинит **SPKI SHA256 CA** → ротация leaf не ломает клиентов. Смена CA = повторный enroll (QR).
- Дополнительно генерируется ECDSA P-256 leaf (резерв под TLS 1.2-compat профиль; по умолчанию выключен).
- 0-RTT/early data не используется; session resumption не допускает пропуска AUTH.

## Flow control

- Окно на стрим: старт 512 КБ, максимум 4 МБ (WINDOW-инкременты).
- Бюджет на сессию (устройство): 16 МБ outstanding — защита от OOM.
- Стримов на туннель ≤ 256 (конфиг); туннелей на устройство ≤ 8; dial — least-outstanding.

## Тайминги

- PING сервера каждые 60 с; idle-таймаут сессии 180 с; dial 10 с.
- Client reconnect: exp backoff 1→60 с ±30% jitter; мгновенный retry при смене сети (cooldown 3 с).

## Anti-SSRF (клиент)

Телефон отказывается диалить (если не включён «разрешить LAN»):
`0.0.0.0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12, 192.168/16, 198.18/15, 224/4, 240/4, ::1, fc00::/7, fe80::/10, ff00::/8`, имена `localhost`.

## Логирование

Хосты назначения **не логируются** (redaction по умолчанию). ADMIN API: unix socket или `127.0.0.1` TCP — `healthz/readyz/metrics/sessions/tokens/reload/devices/kick`.
