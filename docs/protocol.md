# RRP/1 — ReverseRay Protocol v1 (v0.8: + mtproto2, модули)

Транспорт: TCP + **TLS 1.3** (MinVersion), ALPN `reverseray/1`.
Клиент (телефон) всегда инициирует соединение — серверу не нужны входящие порты из мобильных сетей.

## Кадры

Заголовок 12 байт, big-endian:

```
[u8 version=1][u8 type][u16 flags][u32 stream_id][u32 payload_len]
```

| Тип | Код | Направление | Payload |
|---|---|---|---|
| HELLO | 0x01 | C→S | JSON `{agent, ver, device, caps?, max_streams, proto?, protocols?}` |
| HELLO_OK | 0x02 | S→C | JSON `{session_id, server_ver, nonce, tunnel_window, proto, protocols}` |
| AUTH | 0x03 | C→S | JSON `{mode:"token-hmac", hmac, nonce}` |
| READY | 0x04 | S→C | JSON `{tunnel_id, role:"active", max_streams, tunnel_window, proto, protocols}` |
| OPEN | 0x10 | S→C | `[u8 atyp][addr][u16 port]`; домен: `[3][len][name][port]` |
| OPEN_OK | 0x17 | C→S | `[u8 err_code]` (0 = дial успешен) |
| DATA | 0x11 | оба | сырые байты стрима |
| CLOSE | 0x12 | оба | `[u8 err_code]` |
| WINDOW | 0x13 | оба | `[u32be increment]` |
| PING/PONG | 0x14/0x15 | оба | 8 байт nonce |
| STATS | 0x20 | C→S | JSON `{bytes_in, bytes_out, rtt_ms}` |
| UDP_ASSOC | 0x21 | S→C | пустой; `stream_id` = id ассоциации; телефон отвечает OPEN_OK(err) |
| UDP_DATA | 0x22 | оба | `[u8 atyp][addr][u16 port][data]`; S→C — назначение, C→S — фактический источник |
| PROBE | 0x23 | оба | C→S: JSON `{"target":"host:port","timeout_ms":N}`; S→C: `{"ok":bool,"err":"","proto":"…"}` |
| KEY_REQ | 0x24 | S→C | JSON `{p: b64url(256Б), g: 3, g_a: b64url(256Б)}` — только для proto=mtproto2 |
| KEY_RESP | 0x25 | C→S | JSON `{g_b: b64url(256Б)}` — после него DATA/UDP_DATA в MTProto-конверте |
| ERROR | 0x7F | оба | `[u16be code][utf8 msg]` |

Лимиты payload (hardening): DATA ≤ 65535; **все остальные ≤ 4096**. Нарушение → ERROR + закрытие сессии.

## Аутентификация

- Токен: 32 байта, base64url (`rrp://TOKEN@host:443/?pin=CA_PIN&name=phone-1&proto=rrp1`).
- Сервер хранит **только SHA256(token)**; утечка хранилища не раскрывает токены.
- `hmac = base64url_без_паддинга(HMAC-SHA256(key = SHA256(token), msg = nonce ‖ session_id))`.
- **Толерантность кодировок (v0.7.4)**: сервер принимает base64url (с/без паддинга)
  и стандартный base64 — это ОДНИ И ТЕ ЖЕ байты; сравнение остаётся constant-time.
  Канон для новых клиентов — base64url без паддинга (исторический баг 0.7.3:
  std-base64 → «auth failed»; ver числом → «bad HELLO»/ERROR 2).
- `nonce` — 128 бит crypto/rand из HELLO_OK, **одноразовый**, TTL 60 с (анти-replay).
- Сравнение constant-time; перебор всех токенов сервера (их единицы).
- Rate-limit: ≤120 handshakes/min/IP (v0.7, настраивается `limits.handshakes_per_min`
  / `RR_LIMITS_HANDSHAKES_PER_MIN`; до v0.7 было 10 по доке / 60 по коду — рвало
  легитимные реконнекты мобильных сетей); lockout — **только** за невалидный HMAC:
  5 неудач → 30 c·2^n (макс 10 мин). Мусорный TLS/сканы лочить не могут.

## Согласование протоколов (v0.7.4)

Реестр протоколов живёт в `server/internal/rrp/protocol.go` и зеркалится в
`core/RrpProtocols.kt`. Правила:

1. Клиент в HELLO присылает желаемый `proto` (значение `&proto=` ссылки) и
   список `protocols`, которые умеет; сервер в HELLO_OK/READY отвечает
   выбранным `proto` и **полным реестром** `protocols`.
2. Выбор: явный валидный id клиента → первый общий из списков → дефолт сервера.
3. **Мусор/пустота никогда не дают ошибку** — сводятся к дефолту (`rrp1`,
   самый стабильный протокол). Дефолт сервера задаётся `RR_PROTOCOL` (env/compose);
   мусорное значение env тоже сводится к дефолту.
4. Смена протокола на лету: APK поднимает provisional-сессию с новым `proto`,
   сервер подтверждает выбор в HELLO_OK/READY, затем клиент шлёт **PROBE** —
   сервер диалит `host:port` (по умолчанию `1.1.1.1:443`) с своего egress и
   отвечает `{ok, err}`. Коммит (запись ссылки/выбора) — только после успешного
   PROBE; иначе — мгновенный откат UI на последний рабочий протокол
   (3 ретрая по 5 с, cooldown 60 с от rate-limit).

## TLS / PKI

- При первом старте сервер генерирует **self-signed Ed25519 Root CA** (10 лет) и leaf-сертификат (90 дней, автопере выпуск).
- Клиент пинит **SPKI SHA256 CA** → ротация leaf не ломает клиентов. Смена CA = повторный enroll (QR).
- Дополнительно генерируется ECDSA P-256 leaf (резерв под TLS 1.2-compat профиль; по умолчанию выключен).
- Клиент использует **BcTlsCrypto** (lightweight, без JCA) — не зависит от
  платформенного провайдера "BC" (урезан на Android; причина исторического
  падения «no such algorithm: SHA-512 for provider BC»).
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

## mtproto2 — MTProto 2.0-конверт payload'ов (v0.8, модуль protocol.mtproto2)

Вход — приватный хендшейк ReverseRay (TLS 1.3 + SPKI-pin + HMAC). После READY
при согласованном `proto=mtproto2` стороны перегенерируют ключи DH-обменом,
и payload'ы **DATA/UDP_DATA** ходят в MTProto-конверте. Управляющие кадры
(OPEN/CLOSE/WINDOW/PING/PONG/STATS/PROBE/KEY_*) не шифруются.

### Обмен ключами (после READY)

| Тип | Код | Направление | Payload |
|---|---|---|---|
| KEY_REQ | 0x24 | S→C | JSON `{p: b64url(256Б), g: 3, g_a: b64url(256Б)}` |
| KEY_RESP | 0x25 | C→S | JSON `{g_b: b64url(256Б)}` |

- `p` — официальный dh_prime Telegram (2048-битный safe prime; p и (p−1)/2
  простые, канон «known good» из Security Guidelines). Клиент сверяет p
  **байт-в-байт** (anti-logjam) и `g == 3` (p mod 3 = 2).
- Валидация публичных долей (обе стороны): `1 < peer < p−1` и коридор
  `[2^1984, p − 2^1984]` (рекомендация guidelines; 2048−64 = 1984).
- `auth_key` = 256 Б big-endian `g_ab`; `auth_key_id` = SHA1(auth_key)[0:8].
- salt = SHA256("mtproto2-salt:" ‖ rrp_session_id ‖ g_a ‖ g_b)[0:8];
  session_id конверта = SHA256("mtproto2:" ‖ rrp_session_id)[0:8].

### Конверт сообщения (payload кадра DATA/UDP_DATA)

```
[auth_key_id 8][msg_key 16][AES-256-IGE(inner)]
inner = [salt 8][session_id 8][msg_id 8][seq_no 4][len 4][data][pad]
```

- `msg_key = SHA256(auth_key[88+x : 120+x] ‖ inner)[8:24]` (канон 2.0);
  AES key/IV — каноническая таблица 2.0 (sha256_a/sha256_b);
  `x = 0` клиент→сервер, `x = 8` сервер→клиент.
- `msg_id` — чётный клиент→сервер, нечётный сервер→клиент; `seq_no` — 2·счётчик.
- `pad` — 16..31 случайных байт; при расшифровке проверяется канон
  12..1024 и воспроизведение msg_key (целостность); чужой auth_key_id и
  расхождение salt/session_id → сессия закрывается.
- DATA крупнее ~65.4 КБ режется сервером на чанки (поток DATA это позволяет);
  UDP_DATA крупнее лимита — дропается (семантика UDP).
- Кросс-языковой KAT: Go шифрует — Kotlin расшифровывает и наоборот
  (`server/internal/mtproto/katgen_test.go` ↔ `MtProtoKATTest.kt`).

## Модули (v0.8)

- Манифест `modules/modules.json` (schema 1) — ОБЩИЙ источник правды APK ↔
  сервер: реестр протоколов (`id`, `name`, `default`, `enabled`) + политика
  (`probe_default_target`, `dns_probe_names`).
- Правила одинаковые на обеих сторонах: `schema == 1`; id `[a-z0-9]{1,16}`;
  `rrp1` обязателен (фундамент); мусорный манифест НИКОГДА не применяется
  (фоллбек на предыдущий/встроенный); даунгрейд запрещён; скачивание
  только при изменении версии/хеша.
- Сервер: env `RR_MODULES_URL` / `RR_MODULES_AUTO` / `RR_MODULES_CHECK_HOURS`
  (по умолчанию 24 ч), сохранение в `state/modules.json`, применение
  реестра на горячую (`rrp.SetRegistry`; `rrp1` всегда присутствует).
- APK: вкладка «Обновление» → «Обновить модули», авто-применение при старте
  из filesDir/modules.json; реестр виден в переключателе протоколов.
- Согласование не менялось: клиент присылает `proto`/`protocols` в HELLO,
  сервер подтверждает в HELLO_OK/READY; протокол, которого нет у одной из
  сторон, просто не выбирается (авто-фоллбек).

## Логирование

Хосты назначения **не логируются** (redaction по умолчанию). ADMIN API: unix socket или `127.0.0.1` TCP — `healthz/readyz/metrics/sessions/tokens/reload/devices/kick`.

## Веб-морда (v0.7.4)

- `/ui` — read-only дашборд (vanilla JS, без зависимостей): туннели, стримы,
  устройства, auth OK/fail, egress IP, сессии (протокол/RTT/трафик).
  Авто-обновление 3 с; CSS `clamp/auto-fit` — скейл от старых телефонов до
  ультрашироких мониторов.
- `/status` — тот же срез в JSON (для скриптов/rr.sh).
- По умолчанию админ-порт слушает `127.0.0.1`; в LAN — через
  `RR_METRICS_BIND=0.0.0.0` (rr.sh делает это сам и печатает URL `http://<LAN_IP>:9090/ui`).
