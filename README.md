# ReverseRay

**Твой телефон = твой VPN.** Сервер выглядит как обычный SOCKS5/HTTP-прокси,
но весь трафик физически выходит с твоего Android-телефона (серый/резидентный IP за NAT/CGNAT).

```
[Приложения] → [Xray outbound: socks5] → [Docker: reverseray-server]
                                              │  TLS 1.3 туннель RRP/1
                                              │  (телефон инициирует сам → NAT не мешает)
                                              ▼
                                        [Android APK] → [Интернет]
```

Сервер **никогда не ходит в интернет сам** — он только просит телефон «диалнуть» хост.
DNS резолвится на телефоне. Приватность + резидентный IP без VPS-провайдера.

## Состав

| Компонент | Стек | Статус |
|---|---|---|
| `server/` | Go 1.27, ноль внешних зависимостей | ✅ работает: mixed SOCKS5/HTTP inbound, RRP/1, TLS 1.3, HMAC-токены, admin/metrics |
| `android/` | Kotlin, minSdk 14, targetSdk 36, BouncyCastle TLS | 🚧 скелет + pure-Kotlin протокольное ядро |
| `docs/protocol.md` | RRP/1 спека | ✅ |
| `landing/` | gh-pages | ✅ |

## Быстрый старт (5 минут)

### 1. Сервер

```bash
mkdir -p state && chown 65532:65532 state
docker compose up -d
# печать CA-pin + выдача токена устройству:
docker compose exec reverseray /reverseray enroll -state-dir /var/lib/reverseray \
  -name phone-1 -host YOUR_SERVER_IP -port 443
```

Добавь `"phone-1": "<sha256…>"` в `state/tokens.json` → `{"devices":{"phone-1":"…"}}`
и перечитай токены: `curl -X POST http://127.0.0.1:9090/tokens/reload`.

### 2. Телефон

Введи в приложении конфиг-строку из `enroll` (или отсканируй QR):

```
rrp://<token>@YOUR_SERVER_IP:443/?pin=<CA_PIN>&name=phone-1
```

### 3. Проверка

```bash
curl --proxy socks5h://127.0.0.1:1080 https://ifconfig.me
# → IP твоего телефона
```

Xray outbound:

```json
{
  "protocol": "socks",
  "settings": { "servers": [{ "address": "SERVER_IP", "port": 1080 }] }
}
```

## Сборка сервера без Docker

```bash
cd server && go test -race ./... && go build -o reverseray .
```

## Hardening (кратко)

- TLS 1.3 only, ALPN обязателен, SPKI-pin на CA, ротация leaf без разрыва клиентов
- Токены только как SHA-256; HMAC + одноразовый nonce (анти-replay); constant-time
- Frame-limits по типам (DATA ≤64КБ, control ≤4КБ) — OOM-защита; окна 512КБ/стрим, бюджет 16МБ/устройство
- Rate-limit handshake + lockout по IP; admin на localhost/unix; redaction хостов в логах
- Контейнер: distroless, non-root 65532, read_only, cap_drop ALL, no-new-privileges, pids_limit
- Автообновления контейнера **запрещены** — только digest-пин из `deploy/digests.yaml`

Подробно: [docs/protocol.md](docs/protocol.md), [SECURITY.md](SECURITY.md), [TZ-аудит v2](../TZ-reverseray-v2-audit.md).

## CI/CD

- `ci.yml`: gofmt + vet + `go test -race` + coverage + docker smoke
- `release.yml` (тег `v*`): бинари amd64/arm64/armv7 + SHA256SUMS → GitHub Releases; multi-arch образ → `ghcr.io/stelgen/reverseray`

## Лицензия

MIT — см. [LICENSE](LICENSE).

---

### EN (short)

ReverseRay turns an Android phone into the egress node of your personal proxy.
The Go server speaks SOCKS5/HTTP locally and relays connections to your phone
over an outbound-only TLS 1.3 tunnel (RRP/1, see `docs/protocol.md`).
No VPS provider IP — your phone's residential IP is the exit. See quickstart above.
