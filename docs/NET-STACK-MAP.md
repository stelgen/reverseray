# Карта сетевого стека (зеркало сервер↔клиент)

Единый канон — **docs/protocol.md** (кадры, хендшейки, бесшовная смена).
Кросс-язычная верификация — KAT-векторы: Go `katgen_test.go` → JSON → Kotlin
`MtProtoKATTest` / `TorrentKATTest` / `WgKATTest` (одна и та же крипта
обеих сторон проверяется одними векторами).

Правило файлов (v1.8.10, бест-практис дробления): файл = одна зона
ответственности, ориентир 100–200 строк (сквозные таблицы/канон допустимы);
дробление — extension-функции того же пакета (Kotlin) / тот же пакет (Go),
`private → internal` у задетых членов, поведение не меняется.

## Клиент (android/app/src/main/java/dev/stelgen/reverseray)

| Файл | Зона | Зеркало на сервере |
|---|---|---|
| `core/RrpClient.kt` | ядро: TLS+pin, HELLO/AUTH/READY, dispatch, frame IO, close | `internal/rrp/session.go`, `internal/inbound/mixed.go` |
| `core/RrpClientSwitch.kt` | бесшовная смена 0x2C + паркинг payload | `internal/rrp/session_switch.go` (план), `internal/hub` |
| `core/RrpClientHealth.kt` | PING-планировщик, PROBE/E2E-пробер, health-снимки | `internal/rrp` (pong/keepalive), PROBE-egress |
| `core/RrpFrame.kt` | канон кадров (типы, кодеки) | `internal/rrp/frame.go` |
| `core/WsStream.kt` | транспорт ws | `internal/rrp/ws.go` |
| `core/MtProto.kt` / `core/Wg.kt` / `core/Torrent.kt` | конверты-хендшейки | `internal/mtproto` / `internal/wg` / `internal/bt` |
| `core/Negotiation.kt` | согласование протокола HELLO↔HELLO_OK | `internal/rrp` (negotiate) |
| `core/AutoBalancer.kt` / `E2eProbe.kt` | авто-свитчи по деградации (свежесть verdict'ов v1.8.10) | — (клиентская логика; DATA-зеркало: `cmd/prodprobe`) |
| `core/ConnectionManager.kt` | пер-сессия: backoff, тики балансера (guard авто/ротации v1.8.10) | — |
| `core/ProtoFallback.kt` / `ProtoRotator.kt` | фоллбек на rrp1 / расписание ротации | — |
| `service/TunnelService.kt` (+TunnelRotate.kt, TunnelSession.kt…) | андроид-интеграция туннеля | `internal/serverapp` |

## Сервер (server/)

| Файл | Зона |
|---|---|
| `internal/rrp/session.go` | сессия: кадры, окна, keepalive |
| `internal/rrp/protocol.go` | HELLO/AUTH/согласование |
| `internal/rrp/frame.go`, `ws.go` | канон кадров, ws-транспорт |
| `internal/inbound/mixed.go` | TLS-приёмник (альпинистские обёртки) |
| `internal/mtproto|wg|bt` | конверты (та же крипта, что client/*.kt) |
| `cmd/prodprobe/{main,envelopes,switch}.go` | диагностика прода: линия/PROBE, конверты, цепочка свитчей |

## Очередь дробления (следующие транши)

1. `service/TunnelService.kt` (1600+): зоны runners/spawn, session-команды, UI-события.
2. `core/RrpClient.kt` (1423): зоны streams (phone-side стримы/UDP) и crypto-конвертеры.
3. `core/RrpFrame.kt` (881): таблица типов ↔ кодеки ↔ hex-отладка.
4. Сервер: `internal/rrp/session.go` (662) → `session_switch.go`; `internal/inbound/mixed.go` (525).
