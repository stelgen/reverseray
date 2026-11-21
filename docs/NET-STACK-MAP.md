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
| `core/RrpClientStreams.kt` | стримы: OPEN/OPEN_OK/pumpOutgoing, паркинг сокетов, OPEN_RESUME | `internal/rrp/session_stream.go` |
| `core/RrpClientUdp.kt` | UDP-ассоциации (assoc/приём/доставка) | `internal/rrp/session_udp.go` |
| `core/RrpFrameCodec.kt` | wire-кодеки: u16/u32 BE, MiniJson, hex-дамп (rawHex) | `internal/rrp/frame.go` (кодеки) |
| `core/RrpClientSwitch.kt` | бесшовная смена 0x2C + паркинг payload | `internal/rrp/session_switch.go` (план), `internal/hub` |
| `core/RrpClientHealth.kt` | PING-планировщик, PROBE/E2E-пробер, health-снимки | `internal/rrp` (pong/keepalive), PROBE-egress |
| `core/RrpFrame.kt` | канон кадров: sealed-таблица типов + nested-кодеки from/encode | `internal/rrp/frame.go` |
| `core/WsStream.kt` | транспорт ws | `internal/rrp/ws.go` |
| `core/MtProto.kt` / `core/Wg.kt` / `core/Torrent.kt` | конверты-хендшейки | `internal/mtproto` / `internal/wg` / `internal/bt` |
| `core/Negotiation.kt` | согласование протокола HELLO↔HELLO_OK | `internal/rrp` (negotiate) |
| `core/AutoBalancer.kt` / `E2eProbe.kt` | авто-свитчи по деградации (свежесть verdict'ов v1.8.10) | — (клиентская логика; DATA-зеркало: `cmd/prodprobe`) |
| `core/ConnectionManager.kt` | пер-сессия: backoff, тики балансера (guard авто/ротации v1.8.10) | — |
| `core/ProtoFallback.kt` / `ProtoRotator.kt` | фоллбек на rrp1 / расписание ротации | — |
| `service/TunnelService.kt` | андроид-сервис: компаньон/константы, lifecycle | `internal/serverapp` |
| `service/TunnelConfig.kt` | резолв конфига/URI, buildClient/NoisePolicy, camCtl | `internal/rrp/protocol.go` |
| `service/TunnelSessionCmds.kt` | session-команды: switchProtocol/commitProto/camouflage/probeProfile | `internal/rrp/session_switch.go` |
| `service/TunnelRunners.kt` / `TunnelStats.kt` / `TunnelRotate.kt` / `TunnelSession.kt` | runners/spawn, статы/пуши, ротация | `internal/serverapp` |

## Сервер (server/)

| Файл | Зона |
|---|---|
| `internal/rrp/session.go` | сессия: типы, Run/handle-dispatcher, keepalive |
| `internal/rrp/session_switch.go` | WG/BT/ProtoSwitch/CamCtl-хендлеры, KEY_RESP+дедлайн |
| `internal/rrp/protocol.go` | HELLO/AUTH/согласование |
| `internal/rrp/frame.go`, `ws.go` | канон кадров, ws-транспорт |
| `internal/inbound/mixed.go` | TLS-приёмник: Inbound/Serve/handle, dial, encodeHost |
| `internal/inbound/mixed_socks5.go` | SOCKS5 (RFC 1928): greet/auth/target/ошибки |
| `internal/inbound/mixed_http.go` | HTTP-прокси: CONNECT, absolute-URI, basic-auth |
| `internal/inbound/mixed_relay.go` | релей: half-close relay, stream-relay + resume-паркинг |
| `internal/mtproto|wg|bt` | конверты (та же крипта, что client/*.kt) |
| `cmd/prodprobe/{main,envelopes,switch}.go` | диагностика прода: линия/PROBE, конверты, цепочка свитчей |

## Транш-2 (v1.9.0) — выполнено

- Клиент: `TunnelService.kt` 1604→869 (+TunnelConfig 162, TunnelSessionCmds 254); `RrpClient.kt` 1423→1075 (+RrpClientStreams 259, RrpClientUdp 99); `RrpFrame.kt` 881→749 (+RrpFrameCodec 146; sealed-канон не тронут). Регресс «не-wg протоколы при ре-кее» закрыт: `SwitchParking.parkIf{pendingSwitchTarget != null}` — паркинг payload на время ре-кея (транш-1) распространён на открытые стримы.
- Сервер: `session.go` 662→449 (+session_lifecycle 87; зоны stream/switch уже были вынесены в session_stream/session_switch — туда до-слиты openStream-блок и KEY_RESP+дедлайн); `mixed.go` 525→156 (+mixed_socks5 153, mixed_http 120, mixed_relay 135).

## Очередь дробления (следующие транши)

1. `core/RrpFrame.kt` (749): только если станет возможным без нарушения sealed-канона (nested-кодеки в companions).
2. `internal/rrp/handshake.go`/`crypto.go`: аллокация зон консольных конвертов.
3. UI-события сервиса (`TunnelService` → `TunnelEvents.kt`), если сервис снова разрастётся.
