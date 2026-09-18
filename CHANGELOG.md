# Changelog

## v0.1.0 — 2026-09-18

Первый рабочий релиз сервера.

### Server (Go, ноль внешних зависимостей)
- RRP/1: кадры 12B, JSON-контроль, мультиплексирование стримов, flow-control (окно 512КБ/стрим, бюджет 16МБ/устройство), PING/PONG, STATS
- TLS 1.3 only, ALPN reverseray/1, self-signed Ed25519 CA + leaf 90д (авто-ротация), ECDSA P-256 backup
- Auth: HMAC-SHA256 по SHA256(токен) + одноразовый nonce; rate-limit + lockout по IP
- Inbound: mixed SOCKS5/HTTP-CONNECT/absolute-URI, опц. user/pass, allowlist
- Admin API: /healthz /readyz /metrics (Prometheus text) /sessions /tokens/reload /devices/kick; unix socket
- Docker: distroless non-root, read_only, cap_drop ALL, healthcheck; compose hardened (digest-пины, без автообновлений)
- CI: gofmt/vet/test -race/coverage + docker smoke; release: бинари amd64/arm64/armv7 + multi-arch ghcr

### Android
- Скелет + pure-Kotlin ядро протокола (кадры, SSRF-guard, URI), юнит-тесты

### Известные ограничения v0.1
- UDP через туннель — v1.1; WS-транспорт — v1.1; пул телефонов с балансировкой — v1.2
