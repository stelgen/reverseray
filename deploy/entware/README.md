# ReversERay сервер — Netcraze Ultra NC-1812 (Entware, aarch64)

Статический бинарный сервер для роутера **Netcraze Ultra NC-1812**
(SoC MediaTek Filogic 820, 3× ARM Cortex-A73, **ARMv8-A / aarch64**,
Entware через OPKG — поддерживается производителем штатно).

## Что нужно

- Артефакт `reverseray-linux-arm64` из GitHub Releases (статическая сборка
  Go, CGO выключен — динамические библиотеки Entware не нужны).
- Entware, установленный во внутреннюю память или на USB
  (CLI: `opkg install /opt/...` — см. штатную инструкцию Netcraze
  «Installing OPKG Entware»).

## Установка

```sh
# 1. на роутере (Entware ssh/opkg-окружение)
curl -L -o /opt/tmp/reverseray https://github.com/stelgen/reverseray/releases/download/v1.5.1/reverseray-linux-arm64
mkdir -p /opt/bin /opt/etc/reverseray
install -m 0755 /opt/tmp/reverseray /opt/bin/reverseray

# 2. конфиг (enroll-ссылка генерируется сервером при первом старте)
/opt/bin/reverseray --help   # посмотреть флаги
/opt/bin/reverseray          # первый запуск — в stdout будет enroll-ссылка rrp://…

# 3. init-скрипт Entware
cat > /opt/etc/init.d/S99reverseray <<'EOF'
#!/bin/sh
### INIT-скрипт Entware: reverseray сервер
case "$1" in
  start)  /opt/bin/reverseray >/opt/etc/reverseray/log.txt 2>&1 & ;;
  stop)   killall reverseray ;;
  restart) killall reverseray; sleep 1; $0 start ;;
  *) echo "usage: $0 start|stop|restart" ;;
esac
EOF
chmod +x /opt/etc/init.d/S99reverseray
/opt/etc/init.d/S99reverseray start
```

## Примечания

- Фаервол роутера: откройте порт туннеля (по умолчанию из флагов запуска).
- Клиент-APK: вкладка «Серверы» → «+ Добавить сервер» → вставьте rrp://-ссылку
  сервера → «Проверить подключение» + «Подключить сразу».
- NC-1812 — aarch64: бинар собран `GOOS=linux GOARCH=arm64 CGO_ENABLED=0`,
  работает без opkg-зависимостей.
