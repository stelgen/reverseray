#!/usr/bin/env bash
# ReverseRay deploy (v0.7+)
#
# Деплой «относительно текущего каталога»: запусти из любой папки —
# рядом с тобой появится подпапка reverseray/ со всем нужным:
#   reverseray/compose.yaml      прод-компоуз (образ пинится тегом RR_IMAGE_TAG)
#   reverseray/state/            каталог состояния (tokens.json, CA)
#   reverseray/.env              локальные переопределения (RR_IMAGE_TAG и др.)
#   reverseray/README-DEPLOY.md  что делать дальше
#
# Использование:
#   bash deploy/install.sh                  # из корня репо (тег по умолчанию)
#   RR_IMAGE_TAG=v0.7.0 bash deploy/install.sh
#   curl -fsSL <raw-url>/deploy/install.sh | bash   # без репо: скачает compose с GitHub
#
set -euo pipefail

IMAGE_TAG="${RR_IMAGE_TAG:-v0.7.0}"
DEST="${REVERSERAY_DEPLOY_DIR:-reverseray}"
REPO_RAW="https://raw.githubusercontent.com/stelgen/reverseray/${IMAGE_TAG}/compose.yaml"

# Сравнение версий vA.B.C (требуем >= v0.7.0 для деплой-скрипта из репо).
ver_ge() { [ "$(printf '%s\n' "${1#v}" "${2#v}" | sort -V | head -1)" = "${2#v}" ]; }

mkdir -p "${DEST}/state"

if [ -f "$(dirname "$0")/../compose.yaml" ] && ver_ge "${IMAGE_TAG}" v0.7.0; then
  # Репозиторный compose — источник правды.
  cp "$(dirname "$0")/../compose.yaml" "${DEST}/compose.yaml"
else
  # Автономный режим: тянем compose из репо по тегу.
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "${REPO_RAW}" -o "${DEST}/compose.yaml"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "${DEST}/compose.yaml" "${REPO_RAW}"
  else
    echo "error: нужен curl или wget (или запуск из корня репозитория)" >&2
    exit 1
  fi
fi

cat > "${DEST}/.env" << EOF
RR_IMAGE_TAG=${IMAGE_TAG}
RR_SOCKS_PORT=1080
RR_TUNNEL_PORT=4433
RR_METRICS_PORT=9090
# RR_PUBLIC_HOST=vpn.example.com   # DDNS-домен вместо IP в конфиг-строках
EOF

cat > "${DEST}/README-DEPLOY.md" << 'EOF'
# ReverseRay — деплой

Эта папка создана `deploy/install.sh` относительно каталога, где он был запущен.

## Запуск

```bash
cd reverseray
sudo docker compose up -d
# Первый старт: сервер сам создаст state/tokens.json (устройство phone-1)
sudo docker compose logs reverseray | grep -i connect
```

## Регистрация телефона

```bash
sudo docker compose exec reverseray /reverseray enroll -state-dir /var/lib/reverseray -name phone-1
```

Печатная строка вида `rrp://<token>@IP:4433/?pin=<CA_PIN>&name=phone-1` —
вставь её в приложение (или отсканируй QR). TCP 4433 и UDP 1080 должны быть
открыты в файрволе облака (UDP 1080 — для SOCKS5 UDP ASSOCIATE).

## Обновление (автообновления контейнера запрещены — только вручную)

```bash
RR_IMAGE_TAG=vX.Y.Z bash ../deploy/install.sh   # из корня репо, или
RR_IMAGE_TAG=vX.Y.Z curl -fsSL <raw-url>/deploy/install.sh | bash
cd reverseray && sudo docker compose up -d
```

Откат — предыдущий digest из deploy/digests.yaml (см. docs/WORKFLOW.md).
EOF

echo "✓ Deploy dir ready: ${DEST}/ (compose, state/, .env, README-DEPLOY.md)"
echo "  Далее: cd ${DEST} && sudo docker compose up -d"
