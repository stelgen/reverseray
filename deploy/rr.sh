#!/usr/bin/env bash
# ReverseRay rr.sh — автопилот деплоя (v0.8.3+)
#
# Запусти из ЛЮБОГО каталога — рядом появится подпапка reverseray/ со всем
# нужным (compose, state, .env). Скрипт сам решает: свежая установка,
# обновление версии или (по флагу) обнуление состояния — и в конце печатает
# готовую строку подключения для приложения.
#
# v0.8.3: ПРЕДФЛАЙТ и самопроверки — скрипт не молчит и не падает невнятно:
#   - проверка нужных файлов/команд (curl, docker compose) и прав на каталог;
#   - целостность скачанного compose.yaml (не HTML-мусор от прокси);
#   - проверка, что образ реально скачался (docker image inspect);
#   - ожидание healthcheck через docker inspect + РАННИЙ выход с диагностикой
#     (docker logs), если контейнер умер до healthy;
#   - внятный итог: строка подключения, Xray-outbound, веб-морда, диагностика.
#
# Использование:
#   sudo bash rr.sh                     # деплой/обновление до последнего релиза
#   sudo bash rr.sh --tag v0.8.3        # конкретная версия
#   sudo bash rr.sh --reset             # обнулить состояние (токены/CA) и пере-enroll
#   curl -fsSL <raw>/deploy/rr.sh -o rr.sh && sudo bash rr.sh
#
set -euo pipefail

IMAGE_REPO="ghcr.io/stelgen/reverseray"
DEFAULT_TAG="v0.9.2"
DEST="${REVERSERAY_DIR:-reverseray}"
DO_RESET=0
UI_LAN=1 # 1 = открывать веб-морду (/ui) в локальной сети; --no-ui закрывает в localhost
TAG=""

while [ $# -gt 0 ]; do
  case "$1" in
    --reset) DO_RESET=1; shift ;;
    --no-ui) UI_LAN=0; shift ;;
    --tag) TAG="${2:?нужна версия после --tag}"; shift 2 ;;
    *) echo "unknown flag: $1 (доступны --reset, --no-ui, --tag vX.Y.Z)"; exit 2 ;;
  esac
done

log()  { printf '==> %s\n' "$*"; }
warn() { printf '!!  %s\n' "$*"; }
die()  { printf 'XX  %s\n' "$*"; exit 1; }

# --- preflight: нужные команды (curl обязателен ещё до docker-проверок) ---
require_cmd() { command -v "$1" >/dev/null 2>&1 || die "нет команды '$1' — установи её и повтори (см. README)"; }
require_cmd curl

# --- docker: с sudo или без ---
# ВАЖНО: проверяем не только CLI, но и ЖИВОЙ демон (docker info):
# "docker compose version" работает и при мёртвом демоне — скрипт молча
# доезжал до pull и умирал невнятно (поймано в живом тесте).
DC="docker compose"
docker_ok() { docker info >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; }
if ! docker_ok; then
  if command -v sudo >/dev/null 2>&1 && sudo docker info >/dev/null 2>&1 && sudo docker compose version >/dev/null 2>&1; then
    DC="sudo docker compose"
  else
    die "docker compose не найден ИЛИ демон не запущен (запусти dockerd/systemctl start docker; или попробуй sudo bash rr.sh)"
  fi
fi
SUDO=""
case "$DC" in "sudo "*) SUDO="sudo " ;; esac
run() { $DC "$@"; }

# --- версия: --tag > env > последний релиз GitHub > DEFAULT_TAG ---
if [ -z "$TAG" ]; then
  TAG="${RR_IMAGE_TAG:-}"
fi
if [ -z "$TAG" ]; then
  TAG=$(curl -fsSL --max-time 10 "https://api.github.com/repos/stelgen/reverseray/releases/latest" \
        | grep -o '"tag_name": *"[^"]*"' | head -1 | cut -d'"' -f4 2>/dev/null || true)
fi
if [ -z "$TAG" ]; then
  # fallback: последний тег (когда /releases/latest недоступен — rate-limit/прокси)
  TAG=$(curl -fsSL --max-time 10 "https://api.github.com/repos/stelgen/reverseray/tags" \
        | grep -o '"name": *"[^"]*"' | head -1 | cut -d'"' -f4 2>/dev/null || true)
fi
if [ -z "$TAG" ]; then
  TAG="$DEFAULT_TAG"
  log "!! последний релиз не определён через GitHub API — запасной $DEFAULT_TAG (укажите --tag vX.Y.Z для принудительной версии)"
fi
log "Версия: $TAG (последний релиз GitHub)"

# --- целевой каталог (относительный) + права ---
mkdir -p "$DEST/state" 2>/dev/null || die "не могу создать каталог $DEST/state (нет прав? запусти с sudo)"
[ -w "$DEST" ] || [ -n "$SUDO" ] || die "каталог $DEST не доступен на запись — запусти с sudo"
cd "$DEST"
STATE="$PWD/state"
MARKER="$STATE/.enrolled"

# --- reset: обнулить состояние (токены/CA), чтобы всё пересоздалось ---
if [ "$DO_RESET" = "1" ]; then
  log "Обнуляю состояние (--reset): контейнер остановлен, state очищен"
  run down --remove-orphans >/dev/null 2>&1 || true
  $SUDO rm -rf "${STATE:?}/"* "$MARKER" 2>/dev/null || true
fi

# --- compose.yaml: скачать + ПРОВЕРИТЬ целостность ---
log "Скачиваю compose.yaml (тег $TAG)…"
RAW="https://raw.githubusercontent.com/stelgen/reverseray/${TAG}/compose.yaml"
curl -fsSL --max-time 20 "$RAW" -o compose.yaml.new || die "не удалось скачать compose.yaml ($RAW)"
# Целостность: манифест обязан содержать наш сервис, healthcheck и порт-маппинг.
# Ловим типовую беду «прокси вернул HTML-страницу вместо файла».
grep -q '^services:' compose.yaml.new        || die "compose.yaml.new не похож на манифест (нет services:) — прокси/сеть вернули мусор"
grep -q 'reverseray:' compose.yaml.new       || die "compose.yaml.new не содержит сервис reverseray — мусор вместо манифеста"
grep -q 'healthcheck:' compose.yaml.new      || die "compose.yaml.new без healthcheck — мусор вместо манифеста"
grep -q 'ghcr.io/stelgen/reverseray' compose.yaml.new || die "compose.yaml.new без образа ghcr.io/stelgen/reverseray — мусор вместо манифеста"
mv compose.yaml.new compose.yaml
log "compose.yaml целостный ✔"

printf 'RR_IMAGE_TAG=%s\nRR_SOCKS_PORT=1080\nRR_TUNNEL_PORT=4433\nRR_METRICS_PORT=9090\nRR_METRICS_BIND=%s\nRR_PROTOCOL=%s\nRR_HARDENING=true\nRR_MODULES_AUTO=true\nRR_MODULES_CHECK_HOURS=24\nRR_RESTART_DELAY=30\nRR_RESTART_MAX=20\n' \
  "$TAG" \
  "$([ "$UI_LAN" = "1" ] && echo 0.0.0.0 || echo 127.0.0.1)" \
  "${RR_PROTOCOL:-rrp1}" > .env

# --- pull + ПРОВЕРКА, что образ реально на месте ---
log "Тяну образ ${IMAGE_REPO}:${TAG}…"
run pull || warn "pull не прошёл (offline?) — попробую запустить то, что есть локально"
$SUDO docker image inspect "${IMAGE_REPO}:${TAG}" >/dev/null 2>&1 \
  || die "образ ${IMAGE_REPO}:${TAG} не найден локально после pull — проверь сеть/тег (registry ghcr.io)"

# --- up ---
run up -d || die "docker compose up -d не удался (см. вывод выше)"

# --- здоровье: docker inspect + РАННИЙ выход при смерти контейнера ---
log "Жду healthcheck…"
ok=""
for i in $(seq 1 45); do
  st=$($SUDO docker inspect --format '{{.State.Health.Status}}' reverseray 2>/dev/null || echo unknown)
  if [ "$st" = "healthy" ]; then ok=1; break; fi
  cstate=$($SUDO docker inspect --format '{{.State.Status}}' reverseray 2>/dev/null || echo unknown)
  if [ "$cstate" = "exited" ]; then
    warn "Контейнер УМЕР до healthy — не жду таймаут, диагностика:"
    break
  fi
  sleep 2
done
if [ -z "$ok" ]; then
  warn "Состояние контейнера:"
  $SUDO docker ps -a --filter name=reverseray --format 'table {{.Names}}\t{{.Status}}' 2>/dev/null || true
  warn "Последние логи:"
  run logs --tail 60 reverseray || true
  warn " governor FATAL в логах → состояние сломано: sudo bash rr.sh --reset"
  warn " exec /bin/busybox в логах   → старый образ с багом v0.8.2: обнови тег (v0.8.3+)"
  die "сервер не поднялся (не healthy)"
fi
log "Контейнер healthy ✔"

# --- enroll (идемпотентно: только если ещё не делали) ---
if [ ! -f "$MARKER" ]; then
  log "Регистрирую устройство phone-1 (enroll)…"
  ENROLL_OUT="$(mktemp)"
  run exec -T reverseray /reverseray enroll -state-dir /var/lib/reverseray -name phone-1 > "$ENROLL_OUT" 2>&1 || true
  touch "$MARKER" 2>/dev/null || $SUDO touch "$MARKER"
else
  log "Устройство уже зарегистрировано (state/.enrolled) — токен не меняю"
  ENROLL_OUT="$(mktemp)"
  run exec -T reverseray /reverseray enroll -state-dir /var/lib/reverseray -name phone-1 > "$ENROLL_OUT" 2>&1 || true
fi

# --- строка подключения ---
# v0.7.3: строка БЕЗ ведущих пробелов/переносов — новичок копирует как есть
LINE=$(grep -o '^rrp://[^[:space:]]*' "$ENROLL_OUT" 2>/dev/null | head -1 | tr -d '[:space:]' || true)
rm -f "${ENROLL_OUT:-/nonexistent}" 2>/dev/null || true
# LAN-IP хоста (роутер/машина с докером), не IP докер-бриджа — для Xray-аутбаунда
LAN_IP=$(ip -4 route get 1.0.0.0 2>/dev/null | grep -oE 'src [0-9.]+' | awk '{print $2}' | head -1)
[ -n "$LAN_IP" ] || LAN_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -n "$LAN_IP" ] || LAN_IP="<LAN_IP_ХОСТА>"
if [ -z "$LINE" ]; then
  warn "Строка не найдена в выводе enroll — попробуй вручную:"
  warn "  $DC exec reverseray /reverseray enroll -state-dir /var/lib/reverseray -name phone-1"
  exit 0
fi

echo
echo "=============================================================="
echo " ГОТОВО."
echo
echo " 1) СТРОКА ПОДКЛЮЧЕНИЯ ДЛЯ APK (скопируй ЦЕЛИКОМ, начиная с rrp://):"
echo "$LINE"
echo
echo " 2) OUTBOUND ДЛЯ XRAY (вставь в config.json -> outbounds;"
echo "    address = LAN-IP хоста ${LAN_IP} — как машину видит роутер/локалка,"
echo "    не IP докер-бриджа; если Xray на той же машине — оставь как есть):"
echo '{ "tag": "reverseray-out", "protocol": "socks", "settings": { "servers": [ { "address": "'"${LAN_IP}"'", "port": 1080 } ] } }'
echo
echo " Проверка прокси:  curl --proxy socks5h://127.0.0.1:1080 https://ifconfig.me"
echo
echo " ВЕБ-МОРДА (панель: сессии, трафик, IP, протоколы):"
if [ "$UI_LAN" = "1" ]; then
  echo "   http://${LAN_IP}:${RR_METRICS_PORT:-9090}/ui   ← открой в браузере на любом"
  echo "   устройстве этой же локальной сети (телефон/ноутбук)"
  echo "   (закрыть наружу: sudo bash rr.sh --no-ui)"
else
  echo "   http://127.0.0.1:${RR_METRICS_PORT:-9090}/ui (только localhost)"
fi
echo " Протокол по умолчанию: RR_PROTOCOL=${RR_PROTOCOL:-rrp1} (мусор → автоматически стабильный rrp1)"
echo " WAN-hardening: включён (анти-скан/tarpit на туннельном порту; RR_HARDENING)"
echo " Модули: авто-чек манифеста раз в сутки (RR_MODULES_AUTO; качается только при изменении)"
echo " Healthcheck: включён; governor (в самом бинаре) рестартит не чаще 1 раза/30 с,"
echo "   20 падений подряд → контейнер умирает с ошибкой (без бесконечного цикла)"
echo " Обнова (опционально, уровень ХОСТА — ICMP-пинги отвечает ядро, не приложение):"
echo "   sudo iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 30/min -j ACCEPT"
echo "   sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP"
echo " Обновление позже: sudo bash rr.sh            (версия возьмётся с GitHub)"
echo " Обнулить state:   sudo bash rr.sh --reset"
echo "=============================================================="