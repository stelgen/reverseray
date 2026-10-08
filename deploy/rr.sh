#!/usr/bin/env bash
# ReverseRay rr.sh — автопилот деплоя (v0.7.2+)
#
# Запусти из ЛЮБОГО каталога — рядом появится подпапка reverseray/ со всем
# нужным (compose, state, .env). Скрипт сам решает: свежая установка,
# обновление версии или (по флагу) обнуление состояния — и в конце печатает
# готовую строку подключения для приложения.
#
# Использование:
#   sudo bash rr.sh                     # деплой/обновление до последнего релиза
#   sudo bash rr.sh --tag v0.7.2        # конкретная версия
#   sudo bash rr.sh --reset             # обнулить состояние (токены/CA) и пере-enroll
#   curl -fsSL <raw>/deploy/rr.sh -o rr.sh && sudo bash rr.sh
#
set -euo pipefail

IMAGE_REPO="ghcr.io/stelgen/reverseray"
DEFAULT_TAG="v0.8.2"
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

# --- docker: с sudo или без ---
DC="docker compose"
docker_ok() { docker compose version >/dev/null 2>&1; }
if ! docker_ok; then
  if command -v sudo >/dev/null 2>&1 && sudo docker compose version >/dev/null 2>&1; then
    DC="sudo docker compose"
  else
    die "docker compose не найден (или нет прав; попробуй sudo bash rr.sh)"
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
[ -n "$TAG" ] || TAG="$DEFAULT_TAG"
log "Версия: $TAG"

# --- целевой каталог (относительный) ---
mkdir -p "$DEST/state"
cd "$DEST"
STATE="$PWD/state"
MARKER="$STATE/.enrolled"

# --- reset: обнулить состояние (токены/CA), чтобы всё пересоздалось ---
if [ "$DO_RESET" = "1" ]; then
  log "Обнуляю состояние (--reset): контейнер остановлен, state очищен"
  run down --remove-orphans >/dev/null 2>&1 || true
  $SUDO rm -rf "${STATE:?}/"* "$MARKER" 2>/dev/null || true
fi

# --- compose.yaml: есть/обновить/скачать ---
if [ -f compose.yaml ]; then
  log "compose.yaml найден — режим обновления"
else
  log "compose.yaml отсутствует — свежая установка"
fi
RAW="https://raw.githubusercontent.com/stelgen/reverseray/${TAG}/compose.yaml"
curl -fsSL --max-time 20 "$RAW" -o compose.yaml.new || die "не удалось скачать compose.yaml ($RAW)"
mv compose.yaml.new compose.yaml

printf 'RR_IMAGE_TAG=%s\nRR_SOCKS_PORT=1080\nRR_TUNNEL_PORT=4433\nRR_METRICS_PORT=9090\nRR_METRICS_BIND=%s\nRR_PROTOCOL=%s\nRR_HARDENING=true\nRR_MODULES_AUTO=true\nRR_MODULES_CHECK_HOURS=24\nRR_RESTART_DELAY=30\nRR_RESTART_MAX=20\n' \
  "$TAG" \
  "$([ "$UI_LAN" = "1" ] && echo 0.0.0.0 || echo 127.0.0.1)" \
  "${RR_PROTOCOL:-rrp1}" > .env

# --- pull + up ---
log "Тяну образ ${IMAGE_REPO}:${TAG}…"
run pull >/dev/null 2>&1 || warn "pull не прошёл (offline?) — попробую запустить то, что есть локально"
run up -d || die "docker compose up -d не удался (см. вывод выше)"

# --- здоровье ---
log "Жду healthcheck…"
ok=""
for i in $(seq 1 30); do
  st=$(run ps --format '{{.Health}}' reverseray 2>/dev/null | head -1)
  if [ "$st" = "healthy" ]; then ok=1; break; fi
  sleep 2
done
if [ -z "$ok" ]; then
  warn "Контейнер не healthy за 60 с — последние логи:"
  run logs --tail 20 reverseray || true
  die "Если проблема в состоянии — запусти: sudo bash rr.sh --reset"
fi
log "Контейнер healthy"

# --- enroll (идемпотентно: только если ещё не делали) ---
if [ ! -f "$MARKER" ]; then
  log "Регистрирую устройство phone-1 (enroll)…"
  run exec -T reverseray /reverseray enroll -state-dir /var/lib/reverseray -name phone-1 > /tmp/rr-enroll.out 2>&1 || true
  touch "$MARKER" 2>/dev/null || $SUDO touch "$MARKER"
else
  log "Устройство уже зарегистрировано (state/.enrolled) — токен не меняю"
fi

# --- строка подключения ---
LINE=""
if [ -f /tmp/rr-enroll.out ]; then
  # v0.7.3: строка БЕЗ ведущих пробелов/переносов — новичок копирует как есть
  LINE=$(grep -o '^rrp://[^[:space:]]*' /tmp/rr-enroll.out | head -1 | tr -d '[:space:]' || true)
fi
# LAN-IP хоста (роутер/машина с докером), не IP докер-бриджа — для Xray-аутбаунда
LAN_IP=$(ip -4 route get 1.0.0.0 2>/dev/null | grep -oE 'src [0-9.]+' | awk '{print $2}' | head -1)
[ -n "$LAN_IP" ] || LAN_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -n "$LAN_IP" ] || LAN_IP="<LAN_IP_ХОСТА>"
if [ -z "$LINE" ]; then
  # повторный enroll печатает строку, даже если маркер стоит (без записи токена в state не выйдет —
  # тогда просим enroll вручную)
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
echo " Healthcheck: включён; упавший процесс рестартит governor не чаще 1 раза/30 с"
echo " Обнова (опционально, уровень ХОСТА — ICMP-пинги отвечает ядро, не приложение):"
echo "   sudo iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 30/min -j ACCEPT"
echo "   sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP"
echo " Обновление позже: sudo bash rr.sh            (версия возьмётся с GitHub)"
echo " Обнулить state:   sudo bash rr.sh --reset"
echo "=============================================================="
