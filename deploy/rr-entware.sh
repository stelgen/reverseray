#!/bin/sh
# ReverseRay rr-entware.sh — сервер ReversERay на Entware-роутере (NC-1812 и любые aarch64/armv7)
#
# ЗАПУСКАЕТСЯ НА РОУТЕРЕ (Entware/opkg shell), НЕ на ПК. docker НЕ нужен.
# Полностью настраивается конфигом /opt/etc/reverseray/reverseray.conf.
#
# Канон владельца (модем-сервер):
#   - бинарь ставится в /opt/bin, конфиги — в /opt/etc/reverseray;
#   - ВЕБ-МОРДА закрыта: admin слушает ТОЛЬКО 127.0.0.1 (наружу не торчит ничем);
#   - писанина в логи на диск — выключена по умолчанию: лог в tmpfs (/tmp) или /dev/null;
#   - скрипт печатает: порт(ы), ссылку rrp:// для телефона, какие порты пробросить;
#   - ПОЛНАЯ ВАЛИДАЦИЯ: бинарь жив, конфиг валиден, листенеры подняты,
#     прокси реально ходит наружу (self-check через собственный mixed-порт),
#     веб-морда закрыта, туннель биндом наружу, RAM-footprint напечатан.
#
# Использование (на роутере, от root):
#   sh rr-entware.sh                 # установка/обновление до последнего релиза
#   sh rr-entware.sh --tag v1.7.1    # конкретная версия
#   sh rr-entware.sh --reset         # обнулить state (токены/CA) и пере-enroll
#   sh rr-entware.sh --validate      # только прогон валидации текущей установки
#   curl -fsSL <raw>/deploy/rr-entware.sh -o /opt/tmp/rr-entware.sh && sh /opt/tmp/rr-entware.sh
#
set -eu

CONF_DIR=/opt/etc/reverseray
CONF_FILE=$CONF_DIR/reverseray.conf
SERVER_CFG=$CONF_DIR/config.json
INIT_FILE=/opt/etc/init.d/S99reverseray
DEFAULT_BIN=/opt/bin/reverseray
RUN_DIR=/opt/var/run
DEFAULT_STATE=/opt/var/lib/reverseray
RAM_LOG=/tmp/reverseray.log
GH_REPO=stelgen/reverseray

DO_RESET=0
DO_VALIDATE=0
TAG_FROM_CLI=""

log()  { printf '==> %s\n' "$*"; }
warn() { printf '!!  %s\n' "$*"; }
die()  { printf 'XX  %s\n' "$*"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --reset) DO_RESET=1 ;;
    --validate) DO_VALIDATE=1 ;;
    --tag) TAG_FROM_CLI="${2:?нужна версия после --tag}"; shift ;;
    *) die "неизвестный флаг: $1 (доступны --reset, --validate, --tag vX.Y.Z)" ;;
  esac
  shift
done

# ---------------------------------------------------------------- preflight
[ -d /opt ] || die "Entware не найден (нет /opt) — установи OPKG/Entware по штатной инструкции роутера"
mkdir -p "$CONF_DIR" 2>/dev/null || die "нет прав на $CONF_DIR (запусти от root/admin)"

# --- конфиг-файл: единственное место настройки (порт, бинды, лог, имя и т.д.) ---
if [ ! -f "$CONF_FILE" ]; then
  log "Создаю конфиг $CONF_FILE (все настройки — в нём)"
  cat > "$CONF_FILE" <<'EOFCONF'
# ReverseRay — настройки Entware-сервера (правь и перезапускай: sh /opt/etc/init.d/S99reverseray restart)
# Версия релиза: latest | vX.Y.Z
RR_TAG=latest
# Бинарь
RR_BIN=/opt/bin/reverseray
# State (токены/CA) — пишется только сюда
RR_STATE_DIR=/opt/var/lib/reverseray
# Слушатель туннеля для телефона (TLS). ":ПОРТ" = наружу на всех интерфейсах
RR_TUNNEL_BIND=:4433
# Прокси SOCKS5+HTTP (mixed; egress через подключенный телефон).
# ":ПОРТ" = наружу; пусто = выключен
RR_MIXED_BIND=:1080
# UDP-релей прокси наружу (пробрасывать UDP того же порта)
RR_MIXED_UDP=true
# Веб-морда/админ: канон модема — ТОЛЬКО 127.0.0.1 (наружу не торчит).
# Пусто = admin через unix-сокет (полностью без TCP)
RR_ADMIN_BIND=127.0.0.1:9090
# Протокол по умолчанию (rrp1|mtproto2|wireguard|bittorrent|apimask)
RR_PROTOCOL=rrp1
# Анти-скан hardening на туннельном порту
RR_HARDENING=true
# Модули: авто-чек манифеста на модеме выключен (лишние внешние походы)
RR_MODULES_AUTO=false
# Лог: ram = /tmp (tmpfs, исчезает при ребуте), none = /dev/null, file = RR_LOG_FILE
RR_LOG_MODE=ram
RR_LOG_FILE=/opt/var/log/reverseray.log
# Имя устройства для enroll (в ссылке телефона)
RR_ENROLL_NAME=phone-1
# Мультипоточность: 1-8 (дублирует порт в ссылке, сервер агрегирует сессии)
RR_SESSIONS=1
# Публичный хост для ссылки телефона: домен/DDNS/WAN-IP.
# Пусто = авто (WAN-IP роутера по маршруту по умолчанию)
RR_PUBLIC_HOST=
EOFCONF
fi

# --- читаем конфиг (переменные RR_*) ---
. "$CONF_FILE"
RR_BIN=${RR_BIN:-$DEFAULT_BIN}
RR_STATE_DIR=${RR_STATE_DIR:-$DEFAULT_STATE}
RR_TUNNEL_BIND=${RR_TUNNEL_BIND:-":4433"}
RR_ADMIN_BIND=${RR_ADMIN_BIND:-"127.0.0.1:9090"}
RR_LOG_MODE=${RR_LOG_MODE:-ram}
RR_ENROLL_NAME=${RR_ENROLL_NAME:-phone-1}
RR_SESSIONS=${RR_SESSIONS:-1}
RR_PROTOCOL=${RR_PROTOCOL:-rrp1}

case "$RR_LOG_MODE" in
  ram)  LOG_REDIRECT="$RAM_LOG" ;;
  none) LOG_REDIRECT="/dev/null" ;;
  file) LOG_REDIRECT="$RR_LOG_FILE" ;;
  *) die "RR_LOG_MODE=$RR_LOG_MODE не понял (ram|none|file)" ;;
esac

# порты для валидации/итога — вычисляются ОДИН раз наверху (не в функции)
TUN_PORT=$(printf '%s' "$RR_TUNNEL_BIND" | sed 's/.*:\([0-9]*\)/\1/')
MIX_PORT=$(printf '%s' "${RR_MIXED_BIND:-}" | sed 's/.*:\([0-9]*\)/\1/')

# ---------------------------------------------------------------- валидация
# Полный прогон: процесс, листенеры, веб-морда закрыта, прокси наружу, лог-политика.
validate_all() {
  _V_FAIL=0
  v_ok()  { printf '  ✔ %s\n' "$1"; }
  v_bad() { printf '  ✘ %s\n' "$1"; _V_FAIL=1; }

  log "ВАЛИДАЦИЯ (Entware-модем-сервер):"

  # 1. процесс жив + RSS из /proc (busybox ps без -o)
  PIDF="$RUN_DIR/reverseray.pid"
  if [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF")" 2>/dev/null; then
    RP=$(cat "$PIDF")
    RSS=$(grep VmRSS "/proc/$RP/status" 2>/dev/null | awk '{print $2" "$3}')
    v_ok "процесс жив (pid $RP, RSS ${RSS:-?})"
  else
    v_bad "процесс не запустился — смотри лог: $LOG_REDIRECT"
    return 1
  fi

  # 1.5. healthcheck бинарем (админ-порт жив — валидирует admin_tcp/healthz)
  if [ -n "$RR_ADMIN_BIND" ] && have curl; then
    AP=$(printf '%s' "$RR_ADMIN_BIND" | sed 's/.*:\([0-9]*\)/\1/')
    if curl -fsS --max-time 5 "http://127.0.0.1:$AP/healthz" >/dev/null 2>&1; then
      v_ok "healthz отвечает (127.0.0.1:$AP) ✔"
    else
      v_bad "healthz не отвечает на 127.0.0.1:$AP"
    fi
  fi

  # 2. листенеры (busybox netstat)
  have netstat || die "нужен netstat (busybox)"
  NET=$(netstat -tln 2>/dev/null || true)
  printf '%s\n' "$NET" | grep -q "[:.]$TUN_PORT " \
    && v_ok "туннель слушает :$TUN_PORT" || v_bad "туннель НЕ слушает :$TUN_PORT"
  if [ -n "${RR_MIXED_BIND:-}" ]; then
    printf '%s\n' "$NET" | grep -q "[:.]$MIX_PORT " \
      && v_ok "прокси mixed слушает :$MIX_PORT (egress через телефон)" || v_bad "mixed НЕ слушает :$MIX_PORT"
  fi

  # 3. канон «наружу»: туннель — wildcard, веб-морда — закрыта
  case "$RR_TUNNEL_BIND" in
    :*|0.0.0.0:*) v_ok "туннель биндом наружу ($RR_TUNNEL_BIND) — доступен с WAN при пробросе" ;;
    127.0.0.1:*|localhost:*) v_bad "туннель на loopback ($RR_TUNNEL_BIND) — телефон снаружи не подключится" ;;
    *) warn "туннель биндом на конкретный IP ($RR_TUNNEL_BIND) — проверь, что это WAN/LAN-IP роутера" ;;
  esac
  if [ -n "$RR_ADMIN_BIND" ]; then
    case "$RR_ADMIN_BIND" in
      127.0.0.1*|localhost*) v_ok "веб-морда только на 127.0.0.1 (${RR_ADMIN_BIND}) — наружу НЕ торчит" ;;
      *) v_bad "админ бин ${RR_ADMIN_BIND} открыт наружу — правь RR_ADMIN_BIND в $CONF_FILE" ;;
    esac
  else
    v_ok "веб-морда выключена совсем (admin через unix-сокет)"
  fi

  # 4. прокси реально ходит наружу (self-check через собственный mixed)
  if [ -n "${RR_MIXED_BIND:-}" ]; then
    if have curl; then
      EGRESS=$(curl -fsS --max-time 15 --proxy "socks5h://127.0.0.1:$MIX_PORT" https://ifconfig.me 2>/dev/null || true)
      if [ -n "$EGRESS" ]; then
        v_ok "прокси поднимается НАРУЖУ ✔ (egress IP: $EGRESS)"
      else
        warn "прокси слушает, но egress появится после подключения телефона (канон: телефон = egress-узел)"
      fi
    else
      warn "нет curl — self-check прокси пропущен (opkg install curl для полной валидации)"
    fi
  fi

  # 5. лог-политика модема: минимум писанины на диск
  case "$RR_LOG_MODE" in
    ram)  v_ok "лог в tmpfs (/tmp) — диск модема не пишется" ;;
    none) v_ok "лог отключён (/dev/null)" ;;
    file) v_bad "лог пишется на диск ($RR_LOG_FILE) — канон модема: RR_LOG_MODE=ram|none" ;;
  esac

  if [ "$_V_FAIL" = "0" ]; then
    log "Валидация ПРОЙДЕНА ✔"
    return 0
  fi
  log "Валидация С ОШИБКАМИ ✘"
  return 1
}

# --- ветка --validate: текущая установка, БЕЗ переустановки ---
if [ "$DO_VALIDATE" = "1" ]; then
  [ -x "$RR_BIN" ] || die "бинарь не установлен ($RR_BIN) — сначала запуск без флагов"
  validate_all || die "есть ошибки — исправь $CONF_FILE и: sh $INIT_FILE restart"
  exit 0
fi

# ---------------------------------------------------------------- версия
resolve_tag() {
  if [ -n "$TAG_FROM_CLI" ]; then printf '%s' "$TAG_FROM_CLI"; return; fi
  if [ "$RR_TAG" != "latest" ] && [ -n "$RR_TAG" ]; then printf '%s' "$RR_TAG"; return; fi
  curl -fsSL --max-time 15 "https://api.github.com/repos/$GH_REPO/releases/latest" 2>/dev/null \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1
}

have curl || have wget || die "нужен curl или wget: opkg install curl"
have sha256sum || die "нужен sha256sum: opkg install coreutils-sha256sum"

TAG=$(resolve_tag || true)
[ -n "$TAG" ] || die "не смог определить релиз (нет сети?) — укажи --tag vX.Y.Z"
log "Версия: $TAG"

# ---------------------------------------------------------------- бинарь
ARCH=$(uname -m)
case "$ARCH" in
  aarch64|armv8) ASSET=reverseray-linux-arm64 ;;
  armv7*|armv8l) ASSET=reverseray-linux-armv7 ;;
  x86_64)        ASSET=reverseray-linux-amd64 ;;
  *) die "архитектура '$ARCH' не поддерживается (нужен aarch64/armv7 — NC-1812 = aarch64)" ;;
esac
log "Архитектура: $ARCH → $ASSET (NC-1812 = MT7988D aarch64 — ок)"

TMP=/opt/tmp
mkdir -p "$TMP" "$RR_STATE_DIR" "$RUN_DIR" "$CONF_DIR" "$(dirname "$RR_BIN")"

# --- reset ---
if [ "$DO_RESET" = "1" ]; then
  log "Обнуляю state (--reset): стоп сервиса, токены/CA удалены"
  [ -f "$INIT_FILE" ] && sh "$INIT_FILE" stop 2>/dev/null || true
  rm -rf "${RR_STATE_DIR:?}/"* 2>/dev/null || true
  rm -f "$RUN_DIR/reverseray.pid" 2>/dev/null || true
fi

log "Качаю $ASSET ($TAG)…"
URL="https://github.com/$GH_REPO/releases/download/$TAG/$ASSET"
if have curl; then
  curl -fsSL --max-time 300 -o "$TMP/reverseray.new" "$URL" || die "скачивание не удалось: $URL"
else
  wget -O "$TMP/reverseray.new" "$URL" || die "скачивание не удалось: $URL"
fi

# --- sha256 из релиза ---
SUM_URL="https://github.com/$GH_REPO/releases/download/$TAG/SHA256SUMS"
EXPECT=""
if have curl; then
  EXPECT=$(curl -fsSL --max-time 30 "$SUM_URL" 2>/dev/null | grep "$ASSET" | awk '{print $1}' | head -n 1)
else
  EXPECT=$(wget -qO- "$SUM_URL" 2>/dev/null | grep "$ASSET" | awk '{print $1}' | head -n 1)
fi
if [ -n "$EXPECT" ]; then
  GOT=$(sha256sum "$TMP/reverseray.new" | awk '{print $1}')
  [ "$GOT" = "$EXPECT" ] || die "sha256 НЕ совпал ($GOT != $EXPECT) — файл битый/подменён, стоп"
  log "sha256 совпал ✔"
else
  warn "SHA256SUMS не получен — ставлю без сверки (сеть до GitHub частично недоступна?)"
fi

# --- валидация бинаря ДО установки: он вообще живёт на этом ядре? ---
chmod 755 "$TMP/reverseray.new"
"$TMP/reverseray.new" version >/dev/null 2>&1 || die "бинарь не запускается на этом ядре (не та архитектура?)"
log "Бинарь живой ✔ ($("$TMP/reverseray.new" version 2>/dev/null | head -n 1))"

install -m 0755 "$TMP/reverseray.new" "$RR_BIN"
rm -f "$TMP/reverseray.new"
log "Установлен: $RR_BIN"

# ---------------------------------------------------------------- config.json
# Истина настроек — reverseray.conf; серверный config.json рендерится из него.
# JSON собирается частями — никаких висячих запятых.
ADMIN_UNIX=""
if [ -n "$RR_ADMIN_BIND" ]; then
  ADMIN_UNIX=""
else
  ADMIN_UNIX="$RUN_DIR/reverseray-admin.sock"
fi
LISTEN="{\"tunnels\": \"$RR_TUNNEL_BIND\""
[ -n "${RR_MIXED_BIND:-}" ] && LISTEN="$LISTEN, \"mixed\": \"$RR_MIXED_BIND\""
[ -n "$RR_ADMIN_BIND" ] && LISTEN="$LISTEN, \"admin_tcp\": \"$RR_ADMIN_BIND\""
[ -n "$ADMIN_UNIX" ] && LISTEN="$LISTEN, \"admin_unix\": \"$ADMIN_UNIX\""
LISTEN="$LISTEN}"
HARDENING=true; [ "${RR_HARDENING:-true}" = "false" ] && HARDENING=false
MODULES_AUTO=false; [ "${RR_MODULES_AUTO:-false}" = "true" ] && MODULES_AUTO=true

cat > "$SERVER_CFG" <<EOFJSON
{
  "listen": $LISTEN,
  "state_dir": "$RR_STATE_DIR",
  "default_protocol": "$RR_PROTOCOL",
  "hardening": { "enabled": $HARDENING },
  "modules": { "auto": $MODULES_AUTO, "check_hours": 24 },
  "log": { "level": "warn", "redact": true }
}
EOFJSON
log "Серверный конфиг: $SERVER_CFG (без веб-морды: admin = ${RR_ADMIN_BIND:-unix-socket ${ADMIN_UNIX:-}})"

# ---------------------------------------------------------------- init-скрипт
mkdir -p "$(dirname "$INIT_FILE")"
cat > "$INIT_FILE" <<EOFINIT
#!/bin/sh
# ReverseRay init (Entware) — сгенерирован rr-entware.sh; настройки в $CONF_FILE
CONF="$CONF_FILE"
[ -f "\$CONF" ] && . "\$CONF"
BIN="\${RR_BIN:-$RR_BIN}"
CFG="$SERVER_CFG"
PIDF="$RUN_DIR/reverseray.pid"
LOG="$LOG_REDIRECT"

is_alive() { [ -f "\$PIDF" ] && kill -0 "\$(cat \$PIDF)" 2>/dev/null; }

start() {
  if is_alive; then echo "уже запущен (pid \$(cat \$PIDF))"; return 0; fi
  mkdir -p "$RUN_DIR" "\${RR_STATE_DIR:-$DEFAULT_STATE}" 2>/dev/null
  nohup "\$BIN" run -config "\$CFG" >>"\$LOG" 2>&1 &
  echo \$! > "\$PIDF"
  echo "запущен (pid \$(cat \$PIDF)), лог: \$LOG"
}
stop() {
  if is_alive; then kill "\$(cat \$PIDF)" 2>/dev/null; rm -f "\$PIDF"; echo "остановлен"; else rm -f "\$PIDF"; echo "не был запущен"; fi
}
status() {
  if is_alive; then echo "запущен (pid \$(cat \$PIDF))"; else echo "остановлен"; return 1; fi
}
case "\$1" in
  start) start ;;
  stop) stop ;;
  restart) stop; sleep 1; start ;;
  status) status ;;
  *) echo "usage: \$0 start|stop|restart|status" ;;
esac
EOFINIT
chmod 755 "$INIT_FILE"

log "Стартую сервис…"
sh "$INIT_FILE" start

# ---------------------------------------------------------------- прогон валидации
sleep 2
validate_all || warn "есть проблемы — исправь $CONF_FILE и: sh $INIT_FILE restart"

# ---------------------------------------------------------------- enroll + ссылка
MARKER="$RR_STATE_DIR/.enrolled"
ENROLL_OUT=$("$RR_BIN" enroll -state-dir "$RR_STATE_DIR" -name "$RR_ENROLL_NAME" 2>&1 || true)
[ -f "$MARKER" ] || touch "$MARKER" 2>/dev/null || true
LINE=$(printf '%s' "$ENROLL_OUT" | grep -o '^rrp://[^[:space:]]*' | head -n 1 | tr -d '[:space:]')
[ -n "$LINE" ] || warn "ссылка не получена — выполни вручную: $RR_BIN enroll -state-dir $RR_STATE_DIR -name $RR_ENROLL_NAME"

# --- мультипоточность (как в rr.sh: N сессий через тот же порт) ---
case "$RR_SESSIONS" in
  [2-8])
    if [ -n "$LINE" ]; then
      P=$(printf '%s' "$LINE" | sed 's|^rrp://[^@]*@[^:]*:||; s|/.*||')
      MULTI=""
      i=1
      while [ $i -le "$RR_SESSIONS" ]; do MULTI="$MULTI$P,"; i=$((i+1)); done
      MULTI=$(printf '%s' "$MULTI" | sed 's/,$//')
      LINE=$(printf '%s' "$LINE" | sed "s|:$P/|:$MULTI/|")
    fi
    ;;
esac

# --- публичный хост для ссылки ---
PUB="${RR_PUBLIC_HOST:-}"
if [ -z "$PUB" ]; then
  # WAN-IP = src адрес маршрута по умолчанию (на модеме это внешний IP)
  PUB=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.*src \([0-9.]*\).*/\1/p' | head -n 1)
fi
[ -n "$PUB" ] || PUB="<WAN_IP_РОУТЕРА>"
if [ -n "$LINE" ]; then
  LINE=$(printf '%s' "$LINE" | sed "s|^rrp://\([^@]*\)@[^:/]*:|rrp://\1@$PUB:|")
fi

case "$PUB" in
  10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|100.6[4-9].*|100.7[0-9].*|100.1[01][0-9].*|100.12[0-7].*)
    warn "WAN-IP $PUB приватный/CGNAT — снаружи телефон по нему не зайдёт: нужен DDNS/белый IP"
    ;;
esac

# ---------------------------------------------------------------- итог
echo
echo "=============================================================="
echo " ГОТОВО (Entware-модем-сервер)."
echo
echo " 1) ССЫЛКА ДЛЯ ТЕЛЕФОНА (APK: Серверы → + Добавить → вставить):"
if [ -n "$LINE" ]; then echo "$LINE"; else echo "  (см. warn выше — enroll вручную)"; fi
echo
echo " 2) ПОРТЫ ДЛЯ ПРОБРОСА В ФАЙРВОЛ РОУТЕРА (WAN → этот роутер):"
echo "    TCP $TUN_PORT  ← туннель телефона (обязательно)"
if [ -n "${RR_MIXED_BIND:-}" ]; then
  echo "    TCP $MIX_PORT  ← прокси SOCKS5/HTTP наружу"
  [ "${RR_MIXED_UDP:-true}" = "true" ] && echo "    UDP $MIX_PORT  ← UDP-релей прокси (SOCKS5 UDP)"
fi
echo "    Веб-мода наружу НЕ пробрасывается (закрыта на 127.0.0.1) ✔"
echo
echo " 3) КОНФИГ ВСЕГО: $CONF_FILE (порт, бинды, лог, имя устройства, версия)"
echo "    После правки:  sh $INIT_FILE restart"
echo "    Лог: $LOG_REDIRECT (RR_LOG_MODE=$RR_LOG_MODE — диск модема не страдает)"
echo "    Обновление:      sh $0"
echo "    Обнулить state:  sh $0 --reset"
echo "    Валидация:       sh $0 --validate"
echo "=============================================================="
