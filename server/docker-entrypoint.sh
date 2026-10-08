#!/bin/busybox sh
# ReverseRay restart-governor (v0.8): упавший процесс перезапускается
# незаметно и НЕ ЧАЩЕ RR_RESTART_DELAY секунд (по умолчанию 30) — чтобы
# crash-loop не валил систему нагрузкой. Если падение повторяется
# RR_RESTART_MAX раз ПОДРЯД (по умолчанию 20) — governor выходит
# с ошибкой: Docker видит умерший контейнер и помечает его
# (restart policy / healthcheck решают видимость), а не молотит бесконечно.
#
# Чистый выход (код 0) — не считается падением: governor завершается сразу.

RESTART_DELAY="${RR_RESTART_DELAY:-30}"
RESTART_MAX="${RR_RESTART_MAX:-20}"

case "$RESTART_DELAY" in
  ''|*[!0-9]*) RESTART_DELAY=30 ;;
esac
case "$RESTART_MAX" in
  ''|*[!0-9]*) RESTART_MAX=20 ;;
esac

fails=0
while :; do
  /reverseray "$@"
  code=$?
  if [ "$code" -eq 0 ]; then
    echo "governor: reverseray exited cleanly (0)"
    exit 0
  fi
  fails=$((fails + 1))
  echo "governor: reverseray exited with code $code (fails in a row: $fails/$RESTART_MAX); restart in ${RESTART_DELAY}s"
  if [ "$fails" -ge "$RESTART_MAX" ]; then
    echo "governor: FATAL — $fails подряд падений: отдаём контейнер Docker (не крутим бесконечный цикл)"
    exit "$code"
  fi
  busybox sleep "$RESTART_DELAY"
  echo "governor: restarting reverseray…"
done