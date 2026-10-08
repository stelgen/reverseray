#!/usr/bin/env bash
# install.sh — тонкий делегат к автопилоту deploy/rr.sh (v0.7.2+).
# Оставлен для обратной совместимости: новые сценарии — rr.sh.
# rr.sh сам создаёт ./reverseray относительно текущего каталога, ставит или
# обновляет сервер, проверяет здоровье и печатает строку подключения.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$DIR/rr.sh" "$@"
