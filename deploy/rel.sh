#!/usr/bin/env bash
# rel.sh X.Y.Z — безопасный релиз-тег (v1.0.1 канон).
# GitHub глушит push-триггеры (включая теги), если в сообщении HEAD-коммита
# стоит маркер [skip ci]/[ci skip] — а ботовые коммиты вечно с маркером.
# Скрипт: подтягивает main, проверяет HEAD-сообщение, при маркере добавляет
# чистый finalize-коммит, ставит тег и пушит.
set -euo pipefail
V="${1:?usage: rel.sh X.Y.Z}"
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.."
git pull --rebase origin main
MSG="$(git log -1 --format=%s)"
if printf '%s' "$MSG" | grep -qi '\[skip ci\]\|\[ci skip\]'; then
  git commit --allow-empty -m "chore(release): v$V finalize"
  git push origin main
  echo "HEAD был skip-коммитом — добавлен чистый finalize-коммит"
fi
git tag "v$V"
git push origin "v$V"
echo "OK: тег v$V запушен — Release стартует"
