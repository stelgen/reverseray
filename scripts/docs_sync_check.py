#!/usr/bin/env python3
"""docs_sync_check.py — гейт синхрона версий и канонов доков (Фаза 0, v1.8.5).

Анти-деградация: все окружения и все документы обязаны видеть ОДНУ и ту же
версию тулчейна и ОДНУ текущую версию продукта. Дрейф вида «WORKFLOW.md
говорит 1.27.3, а ci.yml — 1.27.4» ловится здесь, а не при разборе инцидента.

Проверки (exit 1 при любом несовпадении):
  1) server/go.mod: toolchain-директива существует, patch-версия == go-version
     во ВСЕХ go-джобах .github/workflows/*.yml
  2) WORKFLOW.md (Политики тулчейна) упоминает ту же патч-версию
  3) CHANGELOG.md: последняя версия == дефолтному versionName в
     android/app/build.gradle.kts
  4) ROADMAP.md: таблица Released содержит строку последней версии CHANGELOG
  5) CI: у govulncheck указан тот же тулчейн (тот же go-version)
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
errors = []


def read(p: str) -> str:
    return (ROOT / p).read_text(encoding="utf-8")


# 1) toolchain-директива в go.mod
gomod = read("server/go.mod")
m = re.search(r"^toolchain go(\d+\.\d+\.\d+)$", gomod, re.M)
if not m:
    errors.append("server/go.mod: нет директивы `toolchain goX.Y.Z`")
    toolchain = None
else:
    toolchain = m.group(1)

if toolchain:
    # все go-джобы всех воркфлоу
    for wf in sorted(pathlib.Path(ROOT / ".github/workflows").glob("*.yml")):
        text = wf.read_text(encoding="utf-8")
        for mm in re.finditer(r"go-version:\s*\"?([\d.]+)\"?", text):
            if mm.group(1) != toolchain:
                errors.append(
                    f"{wf.relative_to(ROOT)}: go-version {mm.group(1)} != toolchain {toolchain}"
                )
    # WORKFLOW.md упоминает ту же патч-версию
    wf_doc = read("docs/WORKFLOW.md")
    if toolchain not in wf_doc:
        errors.append(f"docs/WORKFLOW.md: не упоминается текущий пин {toolchain}")

# 3) CHANGELOG top == versionName default
changelog = read("CHANGELOG.md")
m = re.search(r"^## \[(\d+\.\d+\.\d+)\]", changelog, re.M)
if not m:
    errors.append("CHANGELOG.md: не найдена верхняя версия")
    changelog_top = None
else:
    changelog_top = m.group(1)

gradle = read("android/app/build.gradle.kts")
m = re.search(r'\?: "(\d+\.\d+\.\d+)"', gradle)
gradle_default = m.group(1) if m else None
if changelog_top and gradle_default and changelog_top != gradle_default:
    errors.append(
        f"versionName default {gradle_default} != CHANGELOG top {changelog_top}"
    )

# 4) ROADMAP содержит строку последней версии
roadmap = read("ROADMAP.md")
if changelog_top and f"v{changelog_top}" not in roadmap:
    errors.append(f"ROADMAP.md: нет строки для v{changelog_top}")

if errors:
    print("::error::docs_sync_check FAILED")
    for e in errors:
        print(f"  - {e}")
    sys.exit(1)

print(f"docs_sync_check OK (toolchain={toolchain}, version={changelog_top})")
