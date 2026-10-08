#!/usr/bin/env python3
"""Module integrity check (v0.8): modules/modules.json должен быть валиден
канону — тот же набор правил, что и в Go (internal/modules) и Kotlin
(Modules.kt). CI-робот блокирует битый манифест до merge."""
import json
import re
import sys

ALLOWED_ID = re.compile(r"^[a-z0-9]{1,16}$")
VERSION_RE = re.compile(r"^v?[0-9]+\.[0-9]+(\.[0-9]+)?$")


def fail(msg: str) -> None:
    print(f"XX modules: {msg}")
    sys.exit(1)


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else "modules/modules.json"
    try:
        raw = open(path, encoding="utf-8").read()
    except OSError as e:
        fail(f"не читается {path}: {e}")
    try:
        m = json.loads(raw)
    except json.JSONDecodeError as e:
        fail(f"не JSON: {e}")
    if m.get("schema") != 1:
        fail(f"schema = {m.get('schema')!r}, ожидалась 1")
    version = m.get("version", "")
    if not VERSION_RE.match(version):
        fail(f"версия {version!r} не семвер")
    protocols = m.get("protocols")
    if not isinstance(protocols, list) or not protocols:
        fail("пустой/отсутствующий реестр протоколов")
    seen = set()
    has_rrp1 = False
    for p in protocols:
        pid = str(p.get("id", ""))
        if not ALLOWED_ID.match(pid):
            fail(f"мусорный id протокола: {pid!r}")
        if pid in seen:
            fail(f"дубликат протокола {pid}")
        seen.add(pid)
        if pid == "rrp1":
            has_rrp1 = True
        enabled = p.get("enabled")
        if enabled is not None and not isinstance(enabled, bool):
            fail(f"enabled не bool у {pid}")
    if not has_rrp1:
        fail("реестр без rrp1 — запрещено (фундамент)")
    policy = m.get("policy", {})
    if policy:
        probe = policy.get("probe_default_target")
        if probe is not None:
            host, _, port = str(probe).rpartition(":")
            if not host or not port.isdigit() or not (1 <= int(port) <= 65535):
                fail(f"битый probe_default_target: {probe!r}")
        names = policy.get("dns_probe_names")
        if names is not None and not isinstance(names, list):
            fail("dns_probe_names не список")
    print(f"OK modules: {path} — schema 1, версия {version}, протоколы: {', '.join(sorted(seen))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())