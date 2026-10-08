#!/usr/bin/env python3
"""Module integrity check (v0.8): modules/modules.json должен быть валиден
канону — тот же набор правил, что и в Go (internal/modules) и Kotlin
(Modules.kt). CI-робот блокирует битый манифест до merge."""
import json
import re
import sys

ALLOWED_ID = re.compile(r"^[a-z0-9]{1,16}$")
VERSION_RE = re.compile(r"^v?[0-9]+\.[0-9]+(\.[0-9]+)?$")
# v0.8.1: публичная версия протокола — опциональна; мусор = версии нет
PROTO_VER_RE = re.compile(r"^[A-Za-z0-9._+/-]{1,16}$")


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
        # v0.8.1: ver — публичная версия протокола ("1", "2.0"). Пусто/нет —
        # валидно («версии нет — показываем пусто»); мусор — отказ CI.
        ver = str(p.get("ver", "") or "").strip()
        if ver and not PROTO_VER_RE.match(ver):
            fail(f"мусорная ver у протокола {pid}: {ver!r}")
        enabled = p.get("enabled")
        if enabled is not None and not isinstance(enabled, bool):
            fail(f"enabled не bool у {pid}")
    if not has_rrp1:
        fail("реестр без rrp1 — запрещено (фундамент)")
    # v0.8.2: секция camouflage — модуль камуфляжа «API Mask» (опциональна;
    # если есть — обязаны быть валидный id и разумные параметры)
    camo = m.get("camouflage")
    if camo is not None:
        if not isinstance(camo, dict):
            fail("camouflage не объект")
        cid = str(camo.get("id", ""))
        if not ALLOWED_ID.match(cid):
            fail(f"мусорный id модуля camouflage: {cid!r}")
        cver = str(camo.get("ver", "") or "").strip()
        if cver and not PROTO_VER_RE.match(cver):
            fail(f"мусорная ver у camouflage: {cver!r}")
        cenabled = camo.get("enabled")
        if cenabled is not None and not isinstance(cenabled, bool):
            fail("camouflage.enabled не bool")
        lo = camo.get("min_interval_sec", 0)
        hi = camo.get("max_interval_sec", 0)
        budget = camo.get("max_bytes_per_day", 0)
        for name, val, lim in (("min_interval_sec", lo, 3600), ("max_interval_sec", hi, 21600)):
            if not isinstance(val, int) or val < 0 or val > lim:
                fail(f"camouflage.{name} вне диапазона: {val!r}")
        if not isinstance(budget, int) or budget < 0 or budget > 1024 * 1024:
            fail(f"camouflage.max_bytes_per_day вне диапазона: {budget!r}")
        if lo and hi and lo > hi:
            fail("camouflage: min_interval_sec > max_interval_sec")
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
    vers = {str(p.get("id")): str(p.get("ver", "") or "") for p in protocols}
    print(f"OK modules: версии протоколов (v0.8.1): " + ", ".join(f"{k}={v or '—'}" for k, v in sorted(vers.items())))
    if camo is not None:
        state = "вкл" if camo.get("enabled", True) else "выкл"
        print(
            f"OK modules: камуфляж {camo.get('name', camo.get('id'))}"
            f" (v{camo.get('ver') or '—'}) {state}, "
            f"интервал {camo.get('min_interval_sec', 0)}–{camo.get('max_interval_sec', 0)} с, "
            f"бюджет {camo.get('max_bytes_per_day', 0)} Б/сутки"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())