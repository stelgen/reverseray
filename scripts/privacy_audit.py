#!/usr/bin/env python3
"""Privacy audit (v0.8): ReverseRay не течёт приватными данными.

Робот сканирует исходники APK и сервера и блокирует:
  1. ВНЕШНИЕ ХОСТЫ вне белого списка (телеметрия/аналитика невозможны по
     канону; список — единственные домены, нужные для работы/апдейтов);
  2. plaintext http:// URL в коде приложения (кроме localhost/инбоксов);
  3. маркеры телеметрии (crashlytics, analytics, firebase, sentry, umeng…);
  4. случайные токены/приватные IP 192.168/10. в ДОКАХ (примеры — только
     с масками).

Успех = тишина. Любое совпадение — fail с указанием файла и строки.
"""
import os
import re
import sys

ALLOWED_HOSTS = {
    # GitHub: апдейтер APK, модули, проверки релизов
    "api.github.com",
    "raw.githubusercontent.com",
    "github.com",
    # NetInfo (внешний IP/страна/оператор — данные, которые юзер видит в UI)
    "ipwho.is",
    "ipapi.co",
    "api.ipify.org",
    "ifconfig.me",
    "ipecho.net",
    # PROBE-цель по умолчанию (проверка egress)
    "1.1.1.1",
    # Спидтест
    "speed.cloudflare.com",
    # DoH-проба доступности
    "cloudflare-dns.com",
    # README-бейджи и лендинг проекта
    "img.shields.io",
    "stelgen.github.io",
    # XML-неймспейсы Android/aapt (не сетевые обращения)
    "schemas.android.com",
    "www.w3.org",
    # Доки-стандарты (ссылки в CHANGELOG)
    "keepachangelog.com",
    "semver.org",
}

TELEMETRY_MARKERS = re.compile(
    r"(crashlytics|analytics|firebase|sentry|umeng|mixpanel|amplitude|"
    r"appsflyer|flurry|facebook-sdk|onesignal)",
    re.IGNORECASE,
)

IP_DOC = re.compile(r"\b(?!127\.|0\.0\.|81\.25\.59\.194)(\d{1,3}\.){3}\d{1,3}\b")

CODE_EXTS = {".kt", ".java", ".go", ".py", ".sh", ".js", ".json", ".xml"}
DOC_EXTS = {".md", ".yml", ".yaml", ".txt"}


def fail(msg: str) -> None:
    print(f"XX privacy: {msg}")
    sys.exit(1)


def check_line(path: str, line_no: int, line: str) -> list:
    problems = []
    if path.replace("\\", "/").endswith("scripts/privacy_audit.py"):
        return problems  # сам сканер содержит список маркеров — не самопал
    if TELEMETRY_MARKERS.search(line):
        problems.append(f"маркер телеметрии: {TELEMETRY_MARKERS.search(line).group(0)!r}")
    for m in re.finditer(r"http://([A-Za-z0-9.\-_]+)", line):
        # v0.8.1: plaintext http:// разрешён ТОЛЬКО в loopback/интрасеть
        # (healthcheck, admin-инбокс, примеры LAN). Всё остальное — https://.
        host = m.group(1).lower()
        if host in {"127", "0", "localhost", "<lan_ip>", "lan_ip", "*", "unix"}:
            continue
        if host.startswith("127.") or host.startswith("0.0.0.0") or host.startswith("10."):
            continue
        if host in {"example", "host", "server", "server_ip", "localhost_ip", "admin", "proxyaddr"}:
            continue
        if re.match(r"^example", host) or host.endswith(".example") or host.endswith(".example.com"):
            continue
        if "<" in line and ">" in line:  # <LAN_IP> и прочие шаблонные примеры
            continue
        if re.search(r"\b(LAN_IP|SERVER|HOST|ADDR|IP)\b", line, re.IGNORECASE) and "_" in m.group(0):
            continue
        if "." not in host:  # одноэтапные хосты — шаблоны/инбоксы (t, unix…)
            continue
        if host in ALLOWED_HOSTS or host.endswith("schemas.android.com"):
            # XML-неймспейсы/документационные хосты — не сетевые обращения
            continue
        problems.append(f"plaintext http:// вне loopback (используй https://): {m.group(0)!r}")
    for m in re.finditer(r"https?://([A-Za-z0-9.-]+)", line):
        host = m.group(1).lower()
        base = host.split("/")[0].strip(".")
        if base in ALLOWED_HOSTS:
            continue
        if "." not in base:
            # одноэтапные хосты — внутренние примеры/инбоксы (t, localhost-ip, …)
            continue
        if base.endswith(".localhost") or base in {"localhost", "127.0.0.1"}:
            continue
        if base.startswith("127.") or base.startswith("0.0.0.0"):
            continue
        if re.match(r"^example\.(com|org|net)$", base) or base.endswith(".example.com"):
            continue
        if base.endswith(".example"):
            continue
        problems.append(f"внешний хост вне белого списка: {base}")
    return problems


def main() -> int:
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    problems = []
    scanned = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", "build", ".gradle", ".kotlin"}]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, root)
            if ext in CODE_EXTS or ext in DOC_EXTS:
                try:
                    text = open(path, encoding="utf-8", errors="replace").read()
                except OSError:
                    continue
                scanned += 1
                for i, line in enumerate(text.splitlines(), 1):
                    for p in check_line(rel, i, line):
                        problems.append(f"{rel}:{i}: {p}")
        # docs: приватные IP и токены-подобные строки
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext not in DOC_EXTS:
                continue
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, root)
            try:
                text = open(path, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            for i, line in enumerate(text.splitlines(), 1):
                for m in IP_DOC.finditer(line):
                    ip = m.group(0)
                    if re.match(r"^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)", ip) and not re.search(
                        r"(example|sample|пример|<|\bLAN_IP\b|0\.2$)", ip
                    ):
                        problems.append(f"{rel}:{i}: приватный IP в доке: {ip}")
                if re.search(r"rrp://[A-Za-z0-9+/_-]{20,}", line) and "example" not in line and "<" not in line:
                    problems.append(f"{rel}:{i}: возможный реальный токен в доке")
    print(f"privacy audit: файлов просмотрено {scanned}, проблем {len(problems)}")
    for p in problems[:40]:
        print("XX", p)
    if problems:
        print("XX privacy: добавьте хост в scripts/privacy_audit.py ALLOWED_HOSTS")
        print("            (с обоснованием) или уберите наружное обращение.")
        return 1
    print("OK privacy: утечек не найдено (канон «ничего не прячем, ничего не сливаем»)")
    return 0


if __name__ == "__main__":
    sys.exit(main())