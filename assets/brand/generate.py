#!/usr/bin/env python3
"""ReverseRay brand asset generator.

Deterministic generation of every visual asset:
  - og-image.png      1600x640 banner (black, wordmark, emblem, tagline)
  - screenshot.png    720x1440 app-UI mockup for docs
  - logo-512.png / favicon-32.png / favicon-64.png / logo.svg
  - android res/: launcher icons (mdpi..xxxhdpi) + notification glyph

Emblem: «arrow through the wall» — traffic passes through the node
(reverse-proxy concept). No hand-drawn circles; geometry is parametric.

Usage:
  python3 generate.py [--check]
  --check verifies committed assets against the spec (dimensions + metrics).

Requires Pillow; DejaVu Sans Bold (fonts-dejavu-core on Ubuntu).
"""
from __future__ import annotations

import argparse
import os
import sys

from PIL import Image, ImageDraw, ImageFont

BRAND_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(BRAND_DIR))  # assets/brand -> repo root
RES_DIR = os.path.join(REPO_ROOT, "android/app/src/main/res")
LANDING_DIR = os.path.join(REPO_ROOT, "landing")

ACCENT = (53, 182, 255)     # #35B6FF
TEXT = (255, 255, 255)
MUTED = (138, 143, 152)     # #8A8F98
BG = (0, 0, 0)
WALL = (255, 255, 255, 60)

FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
]


def _font(size: int) -> ImageFont.FreeTypeFont:
    for path in FONT_CANDIDATES:
        if os.path.exists(path):
            return ImageFont.truetype(path, size)
    raise RuntimeError("DejaVuSans-Bold.ttf not found (install fonts-dejavu-core)")


def fit_font(text: str, max_w: int, start_size: int) -> ImageFont.FreeTypeFont:
    """Largest font size <= start_size whose rendered width fits max_w."""
    size = start_size
    while size > 10:
        f = _font(size)
        if f.getlength(text) <= max_w:
            return f
        size -= 2
    return _font(size)


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def _diag_bg(w: int, h: int) -> Image.Image:
    """Диагональный градиент бренда: #0A3D91 -> #35B6FF."""
    img = Image.new("RGB", (w, h))
    c1, c2 = (10, 61, 145), (53, 182, 255)
    px = img.load()
    for y in range(h):
        for x in range(w):
            t = (x / max(1, w - 1) + y / max(1, h - 1)) / 2
            px[x, y] = lerp(c1, c2, t)
    return img


def emblem(size: int, dark: bool = True) -> Image.Image:
    """Эмблема «стрелка сквозь стену»: трафик проходит через узел (reverse-proxy).

    dark=True — чёрный фон (баннер/доки); dark=False — брендовый градиент
    (иконки запуска).
    """
    if dark:
        img = Image.new("RGB", (size, size), BG).convert("RGBA")
    else:
        img = _diag_bg(size, size).convert("RGBA")

    d = ImageDraw.Draw(img, "RGBA")
    m = size * 0.14
    cy = size / 2

    # «Стена»: вертикальный узел, который трафик проходит насквозь
    wall_w = size * 0.09
    wl = Image.new("RGBA", (int(wall_w), int(size - 2 * m)), (0, 0, 0, 0))
    ImageDraw.Draw(wl).rounded_rectangle(
        [0, 0, wl.width - 1, wl.height - 1], radius=int(wall_w / 2),
        fill=(255, 255, 255, 40) if not dark else (255, 255, 255, 34),
    )
    img.alpha_composite(wl, (int(size / 2 - wall_w / 2), int(m)))

    # Стрелка: вход слева -> наконечник справа, сквозь стену
    aw = max(3, int(size * 0.045))
    x0, x1 = int(m * 0.55), int(size - m * 0.55)
    d.line([x0, cy, x1 - size * 0.085, cy], fill=(255, 255, 255, 235), width=aw)
    tip = size * 0.085
    d.polygon([(x1, cy), (x1 - tip, cy - tip * 0.62), (x1 - tip, cy + tip * 0.62)],
              fill=(255, 255, 255, 245))
    rr = size * 0.028
    d.ellipse([x0 - rr, cy - rr, x0 + rr, cy + rr], fill=(255, 255, 255, 235))
    d.ellipse([x1 + tip * 0.45 - rr, cy - rr, x1 + tip * 0.45 + rr, cy + rr],
              fill=ACCENT + (255,))

    # «Открытый проход»: два штриха на кромке стены над/под стрелкой
    for yy in (cy - tip * 0.95, cy + tip * 0.95):
        d.line([size / 2 - wall_w * 0.55, yy, size / 2 + wall_w * 0.55, yy],
               fill=(255, 255, 255, 190), width=max(2, int(size * 0.012)))
    return img


def logo_png(size: int = 512) -> Image.Image:
    """Иконка приложения: брендовый градиент + эмблема."""
    return emblem(size, dark=False)


def stat_glyph(size: int) -> Image.Image:
    """Белый глиф notification: стрелка сквозь стену."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    cy = size / 2
    wall_w = size * 0.12
    d.rounded_rectangle([size / 2 - wall_w / 2, size * 0.16, size / 2 + wall_w / 2, size * 0.84],
                        radius=int(wall_w / 2), outline=(255, 255, 255, 235),
                        width=max(2, size // 16))
    aw = max(2, int(size * 0.055))
    d.line([size * 0.08, cy, size * 0.72, cy], fill=(255, 255, 255, 255), width=aw)
    tip = size * 0.14
    d.polygon([(size * 0.9, cy), (size * 0.9 - tip, cy - tip * 0.6), (size * 0.9 - tip, cy + tip * 0.6)],
              fill=(255, 255, 255, 255))
    return img


def og_image() -> Image.Image:
    return banner()


def banner(w: int = 1600, h: int = 640) -> Image.Image:
    """Широкий баннер: чёрный фон, эмблема, wordmark, слоган."""
    img = Image.new("RGB", (w, h), BG).convert("RGBA")
    emb = emblem(int(h * 0.62), dark=True)
    img.alpha_composite(emb, (int(w * 0.055), int(h * 0.19)))

    d = ImageDraw.Draw(img)
    tx = int(w * 0.36)
    cy = h // 2 - 30
    d.text((tx, cy - int(h * 0.14)), "ReverseRay", font=_font(int(h * 0.185)), fill=TEXT)

    lw = int(w * 0.34)
    overlay = Image.new("RGBA", (lw, 5), (0, 0, 0, 0))
    od = overlay.load()
    for i in range(lw):
        t = i / (lw - 1)
        a = int(255 * (1 - t) ** 1.2)
        for y in range(5):
            od[i, y] = (ACCENT[0], ACCENT[1], ACCENT[2], a)
    img.paste(Image.new("RGB", (lw, 5), ACCENT), (tx, cy + int(h * 0.12)), overlay)

    tagline = "PHONE AS EGRESS   ·   TLS 1.3   ·   SELF-HOSTED"
    d.text((tx, cy + int(h * 0.175)), tagline, font=fit_font(tagline, w - tx - 60, int(h * 0.06)),
           fill=MUTED)
    return img.convert("RGB")


def app_mock(w: int = 720, h: int = 1440) -> Image.Image:
    """Мокап интерфейса приложения (Material 3, тёмная тема)."""
    img = Image.new("RGB", (w, h), (10, 12, 18))
    d = ImageDraw.Draw(img)
    f_title = _font(int(w * 0.075))
    fs = _font(int(w * 0.042))
    fw = _font(int(w * 0.045))

    d.text((w * 0.08, h * 0.05), "ReverseRay", font=f_title, fill=(255, 255, 255))

    # карточка статуса: зелёная галочка
    card = [w * 0.06, h * 0.14, w * 0.94, h * 0.235]
    d.rounded_rectangle(card, radius=18, fill=(22, 27, 34))
    d.ellipse([card[0] + 24, card[1] + (card[3] - card[1]) / 2 - 16,
               card[0] + 24 + 32, card[1] + (card[3] - card[1]) / 2 + 16],
              outline=(46, 125, 50), width=5)
    d.text((card[0] + 24 + 44, card[1] + (card[3] - card[1]) / 2 - 26), "✓",
           font=_font(28), fill=(76, 175, 80))
    d.text((card[0] + 24 + 44, card[1] + (card[3] - card[1]) / 2 - 12),
           "Ready: port 4433", font=fs, fill=(230, 237, 243))

    # поле конфигурации (outlined)
    fconf = [w * 0.06, h * 0.27, w * 0.94, h * 0.42]
    d.rounded_rectangle(fconf, radius=18, fill=(22, 27, 34), outline=(48, 54, 61), width=2)
    d.text((fconf[0] + 24, fconf[1] + 20), "rrp://…", font=fs, fill=(139, 148, 158))
    d.line([fconf[0] + 24, fconf[1] + 74, fconf[0] + 24 + int(w * 0.35), fconf[1] + 74],
           fill=ACCENT, width=3)

    y0 = h * 0.46
    bh = int(h * 0.055)
    d.rounded_rectangle([w * 0.06, y0, w * 0.94, y0 + bh], radius=14, fill=ACCENT)
    d.text((w * 0.40, y0 + bh / 2 - 20), "Start tunnel", font=fw, fill=(6, 16, 34))

    y1 = y0 + bh + 20
    d.rounded_rectangle([w * 0.06, y1, w * 0.47, y1 + bh], radius=14, outline=(48, 54, 61), width=2)
    d.text((w * 0.12, y1 + bh / 2 - 20), "Scan QR", font=fw, fill=(230, 237, 243))
    d.rounded_rectangle([w * 0.53, y1, w * 0.94, y1 + bh], radius=14, outline=(48, 54, 61), width=2)
    d.text((w * 0.61, y1 + bh / 2 - 20), "Show QR", font=fw, fill=(230, 237, 243))

    y2 = y1 + bh + 20
    d.rounded_rectangle([w * 0.06, y2, w * 0.94, y2 + bh], radius=14, fill=(22, 27, 34))
    d.text((w * 0.44, y2 + bh / 2 - 20), "Stop", font=fw, fill=(248, 81, 73))

    y3 = y2 + bh + 26
    d.rounded_rectangle([w * 0.06, y3, w * 0.47, y3 + bh], radius=14, outline=(48, 54, 61), width=2)
    d.text((w * 0.10, y3 + bh / 2 - 20), "Check updates", font=fw, fill=(230, 237, 243))
    d.rounded_rectangle([w * 0.53, y3, w * 0.94, y3 + bh], radius=14, outline=(48, 54, 61), width=2)
    d.text((w * 0.66, y3 + bh / 2 - 20), "Log", font=fw, fill=(230, 237, 243))

    d.text((w * 0.08, h * 0.93), "Android egress  ·  TLS 1.3  ·  no logs",
           font=_font(int(w * 0.032)), fill=(139, 148, 158))
    return img


SVG_LOGO = '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#0A3D91"/><stop offset="1" stop-color="#35B6FF"/>
    </linearGradient>
  </defs>
  <rect width="512" height="512" rx="96" fill="url(#bg)"/>
  <rect x="236" y="72" width="40" height="368" rx="20" fill="#FFFFFF" fill-opacity="0.28"/>
  <line x1="64" y1="256" x2="392" y2="256" stroke="#FFFFFF" stroke-opacity="0.95" stroke-width="24" stroke-linecap="round"/>
  <polygon points="452,256 396,231 396,281" fill="#FFFFFF"/>
  <circle cx="64" cy="256" r="14" fill="#FFFFFF"/>
  <circle cx="452" cy="256" r="14" fill="#B3E5FC"/>
  <line x1="256" y1="220" x2="256" y2="292" stroke="#FFFFFF" stroke-opacity="0.8" stroke-width="10" stroke-linecap="round"/>
</svg>
'''


def write_all() -> list[str]:
    """Пишет все ассеты. Возвращает список записанных путей."""
    written: list[str] = []

    def save(img: Image.Image, rel: str):
        path = os.path.join(REPO_ROOT, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        img.save(path)
        written.append(path)

    og = banner()
    save(og, "assets/brand/og-image.png")
    save(app_mock(), "assets/brand/screenshot.png")
    save(logo_png(512), "assets/brand/logo-512.png")
    save(logo_png(64), "assets/brand/favicon-64.png")
    save(logo_png(32), "assets/brand/favicon-32.png")

    with open(os.path.join(BRAND_DIR, "logo.svg"), "w") as f:
        f.write(SVG_LOGO)
    written.append(os.path.join(BRAND_DIR, "logo.svg"))

    # Android res: launcher icons + notification glyph
    for dpi, px in [("mdpi", 48), ("hdpi", 72), ("xhdpi", 96), ("xxhdpi", 144), ("xxxhdpi", 192)]:
        save(logo_png(px), f"android/app/src/main/res/mipmap-{dpi}/ic_launcher.png")
    for dpi, px in [("mdpi", 24), ("hdpi", 36), ("xhdpi", 48), ("xxhdpi", 72), ("xxxhdpi", 96)]:
        save(stat_glyph(px), f"android/app/src/main/res/drawable-{dpi}/ic_stat_reverseray.png")

    # Лендинг-копии
    if os.path.isdir(LANDING_DIR):
        og.save(os.path.join(LANDING_DIR, "og-image.png"))
        app_mock().save(os.path.join(LANDING_DIR, "screenshot.png"))
        logo_png(32).save(os.path.join(LANDING_DIR, "favicon-32.png"))
        for n in ("og-image.png", "screenshot.png", "favicon-32.png"):
            written.append(os.path.join(LANDING_DIR, n))
    return written


def _metrics(img: Image.Image) -> dict:
    small = img.convert("L").resize((64, 32))
    px = list(small.getdata())
    mean = sum(px) / len(px)
    bright = sum(1 for v in px if v > 200) / len(px)
    return {"size": img.size, "mean": round(mean, 1), "bright_ratio": round(bright, 4)}


def check() -> int:
    """Сверка закоммиченных ассетов со спецификацией генератора."""
    failures = []

    def expect(name: str, want_size: tuple[int, int], max_mean: float = 40.0, min_bright: float = 0.0):
        path = os.path.join(REPO_ROOT, "assets/brand", name)
        if not os.path.exists(path):
            failures.append(f"{name}: missing")
            return
        img = Image.open(path).convert("RGB")
        if img.size != want_size:
            failures.append(f"{name}: size {img.size} != {want_size}")
        m = _metrics(img)
        if m["mean"] > max_mean:
            failures.append(f"{name}: too bright (mean={m['mean']})")
        if want_size == (1600, 640) and m["bright_ratio"] < 0.005:
            failures.append(f"{name}: wordmark pixels not found")

    expect("og-image.png", (1600, 640))
    expect("screenshot.png", (720, 1440), max_mean=60)
    expect("logo-512.png", (512, 512), max_mean=170)  # иконка — брендовый градиент (яркая по дизайну)
    expect("favicon-32.png", (32, 32), max_mean=170)
    expect("favicon-64.png", (64, 64), max_mean=170)

    if failures:
        for f in failures:
            print(f"FAIL: {f}")
        print("Run: python3 assets/brand/generate.py  (then commit the changes)")
        return 1
    print("brand assets OK: 5 files match generator spec")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    if args.check:
        return check()
    for path in write_all():
        print("written:", os.path.relpath(path, REPO_ROOT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
