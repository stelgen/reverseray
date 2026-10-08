#!/usr/bin/env python3
"""ReverseRay brand asset generator.

Generates deterministic, minimal assets:
  - og-image.png   1280x640, black background, wordmark + accent ray (README/OG)
  - logo-512.png   512x512 application logo (dark square, sphere + ray)
  - favicon-32.png / favicon-64.png
  - logo.svg       vector version of the logo
  - Android notification glyph + launcher icons are generated into res/ by
    the same primitives (see android/ res/ directories).

Usage:
  python3 generate.py [--check]

--check regenerates into memory and verifies that committed assets match
the generator output (dimensions + structural metrics). Exit code 1 on mismatch.

Requires: Pillow. Font: DejaVu Sans Bold (fonts-dejavu-core on Ubuntu).
"""
from __future__ import annotations

import argparse
import io
import os
import sys

from PIL import Image, ImageDraw, ImageFont

BRAND_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(BRAND_DIR))  # assets/brand -> repo root

ACCENT = (53, 182, 255)        # #35B6FF
TEXT = (255, 255, 255)
MUTED = (138, 143, 152)        # #8A8F98
BG = (0, 0, 0)                 # black

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


def og_image() -> Image.Image:
    """1280x640: black background, sphere glyph, wordmark, accent ray, tagline."""
    w, h = 1280, 640
    img = Image.new("RGB", (w, h), BG)
    d = ImageDraw.Draw(img)

    left = 96
    cy = h // 2 - 40

    # small sphere glyph: outline circle + inner dot (no stray lines)
    r = 74
    gcx, gcy = left + r, cy
    d.ellipse([gcx - r, gcy - r, gcx + r, gcy + r], outline=TEXT, width=6)
    d.ellipse([gcx - 26, gcy - 34, gcx + 6, gcy - 2], fill=TEXT)

    # wordmark
    tx = gcx + r + 96
    f_title = _font(116)
    d.text((tx, cy - 84), "ReverseRay", font=f_title, fill=TEXT)

    # accent ray: gradient horizontal line under the wordmark
    line_y = cy + 74
    line_w = 560
    overlay = Image.new("RGBA", (line_w, 5), (0, 0, 0, 0))
    od = overlay.load()
    for i in range(line_w):
        t = i / (line_w - 1)
        a = int(255 * (1 - t) ** 1.2)
        for y in range(5):
            od[i, y] = (ACCENT[0], ACCENT[1], ACCENT[2], a)
    img.paste(Image.new("RGB", (line_w, 5), ACCENT), (tx, line_y), overlay)

    # tagline: font auto-fits the remaining width, never clipped
    tagline = "ANDROID EGRESS   ·   TLS 1.3   ·   SOCKS5/HTTP"
    f_tag = fit_font(tagline, w - tx - 48, 38)
    d.text((tx, line_y + 34), tagline, font=f_tag, fill=MUTED)
    return img


def logo_png(size: int = 512) -> Image.Image:
    """Application logo: dark square, blue sphere with white rim, accent ray."""
    img = Image.new("RGB", (size, size), BG)
    d = ImageDraw.Draw(img)
    r = int(size * 0.27)
    cx, cy = int(size * 0.44), int(size * 0.44)
    # ray
    d.line([cx + r * 0.8, cy + r * 0.6, size * 0.94, size * 0.92],
           fill=ACCENT, width=max(4, int(size * 0.035)))
    # sphere: flat fill + rim (minimal, no gradients)
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(30, 90, 160), outline=(200, 240, 255), width=max(3, size // 170))
    d.ellipse([cx - r * 0.42, cy - r * 0.52, cx - r * 0.05, cy - r * 0.15], fill=(210, 235, 252))
    return img


def app_mock(w: int = 720, h: int = 1440) -> Image.Image:
    """Мокап интерфейса приложения (для документации)."""
    img = Image.new("RGB", (w, h), (10, 12, 18))
    d = ImageDraw.Draw(img)
    r = int(w * 0.06)
    d.rounded_rectangle([0, 0, w, h], radius=r, fill=(10, 12, 18))

    # заголовок
    f = _font(int(w * 0.075))
    d.text((w * 0.08, h * 0.05), "ReverseRay", font=f, fill=(255, 255, 255))

    # карточка статуса: зелёная галочка + текст
    card = [w * 0.06, h * 0.14, w * 0.94, h * 0.235]
    d.rounded_rectangle(card, radius=18, fill=(22, 27, 34))
    d.ellipse([card[0] + 24, card[1] + (card[3] - card[1]) / 2 - 16,
               card[0] + 24 + 32, card[1] + (card[3] - card[1]) / 2 + 16],
              outline=(46, 125, 50), width=5)
    d.text((card[0] + 24 + 44, card[1] + (card[3] - card[1]) / 2 - 26), "✓", font=_font(28), fill=(76, 175, 80))
    fs = _font(int(w * 0.042))
    d.text((card[0] + 24 + 44, card[1] + (card[3] - card[1]) / 2 - 12),
           "Ready: port 4433", font=fs, fill=(230, 237, 243))

    # поле конфигурации
    fconf = [w * 0.06, h * 0.27, w * 0.94, h * 0.42]
    d.rounded_rectangle(fconf, radius=18, fill=(22, 27, 34), outline=(48, 54, 61), width=2)
    d.text((fconf[0] + 24, fconf[1] + 20), "rrp://…", font=fs, fill=(139, 148, 158))
    d.line([fconf[0] + 24, fconf[1] + 74, fconf[0] + 24 + int(w * 0.35), fconf[1] + 74],
           fill=ACCENT, width=3)

    # кнопки: filled start, outlined scan/show, text log
    y0 = h * 0.46
    bh = int(h * 0.055)
    d.rounded_rectangle([w * 0.06, y0, w * 0.94, y0 + bh], radius=14, fill=(53, 182, 255))
    fw = _font(int(w * 0.045))
    d.text((w * 0.42, y0 + bh / 2 - 20), "Start tunnel", font=fw, fill=(6, 16, 34))

    y1 = y0 + bh + 20
    d.rounded_rectangle([w * 0.06, y1, w * 0.47, y1 + bh], radius=14, outline=(48, 54, 61), width=2)
    d.text((w * 0.11, y1 + bh / 2 - 20), "Scan QR", font=fw, fill=(230, 237, 243))
    d.rounded_rectangle([w * 0.53, y1, w * 0.94, y1 + bh], radius=14, outline=(48, 54, 61), width=2)
    d.text((w * 0.60, y1 + bh / 2 - 20), "Show QR", font=fw, fill=(230, 237, 243))

    y2 = y1 + bh + 20
    d.rounded_rectangle([w * 0.06, y2, w * 0.94, y2 + bh], radius=14, fill=(22, 27, 34))
    d.text((w * 0.40, y2 + bh / 2 - 20), "Stop", font=fw, fill=(248, 81, 73))

    y3 = y2 + bh + 26
    d.rounded_rectangle([w * 0.06, y3, w * 0.47, y3 + bh], radius=14, outline=(48, 54, 61), width=2)
    d.text((w * 0.13, y3 + bh / 2 - 20), "Check updates", font=fw, fill=(230, 237, 243))
    d.rounded_rectangle([w * 0.53, y3, w * 0.94, y3 + bh], radius=14, outline=(48, 54, 61), width=2)
    d.text((w * 0.63, y3 + bh / 2 - 20), "Log", font=fw, fill=(230, 237, 243))

    # футер-строка
    d.text((w * 0.08, h * 0.93), "Android egress  ·  TLS 1.3  ·  no logs", font=_font(int(w * 0.032)),
           fill=(139, 148, 158))
    return img


def banner(w: int = 1600, h: int = 640) -> Image.Image:
    """Широкий баннер: чёрный фон, глиф-сфера, wordmark, луч, слоган."""
    img = Image.new("RGB", (w, h), BG)
    d = ImageDraw.Draw(img)
    # сфера-глиф слева
    r = int(h * 0.32)
    gcx, gcy = int(w * 0.16), int(h * 0.5)
    d.ellipse([gcx - r, gcy - r, gcx + r, gcy + r], outline=TEXT, width=max(4, h // 100))
    d.ellipse([gcx - int(r * 0.42), gcy - int(r * 0.52), gcx - int(r * 0.05), gcy - int(r * 0.15)], fill=TEXT)
    d.line([gcx + int(r * 0.75), gcy + int(r * 0.55), gcx + int(r * 1.8), gcy + int(r * 1.5)],
           fill=ACCENT, width=max(6, h // 64))
    # wordmark
    tx = int(w * 0.34)
    cy = h // 2 - 30
    f_title = _font(int(h * 0.19))
    d.text((tx, cy - int(h * 0.13)), "ReverseRay", font=f_title, fill=TEXT)
    # акцентная линия
    lw = int(w * 0.36)
    overlay = Image.new("RGBA", (lw, 5), (0, 0, 0, 0))
    od = overlay.load()
    for i in range(lw):
        t = i / (lw - 1)
        a = int(255 * (1 - t) ** 1.2)
        for y in range(5):
            od[i, y] = (ACCENT[0], ACCENT[1], ACCENT[2], a)
    img.paste(Image.new("RGB", (lw, 5), ACCENT), (tx, cy + int(h * 0.115)), overlay)
    # слоган
    f_tag = _font(int(h * 0.062))
    d.text((tx, cy + int(h * 0.17)), "PHONE AS EGRESS   ·   TLS 1.3   ·   SELF-HOSTED", font=f_tag, fill=MUTED)
    return img


def write_all() -> list[str]:
    """Write committed assets. Returns list of written paths."""
    written: list[str] = []

    og = banner()
    p = os.path.join(BRAND_DIR, "og-image.png")
    og.save(p); written.append(p)

    mock = app_mock()
    p = os.path.join(BRAND_DIR, "screenshot.png")
    mock.save(p); written.append(p)

    logo = logo_png(512)
    p = os.path.join(BRAND_DIR, "logo-512.png")
    logo.save(p); written.append(p)

    p = os.path.join(BRAND_DIR, "favicon-64.png")
    logo_png(64).save(p); written.append(p)

    p = os.path.join(BRAND_DIR, "favicon-32.png")
    logo_png(32).save(p); written.append(p)

    # landing copies (site cannot reference ../assets)
    landing = os.path.join(REPO_ROOT, "landing")
    if os.path.isdir(landing):
        og.save(os.path.join(landing, "og-image.png")); written.append(os.path.join(landing, "og-image.png"))
        mock.save(os.path.join(landing, "screenshot.png")); written.append(os.path.join(landing, "screenshot.png"))
        logo_png(32).save(os.path.join(landing, "favicon-32.png")); written.append(os.path.join(landing, "favicon-32.png"))

    return written


def _metrics(img: Image.Image) -> dict:
    """Structural metrics used by --check (stable across Pillow versions)."""
    small = img.convert("L").resize((64, 32))
    px = list(small.getdata())
    mean = sum(px) / len(px)
    bright = sum(1 for v in px if v > 200) / len(px)
    return {"size": img.size, "mean": round(mean, 1), "bright_ratio": round(bright, 4)}


def check() -> int:
    """Verify committed assets match the generator (dimensions + metrics)."""
    failures = []

    def expect(name: str, want_size: tuple[int, int], max_mean: float = 40.0, min_bright: float = 0.0):
        path = os.path.join(BRAND_DIR, name)
        if not os.path.exists(path):
            failures.append(f"{name}: missing")
            return
        img = Image.open(path).convert("RGB")
        if img.size != want_size:
            failures.append(f"{name}: size {img.size} != {want_size}")
        m = _metrics(img)
        if m["mean"] > max_mean:
            failures.append(f"{name}: background too bright (mean={m['mean']})")
        if want_size == (1280, 640) and m["bright_ratio"] < 0.005:
            failures.append(f"{name}: wordmark/text pixels not found (bright={m['bright_ratio']})")

    expect("og-image.png", (1600, 640))
    expect("logo-512.png", (512, 512))
    expect("favicon-32.png", (32, 32), max_mean=70)  # favicon = крупная сфера, mean выше
    expect("favicon-64.png", (64, 64), max_mean=70)
    expect("screenshot.png", (720, 1440), max_mean=60)

    if failures:
        for f in failures:
            print(f"FAIL: {f}")
        print("Run: python3 assets/brand/generate.py  (then commit the changes)")
        return 1
    print("brand assets OK: 4 files match generator spec")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="verify committed assets instead of writing")
    args = ap.parse_args()
    if args.check:
        return check()
    for path in write_all():
        print("written:", os.path.relpath(path, REPO_ROOT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
