#!/usr/bin/env python3
"""ReverseRay brand asset generator.

Deterministic generation of every visual asset:
  - og-image.png      1600x640 banner (black, wordmark, emblem, tagline)
  - banner.gif        1600x400 ДИНАМИЧЕСКИЙ баннер (пульс-кольцо + бегущий трафик)
  - screenshot.png    720x1440 — РЕАЛЬНЫЙ рендер APK (кладёт CI-робот из эмулятор, adb screencap;
                      app-mock.png — мокап-референс генератора)
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
    """Мокап v0.7.4: 4 вкладки, большая круглая Старт/Стоп, окно трафика,
    «терминальный» лог — как в реальном приложении (Material 3, тёмная тема)."""
    img = Image.new("RGB", (w, h), (11, 16, 32))
    d = ImageDraw.Draw(img)
    f_title = _font(int(w * 0.075))
    fs = _font(int(w * 0.042))
    fw = _font(int(w * 0.045))
    fm = _font(int(w * 0.036))
    CARD = (18, 26, 48)
    LINE = (31, 43, 77)
    GREEN = (57, 217, 138)
    TERM_BG = (11, 16, 32)
    TERM_TX = (139, 209, 124)

    # шапка: иконка-эмблема + имя
    emb = emblem(int(w * 0.11), dark=True)
    img.paste(emb, (int(w * 0.445), int(h * 0.025)), emb)
    d.text((w * 0.5 - f_title.getlength("ReverseRay") / 2, h * 0.145),
           "ReverseRay", font=f_title, fill=(255, 255, 255))

    # вкладки
    ty = h * 0.215
    tabs = ["Главная", "Связь", "Обновление", "Настройки"]
    tw = w / 4
    d.line([0, ty + 64, w, ty + 64], fill=LINE, width=2)
    for i, t in enumerate(tabs):
        cx = i * tw
        col = (255, 255, 255) if i == 0 else (143, 163, 217)
        d.text((cx + tw / 2 - fm.getlength(t) / 2, ty + 18), t, font=fm, fill=col)
        if i == 0:
            d.line([cx + 30, ty + 64, cx + tw - 30, ty + 64], fill=(53, 182, 255), width=5)

    # большая круглая кнопка СТАРТ
    by = h * 0.27
    r = int(w * 0.23)
    cx, cy = w // 2, by + r
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(46, 125, 50))
    t1, t2 = "СТАРТ", "туннель"
    d.text((cx - fw.getlength(t1) / 2, cy - 34), t1, font=fw, fill=(255, 255, 255))
    d.text((cx - fm.getlength(t2) / 2, cy + 22), t2, font=fm, fill=(220, 245, 224))

    # карточка трафика
    cy0 = cy + r + 40
    card = [w * 0.06, cy0, w * 0.94, cy0 + h * 0.13]
    d.rounded_rectangle(card, radius=18, fill=CARD, outline=LINE, width=2)
    d.text((card[0] + 24, card[1] + 16), "✓ Готов: порт 4433", font=fs, fill=GREEN)
    d.text((card[0] + 24, card[1] + 66), "↓ 128.4 КБ/с · ↑ 61.9 КБ/с", font=fm, fill=(219, 228, 255))
    d.text((card[0] + 24, card[1] + 110), "TCP · ↑ 512 Б · ↓ 1.2 КБ · пакеты ↑34 ↓56", font=fm, fill=(143, 163, 217))
    d.text((card[0] + 24, card[1] + 154), "IP 85.140.10.20 · RU · Mobile-ISP", font=fm, fill=(143, 163, 217))
    d.text((card[0] + 24, card[1] + 198), "Протокол: rrp1 · сервер: rrp1", font=fm, fill=(53, 182, 255))

    # график трафика (ломаная)
    gy = card[3] + 36
    d.rounded_rectangle([w * 0.06, gy, w * 0.94, gy + h * 0.085], radius=18, fill=CARD, outline=LINE, width=2)
    pts = []
    for i in range(16):
        px = w * 0.085 + i * (w * 0.83 / 15)
        py = gy + h * 0.07 - (0.35 + abs(((i * 7) % 11) - 5) / 5 * 0.4) * h * 0.055
        pts.append((px, py))
    d.line(pts, fill=(53, 182, 255), width=5)

    # терминальный лог
    ly = gy + h * 0.085 + 40
    d.rounded_rectangle([w * 0.06, ly, w * 0.94, ly + h * 0.155], radius=18, fill=TERM_BG, outline=LINE, width=2)
    lines = [
        "81.25.59.194:4433: SENT HELLO ver=1 proto=rrp1",
        "81.25.59.194:4433: RECV HELLO_OK nonce=…",
        "81.25.59.194:4433: SENT AUTH token-hmac",
        "81.25.59.194:4433: RECV READY proto=rrp1",
        "81.25.59.194:4433: PROBE OK — egress подтверждён",
        "туннель готов: порт 4433",
    ]
    for i, t in enumerate(lines):
        d.text((w * 0.085, ly + 26 + i * 52), t, font=fm, fill=TERM_TX)

    d.text((w * 0.08, h * 0.955), "Android egress · TLS 1.3 · вкладки · лимиты трафика",
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


def banner_gif(w: int = 1600, h: int = 400, frames: int = 24) -> list[Image.Image]:
    """Динамический баннер главной страницы (GIF): пульс-кольцо вокруг
    круглой кнопки Старт (как в APK v0.8) + бегущие точки трафика по лучу.
    Детерминированный: одинаковые байты при каждом запуске."""
    img0 = Image.new("RGB", (w, h), BG)
    emb = emblem(int(h * 0.72), dark=True)
    img0.paste(emb, (int(w * 0.03), int(h * 0.14)), emb)
    d0 = ImageDraw.Draw(img0)
    tx = int(w * 0.30)
    d0.text((tx, int(h * 0.16)), "ReverseRay", font=_font(int(h * 0.22)), fill=TEXT)
    tagline = "PHONE AS EGRESS   ·   TLS 1.3   ·   SELF-HOSTED   ·   MTProto/2"
    d0.text((tx, int(h * 0.52)), tagline, font=fit_font(tagline, w - tx - 40, int(h * 0.07)), fill=MUTED)
    sub = "v0.8 — hardening · modules · zero-byte limit rule"
    d0.text((tx, int(h * 0.70)), sub, font=fit_font(sub, w - tx - 40, int(h * 0.06)), fill=MUTED)
    # кнопка справа: тёмно-зелёный круг (как Старт в APK)
    br = int(h * 0.26)
    bcx, bcy = int(w * 0.885), h // 2
    out = []
    for f in range(frames):
        img = img0.copy()
        t = f / frames
        # бегущие точки трафика (сервер → телефон)
        overlay = Image.new("RGBA", (w, h), (0, 0, 0, 0))
        od = ImageDraw.Draw(overlay)
        for k in range(3):
            prog = (t + k / 3.0) % 1.0
            x = int(w * 0.24 + prog * (w * 0.50))
            y = int(h * 0.5 + (k - 1) * h * 0.06)
            r = int(h * 0.018)
            od.ellipse([x - r, y - r, x + r, y + r], fill=ACCENT + (255,))
        # пульс-кольцо
        pr = br + int(t * br * 0.35)
        alpha_ring = int(200 * (1 - t))
        od.ellipse(
            [bcx - pr, bcy - pr, bcx + pr, bcy + pr],
            outline=(57, 217, 138, alpha_ring), width=int(h * 0.012),
        )
        img = Image.alpha_composite(img.convert("RGBA"), overlay).convert("RGB")
        d = ImageDraw.Draw(img)
        d.ellipse([bcx - br, bcy - br, bcx + br, bcy + br], fill=(46, 125, 50))
        fw = _font(int(h * 0.10))
        fm = _font(int(h * 0.055))
        d.text((bcx - fw.getlength("СТАРТ") / 2, bcy - h * 0.075), "СТАРТ", font=fw, fill=TEXT)
        d.text((bcx - fm.getlength("туннель") / 2, bcy + h * 0.045), "туннель", font=fm, fill=(220, 245, 224))
        out.append(img)
    return out


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
    # v0.8: мокап — только как референс; РЕАЛЬНЫЙ скриншот кладёт CI-робот
    # (эмулятор, adb screencap рендерит MainActivity), генератор его НЕ перезаписывает.
    save(app_mock(), "assets/brand/app-mock.png")
    # динамический баннер главной страницы
    gif_path = os.path.join(BRAND_DIR, "banner.gif")
    frames = banner_gif()
    frames[0].save(
        gif_path, save_all=True, append_images=frames[1:],
        duration=80, loop=0, optimize=False,
    )
    written.append(gif_path)
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
    expect("logo-512.png", (512, 512), max_mean=170)  # иконка — брендовый градиент (яркая по дизайну)
    expect("favicon-32.png", (32, 32), max_mean=170)
    expect("favicon-64.png", (64, 64), max_mean=170)

    # v0.8: скриншот — РЕАЛЬНЫЙ кадр APK (кладёт CI-робот с эмулятора),
    # не мокап генератора. Проверяем размер и «не однотонный/не ANR-диалог».
    shot = os.path.join(REPO_ROOT, "assets/brand", "screenshot.png")
    if not os.path.exists(shot):
        failures.append("screenshot.png missing — ждём CI-робота (эмулятор, adb screencap)")
    else:
        img = Image.open(shot)
        if img.size != (720, 1440):
            failures.append(f"screenshot.png: size {img.size} != (720, 1440)")
        colors = len(set(img.convert("RGB").resize((64, 64)).getdata()))
        if colors <= 16:
            failures.append(f"screenshot.png: однотонный кадр ({colors} цветов на 64x64) — похоже на ANR/пустоту")

    # динамический баннер: должен существовать и анимироваться
    gifp = os.path.join(BRAND_DIR, "banner.gif")
    if not os.path.exists(gifp):
        failures.append("banner.gif missing")
    else:
        gif = Image.open(gifp)
        if getattr(gif, "n_frames", 1) < 3:
            failures.append("banner.gif: мало кадров — анимация не живая")
        if gif.size != (1600, 400):
            failures.append(f"banner.gif: size {gif.size} != (1600, 400)")

    if failures:
        for f in failures:
            print(f"FAIL: {f}")
        print("Run: python3 assets/brand/generate.py  (then commit the changes)")
        return 1
    print("brand assets OK: спецификация v0.8 выполнена (og, real screenshot, banner.gif, logos)")
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
