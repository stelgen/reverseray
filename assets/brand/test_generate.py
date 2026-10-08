#!/usr/bin/env python3
"""Tests for the ReverseRay brand asset generator.

Run:  python3 -m unittest discover -s assets/brand -p 'test_*.py'
CI job 'assets' runs the same suite plus `generate.py --check`.

Verified properties:
  - og-image dimensions and black background
  - wordmark actually rendered (bright pixels present in the text zone)
  - accent line present (accent-colored pixels present)
  - deterministic output: two runs produce identical bytes
  - logo/favicon sizes match the spec
"""
from __future__ import annotations

import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import generate  # noqa: E402

from PIL import Image  # noqa: E402


class OgImageTest(unittest.TestCase):
    def setUp(self):
        self.img = generate.og_image()

    def test_dimensions(self):
        self.assertEqual(self.img.size, (1600, 640))

    def test_background_is_black(self):
        # corners must be pure black (minimal dark background)
        for xy in [(2, 2), (1277, 2), (2, 637), (1277, 637)]:
            self.assertEqual(self.img.getpixel(xy), (0, 0, 0), f"corner {xy} not black")

    def test_wordmark_rendered(self):
        # text zone: bright (white) pixels must exist where the wordmark is drawn
        zone = self.img.crop((576, 170, 1240, 340)).convert("L")
        bright = sum(1 for v in zone.getdata() if v > 220)
        self.assertGreater(bright, 2000, "wordmark pixels not found — font missing or moved")

    def test_accent_line_present(self):
        # accent ray line: saturated accent pixels must exist under the wordmark
        # geometry: line at y=366, x from tx=576, width 544
        zone = self.img.crop((576, 360, 1120, 374)).convert("RGB")
        accent = sum(
            1 for r, g, b in zone.getdata()
            if b > 150 and b > r + 40 and g > r
        )
        self.assertGreater(accent, 300, "accent line not found")

    def test_tagline_fits_inside_canvas(self):
        # regression: tagline must never be clipped at the right edge
        tagline = "ANDROID EGRESS   ·   TLS 1.3   ·   SOCKS5/HTTP"
        f = generate.fit_font(tagline, 1600 - 576 - 60, 40)
        self.assertLessEqual(f.getlength(tagline), 1600 - 576 - 60)

    def test_deterministic_bytes(self):
        a = generate.og_image()
        b = generate.og_image()
        ba, bb = io.BytesIO(), io.BytesIO()
        a.save(ba, "PNG"); b.save(bb, "PNG")
        self.assertEqual(ba.getvalue(), bb.getvalue(), "generator is not deterministic")


class LogoTest(unittest.TestCase):
    def test_logo_sizes(self):
        for size in (32, 64, 512):
            img = generate.logo_png(size)
            self.assertEqual(img.size, (size, size))

    def test_logo_emblem_arrow_through_wall(self):
        """Эмблема: белая стрелка по центру, accent-точка выхода справа."""
        img = generate.logo_png(256).convert("RGB")
        cy = 128
        self.assertEqual(img.getpixel((110, cy)), (255, 255, 255), "arrow body missing")
        self.assertEqual(img.getpixel((256 // 2, cy)), (255, 255, 255), "arrow must cross the wall")
        # exit-dot: accent присутствует около правого края на оси стрелки
        accent = [img.getpixel((x, cy)) for x in range(200, 250)]
        self.assertTrue(any(p == generate.ACCENT or (p[2] > 200 and p[0] < 100) for p in accent),
                        "accent exit dot not found")

    def test_logo_gradient_background(self):
        """Иконка: диагональный градиент бренда (тёмно-синий -> голубой)."""
        img = generate.logo_png(256).convert("RGB")
        tl = img.getpixel((8, 8))
        br = img.getpixel((247, 247))
        self.assertLess(sum(tl), sum(br), "gradient must darken to top-left")
        self.assertGreater(sum(br), sum(tl), "gradient must lighten to bottom-right")


class CommittedAssetsTest(unittest.TestCase):
    """Committed files must exist and match generator dimensions."""

    def test_committed_assets_exist_and_match(self):
        for name, size in [("og-image.png", (1600, 640)),
                           ("logo-512.png", (512, 512)),
                           ("favicon-32.png", (32, 32)),
                           ("favicon-64.png", (64, 64))]:
            path = os.path.join(generate.BRAND_DIR, name)
            self.assertTrue(os.path.exists(path), f"{name} missing")
            self.assertEqual(Image.open(path).size, size, f"{name} wrong size")

    def test_landing_copies_in_sync(self):
        landing = os.path.join(generate.REPO_ROOT, "landing")
        for name in ("og-image.png", "favicon-32.png"):
            brand = os.path.join(generate.BRAND_DIR, name)
            site = os.path.join(landing, name)
            self.assertTrue(os.path.exists(site), f"landing/{name} missing")
            with open(brand, "rb") as f1, open(site, "rb") as f2:
                self.assertEqual(f1.read(), f2.read(), f"landing/{name} differs from assets/brand — regenerate")


if __name__ == "__main__":
    unittest.main()
