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
        self.assertEqual(self.img.size, (1280, 640))

    def test_background_is_black(self):
        # corners must be pure black (minimal dark background)
        for xy in [(2, 2), (1277, 2), (2, 637), (1277, 637)]:
            self.assertEqual(self.img.getpixel(xy), (0, 0, 0), f"corner {xy} not black")

    def test_wordmark_rendered(self):
        # text zone: bright (white) pixels must exist where the wordmark is drawn
        zone = self.img.crop((420, 200, 1240, 420)).convert("L")
        bright = sum(1 for v in zone.getdata() if v > 220)
        self.assertGreater(bright, 2000, "wordmark pixels not found — font missing or moved")

    def test_accent_line_present(self):
        # accent ray line: saturated accent pixels must exist under the wordmark
        # geometry: line at y = h//2 - 40 + 74 = 354, x from tx=340, width 560
        zone = self.img.crop((340, 344, 1000, 364)).convert("RGB")
        accent = sum(
            1 for r, g, b in zone.getdata()
            if b > 150 and b > r + 40 and g > r
        )
        self.assertGreater(accent, 300, "accent line not found")

    def test_tagline_fits_inside_canvas(self):
        # regression: tagline must never be clipped at the right edge
        tagline = "ANDROID EGRESS   ·   TLS 1.3   ·   SOCKS5/HTTP"
        f = generate.fit_font(tagline, 1280 - 340 - 48, 38)
        self.assertLessEqual(f.getlength(tagline), 1280 - 340 - 48)

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

    def test_logo_has_sphere_and_accent(self):
        img = generate.logo_png(256).convert("RGB")
        # sphere body color present
        self.assertIn((30, 90, 160), [img.getpixel(xy) for xy in [(128, 100), (128, 115), (110, 110)]])
        # accent ray pixel present near bottom-right
        accent = sum(1 for xy in [(230, 230), (235, 235), (225, 235)]
                     if img.getpixel(xy) == generate.ACCENT)
        self.assertGreater(accent, 0, "accent ray not found")


class CommittedAssetsTest(unittest.TestCase):
    """Committed files must exist and match generator dimensions."""

    def test_committed_assets_exist_and_match(self):
        for name, size in [("og-image.png", (1280, 640)),
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
