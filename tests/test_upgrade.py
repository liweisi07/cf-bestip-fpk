"""Unit tests for app/upgrade.py (online upgrade check + download).

The network is faked with a stub opener; the real repo version data
is only used in a live check (skipped when unreachable).
"""

import base64
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import upgrade

MANIFEST_TEXT = (
    "appname=cfbestipd\n"
    "version=1.0.23\n"
    "display_name=CF\u4f18\u9009IP\uff08\u57df\u540d\u7248\uff09\n"
    "changelog=\u65b0\u589e IPv6 \u4f18\u9009\u3002\n"
)


class FakeResponse:
    def __init__(self, data):
        self._data = data

    def read(self, n=-1):
        if n is None or n < 0:
            out, self._data = self._data, b""
            return out
        out, self._data = self._data[:n], self._data[n:]
        return out

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeOpener:
    """Maps URL substrings to bytes (or an exception)."""

    def __init__(self, mapping):
        self.mapping = dict(mapping)
        self.calls = []

    def open(self, req, timeout=None):
        url = req.full_url
        self.calls.append(url)
        for sub, value in self.mapping.items():
            if sub in url:
                if isinstance(value, Exception):
                    raise value
                return FakeResponse(value)
        raise AssertionError("unexpected URL: %s" % url)


class UpgradeTest(unittest.TestCase):
    def test_parse_version(self):
        self.assertEqual(upgrade.parse_version("1.0.22"), (1, 0, 22))
        self.assertEqual(upgrade.parse_version(" 2.3.5 "), (2, 3, 5))
        self.assertIsNone(upgrade.parse_version("1.0.x"))
        self.assertIsNone(upgrade.parse_version(""))
        self.assertIsNone(upgrade.parse_version(None))

    def test_compare_versions(self):
        self.assertEqual(upgrade.compare_versions("1.0.22", "1.0.23"), -1)
        self.assertEqual(upgrade.compare_versions("1.0.23", "1.0.22"), 1)
        self.assertEqual(upgrade.compare_versions("1.0.22", "1.0.22"), 0)
        self.assertEqual(upgrade.compare_versions("1.0.9", "1.0.22"), -1)
        self.assertIsNone(upgrade.compare_versions("x", "1.0.22"))

    def test_parse_manifest(self):
        version, changelog = upgrade.parse_manifest(MANIFEST_TEXT)
        self.assertEqual(version, "1.0.23")
        self.assertIn("IPv6", changelog)

    def test_fetch_latest_raw(self):
        opener = FakeOpener({
            "raw.githubusercontent.com": MANIFEST_TEXT.encode("utf-8"),
        })
        version, changelog = upgrade.fetch_latest(opener=opener)
        self.assertEqual(version, "1.0.23")
        self.assertIn("IPv6", changelog)

    def test_fetch_latest_api_fallback(self):
        # Raw fails; the GitHub contents API (base64 manifest) works.
        payload = json.dumps({
            "content": base64.b64encode(
                MANIFEST_TEXT.encode("utf-8")).decode("utf-8"),
        }).encode("utf-8")
        opener = FakeOpener({
            "raw.githubusercontent.com": urllib.error.URLError("down"),
            "api.github.com": payload,
        })
        version, _changelog = upgrade.fetch_latest(opener=opener)
        self.assertEqual(version, "1.0.23")

    def test_fetch_latest_both_fail(self):
        opener = FakeOpener({
            "raw.githubusercontent.com": urllib.error.URLError("down"),
            "api.github.com": urllib.error.URLError("down"),
        })
        with self.assertRaises(RuntimeError):
            upgrade.fetch_latest(opener=opener)

    def test_fpk_url_and_name(self):
        # Since 1.0.22 the package is universal (no -arm64 suffix).
        self.assertEqual(upgrade.fpk_name("1.0.23"),
                         "cf-bestip-domain-1.0.23.fpk")
        self.assertIn("cf-bestip-domain-1.0.23.fpk",
                      upgrade.fpk_url("1.0.23"))
        self.assertNotIn("arm64", upgrade.fpk_url("1.0.23"))

    def test_download_fpk(self):
        blob = b"X" * 200 * 1024  # 200 KB of fake .fpk
        opener = FakeOpener({"raw.githubusercontent.com": blob})
        dest_dir = tempfile.mkdtemp(prefix="cfbestipd-upgrade-test-")
        path = upgrade.download_fpk("1.0.23", dest_dir, opener=opener)
        self.assertTrue(os.path.isfile(path))
        self.assertEqual(os.path.getsize(path), len(blob))
        self.assertTrue(path.endswith("cf-bestip-domain-1.0.23.fpk"))

    def test_download_fpk_too_small(self):
        opener = FakeOpener({"raw.githubusercontent.com": b"tiny"})
        dest_dir = tempfile.mkdtemp(prefix="cfbestipd-upgrade-test-")
        with self.assertRaises(RuntimeError):
            upgrade.download_fpk("1.0.23", dest_dir, opener=opener)

    def test_download_fpk_bad_version(self):
        dest_dir = tempfile.mkdtemp(prefix="cfbestipd-upgrade-test-")
        with self.assertRaises(RuntimeError):
            upgrade.download_fpk("nope", dest_dir)


if __name__ == "__main__":
    unittest.main()
