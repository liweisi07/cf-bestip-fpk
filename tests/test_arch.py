"""Unit tests for dual-architecture cfst selection (arm64 + amd64).

detect_arch() maps platform.machine(); find_cfst_bin(arch) prefers
an env override, then a downloaded per-arch binary, then the bundled
per-arch binary. An unsupported arch must raise clearly, never
silently pick the wrong binary.
"""

import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import app

APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class ArchTest(unittest.TestCase):
    def test_detect_arch(self):
        cases = {
            "aarch64": "arm64", "arm64": "arm64",
            "x86_64": "amd64", "amd64": "amd64",
        }
        for machine, want in cases.items():
            with mock.patch.object(app.platform, "machine",
                                   return_value=machine):
                self.assertEqual(app.detect_arch(), want, machine)
        for machine in ("armv7l", "armv6l", "mips", "riscv64"):
            with mock.patch.object(app.platform, "machine",
                                   return_value=machine):
                with self.assertRaises(RuntimeError):
                    app.detect_arch()

    def test_bundled_cfst_path(self):
        arm = app._bundled_cfst_path("arm64")
        amd = app._bundled_cfst_path("amd64")
        self.assertTrue(arm.endswith("cfst"))
        self.assertFalse(arm.endswith("cfst-amd64"))
        self.assertTrue(amd.endswith("cfst-amd64"))
        self.assertTrue(os.path.isfile(arm))
        self.assertTrue(os.path.isfile(amd))

    def test_bundled_cfst_arch(self):
        # ELF e_machine at bytes 18:20: EM_AARCH64=183, EM_X86_64=62.
        import struct
        with open(app._bundled_cfst_path("arm64"), "rb") as fh:
            fh.seek(18)
            machine = struct.unpack("<H", fh.read(2))[0]
        self.assertEqual(machine, 183)
        with open(app._bundled_cfst_path("amd64"), "rb") as fh:
            fh.seek(18)
            machine = struct.unpack("<H", fh.read(2))[0]
        self.assertEqual(machine, 62)

    def test_find_cfst_bin_bundled(self):
        # Env override cleared and no downloaded binary: the bundled
        # per-arch binary is chosen.
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CFBESTIPD_CFST_BIN", None)
            tmp = tempfile.mkdtemp(prefix="cfbestipd-arch-test-")
            with mock.patch.object(app, "CFST_BIN_DIR",
                                   os.path.join(tmp, "cfst-bin")):
                self.assertEqual(app.find_cfst_bin("arm64"),
                                 app._bundled_cfst_path("arm64"))
                self.assertEqual(app.find_cfst_bin("amd64"),
                                 app._bundled_cfst_path("amd64"))

    def test_find_cfst_bin_env_override(self):
        tmp = tempfile.mkdtemp(prefix="cfbestipd-arch-test-")
        fake = os.path.join(tmp, "my-cfst")
        with open(fake, "w") as fh:
            fh.write("fake")
        with mock.patch.dict(os.environ,
                             {"CFBESTIPD_CFST_BIN": fake}):
            self.assertEqual(app.find_cfst_bin("arm64"), fake)
            self.assertEqual(app.find_cfst_bin("amd64"), fake)

    def test_find_cfst_bin_prefers_downloaded(self):
        tmp = tempfile.mkdtemp(prefix="cfbestipd-arch-test-")
        bindir = os.path.join(tmp, "cfst-bin")
        os.makedirs(bindir)
        dl = os.path.join(bindir, "cfst-amd64")
        with open(dl, "w") as fh:
            fh.write("fake")
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CFBESTIPD_CFST_BIN", None)
            with mock.patch.object(app, "CFST_BIN_DIR", bindir):
                self.assertEqual(app.find_cfst_bin("amd64"), dl)

    def test_find_cfst_bin_legacy_arm_only(self):
        # A legacy downloaded "cfst" (no arch suffix) is only a
        # fallback for arm64, never for amd64. The bundled binary is
        # hidden here so the legacy fallback is actually reached.
        tmp = tempfile.mkdtemp(prefix="cfbestipd-arch-test-")
        bindir = os.path.join(tmp, "cfst-bin")
        os.makedirs(bindir)
        legacy = os.path.join(bindir, "cfst")
        with open(legacy, "w") as fh:
            fh.write("fake")
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CFBESTIPD_CFST_BIN", None)
            with mock.patch.object(app, "CFST_BIN_DIR", bindir):
                with mock.patch.object(
                        app, "_bundled_cfst_path",
                        return_value="/nonexistent/cfst"):
                    self.assertEqual(app.find_cfst_bin("arm64"),
                                     legacy)
                    self.assertIsNone(app.find_cfst_bin("amd64"))


if __name__ == "__main__":
    unittest.main()
