"""Unit tests for the days/hours/minutes measurement interval (1.0.15).

Covers only the pure helpers in app/app.py (_interval_parts,
interval_seconds, _fmt_interval): no server, no config files, so this
file is safe to run together with the end-to-end server tests.
"""

import os
import sys
import tempfile
import unittest

# Set the data dir before importing app, exactly like the server
# tests do: app resolves DATA_DIR once at import time, and importing
# it first without this would point it at the real app/data dir.
TMP = tempfile.mkdtemp(prefix="cfbestipd-interval-test-")
os.environ["CFBESTIPD_DATA_DIR"] = TMP

APP_DIR = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, APP_DIR)

import app  # noqa: E402


class IntervalTest(unittest.TestCase):
    def test_defaults(self):
        self.assertEqual(app._interval_parts({}), (7, 0, 0))
        self.assertEqual(app.interval_seconds({}), 7 * 86400)

    def test_old_config_without_hours_minutes(self):
        # A config file written by 1.0.14 only carries interval_days.
        self.assertEqual(
            app._interval_parts({"interval_days": 3}), (3, 0, 0))
        self.assertEqual(
            app.interval_seconds({"interval_days": 3}), 3 * 86400)

    def test_hours_and_minutes(self):
        cfg = {"interval_days": 0, "interval_hours": 2,
               "interval_minutes": 30}
        self.assertEqual(app.interval_seconds(cfg), 2 * 3600 + 30 * 60)
        cfg = {"interval_days": 1, "interval_hours": 1,
               "interval_minutes": 1}
        self.assertEqual(
            app.interval_seconds(cfg), 86400 + 3600 + 60)

    def test_six_minutes(self):
        cfg = {"interval_days": 0, "interval_hours": 0,
               "interval_minutes": 6}
        self.assertEqual(app.interval_seconds(cfg), 360)

    def test_parts_clamped_to_ranges(self):
        cfg = {"interval_days": 99, "interval_hours": 99,
               "interval_minutes": 99}
        self.assertEqual(app._interval_parts(cfg), (30, 23, 59))
        cfg = {"interval_days": -1, "interval_hours": -2,
               "interval_minutes": -3}
        self.assertEqual(app._interval_parts(cfg), (0, 0, 0))

    def test_garbage_values_fall_back_to_defaults(self):
        cfg = {"interval_days": "abc", "interval_hours": None,
               "interval_minutes": "x"}
        self.assertEqual(app._interval_parts(cfg), (7, 0, 0))
        cfg = {"interval_days": "3", "interval_hours": "2",
               "interval_minutes": "30"}
        self.assertEqual(app._interval_parts(cfg), (3, 2, 30))

    def test_fmt_interval(self):
        self.assertEqual(app._fmt_interval(7, 0, 0), "7 天")
        self.assertEqual(app._fmt_interval(0, 6, 0), "6 小时")
        self.assertEqual(app._fmt_interval(0, 0, 6), "6 分钟")
        self.assertEqual(app._fmt_interval(1, 2, 30), "1 天 2 小时 30 分钟")
        self.assertEqual(app._fmt_interval(0, 0, 0), "0 分钟")

    def test_bounds(self):
        self.assertEqual(app.MIN_INTERVAL_SECONDS, 300)
        self.assertEqual(app.MAX_INTERVAL_SECONDS, 30 * 86400)


if __name__ == "__main__":
    unittest.main()
