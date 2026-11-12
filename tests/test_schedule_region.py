"""Unit tests for the 1.0.16 features: daily schedule mode + region pick.

Covers only the pure helpers in app/app.py and app/cfst.py (plus a
load_config normalization check): no server, no network, so this file
is safe to run together with the end-to-end server tests.
"""

import json
import os
import sys
import tempfile
import time
import unittest

# Set the data dir before importing app, exactly like the server
# tests do: app resolves DATA_DIR once at import time, and importing
# it first without this would point it at the real app/data dir.
TMP = tempfile.mkdtemp(prefix="cfbestipd-schedule-test-")
os.environ["CFBESTIPD_DATA_DIR"] = TMP

APP_DIR = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, APP_DIR)

import app  # noqa: E402
import cfst  # noqa: E402

SAMPLE_CSV = (
    "IP 地址,已发送,已接收,丢包率,平均延迟,下载速度(MB/s),地区码\n"
    "104.16.0.1,4,4,0.00,10.0,30.0,LAX\n"
    "104.16.0.2,4,4,0.00,15.0,25.0,HKG\n"
    "104.16.0.3,4,4,0.00,25.0,40.0,HKG\n"
    "104.16.0.4,4,4,0.00,12.0,20.0,SIN\n"
    # Never download-tested: empty region, speed 0, ranks last.
    "104.16.0.5,4,4,0.00,5.0,0.0,\n"
)


def _write_tmp(content):
    fd, path = tempfile.mkstemp(suffix=".csv")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


def _at(year, month, day, hour, minute):
    return time.mktime((year, month, day, hour, minute, 0, 0, 0, -1))


class ScheduleTest(unittest.TestCase):
    def test_mode_defaults_to_interval(self):
        self.assertEqual(app._schedule_mode({}), "interval")
        self.assertEqual(app._schedule_mode({"schedule_mode": "daily"}),
                         "daily")
        self.assertEqual(app._schedule_mode({"schedule_mode": "DAILY"}),
                         "daily")
        self.assertEqual(app._schedule_mode({"schedule_mode": "bogus"}),
                         "interval")
        self.assertEqual(app._schedule_mode({"schedule_mode": None}),
                         "interval")

    def test_time_parsing(self):
        self.assertEqual(app._schedule_time({}), (3, 0))
        self.assertEqual(
            app._schedule_time({"schedule_time": "03:00"}), (3, 0))
        self.assertEqual(
            app._schedule_time({"schedule_time": "3:00"}), (3, 0))
        self.assertEqual(
            app._schedule_time({"schedule_time": "23:59"}), (23, 59))
        self.assertEqual(
            app._schedule_time({"schedule_time": "00:00"}), (0, 0))
        # Garbage and out-of-range values fall back to 03:00.
        self.assertEqual(
            app._schedule_time({"schedule_time": "abc"}), (3, 0))
        self.assertEqual(
            app._schedule_time({"schedule_time": "25:00"}), (3, 0))
        self.assertEqual(
            app._schedule_time({"schedule_time": "24:60"}), (3, 0))
        self.assertEqual(
            app._schedule_time({"schedule_time": "12:60"}), (3, 0))
        self.assertEqual(
            app._schedule_time({"schedule_time": None}), (3, 0))

    def test_fmt_schedule_time(self):
        self.assertEqual(app._fmt_schedule_time(3, 0), "03:00")
        self.assertEqual(app._fmt_schedule_time(23, 59), "23:59")

    def test_next_daily_run_today(self):
        cfg = {"schedule_time": "03:00"}
        nxt = app.next_daily_run(cfg, now=_at(2026, 11, 6, 2, 0))
        self.assertEqual(time.strftime("%Y-%m-%d %H:%M", nxt),
                         "2026-11-06 03:00")

    def test_next_daily_run_tomorrow_after_time(self):
        cfg = {"schedule_time": "03:00"}
        nxt = app.next_daily_run(cfg, now=_at(2026, 11, 6, 4, 0))
        self.assertEqual(time.strftime("%Y-%m-%d %H:%M", nxt),
                         "2026-11-07 03:00")

    def test_next_daily_run_exactly_at_time_is_tomorrow(self):
        cfg = {"schedule_time": "03:00"}
        nxt = app.next_daily_run(cfg, now=_at(2026, 11, 6, 3, 0))
        self.assertEqual(time.strftime("%Y-%m-%d %H:%M", nxt),
                         "2026-11-07 03:00")

    def test_next_run_text_interval(self):
        cfg = {"schedule_mode": "interval", "interval_days": 7,
               "interval_hours": 0, "interval_minutes": 0,
               "last_run": "2026-11-06 10:00:00"}
        self.assertEqual(app.next_run_text(cfg), "2026-11-13 10:00:00")
        cfg2 = {"schedule_mode": "interval", "last_run": None}
        self.assertEqual(app.next_run_text(cfg2), "—")

    def test_next_run_text_daily_ignores_last_run(self):
        cfg = {"schedule_mode": "daily", "schedule_time": "03:00",
               "last_run": "2026-11-05 03:00:00"}
        # Monkeypatch time via now parameter through next_daily_run is
        # not possible here, so only assert the shape: HH:MM:SS on a
        # date at 03:00.
        text = app.next_run_text(cfg)
        self.assertTrue(text.endswith("03:00:00"), text)

    def test_region_helpers(self):
        self.assertEqual(app._region({}), "all")
        self.assertEqual(app._region({"region": "hkg"}), "HKG")
        self.assertEqual(app._region({"region": "HKG"}), "HKG")
        self.assertEqual(app._region({"region": "XXX"}), "all")
        self.assertEqual(app._region({"region": ""}), "all")
        self.assertEqual(app._region_label("HKG"), "香港 HKG")
        self.assertEqual(app._region_label("all"), "全部（自动）")
        self.assertEqual(app._region_label("XXX"), "XXX")

    def test_normalize_region_all_case(self):
        # "all" is lowercase in REGION_OPTIONS while IATA codes are
        # uppercase: a plain upper() + membership check rejects it,
        # so the settings page could never save "全部（自动）".
        self.assertEqual(app._normalize_region("all"), "all")
        self.assertEqual(app._normalize_region("ALL"), "all")
        self.assertEqual(app._normalize_region("All"), "all")
        self.assertEqual(app._normalize_region(" all "), "all")
        self.assertEqual(app._normalize_region("hkg"), "HKG")
        self.assertEqual(app._normalize_region("HKG"), "HKG")
        self.assertIsNone(app._normalize_region("XXX"))
        self.assertIsNone(app._normalize_region(""))
        self.assertIsNone(app._normalize_region(None))
        self.assertEqual(app._region({"region": "ALL"}), "all")

    def test_load_config_old_file_gets_defaults(self):
        saved = dict(app._config)
        try:
            with open(app.CONFIG_PATH, "w", encoding="utf-8") as fh:
                json.dump({"interval_days": 3}, fh)
            app.load_config()
            self.assertEqual(app._config["schedule_mode"], "interval")
            self.assertEqual(app._config["schedule_time"], "03:00")
            self.assertEqual(app._config["region"], "all")
            self.assertIsNone(app._config["last_daily_run"])
        finally:
            app._config.clear()
            app._config.update(saved)

    def test_load_config_garbage_schedule_normalized(self):
        saved = dict(app._config)
        try:
            with open(app.CONFIG_PATH, "w", encoding="utf-8") as fh:
                json.dump({"schedule_mode": "bogus",
                           "schedule_time": "25:99",
                           "region": "XXX",
                           "last_daily_run": "not-a-date"}, fh)
            app.load_config()
            self.assertEqual(app._config["schedule_mode"], "interval")
            self.assertEqual(app._config["schedule_time"], "03:00")
            self.assertEqual(app._config["region"], "all")
            self.assertIsNone(app._config["last_daily_run"])
        finally:
            app._config.clear()
            app._config.update(saved)


class RegionPickTest(unittest.TestCase):
    def setUp(self):
        path = _write_tmp(SAMPLE_CSV)
        try:
            self.rows = cfst.parse_result_csv(path)
        finally:
            os.remove(path)

    def test_parse_keeps_region(self):
        self.assertEqual(len(self.rows), 5)
        regions = [r["region"] for r in self.rows]
        self.assertEqual(regions, ["LAX", "HKG", "HKG", "SIN", ""])

    def test_global_best(self):
        best, fell_back = cfst.pick_best_for_region(self.rows, "all")
        self.assertEqual(best, "104.16.0.1")
        self.assertFalse(fell_back)

    def test_region_best_differs_from_global(self):
        best, fell_back = cfst.pick_best_for_region(self.rows, "HKG")
        self.assertEqual(best, "104.16.0.2")
        self.assertFalse(fell_back)
        best, fell_back = cfst.pick_best_for_region(self.rows, "SIN")
        self.assertEqual(best, "104.16.0.4")
        self.assertFalse(fell_back)

    def test_region_match_is_case_insensitive(self):
        best, fell_back = cfst.pick_best_for_region(self.rows, "hkg")
        self.assertEqual(best, "104.16.0.2")
        self.assertFalse(fell_back)

    def test_empty_region_rows_never_match(self):
        # 104.16.0.5 has the lowest latency but an empty region and
        # speed 0: it must not win any region pick, nor the global one.
        self.assertEqual(
            cfst.rows_in_region(self.rows, "HKG"),
            [r for r in self.rows if r["region"] == "HKG"])
        self.assertEqual(cfst.rows_in_region(self.rows, ""), [])

    def test_missing_region_falls_back_to_global(self):
        best, fell_back = cfst.pick_best_for_region(self.rows, "FRA")
        self.assertEqual(best, "104.16.0.1")
        self.assertTrue(fell_back)

    def test_top_rows_region_filtered(self):
        top = cfst.top_rows(self.rows, region="HKG")
        self.assertEqual([r["ip"] for r in top],
                         ["104.16.0.2", "104.16.0.3"])
        top = cfst.top_rows(self.rows, region="FRA")
        self.assertEqual([r["ip"] for r in top[:3]],
                         ["104.16.0.1", "104.16.0.4", "104.16.0.2"])
        top = cfst.top_rows(self.rows)
        self.assertEqual(top[0]["ip"], "104.16.0.1")


if __name__ == "__main__":
    unittest.main()
