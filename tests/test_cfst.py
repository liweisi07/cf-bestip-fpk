"""Unit tests for app/cfst.py (result.csv parsing + best IP pick)."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import cfst

SAMPLE_CSV = (
    "IP 地址,已发送,已接收,丢包率,平均延迟,下载速度(MB/s),地区码\n"
    "104.16.0.1,4,4,0.00,20.5,30.0,LAX\n"
    "104.16.0.2,4,4,0.00,15.0,25.0,SEA\n"
    "104.16.0.3,4,3,25.00,10.0,99.0,HKG\n"
    "bad-row,4,4,not-a-number,10.0,10.0,XXX\n"
    ",4,4,0.00,10.0,10.0,XXX\n"
)

REORDERED_CSV = (
    "下载速度(MB/s),IP 地址,平均延迟,丢包率,已发送,已接收,地区码\n"
    "40.0,104.16.0.9,18.0,0.00,4,4,SIN\n"
    "50.0,104.16.0.8,22.0,0.00,4,4,NRT\n"
)


def _write_tmp(content):
    fd, path = tempfile.mkstemp(suffix=".csv")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


class CfstTest(unittest.TestCase):
    def test_parse_and_pick_best(self):
        path = _write_tmp(SAMPLE_CSV)
        try:
            rows = cfst.parse_result_csv(path)
        finally:
            os.remove(path)
        # Malformed rows are skipped; 3 valid rows remain.
        self.assertEqual(len(rows), 3)
        # Best = lowest loss, then lowest latency, then highest speed:
        # 104.16.0.2 (loss 0, latency 15) beats 104.16.0.1 (loss 0,
        # latency 20.5) and 104.16.0.3 (loss 25).
        self.assertEqual(cfst.pick_best(rows), "104.16.0.2")

    def test_header_mapping_with_reordered_columns(self):
        path = _write_tmp(REORDERED_CSV)
        try:
            rows = cfst.parse_result_csv(path)
        finally:
            os.remove(path)
        self.assertEqual(len(rows), 2)
        self.assertEqual(cfst.pick_best(rows), "104.16.0.9")

    def test_empty_file(self):
        path = _write_tmp("")
        try:
            rows = cfst.parse_result_csv(path)
        finally:
            os.remove(path)
        self.assertEqual(rows, [])
        self.assertIsNone(cfst.pick_best(rows))

    def test_header_only(self):
        path = _write_tmp(
            "IP 地址,已发送,已接收,丢包率,平均延迟,下载速度(MB/s),地区码\n"
        )
        try:
            rows = cfst.parse_result_csv(path)
        finally:
            os.remove(path)
        self.assertEqual(rows, [])
        self.assertIsNone(cfst.pick_best(rows))


if __name__ == "__main__":
    unittest.main()
