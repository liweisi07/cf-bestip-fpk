"""End-to-end IPv6 test: run_job() with IPv6 enabled.

A fake cfst script writes IPv4 rows when the -f file is ip.txt and
IPv6 rows when it is ip6.txt; cfdns.ensure_records is stubbed to
record the A and AAAA writes. IPv6 connectivity is mocked on (this
sandbox has no IPv6 route). Asserts: best IPv4/IPv6, the top-N record
sets written to DNS (A + AAAA), and that a run failure in IPv6 would
not fail the whole run.
"""

import os
import sys
import tempfile
import unittest
from unittest import mock

TMP = tempfile.mkdtemp(prefix="cfbestipd-ipv6-test-")
os.environ["CFBESTIPD_DATA_DIR"] = TMP

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import app  # noqa: E402
import cfdns  # noqa: E402

FAKE_CFST = """#!/bin/sh
# Fake cfst: writes a fixed result.csv. IPv6 rows when the -f file
# is the IPv6 list (ip6.txt), IPv4 rows otherwise.
ipfile=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-f" ]; then ipfile="$a"; fi
  prev="$a"
done
case "$ipfile" in
  *ip6*)
    printf '%s\\n' \\
      'IP 地址,已发送,已接收,丢包率,平均延迟,下载速度(MB/s),地区码' \\
      '2606:4700:10::6814:1,4,4,0.00,12.0,50.0,LAX' \\
      '2606:4700:10::6814:2,4,4,0.00,15.0,40.0,LAX' \\
      > result.csv
    ;;
  *)
    printf '%s\\n' \\
      'IP 地址,已发送,已接收,丢包率,平均延迟,下载速度(MB/s),地区码' \\
      '104.16.0.99,4,4,0.00,12.0,50.0,LAX' \\
      '104.16.0.98,4,4,0.00,15.0,40.0,LAX' \\
      > result.csv
    ;;
esac
"""


class IPv6Test(unittest.TestCase):
    dns_calls = []

    @classmethod
    def setUpClass(cls):
        # Fake cfst binary. Save the previous CFST_BIN (the server
        # tests set theirs at import time) and restore it afterwards:
        # popping it would make the later server tests fall through
        # to the real cfst binary.
        cls._prev_cfst_bin = os.environ.get("CFBESTIPD_CFST_BIN")
        cls.cfst_path = os.path.join(TMP, "fake-cfst.sh")
        with open(cls.cfst_path, "w") as fh:
            fh.write(FAKE_CFST)
        os.chmod(cls.cfst_path, 0o755)
        os.environ["CFBESTIPD_CFST_BIN"] = cls.cfst_path
        # Stub the DNS record layer.
        cfdns.ensure_records_orig = cfdns.ensure_records

        def fake_ensure_records(token, zone, prefix, ips,
                                record_type="A"):
            cls.dns_calls.append(
                (token, zone, prefix, tuple(ips), record_type))
            return (list(ips), 60,
                    "已更新 DNS 记录 example.com -> %s（共 %d 条 %s 记录）"
                    % ("、".join(ips), len(ips), record_type))

        cfdns.ensure_records = fake_ensure_records
        # This sandbox has no IPv6 route; pretend there is one.
        app.check_ipv6_connectivity_orig = app.check_ipv6_connectivity
        app.check_ipv6_connectivity = lambda: True
        app.load_config()
        app._config.update({
            "subscriptions": [],
            "best_ip": None, "best_ip6": None,
            "last_run": None, "last_log": "", "event_log": "",
            "last_results": [], "last_result_count": 0,
            "last_results6": [], "last_result_count6": 0,
            "cf_token": "TOKEN", "cf_zone": "ZONE", "cf_record": "cf",
            "dns_record_ip": None, "dns_record_ips": [],
            "dns_record_ip6": None, "dns_record_ips6": [],
            "dns_last_update": None, "dns_last_error": "",
            "dns_last_update6": None, "dns_last_error6": "",
            "ipv6_enabled": True, "dns_record_count": 2,
            "region": "all",
            "notify_failure": False, "notify_ip_change": False,
            "notify_daily_result": False,
            "notify_tg_enabled": False, "notify_fs_enabled": False,
        })

    @classmethod
    def tearDownClass(cls):
        cfdns.ensure_records = cfdns.ensure_records_orig
        app.check_ipv6_connectivity = app.check_ipv6_connectivity_orig
        if cls._prev_cfst_bin is None:
            os.environ.pop("CFBESTIPD_CFST_BIN", None)
        else:
            os.environ["CFBESTIPD_CFST_BIN"] = cls._prev_cfst_bin

    def test_ipv6_run_writes_a_and_aaaa(self):
        self.__class__.dns_calls = []
        result = app.run_job()
        self.assertIn("测速完成", result)
        self.assertIn("IPv6 测速完成", result)
        cfg = app.get_config_copy()
        self.assertEqual(cfg["best_ip"], "104.16.0.99")
        self.assertEqual(cfg["best_ip6"], "2606:4700:10::6814:1")
        self.assertEqual(cfg["dns_record_ips"],
                         ["104.16.0.99", "104.16.0.98"])
        self.assertEqual(cfg["dns_record_ips6"],
                         ["2606:4700:10::6814:1",
                          "2606:4700:10::6814:2"])
        self.assertEqual(cfg["dns_record_ip"], "104.16.0.99")
        self.assertEqual(cfg["dns_record_ip6"], "2606:4700:10::6814:1")
        self.assertEqual(cfg["dns_last_error"], "")
        self.assertEqual(cfg["dns_last_error6"], "")
        self.assertIn(("TOKEN", "ZONE", "cf",
                       ("104.16.0.99", "104.16.0.98"), "A"),
                      self.dns_calls)
        self.assertIn(("TOKEN", "ZONE", "cf",
                       ("2606:4700:10::6814:1",
                        "2606:4700:10::6814:2"), "AAAA"),
                      self.dns_calls)

    def test_ipv6_failure_does_not_fail_run(self):
        # IPv6 measurement finds nothing (fake cfst writes IPv4 rows
        # even for the IPv6 file): the run still succeeds on IPv4 and
        # the IPv6 failure is recorded, not fatal.
        with mock.patch.object(app, "check_ipv6_connectivity",
                               return_value=True):
            with mock.patch.object(
                    app, "ip6_file",
                    return_value=os.path.join(TMP, "ip.txt")):
                # Point the IPv6 measurement at the IPv4 file so the
                # IPv6 result.csv holds IPv4 addresses, which the
                # IPv6 path must reject (no usable IPv6).
                self.__class__.dns_calls = []
                result = app.run_job()
                self.assertIn("测速完成", result)
                cfg = app.get_config_copy()
                self.assertEqual(cfg["best_ip"], "104.16.0.99")
                # No AAAA write happened this run.
                types = [c[4] for c in self.dns_calls]
                self.assertNotIn("AAAA", types)


if __name__ == "__main__":
    unittest.main()
