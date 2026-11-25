"""Unit tests for app/cfdns.py with a mocked Cloudflare API.

The fake opener records every request (method, URL, JSON payload) and
answers from a scripted table, so the tests verify: zone lookup, record
create vs update, proxied=false always, TTL 60 with auto fallback,
read-back confirmation, proxied-record rejection, and that the API
token never appears in any error message.
"""

import io
import json
import os
import sys
import unittest
import urllib.error

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import cfdns

TOKEN = "SECRET-TOKEN-XYZ"
ZONE = "example.com"
PREFIX = "cf"
FULL = "cf.example.com"
BEST_IP = "104.16.0.99"


class FakeResponse:
    def __init__(self, payload):
        self._data = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeOpener:
    """answers: list of (method, url_substring, response-or-exception)."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.calls = []

    def open(self, req, timeout=None):
        method = req.get_method()
        url = req.full_url
        try:
            payload = json.loads(req.data.decode("utf-8")) \
                if req.data else None
        except (ValueError, UnicodeDecodeError):
            payload = None
        self.calls.append({"method": method, "url": url,
                           "payload": payload,
                           "auth": req.headers.get("Authorization")})
        for i, (m, sub, resp) in enumerate(self.answers):
            if m == method and sub in url:
                del self.answers[i]
                if isinstance(resp, Exception):
                    raise resp
                return FakeResponse(resp)
        raise AssertionError("unexpected API call: %s %s" % (method, url))


def http_error(code, message):
    body = json.dumps({"errors": [{"message": message}]}).encode("utf-8")
    return urllib.error.HTTPError(
        "https://api.cloudflare.com/client/v4/x", code, "error", {}, io.BytesIO(body)
    )


def ok(result):
    return {"success": True, "result": result}


class CfdnsTest(unittest.TestCase):
    def setUp(self):
        self._orig = cfdns._NO_PROXY_OPENER

    def tearDown(self):
        cfdns._NO_PROXY_OPENER = self._orig

    def _install(self, answers):
        opener = FakeOpener(answers)
        cfdns._NO_PROXY_OPENER = opener
        return opener

    def test_create_path(self):
        opener = self._install([
            ("GET", "/zones?name=", ok([{"id": "zone1"}])),
            ("GET", "/dns_records?type=A", ok([])),
            ("POST", "/dns_records", ok({"id": "rec1"})),
            ("GET", "/dns_records?type=A",
             ok([{"id": "rec1", "content": BEST_IP, "proxied": False}])),
        ])
        ip, ttl, msg = cfdns.ensure_record(TOKEN, ZONE, PREFIX, BEST_IP)
        self.assertEqual(ip, BEST_IP)
        self.assertEqual(ttl, 60)
        self.assertIn("已创建", msg)
        self.assertIn(FULL, msg)
        post = [c for c in opener.calls if c["method"] == "POST"][0]
        self.assertEqual(post["payload"]["type"], "A")
        self.assertEqual(post["payload"]["name"], FULL)
        self.assertEqual(post["payload"]["content"], BEST_IP)
        self.assertIs(post["payload"]["proxied"], False)
        self.assertEqual(post["payload"]["ttl"], 60)
        self.assertEqual(post["auth"], "Bearer " + TOKEN)

    def test_update_path(self):
        opener = self._install([
            ("GET", "/zones?name=", ok([{"id": "zone1"}])),
            ("GET", "/dns_records?type=A",
             ok([{"id": "rec1", "content": "104.16.0.1",
                  "proxied": False}])),
            ("PATCH", "/dns_records/rec1", ok({"id": "rec1"})),
            ("GET", "/dns_records?type=A",
             ok([{"id": "rec1", "content": BEST_IP, "proxied": False}])),
        ])
        ip, ttl, msg = cfdns.ensure_record(TOKEN, ZONE, PREFIX, BEST_IP)
        self.assertEqual(ip, BEST_IP)
        self.assertIn("已更新", msg)
        patch = [c for c in opener.calls if c["method"] == "PATCH"][0]
        self.assertIs(patch["payload"]["proxied"], False)
        self.assertEqual(patch["payload"]["ttl"], 60)

    def test_ttl_fallback_to_auto(self):
        opener = self._install([
            ("GET", "/zones?name=", ok([{"id": "zone1"}])),
            ("GET", "/dns_records?type=A",
             ok([{"id": "rec1", "content": "104.16.0.1",
                  "proxied": False}])),
            ("PATCH", "/dns_records/rec1",
             http_error(400, "ttl must be 1 or between 60 and 86400")),
            ("PATCH", "/dns_records/rec1", ok({"id": "rec1"})),
            ("GET", "/dns_records?type=A",
             ok([{"id": "rec1", "content": BEST_IP, "proxied": False}])),
        ])
        _ip, ttl, msg = cfdns.ensure_record(TOKEN, ZONE, PREFIX, BEST_IP)
        self.assertEqual(ttl, 1)
        self.assertIn("TTL 自动", msg)
        patches = [c for c in opener.calls if c["method"] == "PATCH"]
        self.assertEqual([p["payload"]["ttl"] for p in patches], [60, 1])

    def test_proxied_record_rejected(self):
        self._install([
            ("GET", "/zones?name=", ok([{"id": "zone1"}])),
            ("GET", "/dns_records?type=A",
             ok([{"id": "rec1", "content": BEST_IP, "proxied": True}])),
            ("PATCH", "/dns_records/rec1", ok({"id": "rec1"})),
            ("GET", "/dns_records?type=A",
             ok([{"id": "rec1", "content": BEST_IP, "proxied": True}])),
        ])
        with self.assertRaises(cfdns.DNSApiError) as ctx:
            cfdns.ensure_record(TOKEN, ZONE, PREFIX, BEST_IP)
        self.assertIn("灰云", str(ctx.exception))
        self.assertNotIn(TOKEN, str(ctx.exception))

    def test_readback_mismatch_rejected(self):
        self._install([
            ("GET", "/zones?name=", ok([{"id": "zone1"}])),
            ("GET", "/dns_records?type=A", ok([])),
            ("POST", "/dns_records", ok({"id": "rec1"})),
            ("GET", "/dns_records?type=A",
             ok([{"id": "rec1", "content": "104.16.0.1",
                  "proxied": False}])),
        ])
        with self.assertRaises(cfdns.DNSApiError) as ctx:
            cfdns.ensure_record(TOKEN, ZONE, PREFIX, BEST_IP)
        self.assertIn("回查不一致", str(ctx.exception))
        self.assertNotIn(TOKEN, str(ctx.exception))

    def test_zone_not_found(self):
        self._install([
            ("GET", "/zones?name=", ok([])),
        ])
        with self.assertRaises(cfdns.DNSApiError) as ctx:
            cfdns.ensure_record(TOKEN, ZONE, PREFIX, BEST_IP)
        self.assertIn("找不到域名", str(ctx.exception))
        self.assertNotIn(TOKEN, str(ctx.exception))

    def test_invalid_ip_makes_no_call(self):
        opener = self._install([])
        with self.assertRaises(cfdns.DNSApiError):
            cfdns.ensure_record(TOKEN, ZONE, PREFIX, "not-an-ip")
        self.assertEqual(opener.calls, [])

    def test_multi_create(self):
        ips = ["104.16.0.1", "104.16.0.2", "104.16.0.3"]
        opener = self._install([
            ("GET", "/zones?name=", ok([{"id": "zone1"}])),
            ("GET", "/dns_records?type=A", ok([])),
            ("POST", "/dns_records", ok({"id": "rec1"})),
            ("POST", "/dns_records", ok({"id": "rec2"})),
            ("POST", "/dns_records", ok({"id": "rec3"})),
            ("GET", "/dns_records?type=A", ok([
                {"id": "rec1", "content": ips[0], "proxied": False},
                {"id": "rec2", "content": ips[1], "proxied": False},
                {"id": "rec3", "content": ips[2], "proxied": False},
            ])),
        ])
        got, ttl, msg = cfdns.ensure_records(TOKEN, ZONE, PREFIX, ips, "A")
        self.assertEqual(got, ips)
        self.assertEqual(ttl, 60)
        self.assertIn("已创建", msg)
        self.assertIn("共 3 条 A 记录", msg)
        posts = [c for c in opener.calls if c["method"] == "POST"]
        self.assertEqual([p["payload"]["content"] for p in posts], ips)
        self.assertTrue(all(p["payload"]["type"] == "A" for p in posts))

    def test_multi_update_reuse_patch_create(self):
        # rec1 already has a wanted IP (kept), rec2 is a spare and is
        # PATCHed to a missing wanted IP, the third is created.
        ips = ["1.1.1.1", "3.3.3.3", "4.4.4.4"]
        opener = self._install([
            ("GET", "/zones?name=", ok([{"id": "zone1"}])),
            ("GET", "/dns_records?type=A", ok([
                {"id": "rec1", "content": "1.1.1.1", "proxied": False},
                {"id": "rec2", "content": "2.2.2.2", "proxied": False},
            ])),
            ("PATCH", "/dns_records/rec2", ok({"id": "rec2"})),
            ("POST", "/dns_records", ok({"id": "rec3"})),
            ("GET", "/dns_records?type=A", ok([
                {"id": "rec1", "content": "1.1.1.1", "proxied": False},
                {"id": "rec2", "content": "3.3.3.3", "proxied": False},
                {"id": "rec3", "content": "4.4.4.4", "proxied": False},
            ])),
        ])
        got, _ttl, msg = cfdns.ensure_records(TOKEN, ZONE, PREFIX, ips, "A")
        self.assertEqual(got, ips)
        self.assertIn("已更新", msg)
        self.assertIn("共 3 条 A 记录", msg)
        patches = [c for c in opener.calls if c["method"] == "PATCH"]
        self.assertEqual(len(patches), 1)
        self.assertEqual(patches[0]["payload"]["content"], "3.3.3.3")
        posts = [c for c in opener.calls if c["method"] == "POST"]
        self.assertEqual([p["payload"]["content"] for p in posts],
                         ["4.4.4.4"])
        self.assertEqual([c for c in opener.calls
                          if c["method"] == "DELETE"], [])

    def test_multi_shrink_deletes_stale(self):
        opener = self._install([
            ("GET", "/zones?name=", ok([{"id": "zone1"}])),
            ("GET", "/dns_records?type=A", ok([
                {"id": "rec1", "content": "1.1.1.1", "proxied": False},
                {"id": "rec2", "content": "2.2.2.2", "proxied": False},
                {"id": "rec3", "content": "3.3.3.3", "proxied": False},
            ])),
            ("DELETE", "/dns_records/rec2", ok({})),
            ("DELETE", "/dns_records/rec3", ok({})),
            ("GET", "/dns_records?type=A", ok([
                {"id": "rec1", "content": "1.1.1.1", "proxied": False},
            ])),
        ])
        got, _ttl, msg = cfdns.ensure_records(
            TOKEN, ZONE, PREFIX, ["1.1.1.1"], "A")
        self.assertEqual(got, ["1.1.1.1"])
        self.assertIn("已更新", msg)
        deletes = [c for c in opener.calls if c["method"] == "DELETE"]
        self.assertEqual(len(deletes), 2)
        self.assertEqual([c for c in opener.calls
                          if c["method"] in ("POST", "PATCH")], [])

    def test_multi_dedupes_duplicate_content(self):
        opener = self._install([
            ("GET", "/zones?name=", ok([{"id": "zone1"}])),
            ("GET", "/dns_records?type=A", ok([
                {"id": "rec1", "content": "1.1.1.1", "proxied": False},
                {"id": "rec2", "content": "1.1.1.1", "proxied": False},
                {"id": "rec3", "content": "2.2.2.2", "proxied": False},
            ])),
            ("DELETE", "/dns_records/rec2", ok({})),
            ("GET", "/dns_records?type=A", ok([
                {"id": "rec1", "content": "1.1.1.1", "proxied": False},
                {"id": "rec3", "content": "2.2.2.2", "proxied": False},
            ])),
        ])
        got, _ttl, msg = cfdns.ensure_records(
            TOKEN, ZONE, PREFIX, ["1.1.1.1", "2.2.2.2"], "A")
        self.assertEqual(got, ["1.1.1.1", "2.2.2.2"])
        self.assertIn("共 2 条 A 记录", msg)
        deletes = [c for c in opener.calls if c["method"] == "DELETE"]
        self.assertEqual(len(deletes), 1)

    def test_aaaa_records(self):
        ips = ["2606:4700:10::6814:1", "2606:4700:10::6814:2"]
        opener = self._install([
            ("GET", "/zones?name=", ok([{"id": "zone1"}])),
            ("GET", "/dns_records?type=AAAA", ok([])),
            ("POST", "/dns_records", ok({"id": "rec1"})),
            ("POST", "/dns_records", ok({"id": "rec2"})),
            ("GET", "/dns_records?type=AAAA", ok([
                {"id": "rec1", "content": ips[0], "proxied": False},
                {"id": "rec2", "content": ips[1], "proxied": False},
            ])),
        ])
        got, ttl, msg = cfdns.ensure_records(
            TOKEN, ZONE, PREFIX, ips, "AAAA")
        self.assertEqual(got, ips)
        self.assertEqual(ttl, 60)
        self.assertIn("共 2 条 AAAA 记录", msg)
        posts = [c for c in opener.calls if c["method"] == "POST"]
        self.assertTrue(all(p["payload"]["type"] == "AAAA"
                            for p in posts))
        self.assertEqual([p["payload"]["content"] for p in posts], ips)

    def test_aaaa_rejects_ipv4(self):
        opener = self._install([])
        with self.assertRaises(cfdns.DNSApiError):
            cfdns.ensure_records(TOKEN, ZONE, PREFIX, ["1.1.1.1"], "AAAA")
        self.assertEqual(opener.calls, [])

    def test_ensure_records_empty(self):
        opener = self._install([])
        with self.assertRaises(cfdns.DNSApiError):
            cfdns.ensure_records(TOKEN, ZONE, PREFIX, [], "A")
        self.assertEqual(opener.calls, [])

    def test_full_record_name(self):
        self.assertEqual(cfdns.full_record_name(ZONE, "cf"), FULL)
        self.assertEqual(cfdns.full_record_name(ZONE, ""), ZONE)
        self.assertEqual(cfdns.full_record_name(ZONE, "@"), ZONE)
        self.assertEqual(cfdns.full_record_name(" " + ZONE + " ", " cf "),
                         FULL)


if __name__ == "__main__":
    unittest.main()
