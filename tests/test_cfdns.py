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

    def test_full_record_name(self):
        self.assertEqual(cfdns.full_record_name(ZONE, "cf"), FULL)
        self.assertEqual(cfdns.full_record_name(ZONE, ""), ZONE)
        self.assertEqual(cfdns.full_record_name(ZONE, "@"), ZONE)
        self.assertEqual(cfdns.full_record_name(" " + ZONE + " ", " cf "),
                         FULL)


if __name__ == "__main__":
    unittest.main()
