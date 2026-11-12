"""End-to-end server test for the domain edition (app/app.py).

A local HTTP server stands in for Sub-Store (static YAML). DNS is
stubbed so the Cloudflare-domain node resolves into a Cloudflare
range, the speed-test binary is replaced by a tiny shell script that
writes a fixed result.csv, and the Cloudflare DNS API call is stubbed
so no real token or network is involved. This exercises: DNS settings
save, token never leaking into pages or status, on-demand /sub/<name>
rewritten to the bound domain, manual run (measure + DNS update +
rewrite), manual DNS update, delete.
"""

import http.cookiejar
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TMP = tempfile.mkdtemp(prefix="cfbestipd-test-")
os.environ["CFBESTIPD_DATA_DIR"] = TMP

APP_DIR = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, APP_DIR)

FAKE_CFST = os.path.join(TMP, "fake-cfst.sh")
with open(FAKE_CFST, "w", encoding="utf-8") as fh:
    fh.write(
        "#!/bin/sh\n"
        "printf '%s\\n' "
        "'IP 地址,已发送,已接收,丢包率,平均延迟,下载速度(MB/s),地区码' "
        "'104.16.0.99,4,4,0.00,12.0,50.0,LAX' > result.csv\n"
    )
os.chmod(FAKE_CFST, 0o755)
os.environ["CFBESTIPD_CFST_BIN"] = FAKE_CFST

import app  # noqa: E402
import cfdns  # noqa: E402
import rewriter  # noqa: E402

TOKEN = "SECRET-TOKEN-XYZ"
ZONE = "example.com"
RECORD = "cf"
DOMAIN = "cf.example.com"
BEST_IP = "104.16.0.99"

UPSTREAM_YAML = """proxies:
  - name: cfnode
    type: vless
    server: cf.test.example
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    tls: true
  - name: plainnode
    type: vless
    server: other.test.example
    port: 443
    uuid: 22222222-2222-2222-2222-222222222222
    tls: true
    servername: other.test.example
"""


def _fake_resolver(domain):
    if domain == "cf.test.example":
        return ["104.16.0.10"]
    if domain == "other.test.example":
        return ["93.184.216.34"]
    return []


class _UpstreamHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        data = UPSTREAM_YAML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/yaml; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


# Shared cookie jar: the settings page and management APIs require a
# login, so the test client logs in once and keeps the session cookie.
_JAR = http.cookiejar.CookieJar()


def _opener():
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPCookieProcessor(_JAR))


class ServerDomainTest(unittest.TestCase):
    dns_calls = []

    @classmethod
    def setUpClass(cls):
        rewriter.resolve_ipv4_orig = rewriter.resolve_ipv4
        rewriter.resolve_ipv4 = lambda domain, resolver=None: (
            _fake_resolver(domain)
            if resolver is None else resolver(domain)
        )
        cfdns.ensure_record_orig = cfdns.ensure_record

        def fake_ensure(token, zone, prefix, ip):
            cls.dns_calls.append((token, zone, prefix, ip))
            return (ip, 60,
                    "已更新 DNS 记录 %s -> %s（仅 DNS，TTL 60 秒）"
                    % (DOMAIN, ip))

        cfdns.ensure_record = fake_ensure
        app.load_config()
        # Reset shared run state: under `discover` the app module (and
        # its config file) is shared between test files, so a previous
        # test class's run must not leak best_ip/last_run/subscriptions
        # or a domain binding into this class.
        app._config.update({
            "subscriptions": [], "best_ip": None, "last_run": None,
            "last_log": "", "event_log": "", "last_results": [],
            "last_result_count": 0, "cf_token": "", "cf_zone": "",
            "cf_record": "cf", "dns_record_ip": None,
            "dns_last_update": None, "dns_last_error": "",
            "cf_binding_saved": None,
        })
        app.load_networks()
        cls.upstream = ThreadingHTTPServer(("127.0.0.1", 0), _UpstreamHandler)
        cls.upstream.daemon_threads = True
        threading.Thread(
            target=cls.upstream.serve_forever, daemon=True
        ).start()
        cls.upstream_port = cls.upstream.server_address[1]
        cls.app_server = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        cls.app_server.daemon_threads = True
        threading.Thread(
            target=cls.app_server.serve_forever, daemon=True
        ).start()
        cls.app_port = cls.app_server.server_address[1]
        # The app module/config is shared between test files, so reset
        # the account to the default admin/admin and log in; the
        # session cookie is kept in the shared jar for _get/_post.
        app._config["auth"] = app._new_auth("admin", "admin")
        with app._sessions_lock:
            app._sessions.clear()
        app.save_config()
        app.save_sessions()
        data = urllib.parse.urlencode(
            {"username": "admin", "password": "admin", "next": "/"}
        ).encode("utf-8")
        req = urllib.request.Request(
            "http://127.0.0.1:%d/login" % cls.app_port, data=data)
        with _opener().open(req, timeout=30) as resp:
            assert resp.status == 200, resp.status

    @classmethod
    def tearDownClass(cls):
        cls.app_server.shutdown()
        cls.app_server.server_close()
        cls.upstream.shutdown()
        cls.upstream.server_close()
        rewriter.resolve_ipv4 = rewriter.resolve_ipv4_orig
        cfdns.ensure_record = cfdns.ensure_record_orig

    def _url(self, path):
        return "http://127.0.0.1:%d%s" % (self.app_port, path)

    def _post(self, path, fields):
        data = urllib.parse.urlencode(fields).encode("utf-8")
        req = urllib.request.Request(self._url(path), data=data)
        with _opener().open(req, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8", "ignore")

    def _get(self, path):
        with _opener().open(self._url(path), timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8", "ignore")

    def test_full_flow(self):
        upstream_url = (
            "http://127.0.0.1:%d/sub.yaml" % self.upstream_port
        )
        # Save DNS binding; the token must never come back.
        status, _ = self._post("/api/dns/save", {
            "cf_token": TOKEN, "cf_zone": ZONE, "cf_record": RECORD,
        })
        self.assertEqual(status, 200)
        status, body = self._get("/api/status")
        info = json.loads(body)
        self.assertEqual(info["domain"], DOMAIN)
        self.assertTrue(info["dns_configured"])
        self.assertNotIn(TOKEN, body)
        status, body = self._get("/")
        self.assertEqual(status, 200)
        self.assertIn("域名绑定", body)
        self.assertIn(DOMAIN, body)
        self.assertNotIn(TOKEN, body)
        # DNS update before any measurement: no best IP yet.
        status, _ = self._post("/api/dns/update", {})
        self.assertEqual(status, 200)
        _s, body = self._get("/")
        self.assertIn("尚未测速", body)
        # Add subscription: CF node rewritten to the domain, SNI kept.
        status, _ = self._post("/api/subs/add", {
            "name": "demo", "url": upstream_url,
        })
        self.assertEqual(status, 200)
        status, body = self._get("/sub/demo")
        self.assertEqual(status, 200)
        self.assertIn("server: %s" % DOMAIN, body)
        self.assertIn("servername: cf.test.example", body)
        self.assertIn("server: other.test.example", body)
        # Manual run: measure + DNS update + rewrite.
        status, _ = self._post("/api/run", {})
        self.assertEqual(status, 200)
        deadline = time.time() + 90
        best = None
        while time.time() < deadline:
            _s, body = self._get("/api/status")
            info = json.loads(body)
            if not info["running"] and info["best_ip"]:
                best = info["best_ip"]
                break
            time.sleep(1)
        self.assertEqual(best, BEST_IP)
        self.assertEqual(info["dns_record_ip"], BEST_IP)
        self.assertEqual(info["dns_last_error"], "")
        self.assertIn((TOKEN, ZONE, RECORD, BEST_IP), self.dns_calls)
        self.assertNotIn(TOKEN, json.dumps(info))
        # Manual DNS update now succeeds (best IP known).
        status, _ = self._post("/api/dns/update", {})
        self.assertEqual(status, 200)
        _s, body = self._get("/")
        self.assertIn("已更新 DNS 记录", body)
        # Delete subscription.
        status, _ = self._post("/api/subs/delete", {"name": "demo"})
        self.assertEqual(status, 200)
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._get("/sub/demo")
        self.assertEqual(ctx.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
