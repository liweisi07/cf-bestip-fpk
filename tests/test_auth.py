"""Login tests for the domain edition (app/app.py).

Covers: default admin/admin account, salted-hash verification,
session create/validate/expire, the HTTP login flow (unauthenticated
redirect, wrong/right password, change password, logout), and the
subscription links (/sub/<name>) staying public without a login
(proxy clients fetch them on their own and cannot log in).
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
from http.server import ThreadingHTTPServer

TMP = tempfile.mkdtemp(prefix="cfbestipd-auth-test-")
os.environ["CFBESTIPD_DATA_DIR"] = TMP

APP_DIR = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, APP_DIR)

import app  # noqa: E402


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _opener(jar=None):
    handlers = [urllib.request.ProxyHandler({}), _NoRedirect()]
    if jar is not None:
        handlers.append(urllib.request.HTTPCookieProcessor(jar))
    return urllib.request.build_opener(*handlers)


class AuthUnitTest(unittest.TestCase):
    def setUp(self):
        app.load_config()
        app.load_sessions()
        # Start from a clean account/sessions slate.
        app._config["auth"] = app._new_auth("admin", "admin")
        with app._sessions_lock:
            app._sessions.clear()

    def test_hash_and_verify(self):
        self.assertTrue(app.verify_login("admin", "admin"))
        self.assertFalse(app.verify_login("admin", "wrong"))
        self.assertFalse(app.verify_login("someone", "admin"))
        self.assertFalse(app.verify_login("admin", ""))
        # The stored value is a hash, never the plain password.
        auth = app.get_auth()
        self.assertNotIn("admin", auth["password_hash"])
        self.assertEqual(len(auth["salt"]), 32)

    def test_set_auth_changes_password(self):
        app.set_auth("admin", "newpass1")
        self.assertFalse(app.verify_login("admin", "admin"))
        self.assertTrue(app.verify_login("admin", "newpass1"))

    def test_session_create_validate_expire(self):
        token = app.create_session("admin")
        self.assertEqual(app.validate_session(token), "admin")
        self.assertIsNone(app.validate_session("no-such-token"))
        # Expired token is rejected and removed.
        with app._sessions_lock:
            app._sessions[token]["expires"] = int(time.time()) - 1
        self.assertIsNone(app.validate_session(token))
        with app._sessions_lock:
            self.assertNotIn(token, app._sessions)

    def test_destroy_other_sessions_keeps_current(self):
        keep = app.create_session("admin")
        other = app.create_session("admin")
        app.destroy_other_sessions(keep)
        self.assertEqual(app.validate_session(keep), "admin")
        self.assertIsNone(app.validate_session(other))

    def test_get_auth_falls_back_to_default(self):
        app._config["auth"] = None
        auth = app.get_auth()
        self.assertEqual(auth["username"], "admin")
        self.assertTrue(app.verify_login("admin", "admin"))


class AuthHttpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.load_config()
        app.load_sessions()
        app._config["auth"] = app._new_auth("admin", "admin")
        with app._sessions_lock:
            app._sessions.clear()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        cls.server.daemon_threads = True
        threading.Thread(
            target=cls.server.serve_forever, daemon=True).start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        # Fresh cookie jar per test; reset the account to admin/admin.
        self.jar = http.cookiejar.CookieJar()
        self.op = _opener(self.jar)
        app._config["auth"] = app._new_auth("admin", "admin")
        with app._sessions_lock:
            app._sessions.clear()
        app.save_config()
        app.save_sessions()

    def _url(self, path):
        return "http://127.0.0.1:%d%s" % (self.port, path)

    def _req(self, method, path, data=None, opener=None):
        req = urllib.request.Request(self._url(path), data=data,
                                     method=method)
        try:
            with (opener or self.op).open(req, timeout=10) as resp:
                return resp.status, dict(resp.headers), resp.read().decode(
                    "utf-8", "ignore")
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read().decode(
                "utf-8", "ignore")

    def _post(self, path, fields, opener=None):
        data = urllib.parse.urlencode(fields).encode("utf-8")
        return self._req("POST", path, data=data, opener=opener)

    def _login(self, password="admin", username="admin"):
        return self._post("/login", {"username": username,
                                     "password": password, "next": "/"})

    def test_unauthenticated_redirects(self):
        status, headers, _ = self._req("GET", "/")
        self.assertEqual(status, 303)
        self.assertTrue(headers["Location"].startswith("/login"))
        status, _, body = self._req("GET", "/api/status")
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body)["error"], "未登录")
        status, _, _ = self._req("GET", "/progress")
        self.assertEqual(status, 303)

    def test_login_page_renders(self):
        status, _, body = self._req("GET", "/login")
        self.assertEqual(status, 200)
        self.assertIn('name="username"', body)
        self.assertIn('name="password"', body)

    def test_login_wrong_password(self):
        status, headers, _ = self._login(password="wrong")
        self.assertEqual(status, 303)
        self.assertIn("/login", headers["Location"])
        self.assertIn("msg=", headers["Location"])

    def test_login_default_and_settings_page(self):
        status, headers, _ = self._login()
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/")
        self.assertIn("cfbestipd_session=",
                      headers.get("Set-Cookie", ""))
        self.assertIn("HttpOnly", headers.get("Set-Cookie", ""))
        status, _, body = self._req("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("修改密码", body)
        self.assertIn("退出登录", body)
        status, _, body = self._req("GET", "/api/status")
        self.assertEqual(status, 200)
        self.assertIn("best_ip", json.loads(body))

    def test_change_password_flow(self):
        self._login()
        # Wrong current password.
        status, headers, _ = self._post("/api/password", {
            "current_password": "nope", "new_password": "newpass1",
            "confirm_password": "newpass1"})
        self.assertEqual(status, 303)
        _, _, body = self._req("GET", headers["Location"])
        self.assertIn("当前密码不对", body)
        # Mismatched confirmation.
        status, headers, _ = self._post("/api/password", {
            "current_password": "admin", "new_password": "newpass1",
            "confirm_password": "other"})
        _, _, body = self._req("GET", headers["Location"])
        self.assertIn("两次输入的新密码不一致", body)
        # Too short.
        status, headers, _ = self._post("/api/password", {
            "current_password": "admin", "new_password": "ab",
            "confirm_password": "ab"})
        _, _, body = self._req("GET", headers["Location"])
        self.assertIn("新密码至少", body)
        # Success: old password stops working, new one logs in.
        status, headers, _ = self._post("/api/password", {
            "current_password": "admin", "new_password": "newpass1",
            "confirm_password": "newpass1"})
        _, _, body = self._req("GET", headers["Location"])
        self.assertIn("密码已修改", body)
        fresh = _opener(http.cookiejar.CookieJar())
        status, headers, _ = self._post(
            "/login", {"username": "admin", "password": "admin",
                       "next": "/"}, opener=fresh)
        self.assertIn("/login", headers["Location"])
        status, headers, _ = self._post(
            "/login", {"username": "admin", "password": "newpass1",
                       "next": "/"}, opener=fresh)
        self.assertEqual(headers["Location"], "/")

    def test_logout(self):
        self._login()
        status, _, body = self._req("GET", "/")
        self.assertEqual(status, 200)
        status, headers, _ = self._post("/api/logout", {})
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/login")
        status, headers, _ = self._req("GET", "/")
        self.assertEqual(status, 303)
        self.assertTrue(headers["Location"].startswith("/login"))

    def test_sub_stays_public(self):
        # Add a subscription while logged in, then fetch it with a
        # fresh opener that has no session cookie: it must not be
        # redirected to /login (proxy clients cannot log in).
        self._login()
        self._post("/api/subs/add", {
            "name": "demo", "url": "http://127.0.0.1:9/x.yaml"})
        plain = _opener()
        req = urllib.request.Request(self._url("/sub/demo"))
        try:
            with plain.open(req, timeout=10) as resp:
                status = resp.status
        except urllib.error.HTTPError as exc:
            status = exc.code
        # 502 (upstream unreachable) or 200 both prove no login wall;
        # only a 303 to /login would mean the link is gated.
        self.assertIn(status, (200, 404, 502))


if __name__ == "__main__":
    unittest.main()
