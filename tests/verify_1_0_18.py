#!/usr/bin/env python3
"""Live end-to-end checks for cf-bestipd 1.0.18 (run against a real
server started on a throwaway data dir).

Checks:
  A. Login wall + default admin/admin login.
  B. Settings button (top-right) renders with the account form,
     including the new-username field; no bottom #password card.
  C. Change username only -> old name stops working, new name + old
     password logs in; current browser stays logged in.
  D. Change both username and password -> new credentials log in.
  E. Change password only (old flow) still works.
  F. /sub/<name> stays public (no login needed).
  G. wizard/install pre-fills service port 18089 and interval 7.
"""
import http.cookiejar
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
APP = os.path.join(ROOT, "app", "app.py")
PORT = 18093

PASS = 0
FAIL = 0


def check(name, ok, extra=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print("PASS: %s" % name)
    else:
        FAIL += 1
        print("FAIL: %s %s" % (name, extra))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def opener(jar=None):
    return urllib.request.build_opener(
        _NoRedirect(),
        urllib.request.HTTPCookieProcessor(jar or http.cookiejar.CookieJar()))


def req(op, method, path, data=None):
    url = "http://127.0.0.1:%d%s" % (PORT, path)
    r = urllib.request.Request(url, method=method)
    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode()
        r.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with op.open(r, data=body, timeout=10) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace")


def wait_up(op, tries=30):
    for _ in range(tries):
        try:
            status, _, _ = req(op, "GET", "/login")
            if status in (200, 303):
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def login(op, user, pw):
    status, headers, _ = req(op, "POST", "/login",
                             {"username": user, "password": pw, "next": "/"})
    return headers.get("Location", "")


def main():
    tmp = tempfile.mkdtemp(prefix="cfbestipd-verify-1018-")
    env = dict(os.environ)
    env["CFBESTIPD_DATA_DIR"] = tmp
    env["CFBESTIPD_PORT"] = str(PORT)
    env.pop("http_proxy", None)
    env.pop("https_proxy", None)
    env.pop("HTTP_PROXY", None)
    env.pop("HTTPS_PROXY", None)
    # Fake cfst so no real measurement happens.
    fake = os.path.join(tmp, "fake-cfst.sh")
    with open(fake, "w") as fh:
        fh.write("#!/bin/sh\n"
                 "echo '104.16.0.1,150,44.7,0,0,SJC'\n")
    os.chmod(fake, 0o755)
    env["CFBESTIPD_CFST_BIN"] = fake
    log = open(os.path.join(tmp, "server.log"), "w")
    proc = subprocess.Popen(
        [sys.executable, APP], env=env,
        stdout=log, stderr=subprocess.STDOUT)
    try:
        op = opener()
        check("A0 server starts", wait_up(op))
        status, headers, _ = req(op, "GET", "/")
        check("A1 / redirects to login when logged out",
              status == 303 and headers.get("Location", "").startswith("/login"))
        check("A2 default admin/admin logs in",
              login(op, "admin", "admin") == "/")
        status, _, body = req(op, "GET", "/")
        check("B1 settings button renders in header",
              status == 200 and "⚙ 设置" in body)
        check("B2 account form has new-username field",
              'name="new_username"' in body)
        check("B3 account form titled 账号设置", "账号设置" in body)
        check("B4 no bottom #password card", 'id="password"' not in body)

        # C: username only.
        status, headers, _ = req(op, "POST", "/api/password", {
            "current_password": "admin", "new_username": "kele",
            "new_password": "", "confirm_password": ""})
        _, _, body2 = req(op, "GET", headers.get("Location", "/"))
        check("C1 username-only change accepted", "账号已修改" in body2)
        status, _, body = req(op, "GET", "/")
        check("C2 current browser stays logged in after rename",
              status == 200)
        fresh = opener(http.cookiejar.CookieJar())
        check("C3 old username stops working",
              "/login" in login(fresh, "admin", "admin"))
        check("C4 new username + old password logs in",
              login(fresh, "kele", "admin") == "/")

        # D: both username and password.
        status, headers, _ = req(op, "POST", "/api/password", {
            "current_password": "admin", "new_username": "boss",
            "new_password": "newpass9", "confirm_password": "newpass9"})
        _, _, body2 = req(op, "GET", headers.get("Location", "/"))
        check("D1 username+password change accepted",
              "账号和密码已修改" in body2)
        fresh2 = opener(http.cookiejar.CookieJar())
        check("D2 new credentials log in",
              login(fresh2, "boss", "newpass9") == "/")

        # E: password only (old flow).
        status, headers, _ = req(op, "POST", "/api/password", {
            "current_password": "newpass9", "new_username": "",
            "new_password": "newpass8", "confirm_password": "newpass8"})
        _, _, body2 = req(op, "GET", headers.get("Location", "/"))
        check("E1 password-only change accepted", "密码已修改" in body2)
        fresh3 = opener(http.cookiejar.CookieJar())
        check("E2 new password logs in",
              login(fresh3, "boss", "newpass8") == "/")

        # F: /sub stays public (no login redirect). The upstream
        # http://127.0.0.1:9 is unreachable, so on-demand generation
        # returns 502 — that still proves it is public, not a 303 to
        # /login.
        req(op, "POST", "/api/subs/add", {
            "name": "demo", "url": "http://127.0.0.1:9/x.yaml"})
        plain = opener()
        status, headers, _ = req(plain, "GET", "/sub/demo")
        check("F1 /sub/demo public without login",
              status in (200, 502)
              and not headers.get("Location", "").startswith("/login"),
              "status=%s" % status)

        # G: wizard defaults.
        wiz = json.load(open(os.path.join(ROOT, "wizard", "install")))
        items = {i["field"]: i for i in wiz[0]["items"]}
        check("G1 wizard port pre-filled 18089",
              items.get("wizard_port", {}).get("initValue") == "18089")
        check("G2 wizard interval pre-filled 7",
              items.get("wizard_interval_days", {}).get("initValue") == "7")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        shutil.rmtree(tmp, ignore_errors=True)
    print("\n%d passed, %d failed" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
