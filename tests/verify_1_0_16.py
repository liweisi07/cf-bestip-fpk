#!/usr/bin/env python3
"""Live end-to-end verification for 1.0.16 (daily schedule + region pick).

Runs the real server (app/app.py) with a stub cfst that writes a
fixed multi-region result.csv, drives it with curl, and checks every
1.0.16 behaviour:

  A. settings page renders the new controls; region pick (HKG best,
     FRA fallback + log, all = global); invalid settings rejected
     with config unchanged; daily save works and next-run shows.
  B. interval mode regression: seeded old last_run + 6-minute
     interval fires on the scheduler's first tick; next-run display.
  C. daily mode: time set a few minutes ahead fires once on the
     scheduler tick; a manual run afterwards does not consume the
     daily run; the next tick does not run again.
  D. restart persistence: schedule mode/time, region and interval
     survive a restart.

Lives in tests/ (persistent, never packed into the fpk: the build
script only copies app/cmd/config/wizard/manifest and the icons).
Usage: python3 tests/verify_1_0_16.py
Exit code 0 means every check passed.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, "app", "app.py")
PORT = 18091
BASE = "http://127.0.0.1:%d" % PORT

# Multi-region stub result: global best is 104.16.0.1 (LAX, lowest
# latency); HKG best is 104.16.0.2; SIN best is 104.16.0.4; FRA has
# no rows (fallback case). 104.16.0.5 was never download-tested
# (empty region, speed 0) and must never win a pick.
STUB_CSV = (
    "IP 地址,已发送,已接收,丢包率,平均延迟,下载速度(MB/s),地区码\n"
    "104.16.0.1,4,4,0.00,10.0,30.0,LAX\n"
    "104.16.0.2,4,4,0.00,15.0,25.0,HKG\n"
    "104.16.0.3,4,4,0.00,25.0,40.0,HKG\n"
    "104.16.0.4,4,4,0.00,12.0,20.0,SIN\n"
    "104.16.0.5,4,4,0.00,5.0,0.0,\n"
)

FAILURES = []
PASSES = []


def check(name, cond, detail=""):
    if cond:
        PASSES.append(name)
        print("PASS: %s" % name, flush=True)
    else:
        FAILURES.append(name)
        print("FAIL: %s %s" % (name, detail), flush=True)


# Cookie jar for the login session (1.0.17+: the settings page and
# management APIs require a login; /sub/* stays public). Set by main()
# to a file inside the temp work dir before the first request.
COOKIE_JAR = None


def curl(method, path, fields=None):
    cmd = ["curl", "-s", "--noproxy", "*", "-m", "30", "-L"]
    if COOKIE_JAR:
        cmd += ["-c", COOKIE_JAR, "-b", COOKIE_JAR]
    if method == "POST":
        if fields:
            for key, value in fields.items():
                cmd += ["--data-urlencode", "%s=%s" % (key, value)]
        else:
            # Empty body still forces a real POST (without -d, curl
            # would send GET). -d also makes curl follow a 303 with
            # GET, which is how the ?msg= redirect renders. -X POST
            # would NOT switch to GET and the message would be lost.
            cmd += ["-d", ""]
    cmd.append(BASE + path)
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return out.stdout


def login():
    """Log in with the default admin/admin and keep the session in
    the cookie jar. Returns True when the settings page is reached."""
    curl("POST", "/login", {"username": "admin", "password": "admin",
                            "next": "/"})
    return "修改密码" in curl("GET", "/")


def read_config(data_dir):
    with open(os.path.join(data_dir, "config.json"),
              "r", encoding="utf-8") as fh:
        return json.load(fh)


def wait_for(pred, timeout, interval=5, what="condition"):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            got = pred()
        except Exception:
            got = None
        if got:
            return got
        time.sleep(interval)
    print("TIMEOUT waiting for: %s" % what, flush=True)
    return None


class Server:
    def __init__(self, data_dir, cfst_bin):
        self.data_dir = data_dir
        env = dict(os.environ)
        env["CFBESTIPD_DATA_DIR"] = data_dir
        env["CFBESTIPD_CFST_BIN"] = cfst_bin
        env["CFBESTIPD_PORT"] = str(PORT)
        log = open(os.path.join(data_dir, "server.log"), "ab")
        self.proc = subprocess.Popen(
            [sys.executable, APP], env=env, stdout=log,
            stderr=subprocess.STDOUT)
        self.log = log

    def wait_ready(self, timeout=90):
        def _up():
            try:
                return "CF优选IP" in curl("GET", "/")
            except Exception:
                return False
        return wait_for(_up, timeout, interval=2, what="server ready")

    def stop(self):
        # Exact PID only: never pkill, never match our own command line.
        self.proc.terminate()
        try:
            self.proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.log.close()


def seed_config(data_dir, values):
    with open(os.path.join(data_dir, "config.json"),
              "w", encoding="utf-8") as fh:
        json.dump(values, fh, ensure_ascii=False)


def snapshot(data_dir):
    cfg = read_config(data_dir)
    return {k: cfg.get(k) for k in (
        "last_run", "best_ip", "last_region", "last_region_fallback",
        "event_log")}


def wait_run_done(data_dir, prev_snapshot=None, expect_ip=None,
                  expect_region=None, expect_fallback=None, timeout=300):
    """Wait until a (new) run finished.

    A run is recognised by any change in the run-state fields
    (last_run / best_ip / last_region / fallback flag / event log)
    versus the pre-run snapshot, plus the job being idle and the
    expected pick matching. last_run alone is not enough: two fast
    runs can land in the same second and last_run would not move.
    """
    def _done():
        try:
            cfg = read_config(data_dir)
        except Exception:
            return None
        if expect_ip is not None and cfg.get("best_ip") != expect_ip:
            return None
        if expect_region is not None \
                and cfg.get("last_region") != expect_region:
            return None
        if expect_fallback is not None \
                and cfg.get("last_region_fallback") != expect_fallback:
            return None
        try:
            status = curl("GET", "/api/status")
            if '"running": true' in status or '"running":true' in status:
                return None
        except Exception:
            return None
        if prev_snapshot is None:
            return cfg
        changed = (
            cfg.get("last_run") != prev_snapshot.get("last_run")
            or cfg.get("best_ip") != prev_snapshot.get("best_ip")
            or cfg.get("last_region") != prev_snapshot.get("last_region")
            or cfg.get("last_region_fallback")
            != prev_snapshot.get("last_region_fallback")
            or cfg.get("event_log") != prev_snapshot.get("event_log")
        )
        return cfg if changed else None
    return wait_for(_done, timeout, interval=1, what="run to finish")


def main():
    global COOKIE_JAR
    work = tempfile.mkdtemp(prefix="cfbestipd-verify-1016-")
    COOKIE_JAR = os.path.join(work, "cookies.txt")
    cfst_bin = os.path.join(work, "fake-cfst.sh")
    with open(cfst_bin, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\n")
        fh.write("printf '%s\\n' \\\n")
        for line in STUB_CSV.splitlines():
            fh.write("'%s' \\\n" % line.replace("'", "'\\''"))
        fh.write("> result.csv\n")
    os.chmod(cfst_bin, 0o755)

    # ---- Phase A: region pick + settings validation ----------------
    data_a = os.path.join(work, "data-a")
    os.makedirs(data_a)
    srv = Server(data_a, cfst_bin)
    try:
        check("A0 server starts", bool(srv.wait_ready()),
              "(GET / did not return the settings page)")
        check("A0b login with default admin/admin", login(),
              "(settings page not reached after login)")
        page = curl("GET", "/")
        check("A1 page renders schedule controls",
              all(s in page for s in (
                  'name="schedule_mode"', 'value="daily"',
                  'name="schedule_time"', 'name="region"',
                  '<option value="HKG"', '香港 HKG',
                  'name="interval_days"', '测速计划', 'toggleMode')),
              "(missing mode/time/region controls)")
        # HKG pick.
        body = curl("POST", "/api/settings", {
            "schedule_mode": "interval", "interval_days": "7",
            "interval_hours": "0", "interval_minutes": "0",
            "region": "HKG"})
        check("A2 save region HKG", "测速间隔已保存为 7 天" in body,
              "(save message missing)")
        check("A2b config region HKG",
              read_config(data_a).get("region") == "HKG")
        snap = snapshot(data_a)
        curl("POST", "/api/run", {})
        cfg = wait_run_done(data_a, snap, expect_ip="104.16.0.2",
                            expect_region="HKG", expect_fallback=False)
        check("A3 HKG run picks HKG best",
              cfg is not None and cfg.get("best_ip") == "104.16.0.2",
              "(best_ip=%s)" % (cfg or {}).get("best_ip"))
        check("A3b HKG run stores region state",
              cfg is not None and cfg.get("last_region") == "HKG"
              and cfg.get("last_region_fallback") is False)
        check("A3c HKG run has no fallback log",
              cfg is not None
              and "未找到可用 IP" not in (cfg.get("event_log") or ""))
        page = curl("GET", "/")
        check("A3d results page shows HKG region",
              "优选地区：香港 HKG" in page
              and "104.16.0.1" not in page,
              "(LAX row leaked into the HKG results)")
        # FRA fallback.
        curl("POST", "/api/settings", {
            "schedule_mode": "interval", "interval_days": "7",
            "interval_hours": "0", "interval_minutes": "0",
            "region": "FRA"})
        snap = snapshot(data_a)
        curl("POST", "/api/run", {})
        cfg = wait_run_done(data_a, snap, expect_ip="104.16.0.1",
                            expect_region="FRA", expect_fallback=True)
        check("A4 FRA falls back to global best",
              cfg is not None and cfg.get("best_ip") == "104.16.0.1",
              "(best_ip=%s)" % (cfg or {}).get("best_ip"))
        check("A4b FRA fallback logged",
              cfg is not None
              and "区域 FRA 未找到可用 IP，已用全局最优"
              in (cfg.get("event_log") or ""))
        check("A4c FRA fallback stored",
              cfg is not None and cfg.get("last_region_fallback") is True)
        page = curl("GET", "/")
        check("A4d results page notes the fallback",
              "已退回全局最优" in page)
        # all = global.
        curl("POST", "/api/settings", {
            "schedule_mode": "interval", "interval_days": "7",
            "interval_hours": "0", "interval_minutes": "0",
            "region": "all"})
        snap = snapshot(data_a)
        curl("POST", "/api/run", {})
        cfg = wait_run_done(data_a, snap, expect_ip="104.16.0.1",
                            expect_region="all", expect_fallback=False)
        check("A5 region all = global best",
              cfg is not None and cfg.get("best_ip") == "104.16.0.1"
              and cfg.get("last_region_fallback") is False)
        # Invalid values rejected, config unchanged.
        before = read_config(data_a)
        body = curl("POST", "/api/settings", {
            "schedule_mode": "interval", "interval_days": "7",
            "interval_hours": "0", "interval_minutes": "0",
            "region": "XXX"})
        after = read_config(data_a)
        check("A6 invalid region rejected",
              "地区无效" in body and after.get("region") == "all",
              "(body=%s region=%s)" % (body[:120], after.get("region")))
        for bad_time in ("25:00", "24:60", "abc", "3:00"):
            body = curl("POST", "/api/settings", {
                "schedule_mode": "daily", "schedule_time": bad_time,
                "region": "all"})
            after = read_config(data_a)
            check("A6b invalid time %s rejected" % bad_time,
                  "时间无效" in body
                  and after.get("schedule_mode") == "interval",
                  "(schedule_mode=%s)" % after.get("schedule_mode"))
        body = curl("POST", "/api/settings", {
            "schedule_mode": "bogus", "region": "all"})
        after = read_config(data_a)
        check("A6c invalid mode rejected",
              "测速计划无效" in body
              and after.get("schedule_mode") == "interval")
        # Valid daily save + next-run display.
        body = curl("POST", "/api/settings", {
            "schedule_mode": "daily", "schedule_time": "03:00",
            "region": "all"})
        after = read_config(data_a)
        check("A7 daily save works",
              "测速计划已保存为每天 03:00" in body
              and after.get("schedule_mode") == "daily"
              and after.get("schedule_time") == "03:00")
        page = curl("GET", "/")
        now = time.localtime()
        today_0300 = time.mktime((now.tm_year, now.tm_mon, now.tm_mday,
                                  3, 0, 0, 0, 0, -1))
        if time.time() < today_0300:
            expect = time.strftime("%Y-%m-%d 03:00:00",
                                   time.localtime(today_0300))
        else:
            expect = time.strftime("%Y-%m-%d 03:00:00",
                                   time.localtime(today_0300 + 86400))
        check("A7b daily next-run display",
              ("下次测速：%s" % expect) in page,
              "(expected %s)" % expect)
    finally:
        srv.stop()

    # ---- Phase B: interval regression ------------------------------
    data_b = os.path.join(work, "data-b")
    os.makedirs(data_b)
    seeded_last = time.strftime(
        "%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 7 * 60))
    seed_config(data_b, {
        "schedule_mode": "interval", "interval_days": 0,
        "interval_hours": 0, "interval_minutes": 6,
        "last_run": seeded_last})
    srv = Server(data_b, cfst_bin)
    try:
        check("B0 server starts", bool(srv.wait_ready()))
        check("B0b login with default admin/admin", login(),
              "(settings page not reached after login)")
        cfg = wait_for(
            lambda: (lambda c: c if c.get("last_run") != seeded_last
                     else None)(read_config(data_b)),
            timeout=480, interval=10,
            what="interval scheduler to fire")
        check("B1 interval scheduler fires on first tick",
              cfg is not None and cfg.get("best_ip") == "104.16.0.1",
              "(best_ip=%s)" % (cfg or {}).get("best_ip"))
        if cfg:
            last_ts = time.mktime(time.strptime(
                cfg["last_run"], "%Y-%m-%d %H:%M:%S"))
            expect = time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(last_ts + 360))
            page = curl("GET", "/")
            check("B2 interval next-run display",
                  ("下次测速：%s" % expect) in page,
                  "(expected %s)" % expect)
    finally:
        srv.stop()

    # ---- Phase C: daily mode ---------------------------------------
    data_c = os.path.join(work, "data-c")
    os.makedirs(data_c)
    sched = time.localtime(time.time() + 2 * 60)
    sched_time = time.strftime("%H:%M", sched)
    today = time.strftime("%Y-%m-%d")
    seed_config(data_c, {
        "schedule_mode": "daily", "schedule_time": sched_time,
        "region": "all", "interval_days": 7, "interval_hours": 0,
        "interval_minutes": 0, "last_daily_run": None})
    srv = Server(data_c, cfst_bin)
    try:
        check("C0 server starts", bool(srv.wait_ready()))
        check("C0b login with default admin/admin", login(),
              "(settings page not reached after login)")
        cfg = wait_for(
            lambda: (lambda c: c if c.get("last_daily_run") == today
                     else None)(read_config(data_c)),
            timeout=480, interval=10,
            what="daily scheduler to fire")
        check("C1 daily scheduler fires at set time",
              cfg is not None and cfg.get("best_ip") == "104.16.0.1",
              "(last_daily_run=%s)" % (cfg or {}).get("last_daily_run"))
        if cfg:
            runs = (cfg.get("event_log") or "").count("测速完成")
            check("C2 daily runs exactly once",
                  runs == 1, "(测速完成 count=%d)" % runs)
            expect = time.strftime(
                "%Y-%m-%d " + sched_time + ":00",
                time.localtime(time.time() + 86400))
            page = curl("GET", "/")
            check("C3 daily next-run is tomorrow",
                  ("下次测速：%s" % expect) in page,
                  "(expected %s)" % expect)
            # Manual run must not consume the daily run.
            snap = snapshot(data_c)
            curl("POST", "/api/run", {})
            cfg2 = wait_run_done(data_c, snap, expect_ip="104.16.0.1",
                                 expect_region="all",
                                 expect_fallback=False)
            check("C4 manual run finishes",
                  cfg2 is not None and cfg2.get("best_ip") == "104.16.0.1")
            cfg2 = read_config(data_c)
            check("C4b manual run keeps daily marker",
                  cfg2.get("last_daily_run") == today)
            manual_last = cfg2.get("last_run")
            # The event log holds only the latest run's lines (each
            # run replaces it), so after the manual run it shows
            # exactly one 测速完成: the manual run's own entry.
            runs = (cfg2.get("event_log") or "").count("测速完成")
            check("C4c manual run logged", runs == 1,
                  "(测速完成 count=%d)" % runs)
            # Next scheduler tick must not run again today.
            time.sleep(360)
            cfg3 = read_config(data_c)
            check("C5 no second daily run on next tick",
                  cfg3.get("last_run") == manual_last
                  and cfg3.get("last_daily_run") == today,
                  "(last_run moved to %s)" % cfg3.get("last_run"))
    finally:
        srv.stop()

    # ---- Phase D: restart persistence ------------------------------
    srv = Server(data_c, cfst_bin)
    try:
        check("D0 server restarts", bool(srv.wait_ready()))
        check("D0b login with default admin/admin", login(),
              "(settings page not reached after login)")
        cfg = read_config(data_c)
        check("D1 config persists after restart",
              cfg.get("schedule_mode") == "daily"
              and cfg.get("schedule_time") == sched_time
              and cfg.get("region") == "all"
              and cfg.get("interval_days") == 7,
              "(cfg=%s)" % {k: cfg.get(k) for k in (
                  "schedule_mode", "schedule_time", "region",
                  "interval_days")})
        page = curl("GET", "/")
        check("D2 page shows persisted settings",
              'value="daily" checked' in page
              and ('value="%s"' % sched_time) in page
              and 'value="all" selected' in page
              and 'value="7"' in page)
    finally:
        srv.stop()

    print("\n%d passed, %d failed" % (len(PASSES), len(FAILURES)),
          flush=True)
    if FAILURES:
        print("FAILED: %s" % ", ".join(FAILURES), flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
