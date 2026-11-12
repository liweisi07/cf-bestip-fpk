#!/usr/bin/env python3
"""cf-bestipd: FnOS native app, domain edition.

Same idea as the IP edition, but the best Cloudflare IP is not written
into the subscription. Instead:

  1. You add Sub-Store download links (mihomo/ClashMeta YAML) on the
     built-in settings page (LAN only).
  2. You bind one of your own domain names to the app: a Cloudflare
     API token, the zone (apex domain) and a record prefix. The app
     keeps that record (DNS-only, never proxied) pointed at the
     currently best Cloudflare IP.
  3. On a schedule (default once a week) it runs CloudflareSpeedTest
     to find the best IP, updates the DNS record to it, and serves
     each subscription with its Cloudflare nodes' server rewritten to
     your domain name (a fixed value).
  4. Clients keep using the same app link. When the best IP changes,
     clients do NOT need to re-download the subscription: they just
     re-resolve the domain (TTL 60 seconds) and reach the new IP.

Notes:
  * Sub-Store itself is NOT modified: its own subscription links keep
    working unchanged. This app only post-processes what Sub-Store
    produces, because the Cloudflare Workers build of Sub-Store cannot
    rewrite node addresses itself (script operators are disabled there).
  * The DNS record MUST stay DNS-only (gray cloud). A proxied record
    would resolve to Cloudflare's anycast IPs and the preferred IP
    would be lost; the app writes proxied=false and refuses to accept
    a proxied record on read-back.
  * SNI is preserved exactly like in the IP edition: a node's existing
    servername/sni is kept, an empty one is filled with the original
    domain, and a TLS node without one gets servername=original domain
    inserted. Without this, changing the address would break TLS.
  * The API token is stored only in this app's local config file on
    the NAS. It is never shown on any page, never appears in logs or
    in the status API, and is only sent to api.cloudflare.com.
  * Keep the app on your LAN; do not expose its port to the internet
    and do not share its links. Only Python's standard library is used.
"""

import hashlib
import hmac
import html
import json
import os
import re
import secrets
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cfst as cfst_mod
import cfdns
import rewriter

VERSION = "1.0.18"
APP_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PORT = 18089
DEFAULT_INTERVAL_DAYS = 7
DEFAULT_INTERVAL_HOURS = 0
DEFAULT_INTERVAL_MINUTES = 0
# Total interval bounds: the scheduler only checks every 5 minutes,
# so anything shorter is meaningless; 30 days is the old ceiling.
MIN_INTERVAL_SECONDS = 5 * 60
MAX_INTERVAL_SECONDS = 30 * 86400
DEFAULT_SCHEDULE_MODE = "interval"
DEFAULT_SCHEDULE_TIME = "03:00"
DEFAULT_REGION = "all"
# Login: settings page and management APIs require a session; the
# subscription links (/sub/<name>) stay public because proxy clients
# fetch them on their own and cannot log in. Default admin/admin.
SESSION_COOKIE = "cfbestipd_session"
SESSION_TTL = 30 * 24 * 3600  # 会话有效期 30 天
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "admin"
MIN_PASSWORD_LEN = 4
# Region options for the settings page: (IATA colo code, label).
# The code is the value cfst writes into result.csv's region column
# (from the download response's cf-ray header). These are the
# Cloudflare colos a China home broadband line can usually reach.
REGION_OPTIONS = (
    ("all", "全部（自动）"),
    ("HKG", "香港 HKG"),
    ("SIN", "新加坡 SIN"),
    ("NRT", "东京 NRT"),
    ("ICN", "首尔 ICN"),
    ("LAX", "洛杉矶 LAX"),
    ("SJC", "圣何塞 SJC"),
    ("FRA", "法兰克福 FRA"),
)
MAX_UPSTREAM_BYTES = 10 * 1024 * 1024

CFST_PINNED_URLS = [
    "https://github.com/XIU2/CloudflareSpeedTest/releases/download/"
    "v2.3.5/cfst_linux_arm64.tar.gz",
]
CFST_API_LATEST = (
    "https://api.github.com/repos/XIU2/CloudflareSpeedTest/releases/latest"
)

NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

# The app must never route its own fetches through a proxy: a proxy in the
# path would corrupt measurements and can break localhost/upstream fetches
# entirely when proxy variables happen to be set on the NAS.
_NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


# --------------------------------------------------------------------------
# Paths / environment
# --------------------------------------------------------------------------

def resolve_data_dir():
    for key in ("CFBESTIPD_DATA_DIR", "TRIM_PKGVAR"):
        value = os.environ.get(key)
        if value:
            return value
    return os.path.join(APP_DIR, "data")


DATA_DIR = resolve_data_dir()
CONFIG_PATH = os.path.join(DATA_DIR, "config.json")
SESSIONS_PATH = os.path.join(DATA_DIR, "sessions.json")
OUTPUTS_DIR = os.path.join(DATA_DIR, "outputs")
CFST_WORKDIR = os.path.join(DATA_DIR, "cfst")
CFST_BIN_DIR = os.path.join(DATA_DIR, "cfst-bin")


def resolve_port():
    for key in ("CFBESTIPD_PORT", "wizard_port", "TRIM_SERVICE_PORT"):
        value = os.environ.get(key)
        if value:
            try:
                port = int(value)
            except (TypeError, ValueError):
                continue
            if 1 <= port <= 65535:
                return port
    return DEFAULT_PORT


def bundled_cf_ranges_path():
    return os.path.join(APP_DIR, "cf_ranges.txt")


def data_cf_ranges_path():
    return os.path.join(DATA_DIR, "cf_ranges.txt")


# --------------------------------------------------------------------------
# Config / state
# --------------------------------------------------------------------------

_config_lock = threading.Lock()
_config = {
    "subscriptions": [],
    "interval_days": DEFAULT_INTERVAL_DAYS,
    "interval_hours": DEFAULT_INTERVAL_HOURS,
    "interval_minutes": DEFAULT_INTERVAL_MINUTES,
    "schedule_mode": DEFAULT_SCHEDULE_MODE,
    "schedule_time": DEFAULT_SCHEDULE_TIME,
    "region": DEFAULT_REGION,
    "last_daily_run": None,
    "last_region": None,
    "last_region_fallback": False,
    "best_ip": None,
    "last_run": None,
    "last_log": "",
    "event_log": "",
    "last_results": [],
    "last_result_count": 0,
    "cf_ranges_updated": None,
    # Domain binding (domain edition). The token is only ever stored in
    # this local config file; no page or API response ever echoes it.
    "cf_token": "",
    "cf_zone": "",
    "cf_record": "cf",
    "dns_record_ip": None,
    "dns_last_update": None,
    "dns_last_error": "",
    "cf_binding_saved": None,
}
_networks = rewriter.default_cf_networks()
_job_lock = threading.Lock()
_job_running = False
_job_stage = ""
_job_started = 0.0


def _atomic_write(path, data_bytes):
    tmp = path + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(data_bytes)
    os.replace(tmp, path)


def _interval_parts(cfg):
    """(days, hours, minutes) as ints, tolerating old/missing config.

    Old config files only carry interval_days; missing hour/minute
    keys fall back to 0, so an upgrade keeps the previous interval.
    """
    def _as_int(value, default):
        try:
            return int(value)
        except (TypeError, ValueError):
            return default
    days = _as_int(cfg.get("interval_days"), DEFAULT_INTERVAL_DAYS)
    hours = _as_int(cfg.get("interval_hours"), DEFAULT_INTERVAL_HOURS)
    minutes = _as_int(cfg.get("interval_minutes"), DEFAULT_INTERVAL_MINUTES)
    return (
        max(0, min(30, days)),
        max(0, min(23, hours)),
        max(0, min(59, minutes)),
    )


def interval_seconds(cfg):
    """Total measurement interval in seconds from days/hours/minutes."""
    days, hours, minutes = _interval_parts(cfg)
    return days * 86400 + hours * 3600 + minutes * 60


def _fmt_interval(days, hours, minutes):
    parts = []
    if days:
        parts.append("%d 天" % days)
    if hours:
        parts.append("%d 小时" % hours)
    if minutes:
        parts.append("%d 分钟" % minutes)
    return " ".join(parts) if parts else "0 分钟"


def _schedule_mode(cfg):
    """'interval' or 'daily'; old configs default to interval."""
    mode = str(cfg.get("schedule_mode") or "").strip().lower()
    return mode if mode in ("interval", "daily") else DEFAULT_SCHEDULE_MODE


def _schedule_time(cfg):
    """(hour, minute) from the "HH:MM" setting; garbage -> 03:00."""
    value = str(cfg.get("schedule_time") or "").strip()
    match = re.match(r"^(\d{1,2}):(\d{2})$", value)
    if not match:
        return (3, 0)
    hour, minute = int(match.group(1)), int(match.group(2))
    if 0 <= hour <= 23 and 0 <= minute <= 59:
        return (hour, minute)
    return (3, 0)


def _fmt_schedule_time(hour, minute):
    return "%02d:%02d" % (hour, minute)


def next_daily_run(cfg, now=None):
    """Next daily run as local time: today at HH:MM, else tomorrow."""
    if now is None:
        now = time.time()
    hour, minute = _schedule_time(cfg)
    today = time.localtime(now)
    target = time.mktime((today.tm_year, today.tm_mon, today.tm_mday,
                          hour, minute, 0, 0, 0, -1))
    if target <= now:
        target += 86400
    return time.localtime(target)


def next_run_text(cfg):
    """'下次测速' line for both schedule modes."""
    if _schedule_mode(cfg) == "daily":
        return time.strftime("%Y-%m-%d %H:%M:%S", next_daily_run(cfg))
    last = cfg.get("last_run")
    if not last:
        return "—"
    try:
        last_ts = time.mktime(
            time.strptime(last, "%Y-%m-%d %H:%M:%S"))
    except (ValueError, TypeError):
        return "—"
    return time.strftime(
        "%Y-%m-%d %H:%M:%S",
        time.localtime(last_ts + interval_seconds(cfg)),
    )


def _region(cfg):
    """Region code in effect: 'all' or an IATA colo code."""
    return _normalize_region(cfg.get("region")) or DEFAULT_REGION


def _normalize_region(value):
    """Canonical region code for `value`, or None when invalid.

    Compares case-insensitively so the form value "all" and the
    stored code "HKG" both resolve to the canonical spelling in
    REGION_OPTIONS ("all" stays lowercase, IATA codes uppercase).
    A plain upper() + membership check would reject "all": the
    option list spells it lowercase while the codes are uppercase.
    """
    text = str(value or "").strip()
    for option_code, _ in REGION_OPTIONS:
        if option_code.lower() == text.lower():
            return option_code
    return None


def _region_label(code):
    for option_code, label in REGION_OPTIONS:
        if option_code == code:
            return label
    return code or "全部（自动）"


def load_config():
    global _config
    existed = os.path.isfile(CONFIG_PATH)
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            with _config_lock:
                _config.update(data)
                if not isinstance(_config.get("subscriptions"), list):
                    _config["subscriptions"] = []
                # Normalize the interval: old files carry only
                # interval_days, and a hand-edited file may hold
                # garbage. Never let a loaded interval fall below
                # the 5-minute scheduler step or above 30 days.
                days, hours, minutes = _interval_parts(_config)
                total = days * 86400 + hours * 3600 + minutes * 60
                if total < MIN_INTERVAL_SECONDS:
                    days, hours, minutes = (
                        DEFAULT_INTERVAL_DAYS,
                        DEFAULT_INTERVAL_HOURS,
                        DEFAULT_INTERVAL_MINUTES,
                    )
                elif total > MAX_INTERVAL_SECONDS:
                    days, hours, minutes = 30, 0, 0
                _config["interval_days"] = days
                _config["interval_hours"] = hours
                _config["interval_minutes"] = minutes
                # Schedule mode/time and region: old files carry
                # neither; a hand-edited file may hold garbage.
                _config["schedule_mode"] = _schedule_mode(_config)
                hour, minute = _schedule_time(_config)
                _config["schedule_time"] = _fmt_schedule_time(hour, minute)
                _config["region"] = _region(_config)
                daily = _config.get("last_daily_run")
                if daily is not None and not re.match(
                        r"^\d{4}-\d{2}-\d{2}$", str(daily)):
                    _config["last_daily_run"] = None
    except (OSError, ValueError):
        pass
    if not _config.get("event_log") and _config.get("last_log"):
        # One-time migration: older versions kept only one log, which
        # could hold live tool lines from an interrupted run. Keep only
        # the known summary prefixes so the concise event log never
        # shows tool detail.
        _config["event_log"] = "\n".join([
            line for line in _config["last_log"].splitlines()
            if line.startswith(("IP 段：", "测速完成", "DNS：", "订阅 ", "失败："))
        ][-20:])
    if not existed:
        # First run: seed the interval from the install wizard, if valid.
        # Later changes are made on the settings page itself.
        try:
            days = int(os.environ.get("wizard_interval_days") or 0)
        except (TypeError, ValueError):
            days = 0
        if 1 <= days <= 30:
            with _config_lock:
                _config["interval_days"] = days
    # First run or upgrade from a version without login: create the
    # default admin/admin account and save it.
    _ensure_auth()


def save_config():
    with _config_lock:
        payload = json.dumps(_config, ensure_ascii=False, indent=2)
    _atomic_write(CONFIG_PATH, payload.encode("utf-8"))


# --------------------------------------------------------------------------
# Login (password hashed with salt in config.json; session token in
# sessions.json). Forgot password: delete the "auth" section from
# config.json and restart the app to restore the default admin/admin.
# --------------------------------------------------------------------------

_sessions_lock = threading.Lock()
_sessions = {}  # token -> {"username": str, "expires": int}


def _hash_password(password, salt):
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()


def _new_auth(username, password):
    salt = secrets.token_hex(16)
    return {"username": username, "salt": salt,
            "password_hash": _hash_password(password, salt)}


def _valid_auth(auth):
    return (isinstance(auth, dict)
            and isinstance(auth.get("username"), str)
            and bool(auth["username"])
            and isinstance(auth.get("salt"), str)
            and bool(auth["salt"])
            and isinstance(auth.get("password_hash"), str)
            and bool(auth["password_hash"]))


def get_auth():
    """Current account; falls back to the default admin/admin in memory
    when nothing valid is stored (fresh install or auth deleted)."""
    with _config_lock:
        auth = _config.get("auth")
    if _valid_auth(auth):
        return auth
    return _new_auth(DEFAULT_USERNAME, DEFAULT_PASSWORD)


def _ensure_auth():
    """Make sure _config holds a valid account, creating the default
    admin/admin and saving it when it does not."""
    with _config_lock:
        dirty = not _valid_auth(_config.get("auth"))
        if dirty:
            _config["auth"] = _new_auth(DEFAULT_USERNAME, DEFAULT_PASSWORD)
    if dirty:
        save_config()


def verify_login(username, password):
    """Compare account and password (hash comparison, timing-safe)."""
    if not isinstance(username, str) or not isinstance(password, str):
        return False
    auth = get_auth()
    if username != auth["username"]:
        return False
    expect = _hash_password(password, auth["salt"])
    return hmac.compare_digest(expect, auth["password_hash"])


def set_auth(username, password):
    """Change the account/password: only the config's auth section
    moves; subscriptions, best IP and DNS binding are untouched."""
    with _config_lock:
        _config["auth"] = _new_auth(username, password)
    save_config()


def load_sessions():
    global _sessions
    try:
        with open(SESSIONS_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            now = int(time.time())
            with _sessions_lock:
                _sessions = {t: v for t, v in data.items()
                             if isinstance(v, dict)
                             and isinstance(v.get("expires"), int)
                             and v["expires"] > now
                             and isinstance(v.get("username"), str)}
    except (OSError, ValueError):
        pass


def save_sessions():
    with _sessions_lock:
        payload = json.dumps(_sessions, ensure_ascii=False, indent=2)
    _atomic_write(SESSIONS_PATH, payload.encode("utf-8"))


def create_session(username):
    token = secrets.token_hex(32)
    with _sessions_lock:
        _sessions[token] = {"username": username,
                            "expires": int(time.time()) + SESSION_TTL}
    save_sessions()
    return token


def validate_session(token):
    """Return the account name for a valid session, else None (an
    expired token is removed as a side effect)."""
    if not token:
        return None
    expired = False
    with _sessions_lock:
        sess = _sessions.get(token)
        if not sess:
            return None
        if sess.get("expires", 0) <= int(time.time()):
            del _sessions[token]
            expired = True
        else:
            return sess.get("username")
    if expired:
        save_sessions()
    return None


def destroy_session(token):
    if not token:
        return
    with _sessions_lock:
        gone = _sessions.pop(token, None) is not None
    if gone:
        save_sessions()


def destroy_other_sessions(keep_token):
    """After a password change, keep only the current session; other
    devices/browsers must log in again."""
    with _sessions_lock:
        others = [t for t in _sessions if t != keep_token]
        for t in others:
            del _sessions[t]
    if others:
        save_sessions()


def record_event(line):
    """Append one concise line to the settings page's event log.

    The event log is what 最近日志 shows: short summaries only, never
    the measurement tool's live detail lines (those live on /progress).
    """
    with _config_lock:
        lines = [ln for ln in (_config.get("event_log") or "").splitlines()
                 if ln]
        lines.append(line)
        _config["event_log"] = "\n".join(lines[-20:])
    save_config()


def get_config_copy():
    with _config_lock:
        return json.loads(json.dumps(_config, ensure_ascii=False))


def full_domain(cfg=None):
    """The bound domain, e.g. cf.example.com, or '' when unconfigured."""
    cfg = cfg if cfg is not None else get_config_copy()
    zone = (cfg.get("cf_zone") or "").strip().strip(".")
    if not zone:
        return ""
    return cfdns.full_record_name(zone, cfg.get("cf_record") or "")


def dns_configured(cfg=None):
    """True when token + zone + record are all filled in."""
    cfg = cfg if cfg is not None else get_config_copy()
    return bool(
        (cfg.get("cf_token") or "").strip()
        and (cfg.get("cf_zone") or "").strip()
        and full_domain(cfg)
    )


def update_dns_now(best_ip):
    """Point the bound record at best_ip. Returns a status message.

    Updates the stored DNS state (record IP / last update / last error)
    and saves the config. Raises nothing: failures are reported as a
    message and stored, because a stale record IP still works (it is a
    valid Cloudflare IP, just possibly not the newest best one).
    """
    cfg = get_config_copy()
    if not dns_configured(cfg):
        msg = ("未更新 DNS：请先在下方“域名绑定”里填好 API 令牌、域名和"
               "记录名")
        with _config_lock:
            _config["dns_last_error"] = msg
        save_config()
        return msg
    try:
        record_ip, _ttl, msg = cfdns.ensure_record(
            cfg["cf_token"].strip(),
            cfg["cf_zone"].strip(),
            cfg.get("cf_record") or "",
            best_ip,
        )
        with _config_lock:
            _config["dns_record_ip"] = record_ip
            _config["dns_last_update"] = time.strftime("%Y-%m-%d %H:%M:%S")
            _config["dns_last_error"] = ""
        save_config()
        return msg
    except Exception as exc:  # noqa: BLE001 - shown in UI, token-free
        msg = "DNS 更新失败：%s" % exc
        with _config_lock:
            _config["dns_last_error"] = msg
        save_config()
        return msg


def load_networks():
    """Load CF ranges: refreshed copy first, bundled copy otherwise."""
    global _networks
    for path in (data_cf_ranges_path(), bundled_cf_ranges_path()):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                nets = rewriter.load_cf_networks(fh.read())
            if nets:
                _networks = nets
                return nets
        except OSError:
            continue
    _networks = rewriter.default_cf_networks()
    return _networks


def refresh_cf_ranges():
    """Refresh the CF IPv4 list from cloudflare.com (fallback: keep old)."""
    req = urllib.request.Request(
        rewriter.CF_RANGES_URL, headers={"User-Agent": "cf-bestipd/%s" % VERSION}
    )
    try:
        with _NO_PROXY_OPENER.open(req, timeout=15) as resp:
            text = resp.read().decode("utf-8", "ignore")
    except Exception as exc:  # noqa: BLE001 - report, keep old list
        return False, "刷新失败（沿用旧列表）：%s" % exc
    nets = rewriter.load_cf_networks(text)
    if not nets:
        return False, "刷新失败：下载到的内容不是有效的 IP 段列表，已沿用旧列表"
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        _atomic_write(data_cf_ranges_path(), text.encode("utf-8"))
    except OSError as exc:
        return False, "刷新失败（无法写入）：%s" % exc
    global _networks
    _networks = nets
    with _config_lock:
        _config["cf_ranges_updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
    save_config()
    return True, "已刷新 Cloudflare IP 段（%d 条）" % len(nets)


# --------------------------------------------------------------------------
# CloudflareSpeedTest binary
# --------------------------------------------------------------------------

def find_cfst_bin():
    env_path = os.environ.get("CFBESTIPD_CFST_BIN")
    if env_path and os.path.isfile(env_path):
        return env_path
    bundled = os.path.join(APP_DIR, "cfst")
    if os.path.isfile(bundled):
        return bundled
    local = os.path.join(CFST_BIN_DIR, "cfst")
    if os.path.isfile(local):
        return local
    return None


def _download_cfst(dest_path):
    """Download the official linux_arm64 tarball and extract the binary."""
    import tarfile

    urls = []
    env_urls = os.environ.get("CFBESTIPD_CFST_URLS", "")
    if env_urls.strip():
        urls = [u.strip() for u in env_urls.split(",") if u.strip()]
    else:
        urls = list(CFST_PINNED_URLS)
        # Fallback: ask GitHub API for the latest release asset.
        try:
            req = urllib.request.Request(
                CFST_API_LATEST,
                headers={"User-Agent": "cf-bestipd/%s" % VERSION,
                         "Accept": "application/vnd.github+json"},
            )
            with _NO_PROXY_OPENER.open(req, timeout=20) as resp:
                rel = json.loads(resp.read().decode("utf-8"))
            for asset in rel.get("assets", []):
                if asset.get("name") == "cfst_linux_arm64.tar.gz":
                    urls.append(asset["browser_download_url"])
                    break
        except Exception:  # noqa: BLE001 - pinned URL is tried first anyway
            pass
    last_err = None
    for url in urls:
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "cf-bestipd/%s" % VERSION}
            )
            with _NO_PROXY_OPENER.open(req, timeout=120) as resp:
                blob = resp.read()
            if len(blob) > 64 * 1024 * 1024:
                raise ValueError("下载到的文件过大，已放弃")
            tmpdir = os.path.join(DATA_DIR, "tmp-download")
            os.makedirs(tmpdir, exist_ok=True)
            tgz = os.path.join(tmpdir, "cfst.tar.gz")
            with open(tgz, "wb") as fh:
                fh.write(blob)
            with tarfile.open(tgz, "r:gz") as tf:
                member = None
                for m in tf.getmembers():
                    if m.isfile() and (
                        m.name == "cfst" or m.name.endswith("/cfst")
                    ):
                        member = m
                        break
                if member is None:
                    raise ValueError("压缩包里没有找到 cfst 程序")
                data = tf.extractfile(member).read()
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            with open(dest_path, "wb") as fh:
                fh.write(data)
            os.chmod(dest_path, 0o755)
            return dest_path
        except Exception as exc:  # noqa: BLE001 - try next URL
            last_err = exc
            continue
    raise RuntimeError(
        "自动下载测速程序失败（%s）。请检查 NAS 能否访问 github.com，"
        "或手动把 CloudflareSpeedTest 的 linux_arm64 版 cfst 程序放到 %s"
        % (last_err, dest_path)
    )


def ensure_cfst():
    """Return a usable cfst binary path, downloading it on first run."""
    path = find_cfst_bin()
    if path:
        try:
            os.chmod(path, 0o755)
        except OSError:
            pass
        return path
    dest = os.path.join(CFST_BIN_DIR, "cfst")
    return _download_cfst(dest)


# --------------------------------------------------------------------------
# Subscription fetch + rewrite
# --------------------------------------------------------------------------

def fetch_upstream(url):
    """Fetch a subscription URL, return (body_bytes, codec)."""
    if not (url.startswith("http://") or url.startswith("https://")):
        raise ValueError("订阅链接必须是 http(s) 地址")
    req = urllib.request.Request(
        url, headers={"User-Agent": "cf-bestipd/%s" % VERSION}
    )
    try:
        with _NO_PROXY_OPENER.open(req, timeout=60) as resp:
            body = resp.read(MAX_UPSTREAM_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise RuntimeError("上游返回 HTTP %d" % exc.code)
    except Exception as exc:  # noqa: BLE001 - surfaced to the UI
        raise RuntimeError("拉取上游失败：%s" % exc)
    if len(body) > MAX_UPSTREAM_BYTES:
        raise RuntimeError("上游内容超过 %d 字节，已放弃" % MAX_UPSTREAM_BYTES)
    try:
        body.decode("utf-8")
        return body, "utf-8"
    except UnicodeDecodeError:
        return body, "latin-1"


def rewrite_subscription(name, url, target, networks, best_ip=None):
    """Fetch + rewrite one subscription, store output + meta. Returns meta.

    ``target`` is the bound domain (e.g. cf.example.com). When it is
    empty (DNS binding not configured yet) the upstream text is served
    unchanged, so clients keep working on the original servers instead
    of a domain that does not resolve yet.
    """
    body, codec = fetch_upstream(url)
    text = body.decode(codec)
    if target:
        new_text, stats = rewriter.rewrite_yaml(
            text, target, networks
        )
    else:
        new_text, stats = text, {
            "rewritten": [], "skipped_ip": [],
            "skipped_non_cf": [], "skipped_unresolved": [],
        }
    out_path = os.path.join(OUTPUTS_DIR, name + ".yaml")
    meta = {
        "name": name,
        "url": url,
        "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "best_ip": best_ip,
        "target": target or "",
        "rewritten": len(stats["rewritten"]),
        "skipped_ip": len(stats["skipped_ip"]),
        "skipped_non_cf": len(stats["skipped_non_cf"]),
        "skipped_unresolved": len(stats["skipped_unresolved"]),
        "error": "",
    }
    os.makedirs(OUTPUTS_DIR, exist_ok=True)
    _atomic_write(out_path, new_text.encode(codec))
    _atomic_write(
        os.path.join(OUTPUTS_DIR, name + ".meta.json"),
        json.dumps(meta, ensure_ascii=False, indent=2).encode("utf-8"),
    )
    return meta


def load_meta(name):
    try:
        with open(
            os.path.join(OUTPUTS_DIR, name + ".meta.json"),
            "r", encoding="utf-8",
        ) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


# --------------------------------------------------------------------------
# Measurement job + scheduler
# --------------------------------------------------------------------------

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07|\x1b.")
_COUNT_RE = re.compile(r"(\d+)\s*/\s*(\d+)")
_AVAIL_RE = re.compile(r"可用：\s*(\d+)")
_SPINNER = ("↗", "↘", "↖", "↙", "✓", "✗", "✔", "✘")


def _phase_from_header(line):
    """'开始延迟测速（...' -> '延迟测速'; anything else -> ''."""
    if line.startswith("开始") and len(line) >= 6:
        return line[2:6]
    return ""


def _is_progress_line(line):
    """True for the tool's in-place progress redraws.

    Those lines carry a tested/total counter plus either the 可用
    counter, a bar, a spinner arrow, or a run of bar dashes. Headers,
    errors and completion lines do not, so they stay as detail lines.
    """
    if _COUNT_RE.search(line) and (
        "可用：" in line or "[" in line or "─" in line
    ):
        return True
    return any(ch in line for ch in _SPINNER) or "───" in line


def _clean_progress_line(line, phase):
    """Collapse one raw progress redraw into a tidy status line.

    Strips ANSI escapes, then keeps only the counters: tested/total
    and available. Falls back to the whitespace-collapsed raw line
    (bar and spinner characters removed) when no counters can be
    found, so nothing is silently dropped.
    """
    text = _ANSI_RE.sub("", line).replace("\x1b", "")
    avail = _AVAIL_RE.search(text)
    count = _COUNT_RE.search(text)
    if avail and count:
        core = "已测 %s / %s，可用 %s" % (
            count.group(1), count.group(2), avail.group(1))
    else:
        core = " ".join(
            re.sub(r"[─=\[\]↗↘↖↙✓✗✔✘|]+", " ", text).split()
        )
    if phase:
        return "%s进行中：%s" % (phase, core) if core else "%s进行中" % phase
    return core


def run_job(scheduled=False):
    """One full cycle: measure best IP, rewrite all subscriptions.

    `scheduled` means the run was fired by the scheduler (not by the
    "run now" button): only a scheduled run in daily mode counts as
    the day's timed run, so a manual run never skips the 03:00 run.
    """
    global _job_running, _job_stage, _job_started
    with _job_lock:
        if _job_running:
            return "已有测速任务在运行，本次跳过"
        _job_running = True
        _job_stage = "刷新 IP 段"
        _job_started = time.time()
    log_lines = []
    # Live tool output, kept tidy for the progress page: headers and
    # other meaningful lines as a short history, plus exactly one
    # reformatted progress line. The tool redraws its progress bar in
    # place many times a second; keeping every redraw is what turned
    # the progress page into a wall of bar fragments.
    live_detail = []
    live_progress = ""
    live_phase = ""

    def _publish_live():
        # In-memory only: the final save_config at the end persists the
        # complete log. Updating _config here is what makes the progress
        # page move during a long run instead of staying silent until
        # the run finishes. The event log gets summary lines only: the
        # tool's live detail lines never leak into 最近日志.
        with _config_lock:
            shown = log_lines + live_detail[-15:]
            if live_progress:
                shown = shown + [live_progress]
            _config["last_log"] = "\n".join(shown)
            _config["event_log"] = "\n".join(log_lines[-20:])

    def _on_cfst_line(line):
        nonlocal live_progress, live_phase
        phase = _phase_from_header(line)
        if phase:
            live_phase = phase
            live_detail.append(line)
            del live_detail[:-15]
        elif _is_progress_line(line):
            live_progress = _clean_progress_line(line, live_phase)
        else:
            live_detail.append(line)
            del live_detail[:-15]
        _publish_live()

    try:
        # 1. Refresh CF ranges (best effort, never fatal).
        ok, msg = refresh_cf_ranges()
        log_lines.append("IP 段：" + msg)
        networks = load_networks()
        # 2. Measure.
        try:
            cfst_bin = ensure_cfst()
        except Exception as exc:  # noqa: BLE001 - shown in UI
            raise RuntimeError("测速程序不可用：%s" % exc)
        ip_file = os.path.join(APP_DIR, "ip.txt")
        if not os.path.isfile(ip_file):
            ip_file = "ip.txt"
        cfg_now = get_config_copy()
        region = _region(cfg_now)
        mode = _schedule_mode(cfg_now)
        with _job_lock:
            _job_stage = "测速中"
        best_ip, _log, top_rows, total_rows, fell_back = (
            cfst_mod.run_speedtest(
                cfst_bin, ip_file, CFST_WORKDIR, on_line=_on_cfst_line,
                region=region,
            )
        )
        live_detail.clear()
        live_progress = ""
        log_lines.append("测速完成，最优 IP：%s" % best_ip)
        if fell_back:
            log_lines.append(
                "区域 %s 未找到可用 IP，已用全局最优" % region)
        _publish_live()
        # 3. Point the bound domain at the new best IP. A failure here
        # is not fatal: the record keeps the previous best IP, which
        # still works, and the subscription output is stable anyway.
        target = full_domain()
        with _job_lock:
            _job_stage = "更新 DNS"
        dns_msg = update_dns_now(best_ip)
        log_lines.append("DNS：" + dns_msg)
        _publish_live()
        # 4. Rewrite every subscription to the bound domain.
        with _job_lock:
            _job_stage = "改写订阅"
        cfg = get_config_copy()
        for sub in cfg["subscriptions"]:
            try:
                meta = rewrite_subscription(
                    sub["name"], sub["url"], target, networks, best_ip
                )
                log_lines.append(
                    "订阅 %s：改写 %d 个节点到 %s"
                    % (sub["name"], meta["rewritten"],
                       target or "（未改写，保持原样）")
                )
            except Exception as exc:  # noqa: BLE001 - per-sub failure
                log_lines.append(
                    "订阅 %s 更新失败：%s" % (sub["name"], exc)
                )
        _publish_live()
        with _config_lock:
            _config["best_ip"] = best_ip
            _config["last_run"] = time.strftime("%Y-%m-%d %H:%M:%S")
            _config["last_log"] = "\n".join(log_lines)
            _config["event_log"] = "\n".join(log_lines[-20:])
            _config["last_results"] = top_rows
            _config["last_result_count"] = total_rows
            _config["last_region"] = region
            _config["last_region_fallback"] = fell_back
            if scheduled and mode == "daily":
                _config["last_daily_run"] = time.strftime("%Y-%m-%d")
        save_config()
        return "\n".join(log_lines)
    except Exception as exc:  # noqa: BLE001 - shown in UI
        with _config_lock:
            _config["last_log"] = "\n".join(log_lines + ["失败：%s" % exc])
            _config["event_log"] = "\n".join(
                (log_lines + ["失败：%s" % exc])[-20:])
        save_config()
        return _config["last_log"]
    finally:
        with _job_lock:
            _job_running = False
            _job_stage = ""


def scheduler_loop():
    """Check every 5 minutes; run when due.

    Interval mode: run when last_run + interval has passed.
    Daily mode: run once a day at the set time. A manual run does
    not count as the daily run, so the timer still fires at the
    set time even if the user ran one by hand earlier that day.
    """
    while True:
        time.sleep(300)
        try:
            cfg = get_config_copy()
            if _schedule_mode(cfg) == "daily":
                today = time.strftime("%Y-%m-%d")
                if cfg.get("last_daily_run") == today:
                    continue
                hour, minute = _schedule_time(cfg)
                now = time.localtime()
                target = time.mktime((now.tm_year, now.tm_mon,
                                      now.tm_mday, hour, minute,
                                      0, 0, 0, -1))
                if time.time() >= target:
                    threading.Thread(
                        target=run_job, kwargs={"scheduled": True},
                        daemon=True).start()
                continue
            last = cfg.get("last_run")
            interval = max(interval_seconds(cfg), MIN_INTERVAL_SECONDS)
            if not last:
                continue
            try:
                last_ts = time.mktime(
                    time.strptime(last, "%Y-%m-%d %H:%M:%S")
                )
            except (ValueError, TypeError):
                continue
            if time.time() >= last_ts + interval:
                threading.Thread(target=run_job, daemon=True).start()
        except Exception:  # noqa: BLE001 - scheduler must never die
            continue


# --------------------------------------------------------------------------
# HTTP UI
# --------------------------------------------------------------------------

def _fmt_time(value):
    return value or "—"


def _fmt_elapsed(seconds):
    """Seconds -> 'X 秒' or 'X 分 Y 秒' for the running-job display."""
    try:
        seconds = int(seconds)
    except (TypeError, ValueError):
        return "—"
    if seconds < 0:
        seconds = 0
    if seconds < 60:
        return "%d 秒" % seconds
    return "%d 分 %d 秒" % (seconds // 60, seconds % 60)


# Kept out of the HTML template on purpose: str.format() would choke on
# the braces in CSS. The template inserts this via the {css} placeholder.
CSS = """
body{font-family:system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;margin:0;background:#f0f2f5;color:#262626}
a{color:#1677ff;text-decoration:none}
.layout{display:flex;max-width:1180px;margin:0 auto;padding:20px;gap:20px;align-items:flex-start}
.side{width:190px;flex-shrink:0;background:#fff;border-radius:10px;box-shadow:0 1px 3px rgba(0,0,0,.08);padding:14px 10px;position:sticky;top:20px}
.side .brand{font-size:17px;font-weight:700;padding:8px 10px 12px;border-bottom:1px solid #f0f0f0;margin-bottom:8px}
.side a{display:block;padding:9px 10px;border-radius:6px;color:#595959}
.side a:hover{background:#f0f7ff;color:#1677ff}
.side .ver{margin-top:12px;padding:10px;border-top:1px solid #f0f0f0;color:#8c8c8c;font-size:12px}
.main{flex:1;min-width:0}
.main h1{font-size:22px;margin:0 0 6px}
.topbar{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}
.topbar h1{flex:1;min-width:0}
.settings{position:relative;flex-shrink:0}
.settings summary{list-style:none;cursor:pointer;padding:8px 16px;border-radius:20px;border:1px solid #d9d9d9;background:#fff;font-size:14px;white-space:nowrap}
.settings summary::-webkit-details-marker{display:none}
.settings[open ] summary{background:#f0f7ff;border-color:#1677ff;color:#1677ff}
.settings .panel{position:absolute;right:0;top:calc(100% + 8px);width:340px;max-width:calc(100vw - 24px);background:#fff;border-radius:10px;box-shadow:0 4px 16px rgba(0,0,0,.15);padding:18px 20px;z-index:10}
.settings .panel h2{font-size:16px;margin:0 0 12px;padding-bottom:10px;border-bottom:1px solid #f0f0f0}
.lead{color:#595959;margin:0 0 14px;line-height:1.6}
.card{background:#fff;border-radius:10px;box-shadow:0 1px 3px rgba(0,0,0,.08);padding:18px 20px;margin-bottom:16px}
.card h2{font-size:16px;margin:0 0 12px;padding-bottom:10px;border-bottom:1px solid #f0f0f0}
.kv:not(:last-child)::after{content:" ｜ "}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#52c41a;margin-right:6px}
.dot.amber{background:#faad14}.dot.red{background:#ff4d4f}
table{border-collapse:collapse;width:100%}th{background:#fafafa}td,th{border:1px solid #f0f0f0;padding:8px 10px;text-align:left;font-size:14px}
.tbl{overflow-x:auto}.tbl table{min-width:520px}
td.url{word-break:break-all}
input[type=text],input[type=password]{width:100%;max-width:560px;padding:8px;border:1px solid #d9d9d9;border-radius:6px}
input[type=number]{padding:8px;width:90px;border:1px solid #d9d9d9;border-radius:6px}
button{padding:8px 16px;border-radius:20px;border:1px solid #d9d9d9;background:#fff;cursor:pointer;margin:2px 4px 2px 0}
button.primary{background:#1677ff;border-color:#1677ff;color:#fff}
form{display:inline}
.msg{background:#eef6ee;border:1px solid #b8d8b8;padding:10px;margin:0 0 16px;border-radius:8px;white-space:pre-wrap}
.warn{background:#fff8e6;border:1px solid #e6c87a;padding:10px;margin:0 0 16px;border-radius:8px}
.muted{color:#8c8c8c;font-size:13px}
pre{white-space:pre-wrap;word-break:break-all;background:#fafafa;padding:12px;border:1px solid #f0f0f0;border-radius:8px}
details summary{cursor:pointer}
@media (max-width:760px){
.layout{display:block;padding:12px}
.side{width:auto;position:static;display:flex;overflow-x:auto;padding:8px;gap:4px;margin-bottom:12px}
.side .brand{display:none}.side .ver{display:none}
.side a{white-space:nowrap;padding:8px 12px}
.main h1{font-size:20px}.card{padding:14px}
td,th{padding:6px 8px;font-size:13px}
button{padding:10px 16px;font-size:16px}
input[type=text],input[type=password],input[type=number]{font-size:16px;padding:8px}
.kv{display:block}.kv:not(:last-child)::after{content:none}
pre{font-size:13px}
}
"""


# Kept as a plain string (not inside the settings template): the
# template is rendered with str.format(), which would choke on the
# braces in JavaScript. Inserted via the {toggle_script} placeholder.
TOGGLE_MODE_SCRIPT = """
<script>
function toggleMode() {
  var daily = document.querySelector('input[name="schedule_mode"]:checked').value === 'daily';
  document.getElementById('interval_box').style.display = daily ? 'none' : '';
  document.getElementById('daily_box').style.display = daily ? '' : 'none';
}
toggleMode();
</script>
"""


def _sidebar(items):
    """Clash-style left navigation: brand + links + version."""
    links = "".join(
        '<a href="%s">%s</a>' % (href, label) for href, label in items
    )
    return (
        '<aside class="side"><div class="brand">CF优选IP（域名版）</div>'
        + links
        + '<div class="ver">版本 %s</div></aside>' % VERSION
    )


def login_page(msg="", next_url="/"):
    """Login page. `next_url` is where a successful login returns to;
    only a local path is accepted, anything else falls back to "/"."""
    if not (isinstance(next_url, str) and next_url.startswith("/")
            and not next_url.startswith("//")):
        next_url = "/"
    msg_html = (
        "<div class=\"msg\">%s</div>" % html.escape(msg) if msg else ""
    )
    return """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>登录 - CF优选IP（域名版）</title>
<style>{css}</style></head><body>
<div class="layout" style="justify-content:center">
<main class="main" style="max-width:440px">
<h1>CF优选IP（域名版）</h1>
<p class="lead">请登录后使用设置页。默认账号 admin，默认密码 admin，
首次登录后请点设置页右上角的“⚙ 设置”改掉账号和密码。</p>
{msg_html}
<div class="card"><h2>登录</h2>
<form method="post" action="/login">
<input type="hidden" name="next" value="{next_url}">
<p>账号：<br><input type="text" name="username" autocomplete="username"
autofocus></p>
<p>密码：<br><input type="password" name="password"
autocomplete="current-password"></p>
<p><button class="primary" type="submit">登录</button></p>
</form>
<p class="muted">忘记密码：删掉本机数据目录 config.json 里的 auth 一段，
重启应用即恢复默认 admin / admin。</p>
</div>
</main>
</div>
</body></html>""".format(
        css=CSS,
        msg_html=msg_html,
        next_url=html.escape(next_url, quote=True),
    )


def settings_page(msg="", edit_binding=False):
    cfg = get_config_copy()
    subs = cfg["subscriptions"]
    interval_days, interval_hours, interval_minutes = _interval_parts(cfg)
    next_run = next_run_text(cfg)
    with _job_lock:
        running = _job_running
        stage = _job_stage
        started = _job_started
    if running:
        elapsed = _fmt_elapsed(time.time() - started) if started else "—"
        running_text = "测速进行中（阶段：%s，已用 %s）" % (
            stage or "测速中", elapsed)
    else:
        running_text = "空闲"
    results = cfg.get("last_results") or []
    if results:
        best = results[0]
        last_region = cfg.get("last_region") or "all"
        if last_region != "all":
            if cfg.get("last_region_fallback"):
                region_note = "优选地区 %s 没有可用 IP，已退回全局最优；" % (
                    _region_label(last_region))
            else:
                region_note = "优选地区：%s；" % _region_label(last_region)
        else:
            region_note = ""
        res_rows = []
        for i, r in enumerate(results):
            mark = " ★最优" if i == 0 else ""
            res_rows.append(
                "<tr><td>{ip}{mark}</td><td>{loss}</td>"
                "<td>{lat}</td><td>{speed}</td>"
                "<td>{region}</td></tr>".format(
                    ip=html.escape(str(r.get("ip", ""))),
                    mark=mark,
                    loss=html.escape(str(r.get("loss", ""))),
                    lat=html.escape(str(r.get("latency", ""))),
                    speed=html.escape(str(r.get("speed", ""))),
                    region=html.escape(str(r.get("region", ""))),
                )
            )
        results_html = (
            "<p>本次共测出 %d 个可用 IP，%s按丢包率、延迟、速度排前 %d 名如下；"
            "最优 IP：<b>%s</b>（延迟 %s ms，丢包率 %s，速度 %s MB/s）。"
            "</p><div class=\"tbl\"><table><tr><th>IP</th><th>丢包率</th>"
            "<th>平均延迟（ms）</th><th>下载速度（MB/s）</th><th>地区</th></tr>"
            "%s</table></div>"
            % (cfg.get("last_result_count") or len(results), region_note,
               len(results),
               html.escape(str(best.get("ip", ""))),
               html.escape(str(best.get("latency", ""))),
               html.escape(str(best.get("loss", ""))),
               html.escape(str(best.get("speed", ""))),
               "\n".join(res_rows))
        )
    elif running:
        results_html = ("<p>正在测速，结果出来后这里会列出前 10 名 IP 及其延迟、"
                        "丢包率和速度。测速时点“查看测速过程”可查看实时进度。</p>")
    elif cfg.get("best_ip"):
        results_html = ("<p>已有最优 IP <b>%s</b>，但没有保存测速明细"
                        "（可能是旧版本跑出的结果）。下次测速完成后，"
                        "这里会列出前 10 名 IP 及其延迟、丢包率和速度。"
                        "</p>" % html.escape(cfg["best_ip"]))
    else:
        results_html = "<p>尚未测速，可点“立即测速并更新”。</p>"
    # Subscription management UI was removed from the page on purpose:
    # only a read-only line of the already configured subscription links
    # remains, so the links are still visible. The back end keeps
    # updating them on schedule, and /api/subs/* still works if the UI
    # is ever brought back.
    if subs:
        subs_line = "、".join(
            '<a href="/sub/{name}">/sub/{name}</a>'.format(
                name=html.escape(sub["name"]))
            for sub in subs
        ) + "（共 %d 个，仍按定时正常更新）" % len(subs)
    else:
        subs_line = "尚未配置订阅"
    msg_html = (
        "<div class=\"msg\">%s</div>" % html.escape(msg) if msg else ""
    )
    if dns_configured(cfg):
        binding_html = (
            "<p><span class=\"kv\">当前绑定：<b>{domain}</b>"
            "（Zone：{zone}，记录名：{record}）</span>"
            "<span class=\"kv\">API 令牌：已保存"
            "（页面上永远不显示令牌本身）</span>"
            "<span class=\"kv\">绑定保存时间：{saved}</span>"
            "<span class=\"kv\">DNS 记录 IP：<b>{dns_ip}</b></span>"
            "<span class=\"kv\">DNS 上次更新：{dns_updated}</span>"
            "<span class=\"kv\">DNS 状态：{dns_status}</span></p>"
            .format(
                domain=html.escape(full_domain(cfg)),
                zone=html.escape(cfg.get("cf_zone") or ""),
                record=html.escape(cfg.get("cf_record") or ""),
                saved=_fmt_time(cfg.get("cf_binding_saved")),
                dns_ip=html.escape(cfg.get("dns_record_ip") or "—"),
                dns_updated=_fmt_time(cfg.get("dns_last_update")),
                dns_status=html.escape(
                    cfg.get("dns_last_error")
                    or "已绑定"
                ),
            )
        )
        binding_html += (
            "<form method=\"get\" action=\"/\">"
            "<input type=\"hidden\" name=\"edit_binding\" value=\"1\">"
            "<button type=\"submit\">修改绑定</button></form> "
            "<form method=\"post\" action=\"/api/dns/delete\" "
            "onsubmit=\"return confirm('确定删除域名绑定吗？删除后订阅恢复"
            "原样输出，Cloudflare 上的记录本身不会动。')\">"
            "<button type=\"submit\">删除绑定</button></form>"
        )
        details_open = " open" if edit_binding else ""
    else:
        binding_html = ("<p>尚未配置绑定：填好下面三项并保存后，"
                        "再点“立即更新 DNS 记录”验证一次。</p>")
        details_open = " open"
    # Hero summary: the four glanceable facts, color-coded. The full
    # detail lives in the sections below; this card never repeats it.
    if not dns_configured(cfg):
        hero_dns = '<span class="dot amber"></span>未配置'
    elif cfg.get("dns_last_error"):
        hero_dns = ('<span class="dot red"></span><b>%s</b>（更新失败）'
                    % html.escape(cfg.get("dns_record_ip") or "—"))
    else:
        hero_dns = ('<span class="dot"></span><b>%s</b>（已绑定）'
                    % html.escape(cfg.get("dns_record_ip") or "—"))
    run_html = (
        '<span class="dot amber"></span>' if running
        else '<span class="dot"></span>'
    ) + running_text
    sidebar = _sidebar([
        ("#overview", "总览"), ("#status", "状态"),
        ("#results", "测速结果"), ("#binding", "域名绑定"),
        ("#interval", "测速计划"),
        ("#log", "最近日志"),
        ("/progress", "测速过程"),
    ])
    # Account settings live behind the top-right "设置" button: change
    # the username and/or the password, or log out. The password
    # itself is never shown; only its hash is stored.
    settings_html = (
        "<details class=\"settings\"><summary>⚙ 设置</summary>"
        "<div class=\"panel\"><h2>账号设置</h2>"
        "<p>当前账号：<b>{username}</b></p>"
        "<form method=\"post\" action=\"/api/password\">"
        "<p>新账号（留空表示不改）：<br><input type=\"text\" "
        "name=\"new_username\" autocomplete=\"username\"></p>"
        "<p>当前密码：<br><input type=\"password\" name=\"current_password\" "
        "autocomplete=\"current-password\"></p>"
        "<p>新密码（至少 {minlen} 位，留空表示只改账号）：<br>"
        "<input type=\"password\" name=\"new_password\" "
        "autocomplete=\"new-password\"></p>"
        "<p>确认新密码：<br><input type=\"password\" "
        "name=\"confirm_password\" autocomplete=\"new-password\"></p>"
        "<p><button class=\"primary\" type=\"submit\">保存</button></p>"
        "</form>"
        "<p class=\"muted\">改完后，其它设备/浏览器上的登录会失效，"
        "需要用新账号密码重新登录；当前这个浏览器保持登录。</p>"
        "<form method=\"post\" action=\"/api/logout\">"
        "<button type=\"submit\">退出登录</button></form></div></details>"
        .format(
            username=html.escape(get_auth()["username"]),
            minlen=MIN_PASSWORD_LEN,
        )
    )
    mode = _schedule_mode(cfg)
    schedule_hour, schedule_minute = _schedule_time(cfg)
    region_options = "".join(
        '<option value="{code}"{selected}>{label}</option>'.format(
            code=code, label=html.escape(label),
            selected=" selected" if code == _region(cfg) else "",
        )
        for code, label in REGION_OPTIONS
    )
    return """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CF优选IP（域名版）</title>
<style>{css}</style></head><body>
<div class="layout">
{sidebar}
<main class="main">
<div class="topbar"><h1>CF优选IP（域名版）</h1>
{settings_html}</div>
<p class="lead">定时测出最优 Cloudflare IP，自动把下面绑定的域名记录指向最优 IP；
订阅里走 CF 的节点地址统一写成该域名。IP 再变也不用客户端重新拉订阅，
等 DNS 生效（TTL 60 秒）就自动连到新 IP。</p>
<div class="warn">本页面只应在家里局域网内访问，不要把本机端口映射到公网，
也不要把下面的 app 订阅链接外发给别人。API 令牌只存在本机，页面上
永远不会把它显示出来。</div>
{msg_html}
<div class="card" id="overview"><span class="kv">最优 IP：<b>{best_ip}</b></span><span class="kv">DNS：{hero_dns}</span><span class="kv">任务：{run_html}</span><span class="kv">下次测速：{next_run}</span></div>
<div class="card" id="status"><h2>状态</h2>
<p><span class="kv">上次测速：{last_run}</span><span class="kv">IP 段数量：{ranges} 条（上次刷新：{ranges_updated}）</span></p>
<p>已配置订阅：{subs_line}</p>
<form method="post" action="/api/run"><button class="primary" type="submit">立即测速并更新</button></form>
<form method="post" action="/api/dns/update"><button type="submit">立即更新 DNS 记录</button></form>
<form method="post" action="/api/refresh-ips"><button type="submit">刷新 Cloudflare IP 段</button></form>
<form method="get" action="/"><button type="submit">刷新状态</button></form>
<form method="get" action="/progress"><button type="submit">查看测速过程</button></form>
<form method="post" action="/api/data/clear" onsubmit="return confirm('确定清除测速结果与域名绑定吗？最优 IP、上次测速、测速明细、过程日志与绑定信息都会清空，Cloudflare 上的 DNS 记录本身不动。')"><button type="submit">清除测速结果与绑定</button></form>
</div>
<div class="card" id="results"><h2>测速结果</h2>
{results_html}</div>
<div class="card" id="binding"><h2>域名绑定</h2>
{binding_html}
<details{details_open}>
<summary>编辑绑定</summary>
<form method="post" action="/api/dns/save">
<p>API 令牌（Cloudflare 后台 → My Profile → API Tokens，用“Edit zone DNS”
模板、只给这一个 Zone 的权限；留空表示不改动已保存的令牌）：<br>
<input type="password" name="cf_token" autocomplete="off"
placeholder="{token_hint}"></p>
<p>域名（Zone，即顶级域名，如 example.com；该域名的 DNS 须托管在 Cloudflare）：<br>
<input type="text" name="cf_zone" value="{cf_zone}"></p>
<p>记录名（前缀，如 cf，最终域名就是 cf.example.com；填 @ 则直接用顶级域名）：<br>
<input type="text" name="cf_record" value="{cf_record}"></p>
<p><button class="primary" type="submit">保存域名绑定</button></p>
</form>
</details>
<p>保存后请先点“立即更新 DNS 记录”，看到成功再把 app 链接换到客户端。
记录由 app 自动维护为“仅 DNS（灰云）”：如果它在后台被改成了代理状态
（小黄云），解析出来的就是任播 IP 而不是优选 IP，状态里会报错提醒。</p>
<div class="card" id="interval"><h2>测速计划</h2>
<form method="post" action="/api/settings">
<p>模式：
<label><input type="radio" name="schedule_mode" value="interval"{checked_interval} onchange="toggleMode()"> 每隔一段时间</label>
<label><input type="radio" name="schedule_mode" value="daily"{checked_daily} onchange="toggleMode()"> 每天固定时间</label></p>
<div id="interval_box">
<p>每 <input type="number" name="interval_days" min="0" max="30" value="{interval_days}"> 天
<input type="number" name="interval_hours" min="0" max="23" value="{interval_hours}"> 小时
<input type="number" name="interval_minutes" min="0" max="59" value="{interval_minutes}"> 分钟测一次</p>
<p class="muted">三项加起来算总间隔，最短 5 分钟、最长 30 天；只改天数也行（小时/分钟填 0）。手动测速会重置计时。</p>
</div>
<div id="daily_box">
<p>每天 <input type="text" name="schedule_time" value="{schedule_time}" style="width:90px" placeholder="03:00"> 测一次</p>
<p class="muted">24 小时制，如 03:00；每天到这个时间跑一次。手动测速不影响定时。</p>
</div>
<p>优选地区：<select name="region">{region_options}</select></p>
<p class="muted">只在所选地区里挑最优 IP；该地区没有可用 IP 时用全局最优并记一条日志。选“全部（自动）”就是以前的行为。</p>
<p><button class="primary" type="submit">保存</button></p>
</form></div>
{toggle_script}
<div class="card" id="log"><h2>最近日志</h2>
<pre>{log}</pre>
<p class="muted">这里只记关键事件（测速完成、DNS 更新、绑定变更等），详细测速过程请看“测速过程”页。</p></div>
</main>
</div>
</body></html>""".format(
        css=CSS,
        msg_html=msg_html,
        best_ip=html.escape(cfg.get("best_ip") or "尚未测速"),
        last_run=_fmt_time(cfg.get("last_run")),
        next_run=next_run,
        hero_dns=hero_dns,
        run_html=run_html,
        sidebar=sidebar,
        ranges=len(_networks),
        ranges_updated=_fmt_time(cfg.get("cf_ranges_updated")),
        domain=html.escape(full_domain(cfg) or "未配置"),
        dns_ip=html.escape(cfg.get("dns_record_ip") or "—"),
        dns_updated=_fmt_time(cfg.get("dns_last_update")),
        dns_status=html.escape(
            cfg.get("dns_last_error")
            or ("已绑定" if dns_configured(cfg) else "未配置")
        ),
        token_hint=(
            "已保存令牌（留空不改）" if (cfg.get("cf_token") or "")
            else "尚未保存令牌"
        ),
        cf_zone=html.escape(cfg.get("cf_zone") or ""),
        cf_record=html.escape(cfg.get("cf_record") or ""),
        subs_line=subs_line,
        results_html=results_html,
        binding_html=binding_html,
        details_open=details_open,
        interval_days=interval_days,
        interval_hours=interval_hours,
        interval_minutes=interval_minutes,
        checked_interval=" checked" if mode == "interval" else "",
        checked_daily=" checked" if mode == "daily" else "",
        schedule_time=_fmt_schedule_time(schedule_hour, schedule_minute),
        region_options=region_options,
        toggle_script=TOGGLE_MODE_SCRIPT,
        settings_html=settings_html,
        log=html.escape(cfg.get("event_log") or "暂无"),
    )


def progress_page():
    """Focused view of the measurement process: stage, elapsed, log.

    The page polls /api/status every 2 seconds and updates the stage,
    elapsed time, best IP and log lines in place, like an install flow
    that grows line by line. There is no manual refresh button: while a
    run is active the view moves on its own; when idle it shows the
    previous run's record.
    """
    cfg = get_config_copy()
    with _job_lock:
        running = _job_running
        stage = _job_stage
        started = _job_started
    if running:
        elapsed = _fmt_elapsed(time.time() - started) if started else "—"
        status_text = "测速进行中（阶段：%s，已用 %s）" % (
            stage or "测速中", elapsed)
        hint = "测速进行中，下面过程自动实时更新，不用手动刷新。"
    else:
        status_text = "空闲（上次测速：%s）" % _fmt_time(cfg.get("last_run"))
        hint = ("这是上一次测速留下的过程记录；"
                "点“立即测速并更新”开始新一次测速。")
    sidebar = _sidebar([
        ("/", "总览"), ("/#results", "测速结果"),
        ("/#binding", "域名绑定"), ("/#log", "最近日志"),
    ])
    return (
        "<!DOCTYPE html>\n"
        '<html lang="zh-CN"><head><meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "<title>测速过程</title>\n"
        "<style>" + CSS + "</style></head><body>\n"
        '<div class="layout">' + sidebar + '<main class="main">\n'
        "<h1>测速过程</h1>\n"
        '<div class="card"><p><span class="kv">任务状态：<b id="pstatus">'
        + html.escape(status_text)
        + '</b></span><span class="kv">最优 IP：<b id="pbest">'
        + html.escape(cfg.get("best_ip") or "尚未测速")
        + "</b></span></p>\n"
        "<p>" + hint + "</p>\n"
        '<pre id="plog">' + html.escape(cfg.get("last_log") or "暂无") + "</pre>\n"
        '<form method="post" action="/api/run"><button class="primary" '
        'type="submit">立即测速并更新</button></form>\n'
        '<form method="get" action="/"><button type="submit">返回设置页</button>'
        "</form></div>\n"
        "</main></div>\n"
        "<script>\n"
        "function fmtElapsed(s){\n"
        "  s = Math.max(0, Math.floor(s));\n"
        "  if(s < 60){ return s + ' 秒'; }\n"
        "  return Math.floor(s / 60) + ' 分 ' + (s % 60) + ' 秒';\n"
        "}\n"
        "async function tick(){\n"
        "  try{\n"
        "    const r = await fetch('/api/status');\n"
        "    if(r.status === 401){ location.href = '/login'; return; }\n"
        "    const j = await r.json();\n"
        "    const st = document.getElementById('pstatus');\n"
        "    const bi = document.getElementById('pbest');\n"
        "    const lg = document.getElementById('plog');\n"
        "    if(j.running){\n"
        "      st.textContent = '测速进行中（阶段：' + (j.running_stage || '测速中') + '，已用 ' + fmtElapsed(j.running_seconds) + '）';\n"
        "    } else {\n"
        "      st.textContent = '空闲（上次测速：' + (j.last_run || '尚未测速') + '）';\n"
        "    }\n"
        "    bi.textContent = j.best_ip || '尚未测速';\n"
        "    lg.textContent = j.last_log || '暂无';\n"
        "  }catch(e){}\n"
        "}\n"
        "setInterval(tick, 2000);\n"
        "tick();\n"
        "</script>\n"
        "</body></html>\n"
    )


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # -- helpers ------------------------------------------------------
    def log_message(self, *args):  # keep stdout clean; app.log stays small
        pass

    def _send_text(self, code, body, ctype="text/html; charset=utf-8",
                   extra_headers=None):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        # Never let a browser cache this page: a cached copy makes
        # "刷新状态" look dead and hides live progress.
        self.send_header("Cache-Control",
                         "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        for name, value in (extra_headers or []):
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_bytes(self, code, data, ctype, extra_headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control",
                         "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        for name, value in (extra_headers or []):
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, msg="", extra_headers=None):
        target = "/"
        if msg:
            target += "?msg=" + urllib.parse.quote(msg)
        self.send_response(303)
        self.send_header("Location", target)
        self.send_header("Cache-Control",
                         "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        for name, value in (extra_headers or []):
            self.send_header(name, value)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _redirect_to(self, location, extra_headers=None):
        """Redirect to an explicit path (used for /login)."""
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Cache-Control",
                         "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        for name, value in (extra_headers or []):
            self.send_header(name, value)
        self.send_header("Content-Length", "0")
        self.end_headers()

    # -- login --------------------------------------------------------
    def _session_token(self):
        cookie = self.headers.get("Cookie") or ""
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith(SESSION_COOKIE + "="):
                return part[len(SESSION_COOKIE) + 1:]
        return None

    def _current_user(self):
        return validate_session(self._session_token())

    def _set_session_cookie(self, token):
        if token:
            return [("Set-Cookie",
                     "%s=%s; HttpOnly; Path=/; Max-Age=%d; SameSite=Lax"
                     % (SESSION_COOKIE, token, SESSION_TTL))]
        return [("Set-Cookie",
                 "%s=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax"
                 % SESSION_COOKIE)]

    def _redirect_login(self):
        nxt = urllib.parse.quote(self.path, safe="")
        self._redirect_to("/login?next=" + nxt)

    def _require_login(self):
        """True when a valid session exists; otherwise sends the
        client to /login and returns False."""
        if self._current_user():
            return True
        self._redirect_login()
        return False

    def _read_form(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length > 0 else b""
        parsed = urllib.parse.parse_qs(raw.decode("utf-8", "ignore"))
        return {k: v[0] for k, v in parsed.items() if v}

    # -- GET ----------------------------------------------------------
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        if path == "/login":
            if self._current_user():
                self._redirect_to("/")
                return
            msg = query.get("msg", [""])[0]
            nxt = query.get("next", ["/"])[0]
            self._send_text(200, login_page(msg, nxt))
            return
        if path == "/":
            if not self._require_login():
                return
            msg = query.get("msg", [""])[0]
            edit_binding = query.get("edit_binding", [""])[0] == "1"
            self._send_text(200, settings_page(msg, edit_binding))
            return
        if path == "/progress":
            if not self._require_login():
                return
            self._send_text(200, progress_page())
            return
        if path == "/api/status":
            if not self._current_user():
                self._send_text(
                    401, json.dumps({"error": "未登录"},
                                    ensure_ascii=False),
                    "application/json; charset=utf-8")
                return
            cfg = get_config_copy()
            with _job_lock:
                running = _job_running
                stage = _job_stage
                started = _job_started
            self._send_text(200, json.dumps({
                "best_ip": cfg.get("best_ip"),
                "last_run": cfg.get("last_run"),
                "running": running,
                "running_stage": stage if running else "",
                "running_seconds": (
                    int(time.time() - started)
                    if (running and started) else 0
                ),
                "last_log": cfg.get("last_log") or "",
                "last_results": cfg.get("last_results") or [],
                "last_result_count": cfg.get("last_result_count") or 0,
                "domain": full_domain(cfg),
                "dns_configured": dns_configured(cfg),
                "dns_record_ip": cfg.get("dns_record_ip"),
                "dns_last_update": cfg.get("dns_last_update"),
                "dns_last_error": cfg.get("dns_last_error"),
                "subscriptions": [
                    s["name"] for s in cfg["subscriptions"]
                ],
            }, ensure_ascii=False), "application/json; charset=utf-8")
            return
        if path.startswith("/sub/"):
            name = urllib.parse.unquote(path[len("/sub/"):])
            self._serve_sub(name)
            return
        self._send_text(404, "不存在的地址")

    def _serve_sub(self, name):
        if not NAME_RE.match(name):
            self._send_text(404, "不存在的订阅")
            return
        out_path = os.path.join(OUTPUTS_DIR, name + ".yaml")
        if os.path.isfile(out_path):
            try:
                with open(out_path, "rb") as fh:
                    data = fh.read()
                self._send_bytes(200, data, "text/yaml; charset=utf-8")
                return
            except OSError:
                pass
        # No cached output: generate on demand.
        cfg = get_config_copy()
        sub = None
        for item in cfg["subscriptions"]:
            if item["name"] == name:
                sub = item
                break
        if sub is None:
            self._send_text(404, "不存在的订阅")
            return
        try:
            meta = rewrite_subscription(
                name, sub["url"], full_domain(cfg), load_networks(),
                cfg.get("best_ip"),
            )
            with open(out_path, "rb") as fh:
                data = fh.read()
            self._send_bytes(200, data, "text/yaml; charset=utf-8")
        except Exception as exc:  # noqa: BLE001 - surfaced to the client
            self._send_text(
                502, "订阅暂时无法生成：%s" % exc, "text/plain; charset=utf-8"
            )

    # -- POST ---------------------------------------------------------
    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        form = self._read_form()
        if path == "/login":
            username = (form.get("username") or "").strip()
            password = form.get("password") or ""
            nxt = form.get("next") or "/"
            if not (nxt.startswith("/") and not nxt.startswith("//")):
                nxt = "/"
            if not username or not password:
                self._redirect_to(
                    "/login?msg=" + urllib.parse.quote("请输入账号和密码")
                    + "&next=" + urllib.parse.quote(nxt, safe=""))
                return
            if not verify_login(username, password):
                self._redirect_to(
                    "/login?msg=" + urllib.parse.quote("账号或密码错误")
                    + "&next=" + urllib.parse.quote(nxt, safe=""))
                return
            token = create_session(username)
            self._redirect_to(nxt, self._set_session_cookie(token))
            return
        if path == "/api/logout":
            destroy_session(self._session_token())
            self._redirect_to("/login",
                               self._set_session_cookie(None))
            return
        if path == "/api/password":
            user = self._current_user()
            if not user:
                self._redirect_login()
                return
            current = form.get("current_password") or ""
            new_user = (form.get("new_username") or "").strip()
            new = form.get("new_password") or ""
            confirm = form.get("confirm_password") or ""
            if not verify_login(user, current):
                self._redirect("当前密码不对")
                return
            if new_user and not re.match(
                    r"^[A-Za-z0-9_.\-]{1,32}$", new_user):
                self._redirect("新账号无效：只允许字母、数字、下划线、点、短横线，1-32 位")
                return
            if not new_user and not new:
                self._redirect("账号和密码都没有改")
                return
            if new:
                if len(new) < MIN_PASSWORD_LEN:
                    self._redirect("新密码至少 %d 位" % MIN_PASSWORD_LEN)
                    return
                if new != confirm:
                    self._redirect("两次输入的新密码不一致")
                    return
            # Keep the unchanged half: empty new username keeps the old
            # name, empty new password keeps the old password.
            final_user = new_user or user
            final_pass = new or current
            set_auth(final_user, final_pass)
            if final_user != user:
                # The session stores the old name; refresh it so the
                # current browser keeps working under the new name.
                # (load_sessions() is void; _sessions is the global
                # dict, guarded by _sessions_lock.)
                _tok = self._session_token()
                _changed = False
                with _sessions_lock:
                    if _tok in _sessions:
                        _sessions[_tok]["username"] = final_user
                        _changed = True
                if _changed:
                    save_sessions()
            # Keep this browser logged in; other sessions must log in
            # again with the new credentials.
            destroy_other_sessions(self._session_token())
            if new_user and new:
                self._redirect("账号和密码已修改")
            elif new_user:
                self._redirect("账号已修改")
            else:
                self._redirect("密码已修改")
            return
        # Every other management API requires a login. The public
        # subscription links (/sub/<name>) are GET-only and stay open.
        if path.startswith("/api/"):
            if not self._current_user():
                self._redirect_login()
                return
        if path == "/api/subs/add":
            name = (form.get("name") or "").strip()
            url = (form.get("url") or "").strip()
            if not NAME_RE.match(name):
                self._redirect("名字无效：只允许字母、数字、下划线、短横线")
                return
            if not (url.startswith("http://")
                    or url.startswith("https://")):
                self._redirect("链接无效：必须是 http(s) 地址")
                return
            cfg = get_config_copy()
            if any(s["name"] == name for s in cfg["subscriptions"]):
                self._redirect("名字已存在：%s" % name)
                return
            with _config_lock:
                _config["subscriptions"].append(
                    {"name": name, "url": url}
                )
            save_config()
            try:
                cfg_now = get_config_copy()
                meta = rewrite_subscription(
                    name, url, full_domain(cfg_now), load_networks(),
                    cfg_now.get("best_ip"),
                )
                self._redirect(
                    "已添加 %s（本次改写 %d 个节点）"
                    % (name, meta["rewritten"])
                )
            except Exception as exc:  # noqa: BLE001 - keep the entry
                self._redirect(
                    "已添加 %s，但首次拉取失败：%s（可稍后点“立即测速并更新”）"
                    % (name, exc)
                )
            return
        if path == "/api/subs/delete":
            name = (form.get("name") or "").strip()
            with _config_lock:
                _config["subscriptions"] = [
                    s for s in _config["subscriptions"]
                    if s["name"] != name
                ]
            save_config()
            for suffix in (".yaml", ".meta.json"):
                try:
                    os.remove(os.path.join(OUTPUTS_DIR, name + suffix))
                except OSError:
                    pass
            self._redirect("已删除 %s" % name)
            return
        if path == "/api/run":
            with _job_lock:
                if _job_running:
                    self._redirect("已有测速任务在运行，请稍后再试")
                    return
            threading.Thread(target=run_job, daemon=True).start()
            self._redirect("测速任务已启动，完成后状态页会更新")
            return
        if path == "/api/refresh-ips":
            ok, msg = refresh_cf_ranges()
            load_networks()
            record_event("IP 段：" + msg)
            self._redirect(msg)
            return
        if path == "/api/dns/save":
            # Empty token field means "keep the saved token": the page
            # never shows the token, so a blank field cannot mean clear.
            # Clean paste artifacts (inner spaces, quotes) on save, and
            # ensure_record cleans again at use time for tokens saved
            # by older versions.
            token = cfdns.clean_token(form.get("cf_token") or "")
            zone = (form.get("cf_zone") or "").strip().strip(".")
            record = (form.get("cf_record") or "").strip().strip(".")
            if not zone:
                self._redirect("域名不能为空")
                return
            if record and not re.match(r"^[A-Za-z0-9_-]+$", record) \
                    and record != "@":
                self._redirect("记录名无效：只允许字母、数字、下划线、短横线")
                return
            with _config_lock:
                old_zone = _config.get("cf_zone") or ""
                old_record = _config.get("cf_record") or ""
                if token:
                    _config["cf_token"] = token
                _config["cf_zone"] = zone
                _config["cf_record"] = record
                _config["cf_binding_saved"] = time.strftime(
                    "%Y-%m-%d %H:%M:%S")
                if zone != old_zone or record != old_record:
                    # The binding target changed: the stored DNS state
                    # belongs to the previous record, so clear it until
                    # the new record is verified with an update.
                    _config["dns_record_ip"] = None
                    _config["dns_last_update"] = None
                    _config["dns_last_error"] = ""
            save_config()
            record_event("域名绑定已保存：" + full_domain())
            self._redirect(
                "域名绑定已保存：%s（请点“立即更新 DNS 记录”验证一次）"
                % full_domain()
            )
            return
        if path == "/api/dns/delete":
            with _config_lock:
                _config["cf_token"] = ""
                _config["cf_zone"] = ""
                _config["cf_record"] = ""
                _config["dns_record_ip"] = None
                _config["dns_last_update"] = None
                _config["dns_last_error"] = ""
                _config["cf_binding_saved"] = None
            save_config()
            # Regenerate every subscription unmodified so clients stop
            # getting the old domain at once; failures are ignored
            # because the next run regenerates anyway.
            try:
                cfg_now = get_config_copy()
                networks = load_networks()
                for sub in cfg_now["subscriptions"]:
                    try:
                        rewrite_subscription(
                            sub["name"], sub["url"], "", networks,
                            cfg_now.get("best_ip"),
                        )
                    except Exception:
                        pass
            except Exception:
                pass
            record_event("域名绑定已删除")
            self._redirect(
                "域名绑定已删除（订阅恢复原样输出；Cloudflare 上的记录本身"
                "未动，如需删除请去 Cloudflare 后台手动删）"
            )
            return
        if path == "/api/data/clear":
            # Wipe results + binding from this machine's saved config.
            # The package itself never contains user data; what a fresh
            # install still shows comes from the preserved data dir,
            # which is exactly what this clears. Cloudflare records are
            # untouched, mirroring /api/dns/delete semantics.
            with _job_lock:
                if _job_running:
                    self._redirect("有测速任务在运行，请等它结束后再清除")
                    return
            with _config_lock:
                _config["best_ip"] = None
                _config["last_run"] = None
                _config["last_daily_run"] = None
                _config["last_region"] = None
                _config["last_region_fallback"] = False
                _config["last_log"] = ""
                _config["event_log"] = ""
                _config["last_results"] = []
                _config["last_result_count"] = 0
                _config["cf_token"] = ""
                _config["cf_zone"] = ""
                _config["cf_record"] = "cf"
                _config["cf_binding_saved"] = None
                _config["dns_record_ip"] = None
                _config["dns_last_update"] = None
                _config["dns_last_error"] = ""
            save_config()
            try:
                cfg_now = get_config_copy()
                networks = load_networks()
                for sub in cfg_now["subscriptions"]:
                    try:
                        rewrite_subscription(
                            sub["name"], sub["url"], "", networks, None,
                        )
                    except Exception:
                        pass
            except Exception:
                pass
            self._redirect(
                "已清除测速结果与域名绑定（Cloudflare 上的记录本身未动，"
                "如需删除请去 Cloudflare 后台手动删）"
            )
            return
        if path == "/api/dns/update":
            cfg = get_config_copy()
            best_ip = cfg.get("best_ip")
            if not best_ip:
                self._redirect(
                    "尚未测速，没有可用的最优 IP：请先点“立即测速并更新”"
                )
                return
            msg = update_dns_now(best_ip)
            record_event(msg if msg.startswith("DNS") else "DNS：" + msg)
            self._redirect(msg)
            return
        if path == "/api/settings":
            mode = (form.get("schedule_mode") or "").strip().lower()
            if mode not in ("interval", "daily"):
                self._redirect("测速计划无效：模式请选择“间隔”或“每天固定时间”")
                return
            region = _normalize_region(form.get("region"))
            if region is None:
                self._redirect("地区无效：请从下拉里选")
                return
            if mode == "daily":
                sched_time = (form.get("schedule_time") or "").strip()
                if not re.match(r"^([01]\d|2[0-3]):[0-5]\d$",
                                sched_time):
                    self._redirect(
                        "时间无效：请按 HH:MM 填，如 03:00（00:00–23:59）")
                    return
                with _config_lock:
                    _config["schedule_mode"] = mode
                    _config["schedule_time"] = sched_time
                    _config["region"] = region
                save_config()
                record_event("测速计划改为每天 %s" % sched_time)
                self._redirect("测速计划已保存为每天 %s" % sched_time)
                return
            def _num(name):
                try:
                    return int(form.get(name) or 0)
                except ValueError:
                    return None
            days = _num("interval_days")
            hours = _num("interval_hours")
            minutes = _num("interval_minutes")
            if days is None or hours is None or minutes is None:
                self._redirect("间隔无效：天/小时/分钟请输入数字")
                return
            if not 0 <= days <= 30:
                self._redirect("间隔无效：天数请输入 0 到 30")
                return
            if not 0 <= hours <= 23:
                self._redirect("间隔无效：小时请输入 0 到 23")
                return
            if not 0 <= minutes <= 59:
                self._redirect("间隔无效：分钟请输入 0 到 59")
                return
            total = days * 86400 + hours * 3600 + minutes * 60
            if total < MIN_INTERVAL_SECONDS:
                self._redirect("间隔无效：总间隔不能小于 5 分钟")
                return
            if total > MAX_INTERVAL_SECONDS:
                self._redirect("间隔无效：总间隔不能超过 30 天")
                return
            with _config_lock:
                _config["schedule_mode"] = mode
                _config["interval_days"] = days
                _config["interval_hours"] = hours
                _config["interval_minutes"] = minutes
                _config["region"] = region
            save_config()
            text = _fmt_interval(days, hours, minutes)
            record_event("测速间隔改为 %s" % text)
            self._redirect("测速间隔已保存为 %s" % text)
            return
        self._send_text(404, "不存在的地址")


def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(OUTPUTS_DIR, exist_ok=True)
    load_config()
    load_sessions()
    load_networks()
    # Best-effort IP-range refresh at start; failures keep the old list.
    try:
        refresh_cf_ranges()
        load_networks()
    except Exception:  # noqa: BLE001 - startup must not fail on this
        pass
    port = resolve_port()
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    server.daemon_threads = True
    threading.Thread(target=scheduler_loop, daemon=True).start()
    print("cf-bestipd %s listening on 0.0.0.0:%d (data: %s)"
          % (VERSION, port, DATA_DIR), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
