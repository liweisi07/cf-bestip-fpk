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
import ipaddress
import json
import os
import platform
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
import notify as notify_mod
import upgrade as upgrade_mod

VERSION = "1.0.22"
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
# Multi-record DNS (1.0.22): how many top IPs are written as records
# for one name (1-5, default 5). Same count for A and AAAA.
DEFAULT_DNS_RECORD_COUNT = 5
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

CFST_PINNED_URLS = {
    # One .fpk serves both architectures (manifest platform=all):
    # the package bundles both binaries, and the download fallback
    # below picks the URL matching the host architecture.
    "arm64": (
        "https://github.com/XIU2/CloudflareSpeedTest/releases/download/"
        "v2.3.5/cfst_linux_arm64.tar.gz"
    ),
    "amd64": (
        "https://github.com/XIU2/CloudflareSpeedTest/releases/download/"
        "v2.3.5/cfst_linux_amd64.tar.gz"
    ),
}
CFST_ASSET_NAMES = {
    "arm64": "cfst_linux_arm64.tar.gz",
    "amd64": "cfst_linux_amd64.tar.gz",
}
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
CFST_WORKDIR6 = os.path.join(DATA_DIR, "cfst6")
CFST_BIN_DIR = os.path.join(DATA_DIR, "cfst-bin")
# IPv6 measurement ranges: cfst (v2.1.0+) auto-detects IPv6 from the
# -f file, so no special flag is needed. The file must NOT be the
# official ips-v6 list (7 huge /32s: almost every sampled address is
# unassigned, so barely anything is measurable). The upstream
# CloudflareSpeedTest repo ships a curated ipv6.txt of the subnets
# that are actually in use (ASN data from bgp.he.net AS13335); the
# app bundles that file and refreshes it from the same source.
IP6_RANGES_URL = (
    "https://raw.githubusercontent.com/XIU2/CloudflareSpeedTest/master/"
    "ipv6.txt"
)


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
    # Multi-record DNS (1.0.22): the A record set (top-N IPs).
    "dns_record_ips": [],
    "dns_record_count": DEFAULT_DNS_RECORD_COUNT,
    # IPv6 preference (1.0.22): off by default; the NAS needs an IPv6
    # route for it to work. IPv6 is measured and updated independently
    # of IPv4, with its own AAAA record set and the same count.
    "ipv6_enabled": False,
    "best_ip6": None,
    "dns_record_ip6": None,
    "dns_record_ips6": [],
    "dns_last_update6": None,
    "dns_last_error6": "",
    "last_results6": [],
    "last_result_count6": 0,
    "last_region6": None,
    "last_region_fallback6": False,
    "cf_ranges6_updated": None,
    # Notifications (1.0.22). Tokens/secrets live only in this local
    # config file; no page or API response ever echoes them, and they
    # never appear in logs. Failure events (no IP / DNS abnormal /
    # network down) default ON; the two optional event types
    # (successful IP change, routine speed-test result) default OFF.
    # notify_state holds incident/dedup bookkeeping (see _notify_*).
    # update_check holds the last online-upgrade check result.
    "notify_tg_enabled": False,
    "notify_tg_token": "",
    "notify_tg_chat_id": "",
    "notify_fs_enabled": False,
    "notify_fs_webhook": "",
    "notify_fs_secret": "",
    "notify_proxy": "",
    "notify_failure": True,
    "notify_ip_change": False,
    "notify_daily_result": False,
    "notify_state": {},
    "update_check": {},
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


def _is_ipv4(ip):
    """True when `ip` parses as an IPv4 address."""
    try:
        return isinstance(ipaddress.ip_address(ip),
                          ipaddress.IPv4Address)
    except ValueError:
        return False


def _is_ipv6(ip):
    """True when `ip` parses as an IPv6 address."""
    try:
        return isinstance(ipaddress.ip_address(ip),
                          ipaddress.IPv6Address)
    except ValueError:
        return False


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
                # Notification settings (1.0.22): old files get
                # defaults; a hand-edited file may hold garbage.
                for _key, _default in (
                        ("notify_tg_enabled", False),
                        ("notify_fs_enabled", False),
                        ("notify_failure", True),
                        ("notify_ip_change", False),
                        ("notify_daily_result", False)):
                    if not isinstance(_config.get(_key), bool):
                        _config[_key] = _default
                for _key in ("notify_tg_token", "notify_tg_chat_id",
                             "notify_fs_webhook", "notify_fs_secret",
                             "notify_proxy"):
                    if not isinstance(_config.get(_key), str):
                        _config[_key] = ""
                if not isinstance(_config.get("notify_state"), dict):
                    _config["notify_state"] = {}
                if not isinstance(_config.get("update_check"), dict):
                    _config["update_check"] = {}
                # IPv6 + multi-record DNS (1.0.22): old files get
                # defaults; a hand-edited file may hold garbage.
                if not isinstance(_config.get("ipv6_enabled"), bool):
                    _config["ipv6_enabled"] = False
                try:
                    _n = int(_config.get("dns_record_count") or 0)
                except (TypeError, ValueError):
                    _n = 0
                _config["dns_record_count"] = (
                    max(1, min(5, _n)) if _n else
                    DEFAULT_DNS_RECORD_COUNT)
                for _key in ("dns_record_ips", "dns_record_ips6",
                             "last_results6"):
                    if not isinstance(_config.get(_key), list):
                        _config[_key] = []
                for _key in ("best_ip6", "dns_record_ip6",
                             "dns_last_update6", "last_region6",
                             "cf_ranges6_updated"):
                    if (_config.get(_key) is not None
                            and not isinstance(_config.get(_key), str)):
                        _config[_key] = None
                if not isinstance(_config.get("dns_last_error6"), str):
                    _config["dns_last_error6"] = ""
                if not isinstance(_config.get("last_result_count6"), int):
                    _config["last_result_count6"] = 0
                if not isinstance(_config.get("last_region_fallback6"),
                                  bool):
                    _config["last_region_fallback6"] = False
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


def _dns_record_count(cfg):
    """How many top IPs are written as DNS records (1-5, default 5)."""
    try:
        n = int(cfg.get("dns_record_count") or 0)
    except (TypeError, ValueError):
        return DEFAULT_DNS_RECORD_COUNT
    return max(1, min(5, n)) if n else DEFAULT_DNS_RECORD_COUNT


def _top_ips_for_dns(cfg, record_type="A"):
    """Top-N IPs from the last run's stored rows, for a manual update."""
    count = _dns_record_count(cfg)
    rows = (cfg.get("last_results6") if record_type == "AAAA"
            else cfg.get("last_results")) or []
    return [r.get("ip") for r in rows[:count] if r.get("ip")]


def update_dns_now(ips, record_type="A"):
    """Point the bound record set at `ips`. Returns a status message.

    `ips` is the top-N list (1-5) for the record type ("A" for IPv4,
    "AAAA" for IPv6). Updates the stored DNS state (record IPs / last
    update / last error) and saves the config. Raises nothing:
    failures are reported as a message and stored, because stale
    records still work (they are valid Cloudflare IPs, just possibly
    not the newest best ones). A DNS failure is one of the failure
    events and notifies (deduped, IPv4 and IPv6 separately); a success
    closes the incident.
    """
    cfg = get_config_copy()
    is_v6 = record_type == "AAAA"
    err_key = "dns_last_error6" if is_v6 else "dns_last_error"
    ips_key = "dns_record_ips6" if is_v6 else "dns_record_ips"
    ip_key = "dns_record_ip6" if is_v6 else "dns_record_ip"
    upd_key = "dns_last_update6" if is_v6 else "dns_last_update"
    event_key = "dns6" if is_v6 else "dns"
    label = "AAAA" if is_v6 else "A"
    if not dns_configured(cfg):
        msg = ("未更新 DNS：请先在下方“域名绑定”里填好 API 令牌、域名和"
               "记录名")
        with _config_lock:
            _config[err_key] = msg
        save_config()
        return msg
    if not ips:
        msg = "未更新 DNS（%s）：没有可用的最优 IP" % label
        with _config_lock:
            _config[err_key] = msg
        save_config()
        return msg
    try:
        written, _ttl, msg = cfdns.ensure_records(
            cfg["cf_token"].strip(),
            cfg["cf_zone"].strip(),
            cfg.get("cf_record") or "",
            list(ips),
            record_type,
        )
        with _config_lock:
            _config[ips_key] = list(written)
            _config[ip_key] = written[0] if written else None
            _config[upd_key] = time.strftime("%Y-%m-%d %H:%M:%S")
            _config[err_key] = ""
        save_config()
        clear_notify_incident(event_key)
        return msg
    except Exception as exc:  # noqa: BLE001 - shown in UI, token-free
        msg = "DNS 更新失败（%s）：%s" % (label, exc)
        with _config_lock:
            _config[err_key] = msg
        save_config()
        notify_event(event_key, "域名异常", [
            "域名：%s" % (full_domain() or "未配置"),
            "记录：%s 记录" % label,
            "详情：%s" % msg,
            "请检查 API 令牌权限与域名配置。",
        ])
        return msg


# --------------------------------------------------------------------------
# Notifications (1.0.22): Telegram + Feishu.
#
# Events (only these ever notify):
#   failure (toggle "notify_failure", default ON):
#     no_ip   - a speed-test run found no usable/best IPv4
#     dns     - the bound domain's A record update/check failed
#     no_ip6  - a speed-test run found no usable/best IPv6
#     dns6    - the bound domain's AAAA record update/check failed
#     offline - the NAS lost internet; notified on recovery with
#               the outage window (it cannot be sent while offline)
#   optional (each its own toggle, default OFF):
#     ip_change    - the DNS record IP set changed after a run
#     daily_result - the summary of a successful speed-test run
#
# IPv4 and IPv6 failures are separate incidents (no_ip vs no_ip6,
# dns vs dns6), so a persistent IPv6 failure never suppresses an
# IPv4 notification and vice versa.
#
# Dedup rule (failure events only; the optional ones are per-run by
# definition): the same failure notifies once per incident. An
# incident opens at the first occurrence and closes when its
# condition clears (a successful run / a successful DNS update).
# While open, a repeat is counted but not re-sent, except one
# reminder per 24h while it is still failing. When every channel
# failed to send, the next attempt waits at least an hour.
# --------------------------------------------------------------------------

FAILURE_EVENTS = ("no_ip", "dns", "no_ip6", "dns6", "offline")
# Failure events whose repeats are deduped per incident (offline is
# notified once per outage on recovery, so it needs no dedup).
DEDUP_EVENTS = ("no_ip", "dns", "no_ip6", "dns6")
OPTIONAL_EVENTS = ("ip_change", "daily_result")
NOTIFY_REMINDER_SECONDS = 24 * 3600
NOTIFY_RETRY_SECONDS = 3600
# An outage shorter than this is a blip, not a notified outage.
MIN_OFFLINE_SECONDS = 60


def _notify_enabled(cfg, event_key):
    """True when this event type is switched on in the settings."""
    if event_key in FAILURE_EVENTS:
        return bool(cfg.get("notify_failure", True))
    if event_key == "ip_change":
        return bool(cfg.get("notify_ip_change", False))
    if event_key == "daily_result":
        return bool(cfg.get("notify_daily_result", False))
    return False


def _notify_channels(cfg):
    """Enabled + configured channels: list of (kind, sender, kwargs).

    A channel only appears when it is switched on AND its credentials
    are filled in. The credentials are only ever passed to the sender
    function; they are never logged or shown on a page.
    """
    channels = []
    if (cfg.get("notify_tg_enabled")
            and (cfg.get("notify_tg_token") or "").strip()
            and (cfg.get("notify_tg_chat_id") or "").strip()):
        channels.append(("telegram", notify_mod.send_telegram, {
            "token": cfg["notify_tg_token"].strip(),
            "chat_id": cfg["notify_tg_chat_id"].strip(),
        }))
    if (cfg.get("notify_fs_enabled")
            and (cfg.get("notify_fs_webhook") or "").strip()):
        channels.append(("feishu", notify_mod.send_feishu, {
            "webhook_url": cfg["notify_fs_webhook"].strip(),
            "secret": cfg.get("notify_fs_secret") or "",
        }))
    return channels


def _notify_text(title, detail_lines, when=None):
    """Notification body: title, time, then the detail lines."""
    if when is None:
        when = time.strftime("%Y-%m-%d %H:%M:%S")
    lines = ["【CF优选IP】%s" % title, "时间：%s" % when]
    lines.extend(detail_lines)
    return "\n".join(lines)


def _notify_decision(event_key, state, now):
    """Dedup decision for a failure occurrence.

    `state` is the stored incident dict for this event key (or {}).
    Returns (send, new_state); the caller persists new_state.
    `send` is True on a new incident, on a 24h reminder while the
    incident is still open, or on an hourly retry after every channel
    failed last time.
    """
    state = dict(state or {})
    count = int(state.get("count") or 0) + 1
    last_sent = state.get("last_sent")
    last_attempt = state.get("last_attempt")
    if not state:
        return True, {"since": now, "last_attempt": now,
                      "last_sent": None, "count": count}
    if last_sent:
        if now - last_sent < NOTIFY_REMINDER_SECONDS:
            state["count"] = count
            return False, state
        state["count"] = count
        state["last_attempt"] = now
        return True, state
    if last_attempt and now - last_attempt < NOTIFY_RETRY_SECONDS:
        state["count"] = count
        return False, state
    state["count"] = count
    state["last_attempt"] = now
    return True, state


def clear_notify_incident(event_key):
    """Close a failure incident: the next occurrence is a new incident
    and notifies again."""
    with _config_lock:
        state = dict(_config.get("notify_state") or {})
        if event_key in state:
            del state[event_key]
            _config["notify_state"] = state
            save_config()


def notify_event(event_key, title, detail_lines, now=None):
    """Send a notification for `event_key` when it is enabled (and,
    for failure events, when the dedup rule allows it).

    The actual sends run in a daemon thread so a slow channel never
    blocks a run or a settings save; the dedup state is updated
    synchronously first. Returns a short summary dict. A send failure
    is also appended to the event log so a broken channel is visible.
    """
    if now is None:
        now = time.time()
    cfg = get_config_copy()
    if not _notify_enabled(cfg, event_key):
        return {"sent": [], "skipped": "该类通知未开启"}
    channels = _notify_channels(cfg)
    if not channels:
        return {"sent": [], "skipped": "未配置通知渠道"}
    text = _notify_text(title, detail_lines,
                        time.strftime("%Y-%m-%d %H:%M:%S",
                                      time.localtime(now)))
    if event_key in DEDUP_EVENTS:
        with _config_lock:
            state = dict((_config.get("notify_state") or {}).get(event_key)
                         or {})
            send, new_state = _notify_decision(event_key, state, now)
            merged = dict(_config.get("notify_state") or {})
            merged[event_key] = new_state
            _config["notify_state"] = merged
            save_config()
            if not send:
                return {"sent": [], "skipped": "同一故障已通知过（去重）"}
    proxy = (cfg.get("notify_proxy") or "").strip() or None

    def _send_all():
        for kind, sender, kwargs in channels:
            try:
                ok, err = sender(text=text, timeout=15, proxy=proxy,
                                 **kwargs)
            except Exception as exc:  # noqa: BLE001 - logged, no secret
                ok, err = False, str(exc)
            if not ok:
                label = "Telegram" if kind == "telegram" else "飞书"
                record_event("通知发送失败（%s）：%s" % (label, err))
            elif event_key in DEDUP_EVENTS:
                with _config_lock:
                    merged = dict(_config.get("notify_state") or {})
                    st = dict(merged.get(event_key) or {})
                    st["last_sent"] = now
                    merged[event_key] = st
                    _config["notify_state"] = merged
                save_config()

    threading.Thread(target=_send_all, daemon=True).start()
    return {"sent": [kind for kind, _s, _kw in channels], "skipped": ""}


def check_connectivity(timeout=8):
    """True when the NAS can reach the internet (direct, no proxy).

    A TCP connect to Cloudflare's 1.1.1.1:443 plus a DNS lookup of
    api.cloudflare.com; both must work, because every step of a run
    needs DNS and HTTPS to Cloudflare. Used only to record outages
    (see note_offline_change); a run is never skipped on its account,
    so a false negative only costs a log line, never a measurement.
    """
    try:
        sock = socket.create_connection(("1.1.1.1", 443), timeout=timeout)
        sock.close()
    except OSError:
        return False
    try:
        socket.getaddrinfo("api.cloudflare.com", 443)
    except OSError:
        return False
    return True


def note_offline_change(online, now=None):
    """Record an outage start, or notify on recovery.

    Called by the scheduler tick (the sole outage detector). While
    offline nothing can be sent, so the start time is only recorded;
    when connectivity returns, one notification is sent stating the
    outage window (from X to Y) and that the network is back. An
    outage shorter than MIN_OFFLINE_SECONDS is a blip and is not
    notified.
    """
    if now is None:
        now = time.time()
    cfg = get_config_copy()
    since = (cfg.get("notify_state") or {}).get("offline_since")
    if not online:
        if not since:
            with _config_lock:
                merged = dict(_config.get("notify_state") or {})
                merged["offline_since"] = now
                _config["notify_state"] = merged
            save_config()
            record_event("网络已断开（已记录断网开始时间，恢复后通知）")
        return
    if not since:
        return
    with _config_lock:
        merged = dict(_config.get("notify_state") or {})
        merged.pop("offline_since", None)
        _config["notify_state"] = merged
    save_config()
    if now - since < MIN_OFFLINE_SECONDS:
        return
    window = "%s 至 %s" % (
        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(since)),
        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)))
    detail = ["断网时段：%s" % window,
              "网络已恢复，测速与 DNS 更新将按计划继续。",
              "（断网期间发不出去，恢复后才补发，不是实时送达）"]
    domain = full_domain(cfg)
    if domain:
        detail.insert(0, "域名：%s" % domain)
    notify_event("offline", "网络已恢复", detail, now=now)
    record_event("网络已恢复（断网 %s）" % window)


# --------------------------------------------------------------------------
# Online upgrade (1.0.22): check the repo for a newer release and
# download its .fpk. Nothing is auto-installed: fnOS offers no
# supported way for an app to trigger its own reinstall, so the user
# installs the downloaded file from the app center (direct overwrite,
# config preserved).
# --------------------------------------------------------------------------

def check_update():
    """Check the repo for a newer release; store the result in
    config['update_check'] and return a status message."""
    try:
        latest, changelog = upgrade_mod.fetch_latest()
    except Exception as exc:  # noqa: BLE001 - shown in UI
        return "检查更新失败：%s" % exc
    cmp_result = upgrade_mod.compare_versions(VERSION, latest)
    with _config_lock:
        stored = dict(_config.get("update_check") or {})
        stored["latest"] = latest
        stored["changelog"] = changelog
        stored["checked_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        stored["available"] = bool(cmp_result is not None
                                   and cmp_result < 0)
        _config["update_check"] = stored
    save_config()
    if cmp_result is None:
        return "检查更新失败：仓库版本号无法解析（%s）" % latest
    if cmp_result < 0:
        return "发现新版本 %s（当前 %s）：%s" % (
            latest, VERSION, changelog or "（无更新日志）")
    return "已是最新版本（当前 %s，仓库最新 %s）" % (VERSION, latest)


def download_update():
    """Download the latest .fpk (per the stored check) into the data
    dir's updates/ folder. Returns a status message with the install
    guidance. Never auto-installs."""
    cfg = get_config_copy()
    stored = cfg.get("update_check") or {}
    latest = stored.get("latest") or ""
    if not stored.get("available") or not latest:
        return "没有可下载的新版本：请先点“检查更新”，确认有新版后再下载"
    dest_dir = os.path.join(DATA_DIR, "updates")
    try:
        path = upgrade_mod.download_fpk(latest, dest_dir)
    except Exception as exc:  # noqa: BLE001 - shown in UI
        return "下载失败：%s" % exc
    with _config_lock:
        stored2 = dict(_config.get("update_check") or {})
        stored2["downloaded"] = path
        stored2["downloaded_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        _config["update_check"] = stored2
    save_config()
    record_event("已下载新版 .fpk：%s" % path)
    return ("已下载新版 %s 到：\n%s\n\n安装方法：去飞牛应用中心 → "
            "手动安装（本地安装），选择这个 .fpk 文件，直接覆盖安装即可，"
            "配置会保留。装好后重启应用，版本号会变成 %s。"
            % (latest, path, latest))


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


def bundled_ip6_ranges_path():
    return os.path.join(APP_DIR, "ip6.txt")


def data_ip6_ranges_path():
    return os.path.join(DATA_DIR, "ip6.txt")


def ip6_file():
    """IPv6 measurement file: refreshed copy first, bundled otherwise."""
    for path in (data_ip6_ranges_path(), bundled_ip6_ranges_path()):
        if os.path.isfile(path) and os.path.getsize(path) > 0:
            return path
    return bundled_ip6_ranges_path()


def _valid_ip6_ranges(text):
    """True when `text` looks like a list of IPv6 CIDRs."""
    lines = [ln.strip() for ln in (text or "").splitlines()
             if ln.strip() and not ln.strip().startswith("#")]
    if not lines:
        return False
    import ipaddress
    good = 0
    for line in lines:
        try:
            net = ipaddress.ip_network(line, strict=False)
            if isinstance(net, ipaddress.IPv6Network):
                good += 1
        except ValueError:
            continue
    return good >= 3 and good >= len(lines) // 2


def refresh_ip6_ranges():
    """Refresh the IPv6 measurement ranges from the upstream repo
    (the curated ipv6.txt). Falls back to the bundled copy on failure:
    the bundled file is the same list, so a failed refresh loses
    nothing but freshness."""
    req = urllib.request.Request(
        IP6_RANGES_URL, headers={"User-Agent": "cf-bestipd/%s" % VERSION}
    )
    try:
        with _NO_PROXY_OPENER.open(req, timeout=15) as resp:
            text = resp.read().decode("utf-8", "ignore")
    except Exception as exc:  # noqa: BLE001 - report, keep old list
        return False, "刷新失败（沿用旧列表）：%s" % exc
    if not _valid_ip6_ranges(text):
        return False, "刷新失败：下载到的内容不是有效的 IPv6 段列表，已沿用旧列表"
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        _atomic_write(data_ip6_ranges_path(), text.encode("utf-8"))
    except OSError as exc:
        return False, "刷新失败（无法写入）：%s" % exc
    with _config_lock:
        _config["cf_ranges6_updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
    save_config()
    count = len([ln for ln in text.splitlines() if ln.strip()])
    return True, "已刷新 IPv6 段（%d 条）" % count


def check_ipv6_connectivity(timeout=5):
    """True when this host can reach Cloudflare over IPv6.

    A TCP connect to Cloudflare's 2606:4700:4700::1111:443. Used
    before an IPv6 run: without an IPv6 route the measurement would
    find nothing, so the run is skipped with a clear log line
    instead of a noisy 'no IPv6 found' failure.
    """
    try:
        sock = socket.create_connection(
            ("2606:4700:4700::1111", 443), timeout=timeout)
        sock.close()
        return True
    except OSError:
        return False


# --------------------------------------------------------------------------
# CloudflareSpeedTest binary (dual-architecture, 1.0.22)
#
# One .fpk serves ARM64 and x86_64 (manifest platform=all). The
# package bundles both binaries (app/cfst = arm64, app/cfst-amd64 =
# amd64); the host architecture is detected at runtime and the
# matching one is used. An unsupported architecture fails loudly
# here instead of silently running the wrong binary (which would
# die with an exec-format error deep inside a run).
# --------------------------------------------------------------------------

def detect_arch():
    """Return 'arm64' or 'amd64' for this host.

    Raises RuntimeError for anything else: the package only ships
    those two binaries, and picking one blindly would be wrong.
    """
    machine = (platform.machine() or "").strip().lower()
    if machine in ("aarch64", "arm64"):
        return "arm64"
    if machine in ("x86_64", "amd64"):
        return "amd64"
    raise RuntimeError(
        "不支持的设备架构：%s（本应用只支持 ARM64 与 x86_64）"
        % (machine or "未知"))


def _bundled_cfst_path(arch):
    """Bundled binary for `arch` (arm64 keeps the historic name)."""
    name = "cfst" if arch == "arm64" else "cfst-amd64"
    return os.path.join(APP_DIR, name)


def find_cfst_bin(arch=None):
    """Return a usable cfst binary path for `arch`, or None.

    Order: explicit env override (tests / manual), the downloaded
    binary for this arch, the bundled binary for this arch, then --
    arm64 only -- the legacy download location from before the
    dual-arch change (CFST_BIN_DIR/cfst), so existing arm64 installs
    do not re-download on upgrade.
    """
    if arch is None:
        arch = detect_arch()
    env_path = os.environ.get("CFBESTIPD_CFST_BIN")
    if env_path and os.path.isfile(env_path):
        return env_path
    downloaded = os.path.join(CFST_BIN_DIR, "cfst-" + arch)
    if os.path.isfile(downloaded):
        return downloaded
    bundled = _bundled_cfst_path(arch)
    if os.path.isfile(bundled):
        return bundled
    if arch == "arm64":
        legacy = os.path.join(CFST_BIN_DIR, "cfst")
        if os.path.isfile(legacy):
            return legacy
    return None


def _download_cfst(dest_path, arch=None):
    """Download the official cfst tarball for `arch` and extract it."""
    import tarfile

    if arch is None:
        arch = detect_arch()
    asset = CFST_ASSET_NAMES[arch]
    urls = []
    env_urls = os.environ.get("CFBESTIPD_CFST_URLS", "")
    if env_urls.strip():
        urls = [u.strip() for u in env_urls.split(",") if u.strip()]
    else:
        urls = [CFST_PINNED_URLS[arch]]
        # Fallback: ask GitHub API for the latest release asset.
        try:
            req = urllib.request.Request(
                CFST_API_LATEST,
                headers={"User-Agent": "cf-bestipd/%s" % VERSION,
                         "Accept": "application/vnd.github+json"},
            )
            with _NO_PROXY_OPENER.open(req, timeout=20) as resp:
                rel = json.loads(resp.read().decode("utf-8"))
            for item in rel.get("assets", []):
                if item.get("name") == asset:
                    urls.append(item["browser_download_url"])
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
        "或手动把 CloudflareSpeedTest 的 linux_%s 版 cfst 程序放到 %s"
        % (last_err, arch, dest_path)
    )


def ensure_cfst():
    """Return a usable cfst binary path, downloading it on first run."""
    arch = detect_arch()
    path = find_cfst_bin(arch)
    if path:
        try:
            os.chmod(path, 0o755)
        except OSError:
            pass
        return path
    dest = os.path.join(CFST_BIN_DIR, "cfst-" + arch)
    return _download_cfst(dest, arch)


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
    """One full cycle: measure best IPs, update DNS, rewrite subs.

    `scheduled` means the run was fired by the scheduler (not by the
    "run now" button): only a scheduled run in daily mode counts as
    the day's timed run, so a manual run never skips the 03:00 run.

    IPv4 is the core of the run: if its measurement fails, the run
    fails. IPv6 (when enabled) is independent and best-effort: a
    failed IPv6 measurement is logged and notified (no_ip6) but never
    fails the run, and the IPv4 results are still saved. DNS updates
    write the top-N IPs of the selected region as a record set
    (A for IPv4, AAAA for IPv6 when enabled); a DNS failure is not
    fatal either (stale records still work).
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

    cfg_before = get_config_copy()
    prev_ips = list(cfg_before.get("dns_record_ips") or [])
    prev_ips6 = list(cfg_before.get("dns_record_ips6") or [])
    ipv6_enabled = bool(cfg_before.get("ipv6_enabled"))
    dns_count = _dns_record_count(cfg_before)
    # IPv6 results are filled in below when enabled (None = not run).
    best_ip6 = None
    top_rows6 = []
    total_rows6 = 0
    fell_back6 = False
    ipv6_ran = False
    try:
        # 1. Refresh CF ranges (best effort, never fatal).
        ok, msg = refresh_cf_ranges()
        log_lines.append("IP 段：" + msg)
        networks = load_networks()
        if ipv6_enabled:
            ok6, msg6 = refresh_ip6_ranges()
            log_lines.append("IPv6 段：" + msg6)
        # 2. Measure IPv4.
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
        # The IPv4 ranges file only holds IPv4; drop anything that is
        # not a valid IPv4 address so a wrong file never leaks into
        # DNS or the subscription.
        top_rows = [r for r in top_rows if _is_ipv4(r.get("ip"))]
        if not top_rows or not _is_ipv4(best_ip):
            raise RuntimeError("没有可用的测速结果")
        best_ip = top_rows[0]["ip"]
        live_detail.clear()
        live_progress = ""
        log_lines.append("测速完成，最优 IP：%s" % best_ip)
        if fell_back:
            log_lines.append(
                "区域 %s 未找到可用 IP，已用全局最优" % region)
        _publish_live()
        # 2b. Measure IPv6 (independent, best-effort). Without an
        # IPv6 route the run is skipped with a clear line instead of
        # a noisy failure; a real measurement that finds nothing is
        # a no_ip6 failure event.
        if ipv6_enabled:
            if not check_ipv6_connectivity():
                log_lines.append(
                    "IPv6 未就绪（本机无 IPv6 出口），跳过本次 IPv6 测速")
            else:
                with _job_lock:
                    _job_stage = "测速中（IPv6）"
                try:
                    best_ip6, _log6, top_rows6, total_rows6, fell_back6 = (
                        cfst_mod.run_speedtest(
                            cfst_bin, ip6_file(), CFST_WORKDIR6,
                            on_line=_on_cfst_line, region=region,
                        )
                    )
                    # The IPv6 ranges file only holds IPv6; drop
                    # anything that is not a valid IPv6 address so a
                    # wrong file never writes IPv4 into an AAAA record.
                    top_rows6 = [r for r in top_rows6
                                 if _is_ipv6(r.get("ip"))]
                    if not top_rows6 or not _is_ipv6(best_ip6):
                        raise RuntimeError(
                            "没有可用的测速结果（未测到 IPv6）")
                    best_ip6 = top_rows6[0]["ip"]
                    ipv6_ran = True
                    live_detail.clear()
                    live_progress = ""
                    log_lines.append(
                        "IPv6 测速完成，最优 IPv6：%s" % best_ip6)
                    if fell_back6:
                        log_lines.append(
                            "区域 %s 未找到可用 IPv6，已用全局最优" % region)
                except Exception as exc:  # noqa: BLE001 - best-effort
                    log_lines.append("IPv6 测速失败：%s" % exc)
                    if "没有可用的测速结果" in str(exc):
                        notify_event("no_ip6", "测不到 IPv6", [
                            "域名：%s" % (full_domain() or "未配置"),
                            "原因：%s" % exc,
                            "请检查本机 IPv6 网络，或调整优选地区。",
                        ])
                _publish_live()
        # 3. Point the bound domain at the top-N IPs. A failure here
        # is not fatal: the records keep the previous IPs, which
        # still work, and the subscription output is stable anyway.
        target = full_domain()
        with _job_lock:
            _job_stage = "更新 DNS"
        top_ips = [r["ip"] for r in top_rows[:dns_count] if r.get("ip")]
        dns_msg = update_dns_now(top_ips, "A")
        log_lines.append("DNS：" + dns_msg)
        if ipv6_ran and dns_configured():
            top_ips6 = [r["ip"] for r in top_rows6[:dns_count]
                        if r.get("ip")]
            dns_msg6 = update_dns_now(top_ips6, "AAAA")
            log_lines.append("DNS（IPv6）：" + dns_msg6)
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
        new_ips = list(get_config_copy().get("dns_record_ips") or [])
        new_ips6 = list(get_config_copy().get("dns_record_ips6") or [])
        with _config_lock:
            _config["best_ip"] = best_ip
            _config["last_run"] = time.strftime("%Y-%m-%d %H:%M:%S")
            _config["last_log"] = "\n".join(log_lines)
            _config["event_log"] = "\n".join(log_lines[-20:])
            _config["last_results"] = top_rows
            _config["last_result_count"] = total_rows
            _config["last_region"] = region
            _config["last_region_fallback"] = fell_back
            if ipv6_ran:
                _config["best_ip6"] = best_ip6
                _config["last_results6"] = top_rows6
                _config["last_result_count6"] = total_rows6
                _config["last_region6"] = region
                _config["last_region_fallback6"] = fell_back6
            if scheduled and mode == "daily":
                _config["last_daily_run"] = time.strftime("%Y-%m-%d")
        save_config()
        # Optional notifications (off by default, user opts in).
        # A successful run closes the no-IP incidents.
        clear_notify_incident("no_ip")
        if ipv6_ran:
            clear_notify_incident("no_ip6")
        if new_ips != prev_ips or (ipv6_ran and new_ips6 != prev_ips6):
            detail = ["域名：%s" % (target or "未配置")]
            if new_ips != prev_ips:
                detail.append("IPv4（A 记录）：%s"
                              % ("、".join(new_ips) if new_ips else "无"))
            if ipv6_ran and new_ips6 != prev_ips6:
                detail.append("IPv6（AAAA 记录）：%s"
                              % ("、".join(new_ips6) if new_ips6 else "无"))
            notify_event("ip_change", "成功换 IP", detail)
        _notify_daily_result(best_ip, top_rows, total_rows, fell_back,
                             best_ip6 if ipv6_ran else None,
                             top_rows6 if ipv6_ran else [],
                             total_rows6 if ipv6_ran else 0,
                             fell_back6 if ipv6_ran else False,
                             region, target)
        return "\n".join(log_lines)
    except Exception as exc:  # noqa: BLE001 - shown in UI
        with _config_lock:
            _config["last_log"] = "\n".join(log_lines + ["失败：%s" % exc])
            _config["event_log"] = "\n".join(
                (log_lines + ["失败：%s" % exc])[-20:])
        save_config()
        if "没有可用的测速结果" in str(exc):
            notify_event("no_ip", "测不到 IP", [
                "域名：%s" % (full_domain() or "未配置"),
                "原因：%s" % exc,
                "请检查测速程序与网络，或调整优选地区。",
            ])
        return _config["last_log"]
    finally:
        with _job_lock:
            _job_running = False
            _job_stage = ""


def _notify_daily_result(best_ip, top_rows, total_rows, fell_back,
                         best_ip6, top_rows6, total_rows6, fell_back6,
                         region, target):
    """Routine speed-test summary (optional event, off by default).

    Fires after every successful run when the user switched it on.
    """
    if not top_rows:
        return
    best = top_rows[0]
    detail = [
        "域名：%s" % (target or "未配置"),
        "最优 IP：%s（延迟 %s ms，丢包率 %s，速度 %s MB/s）"
        % (best.get("ip", ""), best.get("latency", ""),
           best.get("loss", ""), best.get("speed", "")),
        "本次共测出 %d 个可用 IP" % total_rows,
    ]
    if fell_back:
        detail.append("区域 %s 未找到可用 IP，已用全局最优" % region)
    if best_ip6 and top_rows6:
        best6 = top_rows6[0]
        detail.append(
            "最优 IPv6：%s（延迟 %s ms，丢包率 %s，速度 %s MB/s）"
            % (best6.get("ip", ""), best6.get("latency", ""),
               best6.get("loss", ""), best6.get("speed", "")))
        detail.append("本次共测出 %d 个可用 IPv6" % total_rows6)
        if fell_back6:
            detail.append("区域 %s 未找到可用 IPv6，已用全局最优" % region)
    notify_event("daily_result", "测速结果", detail)


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
            # Connectivity probe (1.0.22): the sole outage detector.
            # Records an outage start while offline; on recovery it
            # sends the outage-window notification. A failed probe
            # never kills the scheduler. (Runs do not probe: the
            # measurement itself is the authority there.)
            try:
                note_offline_change(check_connectivity())
            except Exception:  # noqa: BLE001 - probe must never break the tick
                pass
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
/* Settings tabs: three functions in one dropdown. Buttons only
   hide/show panels in place, so half-filled forms keep their input.
   flex-wrap keeps the three labels on one row on a phone, or wraps
   them instead of overflowing. */
.settings .tabs{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px}
.settings .tab{flex:1 1 0;padding:7px 4px;margin:0;font-size:13px;white-space:nowrap;min-width:0}
.settings .tab.active{background:#1677ff;border-color:#1677ff;color:#fff}
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
/* Account settings panel: on a phone it becomes a full-width sheet
   pinned near the top of the screen, so the username/password form
   is not squeezed into a narrow dropdown anchored to the button. */
.settings .panel{position:fixed;top:12px;left:12px;right:12px;width:auto;max-width:none;max-height:calc(100vh - 24px);overflow-y:auto}
.settings .panel input[type=text],.settings .panel input[type=password]{max-width:none}
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


# Tab switching for the settings panel (see settings_html): only
# hides/shows panels in place, so form input is never lost. Kept as
# a plain string like TOGGLE_MODE_SCRIPT: the template is rendered
# with str.format(), which would choke on the braces in JavaScript.
# Inserted via the {settings_tabs_script} placeholder.
SETTINGS_TABS_SCRIPT = """
<script>
function showSettingsTab(name) {
  var tabs = ['account', 'notify', 'update'];
  for (var i = 0; i < tabs.length; i++) {
    var pane = document.getElementById('tab-' + tabs[i]);
    if (pane) pane.style.display = tabs[i] === name ? '' : 'none';
  }
  var buttons = document.querySelectorAll('.settings .tab');
  for (var j = 0; j < buttons.length; j++) {
    buttons[j].classList.toggle('active', buttons[j].getAttribute('data-tab') === name);
  }
}
showSettingsTab('account');
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
    # IPv6 results (second table, only when IPv6 is enabled). Same
    # columns and ranking as IPv4; the region filter applies to both.
    results6_html = ""
    if cfg.get("ipv6_enabled"):
        results6 = cfg.get("last_results6") or []
        if results6:
            best6 = results6[0]
            last_region6 = cfg.get("last_region6") or "all"
            if last_region6 != "all":
                if cfg.get("last_region_fallback6"):
                    region_note6 = ("优选地区 %s 没有可用 IPv6，"
                                    "已退回全局最优；"
                                    % _region_label(last_region6))
                else:
                    region_note6 = ("优选地区：%s；"
                                    % _region_label(last_region6))
            else:
                region_note6 = ""
            res_rows6 = []
            for i, r in enumerate(results6):
                mark = " ★最优" if i == 0 else ""
                res_rows6.append(
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
            results6_html = (
                "<h3>IPv6 测速结果</h3>"
                "<p>本次共测出 %d 个可用 IPv6，%s按丢包率、延迟、速度排前 %d 名"
                "如下；最优 IPv6：<b>%s</b>（延迟 %s ms，丢包率 %s，"
                "速度 %s MB/s）。</p>"
                "<div class=\"tbl\"><table><tr><th>IPv6</th><th>丢包率</th>"
                "<th>平均延迟（ms）</th><th>下载速度（MB/s）</th><th>地区</th></tr>"
                "%s</table></div>"
                % (cfg.get("last_result_count6") or len(results6),
                   region_note6, len(results6),
                   html.escape(str(best6.get("ip", ""))),
                   html.escape(str(best6.get("latency", ""))),
                   html.escape(str(best6.get("loss", ""))),
                   html.escape(str(best6.get("speed", ""))),
                   "\n".join(res_rows6))
            )
        elif cfg.get("best_ip6"):
            results6_html = (
                "<h3>IPv6 测速结果</h3><p>已有最优 IPv6 <b>%s</b>，"
                "但没有保存测速明细（可能是旧版本跑出的结果）。"
                "</p>" % html.escape(cfg["best_ip6"]))
        else:
            results6_html = (
                "<h3>IPv6 测速结果</h3><p>IPv6 已开启，尚未测出 IPv6 结果。"
                "</p>")
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
        dns_ips = cfg.get("dns_record_ips") or []
        dns_ips6 = cfg.get("dns_record_ips6") or []
        aaaa_kv = ""
        if cfg.get("ipv6_enabled"):
            aaaa_kv = (
                "<span class=\"kv\">AAAA 记录：<b>{dns_ip6}</b></span>"
                "<span class=\"kv\">AAAA 上次更新：{dns_updated6}</span>"
                "<span class=\"kv\">AAAA 状态：{dns_status6}</span>"
            ).format(
                dns_ip6=html.escape(
                    "、".join(dns_ips6) if dns_ips6 else "—"),
                dns_updated6=_fmt_time(cfg.get("dns_last_update6")),
                dns_status6=html.escape(
                    cfg.get("dns_last_error6") or "已绑定"),
            )
        binding_html = (
            "<p><span class=\"kv\">当前绑定：<b>{domain}</b>"
            "（Zone：{zone}，记录名：{record}）</span>"
            "<span class=\"kv\">API 令牌：已保存"
            "（页面上永远不显示令牌本身）</span>"
            "<span class=\"kv\">绑定保存时间：{saved}</span>"
            "<span class=\"kv\">A 记录（{count} 条）：<b>{dns_ip}</b></span>"
            "{aaaa_kv}"
            "<span class=\"kv\">DNS 上次更新：{dns_updated}</span>"
            "<span class=\"kv\">DNS 状态：{dns_status}</span></p>"
            .format(
                domain=html.escape(full_domain(cfg)),
                zone=html.escape(cfg.get("cf_zone") or ""),
                record=html.escape(cfg.get("cf_record") or ""),
                saved=_fmt_time(cfg.get("cf_binding_saved")),
                count=_dns_record_count(cfg),
                dns_ip=html.escape(
                    "、".join(dns_ips) if dns_ips
                    else (cfg.get("dns_record_ip") or "—")),
                aaaa_kv=aaaa_kv,
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
    # The top-right "设置" panel (three tabs: account, notifications,
    # online upgrade) is built below, after the notification and
    # upgrade sections it embeds.
    mode = _schedule_mode(cfg)
    schedule_hour, schedule_minute = _schedule_time(cfg)
    region_options = "".join(
        '<option value="{code}"{selected}>{label}</option>'.format(
            code=code, label=html.escape(label),
            selected=" selected" if code == _region(cfg) else "",
        )
        for code, label in REGION_OPTIONS
    )
    # DNS record count form (in the binding card): how many top IPs
    # are written as records for the name (1-5, default 5).
    dns_count_html = (
        "<form method=\"post\" action=\"/api/dns/count\">"
        "<p>DNS 记录数量：<input type=\"number\" name=\"dns_record_count\" "
        "min=\"1\" max=\"5\" value=\"{count}\"> 条（1–5，默认 5） "
        "<button type=\"submit\">保存数量</button></p>"
        "<p class=\"muted\">每次更新把同区域测速排前 N 的 IP 各写一条 A 记录"
        "（同一域名多条记录，冗余和分流）；IPv6 开启时 AAAA 记录同理。"
        "更新时先清理该域名下旧的记录再写入新集合，不会越积越多。"
        "改数量后下次更新生效。</p></form>"
    ).format(count=_dns_record_count(cfg))
    # Notification settings (1.0.22): inner content only, no card
    # wrapper -- it is shown as a tab inside the settings panel.
    notify_inner = (
        "<h2>通知设置</h2>"
        "<form method=\"post\" action=\"/api/notify/save\">"
        "<p>Telegram 机器人：<label><input type=\"checkbox\" "
        "name=\"notify_tg_enabled\"{tg_checked}> 启用</label><br>"
        "Bot Token（留空不改）：<br><input type=\"password\" "
        "name=\"notify_tg_token\" autocomplete=\"off\" "
        "placeholder=\"{tg_token_hint}\"></p>"
        "<p>Chat ID：<br><input type=\"text\" name=\"notify_tg_chat_id\" "
        "value=\"{tg_chat_id}\"></p>"
        "<p>飞书机器人：<label><input type=\"checkbox\" "
        "name=\"notify_fs_enabled\"{fs_checked}> 启用</label><br>"
        "Webhook 地址（留空不改）：<br><input type=\"password\" "
        "name=\"notify_fs_webhook\" autocomplete=\"off\" "
        "placeholder=\"{fs_webhook_hint}\"></p>"
        "<p>签名密钥（可选，留空不改）：<br><input type=\"password\" "
        "name=\"notify_fs_secret\" autocomplete=\"off\" "
        "placeholder=\"{fs_secret_hint}\"></p>"
        "<p>通知代理（可选，例如 Clash 混合代理 "
        "http://127.0.0.1:7890）：<br><input type=\"text\" "
        "name=\"notify_proxy\" value=\"{notify_proxy}\"></p>"
        "<p class=\"muted\">Telegram 在国内直连通常不通，需要填一个能出海的"
        "代理；飞书是国内服务，一般直连即可。</p>"
        "<p>通知事件：<br>"
        "<label><input type=\"checkbox\" name=\"notify_failure\""
        "{failure_checked}> 故障通知（测不到 IP / 域名异常 / 断网，"
        "默认开）</label><br>"
        "<label><input type=\"checkbox\" name=\"notify_ip_change\""
        "{ipchange_checked}> 成功换 IP（默认关）</label><br>"
        "<label><input type=\"checkbox\" name=\"notify_daily_result\""
        "{daily_checked}> 日常测速结果（默认关）</label></p>"
        "<p><button class=\"primary\" type=\"submit\">保存通知设置</button>"
        "</p></form>"
        "<form method=\"post\" action=\"/api/notify/test\">"
        "<input type=\"hidden\" name=\"channel\" value=\"telegram\">"
        "<button type=\"submit\">测试 Telegram</button></form> "
        "<form method=\"post\" action=\"/api/notify/test\">"
        "<input type=\"hidden\" name=\"channel\" value=\"feishu\">"
        "<button type=\"submit\">测试飞书</button></form>"
        "<p class=\"muted\">故障通知同一故障只发一次（故障消除后下次再发；"
        "持续超过 24 小时每天补发一次提醒；发送失败每小时最多重试一次）。"
        "断网时发不出去，恢复后补发并注明断网时段。令牌、密钥只存在本机，"
        "页面上永远不显示。</p>"
    ).format(
        tg_checked=" checked" if cfg.get("notify_tg_enabled") else "",
        tg_token_hint=(
            "已保存令牌（留空不改）" if (cfg.get("notify_tg_token") or "")
            else "尚未保存令牌"),
        tg_chat_id=html.escape(cfg.get("notify_tg_chat_id") or ""),
        fs_checked=" checked" if cfg.get("notify_fs_enabled") else "",
        fs_webhook_hint=(
            "已保存地址（留空不改）" if (cfg.get("notify_fs_webhook") or "")
            else "尚未保存地址"),
        fs_secret_hint=(
            "已保存密钥（留空不改）" if (cfg.get("notify_fs_secret") or "")
            else "未设置签名密钥"),
        notify_proxy=html.escape(cfg.get("notify_proxy") or ""),
        failure_checked=" checked" if cfg.get("notify_failure", True) else "",
        ipchange_checked=" checked" if cfg.get("notify_ip_change") else "",
        daily_checked=" checked" if cfg.get("notify_daily_result") else "",
    )
    # Online upgrade (1.0.22): inner content only, no card wrapper --
    # it is shown as a tab inside the settings panel.
    upd = cfg.get("update_check") or {}
    upd_latest = upd.get("latest") or "未检查"
    upd_changelog = upd.get("changelog") or ""
    upd_checked = upd.get("checked_at") or "—"
    upd_downloaded = upd.get("downloaded") or ""
    changelog_html = (
        "<p>更新内容：%s</p>" % html.escape(upd_changelog)
        if upd_changelog else ""
    )
    download_form = (
        "<form method=\"post\" action=\"/api/update/download\">"
        "<button class=\"primary\" type=\"submit\">下载新版 .fpk</button>"
        "</form> "
        if upd.get("available") else ""
    )
    downloaded_html = (
        "<p>已下载到：<br><code>%s</code></p>"
        % html.escape(upd_downloaded)
        if upd_downloaded else ""
    )
    update_inner = (
        "<h2>在线升级</h2>"
        "<p><span class=\"kv\">当前版本：<b>{current}</b></span>"
        "<span class=\"kv\">仓库最新：<b>{latest}</b></span>"
        "<span class=\"kv\">上次检查：{checked}</span></p>"
        "{changelog_html}"
        "<form method=\"post\" action=\"/api/update/check\">"
        "<button type=\"submit\">检查更新</button></form> "
        "{download_form}"
        "{downloaded_html}"
        "<p class=\"muted\">检查的是公开仓库 liweisi07/cf-bestip-fpk 里的 "
        "manifest。下载后去飞牛应用中心 → 手动安装（本地安装），选择下载的 "
        ".fpk 文件直接覆盖安装，配置会保留；不会自动安装。</p>"
    ).format(
        current=VERSION,
        latest=html.escape(upd_latest),
        checked=html.escape(upd_checked),
        changelog_html=changelog_html,
        download_form=download_form,
        downloaded_html=downloaded_html,
    )
    # Settings live behind the top-right "设置" button, as three tabs:
    # account/password, notifications and online upgrade. The tab
    # buttons only hide/show panels in place (SETTINGS_TABS_SCRIPT),
    # so half-filled forms keep their input; after a refresh the
    # account tab is shown again. The three panels are the existing
    # account form, notification settings and online upgrade
    # sections, moved here unchanged. The password itself is never
    # shown; only its hash is stored.
    settings_html = (
        "<details class=\"settings\"><summary>⚙ 设置</summary>"
        "<div class=\"panel\">"
        "<div class=\"tabs\">"
        "<button type=\"button\" class=\"tab active\" data-tab=\"account\" "
        "onclick=\"showSettingsTab('account')\">账号密码设置</button>"
        "<button type=\"button\" class=\"tab\" data-tab=\"notify\" "
        "onclick=\"showSettingsTab('notify')\">通知设置</button>"
        "<button type=\"button\" class=\"tab\" data-tab=\"update\" "
        "onclick=\"showSettingsTab('update')\">检查更新</button>"
        "</div>"
        "<div class=\"tabpane\" id=\"tab-account\">"
        "<h2>账号设置</h2>"
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
        "<button type=\"submit\">退出登录</button></form>"
        "</div>"
        "<div class=\"tabpane\" id=\"tab-notify\">"
        "{notify_inner}"
        "</div>"
        "<div class=\"tabpane\" id=\"tab-update\">"
        "{update_inner}"
        "</div>"
        "</div></details>"
        .format(
            username=html.escape(get_auth()["username"]),
            minlen=MIN_PASSWORD_LEN,
            notify_inner=notify_inner,
            update_inner=update_inner,
        )
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
{results_html}{results6_html}</div>
<div class="card" id="binding"><h2>域名绑定</h2>
{binding_html}{dns_count_html}
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
<p><label><input type="checkbox" name="ipv6_enabled"{checked_ipv6}> 启用 IPv6 优选</label></p>
<p class="muted">开启后每次测速还会测 IPv6（需要本机有 IPv6 出口），把同区域前 N 的 IPv6 各写一条 AAAA 记录；与 IPv4 各自独立优选、各自更新。关掉则只优选 IPv4。</p>
<p><button class="primary" type="submit">保存</button></p>
</form></div>
{toggle_script}
{settings_tabs_script}
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
        results6_html=results6_html,
        binding_html=binding_html,
        dns_count_html=dns_count_html,
        settings_tabs_script=SETTINGS_TABS_SCRIPT,
        details_open=details_open,
        interval_days=interval_days,
        interval_hours=interval_hours,
        interval_minutes=interval_minutes,
        checked_interval=" checked" if mode == "interval" else "",
        checked_daily=" checked" if mode == "daily" else "",
        checked_ipv6=" checked" if cfg.get("ipv6_enabled") else "",
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
                "best_ip6": cfg.get("best_ip6"),
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
                "last_results6": cfg.get("last_results6") or [],
                "last_result_count6": cfg.get("last_result_count6") or 0,
                "domain": full_domain(cfg),
                "dns_configured": dns_configured(cfg),
                "dns_record_ip": cfg.get("dns_record_ip"),
                "dns_record_ips": cfg.get("dns_record_ips") or [],
                "dns_record_ip6": cfg.get("dns_record_ip6"),
                "dns_record_ips6": cfg.get("dns_record_ips6") or [],
                "dns_last_update": cfg.get("dns_last_update"),
                "dns_last_error": cfg.get("dns_last_error"),
                "dns_last_error6": cfg.get("dns_last_error6") or "",
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
            ok6, msg6 = refresh_ip6_ranges()
            record_event("IPv6 段：" + msg6)
            self._redirect(msg + "\n" + msg6)
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
                    _config["dns_record_ips"] = []
                    _config["dns_last_update"] = None
                    _config["dns_last_error"] = ""
                    _config["dns_record_ip6"] = None
                    _config["dns_record_ips6"] = []
                    _config["dns_last_update6"] = None
                    _config["dns_last_error6"] = ""
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
                _config["dns_record_ips"] = []
                _config["dns_last_update"] = None
                _config["dns_last_error"] = ""
                _config["dns_record_ip6"] = None
                _config["dns_record_ips6"] = []
                _config["dns_last_update6"] = None
                _config["dns_last_error6"] = ""
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
                _config["best_ip6"] = None
                _config["last_run"] = None
                _config["last_daily_run"] = None
                _config["last_region"] = None
                _config["last_region_fallback"] = False
                _config["last_region6"] = None
                _config["last_region_fallback6"] = False
                _config["last_log"] = ""
                _config["event_log"] = ""
                _config["last_results"] = []
                _config["last_result_count"] = 0
                _config["last_results6"] = []
                _config["last_result_count6"] = 0
                _config["cf_token"] = ""
                _config["cf_zone"] = ""
                _config["cf_record"] = "cf"
                _config["cf_binding_saved"] = None
                _config["dns_record_ip"] = None
                _config["dns_record_ips"] = []
                _config["dns_last_update"] = None
                _config["dns_last_error"] = ""
                _config["dns_record_ip6"] = None
                _config["dns_record_ips6"] = []
                _config["dns_last_update6"] = None
                _config["dns_last_error6"] = ""
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
            top_ips = _top_ips_for_dns(cfg, "A")
            if not top_ips:
                self._redirect(
                    "尚未测速，没有可用的最优 IP：请先点“立即测速并更新”"
                )
                return
            msgs = []
            msg = update_dns_now(top_ips, "A")
            msgs.append(msg if msg.startswith("DNS") else "DNS：" + msg)
            record_event(msgs[0])
            if cfg.get("ipv6_enabled"):
                top_ips6 = _top_ips_for_dns(cfg, "AAAA")
                if top_ips6:
                    msg6 = update_dns_now(top_ips6, "AAAA")
                    msgs.append(msg6 if msg6.startswith("DNS")
                                else "DNS（IPv6）：" + msg6)
                    record_event(msgs[-1])
            self._redirect("\n".join(msgs))
            return
        if path == "/api/dns/count":
            try:
                count = int(form.get("dns_record_count") or 0)
            except ValueError:
                self._redirect("记录数量无效：请输入 1 到 5")
                return
            if not 1 <= count <= 5:
                self._redirect("记录数量无效：请输入 1 到 5")
                return
            with _config_lock:
                _config["dns_record_count"] = count
            save_config()
            record_event("DNS 记录数量改为 %d 条" % count)
            self._redirect(
                "DNS 记录数量已保存为 %d 条（下次更新生效）" % count)
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
            ipv6_enabled = bool(form.get("ipv6_enabled"))
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
                    _config["ipv6_enabled"] = ipv6_enabled
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
                _config["ipv6_enabled"] = ipv6_enabled
            save_config()
            text = _fmt_interval(days, hours, minutes)
            record_event("测速间隔改为 %s" % text)
            self._redirect("测速间隔已保存为 %s" % text)
            return
        if path == "/api/notify/save":
            # Empty secret fields mean "keep the saved value": the
            # page never shows them, so a blank field cannot mean
            # clear. Chat ID and proxy are plain values (blank clears).
            tg_token = (form.get("notify_tg_token") or "").strip()
            fs_webhook = (form.get("notify_fs_webhook") or "").strip()
            fs_secret = (form.get("notify_fs_secret") or "").strip()
            tg_chat_id = (form.get("notify_tg_chat_id") or "").strip()
            proxy = (form.get("notify_proxy") or "").strip()
            if fs_webhook and not (
                    fs_webhook.startswith("http://")
                    or fs_webhook.startswith("https://")):
                self._redirect("飞书 Webhook 地址无效：必须是 http(s) 地址")
                return
            if proxy and not (
                    proxy.startswith("http://")
                    or proxy.startswith("https://")):
                self._redirect("通知代理无效：必须是 http(s) 地址")
                return
            with _config_lock:
                if tg_token:
                    _config["notify_tg_token"] = tg_token
                _config["notify_tg_chat_id"] = tg_chat_id
                _config["notify_tg_enabled"] = bool(
                    form.get("notify_tg_enabled"))
                if fs_webhook:
                    _config["notify_fs_webhook"] = fs_webhook
                if fs_secret:
                    _config["notify_fs_secret"] = fs_secret
                _config["notify_fs_enabled"] = bool(
                    form.get("notify_fs_enabled"))
                _config["notify_proxy"] = proxy
                _config["notify_failure"] = bool(
                    form.get("notify_failure"))
                _config["notify_ip_change"] = bool(
                    form.get("notify_ip_change"))
                _config["notify_daily_result"] = bool(
                    form.get("notify_daily_result"))
            save_config()
            self._redirect("通知设置已保存")
            return
        if path == "/api/notify/test":
            channel = (form.get("channel") or "").strip()
            cfg = get_config_copy()
            text = _notify_text("测试通知", [
                "这是一条测试消息，说明通知已接通。",
            ])
            proxy = (cfg.get("notify_proxy") or "").strip() or None
            if channel == "telegram":
                token = (cfg.get("notify_tg_token") or "").strip()
                chat_id = (cfg.get("notify_tg_chat_id") or "").strip()
                if not token or not chat_id:
                    self._redirect(
                        "Telegram 未配置：请先填 Bot Token 和 Chat ID")
                    return
                ok, err = notify_mod.send_telegram(
                    token, chat_id, text, timeout=15, proxy=proxy)
                if ok:
                    self._redirect("Telegram 测试通知已发送，请查看聊天")
                else:
                    self._redirect(
                        "Telegram 测试发送失败：%s（国内直连通常不通，"
                        "请在通知设置里填通知代理，如 Clash 混合代理）" % err)
                return
            if channel == "feishu":
                webhook = (cfg.get("notify_fs_webhook") or "").strip()
                if not webhook:
                    self._redirect("飞书未配置：请先填 Webhook 地址")
                    return
                ok, err = notify_mod.send_feishu(
                    webhook, cfg.get("notify_fs_secret") or "", text,
                    timeout=15, proxy=proxy)
                if ok:
                    self._redirect("飞书测试通知已发送，请查看群聊")
                else:
                    self._redirect("飞书测试发送失败：%s" % err)
                return
            self._redirect("测试渠道无效")
            return
        if path == "/api/update/check":
            msg = check_update()
            self._redirect(msg)
            return
        if path == "/api/update/download":
            msg = download_update()
            self._redirect(msg)
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
