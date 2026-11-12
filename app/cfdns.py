"""Cloudflare DNS client for the domain edition of cf-bestip.

One job: point one A record at the measured best Cloudflare IP.

  * The record is always created/updated with ``proxied: false``
    (DNS-only, gray cloud). A proxied (orange cloud) record would make
    the domain resolve to Cloudflare's anycast IPs instead of the
    preferred IP, which would defeat the whole point.
  * TTL is 60 seconds when the API accepts it, so clients pick up a new
    IP within about a minute; if the API rejects 60, it falls back to
    TTL "auto" (1) and says so in the result message.
  * The API token is never included in any error message, log line or
    returned string. It is only ever sent in the Authorization header.

Only Python's standard library is used.
"""

import ipaddress
import json
import re
import urllib.error
import urllib.parse
import urllib.request

API_BASE = "https://api.cloudflare.com/client/v4"
DEFAULT_TTL = 60

_NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class DNSApiError(RuntimeError):
    """A Cloudflare API failure, with the token never in the message."""


def clean_token(token):
    """Strip paste artifacts from a Cloudflare API token.

    A valid API token only contains letters, digits, underscore and
    hyphen, so removing every whitespace character and surrounding
    quotes can never damage a good token -- but a token pasted with an
    inner space, a line wrap or surrounding quotes makes Cloudflare
    reject the request with HTTP 400 "Invalid request headers".
    """
    cleaned = re.sub(r"\s+", "", token or "")
    cleaned = cleaned.strip("\"'")
    return cleaned


def _request(method, path, token, payload=None):
    """One Cloudflare API call. Returns the decoded JSON body."""
    url = API_BASE + path
    data = None
    headers = {
        "Authorization": "Bearer %s" % token,
        "Content-Type": "application/json",
    }
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers,
                                 method=method)
    try:
        with _NO_PROXY_OPENER.open(req, timeout=20) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            body = json.loads(exc.read().decode("utf-8"))
            errors = body.get("errors") or []
            if errors:
                detail = errors[0].get("message") or ""
        except (ValueError, UnicodeDecodeError):
            pass
        if exc.code == 400 and re.fullmatch(
                r"[0-9a-fA-F]{37}", token or ""):
            # A 37-char hex string is a Global API Key, not an API
            # Token: used as a Bearer token it fails header validation.
            detail += ("（这串凭证看起来像 Global API Key，不是 API Token："
                       "请到 Cloudflare 后台 My Profile → API Tokens 里"
                       "复制 API Token，而不是页面下方的 Global API Key）")
        raise DNSApiError(
            "Cloudflare API 返回 HTTP %d%s"
            % (exc.code, ("：" + detail) if detail else "")
        )
    except DNSApiError:
        raise
    except Exception as exc:  # noqa: BLE001 - surfaced to the UI
        raise DNSApiError("请求 Cloudflare API 失败：%s" % exc)


def full_record_name(zone, prefix):
    """Full DNS name for a zone + record prefix ('@'/'' means the zone)."""
    prefix = (prefix or "").strip().strip(".")
    zone = (zone or "").strip().strip(".")
    if not prefix or prefix == "@":
        return zone
    return prefix + "." + zone


def _check_success(body, what):
    if not isinstance(body, dict) or not body.get("success"):
        errors = body.get("errors") if isinstance(body, dict) else None
        detail = ""
        if errors:
            detail = errors[0].get("message") or ""
        raise DNSApiError(
            "%s失败%s" % (what, ("：" + detail) if detail else "")
        )
    return body.get("result")


def get_zone_id(token, zone):
    """Resolve a zone (apex domain) name to its Cloudflare zone id."""
    path = "/zones?name=%s" % urllib.parse.quote(zone)
    result = _check_success(_request("GET", path, token), "查找域名 Zone")
    if not result:
        raise DNSApiError(
            "找不到域名 %s 对应的 Zone：请确认域名拼写、令牌有该 Zone 的 "
            "DNS 编辑权限，且该域名的 DNS 已托管在 Cloudflare" % zone
        )
    return result[0]["id"]


def find_record(token, zone_id, full_name):
    """Return the existing A record dict for full_name, or None."""
    path = (
        "/zones/%s/dns_records?type=A&name=%s"
        % (urllib.parse.quote(zone_id),
           urllib.parse.quote(full_name))
    )
    result = _check_success(_request("GET", path, token), "查询 DNS 记录")
    if not result:
        return None
    return result[0]


def _write_record(method, path, token, full_name, ip, ttl):
    payload = {
        "type": "A",
        "name": full_name,
        "content": ip,
        "proxied": False,
        "ttl": ttl,
    }
    result = _check_success(
        _request(method, path, token, payload), "写入 DNS 记录"
    )
    return result


def _write_with_ttl_fallback(method, path, token, full_name, ip):
    """Write with TTL 60, falling back to auto (1) if 60 is rejected."""
    try:
        _write_record(method, path, token, full_name, ip, DEFAULT_TTL)
        return DEFAULT_TTL
    except DNSApiError as exc:
        if "ttl" not in str(exc).lower() and "TTL" not in str(exc):
            raise
        _write_record(method, path, token, full_name, ip, 1)
        return 1


def ensure_record(token, zone, prefix, ip):
    """Point the record at ip. Returns (record_ip, ttl_used, message).

    Creates the A record when it does not exist, updates it when it
    does. After writing, the record is read back to confirm the value.
    Raises DNSApiError on any failure; the token never appears in it.
    """
    token = clean_token(token)
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        raise DNSApiError("最优 IP 无效：%s" % ip)
    zone = (zone or "").strip().strip(".")
    if not zone:
        raise DNSApiError("未填写域名（Zone）")
    full_name = full_record_name(zone, prefix)
    zone_id = get_zone_id(token, zone)
    existing = find_record(token, zone_id, full_name)
    if existing:
        path = "/zones/%s/dns_records/%s" % (
            urllib.parse.quote(zone_id),
            urllib.parse.quote(existing["id"]),
        )
        ttl_used = _write_with_ttl_fallback(
            "PATCH", path, token, full_name, ip
        )
        action = "已更新"
    else:
        path = "/zones/%s/dns_records" % urllib.parse.quote(zone_id)
        ttl_used = _write_with_ttl_fallback(
            "POST", path, token, full_name, ip
        )
        action = "已创建"
    confirmed = find_record(token, zone_id, full_name)
    if not confirmed or confirmed.get("content") != ip:
        raise DNSApiError(
            "DNS 记录写入后回查不一致（期望 %s），请到 Cloudflare 后台核对"
            % ip
        )
    if confirmed.get("proxied"):
        raise DNSApiError(
            "记录 %s 当前是代理状态（小黄云），请到 Cloudflare 后台把它改成 "
            "仅 DNS（灰云），否则解析出来的是任播 IP 而不是优选 IP"
            % full_name
        )
    ttl_text = "TTL 60 秒" if ttl_used == DEFAULT_TTL else "TTL 自动"
    return ip, ttl_used, "%s DNS 记录 %s -> %s（仅 DNS，%s）" % (
        action, full_name, ip, ttl_text
    )
