"""Outbound notifications for cf-bestipd (Telegram + Feishu).

Only Python's standard library is used. The senders here are dumb:
they take a ready-made text and deliver it to one channel, returning
(ok, error). All decisions (which events are enabled, dedup) live in
app.py; this module never sees the config and never logs secrets.

Telegram: POST https://api.telegram.org/bot<token>/sendMessage.
  The token only ever appears in the request URL, never in a returned
  error string or a log line.

Feishu (Lark): POST to the user-provided incoming-webhook URL with
  {"msg_type": "text", "content": {"text": ...}}. When a signing
  secret is configured, the body also carries "timestamp" and "sign"
  (Feishu's custom-bot signature: sign = base64(HMAC-SHA256(
  timestamp + "\\n" + secret, secret))).

Proxy: notification sends are NOT measurements, so they may use an
optional user-configured HTTP proxy (e.g. the NAS Clash mixed port
http://127.0.0.1:7890). Telegram is not directly reachable from
mainland China, so it usually needs such a proxy; Feishu is a Chinese
service and normally works direct. When no proxy is given, sends are
direct (no proxy env vars are honoured, matching the rest of the app).
"""

import base64
import hashlib
import hmac
import json
import urllib.error
import urllib.parse
import urllib.request

TELEGRAM_API = "https://api.telegram.org/bot%s/sendMessage"
DEFAULT_TIMEOUT = 15


def _make_opener(proxy=None):
    """An opener that uses `proxy` (an http:// URL) when given,
    otherwise a direct connection (proxy env vars ignored)."""
    if proxy:
        proxy = (proxy or "").strip()
    if proxy:
        return urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _post_json(url, payload, timeout, proxy=None, opener=None):
    """POST a JSON body. Returns (ok, error_string).

    `opener` is only for tests (a fake opener); production callers
    leave it as None. The URL is never included in the error string,
    so a Telegram token in the URL can never leak into a log.
    """
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"},
        method="POST")
    used = opener if opener is not None else _make_opener(proxy)
    try:
        with used.open(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            parsed = json.loads(exc.read().decode("utf-8", "ignore"))
            detail = parsed.get("description") or parsed.get("msg") or ""
        except (ValueError, UnicodeDecodeError):
            pass
        return False, "HTTP %d%s" % (
            exc.code, ("：" + detail) if detail else "")
    except Exception as exc:  # noqa: BLE001 - surfaced to the UI/log
        return False, str(exc)
    try:
        parsed = json.loads(body)
    except ValueError:
        return True, ""
    if isinstance(parsed, dict) and parsed.get("ok") is False:
        return False, str(parsed.get("description") or parsed.get("msg")
                          or "对方返回失败")
    if isinstance(parsed, dict) and parsed.get("code") not in (None, 0):
        return False, str(parsed.get("msg") or "对方返回失败")
    return True, ""


def send_telegram(token, chat_id, text, timeout=DEFAULT_TIMEOUT,
                  proxy=None, opener=None):
    """Send `text` to a Telegram chat. Returns (ok, error).

    `token` is the bot token, `chat_id` the chat id (number or string,
    e.g. "-100..." for a group). Neither is ever in the error string.
    """
    token = (token or "").strip()
    chat_id = (chat_id or "").strip()
    if not token or not chat_id:
        return False, "未配置 Telegram 机器人令牌或 Chat ID"
    if not text:
        return False, "消息为空"
    url = TELEGRAM_API % token
    return _post_json(url, {"chat_id": chat_id, "text": text},
                      timeout, proxy=proxy, opener=opener)


def feishu_sign(secret, timestamp):
    """Feishu custom-bot signature for `timestamp` (seconds, str)."""
    string_to_sign = "%s\n%s" % (timestamp, secret)
    digest = hmac.new(secret.encode("utf-8"),
                      string_to_sign.encode("utf-8"),
                      hashlib.sha256).digest()
    return base64.b64encode(digest).decode("utf-8")


def send_feishu(webhook_url, secret, text, timeout=DEFAULT_TIMEOUT,
                proxy=None, opener=None, timestamp=None):
    """Send `text` to a Feishu incoming webhook. Returns (ok, error).

    `secret` is the optional signing secret (empty when the webhook
    has signing disabled). The webhook URL and the secret never appear
    in the error string.
    """
    webhook_url = (webhook_url or "").strip()
    if not webhook_url:
        return False, "未配置飞书 Webhook 地址"
    if not (webhook_url.startswith("http://")
            or webhook_url.startswith("https://")):
        return False, "飞书 Webhook 地址无效：必须是 http(s) 地址"
    if not text:
        return False, "消息为空"
    payload = {"msg_type": "text", "content": {"text": text}}
    secret = (secret or "").strip()
    if secret:
        import time
        ts = str(timestamp if timestamp is not None
                 else int(time.time()))
        payload["timestamp"] = ts
        payload["sign"] = feishu_sign(secret, ts)
    return _post_json(webhook_url, payload, timeout,
                      proxy=proxy, opener=opener)


def mask_secret(value):
    """A safe display form of a stored secret (never the value)."""
    if not value:
        return "未配置"
    return "已保存"
