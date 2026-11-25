"""Unit tests for app/notify.py (Telegram + Feishu senders) and the
dedup decision in app/app.py. Sends are exercised through a fake
opener (no real network); the Feishu signature is checked against a
hand-computed value; the dedup rule is checked directly.
"""

import base64
import hashlib
import hmac
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import notify

TMP = tempfile.mkdtemp(prefix="cfbestipd-notify-test-")
os.environ["CFBESTIPD_DATA_DIR"] = TMP

import app  # noqa: E402


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
    """Records requests; answers from a scripted (status, payload)."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.calls = []

    def open(self, req, timeout=None):
        try:
            payload = json.loads(req.data.decode("utf-8")) \
                if req.data else None
        except (ValueError, UnicodeDecodeError):
            payload = None
        self.calls.append({"url": req.full_url, "payload": payload})
        if not self.answers:
            raise AssertionError("unexpected call: %s" % req.full_url)
        status, body = self.answers.pop(0)
        if status != 200:
            raise urllib.error.HTTPError(
                req.full_url, status, "error", {}, io.BytesIO(
                    json.dumps(body).encode("utf-8")))
        return FakeResponse(body)


class NotifyTest(unittest.TestCase):
    def test_telegram_success(self):
        opener = FakeOpener([(200, {"ok": True, "result": {}})])
        ok, err = notify.send_telegram(
            "TOKEN123", "12345", "hello", opener=opener)
        self.assertTrue(ok)
        self.assertEqual(err, "")
        self.assertEqual(len(opener.calls), 1)
        call = opener.calls[0]
        self.assertTrue(call["url"].startswith(
            "https://api.telegram.org/botTOKEN123/sendMessage"))
        self.assertEqual(call["payload"],
                         {"chat_id": "12345", "text": "hello"})

    def test_telegram_api_error(self):
        opener = FakeOpener([(200, {"ok": False,
                                     "description": "chat not found"})])
        ok, err = notify.send_telegram(
            "TOKEN123", "12345", "hello", opener=opener)
        self.assertFalse(ok)
        self.assertIn("chat not found", err)
        # The token never appears in the error string.
        self.assertNotIn("TOKEN123", err)

    def test_telegram_missing_config(self):
        ok, err = notify.send_telegram("", "12345", "hello")
        self.assertFalse(ok)
        self.assertIn("未配置", err)

    def test_feishu_plain_text(self):
        opener = FakeOpener([(200, {"code": 0, "msg": "success"})])
        ok, err = notify.send_feishu(
            "https://open.feishu.cn/open-apis/bot/v2/hook/abc",
            "", "hello", opener=opener)
        self.assertTrue(ok)
        self.assertEqual(err, "")
        payload = opener.calls[0]["payload"]
        self.assertEqual(payload["msg_type"], "text")
        self.assertEqual(payload["content"], {"text": "hello"})
        self.assertNotIn("sign", payload)

    def test_feishu_sign(self):
        # Hand-computed: sign = base64(HMAC-SHA256(ts + "\n" + secret)).
        secret = "s3cr3t"
        ts = "1700000000"
        expect = base64.b64encode(hmac.new(
            secret.encode("utf-8"),
            ("%s\n%s" % (ts, secret)).encode("utf-8"),
            hashlib.sha256).digest()).decode("utf-8")
        self.assertEqual(notify.feishu_sign(secret, ts), expect)
        opener = FakeOpener([(200, {"code": 0, "msg": "success"})])
        ok, _err = notify.send_feishu(
            "https://open.feishu.cn/open-apis/bot/v2/hook/abc",
            secret, "hello", opener=opener, timestamp=int(ts))
        self.assertTrue(ok)
        payload = opener.calls[0]["payload"]
        self.assertEqual(payload["timestamp"], ts)
        self.assertEqual(payload["sign"], expect)

    def test_feishu_bad_url(self):
        ok, err = notify.send_feishu("not-a-url", "", "hello")
        self.assertFalse(ok)
        self.assertIn("无效", err)

    def test_mask_secret(self):
        self.assertEqual(notify.mask_secret(""), "未配置")
        self.assertEqual(notify.mask_secret("abc"), "已保存")
        self.assertNotIn("abc", notify.mask_secret("abc"))

    def test_notify_text(self):
        text = app._notify_text("测不到 IP", ["域名：a.example.com"],
                                when="2026-11-25 10:00:00")
        self.assertIn("【CF优选IP】测不到 IP", text)
        self.assertIn("域名：a.example.com", text)


class DedupTest(unittest.TestCase):
    def test_new_incident_sends(self):
        send, state = app._notify_decision("no_ip", {}, 1000000)
        self.assertTrue(send)
        self.assertEqual(state["count"], 1)
        self.assertIsNone(state["last_sent"])

    def test_repeat_within_24h_skipped(self):
        state = {"since": 1000000, "last_attempt": 1000000,
                 "last_sent": 1000000, "count": 1}
        send, new = app._notify_decision("no_ip", state, 1000000 + 3600)
        self.assertFalse(send)
        self.assertEqual(new["count"], 2)

    def test_reminder_after_24h(self):
        state = {"since": 1000000, "last_attempt": 1000000,
                 "last_sent": 1000000, "count": 3}
        send, _new = app._notify_decision(
            "no_ip", state, 1000000 + 25 * 3600)
        self.assertTrue(send)

    def test_retry_after_failed_send(self):
        # Never sent successfully: retry at most once an hour.
        state = {"since": 1000000, "last_attempt": 1000000,
                 "last_sent": None, "count": 1}
        send, _new = app._notify_decision("no_ip", state, 1000000 + 1800)
        self.assertFalse(send)
        send, _new = app._notify_decision("no_ip", state, 1000000 + 3700)
        self.assertTrue(send)

    def test_enabled_toggles(self):
        cfg = {"notify_failure": True, "notify_ip_change": False,
               "notify_daily_result": True}
        self.assertTrue(app._notify_enabled(cfg, "no_ip"))
        self.assertTrue(app._notify_enabled(cfg, "dns6"))
        self.assertTrue(app._notify_enabled(cfg, "offline"))
        self.assertFalse(app._notify_enabled(cfg, "ip_change"))
        self.assertTrue(app._notify_enabled(cfg, "daily_result"))
        cfg2 = {"notify_failure": False}
        self.assertFalse(app._notify_enabled(cfg2, "no_ip"))


if __name__ == "__main__":
    unittest.main()
