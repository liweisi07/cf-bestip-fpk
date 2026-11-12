"""Unit tests for app/rewriter.py (byte-preserving mihomo YAML rewrite)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import rewriter

TARGET = "cf.example.com"

SAMPLE = """proxies:
  - name: "CF有servername"
    type: vless
    server: cf.example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    tls: true
    servername: cf.example.com
    network: ws
  - name: "CF无servername-TLS"
    type: vless
    server: cf2.example.com
    port: 443
    uuid: 22222222-2222-2222-2222-222222222222
    tls: true
  - name: "CF-trojan无servername"
    type: trojan
    server: cf3.example.com
    port: 443
    password: secret
  - name: "CF-ss无TLS"
    type: ss
    server: cf4.example.com
    port: 8388
    cipher: aes-128-gcm
    password: secret
  - name: "CF-sni已有"
    type: vless
    server: cf5.example.com
    port: 443
    uuid: 33333333-3333-3333-3333-333333333333
    tls: true
    sni: cf5.example.com
  - name: "非CF域名"
    type: vless
    server: other.example.net
    port: 443
    uuid: 44444444-4444-4444-4444-444444444444
    tls: true
    servername: other.example.net
  - name: "IP字面量"
    type: vless
    server: 1.2.3.4
    port: 443
    uuid: 55555555-5555-5555-5555-555555555555
    tls: true
  - name: "无法解析"
    type: vless
    server: missing.example.com
    port: 443
    uuid: 66666666-6666-6666-6666-666666666666
    tls: true
  - name: "CF空servername"
    type: vless
    server: cf6.example.com
    port: 443
    uuid: 77777777-7777-7777-7777-777777777777
    tls: true
    servername:
proxy-groups:
  - name: auto
    type: url-test
    proxies:
      - CF有servername
rules:
  - MATCH,auto
"""

EXPECTED = """proxies:
  - name: "CF有servername"
    type: vless
    server: cf.example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    tls: true
    servername: cf.example.com
    network: ws
  - name: "CF无servername-TLS"
    type: vless
    server: cf.example.com
    servername: cf2.example.com
    port: 443
    uuid: 22222222-2222-2222-2222-222222222222
    tls: true
  - name: "CF-trojan无servername"
    type: trojan
    server: cf.example.com
    servername: cf3.example.com
    port: 443
    password: secret
  - name: "CF-ss无TLS"
    type: ss
    server: cf.example.com
    port: 8388
    cipher: aes-128-gcm
    password: secret
  - name: "CF-sni已有"
    type: vless
    server: cf.example.com
    port: 443
    uuid: 33333333-3333-3333-3333-333333333333
    tls: true
    sni: cf5.example.com
  - name: "非CF域名"
    type: vless
    server: other.example.net
    port: 443
    uuid: 44444444-4444-4444-4444-444444444444
    tls: true
    servername: other.example.net
  - name: "IP字面量"
    type: vless
    server: 1.2.3.4
    port: 443
    uuid: 55555555-5555-5555-5555-555555555555
    tls: true
  - name: "无法解析"
    type: vless
    server: missing.example.com
    port: 443
    uuid: 66666666-6666-6666-6666-666666666666
    tls: true
  - name: "CF空servername"
    type: vless
    server: cf.example.com
    port: 443
    uuid: 77777777-7777-7777-7777-777777777777
    tls: true
    servername: cf6.example.com
proxy-groups:
  - name: auto
    type: url-test
    proxies:
      - CF有servername
rules:
  - MATCH,auto
"""


def fake_resolver(domain):
    table = {
        "cf.example.com": ["104.16.0.10"],
        "cf2.example.com": ["104.16.0.11"],
        "cf3.example.com": ["104.16.0.12"],
        "cf4.example.com": ["104.16.0.13"],
        "cf5.example.com": ["104.16.0.14"],
        "cf6.example.com": ["104.16.0.15"],
        "other.example.net": ["93.184.216.34"],
        "missing.example.com": [],
    }
    return table.get(domain, [])


class RewriteTest(unittest.TestCase):
    def test_full_sample(self):
        networks = rewriter.default_cf_networks()
        new_text, stats = rewriter.rewrite_yaml(
            SAMPLE, TARGET, networks, resolver=fake_resolver
        )
        self.assertEqual(new_text, EXPECTED)
        rewritten = sorted(r["name"] for r in stats["rewritten"])
        self.assertEqual(rewritten, sorted([
            "CF有servername", "CF无servername-TLS", "CF-trojan无servername",
            "CF-ss无TLS", "CF-sni已有", "CF空servername",
        ]))
        self.assertEqual(stats["skipped_non_cf"], ["非CF域名"])
        self.assertEqual(stats["skipped_ip"], ["IP字面量"])
        self.assertEqual(stats["skipped_unresolved"], ["无法解析"])

    def test_no_best_ip_leaves_text_untouched(self):
        new_text, stats = rewriter.rewrite_yaml(
            SAMPLE, None, rewriter.default_cf_networks(),
            resolver=fake_resolver,
        )
        self.assertEqual(new_text, SAMPLE)
        self.assertEqual(stats["rewritten"], [])

    def test_no_proxies_section_untouched(self):
        text = "proxy-groups:\n  - name: x\n"
        new_text, _ = rewriter.rewrite_yaml(
            text, TARGET, rewriter.default_cf_networks(),
            resolver=fake_resolver,
        )
        self.assertEqual(new_text, text)

    def test_quoted_server_and_comment(self):
        text = (
            "proxies:\n"
            "  - name: q\n"
            "    type: vless\n"
            "    server: \"cf.example.com\" # keep me\n"
            "    port: 443\n"
            "    tls: true\n"
        )
        new_text, stats = rewriter.rewrite_yaml(
            text, TARGET, rewriter.default_cf_networks(),
            resolver=fake_resolver,
        )
        self.assertIn("    server: cf.example.com # keep me\n", new_text)
        self.assertIn("    servername: cf.example.com\n", new_text)
        self.assertEqual(len(stats["rewritten"]), 1)

    def test_ipv6_literal_untouched(self):
        text = (
            "proxies:\n"
            "  - name: v6\n"
            "    type: vless\n"
            "    server: '[2606:4700:4700::1111]'\n"
            "    port: 443\n"
        )
        new_text, stats = rewriter.rewrite_yaml(
            text, TARGET, rewriter.default_cf_networks(),
            resolver=fake_resolver,
        )
        self.assertEqual(new_text, text)
        self.assertEqual(stats["skipped_ip"], ["v6"])

    def test_cf_range_membership(self):
        nets = rewriter.default_cf_networks()
        self.assertTrue(
            rewriter.is_cf_domain(
                "cf.example.com", nets, resolver=fake_resolver
            )
        )
        self.assertFalse(
            rewriter.is_cf_domain(
                "other.example.net", nets, resolver=fake_resolver
            )
        )


if __name__ == "__main__":
    unittest.main()
