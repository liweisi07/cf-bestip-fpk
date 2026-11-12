"""Byte-preserving rewriter for mihomo (ClashMeta) YAML proxy lists.

Only the ``server`` line of a proxy entry is ever modified, and at most one
``servername`` line is inserted (or one empty ``servername``/``sni`` value is
filled) per entry. Every other line is passed through untouched, so the
output keeps the original formatting, comments and key order.

A node is treated as "going through Cloudflare" only when:
  * its ``server`` value is a domain name (not an IP literal), and
  * that domain resolves to at least one IPv4 address inside Cloudflare's
    official IPv4 ranges.

IP-literal servers and non-Cloudflare domains are never touched.

TLS handling (so TLS is not broken by replacing the address):
  * if the entry already has a non-empty ``servername`` or ``sni``, it is
    kept as-is;
  * if it has an empty ``servername``/``sni``, that line is filled with the
    original domain;
  * if it has neither and the node uses TLS, a ``servername`` line equal to
    the original domain is inserted right after the ``server`` line.
  * a node counts as TLS when its ``tls`` field is true, or when its type
    is one of the implicitly-TLS types (trojan, hysteria2, tuic).

Only Python's standard library is used.
"""

import ipaddress
import re
import socket

# Cloudflare's official IPv4 ranges (https://www.cloudflare.com/ips-v4).
# A copy is bundled so the app also works when the refresh fails.
CF_IPV4_RANGES = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
]

CF_RANGES_URL = "https://www.cloudflare.com/ips-v4"

# Node types whose transport is always TLS, even without an explicit
# ``tls: true`` field.
IMPLICIT_TLS_TYPES = {"trojan", "hysteria2", "tuic"}

_PROXIES_KEY_RE = re.compile(r"^proxies:\s*(?:#.*)?$")
_TOP_KEY_RE = re.compile(r"^[A-Za-z0-9][^:]*:")
_ENTRY_START_RE = re.compile(r"^(\s*)- ")
_SERVER_RE = re.compile(
    r"^(\s*)(- )?server:\s*(?:\"([^\"]*)\"|'([^']*)'|(\S+))"
)
_TYPE_RE = re.compile(r"^\s*type:\s*(\S+)")
_TLS_RE = re.compile(
    r"^\s*tls:\s*(true|True|TRUE|yes|Yes|YES|on|On|ON)\s*(?:#.*)?$"
)


def load_cf_networks(text):
    """Parse CIDR lines into a list of IPv4Network objects."""
    networks = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            networks.append(ipaddress.IPv4Network(line, strict=False))
        except ValueError:
            continue
    return networks


def default_cf_networks():
    return load_cf_networks("\n".join(CF_IPV4_RANGES))


def is_ip_literal(value):
    """True when value is an IP literal (v4 or v6, brackets allowed)."""
    candidate = value.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def resolve_ipv4(domain, resolver=None):
    """Resolve a domain to its IPv4 addresses (deduped, order kept)."""
    if resolver is not None:
        return list(dict.fromkeys(resolver(domain)))
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET)
    except (socket.gaierror, UnicodeError, ValueError):
        return []
    out = []
    for info in infos:
        ip = info[4][0]
        if ip not in out:
            out.append(ip)
    return out


def is_cf_domain(domain, networks, resolver=None):
    """True when the domain resolves to an IPv4 inside Cloudflare ranges."""
    for ip in resolve_ipv4(domain, resolver):
        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        if any(addr in net for net in networks):
            return True
    return False


def _server_line_parts(line):
    """Split a server line into (head, value, tail).

    head is everything up to and including ``server: `` (with the original
    quoting style removed from the value position), value is the unquoted
    server value, tail is whatever followed the value token (e.g. a
    comment). Returns None when the line is not a server line.
    """
    m = _SERVER_RE.match(line)
    if not m:
        return None
    indent, dash, dq, sq, bare = m.groups()
    if dq is not None:
        value = dq
        token_end = m.end(3)
        token_start = m.start(3) - 1  # include opening quote
    elif sq is not None:
        value = sq
        token_end = m.end(4)
        token_start = m.start(4) - 1
    else:
        value = bare
        token_end = m.end(5)
        token_start = m.start(5)
    head = line[:token_start]
    tail = line[token_end:]
    # Drop the closing quote from the tail when the value was quoted.
    if (dq is not None or sq is not None) and tail.startswith(('"', "'")):
        tail = tail[1:]
    return head, value, tail


def _sibling_indent(entry_lines, server_idx, entry_indent):
    """Indent used by sibling keys of a proxy entry."""
    line = entry_lines[server_idx]
    m = _SERVER_RE.match(line)
    if m and m.group(2):  # server line itself starts the entry ("- server:")
        return entry_indent + "  "
    m2 = re.match(r"^(\s*)server:", line)
    return m2.group(1) if m2 else entry_indent + "  "


def _entry_name(entry_lines):
    for line in entry_lines:
        m = re.match(r"^\s*-?\s*name:\s*(?:\"([^\"]*)\"|'([^']*)'|(\S+))", line)
        if m:
            return m.group(1) if m.group(1) is not None else (
                m.group(2) if m.group(2) is not None else m.group(3)
            )
    return ""


def _split_entries(lines):
    """Split a proxies section into entries.

    Returns (entries, section_start, section_end) where entries is a list of
    (start, end, entry_indent). Lines outside the proxies section are not
    included. Only top-level ``proxies:`` lists are handled; flow-style
    (single-line) entries are left untouched by the caller.
    """
    section_start = None
    section_end = len(lines)
    entry_indent = None
    entries = []
    current = None
    in_section = False

    for idx, raw in enumerate(lines):
        line = raw.rstrip("\r\n")
        stripped = line.strip()
        if not in_section:
            if _PROXIES_KEY_RE.match(line):
                in_section = True
                section_start = idx
            continue
        # Inside the proxies section.
        if line == "" or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0 and _TOP_KEY_RE.match(line):
            section_end = idx
            break
        m = _ENTRY_START_RE.match(line)
        if m:
            if entry_indent is None:
                entry_indent = m.group(1)
            if m.group(1) == entry_indent:
                if current is not None:
                    entries.append(current)
                current = (idx, idx + 1, entry_indent)
                continue
        if current is not None:
            current = (current[0], idx + 1, current[2])
    if current is not None:
        entries.append(current)
    if section_start is None:
        return [], None, len(lines)
    if section_end is None or section_end == len(lines):
        # Section runs to end of file; entries already end at last line.
        pass
    return entries, section_start, section_end


def rewrite_yaml(text, best_ip, networks, resolver=None):
    """Rewrite Cloudflare-domain servers in a mihomo YAML text.

    Returns (new_text, stats) where stats has:
      rewritten: [{name, old, new}]
      skipped_ip: [names with IP-literal servers]
      skipped_non_cf: [names whose domain is not Cloudflare]
      skipped_unresolved: [names whose domain could not be resolved]
    """
    stats = {
        "rewritten": [],
        "skipped_ip": [],
        "skipped_non_cf": [],
        "skipped_unresolved": [],
    }
    if not best_ip:
        return text, stats

    # Preserve the file's line endings; inserted lines reuse them.
    ending = "\r\n" if "\r\n" in text else "\n"
    lines = text.splitlines(keepends=True)
    if not lines:
        return text, stats

    entries, section_start, _section_end = _split_entries(lines)
    if section_start is None:
        return text, stats

    # Work on a mutable copy; edits are recorded as (index, new_line) and
    # insertions as (index_after, new_line). Apply insertions last, from
    # the bottom up, so indices stay valid.
    replacements = {}
    insertions = []  # (after_index, line)
    for start, end, entry_indent in entries:
        entry_lines = lines[start:end]
        server_idx = None
        server_value = None
        for i, raw in enumerate(entry_lines):
            parts = _server_line_parts(raw.rstrip("\r\n"))
            if parts is not None:
                server_idx = i
                server_value = parts[1]
                break
        if server_idx is None or not server_value:
            continue
        name = _entry_name(entry_lines)
        if is_ip_literal(server_value):
            stats["skipped_ip"].append(name)
            continue
        resolved = resolve_ipv4(server_value, resolver)
        if not resolved:
            stats["skipped_unresolved"].append(name)
            continue
        if not any(
            _ip_in_networks(ip, networks) for ip in resolved
        ):
            stats["skipped_non_cf"].append(name)
            continue

        # --- This node goes through Cloudflare: rewrite its server. ---
        raw_line = entry_lines[server_idx].rstrip("\r\n")
        head, _old, tail = _server_line_parts(raw_line)
        new_line = head + best_ip + tail
        # Keep the original line ending.
        orig_ending = "\r\n" if entry_lines[server_idx].endswith("\r\n") else (
            "\n" if entry_lines[server_idx].endswith("\n") else ""
        )
        replacements[start + server_idx] = new_line + orig_ending

        # --- TLS / servername handling. ---
        sib_indent = _sibling_indent(entry_lines, server_idx, entry_indent)
        node_type = None
        tls_on = False
        sni_idx = None
        sni_empty = False
        for i, raw in enumerate(entry_lines):
            line = raw.rstrip("\r\n")
            if i == 0 and line.startswith(entry_indent + "- "):
                # The entry-start line ("  - name: x") carries a sibling
                # key after the dash; parse it like the other siblings.
                rest = line[len(entry_indent) + 2:]
            elif line.startswith(sib_indent):
                rest = line[len(sib_indent):]
            else:
                continue
            if rest.startswith("type:"):
                node_type = rest[5:].strip().strip("\"'").split()[0] \
                    if rest[5:].strip() else None
            elif _TLS_RE.match(line):
                tls_on = True
            elif rest.startswith("servername:") or rest.startswith("sni:"):
                value = rest.split(":", 1)[1].strip().strip("\"'")
                if value:
                    sni_idx = -1  # marker: a usable sni/servername exists
                elif sni_idx is None:
                    sni_idx = i
                    sni_empty = True
        is_tls = tls_on or (node_type in IMPLICIT_TLS_TYPES)
        if sni_idx is not None and sni_idx >= 0 and sni_empty:
            # Fill the empty servername/sni line with the original domain.
            raw = entry_lines[sni_idx].rstrip("\r\n")
            m = re.match(r"^(\s*)(- )?([A-Za-z0-9_-]+):\s*$", raw)
            if m:
                indent, dash, key = m.groups()
                sni_ending = "\r\n" if entry_lines[sni_idx].endswith("\r\n") \
                    else ("\n" if entry_lines[sni_idx].endswith("\n") else "")
                replacements[start + sni_idx] = (
                    indent + (dash or "") + key + ": "
                    + server_value + sni_ending
                )
        elif sni_idx is None and is_tls:
            # Insert a servername line right after the server line.
            insertions.append(
                (start + server_idx,
                 sib_indent + "servername: " + server_value + ending)
            )
        stats["rewritten"].append(
            {"name": name, "old": server_value, "new": best_ip}
        )

    for idx, new_line in replacements.items():
        lines[idx] = new_line
    for after_idx, new_line in sorted(insertions, reverse=True):
        lines.insert(after_idx + 1, new_line)
    return "".join(lines), stats


def _ip_in_networks(ip, networks):
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return any(addr in net for net in networks)
