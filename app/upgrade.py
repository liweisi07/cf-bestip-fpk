"""Online upgrade check for cf-bestipd (domain edition).

The source of truth for the latest released version is the public
GitHub repo liweisi07/cf-bestip-fpk: the `manifest` file at the repo
root carries the current release version and its changelog, and the
released .fpk sits next to it as cf-bestip-domain-<version>.fpk (a
single universal package since 1.0.22, ARM64 + x86_64).

The check fetches the manifest (raw.githubusercontent.com first,
GitHub contents API as fallback), parses `version=` and
`changelog=`, and compares against the running version. Nothing is
auto-installed: when a newer version exists the user downloads the
.fpk into the data dir's updates/ folder and installs it from the
fnOS app center (direct overwrite, config preserved). fnOS offers
no supported way for an app to trigger its own reinstall, so
download + guidance is the honest scope.

Only the standard library is used. All fetches are direct (proxy
env vars ignored, like the rest of the app).
"""

import base64
import json
import os
import re
import urllib.error
import urllib.request

REPO = "liweisi07/cf-bestip-fpk"
MANIFEST_RAW_URL = (
    "https://raw.githubusercontent.com/%s/main/manifest" % REPO)
MANIFEST_API_URL = (
    "https://api.github.com/repos/%s/contents/manifest" % REPO)
FPK_URL_TEMPLATE = (
    "https://raw.githubusercontent.com/%s/main/"
    "cf-bestip-domain-%%s.fpk" % REPO)
FPK_NAME_TEMPLATE = "cf-bestip-domain-%s.fpk"

DEFAULT_TIMEOUT = 20
DOWNLOAD_TIMEOUT = 300
# A real .fpk is ~3 MB. Refuse anything absurd (wrong file / HTML).
MIN_FPK_BYTES = 100 * 1024
MAX_FPK_BYTES = 50 * 1024 * 1024

_VERSION_RE = re.compile(r"^\s*version\s*=\s*(.+?)\s*$", re.M)
_CHANGELOG_RE = re.compile(r"^\s*changelog\s*=\s*(.+?)\s*$", re.M)


def parse_version(text):
    """Parse 'x.y.z' into a tuple of ints, or None when invalid."""
    if not text:
        return None
    parts = str(text).strip().split(".")
    if not parts or len(parts) > 4:
        return None
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return None
    if any(n < 0 for n in nums):
        return None
    return tuple(nums)


def compare_versions(a, b):
    """-1 when a < b, 0 when equal, 1 when a > b. None means invalid."""
    va, vb = parse_version(a), parse_version(b)
    if va is None or vb is None:
        return None
    va = va + (0,) * (3 - len(va))
    vb = vb + (0,) * (3 - len(vb))
    if va < vb:
        return -1
    if va > vb:
        return 1
    return 0


def parse_manifest(text):
    """Extract (version, changelog) from a manifest file's text."""
    version = None
    changelog = ""
    match = _VERSION_RE.search(text or "")
    if match:
        version = match.group(1).strip()
    match = _CHANGELOG_RE.search(text or "")
    if match:
        changelog = match.group(1).strip()
    return version, changelog


def _fetch(url, timeout, opener=None):
    used = opener
    if used is None:
        used = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(url, method="GET")
    with used.open(req, timeout=timeout) as resp:
        return resp.read()


def fetch_latest(timeout=DEFAULT_TIMEOUT, opener=None):
    """Return (version, changelog) of the latest released version.

    Tries the raw manifest first, then the GitHub contents API.
    Raises RuntimeError with a short reason when both fail.
    """
    last_error = ""
    try:
        text = _fetch(MANIFEST_RAW_URL, timeout, opener=opener)
        version, changelog = parse_manifest(text.decode("utf-8", "ignore"))
        if version:
            return version, changelog
        last_error = "仓库 manifest 里没有 version"
    except Exception as exc:  # noqa: BLE001 - wrapped for the caller
        last_error = str(exc)
    try:
        raw = _fetch(MANIFEST_API_URL, timeout, opener=opener)
        payload = json.loads(raw.decode("utf-8", "ignore"))
        content = base64.b64decode(payload.get("content") or "").decode(
            "utf-8", "ignore")
        version, changelog = parse_manifest(content)
        if version:
            return version, changelog
        last_error = "仓库 manifest 里没有 version"
    except Exception as exc:  # noqa: BLE001 - wrapped for the caller
        last_error = str(exc)
    raise RuntimeError("检查更新失败：%s" % last_error)


def fpk_url(version):
    """Public download URL of the released .fpk for `version`."""
    return FPK_URL_TEMPLATE % version


def fpk_name(version):
    return FPK_NAME_TEMPLATE % version


def download_fpk(version, dest_dir, timeout=DOWNLOAD_TIMEOUT, opener=None,
                 chunk_cb=None):
    """Download the released .fpk for `version` into `dest_dir`.

    Returns the full local path. Raises RuntimeError on failure or
    when the file is implausibly small/large (a wrong file or an
    error page). The download streams to disk (no huge buffer).
    """
    if parse_version(version) is None:
        raise RuntimeError("版本号无效：%s" % version)
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, fpk_name(version))
    tmp = dest + ".part"
    url = fpk_url(version)
    used = opener
    if used is None:
        used = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(url, method="GET")
    total = 0
    try:
        with used.open(req, timeout=timeout) as resp, \
                open(tmp, "wb") as fh:
            while True:
                chunk = resp.read(256 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_FPK_BYTES:
                    raise RuntimeError("下载的文件过大（超过 50 MB），"
                                       "已停止")
                fh.write(chunk)
                if chunk_cb:
                    chunk_cb(total)
    except RuntimeError:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    except Exception as exc:  # noqa: BLE001 - wrapped for the caller
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise RuntimeError("下载失败：%s" % exc)
    if total < MIN_FPK_BYTES:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise RuntimeError("下载的文件过小（%d 字节），可能不是 .fpk" % total)
    os.replace(tmp, dest)
    return dest
