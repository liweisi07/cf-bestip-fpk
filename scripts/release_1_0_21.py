#!/usr/bin/env python3
"""Release 1.0.21 of the domain edition to liweisi07/cf-bestip-fpk.

1.0.21 changes the Feiniu desktop entry from an iframe embed to a
direct URL jump: clicking the desktop icon opens
https://cfip.lolivx.com:56789 (via the Lucky reverse proxy) instead
of embedding the app's internal page in an iframe, so it works both
on the LAN and remotely. No other functional change.

Steps (one commit via the git data API):
  * push the source tree (app/, cmd/, config/, wizard/, manifest,
    LICENSE, README.md, ICON.PNG, ICON_256.PNG, scripts/, tests/,
    icon-work/ source webp, vendor/ text files). The 7.5 MB bundled
    cfst binary (app/cfst) and the vendor tarball are NOT pushed:
    the app downloads cfst automatically on first run when the
    bundled binary is missing. dist/ and __pycache__ are excluded.
  * the built fpk cf-bestip-domain-1.0.21-arm64.fpk is NOT pushed
    to this repo (repo holds source only; the fpk is distributed
    via fn-apps, updated separately). The old 1.0.20 fpk already
    in the repo is left untouched.
  * update the repo README (latest version + 1.0.21 note). The
    fpk filename line is left at 1.0.20 because that is the fpk
    actually present in this repo.
Then sync the local backup in ~/workspace/your_files/ (copy the new
1.0.21 fpk; the old 1.0.20 local backup is kept until fn-apps is
updated) and list the repo to confirm the final state.

Build note: the canonical builder is scripts/build_fnpack.sh
(official fnpack); scripts/build_fpk.py is stale -- its output
fails scripts/verify_fpk.py (missing cmd members, no manifest
checksum line, stale manifest.checksum member), so it must not
be used for releases.

Usage: python3 scripts/release_1_0_21.py
"""

import base64
import os
import shutil
import sys

sys.path.insert(0, os.path.expanduser(
    "~/workspace/custom-connectors/custom.github-pat/bin"))
from gh_api import api  # noqa: E402

REPO = "liweisi07/cf-bestip-fpk"
BRANCH = "main"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FPK = os.path.join(ROOT, "dist", "cf-bestip-domain-1.0.21-arm64.fpk")
NEW_FPK_NAME = "cf-bestip-domain-1.0.21-arm64.fpk"
YOUR_FILES = os.path.expanduser("~/workspace/your_files")

# Source files to push (relative to ROOT). Binary files are listed
# separately so they are base64-encoded for the blob API.
# NOTE: the local README.md (domain-edition doc) is NOT pushed: the
# repo root README.md is the release README (updated separately
# below) and the two would collide at the same path.
TEXT_FILES = [
    ".gitignore",
    "LICENSE",
    "manifest",
    "app/app.py",
    "app/cf_ranges.txt",
    "app/cfdns.py",
    "app/cfst.py",
    "app/ip.txt",
    "app/rewriter.py",
    "app/ui/config",
    "cmd/config_callback",
    "cmd/install_callback",
    "cmd/install_init",
    "cmd/main",
    "cmd/uninstall_callback",
    "cmd/uninstall_init",
    "cmd/upgrade_callback",
    "cmd/upgrade_init",
    "config/privilege",
    "config/resource",
    "scripts/build_fnpack.sh",
    "scripts/build_fpk.py",
    "scripts/make_icons.py",
    "scripts/release_1_0_16.py",
    "scripts/release_1_0_17.py",
    "scripts/release_1_0_18.py",
    "scripts/release_1_0_19.py",
    "scripts/release_1_0_20.py",
    "scripts/release_1_0_21.py",
    "scripts/verify_fpk.py",
    "tests/test_auth.py",
    "tests/test_cfdns.py",
    "tests/test_cfst.py",
    "tests/test_interval.py",
    "tests/test_rewriter.py",
    "tests/test_schedule_region.py",
    "tests/test_server.py",
    "tests/test_server_domain.py",
    "tests/verify_1_0_16.py",
    "tests/verify_1_0_17.py",
    "tests/verify_1_0_18.py",
    "vendor/cfst/cfst_linux_arm64/cfst_hosts.sh",
    "vendor/cfst/cfst_linux_arm64/ip.txt",
    "vendor/cfst/cfst_linux_arm64/ipv6.txt",
    "vendor/cfst/cfst_linux_arm64/使用+错误+反馈说明.txt",
    "wizard/config",
    "wizard/install",
    "wizard/uninstall",
    "wizard/upgrade",
]
BINARY_FILES = [
    "ICON.PNG",
    "ICON_256.PNG",
    "app/ui/images/icon_256.png",
    "app/ui/images/icon_64.png",
    "icon-work/media-generation-cf-bestipd-icon-0-8d835f21-c1d8-4575-8c93-fc5b082ce15f.webp",
]
# File modes for the tree: scripts and cmd hooks are executable.
EXECUTABLE = {
    "cmd/config_callback", "cmd/install_callback", "cmd/install_init",
    "cmd/main", "cmd/uninstall_callback", "cmd/uninstall_init",
    "cmd/upgrade_callback", "cmd/upgrade_init",
    "scripts/build_fnpack.sh", "scripts/build_fpk.py",
    "scripts/make_icons.py", "scripts/release_1_0_16.py",
    "scripts/release_1_0_17.py", "scripts/release_1_0_18.py",
    "scripts/release_1_0_19.py", "scripts/release_1_0_20.py",
    "scripts/release_1_0_21.py",
    "scripts/verify_fpk.py",
    "tests/test_auth.py", "tests/test_cfdns.py", "tests/test_cfst.py",
    "tests/test_interval.py", "tests/test_rewriter.py",
    "tests/test_schedule_region.py", "tests/test_server.py",
    "tests/test_server_domain.py", "tests/verify_1_0_16.py",
    "tests/verify_1_0_17.py",
    "tests/verify_1_0_18.py",
}


def _api(method, path, body=None):
    status, result = api(method, path, body)
    if status not in (200, 201):
        raise RuntimeError("%s %s -> %s %s" % (method, path, status,
                                               result))
    return result


def _create_blob(data_bytes, encoding):
    body = {"encoding": encoding}
    if encoding == "base64":
        body["content"] = base64.b64encode(data_bytes).decode()
    else:
        body["content"] = data_bytes.decode("utf-8")
    return _api("POST", "/repos/%s/git/blobs" % REPO, body)["sha"]


def _repo_readme_text():
    status, readme = api("GET", "/repos/%s/contents/README.md" % REPO)
    if status != 200:
        raise RuntimeError("GET README.md -> %s" % status)
    return base64.b64decode(readme["content"]).decode("utf-8")


def _updated_repo_readme(text):
    orig = text
    text = text.replace(
        "仓库里只保留最新版：IP 版 1.0.8、域名版 1.0.20。",
        "仓库里只保留最新版：IP 版 1.0.8、域名版 1.0.21。")
    text = text.replace(
        "注：域名版 1.0.20 开发者改为可乐冰，点开发者可打开博客；"
        "发布者同步改为可乐冰。",
        "注：域名版 1.0.20 开发者改为可乐冰，点开发者可打开博客；"
        "发布者同步改为可乐冰。\n\n"
        "注：域名版 1.0.21 桌面入口改成直跳：点图标直接打开 "
        "https://cfip.lolivx.com:56789（经 Lucky 反代），不再嵌 "
        "iframe；内网外网都能开。")
    text = text.replace(
        "1.0.20 起开发者改为可乐冰，点开发者可打开博客。",
        "1.0.20 起开发者改为可乐冰，点开发者可打开博客；"
        "1.0.21 起桌面入口改成直跳，点图标直接打开子域名。")
    if text == orig:
        raise RuntimeError("repo README: no replacement applied")
    return text


def main():
    fpk_bytes = open(FPK, "rb").read()
    print("fpk (local only, not pushed): %s (%d bytes)"
          % (NEW_FPK_NAME, len(fpk_bytes)))

    # 1. Current main ref + base tree.
    ref = _api("GET", "/repos/%s/git/ref/heads/%s" % (REPO, BRANCH))
    base_commit = ref["object"]["sha"]
    base_tree = _api("GET", "/repos/%s/git/commits/%s"
                     % (REPO, base_commit))["tree"]["sha"]
    print("base commit %s tree %s" % (base_commit[:12], base_tree[:12]))

    # 2. Blobs for every file going into the new tree.
    entries = []
    for rel in TEXT_FILES:
        path = os.path.join(ROOT, rel)
        with open(path, "rb") as fh:
            data = fh.read()
        sha = _create_blob(data, "utf-8")
        entries.append({"path": rel, "mode": "100755"
                        if rel in EXECUTABLE else "100644",
                        "type": "blob", "sha": sha})
    for rel in BINARY_FILES:
        path = os.path.join(ROOT, rel)
        with open(path, "rb") as fh:
            data = fh.read()
        sha = _create_blob(data, "base64")
        entries.append({"path": rel, "mode": "100644",
                        "type": "blob", "sha": sha})
    # Updated repo README blob (content comes from the repo README,
    # not the local domain-edition README.md).
    new_readme = _updated_repo_readme(_repo_readme_text())
    readme_sha = _create_blob(new_readme.encode("utf-8"), "utf-8")
    entries.append({"path": "README.md", "mode": "100644",
                    "type": "blob", "sha": readme_sha})
    print("blobs ready: %d entries" % len(entries))

    # 3. New tree + commit + move main.
    tree = _api("POST", "/repos/%s/git/trees" % REPO,
                {"base_tree": base_tree, "tree": entries})
    commit = _api("POST", "/repos/%s/git/commits" % REPO, {
        "message": "域名版 1.0.21：桌面入口改成直跳，点图标直接打开子域名",
        "tree": tree["sha"], "parents": [base_commit]})
    _api("PATCH", "/repos/%s/git/refs/heads/%s" % (REPO, BRANCH),
         {"sha": commit["sha"]})
    print("committed %s" % commit["sha"])

    # 4. Sync the local backup in ~/workspace/your_files/ (copy the
    # new fpk; keep the old 1.0.20 local backup until fn-apps is
    # updated).
    shutil.copyfile(FPK, os.path.join(YOUR_FILES, NEW_FPK_NAME))
    print("copied %s to your_files" % NEW_FPK_NAME)

    # 5. Confirm the final repo state.
    listing = _api("GET", "/repos/%s/contents/" % REPO)
    names = sorted(item["name"] for item in listing)
    print("repo top level now: %s" % names)
    for item in listing:
        print("  %s (%d bytes, %s)" % (item["name"], item["size"],
                                        item["type"]))
    assert NEW_FPK_NAME not in names, "fpk must not be in repo"
    for want in ("app", "cmd", "config", "wizard", "scripts", "tests",
                 "manifest", "LICENSE"):
        assert want in names, "source %s missing from repo" % want
    # Confirm the pushed manifest + config carry 1.0.21.
    s, man = api("GET", "/repos/%s/contents/manifest" % REPO)
    man_text = base64.b64decode(man["content"]).decode("utf-8")
    assert "version=1.0.21" in man_text, "manifest not 1.0.21"
    s, cfg = api("GET", "/repos/%s/contents/app/ui/config" % REPO)
    cfg_text = base64.b64decode(cfg["content"]).decode("utf-8")
    assert '"type":"url"' in cfg_text, "config type not url"
    assert "https://cfip.lolivx.com:56789" in cfg_text, "config url wrong"
    print("RELEASE OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
