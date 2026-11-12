#!/usr/bin/env python3
"""Release 1.0.18 of the domain edition to liweisi07/cf-bestip-fpk.

1.0.18 moves the account settings behind a top-right "settings"
button (username and password both changeable) and pre-fills the
install wizard service port (18089) and test interval (7 days).

Steps (one commit via the git data API):
  * push the source tree (app/, cmd/, config/, wizard/, manifest,
    LICENSE, README.md, ICON.PNG, ICON_256.PNG, scripts/, tests/,
    icon-work/ source webp, vendor/ text files). The 7.5 MB bundled
    cfst binary (app/cfst) and the vendor tarball are NOT pushed:
    the app downloads cfst automatically on first run when the
    bundled binary is missing. dist/ and __pycache__ are excluded.
  * upload the new fpk cf-bestip-domain-1.0.18-arm64.fpk.
  * delete the old domain 1.0.17 fpk.
  * update the repo README (latest versions + 1.0.18 notes).
Then sync the local backup in ~/workspace/your_files/ (copy new,
delete old 1.0.17) and list the repo to confirm the final state.

Usage: python3 scripts/release_1_0_18.py
"""

import base64
import json
import os
import shutil
import sys

sys.path.insert(0, os.path.expanduser(
    "~/workspace/custom-connectors/custom.github-pat/bin"))
from gh_api import api  # noqa: E402

REPO = "liweisi07/cf-bestip-fpk"
BRANCH = "main"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FPK = os.path.join(ROOT, "dist", "cf-bestip-domain-1.0.18-arm64.fpk")
NEW_FPK_NAME = "cf-bestip-domain-1.0.18-arm64.fpk"
OLD_FPK_NAME = "cf-bestip-domain-1.0.17-arm64.fpk"
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
        "仓库里只保留最新版：IP 版 1.0.8、域名版 1.0.17。",
        "仓库里只保留最新版：IP 版 1.0.8、域名版 1.0.18。")
    text = text.replace(
        "注：域名版 1.0.17 设置页加账号密码登录（默认 admin / admin，"
        "首次登录后请在设置页“修改密码”里改掉；订阅链接 /sub/<名字> "
        "不需要登录）；图标换成 globe + 闪电的新设计。本仓库从 1.0.17 "
        "起同时收录完整源码（app/、cmd/、config/、wizard/、scripts/、"
        "tests/），直接下载本仓库就能改代码、重新打包。",
        "注：域名版 1.0.17 设置页加账号密码登录（默认 admin / admin，"
        "首次登录后请在设置页右上角“⚙ 设置”里改掉；订阅链接 /sub/<名字> "
        "不需要登录）；图标换成 globe + 闪电的新设计。本仓库从 1.0.17 "
        "起同时收录完整源码（app/、cmd/、config/、wizard/、scripts/、"
        "tests/），直接下载本仓库就能改代码、重新打包。\n\n"
        "注：域名版 1.0.18 账号设置移到设置页右上角的“⚙ 设置”按钮后，"
        "可改账号和密码（只填新账号就是只改账号，只填新密码就是只改"
        "密码）；安装向导的服务端口（18089）与测速间隔（7 天）已预填"
        "默认值，直接点下一步即可。")
    text = text.replace(
        "另外还有一个域名版：`cf-bestip-domain-1.0.17-arm64.fpk`",
        "另外还有一个域名版：`cf-bestip-domain-1.0.18-arm64.fpk`")
    text = text.replace(
        "1.0.17 起设置页需要登录（默认 admin / admin）"
        "并可在设置页修改密码。",
        "1.0.17 起设置页需要登录（默认 admin / admin）"
        "并可在设置页修改密码；1.0.18 起账号设置移到右上角，"
        "可改账号和密码。")
    if text == orig:
        raise RuntimeError("repo README: no replacement applied")
    return text


def main():
    fpk_bytes = open(FPK, "rb").read()
    print("fpk: %s (%d bytes)" % (NEW_FPK_NAME, len(fpk_bytes)))

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
    # New fpk blob.
    fpk_sha = _create_blob(fpk_bytes, "base64")
    entries.append({"path": NEW_FPK_NAME, "mode": "100644",
                    "type": "blob", "sha": fpk_sha})
    # Updated repo README blob (content comes from the repo README,
    # not the local domain-edition README.md).
    new_readme = _updated_repo_readme(_repo_readme_text())
    readme_sha = _create_blob(new_readme.encode("utf-8"), "utf-8")
    entries.append({"path": "README.md", "mode": "100644",
                    "type": "blob", "sha": readme_sha})
    # Delete the old domain fpk.
    entries.append({"path": OLD_FPK_NAME, "mode": "100644",
                    "type": "blob", "sha": None})
    print("blobs ready: %d entries" % len(entries))

    # 3. New tree + commit + move main.
    tree = _api("POST", "/repos/%s/git/trees" % REPO,
                {"base_tree": base_tree, "tree": entries})
    commit = _api("POST", "/repos/%s/git/commits" % REPO, {
        "message": "域名版 1.0.18：账号设置移到右上角，可改账号；安装向导预填默认值",
        "tree": tree["sha"], "parents": [base_commit]})
    _api("PATCH", "/repos/%s/git/refs/heads/%s" % (REPO, BRANCH),
         {"sha": commit["sha"]})
    print("committed %s" % commit["sha"])

    # 4. Sync the local backup in ~/workspace/your_files/.
    shutil.copyfile(FPK, os.path.join(YOUR_FILES, NEW_FPK_NAME))
    old_local = os.path.join(YOUR_FILES, OLD_FPK_NAME)
    if os.path.exists(old_local):
        os.remove(old_local)
        print("deleted local %s" % OLD_FPK_NAME)
    print("copied %s to your_files" % NEW_FPK_NAME)

    # 5. Confirm the final repo state.
    listing = _api("GET", "/repos/%s/contents/" % REPO)
    names = sorted(item["name"] for item in listing)
    print("repo top level now: %s" % names)
    for item in listing:
        print("  %s (%d bytes, %s)" % (item["name"], item["size"],
                                        item["type"]))
    assert NEW_FPK_NAME in names, "new fpk missing from repo"
    assert OLD_FPK_NAME not in names, "old fpk still in repo"
    for want in ("app", "cmd", "config", "wizard", "scripts", "tests",
                 "manifest", "LICENSE"):
        assert want in names, "source %s missing from repo" % want
    print("RELEASE OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
