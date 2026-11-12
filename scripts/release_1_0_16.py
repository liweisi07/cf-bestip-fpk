#!/usr/bin/env python3
"""Release 1.0.16 of the domain edition to liweisi07/cf-bestip-fpk.

Steps: upload the new fpk, delete the old domain 1.0.15 fpk, update
the repo README (latest versions + 1.0.16 notes), sync the local
backup in ~/workspace/your_files/ (copy new, delete old 1.0.15),
then list the repo to confirm the final state (IP 1.0.8 + domain
1.0.16 + README only).

Lives in scripts/ (persistent, never packed into the fpk: the build
only copies app/cmd/config/wizard/manifest and the icons).
Usage: python3 scripts/release_1_0_16.py
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
FPK = os.path.join(ROOT, "dist", "cf-bestip-domain-1.0.16-arm64.fpk")
NEW_NAME = "cf-bestip-domain-1.0.16-arm64.fpk"
OLD_NAME = "cf-bestip-domain-1.0.15-arm64.fpk"
YOUR_FILES = os.path.expanduser("~/workspace/your_files")


def _contents(path):
    status, result = api("GET", "/repos/%s/contents/%s" % (REPO, path))
    if status != 200:
        raise RuntimeError("GET %s -> %s %s" % (path, status, result))
    return result


def _put(path, data_bytes, message, sha=None):
    body = {"message": message, "content": base64.b64encode(data_bytes).decode(),
            "branch": BRANCH}
    if sha:
        body["sha"] = sha
    status, result = api(
        "PUT", "/repos/%s/contents/%s" % (REPO, path), body)
    if status not in (200, 201):
        raise RuntimeError("PUT %s -> %s %s" % (path, status, result))
    return result


def _delete(path, sha, message):
    status, result = api(
        "DELETE", "/repos/%s/contents/%s" % (REPO, path),
        {"message": message, "sha": sha, "branch": BRANCH})
    if status != 200:
        raise RuntimeError("DELETE %s -> %s %s" % (path, status, result))
    return result


def main():
    fpk_bytes = open(FPK, "rb").read()
    print("fpk: %s (%d bytes)" % (NEW_NAME, len(fpk_bytes)))

    # 1. Upload the new fpk.
    _put(NEW_NAME, fpk_bytes, "域名版 1.0.16：每天固定时间测速、按地区优选")
    print("uploaded %s" % NEW_NAME)

    # 2. Delete the old domain 1.0.15 fpk.
    old = _contents(OLD_NAME)
    _delete(OLD_NAME, old["sha"], "删除旧域名版 1.0.15，只留最新版")
    print("deleted %s" % OLD_NAME)

    # 3. Update the repo README.
    readme = _contents("README.md")
    text = base64.b64decode(readme["content"]).decode("utf-8")
    orig = text
    text = text.replace(
        "仓库里只保留最新版：IP 版 1.0.8、域名版 1.0.15。",
        "仓库里只保留最新版：IP 版 1.0.8、域名版 1.0.16。")
    text = text.replace(
        "注：域名版 1.0.15 测速间隔可按天/小时/分钟自由设置"
        "（最短 5 分钟、最长 30 天，设置页三个框自由填；"
        "手动测速仍重置计时；旧配置只有天数时小时/分钟默认 0，"
        "原间隔不变）。",
        "注：域名版 1.0.15 测速间隔可按天/小时/分钟自由设置"
        "（最短 5 分钟、最长 30 天，设置页三个框自由填；"
        "手动测速仍重置计时；旧配置只有天数时小时/分钟默认 0，"
        "原间隔不变）。\n\n"
        "注：域名版 1.0.16 新增每天固定时间测速（设置页“测速计划”"
        "可选每天固定时间，如 03:00；手动测速不影响定时，同一天"
        "定时只跑一次）；优选 IP 可按地区筛选（香港 HKG、新加坡 "
        "SIN、东京 NRT、首尔 ICN、洛杉矶 LAX、圣何塞 SJC、法兰克福 "
        "FRA，或全部自动；该地区没有可用 IP 时用全局最优并记日志）。")
    text = text.replace(
        "另外还有一个域名版：`cf-bestip-domain-1.0.15-arm64.fpk`",
        "另外还有一个域名版：`cf-bestip-domain-1.0.16-arm64.fpk`")
    text = text.replace(
        "域名版 1.0.15 起可在设置页按天/小时/分钟自由改"
        "（最短 5 分钟、最长 30 天）。",
        "域名版 1.0.15 起可在设置页按天/小时/分钟自由改"
        "（最短 5 分钟、最长 30 天）；1.0.16 起还可选每天固定时间"
        "（如 03:00）与按地区优选（HKG/SIN/NRT/ICN/LAX/SJC/FRA"
        " 或全部自动）。")
    if text == orig:
        raise RuntimeError("README: no replacement applied, aborting")
    _put("README.md", text.encode("utf-8"),
         "README：最新版域名版 1.0.16，新增每天固定时间与按地区优选",
         sha=readme["sha"])
    print("README updated")

    # 4. Sync the local backup in ~/workspace/your_files/.
    shutil.copyfile(FPK, os.path.join(YOUR_FILES, NEW_NAME))
    old_local = os.path.join(YOUR_FILES, OLD_NAME)
    if os.path.exists(old_local):
        os.remove(old_local)
        print("deleted local %s" % OLD_NAME)
    print("copied %s to your_files" % NEW_NAME)

    # 5. Confirm the final repo state.
    status, listing = api("GET", "/repos/%s/contents/" % REPO)
    if status != 200:
        raise RuntimeError("list repo -> %s" % status)
    names = sorted(item["name"] for item in listing)
    print("repo now: %s" % names)
    for item in listing:
        print("  %s (%d bytes, sha %s)"
              % (item["name"], item["size"], item["sha"][:12]))
    assert names == ["README.md", "cf-bestip-1.0.8-arm64.fpk", NEW_NAME], \
        "unexpected repo contents: %s" % names
    print("RELEASE OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
