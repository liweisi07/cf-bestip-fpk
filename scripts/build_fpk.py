#!/usr/bin/env python3
"""Build cf-bestip-<version>-arm64.fpk from this project directory.

The layout follows the documented fnOS .fpk container format (verified
against the official fnOS developer skill, the Octop fnos packaging docs
and the fnos-fpk-extractor observations):

  .fpk (gzip tar, members at the package root, no top-level directory)
    manifest                 INI key=value, no extension
    manifest.checksum        MD5 hex of the app.tgz member bytes
    ICON.PNG                 64x64
    ICON_256.PNG             256x256
    LICENSE
    cmd/                     lifecycle scripts (main, *_callback, ...)
    config/                  privilege, resource
    wizard/                  install, config
    app.tgz                  gzip tar of the app/ contents (no app/
                             prefix), i.e. the files installed to
                             /var/apps/<appname>/target/

Tarballs are built deterministically (mtime/uid/gid zeroed, explicit
member lists, no stray files) so rebuilds are byte-identical.
"""

import hashlib
import io
import os
import sys
import tarfile

ROOT = os.path.join(os.path.dirname(__file__), "..")
ROOT = os.path.normpath(ROOT)

APP_FILES = [
    ("app.py", 0o644),
    ("rewriter.py", 0o644),
    ("cfdns.py", 0o644),
    ("cfst.py", 0o644),
    ("cf_ranges.txt", 0o644),
    ("ip.txt", 0o644),
    ("cfst", 0o755),
    ("ui/", None, 0o755),
    ("ui/config", 0o644),
    ("ui/images/", None, 0o755),
    ("ui/images/icon_64.png", 0o644),
    ("ui/images/icon_256.png", 0o644),
]

OUTER_FILES = [
    ("manifest", 0o644),
    ("manifest.checksum", 0o644),
    ("ICON.PNG", 0o644),
    ("ICON_256.PNG", 0o644),
    ("LICENSE", 0o644),
    ("cmd/", None, 0o755),
    ("cmd/main", 0o755),
    ("cmd/install_callback", 0o755),
    ("cmd/uninstall_init", 0o755),
    ("cmd/config_callback", 0o755),
    ("cmd/upgrade_callback", 0o755),
    ("config/", None, 0o755),
    ("config/privilege", 0o644),
    ("config/resource", 0o644),
    ("wizard/", None, 0o755),
    ("wizard/install", 0o644),
    ("wizard/config", 0o644),
    ("wizard/upgrade", 0o644),
    ("wizard/uninstall", 0o644),
]


def parse_manifest(path):
    fields = {}
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            fields[key.strip()] = value.strip()
    return fields


def build_tar(members):
    """members: list of (arcname, filesystem path or None, mode).

    A None path emits a directory entry (arcname must end with "/").
    USTAR format is used: fnpack/Go tooling emits USTAR, and a strict
    installer parser is more likely to accept it than GNU magic.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz",
                      format=tarfile.USTAR_FORMAT) as tf:
        for arcname, fs_path, mode in members:
            if fs_path is None:
                info = tarfile.TarInfo(name=arcname)
                info.type = tarfile.DIRTYPE
                info.size = 0
                info.mtime = 0
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mode = mode
                tf.addfile(info)
                continue
            with open(fs_path, "rb") as fh:
                data = fh.read()
            info = tarfile.TarInfo(name=arcname)
            info.size = len(data)
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mode = mode
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def main():
    manifest = parse_manifest(os.path.join(ROOT, "manifest"))
    appname = manifest.get("appname", "cfbestipd")
    version = manifest.get("version", "1.0.0")
    print("appname=%s version=%s platform=%s"
          % (appname, version, manifest.get("platform")))

    # 1. Inner app.tgz (contents of app/, no app/ prefix).
    app_members = []
    for entry in APP_FILES:
        rel, mode = entry[0], entry[-1]
        if rel.endswith("/"):
            app_members.append((rel, None, mode))
            continue
        fs_path = os.path.join(ROOT, "app", rel)
        if not os.path.isfile(fs_path):
            print("missing app file: %s" % fs_path, file=sys.stderr)
            return 1
        app_members.append((rel, fs_path, mode))
    app_tgz = build_tar(app_members)
    print("app.tgz: %d bytes, %d members" % (len(app_tgz), len(app_members)))

    # 2. manifest.checksum = MD5 of app.tgz bytes.
    checksum = hashlib.md5(app_tgz).hexdigest()

    # 3. Stage the outer members (checksum computed above).
    stage = os.path.join(ROOT, "dist", "stage")
    os.makedirs(stage, exist_ok=True)
    with open(os.path.join(stage, "manifest.checksum"), "w") as fh:
        fh.write(checksum + "\n")
    with open(os.path.join(stage, "app.tgz"), "wb") as fh:
        fh.write(app_tgz)

    def stage_path(name):
        if name == "manifest.checksum":
            return os.path.join(stage, "manifest.checksum")
        if name == "app.tgz":
            return os.path.join(stage, "app.tgz")
        return os.path.join(ROOT, name)

    outer_members = []
    for entry in OUTER_FILES:
        rel, mode = entry[0], entry[-1]
        if rel.endswith("/"):
            outer_members.append((rel, None, mode))
            continue
        fs_path = stage_path(rel)
        if not os.path.isfile(fs_path):
            print("missing outer file: %s" % fs_path, file=sys.stderr)
            return 1
        outer_members.append((rel, fs_path, mode))
    outer_members.append(("app.tgz", os.path.join(stage, "app.tgz"), 0o644))

    out_dir = os.path.join(ROOT, "dist")
    os.makedirs(out_dir, exist_ok=True)
    out_name = "cf-bestip-domain-%s-arm64.fpk" % version
    out_path = os.path.join(out_dir, out_name)
    fpk_bytes = build_tar(outer_members)
    with open(out_path, "wb") as fh:
        fh.write(fpk_bytes)
    print("wrote %s (%d bytes)" % (out_path, len(fpk_bytes)))
    print("manifest.checksum: %s" % checksum)
    return 0


if __name__ == "__main__":
    sys.exit(main())
