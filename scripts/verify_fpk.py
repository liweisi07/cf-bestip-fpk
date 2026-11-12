#!/usr/bin/env python3
"""Verify a built cf-bestip .fpk against the documented fnOS format.

Checks (each printed PASS/FAIL):
  1. Outer gzip-tar members are package-root entries, no top-level dir.
  2. All required outer members exist (manifest, app.tgz, icons,
     icons, LICENSE, cmd/, config/, wizard/, app.tgz).
  3. The manifest's checksum line equals the MD5 of the app.tgz
     member bytes (this is fnpack's mechanism; there is no separate
     manifest.checksum member in fnpack output).
  4. manifest parses and declares appname / version / platform=arm /
     service_port.
  5. Inner app.tgz members are the app/ contents (no app/ prefix) and
     include all app files.
  6. The bundled cfst member is an AArch64 ELF binary.
  7. All Python files in app.tgz compile.
  8. All JSON files in the package parse.
"""

import hashlib
import io
import json
import py_compile
import sys
import tarfile

REQUIRED_OUTER = {
    "manifest", "ICON.PNG", "ICON_256.PNG", "LICENSE",
    "app.tgz",
    "cmd/main", "cmd/install_callback", "cmd/uninstall_init",
    "cmd/config_callback", "cmd/upgrade_callback",
    "config/privilege", "config/resource",
    "wizard/install", "wizard/config",
    "wizard/upgrade", "wizard/uninstall",
    "cmd/install_init", "cmd/uninstall_callback", "cmd/upgrade_init",
}

REQUIRED_INNER = {
    "app.py", "rewriter.py", "cfdns.py", "cfst.py", "cf_ranges.txt", "ip.txt", "cfst",
    "ui/config", "ui/images/icon_64.png", "ui/images/icon_256.png",
}

EM_AARCH64 = 183


def check(label, ok, detail=""):
    print("%s %s %s" % ("PASS" if ok else "FAIL", label, detail))
    return ok


def main():
    path = sys.argv[1]
    all_ok = True
    with open(path, "rb") as fh:
        outer_bytes = fh.read()
    outer = tarfile.open(fileobj=io.BytesIO(outer_bytes), mode="r:gz")
    members = outer.getmembers()
    names = [m.name for m in members]
    all_ok &= check(
        "outer members at package root (no top-level dir)",
        all("/" not in n or not n.startswith("cf-bestip")
            for n in names) and not any(
                n.startswith("cf-bestip-") for n in names),
        "(%d members)" % len(names),
    )
    all_ok &= check(
        "required outer members present",
        REQUIRED_OUTER.issubset(set(names)),
        "missing: %s" % sorted(REQUIRED_OUTER - set(names)),
    )
    blob = {}
    for m in members:
        if m.isfile():
            blob[m.name] = outer.extractfile(m).read()
    app_tgz = blob.get("app.tgz", b"")
    manifest = {}
    for line in blob.get("manifest", b"").decode("utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            manifest[key.strip()] = value.strip()
    actual = hashlib.md5(app_tgz).hexdigest()
    all_ok &= check(
        "manifest checksum line == md5(app.tgz)",
        manifest.get("checksum") == actual,
        "(%s)" % manifest.get("checksum"),
    )
    all_ok &= check(
        "no stale manifest.checksum member (fnpack does not emit one)",
        "manifest.checksum" not in names,
    )
    all_ok &= check(
        "manifest fields",
        manifest.get("platform") == "arm"
        and manifest.get("service_port") == "18089"
        and manifest.get("appname") == "cfbestipd"
        and manifest.get("source") == "thirdparty",
        str(manifest),
    )
    inner = tarfile.open(fileobj=io.BytesIO(app_tgz), mode="r:gz")
    inner_names = [m.name for m in inner.getmembers()]
    all_ok &= check(
        "inner app.tgz members (app/ contents, no app/ prefix)",
        REQUIRED_INNER.issubset(set(inner_names))
        and not any(n.startswith("app/") for n in inner_names),
        "missing: %s" % sorted(REQUIRED_INNER - set(inner_names)),
    )
    cfst_blob = None
    for m in inner.getmembers():
        if m.name == "cfst":
            cfst_blob = inner.extractfile(m).read()
    elf_ok = False
    if cfst_blob and len(cfst_blob) > 20:
        import struct
        machine = struct.unpack("<H", cfst_blob[18:20])[0]
        elf_ok = (
            cfst_blob[:4] == b"\x7fELF"
            and cfst_blob[4] == 2
            and machine == EM_AARCH64
        )
    all_ok &= check("bundled cfst is AArch64 ELF", elf_ok)
    py_ok = True
    for m in inner.getmembers():
        if m.name.endswith(".py"):
            src = inner.extractfile(m).read()
            try:
                compile(src, m.name, "exec")
            except SyntaxError as exc:
                py_ok = False
                print("  syntax error in %s: %s" % (m.name, exc))
    all_ok &= check("python files in package compile", py_ok)
    json_ok = True
    for name in ("config/privilege", "config/resource",
                 "wizard/install", "wizard/config",
                 "wizard/upgrade", "wizard/uninstall"):
        try:
            json.loads(blob[name].decode("utf-8"))
        except (KeyError, ValueError) as exc:
            json_ok = False
            print("  bad json %s: %s" % (name, exc))
    for m in inner.getmembers():
        if m.name == "ui/config":
            try:
                json.loads(inner.extractfile(m).read().decode("utf-8"))
            except ValueError as exc:
                json_ok = False
                print("  bad json ui/config: %s" % exc)
    all_ok &= check("json files parse", json_ok)

    # 9. Icons must be RGBA PNGs (color type 6): fnOS App Center rejects
    # packages whose ICON files are RGB ("应用包不符合系统要求").
    def _png_color_type(blob):
        if len(blob) < 30 or blob[:8] != b"\x89PNG\r\n\x1a\n":
            return None
        return blob[25]
    icon_ok = True
    for name, blob in (("ICON.PNG", blob.get("ICON.PNG")),
                       ("ICON_256.PNG", blob.get("ICON_256.PNG"))):
        if _png_color_type(blob or b"") != 6:
            icon_ok = False
            print("  non-RGBA outer icon %s" % name)
    inner_blob = {}
    for m in inner.getmembers():
        if m.isfile():
            inner_blob[m.name] = inner.extractfile(m).read()
    for name in ("ui/images/icon_64.png", "ui/images/icon_256.png"):
        if _png_color_type(inner_blob.get(name, b"")) != 6:
            icon_ok = False
            print("  non-RGBA inner icon %s" % name)
    all_ok &= check("icons are RGBA PNGs", icon_ok)
    print("RESULT: %s" % ("ALL CHECKS PASSED" if all_ok else "FAILURES"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
