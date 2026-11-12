#!/bin/sh
# Build with the official fnpack tool (canonical .fpk format).
# fnpack packs everything in the project directory, so build from a clean
# copy: no dist/, no __pycache__. Output is renamed to the versioned name.
set -e
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
APP=$(grep '^appname=' "$ROOT/manifest" | cut -d= -f2 | tr -d ' ')
VER=$(grep '^version=' "$ROOT/manifest" | cut -d= -f2 | tr -d ' ')
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM
cp -r "$ROOT/app" "$ROOT/cmd" "$ROOT/config" "$ROOT/wizard" "$ROOT/manifest" "$ROOT/ICON.PNG" "$ROOT/ICON_256.PNG" "$ROOT/LICENSE" "$TMP/"
rm -rf "$TMP/app/__pycache__"
cd "$TMP"
~/workspace/fnpack build -d .
mkdir -p "$ROOT/dist"
cp "$TMP/$APP.fpk" "$ROOT/dist/cf-bestip-domain-$VER-arm64.fpk"
echo "wrote $ROOT/dist/cf-bestip-domain-$VER-arm64.fpk"
