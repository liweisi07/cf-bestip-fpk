#!/usr/bin/env python3
"""Regenerate the app icons from the generated source artwork.

The icon is a generated asset (not drawn by this script): a teal
wireframe globe with a white lightning bolt on a dark navy square,
which reads as "global network + speed" -- what this app does.
Source artwork: icon-work/media-generation-cf-bestipd-icon-*.webp
(a 1600x1600 rounded square on a white background).

This script fills the white corners with the icon's navy so the whole
square is navy (the old placeholder icon was a full square too), then
writes the four RGBA PNGs fnOS needs:

  ICON_256.PNG, ICON.PNG, app/ui/images/icon_256.png,
  app/ui/images/icon_64.png

fnOS App Center rejects packages whose ICON files are not RGBA
("应用包不符合系统要求"), so the outputs are always RGBA PNGs.
Requires Pillow (pip install pillow).
"""

import os
import sys
from collections import deque

from PIL import Image

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NAVY = (27, 31, 64, 255)


def _find_source():
    work = os.path.join(ROOT, "icon-work")
    for name in sorted(os.listdir(work)):
        if name.endswith(".webp"):
            return os.path.join(work, name)
    raise SystemExit("no source .webp found in %s" % work)


def _fill_background(im):
    """Flood-fill the white background (connected to the corners) with
    navy. The white bolt is enclosed by the navy rounded square, so
    the fill cannot reach it."""
    px = im.load()
    width, height = im.size

    def is_bg(r, g, b, a):
        return r > 250 and g > 250 and b > 250

    seen = set()
    for sx, sy in [(0, 0), (width - 1, 0),
                   (0, height - 1), (width - 1, height - 1)]:
        if (sx, sy) in seen:
            continue
        r, g, b, a = px[sx, sy]
        if not is_bg(r, g, b, a):
            continue
        queue = deque([(sx, sy)])
        seen.add((sx, sy))
        while queue:
            x, y = queue.popleft()
            px[x, y] = NAVY
            for nx, ny in ((x + 1, y), (x - 1, y),
                           (x, y + 1), (x, y - 1)):
                if (0 <= nx < width and 0 <= ny < height
                        and (nx, ny) not in seen):
                    r, g, b, a = px[nx, ny]
                    if is_bg(r, g, b, a):
                        seen.add((nx, ny))
                        queue.append((nx, ny))
    return im


def main():
    src = _find_source()
    im = _fill_background(Image.open(src).convert("RGBA"))
    for size, dest in [
        (256, "ICON_256.PNG"),
        (64, "ICON.PNG"),
        (256, os.path.join("app", "ui", "images", "icon_256.png")),
        (64, os.path.join("app", "ui", "images", "icon_64.png")),
    ]:
        out = im.resize((size, size), Image.LANCZOS)
        path = os.path.join(ROOT, dest)
        out.save(path, "PNG")
        print("wrote %s %s %s" % (path, out.size, out.mode))


if __name__ == "__main__":
    main()
