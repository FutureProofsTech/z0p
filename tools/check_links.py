#!/usr/bin/env python3
"""Check relative Markdown links without network access.

External URLs, anchors, and mailto links are skipped. Relative targets must
exist on disk; anchor fragments are not validated.
"""

import re
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git", "target"}
LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
FENCE = re.compile(r"```.*?```", re.DOTALL)
INLINE = re.compile(r"`[^`]*`")


def markdown_files():
    for path in ROOT.rglob("*.md"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        yield path


def check_file(path):
    text = FENCE.sub("", path.read_text())
    text = INLINE.sub("", text)
    broken = []
    for match in LINK.finditer(text):
        raw = match.group(1).strip()
        if raw.startswith("<") and raw.endswith(">"):
            raw = raw[1:-1]
        if raw.startswith(("http://", "https://", "mailto:", "#")):
            continue
        target = raw.split("#", 1)[0].split("?", 1)[0]
        if not target:
            continue
        target = unquote(target)
        if not (path.parent / target).exists():
            broken.append((path.relative_to(ROOT), raw))
    return broken


def main():
    broken = []
    files = list(markdown_files())
    for path in files:
        broken.extend(check_file(path))
    if broken:
        for path, target in broken:
            print(f"FAIL: {path}: missing {target}")
        return 1
    print(f"ok: {len(files)} Markdown files, relative links resolve")
    return 0


if __name__ == "__main__":
    sys.exit(main())
