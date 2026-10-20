#!/usr/bin/env python3
"""Check release metadata consistency for z0p.

Usage:
    tools/release_check.py          metadata only
    tools/release_check.py vX.Y.Z   also require the tag to point at HEAD
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def fail(message):
    print(f"FAIL: {message}")
    return False


def cargo_version():
    text = (ROOT / "Cargo.toml").read_text()
    match = re.search(r'^version = "([^"]+)"$', text, re.MULTILINE)
    return match.group(1) if match else None


def citation_version():
    text = (ROOT / "CITATION.cff").read_text()
    match = re.search(r"^version:\s*([^\s]+)$", text, re.MULTILINE)
    return match.group(1) if match else None


def has_changelog_entry(version):
    text = (ROOT / "CHANGELOG.md").read_text()
    pattern = rf"^## \[{re.escape(version)}\] - \d{{4}}-\d{{2}}-\d{{2}}$"
    return re.search(pattern, text, re.MULTILINE) is not None


def git(*args):
    return subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, text=True
    )


def check_tag(tag, version):
    expected = tag[1:] if tag.startswith("v") else tag
    if expected != version:
        return fail(f"tag {tag} does not match version {version}")

    result = git("rev-parse", "-q", "--verify", f"refs/tags/{tag}")
    if result.returncode != 0:
        return fail(f"tag {tag} does not exist")

    tag_commit = git("rev-list", "-n", "1", tag).stdout.strip()
    head = git("rev-parse", "HEAD").stdout.strip()
    if tag_commit != head:
        return fail(f"tag {tag} points to {tag_commit[:12]}, not HEAD {head[:12]}")
    print(f"ok: tag {tag} -> HEAD")
    return True


def main():
    version = cargo_version()
    if not version:
        fail("no package version in Cargo.toml")
        return 1

    ok = True
    citation = citation_version()
    if citation != version:
        ok = fail(f"CITATION.cff version {citation!r} != Cargo.toml {version!r}")
    else:
        print(f"ok: version {version} (Cargo.toml, CITATION.cff)")

    if not has_changelog_entry(version):
        ok = fail(f"CHANGELOG.md has no dated {version} section")
    else:
        print(f"ok: changelog {version}")

    if not (ROOT / "papers" / "z0p-eprint.pdf").is_file():
        ok = fail("papers/z0p-eprint.pdf is missing")
    else:
        print("ok: paper PDF")

    if git("rev-parse", "--git-dir").returncode == 0:
        if git("status", "--porcelain").stdout.strip():
            print("warn: working tree is dirty (expected before release commit)")
        if len(sys.argv) > 2:
            ok = fail("usage: tools/release_check.py [TAG]") and ok
        elif len(sys.argv) == 2:
            ok = check_tag(sys.argv[1], version) and ok

    if not ok:
        print("RELEASE CHECK FAILED")
        return 1
    print("RELEASE METADATA OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
