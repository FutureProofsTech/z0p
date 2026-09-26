#!/usr/bin/env python3
"""Platinum gates for z0p: fmt, clippy, tests, and bench regression.

Usage:
    tools/check.py            run every gate; fail on any regression
    tools/check.py --update   re-record tools/baseline.json from this machine

Rules (see README in this file's header for rationale):
  * fmt/clippy/tests must pass exactly.
  * Proof sizes must match the baseline byte-for-byte. Sizes are
    deterministic (pure integer math plus hashes; thread-count
    independent), so any mismatch means the wire format or the tuned
    parameters changed and a human must review.
  * Times must stay within 3x of baseline. Boxes are noisy, so timing is
    a tripwire for catastrophic regressions only, not a fine gate.
  * Unknown or missing bench rows fail: tune changes rename the
    production rows, which must be reviewed via --update.
  * Re-record the baseline on new hardware or after intentional changes.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASELINE = Path(__file__).resolve().parent / "baseline.json"
TIME_RATIO_LIMIT = 3.0

FULL_ROW = re.compile(
    r"^(.+?)\s*:\s*prove\s+([\d.]+)\s+ms\s+verify\s+([\d.]+)\s+ms\s+proof\s+(\d+)\s+B"
)
TIME_ROW = re.compile(r"^(.+?)\s*:\s*([\d.]+)\s+ms")


def run(cmd):
    print(f"$ {' '.join(cmd)}", flush=True)
    result = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    return result


def gate_fmt():
    result = run(["cargo", "fmt", "--check"])
    if result.returncode != 0:
        print("FAIL: cargo fmt --check")
        print(result.stdout[-2000:])
        return False
    print("ok: fmt")
    return True


def gate_clippy():
    result = run(["cargo", "clippy", "--all-targets", "--", "-D", "warnings"])
    if result.returncode != 0:
        print("FAIL: cargo clippy")
        print(result.stdout[-3000:])
        return False
    print("ok: clippy")
    return True


def gate_tests(profile):
    cmd = ["cargo", "test"] + (["--release"] if profile == "release" else [])
    result = run(cmd)
    if result.returncode != 0:
        print(f"FAIL: cargo test ({profile})")
        print(result.stdout[-3000:])
        return False
    print(f"ok: tests ({profile})")
    return True


def parse_bench(output):
    rows = {}
    started = False
    for line in output.splitlines():
        if line.startswith("---"):
            started = True
            continue
        if not started or ":" not in line:
            continue
        full = FULL_ROW.match(line)
        if full:
            name, prove, verify, size = full.groups()
            rows[name.strip()] = {
                "prove_ms": float(prove),
                "verify_ms": float(verify),
                "bytes": int(size),
            }
            continue
        single = TIME_ROW.match(line)
        if single:
            name, ms = single.groups()
            # Skip throughput-style rows already covered above; keep the
            # primary milliseconds figure for the rest.
            rows.setdefault(name.strip(), {}).setdefault("prove_ms", float(ms))
    return rows


def gate_bench(update):
    result = run(["cargo", "bench"])
    if result.returncode != 0:
        print("FAIL: cargo bench")
        print(result.stdout[-3000:])
        return False
    rows = parse_bench(result.stdout + result.stderr)
    if not rows:
        print("FAIL: no bench rows parsed")
        return False
    if update:
        BASELINE.write_text(json.dumps({"rows": rows}, indent=2) + "\n")
        print(f"ok: baseline re-recorded ({len(rows)} rows)")
        return True
    if not BASELINE.exists():
        print("FAIL: no baseline.json; run tools/check.py --update")
        return False
    expected = json.loads(BASELINE.read_text())["rows"]
    ok = True
    for name, want in expected.items():
        if name not in rows:
            print(f"FAIL: bench row missing: {name}")
            ok = False
            continue
        got = rows[name]
        if "bytes" in want and got.get("bytes") != want["bytes"]:
            print(f"FAIL: size drift [{name}]: {want['bytes']} -> {got.get('bytes')}")
            ok = False
        for key in ("prove_ms", "verify_ms"):
            if key in want and key in got and want[key] > 0:
                ratio = got[key] / want[key]
                print(f"  time [{name}] {key}: {want[key]:.2f} -> {got[key]:.2f} ms (x{ratio:.2f})")
                if ratio > TIME_RATIO_LIMIT:
                    print(f"FAIL: time regression [{name}] {key}: x{ratio:.2f}")
                    ok = False
    for name in rows:
        if name not in expected:
            print(f"FAIL: unknown bench row: {name} (review, then --update)")
            ok = False
    if ok:
        print("ok: bench regression")
    return ok


def main():
    update = "--update" in sys.argv
    gates = [gate_fmt(), gate_clippy(), gate_tests("debug"), gate_tests("release")]
    gates.append(gate_bench(update))
    if all(gates):
        print("ALL GATES PASS")
        return 0
    print("GATES FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
