# Audit guide

**Status: unaudited.** This document is the entry point for external
reviewers. It states what to check, how to reproduce the evidence, and what
the project does *not* claim.

## Scope

The review surface is the Rust crate in `src/` and its public API:

| Area | Modules | Main properties |
|---|---|---|
| Fields | `babybear`, `ext4`, `gf2` | canonical arithmetic, inverses, tower laws |
| Hashing / commitments | `hash`, `merkle` | BLAKE3-256, domain separation, caps |
| Polynomial machinery | `ntt`, `fri`, `mle`, `sumcheck`, `upcs` | low-degree testing, openings |
| Proof systems | `air`, `range`, `table`, `fold`, `vm` | transition and boundary constraints |
| Masking / randomness | `blind`, `rng` | query-response hiding, seed handling |
| Wire format | `codec` | canonical, fail-closed decoding (`VERSION = 5`) |

The formal specification is [docs/yellowpaper.md](docs/yellowpaper.md). The
design and performance overview is [docs/whitepaper.md](docs/whitepaper.md).

## Reproduce the gates

```sh
python3 tools/check.py          # fmt, clippy, debug+release tests, bench regression
RUSTC_BOOTSTRAP=1 cargo test --features simd
BENCH_ROW=N1048576 cargo bench  # 1M-step AIR row
```

The gate pins proof sizes byte-for-byte and times within 3x of
`tools/baseline.json`. The 1M-step AIR reference row is approximately
1.76 s prove / 2.2 ms verify / 203,553 B on the development machine; the
SIMD path is approximately 1.56 s. Treat times as hardware-dependent and
sizes as normative.

Current test counts: 267 library tests, 9 hardening tests, 13 security
tests, 10 red-team tests, and 5 doc tests.

## Security invariants to review

- **Rate gate on both sides**: declared degree must satisfy
  `degree_bound + 1 <= lde_len / 2`.
- **Transcript binding**: dimensions are absorbed before challenges;
  proof-of-work is verified against the replayed history and queries are
  sampled after grinding.
- **Authenticated next rows**: AIR/fold next-row values come from the same
  committed columns at the omega-shifted index, not an independent witness.
- **Committed leaves**: FRI and AIR trace leaves are hashed from the exact
  revealed 64-byte values; paths and caps are shape-checked before hashing.
- **Fail-closed decoding**: canonical field elements, bounded counts, no
  trailing bytes, no allocation before limits are checked.
- **No `unsafe` and no dependencies**: enforced by the manifest and CI.

## Evidence

- [docs/security-tests.md](docs/security-tests.md) — attack vectors and
  closed findings.
- [docs/red-team.md](docs/red-team.md) — cross-proof and false-statement
  attempts.
- [docs/unit-tests.md](docs/unit-tests.md) — per-module test breakdown.
- [docs/benchmarks.md](docs/benchmarks.md) — methodology and exact sizes.
- [CHANGELOG.md](CHANGELOG.md) — wire-format history and fixes.

## Known limitations

- No external audit yet; soundness figures are conjectured (FRI/Johnson
  heuristic plus Fiat–Shamir in the QROM).
- The advertised ~100-bit schedule is a query/PoW budget, not an end-to-end
  theorem.
- Pre-1.0: the latest `main` or latest tagged release is the supported
  version.
- No recursion, general circuit compiler, or zkVM; `lookup`/`sumcheck` leak
  table contents, and ZK masking is query-response hiding, not full
  program privacy.
- SIMD is an optional nightly feature; the default path is stable Rust.

## Reporting

Do not open a public issue for a suspected soundness or memory-safety bug.
Follow [SECURITY.md](SECURITY.md) and report privately to
**futureproofs@proton.me**.
