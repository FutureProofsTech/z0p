# Unit tests — breakdown

`cargo test --lib` (also run with `--release` by `tools/check.py`).
Measured: 2026-09-26 — **155 passed, 0 failed.**

## Per-module counts

| Module | Tests | What they pin |
|---|---|---|
| `air` | 19 | honest/tampered openings, ZK masking, caps, grinding, encoding, batched compose identity |
| `babybear` | 7 | wrap arithmetic, Barrett vs `%` (100k random + corners), inverse, two-adicity, batch inversion |
| `blind` | 5 | masking degree/length, on-domain agreement, off-domain randomness |
| `codec` | 2 | direction bits, capped counts, truncation, non-canonical fields, version/trailer |
| `fold` | 13 | IVC chaining, broken chains, bad segments, caps, encoding |
| `fri` | 19 | roundtrips, tampering, rate gates both directions, grinding, caps, dimensions, encodings |
| `gf2` | 7 | F8/F64/F128 arithmetic, inverses, distributivity |
| `hash` | 6 | BLAKE3 KATs (empty/`abc`/multi-chunk), single-chunk identity, incremental/split inputs, chunk boundaries |
| `lookup` | 6 | membership, non-members, tampered multiplicities |
| `merkle` | 5 | prove/verify, padding, flat-vs-nested, capped roundtrips |
| `mle` | 5 | evaluation corners, variable fixing, eq-polynomial sums |
| `ntt` | 6 | Horner cross-checks (incl. parallel path at 2¹⁶/2¹⁷), determinism, roundtrips, RS extension |
| `par` | 2 | parallel-vs-sequential identity, sequential thresholds |
| `range` | 16 | honest/out-of-range/boundary, bit columns, ZK masking, caps, encodings |
| `rng` | 7 | ChaCha20 vectors, determinism, key sensitivity, key-material redaction |
| `sumcheck` | 6 | product sums, tampered rounds/finals, transcript binding, shapes |
| `table` | 16 | membership/non-membership, claims, ZK masking, caps, bound formula, encodings |
| `transcript` | 8 | determinism, domain separation, PoW roundtrips/tampering, parallel-scan identity |

## Run

```sh
cargo test --lib              # debug
cargo test --lib --release    # optimized (same 155, also gated)
```
