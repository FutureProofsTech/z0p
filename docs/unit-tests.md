# Unit tests — breakdown

`cargo test --lib` (also run with `--release` by `tools/check.py`).
Measured: 2026-10-20 — **240 passed, 0 failed.**

## Per-module counts

| Module | Tests | What they pin |
|---|---|---|
| `air` | 22 | honest/tampered openings, ZK masking, caps, grinding, encoding, batched compose identity, forged next-column claim, shifted-opening tamper, downgraded FRI bound |
| `babybear` | 7 | wrap arithmetic, Barrett vs `%` (100k random + corners), inverse, two-adicity, batch inversion |
| `basefold` | 14 | honest n=1/2/5/8, wrong value/point/commitment, tampered sumcheck/layer/query, grinding roundtrip, nonzero nonce, params/domain caps, codec roundtrip/version |
| `ext4` | 1 | quartic tower axioms (`u²=11`, `v²=u`), inversion, base embedding/scaling, canonical encoding |
| `blind` | 5 | masking degree/length, on-domain agreement, off-domain randomness |
| `codec` | 2 | direction bits, capped counts, truncation, non-canonical fields, version/trailer |
| `fold` | 15 | IVC chaining, broken chains, bad segments, caps, encoding, shifted-opening tamper, forged out_a boundary |
| `fri` | 20 | roundtrips, tampering, rate gates both directions, grinding, caps, dimensions, encodings |
| `gf2` | 7 | F8/F64/F128 arithmetic, inverses, distributivity |
| `hash` | 6 | BLAKE3 KATs (empty/`abc`/multi-chunk), single-chunk identity, incremental/split inputs, chunk boundaries |
| `lookup` | 8 | membership, non-members, tampered multiplicities, forged fractional multiplicities |
| `merkle` | 7 | prove/verify, padding, flat-vs-nested, capped roundtrips, oversized paths, SIMD batch equivalence |
| `mle` | 5 | evaluation corners, variable fixing, eq-polynomial sums |
| `ntt` | 7 | Horner cross-checks (incl. parallel path at 2¹⁶/2¹⁷), determinism, base/extension roundtrips, RS extension |
| `par` | 2 | parallel-vs-sequential identity, sequential thresholds |
| `range` | 17 | honest/out-of-range/boundary, bit columns, ZK masking, caps, encodings, downgraded FRI bound |
| `upcs` | 25 | honest openings (n=1..64, four points), multi-point batches (k=1..n, up to 16), duplicate/oversized sets, wrong value/point/quotient, leaf/path/commitment/FRI tampering, caps/dim gates, encodings |
| `gemini` | 16 | honest n=0..5, Möbius vs `Mle`, per-layer multi-point shape, wrong value/point, tampered layers/values/openings, shape/codec/transcript, zero coordinates |
| `recursion` | 12 | honest fold chains (2/3 folds, padding), wrong output, broken chain, opening/shift tampering, caps, encoding, degree bound |
| `rng` | 7 | ChaCha20 vectors, determinism, key sensitivity, key-material redaction |
| `sumcheck` | 7 | product sums, tampered rounds/finals, transcript binding, shapes |
| `table` | 18 | membership/non-membership, claims, ZK masking, caps, bound formula, encodings, downgraded FRI bound |
| `transcript` | 10 | determinism, domain separation, extension challenges, PoW roundtrips/tampering, invalid query domains, parallel-scan identity |

## Run

```sh
cargo test --lib              # debug
cargo test --lib --release    # optimized (same 240, also gated)
```
