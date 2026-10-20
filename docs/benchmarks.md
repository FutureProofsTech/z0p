# Benchmarks — measured results

Source: `benches/speed_size.rs` (`cargo bench`), release profile, median of
N runs (plus one warmup). Every benchmark verifies its proof once outside
the timed region. Rows with a separate byte counter also assert it equals
`to_bytes().len()`, so a passing run gates correctness and wire stability.

- Machine: 16 cores, 31 GB RAM, `cargo`/`rustc 1.99.0`
- Measured: 2026-10-20
- Filter partial rows with `BENCH_ROW=substr`, e.g.
  `BENCH_ROW=N65536 cargo bench`
- `tools/check.py` pins all 23 rows: sizes must match byte-for-byte, times
  must stay within 3× of `tools/baseline.json`

## Production shapes (`for_security(100)` — 100-bit query/PoW; Fp4 challenges)

Blowup 16, rate 1/16, 40 queries, 20-bit grinding, size-optimal final
layer and Merkle cap height.

| Row | Prove (ms) | Verify (ms) | Proof (B) | Proof (KiB) |
|---|---|---|---|---|
| `fri prod B16Q40G20C4F16` (poly-256) | 17.34 | 0.76 | 29,378 | 28.7 |
| `air prod B16Q40G20C4F16` (fib-64) | 14.53 | 0.76 | 35,861 | 35.0 |
| `fri prod P1024 B16Q40G20C4F16` | 71.37 | 0.95 | 43,174 | 42.2 |
| `air prod N1024 B16Q40G20C4F16` | 39.31 | 1.22 | 71,373 | 69.7 |
| `air prod N8192 B16Q40G20C4F32` | 81.12 | 1.62 | 104,033 | 101.6 |
| `air prod N65536 B16Q40G20C4F16` | 332.03 | 2.09 | 144,441 | 141.1 |
| `air prod N1048576 B16Q40G20C4F16` | 5,194.42 | 2.32 | 206,353 | 201.5 |

Marginal cost per step (1M row): `5194.42 / 1048576 ≈ 4.95 µs/step`
(≈202k steps/s). The 20-bit PoW grind is amortized over the trace at
scale; on small production rows it dominates run-to-run variance
(the N8192 row fluctuates ~75–100 ms between runs).

**Verification is size-independent.** The verifier derives each FRI domain
point on demand (`O(log)` field ops per query, `O(final_size)` for the degree
check) instead of materializing the `O(lde_len)` folded layer stack. Verify
time therefore stays in the low-millisecond range from 1,024 steps to 1M
steps; earlier revisions spent 0.29 s verifying the 1M-step proof purely
building that table.

## Compact multilinear PCS (1,024 coefficients)

The BaseFold rows open a 10-variable polynomial with blowup 16, 40
queries, and 20-bit grinding; Gemini uses the `O(n)`-opening v1 path with
one multi-point `upcs` proof per layer. The BaseFold-style prototype
commits one root,
reduces `f(r)` to `c(rho)` with sumcheck, and reuses the sumcheck
challenges for Möbius FRI folds. Optional Merkle caps replace the top path
steps of every committed layer with one cap frontier; the cap root is
hashed back to the commitment (top layer) or the proof's layer roots (lower
layers). It is not wired into the AIR stack, but it now backs the
committed lookup below; full paths still make each query open one Merkle
path per layer.

| Row | Prove (ms) | Verify (ms) | Proof (B) | Proof (KiB) |
|---|---|---|---|---|
| `basefold P1024 B16Q40G20` | 43.63 | 1.14 | 127,658 | 124.7 |
| `basefold-capped P1024 B16Q40G20C4` | 44.78 | 0.91 | 80,018 | 78.1 |
| `gemini P1024 B16Q40G20` | 693.04 | 54.42 | 888,672 | 867.8 |

Cap height 4 shrinks the BaseFold proof by ~37% on this shape. Against
Gemini the uncapped prototype is ~16× faster to prove, ~48× faster to
verify, and ~7× smaller; capped is ~19× faster to prove, ~60× faster to
verify, and ~11× smaller. The comparison is a prototype result, not an
audit: the sumcheck/FRI composition needs a written soundness argument,
and WHIR-style batching is required before large tables.


## Committed large-table lookup (`lookup_pcs`)

The committed LogUp prototype commits the padded witness, table,
multiplicities, and both quotient columns with BaseFold. The verifier sees
five commitment roots and eight BaseFold openings: two for each quotient
column, one for the witness, one for the table, and two for the
multiplicities. The witness and table columns never travel on the wire.

| Row | Prove (ms) | Verify (ms) | Commitments + proof (B) | (KiB) |
|---|---|---|---|---|
| `lookup-pcs 1024-in-1024 B16Q40G20C4` | 367.04 | 20.67 | 642,443 | 627.4 |

Four sumchecks cover the rational identity and read-checks; the total
multiplicity weight is folded into the sum-t claim with a fresh `gamma`.
This is a committed-input argument, not zero-knowledge: BaseFold has no
hiding layer, candidate inputs can be tested against the commitment roots,
and the column values are extension-field elements (base-field membership
would need an extra constraint). The eight separate openings are the main
size cost; batching them behind one compact proof is the next step.

## Bench shapes (fast, ~18 conjectured bits)

| Row | Prove (ms) | Verify (ms) | Proof (B) | Proof (KiB) |
|---|---|---|---|---|
| `fri poly256 B4 Q12` | 1.04 | 0.14 | 11,522 | 11.3 |
| `air fib64` | 0.88 | 0.17 | 16,305 | 15.9 |
| `range 16-bit` | 0.44 | 0.09 | 5,217 | 5.1 |
| `table 4-entry` | 0.33 | 0.06 | 4,673 | 4.6 |
| `lookup 64-in-16` | 0.29 | 0.20 | 2,897 | 2.8 |
| `fold 4x8 fib` | 0.74 | 0.22 | 16,845 | 16.5 |
| `air fib1024` | 6.45 | 0.32 | 29,097 | 28.4 |

Lookup's v4 extension-field proof is larger than its former base-field form: multiplicities,
quotients, and four sumcheck proofs now carry 16-byte `Fp4` values
(688 -> 2,897 B). Tower-norm `Fp4` inversion brings prove/verify back to
~0.29/0.19 ms. Proof sizes now come from the real canonical codec rather
than a hand-written estimator. The AIR/FRI production rows above are
unchanged by this migration.

## Primitives

| Row | Result |
|---|---|
| `blake3 1MiB` | 1.42 ms (load-dependent) |
| `gf2 F64 mul` | 287.31 ms for 1M ops (3.5 Mops/s) |
| `bb field mul` | 7.36 ms for 1M ops (~136 Mops/s) |
| `ntt forward 2^14` | 0.33 ms |
| `merkle 64k leaves` | 3.96 ms |

## Vectorized hashing (`--features simd`, nightly; v1-era rows)

Tier 4 batches Merkle leaf/node BLAKE3 eight lanes at a time with
`std::simd` (`u32x8`), byte-identical to the scalar path. Same-session
paired runs on this box (which is not idle), nightly:

| Row | Scalar | `--features simd` |
|---|---|---|
| `merkle 64k leaves` (quiet) | 8.5 ms | **3.2 ms** (~2.6×) |
| `merkle 64k leaves` (loaded) | 9.9 ms | **8.5 ms** (~1.2×) |
| `air prod N1048576` prove | 4,558 ms | **3,980 ms** (~13%) |

SIMD is faster in every paired run; absolute gains depend heavily on box
load (the scalar baseline row itself ranged 3.3–13.9 ms across sessions).
The proof rows above predate the v3 `Fp4` wire format and have not been
re-baselined with SIMD; rerun nightly before quoting them for v3.
End-to-end gains are bounded because NTT, composition, and the transcript
are the other large prove costs. Builds without the feature are unaffected
(scalar fallback, stable MSRV 1.74).

## Reproduce

```sh
cargo bench                          # all 23 rows
BENCH_ROW=N1048576 cargo bench       # single scaled row
BENCH_ROW="air prod" cargo bench     # all production AIR rows
python3 tools/check.py               # full gates incl. bench regression
python3 tools/check.py --update      # re-record baseline (review diffs first)
cargo +nightly test --features simd  # SIMD/scalar byte-equivalence
cargo +nightly bench --features simd # SIMD rows (nightly toolchain)
```
