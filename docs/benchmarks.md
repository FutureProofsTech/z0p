# Benchmarks — measured results

Source: `benches/speed_size.rs` (`cargo bench`), release profile, median of
N runs plus one warm-up. Every benchmark verifies its proof once outside the
timed region. Rows with a separate byte counter also assert that the counter
equals `to_bytes().len()`, so a passing run gates correctness and wire
stability.

- Machine: 16 cores, 31 GB RAM, `cargo`/`rustc 1.99.0`
- Measured: **2026-11-05**
- Filter partial rows with `BENCH_ROW=substr`, e.g.
  `BENCH_ROW=N65536 cargo bench`
- `tools/check.py` pins all **24** rows: sizes must match byte-for-byte,
  times must stay within 3× of `tools/baseline.json`
- Times are hardware- and load-dependent; proof sizes are deterministic

## Production shapes (`for_security(100)` — 100-bit query/PoW)

Blowup 16, rate 1/16, 40 queries, 20-bit grinding, size-optimal final layer
and Merkle cap height.

| Row | Prove (ms) | Verify (ms) | Proof (B) | Proof (KiB) |
|---|---:|---:|---:|---:|
| `fri prod B16Q40G20C4F16` (poly-256) | 10.59 | 0.25 | 29,378 | 28.7 |
| `air prod B16Q40G20C4F16` (fib-64) | 11.99 | 0.27 | 33,061 | 32.3 |
| `fri prod P1024 B16Q40G20C4F16` | 21.50 | 0.31 | 43,174 | 42.2 |
| `air prod N1024 B16Q40G20C4F16` | 37.05 | 0.48 | 68,573 | 67.0 |
| `air prod N8192 B16Q40G20C4F32` | 49.81 | 0.59 | 101,233 | 98.9 |
| `air prod N65536 B16Q40G20C4F16` | 115.49 | 0.90 | 141,641 | 138.3 |
| `air prod N1048576 B16Q40G20C4F16` | **1,733.55** | **1.13** | **203,553** | **198.8** |

Marginal cost per step (1M row):

```text
1733.55 ms / 1048576 = 1.653 µs/step
1048576 / 1.73355 s  = 604,872 steps/s
```

The 20-bit PoW grind is amortized over the trace at scale; on small
production rows it dominates run-to-run variance. The N8192 row fluctuates
with machine load.

**Verification is size-independent.** The verifier derives each FRI domain
point on demand (`O(log)` field operations per query, `O(final_size)` for the
degree check) instead of materializing the `O(lde_len)` folded layer stack.
Verify time therefore stays in the low-millisecond range from 1,024 steps to
1M steps. Earlier revisions spent ~0.29 s verifying the 1M-step proof purely
by building that table.

## Compact multilinear PCS (1,024 coefficients)

The BaseFold rows open a 10-variable polynomial with blowup 16, 40 queries,
and 20-bit grinding. Gemini uses the `O(n)`-opening v1 path with one
multi-point `upcs` proof per layer. BaseFold commits one root, reduces
`f(r)` to `c(rho)` with sumcheck, and reuses the sumcheck challenges for
Möbius FRI folds. Optional Merkle caps replace the top path steps of every
committed layer with one cap frontier; the cap root is hashed back to the
commitment (top layer) or the proof's layer roots (lower layers).

| Row | Prove (ms) | Verify (ms) | Proof (B) | Proof (KiB) |
|---|---:|---:|---:|---:|
| `basefold P1024 B16Q40G20` | 22.65 | 0.88 | 127,658 | 124.7 |
| `basefold-capped P1024 B16Q40G20C4` | 22.91 | 0.63 | 80,018 | 78.1 |
| `gemini P1024 B16Q40G20` | 317.96 | 7.36 | 887,872 | 867.1 |

Cap height 4 shrinks the BaseFold proof by **37.3%** (127,658 → 80,018 B).
Against Gemini:

| Comparison | Uncapped BaseFold | Capped BaseFold |
|---|---:|---:|
| Prove speedup | 14.0× | 13.9× |
| Verify speedup | 8.4× | 11.7× |
| Size reduction | 7.0× | 11.1× |

The comparison is a prototype result, not an audit: the sumcheck/FRI
composition needs a written soundness argument, and WHIR-style batching is
required before large tables.

## Committed large-table lookup (`lookup_pcs`)

The committed LogUp prototype commits the padded witness, table,
multiplicities, and both quotient columns with BaseFold. The verifier sees
five commitment roots and eight BaseFold openings: two for each quotient
column, one for the witness, one for the table, and two for the
multiplicities. The witness and table columns never travel on the wire.

| Row | Prove (ms) | Verify (ms) | Commitments + proof (B) | (KiB) |
|---|---:|---:|---:|---:|
| `lookup-pcs 1024-in-1024 B16Q40G20C4` | 273.01 | 5.77 | 642,443 | 627.4 |

Four sumchecks cover the rational identity and read-checks; the total
multiplicity weight is folded into the sum-t claim with a fresh `gamma`.
This is a committed-input argument, not zero-knowledge: BaseFold has no
hiding layer, candidate inputs can be tested against the commitment roots,
and the column values are extension-field elements (base-field membership
would need an extra constraint). The eight separate openings are the main
size cost; batching them behind one compact proof is the next step.

## Program execution (`vm`)

The `vm` prototype runs a public two-register straight-line program from a
private initial state and proves the public final output. Public one-hot
selectors and immediate polynomials drive committed `A`/`B` columns; the
composition uses selector-weighted transition quotients plus final-row
boundaries at degree below `2n - 1`.

| Row | Prove (ms) | Verify (ms) | Proof (B) | Proof (KiB) |
|---|---:|---:|---:|---:|
| `vm 64-step B16Q12C2` | 0.69 | 0.18 | 14,933 | 14.6 |

This is a fast, weak query schedule and the plain (non-hiding) proving path:
programs are public and straight-line, the initial state is the witness, and
FRI query openings reveal trace values. `vm::prove_zk` masks both trace
columns for query-response hiding (not benchmarked here; its LDE is larger,
so `final_size` must be sized for it). Control flow, memory, instruction
privacy, and a hiding PCS/sumcheck remain roadmap items.

## Bench shapes (fast, ~18 conjectured bits)

| Row | Prove (ms) | Verify (ms) | Proof (B) | Proof (KiB) |
|---|---:|---:|---:|---:|
| `fri poly256 B4 Q12` | 0.15 | 0.08 | 11,522 | 11.3 |
| `air fib64` | 0.17 | 0.11 | 15,465 | 15.1 |
| `range 16-bit` | 0.10 | 0.07 | 5,217 | 5.1 |
| `table 4-entry` | 0.04 | 0.04 | 4,673 | 4.6 |
| `lookup 64-in-16` | 0.19 | 0.09 | 2,897 | 2.8 |
| `fold 4x8 fib` | 0.19 | 0.19 | 16,845 | 16.5 |
| `air fib1024` | 2.01 | 0.20 | 28,257 | 27.6 |

Lookup's extension-field proof is larger than its former base-field form:
multiplicities, quotients, and four sumcheck proofs now carry 16-byte `Fp4`
values. Tower-norm `Fp4` inversion and the streaming transcript bring
prove/verify to the values above. Proof sizes come from the real canonical
codec rather than a hand-written estimator.

## Primitives

| Row | Result |
|---|---:|
| `blake3 1MiB` | 1.17 ms (856.5 MB/s; load-dependent) |
| `gf2 F64 mul` | 272.84 ms for 1M ops (3.7 Mops/s) |
| `bb field mul` | 6.59 ms for 1M ops (151.8 Mops/s) |
| `ntt forward 2^14` | 0.32 ms |
| `merkle 64k leaves` | 3.24 ms |

## Vectorized hashing (`--features simd`, nightly)

Portable-SIMD batches Merkle leaf/node BLAKE3 eight lanes at a time with
`std::simd` (`u32x8`), byte-identical to the scalar path. The scalar path
also has specialized one-compression leaf/node digests, so the end-to-end
gain is modest. A representative run on this box (not idle), nightly:

| Row | Scalar | `--features simd` |
|---|---:|---:|
| `air prod N1048576` prove | 1,733.55 ms | **1,693.58 ms** (~2.3%) |

Absolute gains depend heavily on box load. End-to-end gains are bounded
because NTT, composition, and folding are the other large prove costs.
Builds without the feature are unaffected (scalar fallback, stable MSRV
1.74).

## Reproduce

```sh
cargo bench                          # all 24 rows
BENCH_ROW=N1048576 cargo bench       # single scaled row
BENCH_ROW="air prod" cargo bench     # all production AIR rows
python3 tools/check.py               # full gates incl. bench regression
python3 tools/check.py --update      # re-record baseline (review diffs first)
RUSTC_BOOTSTRAP=1 cargo test --features simd
RUSTC_BOOTSTRAP=1 cargo bench --features simd
```
