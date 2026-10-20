# Benchmarks — measured results

Source: `benches/speed_size.rs` (`cargo bench`), release profile, median of
N runs (plus one warmup). Every benchmark verifies its proof once outside
the timed region and asserts the byte counter equals `to_bytes().len()`,
so a passing run also gates correctness and wire stability.

- Machine: 16 cores, 31 GB RAM, `cargo`/`rustc 1.99.0`
- Measured: 2026-10-20
- Filter partial rows with `BENCH_ROW=substr`, e.g.
  `BENCH_ROW=N65536 cargo bench`
- `tools/check.py` pins all 19 rows: sizes must match byte-for-byte, times
  must stay within 3× of `tools/baseline.json`

## Production shapes (`for_security(100)` — 100-bit query/PoW; Fp4 FRI/composition)

Blowup 16, rate 1/16, 40 queries, 20-bit grinding, size-optimal final
layer and Merkle cap height.

| Row | Prove (ms) | Verify (ms) | Proof (B) | Proof (KiB) |
|---|---|---|---|---|
| `fri prod B16Q40G20C4F16` (poly-256) | 14.45 | 0.76 | 29,378 | 28.7 |
| `air prod B16Q40G20C4F16` (fib-64) | 17.47 | 0.82 | 35,861 | 35.0 |
| `fri prod P1024 B16Q40G20C4F16` | 62.16 | 0.93 | 43,174 | 42.2 |
| `air prod N1024 B16Q40G20C4F16` | 35.42 | 1.21 | 71,373 | 69.7 |
| `air prod N8192 B16Q40G20C4F32` | 107.07 | 1.60 | 104,033 | 101.6 |
| `air prod N65536 B16Q40G20C4F16` | 304.21 | 1.99 | 144,441 | 141.1 |
| `air prod N1048576 B16Q40G20C4F16` | 4,980.54 | 2.60 | 206,353 | 201.5 |

Marginal cost per step (1M row): `4980.54 / 1048576 ≈ 4.75 µs/step`
(≈210k steps/s). The 20-bit PoW grind is amortized over the trace at
scale; on small production rows it dominates run-to-run variance
(the N8192 row fluctuates ~75–100 ms between runs).

**Verification is size-independent.** The verifier derives each FRI domain
point on demand (`O(log)` field ops per query, `O(final_size)` for the degree
check) instead of materializing the `O(lde_len)` folded layer stack. Verify
time therefore stays in the low-millisecond range from 1,024 steps to 1M
steps; earlier revisions spent 0.29 s verifying the 1M-step proof purely
building that table.

## Bench shapes (fast, ~18 conjectured bits)

| Row | Prove (ms) | Verify (ms) | Proof (B) | Proof (KiB) |
|---|---|---|---|---|
| `fri poly256 B4 Q12` | 0.90 | 0.13 | 11,522 | 11.3 |
| `air fib64` | 0.87 | 0.17 | 16,305 | 15.9 |
| `range 16-bit` | 0.39 | 0.09 | 5,217 | 5.1 |
| `table 4-entry` | 0.32 | 0.06 | 4,673 | 4.6 |
| `lookup 64-in-16` | 0.11 | 0.10 | 688 | 0.7 |
| `fold 4x8 fib` | 0.72 | 0.22 | 16,845 | 16.5 |
| `air fib1024` | 6.46 | 0.37 | 29,097 | 28.4 |

## Primitives

| Row | Result |
|---|---|
| `blake3 1MiB` | 1.37 ms (~732 MB/s) |
| `gf2 F64 mul` | 282.91 ms for 1M ops (3.5 Mops/s) |
| `bb field mul` | 6.70 ms for 1M ops (~149 Mops/s) |
| `ntt forward 2^14` | 0.32 ms |
| `merkle 64k leaves` | 3.93 ms |

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
The proof rows above predate the v2 `Fp4` wire format and have not been
re-baselined with SIMD; rerun nightly before quoting them for v2.
End-to-end gains are bounded because NTT, composition, and the transcript
are the other large prove costs. Builds without the feature are unaffected
(scalar fallback, stable MSRV 1.74).

## Reproduce

```sh
cargo bench                          # all 19 rows
BENCH_ROW=N1048576 cargo bench       # single scaled row
BENCH_ROW="air prod" cargo bench     # all production AIR rows
python3 tools/check.py               # full gates incl. bench regression
python3 tools/check.py --update      # re-record baseline (review diffs first)
cargo +nightly test --features simd  # SIMD/scalar byte-equivalence
cargo +nightly bench --features simd # SIMD rows (nightly toolchain)
```
