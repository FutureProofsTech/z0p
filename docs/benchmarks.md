# Benchmarks — measured results

Source: `benches/speed_size.rs` (`cargo bench`), release profile, median of
N runs (plus one warmup). Every benchmark verifies its proof once outside
the timed region and asserts the byte counter equals `to_bytes().len()`,
so a passing run also gates correctness and wire stability.

- Machine: 16 cores, 31 GB RAM, `cargo`/`rustc 1.99.0`
- Measured: 2026-10-19
- Filter partial rows with `BENCH_ROW=substr`, e.g.
  `BENCH_ROW=N65536 cargo bench`
- `tools/check.py` pins all 19 rows: sizes must match byte-for-byte, times
  must stay within 3× of `tools/baseline.json`

## Production shapes (`for_security(100)` — ~100 conjectured bits)

Blowup 16, rate 1/16, 40 queries, 20-bit grinding, size-optimal final
layer and Merkle cap height.

| Row | Prove (ms) | Verify (ms) | Proof (B) | Proof (KiB) |
|---|---|---|---|---|
| `fri prod B16Q40G20C4F16` (poly-256) | 48.72 | 0.68 | 21,506 | 21.0 |
| `air prod B16Q40G20C4F16` (fib-64) | 34.57 | 0.67 | 21,829 | 21.3 |
| `fri prod P1024 B16Q40G20C4F16` | 38.09 | 0.90 | 33,382 | 32.6 |
| `air prod N1024 B16Q40G20C4F16` | 37.51 | 1.04 | 48,221 | 47.1 |
| `air prod N8192 B16Q40G20C4F32` | 81.22 | 1.55 | 74,809 | 73.1 |
| `air prod N65536 B16Q40G20C4F16` | 368.10 | 1.81 | 107,609 | 105.1 |
| `air prod N1048576 B16Q40G20C4F16` | 6,348.85 | 2.27 | 160,401 | 156.6 |

Marginal cost per step (1M row): `6348.85 / 1048576 ≈ 6.1 µs/step`
(≈165k steps/s). The 20-bit PoW grind is amortized over the trace at
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
| `fri poly256 B4 Q12` | 0.89 | 0.13 | 9,170 | 9.0 |
| `air fib64` | 0.92 | 0.15 | 10,869 | 10.6 |
| `range 16-bit` | 0.43 | 0.09 | 4,401 | 4.3 |
| `table 4-entry` | 0.35 | 0.06 | 3,857 | 3.8 |
| `lookup 64-in-16` | 0.12 | 0.11 | 688 | 0.7 |
| `fold 4x8 fib` | 0.79 | 0.18 | 9,565 | 9.3 |
| `air fib1024` | 6.48 | 0.25 | 20,925 | 20.4 |

## Primitives

| Row | Result |
|---|---|
| `blake3 1MiB` | 1.57 ms (~668 MB/s) |
| `gf2 F64 mul` | 300.85 ms for 1M ops (3.3 Mops/s) |
| `bb field mul` | 7.39 ms for 1M ops (~135 Mops/s) |
| `ntt forward 2^14` | 0.37 ms |
| `merkle 64k leaves` | 3.47 ms |

## Reproduce

```sh
cargo bench                          # all 19 rows
BENCH_ROW=N1048576 cargo bench       # single scaled row
BENCH_ROW="air prod" cargo bench     # all production AIR rows
python3 tools/check.py               # full gates incl. bench regression
python3 tools/check.py --update      # re-record baseline (review diffs first)
```
