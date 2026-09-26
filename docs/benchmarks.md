# Benchmarks — measured results

Source: `benches/speed_size.rs` (`cargo bench`), release profile, median of
N runs (plus one warmup). Every benchmark verifies its proof once outside
the timed region and asserts the byte counter equals `to_bytes().len()`,
so a passing run also gates correctness and wire stability.

- Machine: 16 cores, 31 GB RAM, `cargo`/`rustc 1.97.1`
- Measured: 2026-09-26
- Filter partial rows with `BENCH_ROW=substr`, e.g.
  `BENCH_ROW=N65536 cargo bench`
- `tools/check.py` pins all 19 rows: sizes must match byte-for-byte, times
  must stay within 3× of `tools/baseline.json`

## Production shapes (`for_security(100)` — ~100 conjectured bits)

Blowup 16, rate 1/16, 40 queries, 20-bit grinding, size-optimal final
layer and Merkle cap height.

| Row | Prove (ms) | Verify (ms) | Proof (B) | Proof (KiB) |
|---|---|---|---|---|
| `fri prod B16Q40G20C4F16` (poly-256) | 55.38 | 0.78 | 21,506 | 21.0 |
| `air prod B16Q40G20C4F16` (fib-64) | 45.23 | 0.63 | 21,829 | 21.3 |
| `fri prod P1024 B16Q40G20C4F16` | 37.43 | 0.97 | 33,382 | 32.6 |
| `air prod N1024 B16Q40G20C4F16` | 23.45 | 1.38 | 48,221 | 47.1 |
| `air prod N8192 B16Q40G20C4F32` | 74.90 | 2.83 | 74,809 | 73.1 |
| `air prod N65536 B16Q40G20C4F16` | 369.59 | 15.62 | 107,609 | 105.1 |
| `air prod N1048576 B16Q40G20C4F16` | 6,419.70 | 288.60 | 160,401 | 156.6 |

Marginal cost per step (1M row): `6419.70 / 1048576 ≈ 6.1 µs/step`
(≈163k steps/s). The 20-bit PoW grind is amortized over the trace at
scale; on small production rows it dominates run-to-run variance
(the N8192 row fluctuates ~75–100 ms between runs).

## Bench shapes (fast, ~18 conjectured bits)

| Row | Prove (ms) | Verify (ms) | Proof (B) | Proof (KiB) |
|---|---|---|---|---|
| `fri poly256 B4 Q12` | 0.88 | 0.13 | 9,170 | 9.0 |
| `air fib64` | 0.92 | 0.15 | 10,869 | 10.6 |
| `range 16-bit` | 0.38 | 0.09 | 4,401 | 4.3 |
| `table 4-entry` | 0.31 | 0.05 | 3,857 | 3.8 |
| `lookup 64-in-16` | 0.11 | 0.10 | 688 | 0.7 |
| `fold 4x8 fib` | 0.75 | 0.16 | 9,565 | 9.3 |
| `air fib1024` | 8.12 | 0.36 | 20,925 | 20.4 |

## Primitives

| Row | Result |
|---|---|
| `blake3 1MiB` | 1.51 ms (660.6 MB/s) |
| `gf2 F64 mul` | 298.98 ms for 1M ops (3.3 Mops/s) |
| `bb field mul` | 7.43 ms for 1M ops (134.6 Mops/s) |
| `ntt forward 2^14` | 0.36 ms |
| `merkle 64k leaves` | 3.88 ms |

## Reproduce

```sh
cargo bench                          # all 19 rows
BENCH_ROW=N1048576 cargo bench       # single scaled row
BENCH_ROW="air prod" cargo bench     # all production AIR rows
python3 tools/check.py               # full gates incl. bench regression
python3 tools/check.py --update      # re-record baseline (review diffs first)
```
