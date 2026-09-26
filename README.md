# z0p

A from-scratch, zero-dependency zero-knowledge proving stack in safe Rust:
binary fields, an NTT-friendly prime field, BLAKE3, Merkle trees, FRI
polynomial commitments, and STARKs (Fibonacci AIR, range checks, table
lookups, hash-folded IVC) — plus zero-knowledge masking throughout.

No elliptic curves. No trusted setup. No `unsafe`. No dependencies.
Hash-based and transparent, in the plausibly post-quantum STARK family.

## Highlights

- **Truly from zero** — every layer (fields, hash, Merkle, NTT, FRI,
  sumcheck, AIR) is implemented in this crate. `cargo tree` is one node.
- **Platinum Rust** — `#![forbid(unsafe_code)]`, `cargo fmt --check` clean,
  `cargo clippy --all-targets -- -D warnings` clean (pedantic), fallible
  public APIs (`Result`, never `unwrap` on public paths), documented items.
- **Transparent setup, PQ-oriented** — BLAKE3-256 digests, FRI Reed–Solomon
  commitments over BabyBear; nothing to ceremony, nothing pairing-based.
- **Production soundness on demand** — `Params::for_security(steps, …, 100)`
  sizes blowup 16, queries, grinding, final size, and cap height for
  ~100 conjectured bits (see [Soundness](#soundness)).
- **Fast at scale** — 1,048,576-step production proof in ~6.4 s
  (~6.1 µs/step, ~163k steps/s), verified in ~0.29 s, 160,401 bytes.
- **Adversarially tested** — 155 unit tests plus two attack suites
  ([security](docs/security-tests.md), [red-team](docs/red-team.md)):
  ~800 hostile attempts per run, zero acceptances, zero panics.

## Quick start

```sh
cargo build --release
cargo test                 # debug: lib + security + red-team suites
cargo test --release       # same, optimized
cargo bench                # speed/size report (release, median of runs)
python3 tools/check.py     # platinum gates: fmt, clippy, tests, bench regression
```

`BENCH_ROW=substr` runs only matching benchmark rows, e.g.
`BENCH_ROW=N65536 cargo bench`.

## Usage

```rust
use z0p::{air, babybear::Field, transcript::Transcript};

let steps = 64;
let (_, trace_b) = air::build_trace(Field::ONE, Field::ONE, steps);
let params = air::Params::new(
    steps, 8, 12, 8,
    Field::ONE, Field::ONE, trace_b[steps - 1],
).expect("params");

let mut prover = Transcript::new(b"my-app/fib");
let proof = air::prove(params, &mut prover).expect("prove");

let mut verifier = Transcript::new(b"my-app/fib");
air::verify(params, &proof, &mut verifier).expect("verify");
```

Production soundness (~100 conjectured bits) in one call:

```rust
let params = air::Params::for_security(steps, Field::ONE, Field::ONE, b_last, 100)
    .expect("params");
```

Zero-knowledge variants (`air::prove_zk`, `range::prove_zk`,
`table::prove_zk`) mask the trace so query openings reveal nothing;
verification is unchanged.

## Performance

Release profile, median of runs, 16-core / 31 GB machine, `rustc 1.97.1`.
Full table with methodology: [docs/benchmarks.md](docs/benchmarks.md).

| Proof (production shape, ~100 bits) | Prove | Verify | Size |
|---|---|---|---|
| AIR Fibonacci, 1,024 steps | 23 ms | 1.4 ms | 48,221 B |
| AIR Fibonacci, 8,192 steps | 75 ms | 2.8 ms | 74,809 B |
| AIR Fibonacci, 65,536 steps | 370 ms | 15.6 ms | 107,609 B |
| AIR Fibonacci, **1,048,576 steps** | **6.42 s** | **0.29 s** | **160,401 B** |
| FRI poly-1024 | 37 ms | 1.0 ms | 33,382 B |

| Primitive | Result |
|---|---|
| BLAKE3 1 MiB | 1.51 ms (661 MB/s) |
| BabyBear mul | 134.6 Mops/s |
| NTT forward 2¹⁴ | 0.36 ms |
| Merkle 65,536 leaves | 3.88 ms |

Proof sizes are deterministic and asserted byte-for-byte against the wire
format on every benchmark run.

## Soundness

Conjectured bit-levels (Fiat–Shamir + FRI in the QROM, Johnson-radius
heuristic) — see the `fri` module docs for the full sizing table:

| Shape | Rate | Queries | Grinding | Total |
|---|---|---|---|---|
| Bench (fast, weak) | 1/8 | 12 | 0-bit | ~18 bits |
| Production | 1/16 | 40 | 20-bit | ~100 bits |

Grinding bits add one-to-one: a `d`-bit nonce costs the prover `2^d`
hashes and denies a forger a `2^-d` shortcut. Size the queries from the
rate first, then top up with grinding — `for_security` does exactly this,
plus the size-optimal final layer and Merkle cap height.

## Security testing

| Suite | What | Result |
|---|---|---|
| Unit (`cargo test --lib`) | 155 tests across 18 modules | [docs/unit-tests.md](docs/unit-tests.md) |
| `tests/security.rs` | 13 attack vectors, 477 hostile attempts | [docs/security-tests.md](docs/security-tests.md) |
| `tests/redteam.rs` | 10 deeper vectors incl. 500-input garbage storm | [docs/red-team.md](docs/red-team.md) |

Every forgery attempt is rejected; hostile input fails closed with `Err`
(never panics); honest proofs always verify. Past findings and their fixes
are recorded in the security docs.

## Project structure

```text
src/
  gf2.rs        binary fields GF(2⁸)/GF(2⁶⁴)/GF(2¹²⁸)
  babybear.rs   NTT-friendly prime field (Barrett mul, batch inversion)
  hash.rs       BLAKE3-256 from spec (KAT-validated)
  transcript.rs Fiat–Shamir transcript + proof-of-work grinding
  merkle.rs     domain-separated trees, caps, capped openings
  ntt.rs        parallel Cooley–Tukey NTT, Reed–Solomon extension
  par.rs        thread-scope data parallelism (bit-identical)
  fri.rs        FRI polynomial commitment (commit / open / verify)
  mle.rs        multilinear polynomials
  sumcheck.rs   sumcheck over MLE products
  lookup.rs     LogUp-style table membership via sumcheck
  air.rs        Fibonacci AIR/STARK (+ ZK)
  range.rs      range-check AIR (+ ZK)
  table.rs      table-membership AIR (+ ZK)
  fold.rs       hash-folded IVC accumulation, one batched FRI
  blind.rs      vanishing-multiple ZK masking
  rng.rs        ChaCha20 CSPRNG + OS seeding
  codec.rs      versioned canonical serialization (fail-closed decoder)
tests/
  security.rs   adversarial suite (tamper, fuzz, forgery)
  redteam.rs    cross-proof, false-statement, IVC, garbage vectors
benches/
  speed_size.rs speed + wire-exact size harness
tools/
  check.py      platinum gates · baseline.json  pinned regression table
docs/
  whitepaper.md      vision, design, performance, roadmap
  yellowpaper.md     formal specification (math, protocols, encodings)
  benchmarks.md measured numbers + methodology
  security-tests.md  attack-suite results
  red-team.md        red-team results
  unit-tests.md      unit-test breakdown
papers/
  z0p-eprint.tex     ePrint submission source (nul0, Future Proofs Tech)
  z0p-eprint.pdf     compiled submission-ready PDF
```

## Roadmap

- **Tier 4 — vectorized hashing.** The current ceiling is scalar BLAKE3 in
  Merkle levels (~60% of large proves). Requires a `rust-version` policy
  decision (portable SIMD needs 1.89+); scalar-equivalence fuzz included.
- **Recursion.** Arithmetized verifier fragment (one-query check as AIR)
  first, then self-proving — the path to L1-sized proofs.
- **Programs / zkVM.** Multilinear PCS first (unlocks large-table
  lookups), then program execution.
- **External audit.** The suite, gates, versioned wire format, and pinned
  baselines are the pre-audit package.

## License

GPLv3 only — see [LICENSE](LICENSE). This is free software: you can
redistribute it and/or modify it under the terms of the GNU General
Public License version 3 as published by the Free Software Foundation.
