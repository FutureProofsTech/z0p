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
- **Extension-field challenges** — FRI folds and the AIR/range/table/fold
  composition batching use `Fp4 = Fp[v,u]/(v²-u, u²-11)` over BabyBear,
  raising the main STARK algebraic challenge entropy from ~31 bits to
  ~124 bits. Wire format v2 stores extension values canonically (16 bytes).
- **Production parameter sizing** — `Params::for_security(steps, …, 100)`
  sizes blowup 16, queries, grinding, final size, and cap height for a
  ~100-bit query/proof-of-work schedule. See [Soundness](#soundness) for
  the remaining base-field components.
- **Fast at scale** — 1,048,576-step production proof in ~4.98 s
  (~4.75 µs/step, ~210k steps/s), verified in **~2.6 ms**, 206,353 bytes.
  Verification cost is essentially independent of trace size (the verifier
  derives FRI domain points on demand, never materializing `O(lde_len)`).
- **Adversarially tested** — 223 unit tests plus three attack suites
  ([security](docs/security-tests.md), [red-team](docs/red-team.md),
  hardening): ~800 hostile attempts plus decoder fuzzing per run, zero
  acceptances, zero panics.

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

Production query/PoW schedule (~100 bits before the field-size ceiling) in
one call:

```rust
let params = air::Params::for_security(steps, Field::ONE, Field::ONE, b_last, 100)
    .expect("params");
```

Zero-knowledge variants (`air::prove_zk`, `range::prove_zk`,
`table::prove_zk`) mask the trace so query openings reveal nothing;
verification is unchanged.

## Performance

Release profile, median of runs, 16-core / 31 GB machine, `rustc 1.99.0`.
Full table with methodology: [docs/benchmarks.md](docs/benchmarks.md).

| Proof (production query/PoW schedule) | Prove | Verify | Size |
|---|---|---|---|
| AIR Fibonacci, 1,024 steps | 35 ms | 1.2 ms | 71,373 B |
| AIR Fibonacci, 8,192 steps | 107 ms | 1.6 ms | 104,033 B |
| AIR Fibonacci, 65,536 steps | 304 ms | 2.0 ms | 144,441 B |
| AIR Fibonacci, **1,048,576 steps** | **4.98 s** | **2.6 ms** | **206,353 B** |
| FRI poly-1024 | 62 ms | 0.9 ms | 43,174 B |

| Primitive | Result |
|---|---|
| BLAKE3 1 MiB | 1.37 ms (~732 MB/s) |
| BabyBear mul | ~151 Mops/s |
| NTT forward 2¹⁴ | 0.33 ms |
| Merkle 65,536 leaves | 4.0 ms |

Proof sizes are deterministic and asserted byte-for-byte against the wire
format on every benchmark run.

## Soundness

Conjectured query/PoW bit-levels (Fiat–Shamir + FRI in the QROM,
Johnson-radius heuristic) — see the `fri` module docs for the full sizing
table:

| Shape | Rate | Queries | Grinding | Query+PoW target |
|---|---|---|---|---|
| Bench (fast, weak) | 1/8 | 12 | 0-bit | ~18 bits |
| Production | 1/16 | 40 | 20-bit | ~100 bits |

Grinding bits add one-to-one: a `d`-bit nonce costs the prover `2^d`
hashes and denies a forger a `2^-d` shortcut. Size the queries from the
rate first, then top up with grinding — `for_security` does exactly this,
plus the size-optimal final layer and Merkle cap height.

**Challenge fields.** The totals above count query sampling and grinding,
not finite-field algebraic error. FRI folding and the main STARK
composition batches now draw challenges from the quartic extension
`Fp4`, so the previous ~31-bit folding ceiling is removed from the
AIR/range/table/fold path. Some components still use base-field
challenges: `upcs`/`gemini` evaluation points and fold betas, and
`sumcheck`/`lookup` rounds. Those paths retain a ~31-bit algebraic
ceiling until they migrate. Do not claim end-to-end 100-bit soundness
for them, and do not deploy any high-value system before an external
audit.

## Security testing

| Suite | What | Result |
|---|---|---|
| Unit (`cargo test --lib`) | 223 tests across 22 modules | [docs/unit-tests.md](docs/unit-tests.md) |
| `tests/security.rs` | 13 attack vectors, 477 hostile attempts | [docs/security-tests.md](docs/security-tests.md) |
| `tests/redteam.rs` | 10 deeper vectors incl. 500-input garbage storm | [docs/red-team.md](docs/red-team.md) |
| `tests/hardening.rs` | 8 vectors: hostile `Params`, decoder bit-flip fuzz, RNG uniformity | this README |

Every forgery attempt is rejected; hostile input fails closed with `Err`
(never panics); honest proofs always verify. Past findings and their fixes
are recorded in the security docs.

The project is **unaudited** — engineering for audit is complete (transparent
setup, versioned wire format, pinned baselines, adversarial suites), but do not
deploy for high-value statements before an external audit. See
[SECURITY.md](SECURITY.md) for the threat model and reporting policy.

## Project structure

```text
src/
  gf2.rs        binary fields GF(2⁸)/GF(2⁶⁴)/GF(2¹²⁸)
  babybear.rs   NTT-friendly prime field (Barrett mul, batch inversion)
  ext4.rs       quartic extension field Fp4 over BabyBear
  hash.rs       BLAKE3-256 from spec (KAT-validated)
  transcript.rs Fiat–Shamir transcript + proof-of-work grinding
  merkle.rs     domain-separated trees, caps, capped openings
  ntt.rs        parallel Cooley–Tukey NTT, Reed–Solomon extension
  par.rs        thread-scope data parallelism (bit-identical)
  fri.rs        FRI polynomial commitment (commit / open / verify)
  mle.rs        multilinear polynomials
  sumcheck.rs   sumcheck over MLE products
  upcs.rs       FRI-backed univariate commitments + point openings
  gemini.rs     multilinear commitments (Gemini fold chains)
  lookup.rs     LogUp-style table membership via sumcheck
  air.rs        Fibonacci AIR/STARK (+ ZK)
  range.rs      range-check AIR (+ ZK)
  recursion.rs  one-query FRI fold-chain AIR (recursion fragment)
  table.rs      table-membership AIR (+ ZK)
  fold.rs       hash-folded IVC accumulation, one batched FRI
  blind.rs      vanishing-multiple ZK masking
  rng.rs        ChaCha20 CSPRNG + OS seeding
  codec.rs      versioned canonical serialization (fail-closed decoder)
tests/
  security.rs   adversarial suite (tamper, fuzz, forgery)
  redteam.rs    cross-proof, false-statement, IVC, garbage vectors
  hardening.rs  hostile Params, decoder fuzz, invariant + RNG checks
benches/
  speed_size.rs speed + wire-exact size harness
tools/
  check.py      platinum gates · baseline.json  pinned regression table
.github/
  workflows/ci.yml  fmt, clippy, test, MSRV 1.74, rustdoc gates
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
SECURITY.md      threat model + vulnerability reporting
CONTRIBUTING.md  ground rules, gates, wire-format policy
CHANGELOG.md     release history (Keep a Changelog)
```

## Roadmap

- **Tier 4 — vectorized hashing (done).** `--features simd` (nightly)
  runs 8-lane portable-SIMD BLAKE3 over Merkle leaf/node batches,
  byte-identical to the scalar path (pinned by
  `batch_digests_match_reference`), up to ~2.6× on the Merkle primitive
  and ~11% end-to-end at 1M steps. The default build stays scalar, stable,
  and MSRV 1.74; the feature is additive with a scalar fallback.
- **Extension-field FRI — done for the main path.** FRI folds and
  AIR/range/table/fold composition use `Fp4` challenges; the wire format is
  v2. Remaining extension work: PCS evaluation points, Gemini fold betas,
  and sumcheck/lookup challenges.
- **Recursion — fragment done.** `recursion.rs` proves one FRI query's
  fold chain as a STARK: public `(lde_len, leaf, challenges, initial quad,
  output)`, committed quads, shifted-index transition openings, FRI over
  the composition at degree bound `4n - 5`; honest chains verify and
  tampered chains/outputs/openings fail. Remaining for self-proving:
  Merkle/BLAKE3 path checks, final-degree check, and transcript
  derivation inside the AIR — the path to L1-sized proofs.
- **Point-evaluation commitments — done.** `upcs.rs` opens a committed
  univariate polynomial at an arbitrary field point: quotient commitment
  `(g - y)/(X - beta)`, two FRI low-degree proofs, and Merkle-checked
  identity at the quotient's query points. `open_multi` batches up to 16
  distinct points behind one quotient (`(g - I)/Z`) and one FRI pair.
  Transparent, non-hiding (`v1`); cap height must be `0`. This is the
  opening primitive for a multilinear PCS.
- **Multilinear commitments — first version done.** `gemini.rs` commits
  the monomial-coefficient encoding and proves `f(r) = y` with Gemini-style
  fold-chain checks; `commit_evals` applies the Möbius transform. Each
  layer is opened once with a multi-point `upcs` proof, so the `v1` proof
  carries `n` openings rather than `3n - 2`; it remains `O(n)`, so compact
  multilinear FRI (BaseFold/WHIR) is the next step.
- **Programs / zkVM.** Compact multilinear PCS (unlocks large-table
  lookups), then program execution.
- **External audit.** The suite, gates, versioned wire format, and pinned
  baselines are the pre-audit package.

## License

GPLv3 only — see [LICENSE](LICENSE). This is free software: you can
redistribute it and/or modify it under the terms of the GNU General
Public License version 3 as published by the Free Software Foundation.
