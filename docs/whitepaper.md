# z0p — White Paper

*Transparent, post-quantum-oriented zero-knowledge proofs from first
principles: a zero-dependency STARK stack in safe Rust.*

Version 1.0 — 2026-09-26. Companion to the [Yellow Paper](yellowpaper.md)
(formal specification), [Benchmarks](benchmarks.md), [Security
tests](security-tests.md), and [Red-team results](red-team.md).

---

## 1. The problem

Zero-knowledge infrastructure today asks its users to trust too much:
pairing-friendly curves with contested security, multi-party trusted
setup ceremonies whose toxic waste must be destroyed, cryptographic
libraries stacked dozens of dependencies deep, and provers whose
soundness arguments live in slide decks rather than in code. Each layer
is a compromise — and compromises compound.

Meanwhile the threat model is shifting. Large-scale quantum computing
would break every deployed pairing- and discrete-log-based proof
system. The systems that survive that transition will be hash-based and
transparently set up. They should also be small enough to audit, fast
enough to use, and tested hard enough to believe.

## 2. The answer: z0p

**z0p** is a complete zero-knowledge proving stack built from zero —
literally. Binary fields, a prime field, a hash function, Merkle trees,
an NTT, a polynomial commitment, four STARK systems, and a minimal
program-execution AIR are all implemented in one crate, in safe Rust, with
no dependencies beyond the compiler and the operating system. There is no
trusted setup because there is nothing to set up: security reduces to a
hash function and Reed–Solomon proximity testing.

### What it proves

- **Computation integrity (Fibonacci AIR).** An $N$-step execution trace
  with transition and boundary constraints — the template for arbitrary
  program execution proofs.
- **Range membership.** A committed value fits in $n$ bits ($n \le 24$),
  via bit-decomposition constraints.
- **Table membership.** A committed value belongs to a public table, via
  a vanishing-product constraint.
- **Chained computation (IVC).** Multi-segment traces folded into a
  single proof: prove a long computation piece by piece, verify once.
- **Program execution (`vm`).** A public two-register straight-line
  program runs from a private initial state to a public output. This is
  an execution prototype; control flow, memory, and instruction privacy
  are not yet supported.
- **Set membership at scale (LogUp lookups).** Witness values belong to
  a table, argued through quotient sums and sumcheck.
- **Zero knowledge throughout.** Masked proving modes (`prove_zk`) make
  query responses uniform and independent of the witness; verification
  is unchanged.

## 3. Design principles

1. **Trust minimization.** The trusted base is one 256-bit hash
   (BLAKE3), one prime field, and the Rust compiler. No curves, no
   ceremonies, no third-party crates.
2. **Transparency.** Public-coin protocols compiled with Fiat–Shamir.
   Every challenge is a transcript squeeze; the full domain-separation
   schedule is documented and audited in code.
3. **Memory safety by construction.** `#![forbid(unsafe_code)]`.
   Untrusted input — proofs, commitments, byte strings — is decoded
   through a fail-closed reader (canonical encodings, capped counts,
   no `with_capacity` from attacker-controlled lengths) and can never
   panic the verifier.
4. **Conjectured, quantified query soundness.** Query/PoW bit-levels are
   stated explicitly (rate + queries + grinding) rather than implied.
   Bench shapes are fast and labeled weak (~18 query bits); production
   shapes target a ~100-bit query/PoW schedule via
   `Params::for_security(…, 100)`. FRI folds, STARK compositions,
   `upcs`/Gemini points and betas, `sumcheck`, and `lookup` use quartic
   extension-field (`Fp4`) challenges, raising per-challenge algebraic
   bounds to ~124 bits. This is still a conjectured query/PoW schedule,
   not an end-to-end soundness proof.
5. **Evidence over claims.** 261 unit tests, three adversarial suites
   (~800 hostile attempts per run, zero acceptances), and benchmarks
   that assert wire-exact proof sizes on every run. Findings are
   documented, including one real malleability hole the fuzzers caught
   and the transcript binding that closed it.

## 4. Architecture

```text
witness / trace
    │  interpolate + coset LDE (parallel NTT, BabyBear)
    ▼
composition polynomial  ←  AIR constraints ÷ vanishing polynomials,
    │                      randomized by Fiat–Shamir alphas
    │  FRI commit (arity-4 folds, Merkle caps, PoW grinding)
    ▼
proof  =  caps + final polynomial + query openings + trace openings
    │  verify: replay transcript, check folds/paths/degree/identities
    ▼
accept / reject
```

- **Field layer.** Program words live in binary fields
  ($GF(2^8)$, $GF(2^{64})$, $GF(2^{128})$); polynomial domains live in
  BabyBear ($p = 2^{31} - 2^{27} + 1$, two-adicity $2^{27}$), chosen for
  fast NTTs and 4-byte elements.
- **Hash layer.** BLAKE3-256 from the specification, KAT-validated
  against reference vectors including chunk boundaries. Domain-separated
  Merkle trees (leaf `0x00`, node `0x01`), capped commitments that trade
  a few cap digests for much shorter query paths.
- **Commitment layer.** FRI with arity-4 degree-quartering folds, batch
  inversion, parallel folding, Merkle caps, and proof-of-work grinding
  that converts prover effort directly into soundness bits.
- **Application layer.** AIR, range, table, and folding protocols share
  one pattern: constrain, compose, commit the composition with FRI, open
  at the FRI query positions, re-check the identity.
- **Privacy layer.** Vanishing-multiple masking blinds traces before
  commitment; a ChaCha20 stream (RFC 8439, OS-seeded, zeroized on drop)
  supplies the randomness.

## 5. Performance

Measured, release profile, median of runs (full table:
[Benchmarks](benchmarks.md)):

| Workload (production query/PoW schedule) | Prove | Verify | Size |
|---|---|---|---|
| 1,024-step computation | 39 ms | 1.2 ms | 70 KiB |
| 65,536-step computation | 332 ms | 2.1 ms | 141 KiB |
| **1,048,576-step computation** | **5.19 s** | **2.3 ms** | **202 KiB** |

Marginal cost is ~4.95 µs per step (~202k steps/s): proving scales
linearly, verification stays in the low milliseconds *independent of
computation size* (FRI domain points are derived on demand rather than
materialized), and proof size grows logarithmically. No GPU, no assembly, no dependencies — this is
portable scalar-safe-Rust throughput with parallelism over
`std::thread` only.

## 6. Security posture

- **Assumptions.** Collision/preimage resistance of BLAKE3-256;
  Johnson-radius FRI soundness heuristic in the (quantum) random-oracle
  model for Fiat–Shamir; standard Reed–Solomon list-decoding bounds.
  No number-theoretic assumptions: nothing here breaks to Shor's
  algorithm.
- **Adversarial validation.** Beyond unit tests, two suites attack the
  system continuously: direct tampering (every query, fold, value,
  path, digest), 300 single-bit-flip fuzz trials over proof and
  commitment bytes, cross-proof transplants, false statements (which
  must *never* verify), IVC surgery, codec-limit abuse, transcript
  abuse, and a 500-input garbage storm that must fail closed without
  panicking. Current standing: zero acceptances, zero panics.
- **Known limits (stated, not hidden).** Bench defaults are fast but
  weak — production callers must use `for_security`. The `table.rs`
  AIR remains small-table by design. A first Gemini-style multilinear PCS
  (`gemini.rs`) and a compact BaseFold-style prototype (`basefold.rs`)
  exist; the latter is ~11× smaller and ~60× faster to verify with cap
  height 4 at 1,024 coefficients, but it is not wired into the AIR stack
  and is unaudited. A committed LogUp prototype (`lookup_pcs.rs`) now
  commits the witness, table, multiplicities, and quotients and verifies
  with eight BaseFold openings: 1,024-in-1,024 takes ~367 ms prove,
  ~21 ms verify, and 642,443 B with cap height 4. It hides columns from
  the wire but is not zero-knowledge, does not enforce base-field column
  values, and still pays for eight separate openings. Production
  large-table openings need batched openings, a hiding PCS, and an audit.
  A first program-execution prototype (`vm.rs`) proves a public
  two-register straight-line program from a private initial state to a
  public output; a 64-step proof takes ~1.5 ms prove, ~0.24 ms verify,
  and 14,933 B. It is not a zkVM: programs are public, there is no
  control flow or memory, the initial state is the witness, and proving
  is not hiding. The system has not yet had an external audit; the test
  suites, gates, versioned wire format, and pinned baselines are the
  pre-audit package.

## 7. Roadmap

1. **Vectorized hashing — done.** Portable-SIMD Merkle levels behind the
   nightly `simd` feature, byte-identical to the scalar path.
2. **Recursion — fragment done.** `recursion.rs` re-checks one FRI query's
   fold chain in a STARK (committed quads, shifted-index transitions,
   FRI over the composition). Self-proving needs BLAKE3 path checks,
   the final-degree check, and transcript derivation inside the AIR.
3. **Point-evaluation commitments — done.** `upcs.rs` opens a committed
   univariate polynomial at an arbitrary field point: quotient commitment,
   two FRI low-degree checks, and Merkle-checked identity at the quotient's
   query points. `open_multi` batches up to 16 distinct points behind one
   quotient and one FRI pair. Transparent, non-hiding, cap height `0`; the
   opening primitive for a multilinear PCS.
4. **Multilinear PCS — Gemini done, BaseFold prototype done.**
   `gemini.rs` commits the monomial-coefficient encoding and proves
   `f(r) = y` with Gemini-style fold-chain checks and `upcs` point
   openings; `commit_evals` applies the Möbius transform. Each layer is
   opened once with a multi-point proof, so the proof carries `n` openings
   (not `3n - 2`) and remains `O(n)`. `basefold.rs` adds the compact
   recipe: one root, sumcheck reduces `f(r)` to `c(rho)`, and Möbius FRI
   folds reuse the sumcheck challenges. At 1,024 coefficients it is
   ~127.7 KB / ~44 ms / ~1.1 ms, or ~80.0 KB / ~45 ms / ~0.9 ms with cap
   height 4, versus Gemini's ~888.7 KB / ~693 ms / ~54 ms. Optional Merkle
   caps and decoder fuzzing are in place; AIR/STARK wiring and an audit
   remain before production use, and WHIR-style batching is the next PCS
   step.
5. **Programs / zkVM — lookup and register-machine prototypes done.**
   `lookup_pcs` commits the witness, table, multiplicities, and both
   quotient columns, binds sumcheck final values with eight BaseFold
   openings, and hides the input columns from the wire. `vm` adds a
   public-program, private-input two-register execution AIR with opcode
   selectors, immediate polynomials, and a 64-step proof at ~1.5 ms
   prove / ~0.24 ms verify / 14,933 B. Next: batched openings, hiding PCS
   and sumcheck for private tables, then control flow, memory, and a
   general zkVM.
6. **External audit** — procurement item; the evidence package is ready.

## 8. License

GPLv3 only — see [LICENSE](../LICENSE). Free software in the fullest
sense: use it, study it, change it, share it, under the same terms.
