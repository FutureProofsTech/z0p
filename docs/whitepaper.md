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
an NTT, a polynomial commitment, and four STARK systems are all
implemented in one crate, in safe Rust, with no dependencies beyond the
compiler and the operating system. There is no trusted setup because
there is nothing to set up: security reduces to a hash function and
Reed–Solomon proximity testing.

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
4. **Conjectured, quantified soundness.** Bit-levels are stated
   explicitly (rate + queries + grinding) rather than implied. Bench
   shapes are fast and labeled weak (~18 bits); production shapes target
   ~100 bits via `Params::for_security(…, 100)`.
5. **Evidence over claims.** 155 unit tests, two adversarial suites
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

| Workload (production, ~100 bits) | Prove | Verify | Size |
|---|---|---|---|
| 1,024-step computation | 23 ms | 1.4 ms | 47 KiB |
| 65,536-step computation | 370 ms | 16 ms | 105 KiB |
| **1,048,576-step computation** | **6.4 s** | **0.29 s** | **157 KiB** |

Marginal cost is ~6 µs per step (~163k steps/s): proving scales
linearly, verification stays in the milliseconds, and proof size grows
logarithmically. No GPU, no assembly, no dependencies — this is
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
  weak — production callers must use `for_security`. Table lookups are
  small-table (a multilinear PCS for large tables is roadmap work).
  The system has not yet had an external audit; the test suites, gates,
  versioned wire format, and pinned baselines are the pre-audit package.

## 7. Roadmap

1. **Vectorized hashing** — portable-SIMD Merkle levels (the current
   large-prove ceiling), pending a `rust-version` policy decision.
2. **Recursion** — an arithmetized verifier fragment first, then
   self-proving: the path to constant-size proofs.
3. **Programs / zkVM** — multilinear PCS, large-table lookups, then
   general program execution proofs.
4. **External audit** — procurement item; the evidence package is ready.

## 8. License

GPLv3 only — see [LICENSE](../LICENSE). Free software in the fullest
sense: use it, study it, change it, share it, under the same terms.
