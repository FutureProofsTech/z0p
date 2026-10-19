# Changelog

All notable changes to `z0p` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- **FRI commitment parameter binding (air, range, table, fold, recursion).**
  Verifiers previously took `proof.fri_commitment.lde_len` and
  `degree_bound` from the proof without pinning them to protocol parameters.
  A valid plain proof could be re-proved with a larger FRI domain and a
  looser composition bound, weakening the effective FRI rate or making the
  final degree check vacuous. Verifiers now require the plain domain
  `n * blowup`, the exact honest plain degree bound, and `poly_len ==
  lde_len`; masked proofs are restricted to the largest bound any honest
  mask of that padded length can produce. Fold and recursion pin their
  single exact domain/bound. Regressions:
  `air::tests::downgraded_composition_bound_rejected`,
  `range::tests::downgraded_composition_bound_rejected`,
  `table::tests::downgraded_composition_bound_rejected`.
- **Merkle path shift overflow closed.** `MerkleTree::verify` /
  `verify_digest` shifted by an attacker-controlled path length: debug
  panicked, release masked the shift and could pass the index check.
  Paths at or above `usize::BITS` now fail closed; `verify_capped` also
  rejects out-of-range total depths. Regression:
  `merkle::tests::oversized_paths_fail_closed`.
- **`fri::check_degree` hardened.** Mismatched/empty points and values now
  return `false` instead of relying on `debug_assert_eq!`, and the
  vacuous-bound test uses `bound >= n.saturating_sub(1)` so a hostile
  `usize::MAX` bound cannot overflow.
- **`Transcript::challenge_index` fails closed.** It now returns
  `Option<usize>` and rejects zero/non-power-of-two domains, closing a
  release-mode underflow in `domain_size - 1` and biased sampling.
  Regression: `transcript::tests::index_rejects_zero_and_non_power_of_two`.
- **Soundness claims corrected for the 31-bit field.** Docs, README, and
  the ePrint now state that the ~100-bit production figure is a
  query/proof-of-work schedule, not total soundness: finite-field
  challenge collisions cap effective conjectured security well below it
  (about 31 bits at best, lower for wide instances). Extension-field
  challenges or repeated independent checks are required before restoring
  a 100-bit claim.

- **Unbound next-row trace columns fixed (air, fold).** `a_next`/`b_next`
  were committed as separate trace columns, but the verifier never tied
  them to the trace: a malicious prover could choose them to satisfy the
  transition relation on its own, decoupled from `A`/`B`, and prove a false
  output claim (reproduced by an adversarial probe test before the fix;
  composition degree and FRI replay accepted it). Next-row values are now
  the same committed `A`/`B` columns opened at the omega-shifted LDE index
  `(index + lde_len / n_steps) mod lde_len`; the verifier recomputes that
  index and authenticates both Merkle paths against the one trace cap. No
  separate, unauthenticated next-row witness exists. Regression tests:
  `air::tests::false_claim_with_forged_trace_rejected`,
  `air::tests::shifted_opening_tamper_fails`,
  `fold::tests::shifted_opening_tamper_fails`.
- **FRI verifier allocation DoS fixed.** `verify` no longer materializes an
  `O(lde_len)` table of folded domain points (up to ~715 MB from a ~6.6 KB
  forged commitment). Points are derived on demand in `O(log)` field ops. The
  on-demand formula is cross-checked against the previous full layer stack in
  `fri::tests::on_demand_point_at_matches_materialized_layers`.
- **Performance side effect of the same fix:** verifying the 1,048,576-step
  production proof drops from ~0.29 s to ~2.3 ms (verify is now essentially
  independent of trace size). Bench baseline re-recorded.

### Changed
- **Field invariant hardened.** `babybear::Field`'s inner value is now private;
  the only public constructors reduce, so safe code cannot create an
  out-of-range element. A read accessor `as_u32` was added. `new_unchecked` is
  crate-internal.
- **Constant-time `Field::inv`.** Removed the zero branch; the fixed-exponent
  Fermat inverse runs identically for zero and nonzero inputs.
- **Entry-point validation.** `air`, `range`, `table`, `fold`, and `fri`
  re-validate all `Params` (public fields) at every prove/verify/commit entry,
  so a hand-built invalid struct is rejected instead of failing downstream.
- **Uniform field sampling.** `rng::ChaCha20::next_field` rejects the biased
  top interval (rejection sampling) instead of `u64 mod p`, giving exactly
  uniform masking randomness.
- **`air::build_trace` no longer panics** for `n_steps == 0` (returns empty).
- **`range::build_columns` guards the shift** for `n_bits > 32`.
- **Trace wire format (air, fold).** Trace rows are now 8-byte `A || B`
  leaves (previously 16-byte `A || B || A_next || B_next`) and each opening
  carries a second Merkle path for the shifted row. Proving is faster (the
  trace LDE halves and no next-column NTT runs); proofs are slightly larger
  (one extra ~33-byte path step per query). Bench baseline re-recorded;
  1M-step AIR proof 160,401 → 186,961 B, prove 6.35 → 4.65 s.

### Added
- **Multilinear PCS (`gemini`).** Gemini-style commitment to the
  monomial-coefficient encoding of an `n`-variable multilinear polynomial:
  `commit_evals` applies the Möbius transform, `open` folds one variable
  at a time, commits the folded layers, and opens each layer **once** with
  a multi-point `upcs` proof at the points of its fold checks:
  `g_0` at `beta_1, -beta_1`, interior `g_i` at
  `beta_i^2, beta_{i+1}, -beta_{i+1}`, and `g_{n-1}` at
  `beta_{n-1}^2, r_0`. The fold identity
  `g_i(beta^2) = (g_{i-1}(beta) + g_{i-1}(-beta))/2 +
  r_i (g_{i-1}(beta) - g_{i-1}(-beta))/(2 beta)` and the public final-point
  check `g_{n-1}(r_0) = y` are then checked from those openings. 16 tests:
  honest `n = 0..5`, Möbius vs `Mle`, zero coordinates, wrong
  value/point, tampered layers/values/openings, batched layer shapes,
  dimension/codec/transcript gates. Transparent, non-hiding v1; proof size
  is `n` `upcs` openings (down from `3n - 2`), and the 31-bit field bounds
  the fold-check error (`n 2^n / p`), so wide instances await
  extension-field challenges or compact multilinear FRI.
- **Point-evaluation commitments (`upcs`).** FRI-backed univariate PCS:
  commit to coefficients over the bit-reversed LDE, open `g(beta) = y` by
  committing the quotient `(g - y)/(X - beta)`, FRI low-degree-testing both
  `g` and the quotient, and checking the quotient identity at the
  quotient's random query points (Merkle-opening `g` there). `open_multi`
  opens up to 16 distinct points with one interpolation polynomial `I`,
  vanishing polynomial `Z`, quotient `(g - I)/Z`, and FRI pair; when the
  point count equals `n`, `I` fixes `g` and the quotient is zero. 25 tests:
  honest single- and multi-point openings (multi-point `k = 1..n`, up to
  16), duplicate/oversized sets, wrong value/point/quotient/commitment,
  tampered leaves/paths/FRI values/commitments, cap-height and dimension
  gates, canonical encodings, transcript binding. Transparent, non-hiding
  v1; cap height must be `0`.
- **Recursion fragment (`recursion`).** A STARK re-checking one FRI query's
  fold chain. Public statement `(lde_len, leaf, fold challenges, initial
  quad, output)`; witness quads are committed and transitions read next-row
  values from the same columns at the omega-shifted LDE index (authenticated
  second path, the same scheme as the soundness fix). Constraints: fold
  identity (`out_d = fold_values(q_d, 1/x_d, c_d)`), chain
  (`q_{d+1}[j_d] = out_d`), row-0 initial-quad boundary, and the one-hot
  last-real-row output boundary; composition degree bound `4n - 5`, committed
  with FRI. 12 tests: honest 2/3-fold chains (incl. padding), wrong output,
  broken chain, tampered base/shifted openings and paths, caps, encoding,
  statement mismatch, and degree-bound tightness. Module docs state the
  remaining self-proving scope (BLAKE3 path checks, final-degree check,
  transcript derivation in-AIR).
- **`simd` feature (Tier 4).** 8-lane portable-SIMD BLAKE3 for Merkle
  leaf/node batches (`src/hash.rs` `simd` module), byte-identical to the
  scalar path (pinned by `merkle::tests::batch_digests_match_reference`).
  Nightly-only (`std::simd` is unstable on Rust 1.99); default builds stay
  scalar and MSRV 1.74. Up to ~2.6× on the Merkle primitive (box-load
  dependent); end-to-end AIR 1M-step prove ~11% faster.
- `tests/hardening.rs`: 8 tests for hostile `Params` structs, decoder
  single-bit-flip fuzzing across every proof type, the field invariant, and
  RNG uniformity.
- `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, and a CI workflow.
- `Field::as_u32`.

### Fixed
- Metadata: repository/homepage URLs, `readme`, keywords, categories, and
  `rust-version = 1.74` (the `[lints]` table). `Cargo.lock` is no longer
  committed (library, no dependencies).
- Documentation: BLAKE3 (not SHA3) throughout; rustdoc link/`squeeze` warnings;
  `bench_sha3` renamed to `bench_blake3`.
- Clippy clean on Rust 1.99: `div_ceil` in `fri`/`hash`/`ntt`/`par`, and
  pedantic fixes in the new hardening suite.

## [0.1.0] - 2026-10-19

### Added
- Initial release: binary fields (`gf2`), BabyBear (`babybear`), BLAKE3-256
  (`hash`), Fiat–Shamir transcript with grinding (`transcript`), Merkle trees
  with caps (`merkle`), parallel NTT (`ntt`, `par`), FRI (`fri`), MLE
  (`mle`), sumcheck (`sumcheck`), LogUp lookups (`lookup`), Fibonacci
  AIR/STARK (`air`), range checks (`range`), table membership (`table`),
  hash-folded IVC (`fold`), ZK masking (`blind`), ChaCha20 CSPRNG (`rng`), and
  versioned canonical serialization (`codec`).
- Zero-knowledge variants: `air::prove_zk`, `range::prove_zk`,
  `table::prove_zk`.
- Production soundness sizing: `Params::for_security`.
- Adversarial suites `tests/security.rs` and `tests/redteam.rs`.
- White paper and yellow paper, ePrint submission source/PDF, and benchmark
  and security documentation.
- Platinum gates: `tools/check.py` with a pinned `tools/baseline.json`.

[Unreleased]: https://github.com/FutureProofsTech/z0p/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/FutureProofsTech/z0p/releases/tag/v0.1.0
