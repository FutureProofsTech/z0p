# Changelog

All notable changes to `z0p` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
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

### Added
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
