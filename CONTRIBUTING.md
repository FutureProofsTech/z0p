# Contributing to z0p

Thanks for helping. `z0p` is a from-zero, zero-dependency ZK stack; the rules
below keep it auditable.

## Ground rules

- **No dependencies.** `cargo tree` must stay a single node. Standard library
  and the compiler only.
- **No `unsafe`.** `#![forbid(unsafe_code)]` is load-bearing.
- **From-zero.** Fields, hash, Merkle, NTT, FRI, and the proof systems are
  implemented in-crate, not wrapped.
- **Fallible public APIs.** Return `Result`; never `unwrap`/`expect`/`panic!`
  on a public code path. Hostile input fails closed.
- **Documented.** Public items carry docs; new invariants belong in the docs
  and in a test.

## Before you open a PR

Run the full gate and make sure it is green:

```sh
python3 tools/check.py          # fmt, clippy, tests, bench regression
```

or manually:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo test --release
```

The MSRV is **1.74** (the `[lints]` manifest table). CI also builds on stable.
`Cargo.lock` is not committed (library, zero dependencies), so old toolchains
are not pinned by a v4 lockfile.

## Adding a security test

Attack vectors go in `tests/security.rs` or `tests/redteam.rs`; parameter
abuse and decoder fuzzing go in `tests/hardening.rs`. Each vector should:

1. print its name, attempt count, and rejection count,
2. assert 100% rejection (a single acceptance fails the suite),
3. fail closed with `Err`, never panic.

## Changing the wire format

Bump `codec::VERSION`, keep decoders fail-closed with hard caps, and update the
byte-exact size assertions in `benches/speed_size.rs` and
`tools/baseline.json`.

## Commit / PR style

- Keep commits focused; describe the *why*.
- Reference the security doc you updated when behavior changes.
- Never commit secrets or generated artifacts (`Cargo.lock`, `target/`).
