# Fuzzing

Coverage-guided decoder fuzzing for every public proof, commitment, and
opening encoding. The target rejects nothing itself: it calls `from_bytes`
on each type, and for any successful decode requires a canonical round-trip
(`to_bytes` then `from_bytes` returns the same value). A panic, allocation
blow-up, or round-trip mismatch is a release blocker.

This is a separate, dev-only package. `libfuzzer-sys` is never linked into
the library, and `cargo tree` in the repository root remains a single node.

## Run

```sh
cargo install cargo-fuzz   # once
cargo +nightly fuzz run decode
cargo +nightly fuzz run decode -- -runs=100000 -max_len=8192
```

Corpus and crash artifacts are written under `fuzz/corpus/` and
`fuzz/artifacts/`; both are ignored by git. Reproduce a crash with:

```sh
cargo +nightly fuzz run decode fuzz/artifacts/decode/<artifact>
```

## Scope

The target covers the untrusted parser surface only. It does not exercise
verification, because valid parameters and statements are not derivable from
raw bytes alone. Verification hostile-input paths are covered by
`tests/hardening.rs`, `tests/security.rs`, and `tests/redteam.rs`.
