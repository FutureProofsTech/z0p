# Security tests — measured results

Suite: `tests/security.rs` (13 tests). Shape under test: 32-step Fibonacci
AIR, blowup 8, 8 queries, final 16, 8-bit PoW grinding, cap height 2 —
small enough for debug runs, exercising every gate for real (FRI folds,
Merkle caps, composition identities, proof-of-work).

Run with the live table:

```sh
cargo test --test security -- --nocapture
```

Measured: 2026-09-26 — **13 passed, 0 failed; 477 hostile attempts,
477 rejected, 0 accepted.**

## Results

| Vector | Attempts | Rejected | Accepted |
|---|---|---|---|
| Honest proof accepts (sanity) | 1 | 0 | 1 |
| FRI value tampering (every query × fold × value) | 64 | 64 | 0 |
| Final-polynomial tampering (every element) | 16 | 16 | 0 |
| Trace value tampering (every opening × 4 columns) | 32 | 32 | 0 |
| Merkle path tampering (truncate / digest flip / direction swap) | 5 | 5 | 0 |
| Commitment tampering (FRI cap + column cap digests) | 2 | 2 | 0 |
| Wrong transcript domain / cross-statement replay | 2 | 2 | 0 |
| Forged PoW nonces (+ absurd difficulty deterministically fails) | 5 | 5 | 0 |
| Rate-gate forgeries (raised bound / lowered bound) | 2 | 2 | 0 |
| Proof byte-fuzz (single-bit flips) | 200 | 200 | 0 |
| Commitment byte-fuzz (single-bit flips) | 100 | 100 | 0 |
| Truncated / empty / over-long inputs | 11 | 11 | 0 |
| Merkle adversarial (wrong leaf/index/short/long path × 8 leaves) | 32 | 32 | 0 |

## Finding closed by this suite

Bit-flip fuzzing initially accepted 1/200 proof bytes and 5/100
commitment bytes. The accepted positions mapped to prover-echoed
dimensions (`poly_len`, low bits of `degree_bound`) that never entered
the transcript — proof malleability without statement forgery, but below
the bar. Fix: prover and verifier now absorb
`(lde_len, poly_len, degree_bound)` under a `fri-dims` label before any
challenge (`src/fri.rs`, protocol docs updated). Since the fix, fuzzing
is at 200/200 and 100/100 with proof sizes byte-identical.
