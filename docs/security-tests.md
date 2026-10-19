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

## Finding closed by internal adversarial review: unbound next-row columns

An adversarial probe against the AIR prover (constructing proofs with
`compose` directly, bypassing the honest trace path) showed that
`a_next`/`b_next` were committed but never bound to the shift of the
committed `A`/`B` columns. A malicious prover could set them to satisfy
the transition relation on their own — free at the last row — and the
verifier accepted a proof of a **false** output claim (composition degree
and FRI replay were all consistent). `fold` used the same pattern and was
affected identically.

Fix: next-row values are the *same* committed columns opened at the
omega-shifted LDE index `(index + lde_len / n_steps) mod lde_len`; the
verifier recomputes that index, authenticates a second Merkle path
against the one trace cap, and rejects commitments where the shift is
undefined (`lde_len % n_steps != 0`, non-power-of-two `lde_len`). Trace
rows shrank to 8-byte `A || B` leaves (proofs carry one extra path per
opening; sizes re-recorded). Regression tests:
`air::tests::false_claim_with_forged_trace_rejected`,
`air::tests::shifted_opening_tamper_fails`,
`fold::tests::shifted_opening_tamper_fails`.

## Finding closed by internal audit: constructor overflow

`air`, `range`, `fold`, and `table` constructors checked that each size was
a power of two, then multiplied before checking the two-adicity ceiling. A
hand-built pair of huge power-of-two sizes (for example `1 << 40` and
`1 << 30`) overflowed in debug builds and panicked instead of returning
`Err`. All four now use `checked_mul`; the `rejects_bad_params` tests include
overflowing pairs. `table::prove` also validates parameters before computing
its membership bound, so an invalid `n_rows = 1` fails closed rather than
underflowing.

## Finding closed by internal audit: unbound lookup multiplicities

`lookup` sends multiplicities as proof data and only checked that they sum
to the padded witness length. Field-valued multiplicities need not be
integer counts: a non-member could solve the two rational-sum constraints
with fractional values, derive consistent quotient columns, and pass all
four sumchecks. An adversarial regression constructed exactly this proof
for witness `[99]` and table `[1,2,3,4]`; it verified before the fix.

Fix: `lookup::verify` has the witness and table in clear, so it recomputes
the canonical first-index counts and requires exact equality with
`proof.multiplicities`. The fractional construction now fails closed.
Regression: `lookup::tests::forged_multiplicities_rejected`. This does not
make the API zero-knowledge; multiplicities and quotient columns remain
public.

## Findings closed by internal audit: parameter binding and panic surfaces

- **FRI commitment parameter binding.** AIR, range, table, fold, and
  recursion verifiers trusted `proof.fri_commitment.lde_len` and
  `degree_bound`. A valid plain proof could be re-proved with an inflated
  composition bound, weakening the effective FRI rate or making the final
  degree check vacuous. Plain proofs now pin the exact domain
  (`n * blowup`), exact honest bound, and `poly_len == lde_len`; masked
  proofs are capped at the largest honest bound for their padded length.
  Regressions: `air`, `range`, and `table`
  `downgraded_composition_bound_rejected`.
- **Merkle shift overflow.** Attacker-controlled path lengths of
  `>= usize::BITS` panicked in debug and wrapped the index check in
  release. `verify`, `verify_digest`, and `verify_capped` now fail closed;
  regression `merkle::tests::oversized_paths_fail_closed`.
- **Query-domain underflow.** `Transcript::challenge_index` debug-asserted
  a power-of-two domain but underflowed `domain_size - 1` in release.
  It now returns `None` for zero/non-power-of-two domains; regression
  `transcript::tests::index_rejects_zero_and_non_power_of_two`.
- **`check_degree` hostile inputs.** Mismatched/empty slices and a
  `usize::MAX` bound no longer rely on debug assertions or overflow.
- **Field-size ceiling documented.** The ~100-bit production figure is a
  query/PoW schedule, not total soundness; 31-bit challenges cap the
  algebraic term. See README, `fri` docs, and the ePrint.
