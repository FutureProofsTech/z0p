# Security tests — measured results

Suite: `tests/security.rs` (13 tests). Shape under test: 32-step Fibonacci
AIR, blowup 8, 8 queries, final 16, 8-bit PoW grinding, cap height 2 —
small enough for debug runs, exercising every gate for real (FRI folds,
Merkle caps, composition identities, proof-of-work).

Run with the live table:

```sh
cargo test --test security -- --nocapture
```

Measured: 2026-11-05 — **13 passed, 0 failed; 480 attempts, 479 rejected,
1 honest sanity accepted.**

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
| Merkle adversarial (wrong leaf/index/short/long path × 8 leaves) | 40 | 40 | 0 |

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

## Finding closed by internal audit: zero-grind nonce malleability

With `grinding_bits == 0`, the FRI prover wrote `pow_nonce = 0` but the
verifier ignored the field. Changing only the nonce therefore produced a
second valid encoding of the same proof. Verification now requires the
canonical zero nonce when grinding is disabled; the proof-of-work path is
unchanged. Regression: `fri::tests::grinding_roundtrip_and_tamper`.

## Finding closed by internal audit: fold A-boundary jump

Each fold segment constrained `A`/`B` at row 0 and `B` at the last row,
but not `A` at the last row. A multi-segment prover could set a segment's
`out_a` claim arbitrarily, start the next segment at that `A`, keep `B`
chained, and reach a false global `B`. A two-segment adversarial proof
(fragment of the Fibonacci chain with an arbitrary `A` jump) verified
before the fix.

Fix: the per-segment composition now includes
`(A - out_a)/(x - w_last)` with a sixth `fold/alpha` challenge, binding
the claimed output `A` to the committed column. Regression:
`fold::tests::forged_segment_a_jump_rejected`; it now fails closed.

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

## Hardening closed by internal audit: mask domains and shift portability

`blind::mask_coeffs` allocated `n + n_rand` mask coefficients and padded
the result before checking either arithmetic or the crate's `2^27` domain
ceiling; a public hostile `n_rand` could therefore panic or request an
unsupported domain. It now checks `checked_add`, `checked_next_power_of_two`,
and the ceiling before drawing randomness or allocating. The NTT
bit-reversal routine accepts a one-element slice, and FRI rejects fold
counts whose `2 * i` layer shifts would exceed `usize` on 32-bit targets.
Regression: `blind::tests::rejects_bad_shapes`.

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
  query/PoW schedule, not total soundness. FRI folds, STARK
  compositions, `upcs`/Gemini points and betas, `sumcheck`, and `lookup`
  all use `Fp4` challenges. See README, `fri` docs, and the ePrint.

## Finding closed by internal audit: Merkle paths did not bind the index

`MerkleTree::verify`/`verify_digest`/`verify_capped`/`verify_capped64`
hashed the supplied direction bits but never checked them against the
claimed leaf index. A valid opening for leaf `j` therefore verified at any
other in-range `index` with the same path length. FRI samples its query
positions from the transcript and every STARK opening is tied to those
positions, so a prover could answer a query at `i` with a row committed at
`j` (for example, hiding the one trace row that violates a constraint).
The same gap existed in the hand-rolled FRI and BaseFold path walks.

Fix: all Merkle verifiers and both hand-rolled walkers now require every
direction bit to equal the corresponding index bit; caps still select the
frontier entry from the same bound index. Regressions:
`merkle::tests::prove_verify_pow2`,
`merkle::tests::capped_roundtrip`, and the in-range wrong-index vector in
`tests/security.rs::merkle_adversarial_vectors`.

## Finding closed by internal audit: fold-free FRI was not binding

FRI accepted `final_size == lde_len`, which produces zero folds. With no
fold there are no query openings, so the verifier's final low-degree check
inspected a proof-supplied `final_poly` that was never tied to the
commitment. Bare `fri::verify` could therefore accept a commitment to one
polynomial and a low-degree polynomial from somewhere else.

Fix: `commit`/`commit_evals` reject fold-free shapes, and `verify` rejects
a commitment with fewer than two caps. Regression:
`fri::tests::fold_free_instances_rejected`. The final layer is also capped
at `MAX_FINAL_SIZE = 1024` so a hostile commitment cannot force the
quadratic final degree check; the check itself now stops at order
`bound + 1`.

## Hardening closed by internal audit: prover allocation ordering

`air::prove` allocated the trace before validating public `Params`, and
`range::prove` allocated `n_bits + 1` columns before validating them. A
hand-built `n_steps`/`n_bits` could therefore attempt an enormous
allocation instead of returning `Err`. Both now validate first; regression
`tests/hardening.rs::oversized_final_layers_and_fold_counts_fail_closed`.
`recursion::Params::n_rows` and `for_security` clamp/reject absurd fold
counts before `next_power_of_two`, `table::membership_bound` saturates,
and `Transcript::grind` fails closed above the protocol's 32-bit
difficulty cap instead of looping forever.

## Performance hardening: transcript history

`Transcript` used to re-hash its entire byte log for every challenge,
making query sampling quadratic in the number of challenges. It now keeps
a streaming BLAKE3 state and clones that state for each squeeze; the
result is byte-identical to the old concatenation (regression
`transcript::tests::streaming_history_matches_concatenation`) and
challenge cost no longer grows with history length.

## Finding closed by internal audit: ZK mask budget undercounted openings

`air::prove_zk` and `vm::prove_zk` required only `n_rand >= num_queries`,
but each AIR query reveals a full eight-row joint leaf plus its shifted
leaf (up to 16 masked values per column), and each VM query reveals both
the current and shifted rows (2 values per column). The Vandermonde
hiding argument needs one masker per revealed value, so the old budget
left linear relations between mask evaluations that could leak witness
information (VM's initial state is private). AIR now requires
`16 * num_queries`, VM requires `2 * num_queries`; one-point openings
(`range`, `table`) keep `num_queries`. Regressions:
`air::tests::zk_rejects_few_maskers`,
`vm::tests::zk_rejects_few_maskers`, and the updated ZK roundtrips in
`tests/redteam.rs`.

## Critical finding closed by internal audit: one-point FRI final layer

FRI's final degree check is vacuous when the final layer has one point:
any value interpolates a degree-0 polynomial at one point. `final_size = 1`
therefore let a prover fold a dense false composition honestly and pass,
and `table::Params::for_security(2, 2, ...)` could select exactly that
shape for tiny tables. Confirmed accepted: false AIR `b_last`, out-of-range
range claim, non-member table claim, false VM output, invalid fold chain,
and false recursion output.

Fix: every `Params` now requires `final_size >= 2`; FRI additionally
rejects a residual bound with `residual + 1 >= final_size` (so the final
check is non-vacuous), `tune_shape` no longer considers `1`, and the
table tuner floors its blowup at 4 so the smallest LDE is 8. Regression:
`tests/hardening.rs::one_point_final_layers_are_rejected`.

## High finding closed by internal audit: committed lookup read-checks

`lookup_pcs` derived `beta + witness` and `beta + table` as uncommitted
MLEs for its read-check sumchecks. A malicious prover could choose those
polynomials after the challenge and satisfy the sumcheck while only
matching the committed witness/table at the final opening point, breaking
the membership binding. Fix: the read-checks now use the committed
witness/table/multiplicity columns directly, with expanded terms
`eq*q*v + beta*eq*q - eq*target`; every final value is opened against its
commitment. Regression: the final-value tampering vectors in
`lookup_pcs::tests::tampered_sumcheck_and_opening_rejected`.

## High finding closed by internal audit: VM ZK composition degree

`vm::prove_zk` declared `n + n_rand - 1` for a composition containing a
`Mul` transition, whose quotient is quadratic in the masked columns
(degree about `2 * (n + n_rand - 1)`). Honest proofs with a sufficiently
large final layer failed, and under-declaring weakened the FRI rate.
Fix: the prover declares `2 * (n + n_rand - 1)` and the verifier accepts
up to `2 * padded - 2` for masked traces. Regression:
`vm::tests::zk_honest_final_layer_sixteen_verifies`.

## Hardening closed by internal audit: final caps, cap height, buffers

- FRI now recomputes the final layer's cap from `final_poly` and requires
  it to match `commitment.caps.last()`, removing an unconstrained
  commitment digest.
- `cap_height` is capped at 8 in every `Params`, matching the decoder's
  `MAX_CAP_DIGESTS`; previously a larger hand-built cap produced a proof
  that could not round-trip through `to_bytes`/`from_bytes`.
- Trace/composition flat buffers use `checked_mul` so 32-bit targets fail
  closed instead of overflowing `m * row_len`.
- Recursion rejects an outer `lde_len` above `2^27` during validation.
- `gf2::F128::embed_f64` was removed: it claimed a subfield embedding but
  the F64 modulus does not divide the F128 modulus, so multiplication did
  not commute with it.
