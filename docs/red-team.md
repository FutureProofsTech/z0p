# Red-team tests — measured results

Suite: `tests/redteam.rs` (10 tests). Second-round adversarial coverage:
cross-proof transplants, false statements, IVC surgery, codec limits,
transcript abuse, exact rate boundaries, masked (ZK) soundness, and a
500-input hostile-garbage storm (fail-closed with `Err`, never panic).

```sh
cargo test --test redteam -- --nocapture
```

Measured: 2026-09-26 — **10 passed, 0 failed; 41 targeted attempts plus
500 garbage trials, 0 acceptances, 0 panics, 0 unexpected decodes.**

## Results

| Vector | Attempts | Rejected | Accepted |
|---|---|---|---|
| False statements (range-300-in-8-bits, table non-member, lookup out-of-table fails at prove) | 3 | 3 | 0 |
| Transplant attacks (opening / foreign-trace cap / whole FRI proof / whole commitment) | 4 | 4 | 0 |
| FRI surgery (cross-commitment verify, final-swap, query amputate/duplicate) | 4 | 4 | 0 |
| IVC fold tampering (claim / column / cap / step amputation) | 4 | 4 | 0 |
| Leaf/node domain confusion (second-preimage craft) | 5 | 5 | 0 |
| Hostile garbage (500 random inputs × 6 proof types) | 500 | 500 | 0 panics, 0 decodes |
| Count limits (oversized counts, bad version) | 4 | 4 | 0 |
| Transcript abuse (order swap, replay, index range, PoW downgrade) | 4 | 4 | 0 |
| Rate boundary exact (bound 31 verifies; 32 fails at prove; raised fails at verify) | 3 | 3 | 0 |
| ZK roundtrips + tamper (air/range/table blinded verify; masked false statements still fail) | 6 | 6 | 0 |

## Triage notes

- The identical-trace cap "transplant" is a pinned no-op, not an attack:
  two proofs over the same trace share byte-identical column caps. The
  suite asserts this explicitly and transplants a foreign-trace cap
  instead, which fails as required.
- Masking hides nothing from soundness: blinded out-of-range and
  non-member proofs fail verification exactly like plain ones.
- The PoW-downgrade vector (8-bit-ground proof verified under 0-bit
  params) fails deterministically through transcript divergence — params
  must match on both sides.
