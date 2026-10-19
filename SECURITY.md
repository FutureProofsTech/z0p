# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately to **futureproofs@proton.me**.
Do not open a public issue for anything that could affect soundness, zero
knowledge, or memory safety. Include:

- a description of the issue and its impact,
- the affected module and version/commit,
- a minimal reproduction (proof bytes, parameters, or a test) if possible.

You will get an acknowledgement within 72 hours and a status update within 7
days. Coordinated disclosure is preferred; credit is given in `CHANGELOG.md`
and the relevant docs unless you ask to stay anonymous.

## Threat model

`z0p` proves and verifies computational statements about public claims
(Fibonacci steps, range membership, table membership, folded IVC chains). The
verifier is the adversary-facing surface:

- **Untrusted inputs** are proof bytes, commitments, public `Params`, and the
  public table/claims. Every decoder is fail-closed with hard size caps, and
  every `Params`-consuming entry point re-validates its fields (the structs
  have public fields and cannot be trusted from the constructor alone).
- **Hostile inputs must fail closed**: `Err`, never a panic, and never
  unbounded allocation or work. The verifier computes FRI domain points on
  demand (`O(final_size)`), so a tiny forged commitment cannot force an
  `O(lde_len)` allocation.
- **Not hidden by current ZK paths**: `lookup` and `sumcheck` expose full
  tables (see `blind.rs` scope). Proof-of-work grinding requires a hash gap,
  which this scalar codebase provides only on the prover side.
- **Out of scope**: side channels in the host OS, compiler, or CPU
  (this crate uses no `unsafe` and no secrets beyond optional witness
  randomness); denial of service by the *prover* against itself; physical
  attacks.

## Cryptographic status

The stack is **unaudited**. It is engineered for audit: transparent setup, no
elliptic curves, hash-based commitments, versioned canonical wire format with
byte-exact regression tests, a from-zero implementation with no dependencies,
and adversarial test suites (`tests/security.rs`, `tests/redteam.rs`,
`tests/hardening.rs`). Soundness numbers in the README and `docs/` are
*conjectured* (Fiat–Shamir + FRI in the QROM, Johnson-radius heuristic). Do
not deploy in production for high-value statements before an external audit.

Internal adversarial review has already closed two findings with fixes and
regression tests: the FRI verifier allocation DoS (an `O(lde_len)` table
built from a tiny forged commitment) and unbound next-row trace columns in
`air`/`fold` (a malicious prover could decouple the transition relation
from the committed trace and prove a false output claim). Both are recorded
in `CHANGELOG.md` and `docs/security-tests.md`, including reproducer
descriptions; neither affected the honest path silently — old-format
proofs are rejected by the new verifier.

## Supported versions

The project is pre-1.0: only the latest `main` (or latest tagged release) is
supported with security fixes.

## Safe harbor

We will not pursue legal action against researchers who act in good faith,
avoid privacy violations and service disruption, and give us reasonable time
to fix the issue before disclosure.
