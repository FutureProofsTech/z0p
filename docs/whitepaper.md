# z0p — White Paper

*Transparent, post-quantum-oriented zero-knowledge proofs from first
principles: a zero-dependency STARK stack in safe Rust.*

**Version 1.2 — 2026-11-06.** Companion documents:
[Yellow Paper](yellowpaper.md) (formal specification),
[Benchmarks](benchmarks.md) (measured results and methodology),
[Security tests](security-tests.md), [Red-team results](red-team.md), and
the [white-paper PDF](../papers/z0p-whitepaper.pdf) and the
[combined technical report PDF](../papers/z0p-eprint.pdf).

> **Status.** v0.3.0, unaudited research software. The ~100-bit figure is a
> conjectured query/proof-of-work schedule, not an end-to-end soundness
> theorem. See [SECURITY.md](../SECURITY.md) and [AUDIT.md](../AUDIT.md).

---

## Abstract

We present **z0p**, a complete zero-knowledge proving stack implemented from
first principles in safe Rust with no dependencies beyond the compiler and
the operating system. Binary fields, the BabyBear prime field, a quartic
extension field, BLAKE3-256, Merkle trees, a parallel NTT, FRI, sumcheck,
univariate and multilinear polynomial commitments, LogUp lookups, four
STARK-style AIR systems, hash-folded IVC, a minimal register-machine AIR, and
zero-knowledge masking are owned by one crate under
`#![forbid(unsafe_code)]`.

The construction is transparent: there is no trusted setup, no elliptic
curve, and no pairing. Security reduces to BLAKE3-256, Reed–Solomon proximity
testing, and Fiat–Shamir. Production parameters target a **conjectured
100-bit query/proof-of-work schedule** — rate `1/16`, 40 queries, and 20-bit
grinding — while algebraic challenges are drawn from
`Fp4 = Fp2[v]/(v^2-u)`, `Fp2 = Fp[u]/(u^2-11)`, giving roughly 124 bits of
per-challenge algebraic entropy.

On the 16-core reference machine, release profile, `rustc 1.99.0`, a
1,048,576-step Fibonacci AIR proves in **1.73355 s** (**1.653 µs/step**,
~604,872 steps/s), verifies in **1.13 ms**, and produces a **203,553-byte**
(198.8 KiB) proof. Verification is essentially independent of trace size:
the verifier derives FRI domain points on demand rather than materializing
the `O(lde_len)` layer stack. The same tree passes 277 library tests, 13
security tests (479 hostile attempts), 10 red-team tests (37 targeted attacks
plus a 500-input garbage storm), 11 hardening tests (including exhaustive
per-bit AIR decoder fuzzing and 14,000 random mutations across seven
encodings), and 5 doc tests. Every measured forgery is rejected; hostile
input fails closed with `Err`, never a panic.

The system is deliberately **unaudited**. The contribution is an auditable
engineering artifact and an explicit, reproducible evidence package — not a
claim of production-grade end-to-end soundness.

---

## 1. Motivation

Practical zero-knowledge infrastructure asks its users to trust a large
surface:

- pairing-friendly curves whose security assumptions are contested and whose
  implementations are complex;
- multi-party trusted-setup ceremonies whose toxic waste must be destroyed;
- cryptographic libraries stacked dozens of dependencies deep, each with its
  own build system, feature flags, and supply-chain risk;
- protocol behavior described in papers and slide decks but not reproducible
  from the code that actually runs.

At the same time, large-scale quantum computing threatens every deployed
pairing- and discrete-log-based proof system. The systems that survive that
transition will be hash-based, transparently set up, small enough to audit,
and tested hard enough to believe. z0p is an experiment in how small that
trusted base can be made while retaining a useful proof toolkit.

### 1.1 Design goals

1. **From zero.** Every cryptographic layer is implemented in this crate:
   fields, hash, Merkle trees, NTT, FRI, sumcheck, AIRs, lookups, masking,
   and the wire format. `cargo tree` is one node.
2. **Transparent and plausibly post-quantum.** BLAKE3-256 and Reed–Solomon
   proximity testing; no curves, pairings, or setup ceremonies.
3. **Safe by construction.** `#![forbid(unsafe_code)]`; fallible public APIs;
   canonical fail-closed decoding; hostile parameters re-validated at every
   entry point.
4. **Quantified security.** Query and proof-of-work budgets are stated
   explicitly and tied to parameter constructors. Bench shapes are labeled
   weak; production shapes are labeled conjectured.
5. **Evidence over claims.** Adversarial suites, byte-exact proof-size
   assertions, a pinned benchmark regression table, and a single gate
   command (`python3 tools/check.py`).
6. **Auditability.** One crate, one wire format, one formal specification,
   one long-form paper, and a documented threat model.

### 1.2 Non-goals

z0p is not an audited production system, a general circuit compiler, a zkVM,
a private-table lookup protocol, or a side-channel-hardened hardware token.
The `lookup` and `sumcheck` APIs expose tables in clear; `lookup_pcs` hides
columns from the wire but is not zero-knowledge; `basefold`, `gemini`,
`lookup_pcs`, `vm`, and `recursion` are prototypes. The ~100-bit figure is a
query/PoW sizing, not a theorem.

---

## 2. Threat model and trust base

### 2.1 Adversary-facing surface

The verifier is the adversary-facing surface. Untrusted inputs are:

- proof and commitment bytes;
- public parameters, including hand-built `Params` structs whose fields are
  public;
- public statements: Fibonacci claims, range values, table contents, VM
  programs and outputs, lookup witnesses/tables in the clear where the API
  takes them.

The verifier must fail closed with `Err`, never panic, and never perform
unbounded allocation or work. It must derive all challenge-dependent data
from the transcript and bind every public input before sampling challenges.

### 2.2 Trust base

The trusted base is:

1. the Rust compiler and standard library;
2. BLAKE3-256 as a collision-resistant hash;
3. the Reed–Solomon/FRI proximity heuristic and Fiat–Shamir in the
   (quantum) random-oracle model;
4. the correctness of the field and NTT implementations, which are
   cross-tested against independent Horner/`%` references.

No trusted setup, elliptic-curve group, pairing, or discrete-log assumption
is used. Shor's algorithm does not apply to the cryptographic core.

### 2.3 Out of scope

Host OS, compiler, CPU microarchitecture, power/EM side channels, physical
attacks, denial of service by a prover against itself, and high-value
production deployment before an external audit. See
[SECURITY.md](../SECURITY.md#threat-model).

---

## 3. System architecture

```text
witness / trace
    │  interpolate + coset LDE (parallel NTT, BabyBear)
    ▼
composition polynomial  ←  AIR constraints ÷ vanishing polynomials,
    │                      randomized by Fiat–Shamir alphas
    │  FRI commit (arity-4 folds, Merkle caps, PoW grinding)
    ▼
proof = caps + final polynomial + query openings + trace openings
    │  verify: replay transcript, check paths, folds, degree, identities
    ▼
accept / reject
```

### 3.1 Layers

| Layer | Modules | Responsibility |
|---|---|---|
| Algebra | `gf2`, `babybear`, `ext4` | Word fields, NTT-friendly prime field, quartic challenge field |
| Hashing | `hash`, `merkle` | BLAKE3-256, domain separation, caps, index-bound paths |
| Fiat–Shamir | `transcript`, `rng` | Streaming transcript, challenges, grinding, ChaCha20 CSPRNG |
| Polynomial core | `ntt`, `mle`, `sumcheck`, `fri` | Coset NTT, multilinear tables, sumcheck, FRI |
| Commitments | `upcs`, `gemini`, `basefold` | Univariate and multilinear opening prototypes |
| Lookups | `lookup`, `lookup_pcs` | LogUp in clear and committed-input LogUp |
| Statements | `air`, `range`, `table`, `fold`, `vm`, `recursion` | STARKs, IVC, execution, recursion fragment |
| Privacy | `blind` | Vanishing-multiple masking |
| Wire format | `codec` | Canonical versioned encoding, fail-closed decoding |
| Parallelism | `par` | Deterministic `std::thread` data parallelism |

### 3.2 Invariants

The implementation enforces the following invariants at every entry point:

- **Rate gate.** `degree_bound + 1 <= lde_len / 2` at prove and verify.
- **Transcript binding.** Dimensions, commitments, public inputs, and PoW
  nonces are absorbed before the challenges that depend on them.
- **Authenticated next rows.** AIR and IVC next-row values are the same
  committed columns opened at the `omega`-shifted LDE index, not an
  independent witness.
- **Committed leaves.** FRI quads and AIR trace leaves are hashed from the
  exact revealed bytes; Merkle direction bits are bound to the claimed
  index.
- **Fail-closed decoding.** Canonical fields, bounded counts, no trailing
  bytes, and no allocation before limits are checked.
- **Final-degree soundness.** FRI requires at least one fold and at least two
  final points, caps the final layer at 1024, and rejects a residual bound
  for which the final check would be vacuous.
- **No `unsafe`, no dependencies.** Enforced by the manifest, crate
  attribute, CI, and `cargo tree`.

---

## 4. Cryptographic foundations

### 4.1 Fields

Program words use binary fields `GF(2^8)`, `GF(2^64)`, and `GF(2^128)`.
Polynomial domains use BabyBear:

```text
p = 2^31 - 2^27 + 1 = 2013265921
p - 1 = 2^27 * 15
generator = 31
```

Multiplicative subgroups of order `2^k` exist for `k <= 27`, which is
exactly what the NTT needs. Elements serialize as four canonical
little-endian bytes; the decoder rejects values `>= p`. Multiplication uses
Barrett reduction with `mu = floor(2^64 / p)`. Inversion is Fermat
(`a^(p-2)`, mapping zero to zero). Batch inversion uses Montgomery's trick.

All algebraic challenges use the quartic tower

```text
Fp2 = Fp[u] / (u^2 - 11)
Fp4 = Fp2[v] / (v^2 - u)
```

represented as `a + b u + c v + d u v` with four canonical coordinates.
`11` is a quadratic non-residue in `Fp`, and `u` is a non-square in `Fp2`.
Inversion uses the tower norm: for `x = c + d v`,
`x^-1 = (c - d v) / (c^2 - u d^2)`, so one `Fp2` inversion suffices.
Multiplication is the tower formula with Karatsuba for the cross term.

### 4.2 Domains and NTT

The base trace domain is

```text
H = {1, omega, ..., omega^(N-1)}
```

with `N` a power of two. The evaluation domain is a coset

```text
D = gamma * <Omega>,  |D| = M = N * beta
```

where `beta` is the blowup, `Omega` is a primitive `M`-th root, and
`gamma = 31` (`LDE_SHIFT`). Every entry point enforces `M <= 2^27`.
The vanishing polynomial of `H` is `Z_H(x) = x^N - 1`.

The NTT is a Cooley–Tukey transform with bit-reversal permutation,
table-driven twiddles, and deterministic parallel stages over
`std::thread`. Large transforms gather through owned buffers; small
transforms permute in place. The inverse transform folds the `1/N` scaling
into its last stage. Reed–Solomon extension is interpolation followed by
coset evaluation.

### 4.3 BLAKE3 and Merkle trees

BLAKE3-256 is implemented from the specification: 7-round ARX compression,
the standard message permutation, flags `CHUNK_START`, `CHUNK_END`,
`PARENT`, and `ROOT`, 1024-byte chunks, and Bao-style merge-while-even
stacking. It is validated against reference vectors for the empty input,
`abc`, and multi-chunk inputs crossing chunk boundaries.

Column trees domain-separate leaves and internal nodes:

```text
leaf(d)    = H(0x00 || d)
node(l, r) = H(0x01 || l || r)
```

FRI layers commit one 64-byte leaf per quad (four canonical 16-byte `Fp4`
values); AIR trace layers commit one 64-byte leaf per eight joint rows.
Both use standard BLAKE3 for the 64-byte leaf digest and the same `0x01`
internal-node hash.

**Caps.** A capped commitment exposes an upper tree layer of `2^h` digests.
Openings carry only the middle path segment, and the verifier hashes the
frontier back to the layer root. Caps are size-only: they do not change the
committed function or the query count. Cap height is capped at 8 in every
`Params` so encoded proofs remain decodable (`MAX_CAP_DIGESTS = 256`).

**Index binding.** Every Merkle verifier checks that each path direction bit
matches the corresponding bit of the claimed leaf index. Without this check,
a valid opening for leaf `j` would verify at any other in-range index with
the same path length, allowing a prover to substitute rows at
transcript-sampled positions.

### 4.4 Fiat–Shamir transcript

The transcript is append-only and length-prefix-framed. Each absorb writes
`(label_len, label, data_len, data)` into a streaming BLAKE3 state. A
challenge clones that state, appends `(label_len, label, counter)`, finalizes,
and feeds the output back into the history. This is byte-identical to the
historical `H(full_log || label || counter)` construction, but squeeze cost
is independent of the number of prior challenges.

Challenge mapping:

- `Fp` challenges reduce a 64-bit word modulo `p` (bias below `2^-31`);
- query indices mask low bits for power-of-two domains (unbiased);
- `Fp4` challenges reduce each of four 16-byte coordinates.

**Proof of work.** `grind(label, d)` returns the smallest nonce with at least
`d` leading zero bits under the history commitment, using a banded parallel
search that is bit-identical to a sequential scan. Protocol parameters cap
grinding at 32 bits; `grind` fails closed above that. `verify_grind` checks
the nonce and absorbs it only on success.

**Domain separation.** Every protocol uses unique labels: FRI dimensions and
layer roots, AIR/range/table parameters and alphas, fold step/trace/alphas
and gammas, lookup context and challenges, VM parameters/trace/alphas,
sumcheck claim/round/challenge. The full schedule is normative in the
[Yellow Paper](yellowpaper.md#5-fiat-shamir-transcript-and-proof-of-work).

---

## 5. FRI polynomial commitment

### 5.1 Commitment

`commit` maps `n` coefficients to `M = n beta` coset evaluations with a
shifted NTT. `commit_evals` accepts caller-supplied LDE values with a
declared degree bound `< M`. Both paths:

- reject empty or non-power-of-two lengths;
- enforce `M <= 2^27`;
- require a final layer of at least two points and at most 1024;
- require at least one fold (`final_size < M`);
- enforce the rate gate `degree_bound + 1 <= M/2`;
- bind `(lde_len, poly_len, degree_bound)` into the transcript before any
  challenge.

### 5.2 Arity-4 folding

Layers are bit-reversed. Each adjacent quad sits at
`(x, -x, j0 x, -j0 x)` for the fixed fourth root `j0`, sharing `x^4`.
Writing `P(X) = A + B X + C X^2 + D X^3` in `Y = X^4`, the fold is

```text
fold(e0, e1, e2, e3) = A + r0 B + r1 C + r2 D
```

with `(r0, r1, r2)` drawn from `Fp4`. The even/odd decomposition gives

```text
A = (e0 + e1 + e2 + e3) / 4
B = ((e0 - e1) - j0 (e2 - e3)) / (4 x)
C = ((e0 + e1) - (e2 + e3)) / (4 x^2)
D = ((e0 - e1) + j0 (e2 - e3)) / (4 x^3)
```

Point inverses are base-field values and are batch-inverted once per layer.
Each fold quarters the degree.

### 5.3 Proof and verification

A FRI proof carries the final polynomial in the clear, one opening per query
(four `Fp4` values per folded quad plus the middle Merkle path segment), and
a PoW nonce. The verifier:

1. validates dimensions, cap shapes, fold count, and the rate gate;
2. absorbs dimensions, cap digests, and the final polynomial;
3. checks the PoW nonce against the replayed history;
4. verifies the final layer by divided differences against the residual
   bound `degree_bound >> 2f` at the true folded domain points;
5. recomputes the final layer cap from `final_poly` and compares it to the
   commitment;
6. samples query indices after grinding and checks every Merkle path and fold
   relation, chaining intermediate parents forward and the last parent into
   `final_poly`.

The final degree check is **non-vacuous**: a one-point final layer would let
any value interpolate a degree-0 polynomial, so `final_size >= 2` is
mandatory and `residual + 1 < final_size` is enforced.

### 5.4 Conjectured soundness

Under the Johnson-radius heuristic, a word `delta`-far from the code survives
one query with probability at most `1 - delta`, where
`delta ~= 1 - sqrt(rate)`. The production schedule uses rate `1/16`, 40
queries, and 20-bit grinding:

```text
delta ~= 0.75
~2 bits per query
80 query bits + 20 PoW bits = 100-bit query/PoW schedule
```

The fast bench shape uses rate `1/8`, 12 queries, and no grinding: about
18 bits. These counts exclude the finite-field algebraic term. FRI folds,
STARK composition batches, UPCs/Gemini points and betas, sumcheck rounds,
and lookup identities use `Fp4`, so a degree-`d` algebraic identity collides
with probability about `d/p^4` per challenge (~124 bits). This removes the
former ~31-bit algebraic ceiling but remains a query/PoW formula, not an
end-to-end theorem.

---

## 6. Sumcheck and multilinear commitments

### 6.1 MLE and sumcheck

A multilinear polynomial is stored by its evaluations over `{0,1}^n` in
MSB-first order. `Mle::evaluate` folds the least-significant variable first.
The equality polynomial is

```text
eq(r, x) = product_i (r_i x_i + (1 - r_i)(1 - x_i))
```

Sumcheck proves `sum_x f(x) = S` for a summand expressed as a sum of terms
`c_k * product_j mle[k_j]`. Round `i` sends the univariate restriction at
`0..=degree`; the verifier checks `g_i(0) + g_i(1) = g_{i-1}(r_{i-1})`,
samples `r_i`, and finally checks the oracle value. Challenges are `Fp4`.

### 6.2 UPCs

`upcs` commits a univariate polynomial as a Merkle-committed Reed–Solomon
LDE. To prove `g(beta) = y`, the prover commits the quotient
`q = (g - y)/(X - beta)` and proves both `g` and `q` low-degree with FRI.
The verifier checks `(X - beta) q = g - y` at the quotient's FRI query
points. Multi-point openings use `I` interpolating the claims and
`Z = product_j (X - p_j)`, with `q = (g - I)/Z` and the identity
`g = I + Z q`.

When the number of points equals the polynomial length, the quotient is
identically zero; the verifier checks `g` against the interpolant directly
rather than allowing a nonzero constant quotient to absorb the difference
at random points. Optional Merkle caps shorten paths and are authenticated
against the commitment root.

### 6.3 Gemini

`gemini` commits the monomial-coefficient encoding

```text
g_0(X) = sum_b c_b X^index(b)
```

and proves `f(r) = y` by folding one variable at a time:

```text
g_{i-1}(X) = A_i(X^2) + X B_i(X^2)
g_i(Y) = A_i(Y) + r_i B_i(Y)
```

Each committed layer is opened once with a multi-point UPCs proof at all
points its relations use. Layer commitments are absorbed before the fold
betas. Proof size is linear (`n` openings), not constant; Gemini is the
conservative v1 multilinear PCS.

### 6.4 BaseFold prototype

`basefold` commits the coefficient encoding with FRI and reduces
`f(r) = y` to a coefficient-oracle evaluation `c(rho)` with sumcheck. The
prover folds the LDE with the Möbius/eq rule

```text
(1 - rho_i) E(X) + rho_i O(X)
```

rather than the coefficient-encoding rule `E(X) + rho_i O(X)`, so the final
FRI constant is exactly `c(rho)`. The verifier recomputes

```text
w(rho) = product_i (1 - rho_i + rho_i r_i)
```

and checks `f(r) = c(rho) w(rho)`. Proofs carry one root, `n-1` layer roots,
sumcheck rounds, and one pair plus one Merkle path per layer per query.
Optional caps store a digest frontier per layer and hash it back to the
layer root. The module also provides batched multi-point openings
(`open_multi`/`verify_multi`, up to `MAX_BATCH = 1024` points) using the
multilinear basis table.

The BaseFold prototype is **not** wired into the AIR/STARK stack and has no
end-to-end soundness proof. It backs the committed lookup prototype.

---

## 7. Lookup arguments

### 7.1 LogUp in clear

For witness `w` and table `t`, padded to powers of two, the prover computes
first-index multiplicities `m`, samples `beta`, and forms

```text
q^w_i = 1 / (beta + w_i)
q^t_j = m_j / (beta + t_j)
```

The rational identity

```text
sum_i q^w_i = sum_j q^t_j
```

is checked by sumcheck, together with read-checks
`q^w_i (beta + w_i) = 1` and `q^t_j (beta + t_j) = m_j` at random equality
points. The verifier has the witness and table in clear, so it recomputes
the canonical first-index multiplicities and rejects any other vector. This
closes the fractional-multiplicity attack. The API is sound for membership
but not hiding: multiplicities and quotients travel in clear.

### 7.2 Committed LogUp (`lookup_pcs`)

The committed variant commits witness, table, multiplicities, and both
quotient columns with BaseFold. The verifier receives five commitments and
eight point-opening proofs. The read-checks use the **committed** columns
directly:

```text
eq * (q * (beta + v) - target) = 0
```

expanded as `eq*q*v + beta*eq*q - eq*target`. Every final sumcheck value is
bound to an opening. A fresh `gamma` folds the total multiplicity weight into
the sum-t claim:

```text
sum(q^t + gamma m) = sum q^w + gamma W
```

The verifier rejects `gamma = 0`. At 1,024-in-1,024 with `B16 Q40 G20 C4`,
the prototype proves in 273.01 ms, verifies in 5.77 ms, and carries
642,443 bytes. It is committed-input but **not zero-knowledge**: BaseFold has
no hiding layer, candidate inputs can be tested against the commitments, and
the columns are extension-field values. Eight separate openings are the main
size cost; batched openings are the next step.

---

## 8. AIR systems

All AIRs share one pattern: interpolate columns, extend on the LDE coset,
Merkle-commit joint rows, evaluate the composition vector (geometric
vanishing recurrence plus Montgomery-batched denominators, bit-identical to
scalar evaluation), FRI-commit it, open trace columns at FRI query
positions, and re-verify the identity per query.

### 8.1 Fibonacci AIR

Trace `A[0] = a0`, `B[0] = b0`, `A[i+1] = B[i]`,
`B[i+1] = A[i] + B[i]`, claim `B[N-1] = b_last`. With
`w_last = omega^(N-1)` and `Z_trans(x) = (x^N - 1)/(x - w_last)` (zero on
rows `0..N-2`), at point `x` with values `(a,b)` and next row `(a',b')`:

```text
C(x) = alpha0 (a' - b) / Z_trans(x)
     + alpha1 (b' - (a+b)) / Z_trans(x)
     + alpha2 (a - a0) / (x - 1)
     + alpha3 (b - b0) / (x - 1)
     + alpha4 (b - b_last) / (x - w_last)
```

Five `fib/alpha` challenges; `deg C < N` iff the trace is valid. Dividing,
not multiplying, by `Z_trans` is load-bearing. Blowup is at least 4.
Next-row values are the same committed columns at the omega-shifted LDE
index, authenticated by a second Merkle path.

### 8.2 Range checks

Value column `V` plus `n` bit columns (`1 <= n <= 24`). With challenges
`alpha_decomp`, `{alpha_j}`, `alpha_bound`:

```text
C = alpha_decomp (V - sum_j 2^j C_j) / Z_H
  + sum_j alpha_j C_j (C_j - 1) / Z_H
  + alpha_bound (V - value) / (x - 1)
```

Booleanity doubles the masked composition degree; masked callers should size
blowup/queries for a rate near `2/blowup`. The verifier caps the declared
bound at the largest honest masked degree.

### 8.3 Table membership

Constant column `v` against public table `T`:

```text
C(x) = alpha_member product_{t in T}(v - t) / Z_H(x)
     + alpha_bound (v - value) / (x - 1)
```

Small tables by design; cost scales with `|T|`. The honest composition bound
is `|T| (n + k - 1) - n` for `n` rows and `k` maskers. The tiny-table
`for_security` tuner floors blowup at 4 so FRI always has a valid final
layer.

### 8.4 Hash-folded IVC

Segments of `seg_steps` Fibonacci rows are committed independently with
explicit in/out claims. The verifier checks the chain links, then verifies
one shared FRI proof over the random combination

```text
V = sum_s gamma_s C_s
```

of per-step compositions. A far-from-code step keeps the combination far
with overwhelming probability over the gammas. The statement is existential
over the number of segments; callers requiring an exact step count must
check `proof.steps.len()`. The accumulator retains each segment's LDE,
Merkle tree, and composition until finalization, so prover memory is
`O(segments * seg_steps * blowup)`.

### 8.5 Register-machine execution (`vm`)

A public two-register straight-line program runs from a private initial
state to a public output. Each row applies `Add`, `Mul`, `Swap`, `SetA`,
`SetB`, or `Halt`; the last row is the public output and has no outgoing
transition. Public one-hot selectors and immediate polynomials drive the
composition:

```text
C(x) = alpha0 T(x)/Z_trans(x)
     + alpha1 U(x)/Z_trans(x)
     + alpha2 (A(x) - a_last)/(x - w_last)
     + alpha3 (B(x) - b_last)/(x - w_last)
```

Plain composition degree is below `2n-1`, so blowup is at least 8. A
64-step `B16 Q12 C2` proof measures 0.69 ms prove, 0.18 ms verify, and
14,933 bytes. `prove_zk` masks both columns. Each query reveals the current
and shifted rows, so the mask budget is `2 * num_queries`; the masked `Mul`
quotient is quadratic, so the prover declares `2 * (n + n_rand - 1)` and the
verifier accepts up to `2 * padded - 2`. The program and output remain
public; there is no control flow or memory.

### 8.6 Recursion fragment

`recursion` proves one FRI query's fold chain as a small STARK. Public inputs
are the outer `lde_len`, leaf, per-depth fold challenges, the layer-0 quad,
and the claimed output; the witness is the sequence of quads and folded
outputs. Constraints cover the fold identity, the selected next-layer
element, the initial quad, and the final output. The fragment re-checks the
arithmetic of one query but does not yet verify BLAKE3 paths, the final
degree check, or transcript derivation inside the AIR. It is a recursion
fragment, not a self-proving recursion system.

---

## 9. Zero knowledge

Masked proving maps a column `T` of degree `< n` to

```text
M(x) = T(x) + Z_H(x) R(x)
```

where `R` has `n_rand` uniform coefficients. `Z_H` vanishes on every base
row, so the trace values and all AIR quotient identities are preserved.
Off-domain, the mask term is nonzero. The evaluations of `R` at the revealed
points are jointly uniform when `n_rand` is at least the number of distinct
revealed values per column (Vandermonde surjectivity), giving perfect hiding
of query responses.

The budget depends on what the proof reveals:

| Protocol | Revealed values per column per query | Minimum `n_rand` |
|---|---|---:|
| `range`, `table` | one point | `num_queries` |
| `vm` | current and shifted rows | `2 * num_queries` |
| `air` | eight-row joint leaf plus shifted leaf | `16 * num_queries` |

The composition degree grows accordingly; callers must size `final_size` for
the masked LDE. Verification is unchanged, and masked false statements still
fail. This is query-response hiding, not full program privacy: the program,
public inputs, Merkle roots, and composition commitments remain visible.
`lookup`, `sumcheck`, `upcs`, `gemini`, and `basefold` are not hiding.

---

## 10. Implementation engineering

### 10.1 Safe Rust and fallible APIs

The crate uses `#![forbid(unsafe_code)]`. Public paths return `Result` and
avoid `unwrap`/`expect`/`panic!`. Untrusted proof bytes are decoded through a
cursor-checked reader with hard caps and incremental vector growth. Hostile
`Params` structs are re-validated at every entry point because their fields
are public.

### 10.2 Parallelism

`par::for_each_indexed` splits disjoint mutable chunks across
`std::thread::scope` workers. Worker count is cached from
`available_parallelism` and bounded by work size. NTT stages, Merkle levels,
FRI folding, composition, and proof-of-work search are parallelized. Every
parallel routine is deterministic and bit-identical to its sequential
reference; tests pin this.

### 10.3 Performance engineering

- Barrett multiplication avoids hardware division in the NTT hot path.
- Table-driven Cooley–Tukey stages with one twiddle multiply per butterfly.
- Batched composition uses geometric vanishing recurrences and Montgomery
  inversion per chunk.
- The verifier derives FRI domain points on demand, never materializing the
  `O(lde_len)` layer stack.
- FRI commits four `Fp4` values per 64-byte leaf; AIR commits eight joint rows
  per 64-byte leaf.
- Short Merkle leaves hash through small stack buffers rather than zeroing a
  1 KiB chunk buffer per leaf.
- The transcript keeps a streaming BLAKE3 history, so challenge cost does not
  grow with history length.

### 10.4 Wire format

All proofs use a canonical versioned encoding (`VERSION = 6`): little-endian
integers, `u32` counts, canonical base/extension fields, 32-byte digests,
`0/1` direction bytes, no trailing bytes. Decoder limits are listed in the
[README](../README.md#wire-format-and-compatibility) and the
[Yellow Paper](yellowpaper.md#14-wire-format).

---

## 11. Performance evaluation

**Method.** `benches/speed_size.rs`, release profile, median of runs after
one warm-up, 16 cores / 31 GB, `rustc 1.99.0`, measured 2026-11-05. Every
benchmark verifies its proof once outside the timed region; byte counters
assert `to_bytes().len()` exactly. Proof sizes are deterministic. The
regression gate allows 3× timing drift and requires byte-exact sizes.

### 11.1 Production AIR / FRI

| Workload | Prove | Verify | Proof |
|---|---:|---:|---:|
| FRI polynomial, 256 coefficients | 10.59 ms | 0.25 ms | 29,378 B |
| AIR Fibonacci, 64 steps | 11.99 ms | 0.27 ms | 33,061 B |
| FRI polynomial, 1,024 coefficients | 21.50 ms | 0.31 ms | 43,174 B |
| AIR Fibonacci, 1,024 steps | 37.05 ms | 0.48 ms | 68,573 B |
| AIR Fibonacci, 8,192 steps | 49.81 ms | 0.59 ms | 101,233 B |
| AIR Fibonacci, 65,536 steps | 115.49 ms | 0.90 ms | 141,641 B |
| **AIR Fibonacci, 1,048,576 steps** | **1,733.55 ms** | **1.13 ms** | **203,553 B** |

The 1M-step row is **1.653 µs/step** and **604,872 steps/s**. Proof size
grows logarithmically; verification stays in the low-millisecond range from
1,024 to 1,048,576 steps. On the optional nightly SIMD hash path, a
representative run measured **1,693.58 ms** for the same row (~2.3% faster);
the default scalar path remains the supported stable build.

### 11.2 Multilinear PCS and lookup

| Construction | Prove | Verify | Size |
|---|---:|---:|---:|
| BaseFold-style, 1,024 coefficients | 22.65 ms | 0.88 ms | 127,658 B |
| BaseFold-style, cap height 4 | 22.91 ms | 0.63 ms | 80,018 B |
| Gemini v1, 1,024 coefficients | 317.96 ms | 7.36 ms | 887,872 B |
| `lookup_pcs`, 1,024-in-1,024, C4 | 273.01 ms | 5.77 ms | 642,443 B |
| `vm`, 64 steps, `B16 Q12 C2` | 0.69 ms | 0.18 ms | 14,933 B |

Cap height 4 reduces the BaseFold proof by **37.3%**. The BaseFold and
committed-lookup rows are prototypes; the VM row is the plain path.

### 11.3 Fast shapes and primitives

| Workload | Prove | Verify | Proof |
|---|---:|---:|---:|
| FRI polynomial, 256 coefficients | 0.15 ms | 0.08 ms | 11,522 B |
| AIR Fibonacci, 64 steps | 0.17 ms | 0.11 ms | 15,465 B |
| Range, 16-bit | 0.10 ms | 0.07 ms | 5,217 B |
| Table, 4 entries | 0.04 ms | 0.04 ms | 4,673 B |
| Lookup, 64-in-16 | 0.19 ms | 0.09 ms | 2,897 B |
| Fold, 4×8 Fibonacci | 0.19 ms | 0.19 ms | 16,845 B |
| AIR Fibonacci, 1,024 steps | 2.01 ms | 0.20 ms | 28,257 B |

| Primitive | Measured |
|---|---:|
| BLAKE3, 1 MiB | 1.17 ms (856.5 MB/s) |
| BabyBear multiplication | 6.59 ms / 1M ops (151.8 Mops/s) |
| GF(2^64) multiplication | 272.84 ms / 1M ops (3.7 Mops/s) |
| NTT forward, 2^14 | 0.32 ms |
| Merkle tree, 65,536 leaves | 3.24 ms |

The full table and methodology are in [Benchmarks](benchmarks.md).

---

## 12. Security evaluation

### 12.1 Assumptions

- BLAKE3-256 collision and preimage resistance;
- FRI soundness under the Johnson-radius heuristic;
- Fiat–Shamir in the (quantum) random-oracle model;
- standard Reed–Solomon list-decoding bounds.

No discrete-log, pairing, or trusted-setup assumptions. The system is
Shor-inert by construction.

### 12.2 Enforced invariants

- Rate gate at prove and verify.
- Verifier-derived domains and query indices.
- Final divided-difference check at true folded points, non-vacuous.
- Cap/path shape pins before hashing; direction bits bound to indices.
- `fri-dims` dimension binding.
- Canonical-only decoding with hard caps.
- PoW bound to the full history; queries sampled after grinding.
- Committed read-checks in `lookup_pcs`.
- Correct masked composition bounds in VM.

### 12.3 Adversarial evidence

| Suite | Tests | Result |
|---|---:|---|
| Library | 277 | All pass; KATs, Horner cross-checks, parallel determinism |
| `security.rs` | 13 | 479 hostile attempts, 0 accepted |
| `redteam.rs` | 10 | 37 targeted + 500 garbage, 0 accepted, 0 panics |
| `hardening.rs` | 11 | Hostile params, exhaustive per-bit AIR decoder fuzz, 14,000 mutations, 0 panics |
| Doc tests | 5 | All pass |
| **Total** | **316** | Plus coverage-guided `fuzz/decode` |

### 12.4 Closed findings

The evidence package records real issues found and fixed during internal
adversarial review:

- Merkle path index binding across all verifiers and hand-rolled FRI/BaseFold
  walks.
- One-point FRI final layer / vacuous degree check; every `Params` now
  requires `final_size >= 2`, and FRI rejects vacuous residual bounds.
- Fold-free FRI with no query openings; commit and verify reject it.
- FRI final cap binding to `final_poly`.
- `lookup_pcs` read-checks bound to committed columns.
- VM masked `Mul` quotient degree corrected.
- AIR/VM zero-knowledge mask budgets corrected to 16/2 values per query.
- Batched BaseFold opening uses the multilinear basis table.
- Prover allocation ordering, checked buffer arithmetic, cap-height bounds,
  recursion domain bounds, and transcript/grinding hardening.

Details and regression names are in [Security tests](security-tests.md).

### 12.5 Residual risk

The system remains unaudited. The soundness numbers are conjectured. The
small-table `table` AIR scales with table size. `lookup_pcs` is not
zero-knowledge and does not constrain columns to the base field. The
BaseFold, Gemini, VM, and recursion modules are prototypes. Side channels in
the host OS, compiler, or CPU are out of scope. Do not deploy for high-value
statements before an external audit.

---

## 13. Related work

z0p follows the STARK/FRI lineage: Ben-Sasson et al.'s STARKs and FRI,
DEEP-FRI, and BCS-style Fiat–Shamir. Production systems such as Plonky2 and
RISC Zero share the BabyBear-plus-FRI engineering core but retain larger
dependency footprints. z0p differs by taking dependency-freedom and
auditable minimalism as hard constraints, and by publishing adversarial test
evidence alongside performance claims. Lookups follow the LogUp
logarithmic-derivative design. The hash is BLAKE3; Fiat–Shamir is classical.

### References

1. E. Ben-Sasson, I. Bentov, Y. Horesh, M. Riabzev. *Scalable, transparent,
   and post-quantum secure computational integrity.* ePrint 2018/046.
2. E. Ben-Sasson, I. Bentov, Y. Horesh, M. Riabzev. *Fast Reed–Solomon
   interactive oracle proofs of proximity.* ICALP 2018.
3. E. Ben-Sasson, D. Bentov, Y. Horesh, M. Riabzev. *DEEP-FRI: Sampling
   outside the box improves soundness.* ePrint 2019/336.
4. E. Ben-Sasson, A. Chiesa, N. Spooner. *Interactive oracle proofs.*
   TCC 2016.
5. A. Fiat, A. Shamir. *How to prove yourself.* CRYPTO 1986.
6. J.-P. Aumasson, S. Neves, J. O'Connor, Z. Wilcox-O'Hearn. *BLAKE3: one
   function, fast everywhere.* 2020.
7. U. Haböck. *Multivariate lookups based on logarithmic derivatives.*
   ePrint 2022/1530.
8. Polygon Zero Team. *Plonky2: fast recursive arguments with PLONK and
   FRI.* 2022.

---

## 14. Roadmap

1. **External audit.** The evidence package is ready for review.
2. **Hiding PCS and sumcheck.** Private tables and witness-independent
   multilinear openings.
3. **Batched BaseFold openings.** Replace `lookup_pcs`'s eight separate
   openings with `open_multi`.
4. **Self-proving recursion.** BLAKE3 path checks, final-degree check, and
   transcript derivation inside the recursion AIR.
5. **zkVM direction.** Control flow, memory, instruction privacy, and a
   general circuit compiler.
6. **SIMD and scheduling.** Broader portable-SIMD hash coverage and lower
   parallel scheduling overhead.

---

## Appendix A — Parameter recipes

| Purpose | Constructor | Shape |
|---|---|---|
| Fast bench | `Params::new(...)` / `for_security` small target | Rate ~1/8, 12 queries, no grinding |
| Production | `Params::for_security(len, ..., 100)` | Blowup 16, 40 queries, 20-bit grinding, tuned final/cap |
| AIR ZK | manual | `n_rand >= 16 * num_queries`; size final for masked LDE |
| VM ZK | manual | `n_rand >= 2 * num_queries`; size final for masked LDE |
| Range/table ZK | manual | `n_rand >= num_queries` |
| BaseFold | `basefold::Params::for_security(poly_len, 100)` | Blowup 16, tuned queries/grinding |

## Appendix B — Reproducibility

```sh
cargo fmt --check
python3 tools/check_links.py
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
cargo clippy --all-targets -- -D warnings
cargo test
cargo test --release
cargo bench
python3 tools/check.py
```

The gate pins all 24 benchmark rows: proof sizes byte-for-byte, times within
3× of `tools/baseline.json`. See [AUDIT.md](../AUDIT.md) for the review
order and [docs/unit-tests.md](unit-tests.md) for the per-module breakdown.

## Appendix C — Glossary

| Term | Meaning |
|---|---|
| AIR | Algebraic Intermediate Representation: trace + transition/boundary constraints |
| FRI | Fast Reed–Solomon Interactive Oracle Proof of Proximity |
| LDE | Low-degree extension: evaluations on a larger coset domain |
| MLE | Multilinear extension/polynomial |
| PCS | Polynomial commitment scheme |
| PoW | Proof of work used as a Fiat–Shamir grinding step |
| STARK | Scalable Transparent Argument of Knowledge |
| UPCs | Univariate polynomial commitment scheme |
| ZK | Zero knowledge |

---

**License.** GPL-3.0-only. See [LICENSE](../LICENSE).
**Security reports:** follow [SECURITY.md](../SECURITY.md); email
**futureproofs@proton.me**. Do not open a public issue for suspected
soundness, zero-knowledge, or memory-safety bugs.
