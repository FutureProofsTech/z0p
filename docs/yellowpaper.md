# z0p — Yellow Paper

## Formal specification of the z0p proving stack

**Version 1.2 — 2026-11-06.** Normative where marked. Code references are to
the `src/` modules of the crate at version `0.3.0`. The companion
[White Paper](whitepaper.md) gives the design rationale and evaluation; the
[formal PDF](../papers/z0p-yellowpaper.pdf) is compiled from this source. This
document gives the exact mathematics, algorithms, encodings, validation
rules, and security invariants implemented by the code.

> **Status.** v0.3.0, unaudited research software. The production figure is a
> **conjectured query/proof-of-work schedule**, not an end-to-end soundness
> theorem. Normative parameter checks are enforced by the code; conjectured
> bit-levels are explicitly marked.

---

## Contents

1. [Conventions and notation](#1-conventions-and-notation)
2. [Fields](#2-fields)
3. [Domains, NTT, and Reed–Solomon encoding](#3-domains-ntt-and-reed-solomon-encoding)
4. [BLAKE3 and Merkle commitments](#4-blake3-and-merkle-commitments)
5. [Fiat–Shamir transcript and proof of work](#5-fiat-shamir-transcript-and-proof-of-work)
6. [FRI polynomial commitment](#6-fri-polynomial-commitment)
7. [Multilinear polynomials and sumcheck](#7-multilinear-polynomials-and-sumcheck)
8. [Univariate point openings (UPCs)](#8-univariate-point-openings-upcs)
9. [Gemini multilinear commitments](#9-gemini-multilinear-commitments)
10. [BaseFold prototype](#10-basefold-prototype)
11. [Lookup arguments](#11-lookup-arguments)
12. [AIR systems](#12-air-systems)
13. [Zero-knowledge masking](#13-zero-knowledge-masking)
14. [Wire format](#14-wire-format)
15. [Parameter validation and sizing](#15-parameter-validation-and-sizing)
16. [Security analysis](#16-security-analysis)
17. [Evidence and reproducibility](#17-evidence-and-reproducibility)
18. [Appendices](#18-appendices)

---

## 1. Conventions and notation

### 1.1 Normative language

- **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used normatively.
- A **proof object** is the in-memory Rust value; its **encoding** is the
  canonical byte string produced by `to_bytes`.
- A **verifier** MUST reject on any failed check with `Err`; it MUST NOT panic
  on untrusted input.
- Public `Params` structs have public fields. Every entry point MUST
  re-validate them rather than trusting a constructor.
- All integer arithmetic in encodings is little-endian.
- `usize` is the platform word; the crate supports 32-bit and 64-bit targets
  subject to the domain ceilings below.

### 1.2 Symbols

| Symbol | Meaning |
|---|---|
| `p` | BabyBear modulus `2^31 - 2^27 + 1 = 2013265921` |
| `Fp` | Prime field `Z/pZ` |
| `Fp2` | `Fp[u]/(u^2 - 11)` |
| `Fp4` | `Fp2[v]/(v^2 - u)` |
| `H` | Base trace domain of size `N` |
| `D` | Coset LDE domain of size `M = N * beta` |
| `beta` | Blowup factor, a power of two |
| `omega` | Primitive `N`-th root of unity |
| `Omega` | Primitive `M`-th root of unity |
| `gamma` | Coset shift `LDE_SHIFT = 31` |
| `Z_H(x)` | `x^N - 1` |
| `w_last` | `omega^(N-1)` |
| `Q` | Number of FRI queries |
| `f` | Number of FRI folds |
| `F` | Final layer size (`final_size`) |
| `C` | Composition polynomial |
| `Fp4` challenge | Element of the quartic extension field |
| `H(x)` | BLAKE3-256 digest of `x` |

### 1.3 Complexity notation

`O(n)` and `O(n log n)` refer to field or hash operations as appropriate.
The verifier avoids `O(M)` materialization; it derives domain points on
demand. Proof sizes are reported in bytes of the canonical encoding.

---

## 2. Fields

### 2.1 BabyBear prime field

```text
p = 2^31 - 2^27 + 1 = 2013265921
p - 1 = 2^27 * 15
g = 31  (primitive root)
```

`Fp` elements are canonical integers in `[0, p)`. The private representation
is a `u32` with the invariant `value < p`. The public constructor reduces
modulo `p`; the decoder rejects non-canonical bytes.

#### 2.1.1 Addition and subtraction

For `a, b < p`:

```text
a + b = a + b            if a + b < p
        a + b - p        otherwise
a - b = a - b            if a >= b
        a - b + p        otherwise
```

Both fit in `u32` because `2p < 2^32`. Negation maps `0` to `0` and `a` to
`p - a`.

#### 2.1.2 Multiplication

Let

```text
MU = floor(2^64 / p) = 9162596893
x  = a * b < p^2 < 2^62
q  = ((x >> 32) * MU) >> 32
r  = x - q * p
```

Then `q <= floor(x/p)` and `r < 2p`; a short loop subtracts `p` until
`r < p`. This is the Barrett reduction used by the hot NTT/FRI paths. It is
cross-checked against wide `%` on 100,000 random pairs and edge values.

#### 2.1.3 Inversion and halving

Inversion is Fermat:

```text
a^-1 = a^(p-2)
```

with `0^-1 = 0` by convention. The exponentiation uses a fixed exponent
`p-2`; the loop length is public. `halve(a)` computes
`(a + (a mod 2) * p) / 2`, which is exact because `p` is odd.

#### 2.1.4 Batch inversion

For a slice `a_0, ..., a_{n-1}`, Montgomery's trick computes all nonzero
inverses with one field inversion and `3n` multiplications. Zeros map to
zero and do not contribute to the running product. The in-place variant is
used in composition and folding hot loops.

#### 2.1.5 Roots of unity

For `k <= 27`, `two_adic_generator(k) = g^((p-1)/2^k)` generates the unique
subgroup of order `2^k`. `primitive_root(m)` requires `m` to be a power of
two `<= 2^27`. The NTT and FRI domains never exceed `2^27`.

### 2.2 Quartic extension field

Define the tower

```text
Fp2 = Fp[u] / (u^2 - 11)
Fp4 = Fp2[v] / (v^2 - u)
```

An element is `a + b u + c v + d u v`, stored as four canonical `Fp`
coordinates `[a, b, c, d]`.

#### 2.2.1 Addition and subtraction

Coordinate-wise in `Fp`.

#### 2.2.2 Multiplication

For `x = a + b u + c v + d u v` and `y = a' + b' u + c' v + d' u v`, write
`x = A + C v`, `y = B + D v` with `A, B, C, D in Fp2`. Then

```text
x y = (A B + u C D) + (A D + C B) v.
```

The implementation uses Karatsuba for the cross term:

```text
cross = (A + C)(B + D) - A B - C D.
```

`Fp2` multiplication is

```text
(a0 + a1 u)(b0 + b1 u)
  = (a0 b0 + 11 a1 b1) + (a0 b1 + a1 b0) u.
```

#### 2.2.3 Inversion

For `x = c + d v` with `c, d in Fp2`,

```text
x^-1 = (c - d v) / (c^2 - u d^2).
```

The denominator is an `Fp2` element; its inverse uses the `Fp2` norm

```text
(c0 + c1 u)^-1
  = (c0 - c1 u) / (c0^2 - 11 c1^2).
```

One `Fp2` inversion therefore suffices. `inv(0) = 0`; no branch on
zero-ness is used in the field core.

#### 2.2.4 Canonical encoding

Each coordinate is four canonical little-endian bytes; an element is 16
bytes. The decoder checks every coordinate against `p`.

### 2.3 Binary fields

The word layer provides:

| Field | Polynomial |
|---|---|
| `GF(2^8)` | `x^8 + x^4 + x^3 + x + 1` (`0x11B`) |
| `GF(2^64)` | `x^64 + x^4 + x^3 + x + 1` |
| `GF(2^128)` | `x^128 + x^7 + x^2 + x + 1` |

Addition is XOR. Multiplication is carryless multiplication followed by
reduction modulo the field polynomial. The arithmetic loops run fixed
iteration counts; inverses use fixed Fermat exponentiation and map zero to
zero. Every bit pattern is a valid element, so decoding is infallible.
`F128::embed_f64` is **not** provided: a bit-level embedding of `F64` into
`F128` is not a field homomorphism because the `F64` modulus does not divide
the `F128` modulus.

---

## 3. Domains, NTT, and Reed-Solomon encoding

### 3.1 Domains

The base domain is

```text
H = {1, omega, ..., omega^(N-1)},   omega = primitive_root(N).
```

The evaluation domain is the coset

```text
D = gamma * <Omega>,   |D| = M = N * beta,
```

with `Omega = primitive_root(M)` and `gamma = 31`. The domain ceiling is
`M <= 2^27`.

The vanishing polynomial of `H` is `Z_H(x) = x^N - 1`. It is zero exactly on
`H` and nonzero on the coset `D` because `gamma != 0` and `D` is disjoint
from `H` for the chosen coset.

### 3.2 Bit-reversal permutation

For length `n = 2^k`, the bit-reversal permutation maps index `i` to

```text
rev_k(i) = reverse_bits(i) >> (usize::BITS - k).
```

Small arrays are permuted in place; large arrays gather into a fresh buffer
in parallel. FRI layers are stored in bit-reversed order so that each
adjacent quad corresponds to the four points `(x, -x, j0 x, -j0 x)`.

### 3.3 Forward and inverse NTT

The forward NTT evaluates a coefficient vector at powers of `omega`. The
inverse NTT interpolates and scales by `1/n`. The implementation uses
Cooley–Tukey stages:

```text
for len = 2, 4, ..., n:
    for each block of length len:
        for j in 0 .. len/2:
            u = block[j]
            v = block[j + len/2] * twiddle[j * (n/len)]
            block[j]         = u + v
            block[j + len/2] = u - v
```

Twiddles are precomputed once per transform as chained powers
`1, root, ..., root^(n/2-1)`. The inverse transform uses the inverse root
and folds the `1/n` scaling into the final stage. Domains must be nonempty
powers of two `<= 2^27`.

### 3.4 Coset evaluation and interpolation

For coefficients `c_0, ..., c_{n-1}` and blowup `beta`, coset evaluation
computes `M = n beta` values

```text
c(gamma * Omega^i),   i = 0, ..., M-1,
```

by multiplying `c_i` by `gamma^i`, zero-padding to `M`, and applying the
forward NTT. Interpolation inverts the base-domain transform. Extension-field
coset evaluation applies the base-field transform to each of the four
coordinates and recombines.

### 3.5 Complexity

A transform of size `n` uses `O(n log n)` field operations and `O(n)`
memory. Parallel stages are deterministic and bit-identical to the
sequential reference; worker count depends only on lengths and available
parallelism.

---

## 4. BLAKE3 and Merkle commitments

### 4.1 BLAKE3-256

The crate implements unkeyed BLAKE3 with 256-bit output:

- 16-word state, 7 ARX rounds;
- message permutation
  `[2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8]`;
- flags `CHUNK_START = 1`, `CHUNK_END = 2`, `PARENT = 4`, `ROOT = 8`;
- 1024-byte chunks and 64-byte blocks;
- Bao-style merge-while-even chaining-value stack.

The implementation is validated against reference vectors for the empty
input, `abc`, exactly one chunk, one byte over a chunk, two chunks, and a
multi-chunk input crossing boundaries. Incremental updates with arbitrary
splits must equal the one-shot digest.

### 4.2 Merkle trees

A tree is a complete binary tree over leaves padded by duplicating the last
leaf to a power of two. For raw leaves:

```text
leaf(d)    = BLAKE3(0x00 || d)
node(l, r) = BLAKE3(0x01 || l || r)
```

FRI quad trees and AIR trace trees use 64-byte leaves hashed with standard
BLAKE3 (one compression per full block); internal nodes use the same
`0x01 || l || r` construction.

A path is a sequence `(sibling, is_left)`. Verification recomputes the leaf
digest, folds upward, and compares to the root. A path is valid for index
`i` only if, for every level `k`,

```text
is_left_k = ((i >> k) & 1 == 0).
```

This index binding is mandatory. Without it, a valid opening for leaf `j`
would verify at any other in-range index with the same path length.

### 4.3 Caps

A cap at drop `d` is the tree layer at depth `depth - d`:

```text
cap(d) = layers[depth - min(d, depth)].
```

It contains `2^min(d, depth)` digests. Openings omit the top `d` path steps
and authenticate the remaining path to the selected cap entry. The verifier
recomputes the cap root by hashing pairs with `node`. Cap height is capped at
8 in every public `Params`; `MAX_CAP_DIGESTS = 256`.

For FRI, opened layers commit one 64-byte leaf per quad; the final layer is
sent in the clear and its cap is recomputed from `final_poly`. For AIR, a
64-byte trace leaf contains eight joint rows (`A || B`, 8 bytes per row).
The verifier checks the row at `(index & 7) * 8` and authenticates the whole
leaf at `index / 8`.

### 4.4 Padding and tree shape

`num_leaves` is always a power of two after padding. `capped_shape(n, h)`
returns

```text
(drop, depth) = (min(h, log2(n)), log2(n)).
```

Prover and verifier derive the same shape from the same leaf count.

---

## 5. Fiat-Shamir transcript and proof of work

### 5.1 Framing

The transcript is an append-only byte history. `absorb(label, data)` appends

```text
u64_le(label.len()) || label || u64_le(data.len()) || data.
```

The implementation stores the history as a streaming BLAKE3 state. A squeeze
clones the state, appends

```text
u64_le(label.len()) || label || u64_le(counter),
```

finalizes, increments `counter`, and absorbs the 32-byte output back into the
history. This is byte-identical to hashing the full concatenation, but cost
is independent of history length.

### 5.2 Challenge derivation

- `challenge_f64`: first 8 bytes as little-endian `u64`.
- `challenge_f128`: first 16 bytes as little-endian `u128`.
- `challenge_bb`: first 8 bytes as `u64 mod p`; reduction bias below
  `2^-31`.
- `challenge_ext`: four 4-byte coordinates reduced modulo `p`.
- `challenge_index(label, domain_size)`: masks the low 64 bits with
  `domain_size - 1`; requires a nonzero power-of-two domain. Returns `None`
  otherwise.

Every squeeze is domain-separated by label and counter and is bound to all
prior absorptions.

### 5.3 Proof of work

`grind(label, d)` computes

```text
head = BLAKE3(history) || u64_le(label.len()) || label
```

and searches for the smallest nonce `u64` such that
`BLAKE3(head || u64_le(nonce))` has at least `d` leading zero bits
(most-significant-bit first). The search is banded across threads and returns
the same nonce as a sequential scan.

Protocol parameters cap `d <= 32`. `grind` fails closed above 32 by absorbing
nonce `0` and returning `0`. `verify_grind` re-hashes and accepts only if the
nonce meets the target; it hard-rejects `d > 256`. Queries are sampled after
the nonce is absorbed, so they bind to the work.

### 5.4 Label schedule

| Protocol | Labels, in order |
|---|---|
| FRI | `fri-dims` (dimensions first), `fri-layer-root` per cap digest, `fri-fold` ×3 per layer, `fri-final`, `fri-pow`, `fri-query` per query |
| AIR / range / table | `<proto>/params`, `<proto>/column`, `<proto>/alpha` (fixed count) |
| fold (IVC) | `fold/params`; per step `fold/step`, `fold/trace`, six `fold/alpha`; then one `fold/gamma` per step |
| lookup | `lookup/witness`, `lookup/table`, `lookup/beta-challenge`, `lookup/beta`, `lookup/m`, `lookup/qw`, `lookup/qt`, `lookup/sums`, `lookup/ctx` separators, `lookup/r1`, `lookup/r2` |
| lookup_pcs | `lookup-pcs/commitments`, `lookup-pcs/beta`, `lookup-pcs/quotients`, `lookup-pcs/sum-w`, `lookup-pcs/ctx`, `lookup-pcs/r1`, `lookup-pcs/gamma`, `lookup-pcs/r2`, and one `lookup-pcs/open` label per BaseFold opening |
| vm | `vm/params`, `vm/trace`, four `vm/alpha` |
| recursion | `rec/params`, `rec/trace`, seven `rec/alpha` |
| sumcheck | `sumcheck/claim`; per round `sumcheck/round`, `sumcheck/challenge` |

A caller MUST start the transcript with a unique application label. The
transcript constructor absorbs `("domain", label)` first.

---

## 6. FRI polynomial commitment

### 6.1 Parameters

```text
Params {
    blowup: usize,       // power of two, >= 2
    num_queries: usize,  // >= 1, <= MAX_QUERIES = 2^20
    final_size: usize,   // power of two, 2 ..= MAX_FINAL_SIZE = 1024
    grinding_bits: u32,  // <= 32
    cap_height: usize,   // <= 8
}
```

`final_size` MUST be strictly below the LDE length: at least one fold is
required. `final_size >= 2` is required for a non-vacuous final degree
check. The ratio `M / final_size` MUST be a power of four so quartering lands
exactly.

### 6.2 Commitment

`commit(coeffs, params, transcript)`:

1. validate params;
2. require nonempty power-of-two coefficients and `M = n beta <= 2^27`;
3. evaluate on the coset and bit-reverse;
4. absorb `fri-dims = (M, n, degree_bound)` where
   `degree_bound = n - 1`;
5. for each layer:
   - commit the layer with 64-byte quads (or 16-byte values if the layer is
     not divisible by four);
   - compute the cap and absorb every cap digest under
     `fri-layer-root`;
   - if the layer is larger than `final_size`, squeeze three `fri-fold`
     challenges and fold every quad;
6. absorb `fri-final` with the final layer;
7. return prover state.

`commit_evals(lde, bound, ...)` takes already-expanded natural-order coset
values, requires `bound < M`, sets `poly_len = M`, and follows the same
inner path. `commit_ext` and `commit_ext_evals` are the extension-field
analogues.

The rate gate is

```text
degree_bound + 1 <= M / 2.
```

It is enforced at prove and verify.

### 6.3 Arity-4 folding

Let the four values of a quad be `e0, e1, e2, e3` at
`(x, -x, j0 x, -j0 x)`, where `j0` is the primitive fourth root. Write

```text
P(X) = A + B X + C X^2 + D X^3,   Y = X^4.
```

Then

```text
A = (e0 + e1 + e2 + e3) / 4
B = ((e0 - e1) - j0 (e2 - e3)) / (4 x)
C = ((e0 + e1) - (e2 + e3)) / (4 x^2)
D = ((e0 - e1) + j0 (e2 - e3)) / (4 x^3)
```

and the fold is

```text
fold(e0,e1,e2,e3) = A + r0 B + r1 C + r2 D,
```

with `(r0,r1,r2) in Fp4^3`. Each fold quarters the degree. Point inverses
are base-field values and are batch-inverted once per layer.

### 6.4 Proof object

```text
Proof {
    final_poly: Vec<Fp4>,
    queries: Vec<QueryProof>,
    pow_nonce: u64,
}
QueryProof { folds: Vec<FoldWitness> }
FoldWitness { values: [Fp4; 4], path: Vec<(Digest, bool)> }
```

Each query opens all four values of every folded quad plus the middle Merkle
path segment. The leaf digest is the standard BLAKE3 root of the canonical
64-byte encoding of the four `Fp4` values. With caps, the stored path omits
the top `cap_height` steps and the cap entry is selected by the query index.

### 6.5 Verification

`verify(commitment, proof, params, transcript)` performs:

1. `params.validate()`;
2. `proof.queries.len() == params.num_queries`;
3. `proof.final_poly.len() == params.final_size`;
4. nonempty caps, power-of-two `lde_len <= 2^27`;
5. `degree_bound < lde_len`, `poly_len` nonzero power of two;
6. if `poly_len != lde_len` (the `commit` path), require
   `lde_len == poly_len * params.blowup`;
7. rate gate `degree_bound + 1 <= lde_len / 2`;
8. at least one fold: `folds = caps.len() - 1 >= 1`;
9. fold-count consistency `(lde_len >> 2 f) == params.final_size`;
10. cap shape pins before hashing: each cap has exactly `2^drop` digests;
11. replay `fri-dims`, cap absorptions, `fri-fold` challenges, and
    `fri-final`;
12. PoW gate: with zero grinding require nonce `0`; otherwise
    `verify_grind`;
13. compute `residual = degree_bound >> 2f`; reject if
    `residual + 1 >= final_size`;
14. compute the true folded domain points and check the final layer by
    divided differences;
15. recompute the final cap from `final_poly` and compare it to the last
    commitment cap;
16. sample `num_queries` indices after grinding and check every query:
    exact path length, cap entry, direction bits, leaf hash, fold relation,
    and chaining into the next layer or `final_poly`.

### 6.6 Final degree check

Given distinct points `x_0, ..., x_{n-1}` and values `v_0, ..., v_{n-1}`,
the divided-difference table is

```text
T^{(0)}_i = v_i
T^{(k)}_i = (T^{(k-1)}_{i+1} - T^{(k-1)}_i) / (x_{i+k} - x_i).
```

The values interpolate a polynomial of degree `<= bound` iff every divided
difference of order `bound + 1` vanishes. Higher orders then vanish
automatically, so the implementation stops at order `bound + 1` rather than
computing the full quadratic table. If `bound >= n - 1`, the check is
vacuous and the verifier rejects the shape earlier via the residual test.

### 6.7 Conjectured soundness

Under the Johnson-radius heuristic, a word at distance `delta` from the code
survives one query with probability at most `1 - delta`, where

```text
delta ~= 1 - sqrt(rate).
```

| Shape | Rate | Queries | Grinding | Conjectured query + PoW |
|---|---:|---:|---:|---:|
| Bench | 1/8 | 12 | 0 | ~18 bits |
| Production | 1/16 | 40 | 20 | ~100 bits (80 + 20) |

These counts exclude finite-field algebraic error. FRI folds, STARK
compositions, UPCs/Gemini points and betas, sumcheck rounds, and lookup
identities use `Fp4`, so a degree-`d` identity collides with probability
about `d/p^4` per challenge (~124 bits). This is still a conjectured
query/PoW schedule, not an end-to-end theorem.

---

## 7. Multilinear polynomials and sumcheck

### 7.1 MLE representation

An `Mle` with `n` variables stores `2^n` evaluations in index order. The
index, read most-significant-bit first, is the variable assignment. Index
`0` is `(0,...,0)`; index `2^n - 1` is `(1,...,1)`.

`evaluate(point)` folds the least-significant variable first:

```text
buf[i] = buf[2i] + r (buf[2i+1] - buf[2i]).
```

The equality polynomial is

```text
eq(r, x) = product_i (r_i x_i + (1 - r_i)(1 - x_i)).
```

`eq_evals(r)` builds its hypercube table in MSB-first order.

### 7.2 Sumcheck protocol

A summand is a sum of terms

```text
f(x) = sum_k c_k product_{j in factors_k} mle_j(x),
```

with `c_k in Fp4`. The prover claims `S = sum_{x in {0,1}^n} f(x)` and sends
round polynomials `g_i` of degree at most the maximum factor count. Round
`i` restricts the current buffers to the line through the two halves of
variable `i` and evaluates at `0, 1, ..., degree`.

Verification:

1. absorb the claimed sum;
2. for each round, require `g_i(0) + g_i(1) = previous`, absorb the round,
   sample `r_i`, and set `previous = g_i(r_i)`;
3. require the final oracle values to satisfy the summand;
4. if the oracle is committed, open each final value at the challenge point.

Challenges are `Fp4`. The degree is bounded by the largest factor count.

### 7.3 Complexity

Prover work is `O(n * 2^n * terms * factors)` field operations; verifier work
is `O(n * terms * factors)` plus oracle evaluation/opening. The
implementation keeps dense buffers and folds them in place.

---

## 8. Univariate point openings (UPCs)

### 8.1 Commitment

`upcs::commit(coeffs, blowup)` computes the bit-reversed coset LDE of the
coefficient polynomial and commits it as 64-byte leaves (four `Fp4` values
per leaf). `poly_len` is the coefficient count; `lde_len = poly_len * blowup`.
`check_dims` enforces a power-of-two `poly_len`, blowup at least 2, and
`lde_len <= 2^27`.

### 8.2 Single-point opening

To prove `g(beta) = y`:

1. absorb the commitment root, dimensions, point, and value;
2. commit `g` with FRI and check that the FRI base cap hashes to the
   statement root;
3. compute the quotient `q = (g - y)/(X - beta)` and commit it with FRI at
   degree bound `max(poly_len - 2, 0)`;
4. sample the quotient's FRI query indices;
5. for each index, open the quad containing the evaluation of `g` and the
   quotient value, and check

```text
(X - beta) q(X) = g(X) - y.
```

### 8.3 Multi-point opening

For distinct points `p_0, ..., p_{k-1}` and values `y_j`, let `I` interpolate
the claims and `Z = product_j (X - p_j)`. The prover commits
`q = (g - I)/Z` at degree bound `poly_len - k - 1` and proves the identity

```text
g(X) = I(X) + Z(X) q(X)
```

at the quotient's query points. `check_points` requires `1 <= k <= 16`,
`k <= poly_len`, and distinct points.

When `k == poly_len`, `I` determines `g` and the quotient is identically
zero. The verifier checks `g` against `I` directly rather than allowing a
nonzero constant quotient to absorb the difference at random points. For
`poly_len == 1`, the single-point verifier checks `opening.value == value`.

### 8.4 Caps

UPCs uses the FRI base cap for the statement commitment and threads the same
cap height through evaluation paths. The FRI base cap must hash to the
statement root; evaluation paths are authenticated against the corresponding
cap entry.

### 8.5 Soundness sketch

FRI certifies both `g` and `q` are low-degree. The identity difference has
degree below `poly_len`; it is checked at the quotient's random coset points,
so a nonzero difference is missed with probability at most
`(poly_len - 1)/lde_len = 1/blowup` per query. For multi-point openings the
same bound holds because `g - I - Z q` has degree below `poly_len`. The
full-point case is checked directly against the interpolant.

---

## 9. Gemini multilinear commitments

### 9.1 Coefficient encoding

For a multilinear polynomial `f` with monomial coefficients `c_b`, commit

```text
g_0(X) = sum_b c_b X^index(b)
```

with UPCs. `commit_evals` applies the Möbius transform to hypercube
evaluations; the index order matches `Mle` (MSB-first).

### 9.2 Folding

For `i = 1..n`, write

```text
g_{i-1}(X) = A_i(X^2) + X B_i(X^2)
g_i(Y) = A_i(Y) + r_i B_i(Y),
```

where `r_i` is the `i`-th unfolding coordinate. The prover commits
`g_1, ..., g_{n-1}` and checks, for a nonzero random `beta_i`:

```text
g_i(beta_i^2) = (g_{i-1}(beta_i) + g_{i-1}(-beta_i))/2
              + r_i (g_{i-1}(beta_i) - g_{i-1}(-beta_i))/(2 beta_i).
```

The final public check is `g_{n-1}(r_0) = y`.

### 9.3 Openings

Each layer is opened once with a multi-point UPCs proof at all points its
relations use:

- `g_0` at `beta_1, -beta_1`;
- interior `g_i` at `beta_i^2, beta_{i+1}, -beta_{i+1}`;
- `g_{n-1}` at `beta_{n-1}^2, r_0`.

Layer commitments are absorbed before the betas. The proof carries `n-1`
layer commitments, one multi-point opening per layer, and the layer-opening
values. It is linear-size, not constant-size.

### 9.4 Verification

The verifier:

1. validates dimensions (`n_vars <= MAX_VARS = 20`, blowup at least 8);
2. absorbs the statement and layer commitments;
3. samples nonzero fold betas;
4. verifies each layer's multi-point UPCs opening;
5. checks each fold identity and the final public value.

### 9.5 Soundness

Each fold identity has degree below `2^(n-i+1)`, so one random check misses a
nonzero identity with probability at most `2^(n-i+1)/p^4`. Over `n` layers
the algebraic error is at most `n 2^n / p^4` (below `2^-99` for `n = 20`).
The query/PoW schedule is separate and conjectured.

---

## 10. BaseFold prototype

### 10.1 Commitment

`basefold::commit(coeffs, blowup)` commits the monomial-coefficient encoding
with FRI. Coefficients are in Möbius order, matching `Mle`. The maximum
variable count is `MAX_VARS = 16`. `commit_ext` accepts extension-field
coefficients; `commit_evals`/`commit_evals_ext` apply the Möbius transform to
hypercube evaluations.

### 10.2 Sumcheck reduction

To prove `f(r) = y`, the prover builds the multilinear basis table

```text
w_b = product_i r_i^{b_i}
```

and uses sumcheck on

```text
sum_b c_b w_b = f(r).
```

The sumcheck outputs a challenge `rho in Fp4^n` and a claimed value
`c(rho)`, where `c` is the multilinear extension of the coefficient table.

### 10.3 Möbius FRI fold

The prover folds the LDE with the Möbius/eq rule

```text
(1 - rho_i) E(X) + rho_i O(X)
```

rather than the coefficient-encoding rule `E(X) + rho_i O(X)`, so the final
FRI constant is exactly `c(rho)`. The verifier recomputes

```text
w(rho) = product_i (1 - rho_i + rho_i r_i)
```

and checks `f(r) = c(rho) w(rho)`.

### 10.4 Proof and queries

A proof carries:

- sumcheck claimed sum and `n` rounds of three `Fp4` evaluations;
- `n-1` layer roots;
- optional cap frontiers, one per committed layer;
- a PoW nonce;
- one query per `num_queries`: one pair of values per layer plus a Merkle
  path from the pair parent to the layer root or cap entry.

Paths make the prototype `O(Q n^2)` bytes, not `O(n)`. Caps replace the top
path steps with a digest frontier and are authenticated against the layer
root.

### 10.5 Batched openings

`open_multi` proves several evaluations with one sumcheck and one fold walk.
The prover samples nonzero batch weights `lambda_j` after absorbing the
commitment, points, and values, then shows

```text
sum_j lambda_j f(point_j) = sum_j lambda_j value_j.
```

The summand weight is the multilinear basis table, not the equality table;
using the equality table for a monomial-coefficient commitment is a
correctness bug (fixed). `verify_multi` recomputes the same weighted sum.
Batches are capped at `MAX_BATCH = 1024` points.

### 10.6 Caps and status

`MAX_CAP_HEIGHT = 8`. The top cap hashes to the commitment root; lower caps
hash to the proof's layer roots. The BaseFold prototype is not wired into the
AIR/STARK stack and has no end-to-end soundness proof. It backs the committed
lookup prototype.

---

## 11. Lookup arguments

### 11.1 LogUp in clear

Let witness `w` and table `t` be padded to powers of two. The prover computes
first-index multiplicities

```text
m_j = |{ i : w_i = t_j }|,
```

samples `beta` avoiding all poles `-w_i` and `-t_j`, and forms

```text
q^w_i = 1/(beta + w_i)
q^t_j = m_j/(beta + t_j).
```

The rational identity is

```text
sum_i q^w_i = sum_j q^t_j.
```

Four sumchecks establish:

1. `sum q^w = sum_w`;
2. read-check `q^w_i (beta + w_i) = 1`;
3. `sum q^t = sum_t`;
4. read-check `q^t_j (beta + t_j) = m_j`.

Read-checks use a random equality point `r` and the summand

```text
eq(r,x) (q(x)(beta + v(x)) - target(x)).
```

The verifier has the witness and table in clear and recomputes canonical
multiplicities exactly; fractional multiplicities are rejected. The API is
sound for membership but not hiding.

### 11.2 Committed LogUp (`lookup_pcs`)

The committed variant commits witness, table, multiplicities, and both
quotient columns with BaseFold. The verifier sees five commitments and eight
openings. The read-checks use the committed columns directly:

```text
eq * (q * (beta + v) - target) = 0
```

expanded as

```text
eq*q*v + beta*eq*q - eq*target.
```

Using an uncommitted `beta + v` MLE would let a prover choose it after the
challenge and satisfy the sumcheck while only matching `v` at the final
point; the committed form closes that gap.

A fresh `gamma` folds the total multiplicity weight into the sum-t claim:

```text
sum(q^t + gamma m) = sum q^w + gamma W.
```

The verifier rejects `gamma = 0`. Every final sumcheck value is opened against
its commitment. At 1,024-in-1,024 with `B16 Q40 G20 C4`, the prototype
measures 273.01 ms prove, 5.77 ms verify, and 642,443 bytes. It is
committed-input but not zero-knowledge and does not constrain columns to the
base field.

### 11.3 Padding

Witness and table are padded to powers of two. The witness repeats its last
value; the table repeats its last value but padding slots receive zero
multiplicity. The lookup statement is membership of the padded witness, not
just its original prefix.

---

## 12. AIR systems

### 12.1 Common machinery

All AIRs:

1. interpolate trace columns;
2. extend on the coset `D`;
3. Merkle-commit joint rows;
4. absorb parameters and the column cap;
5. sample composition challenges;
6. evaluate the composition vector on `D` using geometric vanishing
   recurrences and Montgomery-batched inverses;
7. FRI-commit the composition with `commit_evals`;
8. open trace columns at FRI query positions;
9. re-check the composition identity per query.

Next-row values are the same committed columns at the `omega`-shifted LDE
index, authenticated by a second Merkle path. This prevents a prover from
decoupling the transition relation from the committed trace.

### 12.2 Fibonacci AIR

Trace:

```text
A[0] = a0
B[0] = b0
A[i+1] = B[i]
B[i+1] = A[i] + B[i]
B[N-1] = b_last.
```

Let `w_last = omega^(N-1)` and

```text
Z_trans(x) = (x^N - 1)/(x - w_last),
```

which is zero on rows `0..N-2`. At point `x` with values `(a,b)` and next
row `(a',b')`:

```text
C(x) = alpha0 (a' - b) / Z_trans(x)
     + alpha1 (b' - (a + b)) / Z_trans(x)
     + alpha2 (a - a0) / (x - 1)
     + alpha3 (b - b0) / (x - 1)
     + alpha4 (b - b_last) / (x - w_last).
```

Five `fib/alpha` challenges. `deg C < N` iff the trace is valid. Dividing by
`Z_trans` is load-bearing; multiplying would make the constraint vacuous.
Blowup is at least 4.

Plain proof degree bound is `N-1`. Masked proofs use a larger padded LDE and
a bound `N + n_rand - 1`. The verifier pins the plain domain and bound
exactly; for masked proofs it requires `m >= N*blowup`, `m % (N*blowup) == 0`,
`poly_len == m`, and `degree_bound < m/blowup`.

### 12.3 Range check AIR

Columns: value `V` and bits `C_0..C_{n-1}`, `1 <= n <= 24`. With challenges
`alpha_decomp`, `{alpha_j}`, `alpha_bound`:

```text
C = alpha_decomp (V - sum_j 2^j C_j) / Z_H
  + sum_j alpha_j C_j (C_j - 1) / Z_H
  + alpha_bound (V - value) / (x - 1).
```

The honest composition is identically zero; the declared bound covers the
boundary quotient. Any violated constraint leaves a nonzero numerator over a
vanishing denominator, whose coset interpolant is dense and rejected by FRI.
Masked booleanity doubles the degree; the verifier caps the declared bound
at `2*padded - n - 2`.

### 12.4 Table membership AIR

Constant column `v` against public table `T`:

```text
C(x) = alpha_member product_{t in T}(v - t) / Z_H(x)
     + alpha_bound (v - value) / (x - 1).
```

The membership numerator is zero on every row iff `v` is in `T`. The honest
composition bound is

```text
membership_bound(|T|, n, k) = |T| (n + k - 1) - n,
```

for `n` rows and `k` maskers. `table::Params::for_security` floors blowup at
4 so the smallest LDE is 8 and FRI has a valid final layer. Large tables need
proportionally larger blowup; the AIR is small-table by design.

### 12.5 Hash-folded IVC

Segments of `seg_steps` Fibonacci rows are committed independently with
claims `(in_a, in_b, out_a, out_b)`. The verifier checks:

- the first segment's input claims equal the public inputs;
- adjacent segments satisfy `out_a = next in_a` and `out_b = next in_b`;
- the last segment's `out_b` equals the public output.

Each segment has a composition `C_s`. After all segments are committed, the
prover samples `gamma_s` and commits

```text
V = sum_s gamma_s C_s
```

with one FRI instance. A far-from-code segment keeps the combination far with
overwhelming probability over the gammas. The statement is existential over
the number of segments; callers requiring an exact step count must check
`proof.steps.len()`. The accumulator retains each segment's LDE, Merkle tree,
and composition until finalization.

### 12.6 Register-machine AIR (`vm`)

A public two-register straight-line program executes on a private initial
state. Opcodes:

| Opcode | Effect |
|---|---|
| `Add` | `a <- a + b` |
| `Mul` | `a <- a * b` |
| `Swap` | swap `a` and `b` |
| `SetA(v)` | `a <- v` |
| `SetB(v)` | `b <- v` |
| `Halt` | leave both registers unchanged |

Rows `0..program.len()` execute the program; shorter traces pad with `Halt`.
The last row is the public output and has no outgoing transition. Public
one-hot selectors `sigma_o(x)` and immediate polynomials `I_A(x), I_B(x)`
drive the transition numerators `T, U`. With
`Z = (x^n - 1)/(x - w_last)`:

```text
C(x) = alpha0 T(x)/Z(x)
     + alpha1 U(x)/Z(x)
     + alpha2 (A(x) - a_last)/(x - w_last)
     + alpha3 (B(x) - b_last)/(x - w_last).
```

Plain composition degree is below `2n-1`, so blowup is at least 8. Masked
columns have degree `padded-1`; the `Mul` transition is quadratic, so the
prover declares

```text
degree_bound = 2 (n + n_rand - 1)
```

and the verifier accepts up to `2*padded - 2` for masked traces. Each query
reveals the current and shifted rows, so the mask budget is
`2*num_queries`. The program and output remain public; there is no control
flow or memory.

### 12.7 Recursion fragment

`recursion` proves one FRI query's fold chain as a small STARK. Public inputs:

```text
(lde_len, leaf, folds, challenges, initial quad, output).
```

Witness: the quads and fold outputs. Constraints:

| Constraint | Divisor | Quotient degree |
|---|---|---:|
| `out - fold_values(q, 1/x, c)` | `x^n - 1` | `4n - 5` |
| `out - sum_j e_j q_j(omega x)` | `(x^n - 1)/(x - w_last)` | `n - 1` |
| `q_j - initial_j` on row 0 | `x - 1` | `n - 2` |
| `e_last (out - output)` | `x^n - 1` | `n - 2` |

`MAX_FOLDS = 16`; outer `lde_len` must be a power of two `<= 2^27`, at least
4, with `2*folds <= log2(lde_len)`. The fragment does not yet verify BLAKE3
paths, the final degree check, or transcript derivation inside the AIR.

---

## 13. Zero-knowledge masking

### 13.1 Mask construction

For a column `T` of degree `< n`, choose `R` of degree `< n_rand` with
uniform coefficients and set

```text
M(x) = T(x) + Z_H(x) R(x).
```

Because `Z_H` vanishes on every base row, `M` agrees with `T` on `H`, so all
AIR quotient identities are preserved. Off-domain, the mask term is nonzero.

### 13.2 Hiding condition

The verifier sees evaluations of `M` at a set of distinct off-domain points.
The evaluations of `R` at `k` distinct points are jointly uniform if
`n_rand >= k` (Vandermonde). Therefore the mask budget is the number of
distinct values revealed per column:

| Protocol | Revealed values per column per query | Minimum `n_rand` |
|---|---|---:|
| `range`, `table` | one point | `num_queries` |
| `vm` | current and shifted rows | `2 * num_queries` |
| `air` | eight-row joint leaf plus shifted leaf | `16 * num_queries` |

The composition degree grows accordingly:

- AIR: `n + n_rand - 1`;
- range: `n + 2 n_rand - 2`;
- table: `|T| (n + n_rand - 1) - n`;
- VM: `2 (n + n_rand - 1)` for the quadratic `Mul` transition.

Callers MUST size `final_size` and FRI queries for the masked LDE.

### 13.3 Scope

This is query-response hiding, not full program privacy. Merkle roots,
commitments, public inputs, and composition values remain visible.
`lookup`, `sumcheck`, `upcs`, `gemini`, and `basefold` are not hiding.
`lookup_pcs` hides columns from the wire but candidate inputs can be tested
against its commitments.

---

## 14. Wire format

### 14.1 Version

```text
VERSION = 6
```

All proof types encode as `VERSION || body`.

### 14.2 Primitive encodings

| Type | Encoding |
|---|---|
| `u32` | 4 little-endian bytes |
| `u64` | 8 little-endian bytes |
| count | `u32`, checked against a hard limit |
| `Field` | 4 canonical little-endian bytes, `< p` |
| `Ext4` | 16 canonical bytes, four checked coordinates |
| digest | 32 bytes |
| direction | one byte, `0` or `1` only |
| path | `count || (digest || direction)*` |
| cap | `count || digest*` |

### 14.3 Hard limits

| Limit | Value |
|---|---:|
| `MAX_QUERIES` | `2^20 = 1,048,576` |
| `MAX_FOLDS` | 64 |
| `MAX_PATH_STEPS` | 128 |
| `MAX_CAP_DIGESTS` | 256 |
| `MAX_ELEMS` | `2^27 = 134,217,728` |
| `MAX_STEPS` (IVC) | `2^20 = 1,048,576` |
| FRI `MAX_FINAL_SIZE` | 1024 |
| maximum Merkle cap height | 8 |
| BaseFold `MAX_BATCH` | 1024 |
| BaseFold `MAX_VARS` | 16 |
| Gemini `MAX_VARS` | 20 |
| UPCs `MAX_POINTS` | 16 |
| VM `MAX_PROGRAM` | `2^20` |
| recursion `MAX_FOLDS` | 16 |

Counts are checked before looping. Vectors grow incrementally; the decoder
never calls `with_capacity` from an untrusted count. Trailing bytes,
truncations, non-canonical fields, and invalid direction bytes are rejected.
Decoding is shape-only; all soundness checks live in `verify`.

### 14.4 Proof bodies

- **FRI:** final polynomial, PoW nonce, queries; each query has one fold
  witness per layer with four `Ext4` values and a path.
- **AIR/range/table/vm/recursion:** column cap, FRI commitment and proof,
  openings (index, values, paths, and 64-byte leaves where applicable).
- **fold:** step count, per-step claims/cap/openings, shared FRI commitment
  and proof.
- **BaseFold:** sumcheck sum/rounds, layer roots, caps, PoW nonce, queries.
- **UPCs:** two FRI instances, quotient commitment/proof, openings.
- **Gemini:** layer commitments, values, nested UPCs openings.
- **lookup:** beta, multiplicities, quotient columns, sums, four nested
  sumcheck proofs.
- **lookup_pcs:** beta, sum, four nested sumcheck proofs, eight BaseFold
  openings.
- **sumcheck:** claimed sum, rounds, final values.

---

## 15. Parameter validation and sizing

### 15.1 Common validation

Every entry point validates:

- domains are nonempty powers of two within `2^27`;
- blowup is a power of two (`>= 4` for AIR/fold, `>= 2` for FRI/range/table,
  `>= 8` for Gemini/VM);
- queries `>= 1` and `<= 2^20`;
- `final_size >= 2`, power of two, `<= 1024`, and strictly below the LDE
  size;
- `M / final_size` is a power of four;
- cap height `<= 8`;
- grinding bits `<= 32`;
- rate gate `degree_bound + 1 <= M/2`;
- residual bound non-vacuous: `(degree_bound >> 2f) + 1 < final_size`;
- recursion outer `lde_len <= 2^27`.

### 15.2 Production sizing

`Params::for_security(len, ..., target_bits)`:

1. selects blowup 16;
2. computes `millibits_per_query` from the rate and composition degree;
3. splits the target between queries and grinding with
   `tune_strength(target, millibits)`;
4. chooses `final_size` and `cap_height` with `tune_shape`, minimizing the
   exact byte estimator.

For target 100, the AIR/FRI production shape is rate `1/16`, 40 queries,
20-bit grinding. The FRI tuner never selects a one-point final layer and
caps finals at 32 in normal tuning; the hard verifier cap is 1024.

### 15.3 Masked sizing

| Protocol | Degree bound | Mask budget |
|---|---|---:|
| AIR | `N + n_rand - 1` | `16 * num_queries` |
| Range | `N + 2 n_rand - 2` | `num_queries` |
| Table | `|T| (N + n_rand - 1) - N` | `num_queries` |
| VM | `2 (N + n_rand - 1)` | `2 * num_queries` |

Masked callers must size `final_size` for the padded LDE. The verifiers cap
declared bounds at the largest honest masked degree.

---

## 16. Security analysis

### 16.1 Assumptions

- BLAKE3-256 collision and preimage resistance;
- FRI soundness under the Johnson-radius heuristic;
- Fiat–Shamir in the (quantum) random-oracle model;
- standard Reed–Solomon list-decoding bounds.

No discrete-log, pairing, or trusted-setup assumptions. The construction is
Shor-inert by design.

### 16.2 Adversary model

The adversary controls proof bytes, commitments, public parameters, and
public statements. It may choose malformed counts, paths, caps, field
encodings, and dimensions. The verifier must fail closed, never panic, and
never allocate based on an unchecked count. The adversary may also choose
the prover's witness and strategy; soundness is argued against a malicious
prover, not only random errors.

### 16.3 Enforced invariants

1. Rate gate at prove and verify.
2. Verifier-derived domains and query indices.
3. Non-vacuous final divided-difference check.
4. Cap/path shape pins before hashing.
5. Direction bits bound to claimed indices.
6. `fri-dims` dimension binding.
7. Canonical-only decoding with hard caps.
8. PoW bound to the full history; queries sampled after grinding.
9. Committed read-checks in `lookup_pcs`.
10. Correct masked composition bounds in VM.
11. Next-row openings authenticated against the same trace cap.
12. No allocation before count limits are checked.

### 16.4 Closed findings

The internal adversarial review has closed, among others:

- Merkle path index substitution (all verifiers and hand-rolled FRI/BaseFold
  walks).
- One-point FRI final layer / vacuous degree check; fold-free FRI; final cap
  not bound to `final_poly`.
- `lookup_pcs` read-checks using uncommitted shifted MLEs.
- VM masked `Mul` degree under-declaration.
- AIR/VM ZK mask budgets undercounting revealed values.
- Batched BaseFold openings using the equality table instead of the
  multilinear basis table.
- Prover allocation ordering, cap-height/roundtrip limits, recursion domain
  bounds, checked buffer arithmetic, and transcript/grinding hardening.

Regression tests and reproducer descriptions are in
[Security tests](security-tests.md).

### 16.5 Residual risk

The system is unaudited. The query/PoW figures are conjectured. The
small-table AIR scales with table size. `lookup_pcs` is not zero-knowledge
and does not constrain columns to the base field. BaseFold, Gemini, VM, and
recursion are prototypes. Side channels in the host OS, compiler, or CPU are
out of scope. Do not deploy for high-value statements before an external
audit.

---

## 17. Evidence and reproducibility

### 17.1 Test matrix

| Suite | Tests | Evidence |
|---|---:|---|
| Library | 277 | KATs, Horner/`%` cross-checks, parallel determinism, protocol roundtrips |
| `security.rs` | 13 | 479 hostile attempts, zero accepted |
| `redteam.rs` | 10 | 37 targeted + 500 garbage, zero accepted/panics |
| `hardening.rs` | 11 | Hostile params, exhaustive per-bit AIR decoder fuzz, 14,000 mutations, zero panics |
| Doc tests | 5 | Public examples |
| **Total** | **316** | Plus coverage-guided `fuzz/decode` |

### 17.2 Benchmark methodology

`benches/speed_size.rs`, release profile, median of runs after one warm-up,
16 cores / 31 GB, `rustc 1.99.0`, measured 2026-11-05. Every row verifies its
proof outside the timed region and asserts byte counters equal
`to_bytes().len()`. The gate allows 3× timing drift and requires byte-exact
sizes.

### 17.3 Production numbers

| Workload | Prove | Verify | Proof |
|---|---:|---:|---:|
| AIR Fibonacci, 1,024 steps | 37.05 ms | 0.48 ms | 68,573 B |
| AIR Fibonacci, 8,192 steps | 49.81 ms | 0.59 ms | 101,233 B |
| AIR Fibonacci, 65,536 steps | 115.49 ms | 0.90 ms | 141,641 B |
| AIR Fibonacci, 1,048,576 steps | 1,733.55 ms | 1.13 ms | 203,553 B |
| FRI polynomial, 1,024 coefficients | 21.50 ms | 0.31 ms | 43,174 B |

The 1M-step row is 1.653 µs/step and 604,872 steps/s. Proof size grows
logarithmically; verification is size-independent in the measured range.
Full tables: [Benchmarks](benchmarks.md).

### 17.4 Gate

```sh
python3 tools/check.py
```

runs fmt, relative Markdown links, rustdoc, pedantic clippy, debug tests,
release tests, and the benchmark regression. The baseline pins all 24 rows.

---

## 18. Appendices

### 18.1 Error taxonomy

| Error | Meaning |
|---|---|
| `EmptyInput` | Empty table/vector where at least one element is required |
| `IndexOutOfBounds` | Index outside a committed domain |
| `InvalidDomainSize` | Non-power-of-two, zero, or above the domain ceiling |
| `InvalidBlowup` | Blowup below the protocol floor or not a power of two |
| `NoQueries` | Zero FRI queries |
| `BadMerklePath` | Failed path, cap, shape, or index check |
| `FriVerificationFailed` | Fold, degree, PoW, or identity failure |
| `MalformedInput` | Canonical encoding or parameter violation |
| `RngUnavailable` | OS RNG failure |

### 18.2 Public API map

| Module | Main entry points |
|---|---|
| `babybear` | `Field`, `batch_invert` |
| `ext4` | `Ext4`, `from_base`, `mul_base`, `inv` |
| `gf2` | `F8`, `F64`, `F128`, `splitmix64` |
| `hash` | `blake3_256`, `Hasher` |
| `merkle` | `MerkleTree`, `hash_leaf`, `hash_node`, `capped_shape` |
| `transcript` | `Transcript`, `challenge_*`, `grind`, `verify_grind` |
| `ntt` | `forward`, `inverse`, `interpolate`, `evaluate_on_coset`, `evaluate` |
| `fri` | `Params`, `commit`, `commit_evals`, `open`, `verify` |
| `mle` | `Mle`, `eq_evals`, `evaluate`, `fix_last` |
| `sumcheck` | `Term`, `Proof`, `prove`, `verify`, `interpolate_at` |
| `upcs` | `commit`, `open`, `open_multi`, `verify`, `verify_multi` |
| `gemini` | `commit`, `commit_evals`, `open`, `verify` |
| `basefold` | `commit`, `open`, `open_multi`, `verify`, `verify_multi` |
| `lookup` | `prove`, `verify` |
| `lookup_pcs` | `prove`, `verify`, `Commitments` |
| `air` | `Params`, `build_trace`, `prove`, `prove_zk`, `verify` |
| `range` | `Params`, `build_columns`, `prove`, `prove_zk`, `verify` |
| `table` | `Params`, `prove`, `prove_zk`, `verify` |
| `fold` | `Params`, `Accumulator`, `verify` |
| `vm` | `Params`, `Op`, `prove`, `prove_zk`, `verify` |
| `recursion` | `Params`, `prove`, `verify` |
| `blind` | `mask_coeffs`, `masked_column_degree` |
| `rng` | `ChaCha20`, `os_seed`, `fresh_stream` |
| `codec` | internal canonical reader/writer (`VERSION = 6`) |

### 18.3 Parameter quick reference

| Constructor | Key validation |
|---|---|
| `fri::Params::new(blowup, queries, final)` | blowup `>=2`, queries `>=1`, final `2..=1024` |
| `air::Params::new(N, blowup, Q, F, a0,b0,b_last)` | `N` power of two `>=2`, blowup `>=4`, `M<=2^27` |
| `range::Params::new(rows, bits, blowup, Q, F, value)` | bits `1..=24`, blowup `>=2` |
| `table::Params::new(rows, blowup, Q, F, value)` | table checked at prove/verify, blowup `>=2` |
| `fold::Params::new(seg, blowup, Q, F, in_a,in_b,out_b)` | seg `>=2`, blowup `>=4` |
| `vm::Params::new(N, blowup, Q, F, program, a_last,b_last)` | blowup `>=8`, program `<= N-1` |
| `recursion::Params::new(lde, leaf, folds, challenges, initial, output, blowup, Q, F)` | folds `1..=16`, outer lde `<=2^27` |
| `basefold::Params::new(blowup, Q, G)` | blowup `>=2`, cap `<=8`, vars `<=16` |
| `gemini::Params::new(blowup, Q, G)` | blowup `>=8`, vars `<=20` |
| `upcs` | points `<=16`, blowup `>=2`, lde `<=2^27` |

### 18.4 Glossary

| Term | Meaning |
|---|---|
| AIR | Algebraic Intermediate Representation |
| FRI | Fast Reed–Solomon IOP of Proximity |
| LDE | Low-degree extension |
| MLE | Multilinear extension |
| PCS | Polynomial commitment scheme |
| PoW | Proof of work / Fiat–Shamir grinding |
| STARK | Scalable Transparent Argument of Knowledge |
| UPCs | Univariate polynomial commitment scheme |
| ZK | Zero knowledge |

### 18.5 Reproducibility checklist

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

The formal specification, white paper, benchmark table, security results,
red-team results, and unit-test breakdown are linked from
[AUDIT.md](../AUDIT.md).

---

**License.** GPL-3.0-only. See [LICENSE](../LICENSE).

**Security reporting.** Follow [SECURITY.md](../SECURITY.md); email
**futureproofs@proton.me**. Do not open a public issue for suspected
soundness, zero-knowledge, or memory-safety bugs.
