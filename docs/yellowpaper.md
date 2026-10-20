# z0p — Yellow Paper (formal specification)

*The exact mathematics, protocols, encodings, and parameters implemented
by the z0p crate. Normative where stated; conjectured bit-levels are
marked as such.*

Version 1.0 — 2026-09-26. Code references are to `src/` modules.
High-level companion: the [White Paper](whitepaper.md).

---

## 1. Notation and fields

### 1.1 BabyBear prime field $\mathbb{F}_p$

$$p = 2^{31} - 2^{27} + 1 = 2013265921, \qquad g = 31.$$

$p - 1 = 2^{27} \cdot 15$: multiplicative subgroups of order $2^k$ exist
for $k \le 27$. `two_adic_generator(bits)` returns
$g^{(p-1)/2^{\mathrm{bits}}}$; `primitive_root(m)` the primitive $m$-th
root of unity for $m = 2^k \le 2^{27}$. Elements serialize as 4
little-endian bytes, canonical ($< p$); the decoder rejects $\ge p$.

Multiplication uses Barrett reduction with $\mu = \lfloor 2^{64}/p
\rfloor$; inversion is Fermat ($a^{p-2}$, mapping $0 \mapsto 0$);
batch inversion is Montgomery's trick. All operation counts are
input-independent for fixed parameters.

**Quartic extension field.** All algebraic challenges use
$\mathbb{F}_{p^4} = \mathbb{F}_{p^2}[v]/(v^2-u)$ with
$\mathbb{F}_{p^2} = \mathbb{F}_p[u]/(u^2-11)$, represented as
$a + bu + cv + duv$ (four canonical field coordinates, 16 bytes).
Inversion uses the tower norm: for $x = c + dv$,
$x^{-1} = (c - dv)/(c^2 - ud^2)$, so one $\mathbb{F}_{p^2}$ inversion
suffices; multiplication is the tower formula. `11` is a quadratic
non-residue and `u` is a non-square in $\mathbb{F}_{p^2}$.

### 1.2 Binary fields

$GF(2^8)$, $GF(2^{64})$, $GF(2^{128})$ hold program words (XOR addition,
carryless multiplication). They carry transcript challenges and digest
parsing; polynomial domains always use $\mathbb{F}_p$.

### 1.3 Domains

- Base trace domain $H = \{1, \omega, \dots, \omega^{N-1}\}$,
  $\omega = $ `primitive_root(N)`, $N$ a power of two, $N \ge 2$.
- Evaluation (LDE) domain $D = \gamma \cdot \langle \Omega \rangle$,
  $|\,D\,| = M = N \cdot \beta$ ($\beta$ = blowup, power of two),
  $\Omega = $ `primitive_root(M)`, coset shift $\gamma = g$
  (`LDE_SHIFT`, equal to the field generator $31$).
- $M \le 2^{27}$ is enforced at every entry point.
- Vanishing polynomial of $H$: $Z_H(x) = x^N - 1$.

## 2. Hash function and transcripts

### 2.1 BLAKE3-256

Unkeyed BLAKE3, 256-bit output, implemented from the specification:
7-round ARX compression on a 16-word state, message permutation
$[2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8]$, flags `CHUNK_START = 1`,
`CHUNK_END = 2`, `PARENT = 4`, `ROOT = 8`, 1024-byte chunks, Bao-style
merge-while-even stacking. Validated against reference vectors
(empty, `abc`, and multi-chunk inputs crossing chunk boundaries).

### 2.2 Merkle trees

Binary trees, leaves padded by duplicating the last leaf to a power of
two. Domain separation (second-preimage resistance):

$$\mathrm{leaf}(d) = H(0x00 \,\|\, d), \qquad
  \mathrm{node}(l, r) = H(0x01 \,\|\, l \,\|\, r).$$

**Caps.** `cap(dropped)` exposes the layer at depth
$\mathrm{depth} - \mathrm{dropped}$ ($2^{\mathrm{dropped}}$ digests) in
the commitment; openings then carry only the middle path segment.
Column trees drop $\min(h, \mathrm{depth})$; FRI quad layers drop
$\min(h, \mathrm{depth}-2)$ (the verifier rebuilds the bottom two
levels from the four revealed values).

### 2.3 Fiat–Shamir transcript

Append-only, length-prefix-framed absorbs; each squeeze hashes
$\mathrm{log} \,\|\, \mathrm{label} \,\|\, \mathrm{counter}$ and feeds
the output back into the log. $\mathbb{F}_p$ challenges reduce a
64-bit word mod $p$ (bias $< 2^{-31}$, documented); query indices mask
low bits for power-of-two domains (unbiased).

**Label schedule (both sides must match exactly):**

| Protocol | Labels (in order) |
|---|---|
| FRI | `fri-dims` (dimensions first), `fri-layer-root` per cap digest, `fri-fold` ×3 per layer, `fri-final`, `fri-pow` (nonce), `fri-query` per query |
| AIR / range / table | `<proto>/params` (all parameters first), `<proto>/column` (column cap), `<proto>/alpha` (one squeeze per constraint class, fixed count) |
| fold (IVC) | `fold/params`, then per step `fold/step`, `fold/trace`, six `fold/alpha`, finally one `fold/gamma` per step |
| lookup | `lookup/ctx` separators (`sum-w`/`read-w`/`sum-t`/`read-t`), `witness`, `table`, `sums`, `qw`, `qt`, `m`, `beta`, `beta-challenge`, `r1`, `r2` |
| sumcheck | `sumcheck/claim`, then per round `sumcheck/round`, `sumcheck/challenge` |

**Proof of work.** `grind(label, d)` returns the smallest $u64$ nonce
with $\ge d$ leading zero bits under the history commitment (banded
parallel search, bit-identical to sequential scan); `verify_grind`
re-checks and absorbs on success only. Difficulties $> 256$ always fail.

## 3. FRI polynomial commitment

### 3.1 Encoding

`commit` maps $n$ coefficients to $M = n\beta$ coset evaluations
(shifted NTT); `commit_evals` takes caller-supplied LDE values of
declared degree $\le \mathrm{bound} < M$. Both reject vacuous bounds
($\mathrm{bound} \ge M$) and enforce the **rate gate**
$\mathrm{bound} + 1 \le M/2$ at prove *and* verify time.

### 3.2 Folding (arity 4)

Layers are bit-reversed. Each quad of adjacent values sits at
$(x, -x, j_0 x, -j_0 x)$ for the fixed fourth root
$j_0 = $ `two_adic_generator(2)`, sharing $x^4$. With
$P(X) = A + BX + CX^2 + DX^3$ in $Y = X^4$:

$$\mathrm{fold}(e_0,e_1,e_2,e_3) = A + r_0 B + r_1 C + r_2 D,$$

solved as: $A$ = mean; $B = ((e_0-e_1) - j_0(e_2-e_3))/4 \cdot x^{-1}$;
$C = ((e_0+e_1)-(e_2+e_3))/4 \cdot x^{-2}$;
$D = ((e_0-e_1) + j_0(e_2-e_3))/4 \cdot x^{-3}$,
with $(r_0, r_1, r_2) \in \mathbb{F}_{p^4}$ the layer's `fri-fold`
challenges, values in $\mathbb{F}_{p^4}$ (base values embed in the first
coordinate), and point inverses (base field) batch-inverted once per
layer. Each fold quarters the degree.

### 3.3 Proof and verification

`Proof { final_poly, queries, pow_nonce }`, where each query opens all
four $\mathbb{F}_{p^4}$ values (16 bytes each) of every folded quad plus
the middle Merkle path segment; leaves hash the canonical 16-byte
encoding.
The verifier:

1. checks dimensions, the rate gate, cap shapes ($2^{\mathrm{drop}}$
   digests per layer), and fold-count consistency
   ($M / 4^f = \mathrm{final\_size}$);
2. replays absorbs/challenges, checks the PoW gate;
3. checks the final layer by divided differences against residual bound
   $\mathrm{bound} \gg 2f$ at the true folded domain points;
4. checks every Merkle path (rebuilding quad nodes from values) and
   every fold relation, chaining intermediate parents into the next
   layer's revealed quad, the last into `final_poly`.

Query indices are verifier-recomputed (`fri-query` squeezes) and never
stored.

### 3.4 Conjectured soundness (normative for parameter choice)

Johnson-radius heuristic ($\delta \approx 1 - \sqrt{\rho}$ per-query
survival $\le 1 - \delta$):

- Bench shape ($\beta = 8$, $\rho = 1/8$, 12 queries, no grinding):
  $\delta \approx 0.65$, ~1.5 bits/query, **~18 bits** total.
- Production shape ($\beta = 16$, $\rho = 1/16$, 40 queries, 20-bit
  grinding): $\delta \approx 0.75$, ~2 bits/query, a **100-bit
  query/PoW schedule** (80 + 20). `tune_strength` caps grinding at 20
  bits (half the target when smaller); `tune_shape` picks finals
  $\le 32$ and caps $0..=4$ minimizing the exact byte estimator. Merkle
  caps are size-only and do not affect bit-levels.

**Challenge fields.** This heuristic counts query sampling and grinding
only. FRI folds, STARK composition batches, `upcs`/`gemini` evaluation
points and fold betas, `sumcheck` rounds, and lookup's rational-identity
challenge use the quartic extension field $\mathbb{F}_{p^4}$ (tower
$\mathbb{F}_p[u]/(u^2-11)$, then $\mathbb{F}_{p^2}[v]/(v^2-u)$), so a
degree-$d$ identity collides with probability about $d/p^4$ per
challenge. The former $\approx 31$-bit algebraic ceiling is gone. The
production schedule remains a query/PoW formula, not an end-to-end
soundness proof.

## 4. AIR systems

All four protocols share one pattern: interpolate columns, extend on
the LDE coset, Merkle-commit the joint rows, evaluate the composition
vector (geometric vanishing recurrence + Montgomery-batched
denominators, bit-identical to scalar evaluation), FRI-commit it with
`commit_evals`, open trace columns at the FRI query positions, and
re-verify the composition identity per query.

### 4.1 Fibonacci AIR (`air`)

Trace $A[0] = a_0$, $B[0] = b_0$, $A[i+1] = B[i]$,
$B[i+1] = A[i] + B[i]$, claim $B[N-1] = b_{\mathrm{last}}$.
With $w_{\mathrm{last}} = \omega^{N-1}$ and
$Z_{\mathrm{trans}}(x) = (x^N - 1)/(x - w_{\mathrm{last}})$ (zero exactly
on rows $0..N-2$), at point $x$ with values $(a, b)$ and next-row
$(a', b')$:

$$C(x) = \alpha_0\frac{a' - b}{Z_{\mathrm{trans}}(x)}
       + \alpha_1\frac{b' - (a + b)}{Z_{\mathrm{trans}}(x)}
       + \alpha_2\frac{a - a_0}{x - 1}
       + \alpha_3\frac{b - b_0}{x - 1}
       + \alpha_4\frac{b - b_{\mathrm{last}}}{x - w_{\mathrm{last}}}.$$

Five `fib/alpha`-class challenges; $\deg C < N$ iff the trace is valid
(dividing — not multiplying — by $Z_{\mathrm{trans}}$ is load-bearing:
see the `bad_trace` regression test). Blowup $\ge 4$ keeps the rate
$< 1/2$.

### 4.2 Range check (`range`)

Value column $V$ plus $n$ bit columns ($1 \le n \le 24$), $n_{\mathrm{rows}}$
rows. With challenges $\alpha_{\mathrm{decomp}}$,
$\{\alpha_j\}$, $\alpha_{\mathrm{bound}}$:

$$C = \alpha_{\mathrm{decomp}}\frac{V - \sum_j 2^j C_j}{Z_H}
    + \sum_j \alpha_j\frac{C_j(C_j - 1)}{Z_H}
    + \alpha_{\mathrm{bound}}\frac{V - v}{Z_{\mathrm{row0}}}.$$

### 4.3 Table membership (`table`)

Constant column $v$ against public table $T$:

$$C(x) = \alpha_{\mathrm{member}}\frac{\prod_{t \in T}(v - t)}{Z_H(x)}
       + \alpha_{\mathrm{bound}}\frac{v - \mathrm{value}}{x - 1}.$$

Declared bound $|T|\cdot(n + k - 1)$-style via `membership_bound`
($n$ rows, $k$ maskers). Small tables by design; cost scales with $|T|$.

### 4.4 Folding / IVC (`fold`)

$S$-step Fibonacci segments chained ($out$ of step $s$ = $in$ of step
$s+1$, enforced at accumulation). Per-step AIR compositions $C_s$ share
one batched FRI commitment over the random combination
$\sum_s \gamma_s C_s$ ($\gamma_s$ = per-step `fold/gamma` challenge).
One proof covers the whole chain.

### 4.5 LogUp lookups (`lookup`)

Witness $w$ ($|w|$ a power of two after padding) against table $t$:
multiplicities $m$ (first-index matching; prove fails closed on
no-match), $\beta$ challenge, quotients
$q^w_i = 1/(\beta + w_i)$, $q^t_j = m_j/(\beta + t_j)$, rational-sum
equality plus four sumchecks (two sums, two read-checks at random
evaluation points).

### 4.6 Zero knowledge

`prove_zk` blinds columns with vanishing-multiple masks from a ChaCha20
(RFC 8439) stream ($n_{\mathrm{rand}} \ge$ queries enforced), raising
the composition degree (callers size finals accordingly). Query openings
become uniform and witness-independent; verification is identical, and
masked false statements still fail.

### 4.7 Multilinear commitments (`gemini`, `basefold` prototype)

For monomial coefficients $c_b$ of a multilinear polynomial $f$, both
constructions commit the coefficient encoding
$g_0(X)=\sum_b c_b X^{\mathrm{index}(b)}$ with a Merkle-committed
Reed--Solomon LDE.

`gemini` folds one variable at a time,
$g_{i-1}(X)=A_i(X^2)+X B_i(X^2)$, opens each committed layer once with a
multi-point `upcs` proof, and checks
$g_i(\beta^2)=A_i(\beta^2)+r_i B_i(\beta^2)$ at a fresh $\beta$.
The proof has one root plus $n-1$ layer commitments and $n$ opening
proofs, so it is linear-size.

The experimental `basefold` prototype replaces the per-layer openings
with sumcheck and one FRI instance. Let
$w_b=\prod_i r_i^{b_i}$ and
$w(X)=\prod_i (1+(r_i-1)X_i)$. Sumcheck proves
$\sum_b c_b w_b=f(r)$ and outputs $c(\rho)$ for a challenge
$\rho\in\mathbb{F}_{p^4}^n$, where $c(\cdot)$ is the multilinear
extension of the coefficient table. The prover folds the LDE with the
Möbius/eq rule
$(1-\rho_i)E(X)+\rho_i O(X)$ rather than the coefficient-encoding rule
$E(X)+\rho_i O(X)$, so the final FRI constant is exactly $c(\rho)$.
The verifier recomputes
$w(\rho)=\prod_i(1-\rho_i+\rho_i r_i)$ and checks
$f(r)=c(\rho)w(\rho)$. The proof contains one root, $n-1$ layer roots,
$3n$ extension-field sumcheck evaluations, and $Q$ queries with one pair
and one Merkle path per layer per query; paths make the prototype
$O(Qn^2)$ bytes, not $O(n)$.

At 1,024 coefficients with blowup 16, 40 queries, and 20-bit grinding,
the prototype proves in about 56 ms, verifies in 1.1 ms, and carries
127,654 bytes; Gemini on the same shape takes 604 ms / 55 ms and carries
888,672 bytes. The prototype is not wired into the AIR/STARK stack, has
no Merkle caps or hiding, and has no end-to-end soundness proof; it must
not be treated as production-ready.

## 5. Encodings (normative wire format, `VERSION = 3`)

```
proof      := VERSION || body
u32/u64    := little-endian, counts as u32
field      := 4 canonical LE bytes (< p, else MalformedInput)
ext4       := 16 canonical LE bytes (four field coordinates)
digest     := 32 bytes
direction  := 0 | 1 (else MalformedInput)
path       := count || (digest || direction)*
cap        := count || digest*
commitment := VERSION || lde_len u64 || poly_len u64
              || degree_bound u64 || caps
```

Hard decoder limits (fail before allocation, vectors grow
incrementally): `MAX_QUERIES = 2^20`, `MAX_FOLDS = 64`,
`MAX_PATH_STEPS = 128`, `MAX_CAP_DIGESTS = 256`,
`MAX_ELEMS = 2^27`, `MAX_STEPS = 2^20`. Trailing bytes rejected.
Decoding is shape-only; all soundness checks live in `verify`.

## 6. Parameters (normative validation)

- $N$ (steps/rows/poly length): power of two, $\ge 2$ (FRI coeff path:
  non-empty power of two).
- Blowup: power of two, $\ge 2$ (AIR/fold: $\ge 4$).
- Queries $\ge 1$; final size a power of two with $M/\mathrm{final}$
  a power of four (quartering lands exactly); finals tuned $\le 32$.
- $M = N\cdot\mathrm{blowup} \le 2^{27}$; caps $0..=4$ (tuned).
- `for_security(len, …, target)`: blowup 16, strength split by
  `tune_strength`, shape by `tune_shape`. Masked callers size manually.

## 7. Security analysis

**Assumptions.** BLAKE3 collision/preimage resistance; FRI soundness
under the Johnson-radius heuristic; Fiat–Shamir in the (Q)ROM. No
discrete-log, pairing, or trusted-setup assumptions — Shor-inert by
construction.

**Enforced invariants.** Rate gate both sides; verifier-derived domains
and query indices; final divided-difference check at true folded points;
cap/path shape pins before hashing; `fri-dims` dimension binding
(closes proof malleability of echoed dimensions); canonical-only
decoding; PoW bound to history with queries sampled after.

**Validation.** 240 unit tests (KATs, cross-checks against Horner/`%`,
parallel-vs-sequential identity), 13-test security suite and 10-test
red-team suite (~800 hostile attempts/run, zero acceptances, zero
panics), wire-exact size assertions on every benchmark, and a
`tools/check.py` gate (fmt, pedantic clippy, debug+release tests, bench
regression vs `tools/baseline.json`).

**Out of scope / stated limits.** Bench shapes (~18 bits) are not
production soundness; large-table lookups still await a production
compact multilinear PCS. Vectorized hashing, the one-query recursion
fragment, FRI-backed univariate point and multi-point openings, a
Gemini-style multilinear PCS (`O(n)` openings, one batched opening per
layer), and a compact BaseFold-style prototype (one root, sumcheck plus
Möbius FRI folds) are done. The BaseFold module is experimental and not
wired into AIR/STARK; Merkle caps/WHIR batching, self-proving recursion,
and a zkVM are roadmap items. No external audit has yet been performed.

## 8. License

GPLv3 only — see [LICENSE](../LICENSE).
