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
| fold (IVC) | `fold/params`, then per step `fold/step`, `fold/trace`, five `fold/alpha`, finally one `fold/gamma` per step |
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
with $(r_0, r_1, r_2)$ the layer's `fri-fold` challenges and point
inverses batch-inverted once per layer. Each fold quarters the degree.

### 3.3 Proof and verification

`Proof { final_poly, queries, pow_nonce }`, where each query opens all
four values of every folded quad plus the middle Merkle path segment.
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
  grinding): $\delta \approx 0.75$, ~2 bits/query, **80 + 20 = 100
  bits** total. `tune_strength` caps grinding at 20 bits (half the
  target when smaller); `tune_shape` picks finals $\le 32$ and caps
  $0..=4$ minimizing the exact byte estimator. Merkle caps are
  size-only and do not affect bit-levels.

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

## 5. Encodings (normative wire format, `VERSION = 1`)

```
proof      := VERSION || body
u32/u64    := little-endian, counts as u32
field      := 4 canonical LE bytes (< p, else MalformedInput)
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

**Validation.** 155 unit tests (KATs, cross-checks against Horner/`%`,
parallel-vs-sequential identity), 13-test security suite and 10-test
red-team suite (~800 hostile attempts/run, zero acceptances, zero
panics), wire-exact size assertions on every benchmark, and a
`tools/check.py` gate (fmt, pedantic clippy, debug+release tests, bench
regression vs `tools/baseline.json`).

**Out of scope / stated limits.** Bench shapes (~18 bits) are not
production soundness; large-table lookups await a multilinear PCS;
vectorized hashing, recursion, and a zkVM are roadmap items; no
external audit has yet been performed.

## 8. License

GPLv3 only — see [LICENSE](../LICENSE).
