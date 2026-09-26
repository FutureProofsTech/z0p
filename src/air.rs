//! Minimal AIR/STARK: proves an `N`-step Fibonacci trace.
//!
//! Trace columns `A`, `B` with `A[0] = a0`, `B[0] = b0`,
//! `A[i+1] = B[i]`, `B[i+1] = A[i] + B[i]`, and output claim
//! `B[N-1] = b_last`. Columns (plus next-row columns) are interpolated,
//! extended on the [`LDE_SHIFT`](crate::fri::LDE_SHIFT) coset, and Merkle
//! committed; transition quotients (divided by the transition vanishing
//! polynomial) and boundary quotients are combined with five Fiat-Shamir
//! challenges into a composition polynomial of degree `< N`, committed with
//! [`crate::fri::commit_evals`].
//!
//! Verification replays the transcript, checks [`crate::fri`] (including its
//! final low-degree check, which is what rejects false traces), opens the
//! trace columns at the FRI query positions, and re-evaluates the composition
//! identity. [`prove`] leaks trace values at query positions; [`prove_zk`]
//! blinds the columns first for perfect hiding of query responses.

use crate::babybear::Field;
use crate::error::{Error, Result};
use crate::fri::{self, Commitment as FriCommitment, Proof as FriProof};
use crate::merkle::MerkleTree;
use crate::ntt::{evaluate_on_coset, interpolate};
use crate::transcript::Transcript;

/// AIR parameters: domain sizes plus the public input/output claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// Trace length: power of two, `>= 2`.
    pub n_steps: usize,
    /// Trace LDE blowup: power of two, `>= 4` (composition rate `< 1/2`).
    pub blowup: usize,
    /// FRI query count (`>= 1`).
    pub num_queries: usize,
    /// FRI final layer size (power of two, `>= 1`).
    pub final_size: usize,
    /// Proof-of-work difficulty in leading-zero bits (`0` disables grinding).
    ///
    /// Threaded into FRI and bound under `"fib/params"`.
    pub grinding_bits: u32,
    /// Merkle cap height for the column tree and FRI layers (`0` = roots).
    ///
    /// Threaded into FRI and bound under `"fib/params"`.
    pub cap_height: usize,
    /// First column claims.
    pub a0: Field,
    /// Second column claims.
    pub b0: Field,
    /// Output claim `B[N-1]`.
    pub b_last: Field,
}

impl Params {
    /// Validate parameters.
    ///
    /// # Errors
    /// Returns [`Error`] for non-power-of-two sizes, tiny domains, or an LDE
    /// exceeding `2^27`.
    pub const fn new(
        n_steps: usize,
        blowup: usize,
        num_queries: usize,
        final_size: usize,
        a0: Field,
        b0: Field,
        b_last: Field,
    ) -> Result<Self> {
        if n_steps < 2 || !n_steps.is_power_of_two() {
            return Err(Error::InvalidDomainSize { size: n_steps });
        }
        if blowup < 4 || !blowup.is_power_of_two() {
            return Err(Error::InvalidBlowup { factor: blowup });
        }
        if num_queries == 0 {
            return Err(Error::NoQueries);
        }
        if final_size == 0 || !final_size.is_power_of_two() {
            return Err(Error::InvalidDomainSize { size: final_size });
        }
        // `n_steps * blowup` overflow is impossible for validated sizes, but
        // check the two-adicity ceiling explicitly.
        let lde = n_steps * blowup;
        if lde / blowup != n_steps || lde > (1usize << Field::TWO_ADICITY) {
            return Err(Error::InvalidDomainSize { size: lde });
        }
        Ok(Self {
            n_steps,
            blowup,
            num_queries,
            final_size,
            grinding_bits: 0,
            cap_height: 0,
            a0,
            b0,
            b_last,
        })
    }

    /// Set the proof-of-work difficulty (builder; default `0` = disabled).
    #[must_use]
    pub const fn with_grinding_bits(mut self, bits: u32) -> Self {
        self.grinding_bits = bits;
        self
    }

    /// Set the Merkle cap height (builder; default `0` = roots only).
    #[must_use]
    pub const fn with_cap_height(mut self, height: usize) -> Self {
        self.cap_height = height;
        self
    }

    /// Production parameters for plain (non-masked) traces: blowup 16,
    /// strength sized for `target_bits` conjectured soundness bits, and
    /// size-optimal final size and cap height.
    ///
    /// Masked ([`prove_zk`](crate::air::prove_zk)) callers size manually:
    /// masking raises the composition degree, which this constructor
    /// cannot see.
    ///
    /// # Errors
    /// Same domain errors as [`Params::new`].
    pub fn for_security(
        n_steps: usize,
        a0: Field,
        b0: Field,
        b_last: Field,
        target_bits: u32,
    ) -> Result<Self> {
        if n_steps < 2 || !n_steps.is_power_of_two() {
            return Err(Error::InvalidDomainSize { size: n_steps });
        }
        let blowup = 16;
        let lde_len = n_steps
            .checked_mul(blowup)
            .ok_or(Error::InvalidDomainSize { size: n_steps })?;
        if lde_len > (1usize << Field::TWO_ADICITY) {
            return Err(Error::InvalidDomainSize { size: lde_len });
        }
        let millibits = crate::fri::composition_millibits(lde_len, n_steps - 1);
        let (num_queries, grinding_bits) = crate::fri::tune_strength(target_bits, millibits);
        // Column openings carry 8 index bytes plus 16 field bytes each.
        let (final_size, cap_height) =
            crate::fri::tune_shape(lde_len, num_queries, &[(lde_len, 24)]);
        Ok(Self {
            n_steps,
            blowup,
            num_queries,
            final_size,
            grinding_bits,
            cap_height,
            a0,
            b0,
            b_last,
        })
    }

    /// Length of the LDE domain.
    #[must_use]
    pub const fn lde_len(&self) -> usize {
        self.n_steps * self.blowup
    }

    fn fri_params(&self) -> Result<fri::Params> {
        Ok(
            fri::Params::new(self.blowup, self.num_queries, self.final_size)?
                .with_grinding_bits(self.grinding_bits)
                .with_cap_height(self.cap_height),
        )
    }
}

/// One trace opening at an LDE position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceOpening {
    /// Natural-order LDE index.
    pub index: usize,
    /// Column values at `index`.
    pub a: Field,
    /// Column values at `index`.
    pub b: Field,
    /// Next-row columns at `index`.
    pub a_next: Field,
    /// Next-row columns at `index`.
    pub b_next: Field,
    /// Merkle path of the joint row leaf (`A || B || A_next || B_next`).
    pub path: Vec<([u8; 32], bool)>,
}

/// AIR proof: trace roots, FRI commitment/proof, trace openings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// Merkle cap of the joint row LDE (`2^cap_height` digests; one root
    /// when caps are disabled).
    pub column_cap: Vec<[u8; 32]>,
    /// FRI commitment to the composition polynomial.
    pub fri_commitment: FriCommitment,
    /// FRI opening proof.
    pub fri_proof: FriProof,
    /// Trace openings, one per FRI query, in query order.
    pub openings: Vec<TraceOpening>,
}

impl Proof {
    /// Canonical bytes: version, column cap, FRI commitment/proof, then
    /// openings (index, four fields, path each).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = crate::codec::Writer::new();
        writer.byte(crate::codec::VERSION);
        writer.cap(&self.column_cap);
        self.fri_commitment.write_body(&mut writer);
        self.fri_proof.write_body(&mut writer);
        writer.count(self.openings.len());
        for opening in &self.openings {
            writer.u64_le(opening.index as u64);
            writer.field(opening.a);
            writer.field(opening.b);
            writer.field(opening.a_next);
            writer.field(opening.b_next);
            writer.path(&opening.path);
        }
        writer.finish()
    }

    /// Decode [`Proof::to_bytes`] output, rejecting anything else.
    ///
    /// Shape-checked only; soundness checks happen in [`verify`].
    ///
    /// # Errors
    /// Returns [`Error::MalformedInput`] on any encoding violation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        use crate::codec::MAX_QUERIES;
        let mut reader = crate::codec::Reader::new(bytes);
        reader.version()?;
        let column_cap = reader.cap()?;
        let fri_commitment = fri::Commitment::read_body(&mut reader)?;
        let fri_proof = fri::Proof::read_body(&mut reader)?;
        let mut openings = Vec::new();
        for _ in 0..reader.count(MAX_QUERIES)? {
            openings.push(TraceOpening {
                index: reader.dimension()?,
                a: reader.field()?,
                b: reader.field()?,
                a_next: reader.field()?,
                b_next: reader.field()?,
                path: reader.path()?,
            });
        }
        reader.end()?;
        Ok(Self {
            column_cap,
            fri_commitment,
            fri_proof,
            openings,
        })
    }
}

/// Build the Fibonacci trace columns from the input claims.
#[must_use]
pub fn build_trace(a0: Field, b0: Field, n_steps: usize) -> (Vec<Field>, Vec<Field>) {
    let mut a = vec![Field::ZERO; n_steps];
    let mut b = vec![Field::ZERO; n_steps];
    a[0] = a0;
    b[0] = b0;
    for i in 0..n_steps - 1 {
        a[i + 1] = b[i];
        b[i + 1] = a[i] + b[i];
    }
    (a, b)
}

/// Prove the Fibonacci claim in `params`.
///
/// The trace is deterministic from `(a0, b0)`; proving succeeds structurally
/// for any claims, but [`verify`] accepts only traces satisfying the output
/// claim (a false `b_last` yields a high-degree composition quotient that
/// FRI's final check rejects).
///
/// # Errors
/// Returns [`Error`] for domain or Merkle failures (all structural).
pub fn prove(params: Params, transcript: &mut Transcript) -> Result<Proof> {
    let (col_a, col_b) = build_trace(params.a0, params.b0, params.n_steps);
    prove_with_trace(params, &col_a, &col_b, transcript)
}

/// Prove with explicit trace columns (expert API).
///
/// Columns must have length `params.n_steps`. Unlike [`prove`], the columns
/// need not satisfy the transition relation; proving still succeeds
/// structurally, but [`verify`] rejects invalid traces through FRI's final
/// low-degree check. Used to test soundness end to end.
///
/// # Errors
/// Returns [`Error::MalformedInput`] on column-length mismatch, otherwise the
/// structural errors of [`prove`].
pub fn prove_with_trace(
    params: Params,
    col_a: &[Field],
    col_b: &[Field],
    transcript: &mut Transcript,
) -> Result<Proof> {
    let n = params.n_steps;
    if col_a.len() != n || col_b.len() != n {
        return Err(Error::MalformedInput {
            reason: "trace columns must match n_steps",
        });
    }
    let coeff_a = interpolate(col_a)?;
    let coeff_b = interpolate(col_b)?;
    prove_from_coeffs(params, &coeff_a, &coeff_b, n - 1, transcript)
}

/// Prove zero-knowledge: identical to [`prove`] except both trace columns
/// are masked with [`crate::blind::mask_coeffs`] (`n_rand` maskers each),
/// so query openings are jointly uniform and independent of the witness
/// (perfect hiding of responses; see [`crate::blind`]). Verification is the
/// same [`verify`]: masking preserves every base-row value, hence every
/// quotient identity.
///
/// Requires `n_rand >= num_queries`; the composition bound grows to
/// `n_steps + n_rand - 1` (still rate `< 1`).
///
/// # Errors
/// Returns [`Error::MalformedInput`] when `n_rand < num_queries`, otherwise
/// the structural errors of [`prove`].
pub fn prove_zk(
    params: Params,
    n_rand: usize,
    rng: &mut crate::rng::ChaCha20,
    transcript: &mut Transcript,
) -> Result<Proof> {
    if n_rand < params.num_queries {
        return Err(Error::MalformedInput {
            reason: "n_rand must cover num_queries for hiding",
        });
    }
    let n = params.n_steps;
    let (col_a, col_b) = build_trace(params.a0, params.b0, n);
    let coeff_a = interpolate(&col_a)?;
    let coeff_b = interpolate(&col_b)?;
    let masked_a = crate::blind::mask_coeffs(&coeff_a, n, n_rand, rng)?;
    let masked_b = crate::blind::mask_coeffs(&coeff_b, n, n_rand, rng)?;
    prove_from_coeffs(params, &masked_a, &masked_b, n + n_rand - 1, transcript)
}

/// Shared prover body over base coefficient vectors of any power-of-two
/// length (plain `n` or masked padded length).
fn prove_from_coeffs(
    params: Params,
    coeff_a: &[Field],
    coeff_b: &[Field],
    degree_bound: usize,
    transcript: &mut Transcript,
) -> Result<Proof> {
    let n = params.n_steps;
    absorb_params(params, transcript);

    let omega_base = Field::primitive_root(n)?;
    let coeff_cols = [coeff_a.to_vec(), coeff_b.to_vec()];
    let coeff_next = [
        shift_coeffs(&coeff_cols[0], omega_base),
        shift_coeffs(&coeff_cols[1], omega_base),
    ];

    let lde_cols = [
        evaluate_on_coset(&coeff_cols[0], params.blowup, crate::fri::LDE_SHIFT)?,
        evaluate_on_coset(&coeff_cols[1], params.blowup, crate::fri::LDE_SHIFT)?,
    ];
    let lde_next = [
        evaluate_on_coset(&coeff_next[0], params.blowup, crate::fri::LDE_SHIFT)?,
        evaluate_on_coset(&coeff_next[1], params.blowup, crate::fri::LDE_SHIFT)?,
    ];
    let all_lde = [&lde_cols[0], &lde_cols[1], &lde_next[0], &lde_next[1]];
    let m = lde_cols[0].len();
    // One joint tree over interleaved rows: a single path opens every
    // column at a position instead of four parallel paths. Rows pack flat
    // (one allocation) into `from_flat`.
    let row_len = 4 * all_lde.len();
    let mut flat = vec![0u8; m * row_len];
    for (i, chunk) in flat.chunks_exact_mut(row_len).enumerate() {
        for (lde, slot) in all_lde.iter().zip(chunk.chunks_exact_mut(4)) {
            slot.copy_from_slice(&lde[i].to_le_bytes());
        }
    }
    let tree = MerkleTree::from_flat(&flat, row_len)?;
    let (drop, _) = crate::merkle::capped_shape(m, params.cap_height);
    let column_cap = tree.cap(drop);
    transcript.absorb(b"fib/trace", &crate::merkle::cap_bytes(&column_cap));

    let alphas = [
        transcript.challenge_bb(b"fib/alpha"),
        transcript.challenge_bb(b"fib/alpha"),
        transcript.challenge_bb(b"fib/alpha"),
        transcript.challenge_bb(b"fib/alpha"),
        transcript.challenge_bb(b"fib/alpha"),
    ];

    let points = lde_points(m)?;
    let w_last = omega_base.pow((n - 1) as u64);
    let composition = compose(
        &lde_cols,
        &lde_next,
        &points,
        w_last,
        params.a0,
        params.b0,
        params.b_last,
        n,
        &alphas,
    );

    // Declared degree bound comes from the caller: `< N` plain, higher
    // with masking (rate stays `< 1` either way).
    let fri_params = params.fri_params()?;
    let fri_state = fri::commit_evals(&composition, degree_bound, fri_params, transcript)?;
    let fri_commitment = fri::public_commitment(&fri_state);
    let (fri_proof, fri_indices) = fri::open(&fri_state, transcript)?;

    let log_m = m.trailing_zeros();
    let mut openings = Vec::with_capacity(params.num_queries);
    for &leaf in &fri_indices {
        let index = bit_reverse_index(leaf, log_m);
        let cols = [lde_cols[0][index], lde_cols[1][index]];
        let next = [lde_next[0][index], lde_next[1][index]];
        let path = tree.prove_capped(index, drop)?;
        openings.push(TraceOpening {
            index,
            a: cols[0],
            b: cols[1],
            a_next: next[0],
            b_next: next[1],
            path,
        });
    }

    Ok(Proof {
        column_cap,
        fri_commitment,
        fri_proof,
        openings,
    })
}

/// Verify a Fibonacci [`Proof`] under `params`.
///
/// # Errors
/// Returns [`Error::FriVerificationFailed`] or [`Error::BadMerklePath`] on
/// any failed check.
pub fn verify(params: Params, proof: &Proof, transcript: &mut Transcript) -> Result<()> {
    let n = params.n_steps;
    // Domain size comes from the commitment: ZK proofs use larger (masked)
    // LDEs than `params.lde_len()`. FRI binding keeps this sound.
    let m = proof.fri_commitment.lde_len;
    absorb_params(params, transcript);

    if proof.openings.len() != params.num_queries {
        return Err(Error::FriVerificationFailed);
    }
    transcript.absorb(b"fib/trace", &crate::merkle::cap_bytes(&proof.column_cap));
    let alphas = [
        transcript.challenge_bb(b"fib/alpha"),
        transcript.challenge_bb(b"fib/alpha"),
        transcript.challenge_bb(b"fib/alpha"),
        transcript.challenge_bb(b"fib/alpha"),
        transcript.challenge_bb(b"fib/alpha"),
    ];

    let fri_params = params.fri_params()?;
    let fri_indices = fri::verify(
        &proof.fri_commitment,
        &proof.fri_proof,
        fri_params,
        transcript,
    )?;

    let omega_base = Field::primitive_root(n)?;
    let w_last = omega_base.pow((n - 1) as u64);
    let log_m = m.trailing_zeros();

    for ((query, opening), &leaf) in proof
        .fri_proof
        .queries
        .iter()
        .zip(&proof.openings)
        .zip(&fri_indices)
    {
        let index = bit_reverse_index(leaf, log_m);
        if opening.index != index {
            return Err(Error::FriVerificationFailed);
        }
        // Authenticate the joint row against the cap entry covering it.
        // Shapes are pinned first: the cap holds exactly `2^drop`
        // digests and every path is exactly `depth - drop` steps, so
        // malformed proofs fail before any hashing.
        let values = [opening.a, opening.b, opening.a_next, opening.b_next];
        let mut row = Vec::with_capacity(16);
        for value in &values {
            row.extend_from_slice(&value.to_le_bytes());
        }
        let (drop, depth) = crate::merkle::capped_shape(m, params.cap_height);
        if proof.column_cap.len() != 1usize << drop || opening.path.len() != depth - drop {
            return Err(Error::BadMerklePath);
        }
        let entry = proof
            .column_cap
            .get(index >> (depth - drop))
            .ok_or(Error::BadMerklePath)?;
        if !MerkleTree::verify_capped(entry, &row, index, depth, &opening.path) {
            return Err(Error::BadMerklePath);
        }
        // Re-evaluate the composition identity at this point. The point
        // is derived on demand (one `pow` per query) instead of building
        // the full domain: identical value, negligible work.
        let cols = [opening.a, opening.b];
        let next = [opening.a_next, opening.b_next];
        let expected = composition_at(
            cols,
            next,
            lde_point_at(m, index)?,
            w_last,
            params.a0,
            params.b0,
            params.b_last,
            n,
            &alphas,
        );
        // FRI layer-0 value at the queried (bit-reversed) position.
        // `first` (not indexing): a degenerate commitment could carry
        // fold-free queries, and proofs are untrusted input.
        let quad = query.folds.first().ok_or(Error::FriVerificationFailed)?;
        let qval = quad.values[leaf % 4];
        if qval != expected {
            return Err(Error::FriVerificationFailed);
        }
    }
    Ok(())
}

fn absorb_params(params: Params, transcript: &mut Transcript) {
    let mut buf = Vec::with_capacity(56);
    buf.extend_from_slice(&(params.n_steps as u64).to_le_bytes());
    buf.extend_from_slice(&(params.blowup as u64).to_le_bytes());
    buf.extend_from_slice(&(params.num_queries as u64).to_le_bytes());
    buf.extend_from_slice(&(params.final_size as u64).to_le_bytes());
    buf.extend_from_slice(&params.grinding_bits.to_le_bytes());
    buf.extend_from_slice(&(params.cap_height as u64).to_le_bytes());
    buf.extend_from_slice(&params.a0.to_le_bytes());
    buf.extend_from_slice(&params.b0.to_le_bytes());
    buf.extend_from_slice(&params.b_last.to_le_bytes());
    transcript.absorb(b"fib/params", &buf);
}

/// Multiply coefficient `k` by `omega^k`: the next-row polynomial.
fn shift_coeffs(coeffs: &[Field], omega: Field) -> Vec<Field> {
    let mut out = Vec::with_capacity(coeffs.len());
    let mut power = Field::ONE;
    for &c in coeffs {
        out.push(c * power);
        power *= omega;
    }
    out
}

/// Natural-order coset points `SHIFT * omega^i`.
fn lde_points(m: usize) -> Result<Vec<Field>> {
    let omega = Field::primitive_root(m)?;
    let mut points = Vec::with_capacity(m);
    let mut current = crate::fri::LDE_SHIFT;
    for _ in 0..m {
        points.push(current);
        current *= omega;
    }
    Ok(points)
}

/// Single coset point `SHIFT * omega^index` without building the domain.
///
/// Byte-identical to `lde_points(m)[index]` (exact field math); the
/// verifier needs only one point per query, so the full vector is pure
/// overhead there.
///
/// # Errors
/// Returns [`Error::InvalidDomainSize`] for invalid `m`, as usual.
fn lde_point_at(m: usize, index: usize) -> Result<Field> {
    let omega = Field::primitive_root(m)?;
    Ok(crate::fri::LDE_SHIFT * omega.pow(index as u64))
}

/// Full composition vector on the LDE domain.
#[allow(clippy::too_many_arguments)]
fn compose(
    cols: &[Vec<Field>; 2],
    next: &[Vec<Field>; 2],
    points: &[Field],
    w_last: Field,
    a0: Field,
    b0: Field,
    b_last: Field,
    n: usize,
    alphas: &[Field; 5],
) -> Vec<Field> {
    if points.len() < 2 {
        // Degenerate (unreachable at real domain sizes): scalar fallback.
        return points
            .iter()
            .enumerate()
            .map(|(i, &point)| {
                composition_at(
                    [cols[0][i], cols[1][i]],
                    [next[0][i], next[1][i]],
                    point,
                    w_last,
                    a0,
                    b0,
                    b_last,
                    n,
                    alphas,
                )
            })
            .collect();
    }
    // Vanishing geometric: points are `SHIFT * omega^i`, so
    // `points[i]^n = P0 * RATIO^i` exactly (no 64-step pow per element).
    let p0 = points[0].pow(n as u64);
    let ratio = (points[1] * points[0].inv()).pow(n as u64);
    let mut out = vec![Field::ZERO; points.len()];
    crate::par::for_each_indexed(&mut out, 2048, |base, piece| {
        // Chunk denominators, inverted in two Montgomery batches (one
        // inversion per batch; zeros map to zero exactly like the
        // scalar path, including the singular rows).
        let mut den_a = Vec::with_capacity(piece.len());
        let mut den_b = Vec::with_capacity(piece.len());
        let mut vanishing = Vec::with_capacity(piece.len());
        let mut cur = p0 * ratio.pow(base as u64);
        for j in 0..piece.len() {
            let i = base + j;
            den_a.push(points[i] - w_last);
            den_b.push(points[i] - Field::ONE);
            vanishing.push(cur - Field::ONE);
            cur *= ratio;
        }
        let inv_a = crate::babybear::batch_invert(&den_a);
        let inv_b = crate::babybear::batch_invert(&den_b);
        let mut z_trans = Vec::with_capacity(piece.len());
        for (v, a) in vanishing.iter().zip(&inv_a) {
            z_trans.push(*v * *a);
        }
        let inv_z = crate::babybear::batch_invert(&z_trans);
        // Combine: identical arithmetic to `composition_at` (exact field
        // math has no rounding), so the vector is bit-identical.
        for (j, slot) in piece.iter_mut().enumerate() {
            let i = base + j;
            let trans1 = (next[0][i] - cols[1][i]) * inv_z[j];
            let trans2 = (next[1][i] - (cols[0][i] + cols[1][i])) * inv_z[j];
            let bound_a = (cols[0][i] - a0) * inv_b[j];
            let bound_b = (cols[1][i] - b0) * inv_b[j];
            let bound_out = (cols[1][i] - b_last) * inv_a[j];
            *slot = alphas[0] * trans1
                + alphas[1] * trans2
                + alphas[2] * bound_a
                + alphas[3] * bound_b
                + alphas[4] * bound_out;
        }
    });
    out
}

/// Composition value at one point: transition quotients plus boundaries.
///
/// Transition numerators are divided by the transition vanishing polynomial
/// (zero exactly on rows `0..N-2`): the quotient is low-degree iff the
/// transition holds on every covered row. Multiplying instead of dividing
/// would be vacuous (always low-degree) — see the `bad_trace` regression test.
#[allow(clippy::too_many_arguments)]
fn composition_at(
    cols: [Field; 2],
    next: [Field; 2],
    point: Field,
    w_last: Field,
    a0: Field,
    b0: Field,
    b_last: Field,
    n: usize,
    alphas: &[Field; 5],
) -> Field {
    // Transition vanishing: zero on every base row except the last.
    let vanishing = point.pow(n as u64) - Field::ONE;
    let z_trans = vanishing * (point - w_last).inv();
    let trans1 = (next[0] - cols[1]) * z_trans.inv();
    let trans2 = (next[1] - (cols[0] + cols[1])) * z_trans.inv();
    let bound_a = (cols[0] - a0) * (point - Field::ONE).inv();
    let bound_b = (cols[1] - b0) * (point - Field::ONE).inv();
    let bound_out = (cols[1] - b_last) * (point - w_last).inv();
    alphas[0] * trans1
        + alphas[1] * trans2
        + alphas[2] * bound_a
        + alphas[3] * bound_b
        + alphas[4] * bound_out
}

fn bit_reverse_index(mut x: usize, bits: u32) -> usize {
    let mut out = 0usize;
    for _ in 0..bits {
        out = (out << 1) | (x & 1);
        x >>= 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fibonacci output in the field (mirrors [`build_trace`] arithmetic).
    fn fib_field(n: usize) -> Field {
        let (mut a, mut b) = (Field::ONE, Field::ONE);
        for _ in 1..n {
            let c = a + b;
            a = b;
            b = c;
        }
        b
    }

    fn test_params() -> Params {
        let n = 16;
        Params::new(n, 8, 8, 8, Field::ONE, Field::ONE, fib_field(n)).unwrap()
    }

    /// ZK variant: masked LDEs are larger (M = 256), so the final size must
    /// give a power-of-four ratio (256 / 4).
    fn test_params_zk() -> Params {
        let n = 16;
        Params::new(n, 8, 8, 4, Field::ONE, Field::ONE, fib_field(n)).unwrap()
    }

    #[test]
    fn rejects_bad_params() {
        assert!(Params::new(3, 8, 8, 4, Field::ONE, Field::ONE, Field::ONE).is_err());
        assert!(Params::new(1, 8, 8, 4, Field::ONE, Field::ONE, Field::ONE).is_err());
        assert!(Params::new(16, 2, 8, 4, Field::ONE, Field::ONE, Field::ONE).is_err());
        assert!(Params::new(16, 8, 0, 4, Field::ONE, Field::ONE, Field::ONE).is_err());
    }

    #[test]
    fn honest_proof_verifies() {
        let params = test_params();
        let mut prover_t = Transcript::new(b"fib-e2e");
        let proof = prove(params, &mut prover_t).unwrap();
        assert_eq!(proof.openings.len(), params.num_queries);
        let mut verifier_t = Transcript::new(b"fib-e2e");
        verify(params, &proof, &mut verifier_t).unwrap();
    }

    #[test]
    fn wrong_output_claim_fails() {
        let params = test_params();
        let mut prover_t = Transcript::new(b"fib-wrong-out");
        let proof = prove(params, &mut prover_t).unwrap();
        let mut bad = params;
        bad.b_last += Field::ONE;
        let mut verifier_t = Transcript::new(b"fib-wrong-out");
        assert!(verify(bad, &proof, &mut verifier_t).is_err());
    }

    #[test]
    fn tampered_opening_fails() {
        let params = test_params();
        let mut prover_t = Transcript::new(b"fib-tamper");
        let mut proof = prove(params, &mut prover_t).unwrap();
        proof.openings[0].b += Field::ONE;
        let mut verifier_t = Transcript::new(b"fib-tamper");
        assert!(verify(params, &proof, &mut verifier_t).is_err());
    }

    #[test]
    fn bad_trace_rejected_by_fri_degree() {
        // A trace violating the transition relation commits honestly, but the
        // composition interpolant is high-degree and FRI rejects it: same
        // transcript flow, failure isolated to the low-degree check.
        let params = test_params();
        let (mut col_a, col_b) = build_trace(params.a0, params.b0, params.n_steps);
        col_a[5] += Field::ONE;
        let mut prover_t = Transcript::new(b"fib-badtrace");
        let proof = prove_with_trace(params, &col_a, &col_b, &mut prover_t).unwrap();
        let mut verifier_t = Transcript::new(b"fib-badtrace");
        assert!(verify(params, &proof, &mut verifier_t).is_err());
    }

    #[test]
    fn wrong_transcript_fails() {
        let params = test_params();
        let mut prover_t = Transcript::new(b"fib-A");
        let proof = prove(params, &mut prover_t).unwrap();
        let mut verifier_t = Transcript::new(b"fib-B");
        assert!(verify(params, &proof, &mut verifier_t).is_err());
    }

    #[test]
    fn grinding_roundtrip() {
        let params = test_params().with_grinding_bits(8);
        let mut prover_t = Transcript::new(b"fib-grind");
        let proof = prove(params, &mut prover_t).unwrap();
        let mut verifier_t = Transcript::new(b"fib-grind");
        verify(params, &proof, &mut verifier_t).unwrap();
    }

    #[test]
    fn batched_compose_matches_scalar() {
        // Pseudo-random columns (including zeros) over a real domain:
        // batch zeros must mirror scalar zeros, singular rows included.
        let n = 16;
        let m = n * 8;
        let points = lde_points(m).unwrap();
        let omega_base = Field::primitive_root(n).unwrap();
        let w_last = omega_base.pow((n - 1) as u64);
        let mut cols = [vec![Field::ZERO; m], vec![Field::ZERO; m]];
        let mut next = [vec![Field::ZERO; m], vec![Field::ZERO; m]];
        let mut state = 0x1234_5678_9abc_def1u64;
        let mut draw = || {
            state = crate::gf2::splitmix64(&mut state);
            Field::from_u64(state)
        };
        for i in 0..m {
            cols[0][i] = draw();
            cols[1][i] = draw();
            next[0][i] = draw();
            next[1][i] = draw();
        }
        cols[0][0] = Field::ZERO;
        next[1][m - 1] = Field::ZERO;
        let alphas = [
            Field::ONE,
            Field::TWO,
            Field::new(3),
            Field::new(4),
            Field::new(5),
        ];
        let batched = compose(
            &cols,
            &next,
            &points,
            w_last,
            Field::ONE,
            Field::ONE,
            Field::TWO,
            n,
            &alphas,
        );
        let scalar: Vec<Field> = (0..m)
            .map(|i| {
                composition_at(
                    [cols[0][i], cols[1][i]],
                    [next[0][i], next[1][i]],
                    points[i],
                    w_last,
                    Field::ONE,
                    Field::ONE,
                    Field::TWO,
                    n,
                    &alphas,
                )
            })
            .collect();
        assert_eq!(batched, scalar);
    }

    #[test]
    fn for_security_roundtrip() {
        let n = 16;
        let params = Params::for_security(n, Field::ONE, Field::ONE, fib_field(n), 12).unwrap();
        assert_eq!(params.blowup, 16);
        assert_eq!((params.num_queries, params.grinding_bits), (3, 6));
        assert!(params.cap_height <= 4);
        let mut prover_t = Transcript::new(b"fib-forsec");
        let proof = prove(params, &mut prover_t).unwrap();
        let mut verifier_t = Transcript::new(b"fib-forsec");
        verify(params, &proof, &mut verifier_t).unwrap();

        assert!(Params::for_security(3, Field::ONE, Field::ONE, Field::ONE, 12).is_err());
        assert!(
            Params::for_security(1usize << 24, Field::ONE, Field::ONE, Field::ONE, 12).is_err()
        );
    }

    #[test]
    fn truncated_and_swapped_openings_fail() {
        let params = test_params();
        let mut prover_t = Transcript::new(b"fib-shape");
        let proof = prove(params, &mut prover_t).unwrap();
        // Dropped opening: count mismatch against `num_queries`.
        let mut short = proof.clone();
        short.openings.pop();
        let mut verifier_t = Transcript::new(b"fib-shape");
        assert!(verify(params, &short, &mut verifier_t).is_err());
        // Swapped order: indices no longer match query order.
        let mut swapped = proof.clone();
        swapped.openings.swap(0, 1);
        let mut verifier_t = Transcript::new(b"fib-shape");
        assert!(verify(params, &swapped, &mut verifier_t).is_err());
    }

    #[test]
    fn cap_mismatch_rejects() {
        let capped = test_params().with_cap_height(2);
        let mut prover_t = Transcript::new(b"fib-capmix");
        let proof = prove(capped, &mut prover_t).unwrap();
        // Capped proof under plain params (and the reverse): caps are
        // transcript-bound, so the schedules diverge and paths miss.
        let plain = test_params();
        let mut verifier_t = Transcript::new(b"fib-capmix");
        assert!(verify(plain, &proof, &mut verifier_t).is_err());

        let mut prover_t = Transcript::new(b"fib-capmix");
        let plain_proof = prove(plain, &mut prover_t).unwrap();
        let mut verifier_t = Transcript::new(b"fib-capmix");
        assert!(verify(capped, &plain_proof, &mut verifier_t).is_err());
    }

    #[test]
    fn malformed_shapes_rejected() {
        // Bloated column cap and over-long opening path fail closed
        // before hashing.
        let params = test_params();
        let mut prover_t = Transcript::new(b"fib-shapes");
        let proof = prove(params, &mut prover_t).unwrap();

        let mut fat_cap = proof.clone();
        fat_cap.column_cap.push([9u8; 32]);
        let mut verifier_t = Transcript::new(b"fib-shapes");
        assert!(verify(params, &fat_cap, &mut verifier_t).is_err());

        let mut long_path = proof.clone();
        long_path.openings[0].path.push(([9u8; 32], true));
        let mut verifier_t = Transcript::new(b"fib-shapes");
        assert!(verify(params, &long_path, &mut verifier_t).is_err());
    }

    #[test]
    fn encoding_roundtrip_and_rejects() {
        for (label, params) in [
            ("air-codec", test_params()),
            ("air-codec-cap", test_params().with_cap_height(2)),
        ] {
            let mut prover_t = Transcript::new(label.as_bytes());
            let proof = prove(params, &mut prover_t).unwrap();
            let bytes = proof.to_bytes();
            assert_eq!(Proof::from_bytes(&bytes).unwrap(), proof);
            // Decoded proofs verify: catches mirrored encode/decode bugs
            // that a pure roundtrip would miss.
            let mut verifier_t = Transcript::new(label.as_bytes());
            verify(params, &Proof::from_bytes(&bytes).unwrap(), &mut verifier_t).unwrap();
            assert!(Proof::from_bytes(&bytes[..bytes.len() - 1]).is_err());
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(Proof::from_bytes(&trailing).is_err());
        }
    }

    #[test]
    fn capped_roundtrip() {
        let params = test_params().with_cap_height(2);
        let mut prover_t = Transcript::new(b"fib-cap");
        let proof = prove(params, &mut prover_t).unwrap();
        assert_eq!(proof.column_cap.len(), 4);
        // Column paths shrink by the cap height (depth 7 -> 5 steps).
        for opening in &proof.openings {
            assert_eq!(opening.path.len(), 5);
        }
        let mut verifier_t = Transcript::new(b"fib-cap");
        verify(params, &proof, &mut verifier_t).unwrap();

        // Forged cap entry fails.
        let mut bad = proof.clone();
        bad.column_cap[0][0] ^= 1;
        let mut verifier_t = Transcript::new(b"fib-cap");
        assert!(verify(params, &bad, &mut verifier_t).is_err());
    }
    #[test]
    fn larger_trace_verifies() {
        let n = 64;
        let params = Params::new(n, 8, 12, 8, Field::ONE, Field::ONE, fib_field(n)).unwrap();
        let mut prover_t = Transcript::new(b"fib-big");
        let proof = prove(params, &mut prover_t).unwrap();
        let mut verifier_t = Transcript::new(b"fib-big");
        verify(params, &proof, &mut verifier_t).unwrap();
    }

    fn zk_rng() -> crate::rng::ChaCha20 {
        crate::rng::ChaCha20::new([11u8; 32], [22u8; 12])
    }

    #[test]
    fn zk_proof_verifies_with_same_verify() {
        let params = test_params_zk();
        let mut prover_t = Transcript::new(b"fib-zk");
        let proof = prove_zk(params, 8, &mut zk_rng(), &mut prover_t).unwrap();
        let mut verifier_t = Transcript::new(b"fib-zk");
        verify(params, &proof, &mut verifier_t).unwrap();
    }

    #[test]
    fn zk_openings_differ_from_plain() {
        // Same statement, same transcript label: blinding must change what
        // the verifier sees at query positions.
        let params = test_params();
        let params_zk = test_params_zk();
        let mut t1 = Transcript::new(b"fib-diverge");
        let plain = prove(params, &mut t1).unwrap();
        let mut t2 = Transcript::new(b"fib-diverge");
        let blinded = prove_zk(params_zk, 8, &mut zk_rng(), &mut t2).unwrap();
        assert_ne!(plain.openings[0].a, blinded.openings[0].a);
        // Deterministic under a fixed stream.
        let mut t3 = Transcript::new(b"fib-diverge");
        let rerun = prove_zk(params_zk, 8, &mut zk_rng(), &mut t3).unwrap();
        assert_eq!(blinded, rerun);
    }

    #[test]
    fn zk_rejects_few_maskers() {
        let params = test_params_zk();
        let mut t = Transcript::new(b"fib-fewmask");
        assert!(prove_zk(params, params.num_queries - 1, &mut zk_rng(), &mut t).is_err());
    }

    #[test]
    fn zk_tampered_opening_fails() {
        let params = test_params_zk();
        let mut prover_t = Transcript::new(b"fib-zktamper");
        let mut proof = prove_zk(params, 8, &mut zk_rng(), &mut prover_t).unwrap();
        proof.openings[0].b_next += Field::ONE;
        let mut verifier_t = Transcript::new(b"fib-zktamper");
        assert!(verify(params, &proof, &mut verifier_t).is_err());
    }
}
