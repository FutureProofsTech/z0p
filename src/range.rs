//! Range-check AIR: proves a public value fits in `k` bits over committed data.
//!
//! Columns: `V` (constant `= v`) plus bit columns `C_0..C_{k-1}` (constant bit
//! values of `v`, LSB first), all Merkle committed on the
//! [`LDE_SHIFT`](crate::fri::LDE_SHIFT) coset. Constraints, each divided by a
//! vanishing polynomial so that constant offsets stay visible (a nonzero
//! constant numerator divided by `Z_H` interpolates to high degree):
//! - decomposition `(V - sum 2^j C_j) / Z_H`,
//! - booleanity `C_j (C_j - 1) / Z_H` per bit,
//! - boundary `(V - v) / (x - 1)` binding the public claim.
//!
//! The honest composition is identically zero (degree `-inf`); the declared
//! bound `N - 1` covers the boundary quotient shape. Any violated constraint
//! leaves a nonzero numerator over a vanishing denominator, whose coset
//! interpolant is dense and FRI's final check rejects.
//!
//! [`prove`] leaks column values at query positions; [`prove_zk`] blinds
//! every column first for perfect hiding of query responses.

use crate::babybear::Field;
use crate::error::{Error, Result};
use crate::fri::{self, Commitment as FriCommitment, Proof as FriProof};
use crate::merkle::MerkleTree;
use crate::ntt::{evaluate_on_coset, interpolate};
use crate::transcript::Transcript;

/// Range-check parameters plus the public value claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// Trace rows: power of two, `>= 2` (columns are constant; any size works).
    pub n_rows: usize,
    /// Bit width: `1..=24`.
    pub n_bits: usize,
    /// LDE blowup: power of two, `>= 2`.
    pub blowup: usize,
    /// FRI query count (`>= 1`).
    pub num_queries: usize,
    /// FRI final layer size (power of two, `>= 1`).
    pub final_size: usize,
    /// Proof-of-work difficulty in leading-zero bits (`0` disables grinding).
    ///
    /// Threaded into FRI and bound under `"range/params"`.
    pub grinding_bits: u32,
    /// Merkle cap height for the column tree and FRI layers (`0` = roots).
    ///
    /// Threaded into FRI and bound under `"range/params"`.
    pub cap_height: usize,
    /// Claimed value, must fit in `n_bits` bits for honesty.
    pub value: Field,
}

impl Params {
    /// Validate parameters.
    ///
    /// # Errors
    /// Returns [`Error`] for out-of-range sizes or an LDE above `2^27`.
    pub const fn new(
        n_rows: usize,
        n_bits: usize,
        blowup: usize,
        num_queries: usize,
        final_size: usize,
        value: Field,
    ) -> Result<Self> {
        if n_rows < 2 || !n_rows.is_power_of_two() {
            return Err(Error::InvalidDomainSize { size: n_rows });
        }
        if n_bits == 0 || n_bits > 24 {
            return Err(Error::MalformedInput {
                reason: "n_bits must be within 1..=24",
            });
        }
        if blowup < 2 || !blowup.is_power_of_two() {
            return Err(Error::InvalidBlowup { factor: blowup });
        }
        if num_queries == 0 {
            return Err(Error::NoQueries);
        }
        if final_size == 0 || !final_size.is_power_of_two() {
            return Err(Error::InvalidDomainSize { size: final_size });
        }
        let lde = n_rows * blowup;
        if lde / blowup != n_rows || lde > (1usize << Field::TWO_ADICITY) {
            return Err(Error::InvalidDomainSize { size: lde });
        }
        Ok(Self {
            n_rows,
            n_bits,
            blowup,
            num_queries,
            final_size,
            grinding_bits: 0,
            cap_height: 0,
            value,
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

    /// Production parameters for plain (non-masked) columns: blowup 16,
    /// strength sized for `target_bits` conjectured soundness bits, and
    /// size-optimal final size and cap height.
    ///
    /// Masked ([`prove_zk`](crate::range::prove_zk)) callers size manually.
    ///
    /// # Errors
    /// Same domain errors as [`Params::new`].
    pub fn for_security(
        n_rows: usize,
        n_bits: usize,
        value: Field,
        target_bits: u32,
    ) -> Result<Self> {
        if n_rows < 2 || !n_rows.is_power_of_two() {
            return Err(Error::InvalidDomainSize { size: n_rows });
        }
        if n_bits == 0 || n_bits > 24 {
            return Err(Error::MalformedInput {
                reason: "n_bits must be within 1..=24",
            });
        }
        let blowup = 16;
        let lde_len = n_rows
            .checked_mul(blowup)
            .ok_or(Error::InvalidDomainSize { size: n_rows })?;
        if lde_len > (1usize << Field::TWO_ADICITY) {
            return Err(Error::InvalidDomainSize { size: lde_len });
        }
        let millibits = crate::fri::composition_millibits(lde_len, n_rows - 1);
        let (num_queries, grinding_bits) = crate::fri::tune_strength(target_bits, millibits);
        // Column openings carry 8 index bytes plus 4 per column.
        let value_bytes = 8 + 4 * (n_bits + 1);
        let (final_size, cap_height) =
            crate::fri::tune_shape(lde_len, num_queries, &[(lde_len, value_bytes)]);
        Ok(Self {
            n_rows,
            n_bits,
            blowup,
            num_queries,
            final_size,
            grinding_bits,
            cap_height,
            value,
        })
    }

    /// Length of the LDE domain.
    #[must_use]
    pub const fn lde_len(&self) -> usize {
        self.n_rows * self.blowup
    }

    /// Column count: value plus one per bit.
    #[must_use]
    pub const fn n_columns(&self) -> usize {
        self.n_bits + 1
    }

    fn fri_params(&self) -> Result<fri::Params> {
        Ok(
            fri::Params::new(self.blowup, self.num_queries, self.final_size)?
                .with_grinding_bits(self.grinding_bits)
                .with_cap_height(self.cap_height),
        )
    }
}

/// One opening across all range columns at an LDE position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeOpening {
    /// Natural-order LDE index.
    pub index: usize,
    /// Value column at `index`.
    pub v: Field,
    /// Bit columns at `index`, LSB first.
    pub bits: Vec<Field>,
    /// Merkle path of the joint row leaf (`V || C_0 || ..`).
    pub path: Vec<([u8; 32], bool)>,
}

/// Range-check proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// Merkle cap of the joint row LDE (`2^cap_height` digests; one root
    /// when caps are disabled).
    pub column_cap: Vec<[u8; 32]>,
    /// FRI commitment to the composition polynomial.
    pub fri_commitment: FriCommitment,
    /// FRI opening proof.
    pub fri_proof: FriProof,
    /// Column openings, one per FRI query, in query order.
    pub openings: Vec<RangeOpening>,
}

impl Proof {
    /// Canonical bytes: version, column cap, FRI commitment/proof, then
    /// openings (index, value, bit vector, path each).
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
            writer.field(opening.v);
            writer.count(opening.bits.len());
            for bit in &opening.bits {
                writer.field(*bit);
            }
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
        use crate::codec::{MAX_ELEMS, MAX_QUERIES};
        let mut reader = crate::codec::Reader::new(bytes);
        reader.version()?;
        let column_cap = reader.cap()?;
        let fri_commitment = fri::Commitment::read_body(&mut reader)?;
        let fri_proof = fri::Proof::read_body(&mut reader)?;
        let mut openings = Vec::new();
        for _ in 0..reader.count(MAX_QUERIES)? {
            let index = reader.dimension()?;
            let v = reader.field()?;
            let mut bits = Vec::new();
            for _ in 0..reader.count(MAX_ELEMS)? {
                bits.push(reader.field()?);
            }
            let path = reader.path()?;
            openings.push(RangeOpening {
                index,
                v,
                bits,
                path,
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

/// Build constant columns for `value`: `V = value`, `C_j = bit_j(value)`.
///
/// Bits beyond the integer width read as zero; values `>= 2^k` truncate,
/// which violates decomposition and fails verification (tested).
#[must_use]
pub fn build_columns(value: Field, n_bits: usize, n_rows: usize) -> (Vec<Field>, Vec<Vec<Field>>) {
    let v_col = vec![value; n_rows];
    let mut bit_cols = Vec::with_capacity(n_bits);
    for j in 0..n_bits {
        let bit = Field::new((value.0 >> j) & 1);
        bit_cols.push(vec![bit; n_rows]);
    }
    (v_col, bit_cols)
}

/// Prove `params.value` fits in `params.n_bits` bits.
///
/// # Errors
/// Returns [`Error`] for domain or Merkle failures (all structural; an
/// out-of-range value still proves structurally and fails [`verify`]).
pub fn prove(params: Params, transcript: &mut Transcript) -> Result<Proof> {
    let (v_col, bit_cols) = build_columns(params.value, params.n_bits, params.n_rows);
    prove_with_columns(params, &v_col, &bit_cols, transcript)
}

/// Prove with explicit columns (expert API).
///
/// Lengths must be `params.n_rows` with exactly `params.n_bits` bit columns.
/// Invalid columns still prove structurally and fail [`verify`].
///
/// # Errors
/// Returns [`Error::MalformedInput`] on shape mismatch, otherwise structural
/// errors.
pub fn prove_with_columns(
    params: Params,
    v_col: &[Field],
    bit_cols: &[Vec<Field>],
    transcript: &mut Transcript,
) -> Result<Proof> {
    let n = params.n_rows;
    if v_col.len() != n || bit_cols.len() != params.n_bits || bit_cols.iter().any(|c| c.len() != n)
    {
        return Err(Error::MalformedInput {
            reason: "range columns must match n_rows/n_bits",
        });
    }
    let mut columns: Vec<Vec<Field>> = Vec::with_capacity(params.n_columns());
    columns.push(v_col.to_vec());
    columns.extend(bit_cols.iter().cloned());
    let mut coeffs: Vec<Vec<Field>> = Vec::with_capacity(params.n_columns());
    for col in &columns {
        coeffs.push(interpolate(col)?);
    }
    prove_from_columns(params, &coeffs, n - 1, transcript)
}

/// Prove zero-knowledge: identical to [`prove`] except every column is
/// masked with [`crate::blind::mask_coeffs`] (`n_rand` maskers each), so
/// query openings are jointly uniform and independent of the value and its
/// bits. Verification is the same [`verify`]. The composition bound grows
/// to `n_rows + 2 * n_rand - 2` (boolean numerators double the masking
/// degree; still rate `< 1/2`).
///
/// Requires `n_rand >= num_queries`.
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
    let n = params.n_rows;
    let (v_col, bit_cols) = build_columns(params.value, params.n_bits, n);
    let mut columns: Vec<Vec<Field>> = Vec::with_capacity(params.n_columns());
    columns.push(interpolate(&v_col)?);
    for bits in &bit_cols {
        columns.push(interpolate(bits)?);
    }
    let mut masked: Vec<Vec<Field>> = Vec::with_capacity(params.n_columns());
    for col in &columns {
        masked.push(crate::blind::mask_coeffs(col, n, n_rand, rng)?);
    }
    // Tight honest bound: boolean numerators reach `2(n+k-1)`, halved by the
    // degree-`n` vanishing divisor.
    prove_from_columns(params, &masked, n + 2 * n_rand - 2, transcript)
}

/// Shared prover body over coefficient columns of any power-of-two length.
///
/// Note: unlike [`prove_with_columns`], inputs here are already
/// coefficient vectors (base or masked), not evaluations.
fn prove_from_columns(
    params: Params,
    columns: &[Vec<Field>],
    degree_bound: usize,
    transcript: &mut Transcript,
) -> Result<Proof> {
    let n = params.n_rows;
    if columns.len() != params.n_columns() {
        return Err(Error::MalformedInput {
            reason: "column count must match n_columns",
        });
    }
    absorb_params(params, transcript);

    // Extend every column, then commit one joint tree over interleaved
    // rows: a single path opens every column at a position.
    let mut ldes: Vec<Vec<Field>> = Vec::with_capacity(params.n_columns());
    for col in columns {
        ldes.push(evaluate_on_coset(
            col,
            params.blowup,
            crate::fri::LDE_SHIFT,
        )?);
    }
    let m = ldes[0].len();
    let row_len = 4 * params.n_columns();
    let mut flat = vec![0u8; m * row_len];
    for (i, chunk) in flat.chunks_exact_mut(row_len).enumerate() {
        for (lde, slot) in ldes.iter().zip(chunk.chunks_exact_mut(4)) {
            slot.copy_from_slice(&lde[i].to_le_bytes());
        }
    }
    let tree = MerkleTree::from_flat(&flat, row_len)?;
    let (drop, _) = crate::merkle::capped_shape(m, params.cap_height);
    let column_cap = tree.cap(drop);
    transcript.absorb(b"range/column", &crate::merkle::cap_bytes(&column_cap));

    // One challenge for decomposition, one per boolean, one for boundary.
    let alpha_decomp = transcript.challenge_bb(b"range/alpha");
    let mut alpha_bits = Vec::with_capacity(params.n_bits);
    for _ in 0..params.n_bits {
        alpha_bits.push(transcript.challenge_bb(b"range/alpha"));
    }
    let alpha_bound = transcript.challenge_bb(b"range/alpha");

    let points = lde_points(m)?;
    let composition = compose(
        &ldes[0],
        &ldes[1..],
        &points,
        params.value,
        n,
        alpha_decomp,
        &alpha_bits,
        alpha_bound,
    );

    let fri_params = params.fri_params()?;
    let fri_state = fri::commit_evals(&composition, degree_bound, fri_params, transcript)?;
    let fri_commitment = fri::public_commitment(&fri_state);
    let (fri_proof, fri_indices) = fri::open(&fri_state, transcript)?;

    let log_m = m.trailing_zeros();
    let mut openings = Vec::with_capacity(params.num_queries);
    for &leaf in &fri_indices {
        let index = bit_reverse_index(leaf, log_m);
        let v = ldes[0][index];
        let mut bits = Vec::with_capacity(params.n_bits);
        for lde in ldes.iter().skip(1) {
            bits.push(lde[index]);
        }
        let path = tree.prove_capped(index, drop)?;
        openings.push(RangeOpening {
            index,
            v,
            bits,
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

/// Verify a range-check [`Proof`] under `params`.
///
/// # Errors
/// Returns [`Error::FriVerificationFailed`] or [`Error::BadMerklePath`] on
/// any failed check.
pub fn verify(params: Params, proof: &Proof, transcript: &mut Transcript) -> Result<()> {
    let n = params.n_rows;
    // Domain size comes from the commitment: ZK proofs use larger (masked)
    // LDEs than `params.lde_len()`. FRI binding keeps this sound.
    let m = proof.fri_commitment.lde_len;
    absorb_params(params, transcript);

    if proof.openings.len() != params.num_queries {
        return Err(Error::FriVerificationFailed);
    }
    transcript.absorb(
        b"range/column",
        &crate::merkle::cap_bytes(&proof.column_cap),
    );
    let alpha_decomp = transcript.challenge_bb(b"range/alpha");
    let mut alpha_bits = Vec::with_capacity(params.n_bits);
    for _ in 0..params.n_bits {
        alpha_bits.push(transcript.challenge_bb(b"range/alpha"));
    }
    let alpha_bound = transcript.challenge_bb(b"range/alpha");

    let fri_params = params.fri_params()?;
    let fri_indices = fri::verify(
        &proof.fri_commitment,
        &proof.fri_proof,
        fri_params,
        transcript,
    )?;

    let log_m = m.trailing_zeros();
    for ((query, opening), &leaf) in proof
        .fri_proof
        .queries
        .iter()
        .zip(&proof.openings)
        .zip(&fri_indices)
    {
        let index = bit_reverse_index(leaf, log_m);
        if opening.index != index || opening.bits.len() != params.n_bits {
            return Err(Error::FriVerificationFailed);
        }
        // Authenticate the joint row against the cap entry covering it.
        // Shapes are pinned first: the cap holds exactly `2^drop`
        // digests and every path is exactly `depth - drop` steps, so
        // malformed proofs fail before any hashing.
        let mut row = Vec::with_capacity(4 * params.n_columns());
        row.extend_from_slice(&opening.v.to_le_bytes());
        for bit in &opening.bits {
            row.extend_from_slice(&bit.to_le_bytes());
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
        let expected = composition_at(
            opening.v,
            &opening.bits,
            // On-demand domain point (one `pow` per query): identical to
            // the full vector, negligible work.
            lde_point_at(m, index)?,
            params.value,
            n,
            alpha_decomp,
            &alpha_bits,
            alpha_bound,
        );
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
    let mut buf = Vec::with_capacity(48);
    buf.extend_from_slice(&(params.n_rows as u64).to_le_bytes());
    buf.extend_from_slice(&(params.n_bits as u64).to_le_bytes());
    buf.extend_from_slice(&(params.blowup as u64).to_le_bytes());
    buf.extend_from_slice(&(params.num_queries as u64).to_le_bytes());
    buf.extend_from_slice(&(params.final_size as u64).to_le_bytes());
    buf.extend_from_slice(&params.grinding_bits.to_le_bytes());
    buf.extend_from_slice(&(params.cap_height as u64).to_le_bytes());
    buf.extend_from_slice(&params.value.to_le_bytes());
    transcript.absorb(b"range/params", &buf);
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

/// Full composition vector: every constraint divided by its vanishing poly.
///
/// Batched like [`crate::air`] composition: vanishing geometric plus
/// Montgomery inversions per chunk, bit-identical to [`composition_at`].
/// The per-element bit vector is also gone (direct column indexing).
#[allow(clippy::too_many_arguments)]
fn compose(
    lde_v: &[Field],
    lde_bits: &[Vec<Field>],
    points: &[Field],
    value: Field,
    n: usize,
    alpha_decomp: Field,
    alpha_bits: &[Field],
    alpha_bound: Field,
) -> Vec<Field> {
    if points.len() < 2 {
        // Degenerate (unreachable at real domain sizes): scalar fallback.
        return points
            .iter()
            .enumerate()
            .map(|(i, &point)| {
                let bits: Vec<Field> = lde_bits.iter().map(|col| col[i]).collect();
                composition_at(
                    lde_v[i],
                    &bits,
                    point,
                    value,
                    n,
                    alpha_decomp,
                    alpha_bits,
                    alpha_bound,
                )
            })
            .collect();
    }
    let p0 = points[0].pow(n as u64);
    let ratio = (points[1] * points[0].inv()).pow(n as u64);
    let mut out = vec![Field::ZERO; points.len()];
    crate::par::for_each_indexed(&mut out, 2048, |base, piece| {
        let mut den_z = Vec::with_capacity(piece.len());
        let mut den_b = Vec::with_capacity(piece.len());
        let mut cur = p0 * ratio.pow(base as u64);
        for j in 0..piece.len() {
            let i = base + j;
            den_z.push(cur - Field::ONE);
            den_b.push(points[i] - Field::ONE);
            cur *= ratio;
        }
        let inv_z = crate::babybear::batch_invert(&den_z);
        let inv_b = crate::babybear::batch_invert(&den_b);
        for (j, slot) in piece.iter_mut().enumerate() {
            let i = base + j;
            let mut reconstructed = Field::ZERO;
            let mut power = Field::ONE;
            for col in lde_bits {
                reconstructed += power * col[i];
                power += power;
            }
            let mut acc = alpha_decomp * (lde_v[i] - reconstructed) * inv_z[j];
            for (col, &alpha) in lde_bits.iter().zip(alpha_bits.iter()) {
                let bit = col[i];
                acc += alpha * bit * (bit - Field::ONE) * inv_z[j];
            }
            acc += alpha_bound * (lde_v[i] - value) * inv_b[j];
            *slot = acc;
        }
    });
    out
}

/// Composition value at one point. All numerators vanish on their domains
/// exactly when the range claim holds, keeping the interpolant low-degree.
#[allow(clippy::too_many_arguments)]
fn composition_at(
    v: Field,
    bits: &[Field],
    point: Field,
    value: Field,
    n: usize,
    alpha_decomp: Field,
    alpha_bits: &[Field],
    alpha_bound: Field,
) -> Field {
    debug_assert_eq!(bits.len(), alpha_bits.len());
    let vanishing = point.pow(n as u64) - Field::ONE;
    let z_inv = vanishing.inv();
    // Decomposition: V - sum 2^j C_j, over the full-row vanishing poly.
    let mut reconstructed = Field::ZERO;
    let mut power = Field::ONE;
    for &bit in bits {
        reconstructed += power * bit;
        power += power;
    }
    let mut acc = alpha_decomp * (v - reconstructed) * z_inv;
    // Booleanity per bit, over the same vanishing poly.
    for (j, &bit) in bits.iter().enumerate() {
        acc += alpha_bits[j] * bit * (bit - Field::ONE) * z_inv;
    }
    // Boundary binding the public claim at row 0 (`x = 1`).
    acc += alpha_bound * (v - value) * (point - Field::ONE).inv();
    acc
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

    fn test_params(value: u32) -> Params {
        Params::new(8, 16, 8, 8, 4, Field::new(value)).unwrap()
    }

    #[test]
    fn rejects_bad_params() {
        assert!(Params::new(3, 16, 8, 8, 4, Field::ONE).is_err());
        assert!(Params::new(8, 0, 8, 8, 4, Field::ONE).is_err());
        assert!(Params::new(8, 25, 8, 8, 4, Field::ONE).is_err());
        assert!(Params::new(8, 16, 1, 8, 4, Field::ONE).is_err());
        assert!(Params::new(8, 16, 8, 0, 4, Field::ONE).is_err());
    }

    #[test]
    fn honest_proof_verifies() {
        let params = test_params(12_345);
        let mut prover_t = Transcript::new(b"range-e2e");
        let proof = prove(params, &mut prover_t).unwrap();
        assert_eq!(proof.openings.len(), params.num_queries);
        let mut verifier_t = Transcript::new(b"range-e2e");
        verify(params, &proof, &mut verifier_t).unwrap();
    }

    #[test]
    fn for_security_roundtrip() {
        let params = Params::for_security(8, 16, Field::new(12_345), 12).unwrap();
        assert_eq!(params.blowup, 16);
        assert_eq!((params.num_queries, params.grinding_bits), (3, 6));
        assert!(params.cap_height <= 4);
        let mut prover_t = Transcript::new(b"range-forsec");
        let proof = prove(params, &mut prover_t).unwrap();
        let mut verifier_t = Transcript::new(b"range-forsec");
        verify(params, &proof, &mut verifier_t).unwrap();

        assert!(Params::for_security(3, 16, Field::ONE, 12).is_err());
        assert!(Params::for_security(8, 0, Field::ONE, 12).is_err());
        assert!(Params::for_security(8, 25, Field::ONE, 12).is_err());
    }

    #[test]
    fn truncated_and_swapped_openings_fail() {
        let params = test_params(12_345);
        let mut prover_t = Transcript::new(b"range-shape");
        let proof = prove(params, &mut prover_t).unwrap();
        let mut short = proof.clone();
        short.openings.pop();
        let mut verifier_t = Transcript::new(b"range-shape");
        assert!(verify(params, &short, &mut verifier_t).is_err());
        let mut swapped = proof.clone();
        swapped.openings.swap(0, 1);
        let mut verifier_t = Transcript::new(b"range-shape");
        assert!(verify(params, &swapped, &mut verifier_t).is_err());
    }

    #[test]
    fn cap_mismatch_rejects() {
        let capped = test_params(12_345).with_cap_height(2);
        let mut prover_t = Transcript::new(b"range-capmix");
        let proof = prove(capped, &mut prover_t).unwrap();
        let plain = test_params(12_345);
        let mut verifier_t = Transcript::new(b"range-capmix");
        assert!(verify(plain, &proof, &mut verifier_t).is_err());

        let mut prover_t = Transcript::new(b"range-capmix");
        let plain_proof = prove(plain, &mut prover_t).unwrap();
        let mut verifier_t = Transcript::new(b"range-capmix");
        assert!(verify(capped, &plain_proof, &mut verifier_t).is_err());
    }

    #[test]
    fn encoding_roundtrip_and_rejects() {
        for (label, params) in [
            ("range-codec", test_params(12_345)),
            ("range-codec-cap", test_params(12_345).with_cap_height(2)),
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
        let params = test_params(12_345).with_cap_height(2);
        let mut prover_t = Transcript::new(b"range-cap");
        let proof = prove(params, &mut prover_t).unwrap();
        assert_eq!(proof.column_cap.len(), 4);
        // Column paths shrink by the cap height (depth 6 -> 4 steps).
        for opening in &proof.openings {
            assert_eq!(opening.path.len(), 4);
        }
        let mut verifier_t = Transcript::new(b"range-cap");
        verify(params, &proof, &mut verifier_t).unwrap();

        // Forged cap entry fails.
        let mut bad = proof.clone();
        bad.column_cap[0][0] ^= 1;
        let mut verifier_t = Transcript::new(b"range-cap");
        assert!(verify(params, &bad, &mut verifier_t).is_err());
    }

    #[test]
    fn boundary_values_verify() {
        for value in [0u32, 1, 65_535] {
            let params = test_params(value);
            let mut prover_t = Transcript::new(b"range-bound");
            let proof = prove(params, &mut prover_t).unwrap();
            let mut verifier_t = Transcript::new(b"range-bound");
            verify(params, &proof, &mut verifier_t).unwrap();
        }
    }

    #[test]
    fn out_of_range_rejected() {
        // 70000 needs 17 bits: truncated bit columns violate decomposition,
        // and the nonzero constant numerator over Z_H interpolates densely.
        let params = test_params(70_000);
        let mut prover_t = Transcript::new(b"range-oor");
        let proof = prove(params, &mut prover_t).unwrap();
        let mut verifier_t = Transcript::new(b"range-oor");
        assert!(verify(params, &proof, &mut verifier_t).is_err());
    }

    #[test]
    fn non_bit_column_rejected() {
        // A constant `2` bit column violates booleanity with a constant
        // nonzero numerator over Z_H: same density argument as decomposition.
        let params = test_params(5);
        let (v_col, mut bit_cols) = build_columns(params.value, params.n_bits, params.n_rows);
        bit_cols[3] = vec![Field::new(2); params.n_rows];
        let mut prover_t = Transcript::new(b"range-nonbit");
        let proof = prove_with_columns(params, &v_col, &bit_cols, &mut prover_t).unwrap();
        let mut verifier_t = Transcript::new(b"range-nonbit");
        assert!(verify(params, &proof, &mut verifier_t).is_err());
    }

    #[test]
    fn tampered_opening_fails() {
        let params = test_params(999);
        let mut prover_t = Transcript::new(b"range-tamper");
        let mut proof = prove(params, &mut prover_t).unwrap();
        proof.openings[0].bits[2] += Field::ONE;
        let mut verifier_t = Transcript::new(b"range-tamper");
        assert!(verify(params, &proof, &mut verifier_t).is_err());
    }

    #[test]
    fn wrong_claim_fails() {
        let params = test_params(999);
        let mut prover_t = Transcript::new(b"range-claim");
        let proof = prove(params, &mut prover_t).unwrap();
        let mut bad = params;
        bad.value = Field::new(1_000);
        let mut verifier_t = Transcript::new(b"range-claim");
        assert!(verify(bad, &proof, &mut verifier_t).is_err());
    }

    fn zk_rng() -> crate::rng::ChaCha20 {
        crate::rng::ChaCha20::new([33u8; 32], [44u8; 12])
    }

    /// ZK variant: masked LDEs are larger (M = 128), so the final size must
    /// give a power-of-four ratio (128 / 8).
    fn test_params_zk(value: u32) -> Params {
        Params::new(8, 16, 8, 8, 8, Field::new(value)).unwrap()
    }

    #[test]
    fn zk_proof_verifies_with_same_verify() {
        let params = test_params_zk(12_345);
        let mut prover_t = Transcript::new(b"range-zk");
        let proof = prove_zk(params, 8, &mut zk_rng(), &mut prover_t).unwrap();
        let mut verifier_t = Transcript::new(b"range-zk");
        verify(params, &proof, &mut verifier_t).unwrap();
    }

    #[test]
    fn zk_openings_differ_from_plain() {
        let params = test_params(999);
        let params_zk = test_params_zk(999);
        let mut t1 = Transcript::new(b"range-diverge");
        let plain = prove(params, &mut t1).unwrap();
        let mut t2 = Transcript::new(b"range-diverge");
        let blinded = prove_zk(params_zk, 8, &mut zk_rng(), &mut t2).unwrap();
        assert_ne!(plain.openings[0].v, blinded.openings[0].v);
        let mut t3 = Transcript::new(b"range-diverge");
        let rerun = prove_zk(params_zk, 8, &mut zk_rng(), &mut t3).unwrap();
        assert_eq!(blinded, rerun);
    }

    #[test]
    fn zk_out_of_range_still_rejected() {
        let params = test_params_zk(70_000);
        let mut prover_t = Transcript::new(b"range-zkoor");
        let proof = prove_zk(params, 8, &mut zk_rng(), &mut prover_t).unwrap();
        let mut verifier_t = Transcript::new(b"range-zkoor");
        assert!(verify(params, &proof, &mut verifier_t).is_err());
    }

    #[test]
    fn zk_rejects_few_maskers() {
        let params = test_params_zk(7);
        let mut t = Transcript::new(b"range-fewmask");
        assert!(prove_zk(params, params.num_queries - 1, &mut zk_rng(), &mut t).is_err());
    }
}
