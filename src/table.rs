//! Table-membership AIR: proves a committed value belongs to a public table.
//!
//! For public table `T = {t_0, ..}` and committed column `V` (constant `= v`),
//! the constraint is the vanishing product `P(V) = prod_{t in T}(V - t) = 0`
//! divided by the full-row vanishing polynomial `Z_H`, plus the boundary
//! `(V - v) / (x - 1)` binding the public claim. Every term is a quotient,
//! so constant offsets stay visible: a non-member yields a nonzero constant
//! numerator over `Z_H`, whose coset interpolant is dense and FRI rejects.
//!
//! This covers the standard private-lookup setting (public table, hidden
//! witness) for small tables. Cost scales with `|T|`: the vanishing product
//! has degree `|T|`, so the composition bound is `|T| * (n + k - 1) - n`
//! and large tables need proportionally larger blowup to keep rate `< 1/2`.
//! Large-table `LogUp` with hidden tables needs committed sumcheck (a
//! multilinear PCS), which remains a scheduled follow-up.

use crate::babybear::Field;
use crate::error::{Error, Result};
use crate::fri::{self, Commitment as FriCommitment, Proof as FriProof};
use crate::merkle::MerkleTree;
use crate::ntt::{evaluate_on_coset, interpolate};
use crate::transcript::Transcript;

/// Membership parameters plus the public value claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// Trace rows: power of two, `>= 2` (the column is constant).
    pub n_rows: usize,
    /// LDE blowup: power of two, `>= 2` (size for `|T|` so rate `< 1/2`).
    pub blowup: usize,
    /// FRI query count (`>= 1`).
    pub num_queries: usize,
    /// FRI final layer size (power of two, `>= 1`).
    pub final_size: usize,
    /// Proof-of-work difficulty in leading-zero bits (`0` disables grinding).
    ///
    /// Threaded into FRI and bound under `"table/params"`.
    pub grinding_bits: u32,
    /// Merkle cap height for the column tree and FRI layers (`0` = roots).
    ///
    /// Threaded into FRI and bound under `"table/params"`.
    pub cap_height: usize,
    /// Claimed member of the table.
    pub value: Field,
}

impl Params {
    /// Validate parameters (not the table; see [`prove`]).
    ///
    /// # Errors
    /// Returns [`Error`] for out-of-range sizes or an LDE above `2^27`.
    pub const fn new(
        n_rows: usize,
        blowup: usize,
        num_queries: usize,
        final_size: usize,
        value: Field,
    ) -> Result<Self> {
        if n_rows < 2 || !n_rows.is_power_of_two() {
            return Err(Error::InvalidDomainSize { size: n_rows });
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

    /// Production parameters for plain (non-masked) columns: blowup sized
    /// for rate `<= 1/4` at this table length, strength sized for
    /// `target_bits` conjectured soundness bits, and size-optimal final
    /// size and cap height.
    ///
    /// Masked ([`prove_zk`](crate::table::prove_zk)) callers size manually.
    ///
    /// # Errors
    /// Same domain errors as [`Params::new`], plus oversized tables whose
    /// LDE would exceed `2^27`.
    pub fn for_security(
        n_rows: usize,
        table_len: usize,
        value: Field,
        target_bits: u32,
    ) -> Result<Self> {
        if n_rows < 2 || !n_rows.is_power_of_two() {
            return Err(Error::InvalidDomainSize { size: n_rows });
        }
        if table_len < 2 {
            return Err(Error::MalformedInput {
                reason: "table needs at least two entries",
            });
        }
        let bound = membership_bound(table_len, n_rows, 0);
        // Smallest blowup in 2.. with `(bound + 1) <= lde / 4`.
        let need = bound.saturating_add(1);
        let mut blowup = 2usize;
        let lde_len = loop {
            let lde = n_rows
                .checked_mul(blowup)
                .ok_or(Error::InvalidDomainSize { size: n_rows })?;
            if need <= lde / 4 || blowup >= (1usize << 27) {
                break lde;
            }
            blowup *= 2;
        };
        if lde_len > (1usize << Field::TWO_ADICITY) || need > lde_len / 4 {
            return Err(Error::InvalidDomainSize { size: lde_len });
        }
        let millibits = crate::fri::composition_millibits(lde_len, bound);
        let (num_queries, grinding_bits) = crate::fri::tune_strength(target_bits, millibits);
        // Column openings carry 8 index bytes plus one field.
        let (final_size, cap_height) =
            crate::fri::tune_shape(lde_len, num_queries, &[(lde_len, 12)]);
        Ok(Self {
            n_rows,
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

    fn fri_params(&self) -> Result<fri::Params> {
        Ok(
            fri::Params::new(self.blowup, self.num_queries, self.final_size)?
                .with_grinding_bits(self.grinding_bits)
                .with_cap_height(self.cap_height),
        )
    }
}

/// One column opening at an LDE position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableOpening {
    /// Natural-order LDE index.
    pub index: usize,
    /// Value column at `index`.
    pub v: Field,
    /// Merkle path for `v`.
    pub path: Vec<([u8; 32], bool)>,
}

/// Membership proof: public table is a verify-time input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// Merkle cap of the `V` LDE (`2^cap_height` digests; one root when
    /// caps are disabled).
    pub column_cap: Vec<[u8; 32]>,
    /// FRI commitment to the composition polynomial.
    pub fri_commitment: FriCommitment,
    /// FRI opening proof.
    pub fri_proof: FriProof,
    /// Column openings, one per FRI query, in query order.
    pub openings: Vec<TableOpening>,
}

impl Proof {
    /// Canonical bytes: version, column cap, FRI commitment/proof, then
    /// openings (index, value, path each).
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
            let index = reader.dimension()?;
            let v = reader.field()?;
            let path = reader.path()?;
            openings.push(TableOpening { index, v, path });
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

/// Check table shape: at least two entries (a singleton is an equality
/// claim, better served by a boundary alone).
fn check_table(table: &[Field]) -> Result<()> {
    if table.len() < 2 {
        return Err(Error::MalformedInput {
            reason: "table needs at least two entries",
        });
    }
    Ok(())
}

/// Prove `params.value` belongs to `table`.
///
/// # Errors
/// Returns [`Error::MalformedInput`] for tiny tables, otherwise structural
/// errors (a non-member still proves structurally and fails [`verify`]).
pub fn prove(params: Params, table: &[Field], transcript: &mut Transcript) -> Result<Proof> {
    check_table(table)?;
    let base_vals = vec![params.value; params.n_rows];
    let coeffs = interpolate(&base_vals)?;
    prove_from_coeffs(
        params,
        table,
        &coeffs,
        membership_bound(table.len(), params.n_rows, 0),
        transcript,
    )
}

/// Prove zero-knowledge: identical to [`prove`] except the value column is
/// masked with [`crate::blind::mask_coeffs`] (`n_rand` maskers), so query
/// openings are uniform and independent of the claimed member.
/// Verification is the same [`verify`].
///
/// Requires `n_rand >= num_queries`.
///
/// # Errors
/// Returns [`Error::MalformedInput`] for tiny tables or `n_rand < num_queries`,
/// otherwise the structural errors of [`prove`].
pub fn prove_zk(
    params: Params,
    table: &[Field],
    n_rand: usize,
    rng: &mut crate::rng::ChaCha20,
    transcript: &mut Transcript,
) -> Result<Proof> {
    check_table(table)?;
    if n_rand < params.num_queries {
        return Err(Error::MalformedInput {
            reason: "n_rand must cover num_queries for hiding",
        });
    }
    let n = params.n_rows;
    let base_vals = vec![params.value; n];
    let base = interpolate(&base_vals)?;
    let masked = crate::blind::mask_coeffs(&base, n, n_rand, rng)?;
    prove_from_coeffs(
        params,
        table,
        &masked,
        membership_bound(table.len(), n, n_rand),
        transcript,
    )
}

/// Honest composition-degree bound for `|table|` entries, base size `n`,
/// and `n_rand` maskers: vanishing-product numerator `|T| * (n + k - 1)`
/// over the degree-`n` row vanishing polynomial.
#[must_use]
pub const fn membership_bound(table_len: usize, n: usize, n_rand: usize) -> usize {
    table_len * (n + n_rand - 1) - n
}

/// Shared prover body over coefficient vectors of any power-of-two length.
fn prove_from_coeffs(
    params: Params,
    table: &[Field],
    coeffs: &[Field],
    degree_bound: usize,
    transcript: &mut Transcript,
) -> Result<Proof> {
    absorb_params(params, table, transcript);

    let lde = evaluate_on_coset(coeffs, params.blowup, crate::fri::LDE_SHIFT)?;
    let tree = commit_evals(&lde)?;
    let m = lde.len();
    let (drop, _) = crate::merkle::capped_shape(m, params.cap_height);
    let column_cap = tree.cap(drop);
    transcript.absorb(b"table/column", &crate::merkle::cap_bytes(&column_cap));

    let alpha_member = transcript.challenge_bb(b"table/alpha");
    let alpha_bound = transcript.challenge_bb(b"table/alpha");

    let points = lde_points(m)?;
    let composition = compose(
        &lde,
        &points,
        table,
        params.value,
        params.n_rows,
        alpha_member,
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
        openings.push(TableOpening {
            index,
            v: lde[index],
            path: tree.prove_capped(index, drop)?,
        });
    }

    Ok(Proof {
        column_cap,
        fri_commitment,
        fri_proof,
        openings,
    })
}

/// Verify a membership [`Proof`] against the public `table`.
///
/// # Errors
/// Returns [`Error::FriVerificationFailed`] or [`Error::BadMerklePath`] on
/// any failed check.
pub fn verify(
    params: Params,
    table: &[Field],
    proof: &Proof,
    transcript: &mut Transcript,
) -> Result<()> {
    check_table(table)?;
    // Domain size comes from the commitment: ZK proofs use larger (masked)
    // LDEs than `params.lde_len()`. FRI binding keeps this sound.
    let m = proof.fri_commitment.lde_len;
    absorb_params(params, table, transcript);

    if proof.openings.len() != params.num_queries {
        return Err(Error::FriVerificationFailed);
    }
    transcript.absorb(
        b"table/column",
        &crate::merkle::cap_bytes(&proof.column_cap),
    );
    let alpha_member = transcript.challenge_bb(b"table/alpha");
    let alpha_bound = transcript.challenge_bb(b"table/alpha");

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
        if opening.index != index {
            return Err(Error::FriVerificationFailed);
        }
        // Shapes are pinned first: the cap holds exactly `2^drop`
        // digests and every path is exactly `depth - drop` steps, so
        // malformed proofs fail before any hashing.
        let (drop, depth) = crate::merkle::capped_shape(m, params.cap_height);
        if proof.column_cap.len() != 1usize << drop || opening.path.len() != depth - drop {
            return Err(Error::BadMerklePath);
        }
        let entry = proof
            .column_cap
            .get(index >> (depth - drop))
            .ok_or(Error::BadMerklePath)?;
        if !MerkleTree::verify_capped(entry, &opening.v.to_le_bytes(), index, depth, &opening.path)
        {
            return Err(Error::BadMerklePath);
        }
        let expected = composition_at(
            opening.v,
            // On-demand domain point (one `pow` per query): identical to
            // the full vector, negligible work.
            lde_point_at(m, index)?,
            table,
            params.value,
            params.n_rows,
            alpha_member,
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

fn absorb_params(params: Params, table: &[Field], transcript: &mut Transcript) {
    let mut buf = Vec::with_capacity(32 + 4 * table.len());
    buf.extend_from_slice(&(params.n_rows as u64).to_le_bytes());
    buf.extend_from_slice(&(params.blowup as u64).to_le_bytes());
    buf.extend_from_slice(&(params.num_queries as u64).to_le_bytes());
    buf.extend_from_slice(&(params.final_size as u64).to_le_bytes());
    buf.extend_from_slice(&params.grinding_bits.to_le_bytes());
    buf.extend_from_slice(&(params.cap_height as u64).to_le_bytes());
    buf.extend_from_slice(&params.value.to_le_bytes());
    buf.extend_from_slice(&(table.len() as u64).to_le_bytes());
    for entry in table {
        buf.extend_from_slice(&entry.to_le_bytes());
    }
    transcript.absorb(b"table/params", &buf);
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

fn commit_evals(lde: &[Field]) -> Result<MerkleTree> {
    let mut flat = vec![0u8; 4 * lde.len()];
    for (slot, f) in flat.chunks_exact_mut(4).zip(lde.iter()) {
        slot.copy_from_slice(&f.to_le_bytes());
    }
    MerkleTree::from_flat(&flat, 4)
}

/// Full composition vector: vanishing-product and boundary quotients.
///
/// Batched like [`crate::air`] composition: vanishing geometric plus
/// Montgomery inversions per chunk, bit-identical to [`composition_at`].
fn compose(
    lde: &[Field],
    points: &[Field],
    table: &[Field],
    value: Field,
    n: usize,
    alpha_member: Field,
    alpha_bound: Field,
) -> Vec<Field> {
    if points.len() < 2 {
        // Degenerate (unreachable at real domain sizes): scalar fallback.
        return points
            .iter()
            .enumerate()
            .map(|(i, &point)| {
                composition_at(lde[i], point, table, value, n, alpha_member, alpha_bound)
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
            let mut product = Field::ONE;
            for &entry in table {
                product *= lde[i] - entry;
            }
            *slot = alpha_member * product * inv_z[j] + alpha_bound * (lde[i] - value) * inv_b[j];
        }
    });
    out
}

/// Composition value at one point. The vanishing product is zero on the
/// base rows exactly when the committed value lies in the table.
fn composition_at(
    v: Field,
    point: Field,
    table: &[Field],
    value: Field,
    n: usize,
    alpha_member: Field,
    alpha_bound: Field,
) -> Field {
    let vanishing = point.pow(n as u64) - Field::ONE;
    let z_inv = vanishing.inv();
    let mut product = Field::ONE;
    for &entry in table {
        product *= v - entry;
    }
    alpha_member * product * z_inv + alpha_bound * (v - value) * (point - Field::ONE).inv()
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

    fn table() -> Vec<Field> {
        vec![
            Field::new(10),
            Field::new(20),
            Field::new(30),
            Field::new(40),
        ]
    }

    fn test_params(value: u32) -> Params {
        Params::new(8, 8, 8, 4, Field::new(value)).unwrap()
    }

    #[test]
    fn rejects_bad_params() {
        assert!(Params::new(3, 8, 8, 4, Field::ONE).is_err());
        assert!(Params::new(8, 1, 8, 4, Field::ONE).is_err());
        assert!(Params::new(8, 8, 0, 4, Field::ONE).is_err());
        let params = test_params(20);
        let mut t = Transcript::new(b"table-shape");
        assert!(prove(params, &[Field::ONE], &mut t).is_err());
        assert!(prove(params, &[], &mut t).is_err());
    }

    #[test]
    fn honest_member_verifies() {
        for value in [10u32, 20, 30, 40] {
            let params = test_params(value);
            let mut prover_t = Transcript::new(b"table-e2e");
            let proof = prove(params, &table(), &mut prover_t).unwrap();
            let mut verifier_t = Transcript::new(b"table-e2e");
            verify(params, &table(), &proof, &mut verifier_t).unwrap();
        }
    }

    #[test]
    fn for_security_roundtrip() {
        // Four-entry table: bound 20 over LDE 128 needs blowup 16.
        let params = Params::for_security(8, 4, Field::new(30), 12).unwrap();
        assert_eq!(params.blowup, 16);
        assert_eq!((params.num_queries, params.grinding_bits), (6, 6));
        assert!(params.cap_height <= 4);
        let mut prover_t = Transcript::new(b"table-forsec");
        let proof = prove(params, &table(), &mut prover_t).unwrap();
        let mut verifier_t = Transcript::new(b"table-forsec");
        verify(params, &table(), &proof, &mut verifier_t).unwrap();

        assert!(Params::for_security(3, 4, Field::ONE, 12).is_err());
        assert!(Params::for_security(8, 1, Field::ONE, 12).is_err());
    }

    #[test]
    fn truncated_and_swapped_openings_fail() {
        let params = test_params(30);
        let mut prover_t = Transcript::new(b"table-shape");
        let proof = prove(params, &table(), &mut prover_t).unwrap();
        let mut short = proof.clone();
        short.openings.pop();
        let mut verifier_t = Transcript::new(b"table-shape");
        assert!(verify(params, &table(), &short, &mut verifier_t).is_err());
        let mut swapped = proof.clone();
        swapped.openings.swap(0, 1);
        let mut verifier_t = Transcript::new(b"table-shape");
        assert!(verify(params, &table(), &swapped, &mut verifier_t).is_err());
    }

    #[test]
    fn cap_mismatch_rejects() {
        let capped = test_params(30).with_cap_height(2);
        let mut prover_t = Transcript::new(b"table-capmix");
        let proof = prove(capped, &table(), &mut prover_t).unwrap();
        let plain = test_params(30);
        let mut verifier_t = Transcript::new(b"table-capmix");
        assert!(verify(plain, &table(), &proof, &mut verifier_t).is_err());

        let mut prover_t = Transcript::new(b"table-capmix");
        let plain_proof = prove(plain, &table(), &mut prover_t).unwrap();
        let mut verifier_t = Transcript::new(b"table-capmix");
        assert!(verify(capped, &table(), &plain_proof, &mut verifier_t).is_err());
    }

    #[test]
    fn encoding_roundtrip_and_rejects() {
        for (label, params) in [
            ("table-codec", test_params(30)),
            ("table-codec-cap", test_params(30).with_cap_height(2)),
        ] {
            let mut prover_t = Transcript::new(label.as_bytes());
            let proof = prove(params, &table(), &mut prover_t).unwrap();
            let bytes = proof.to_bytes();
            assert_eq!(Proof::from_bytes(&bytes).unwrap(), proof);
            // Decoded proofs verify: catches mirrored encode/decode bugs
            // that a pure roundtrip would miss.
            let mut verifier_t = Transcript::new(label.as_bytes());
            verify(
                params,
                &table(),
                &Proof::from_bytes(&bytes).unwrap(),
                &mut verifier_t,
            )
            .unwrap();
            assert!(Proof::from_bytes(&bytes[..bytes.len() - 1]).is_err());
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(Proof::from_bytes(&trailing).is_err());
        }
    }

    #[test]
    fn capped_roundtrip() {
        let params = test_params(30).with_cap_height(2);
        let mut prover_t = Transcript::new(b"table-cap");
        let proof = prove(params, &table(), &mut prover_t).unwrap();
        assert_eq!(proof.column_cap.len(), 4);
        // Column paths shrink by the cap height (depth 6 -> 4 steps).
        for opening in &proof.openings {
            assert_eq!(opening.path.len(), 4);
        }
        let mut verifier_t = Transcript::new(b"table-cap");
        verify(params, &table(), &proof, &mut verifier_t).unwrap();

        // Forged cap entry fails.
        let mut bad = proof.clone();
        bad.column_cap[0][0] ^= 1;
        let mut verifier_t = Transcript::new(b"table-cap");
        assert!(verify(params, &table(), &bad, &mut verifier_t).is_err());
    }

    #[test]
    fn non_member_rejected() {
        // P(99) is a nonzero constant over Z_H: dense interpolant, refused.
        let params = test_params(99);
        let mut prover_t = Transcript::new(b"table-nonmember");
        let proof = prove(params, &table(), &mut prover_t).unwrap();
        let mut verifier_t = Transcript::new(b"table-nonmember");
        assert!(verify(params, &table(), &proof, &mut verifier_t).is_err());
    }

    #[test]
    fn tampered_opening_fails() {
        let params = test_params(30);
        let mut prover_t = Transcript::new(b"table-tamper");
        let mut proof = prove(params, &table(), &mut prover_t).unwrap();
        proof.openings[0].v += Field::ONE;
        let mut verifier_t = Transcript::new(b"table-tamper");
        assert!(verify(params, &table(), &proof, &mut verifier_t).is_err());
    }

    #[test]
    fn wrong_table_fails() {
        let params = test_params(20);
        let mut prover_t = Transcript::new(b"table-wrong");
        let proof = prove(params, &table(), &mut prover_t).unwrap();
        let mut other = table();
        other[1] = Field::new(21);
        let mut verifier_t = Transcript::new(b"table-wrong");
        assert!(verify(params, &other, &proof, &mut verifier_t).is_err());
    }

    #[test]
    fn wrong_claim_fails() {
        let params = test_params(20);
        let mut prover_t = Transcript::new(b"table-claim");
        let proof = prove(params, &table(), &mut prover_t).unwrap();
        let mut bad = params;
        bad.value = Field::new(30);
        let mut verifier_t = Transcript::new(b"table-claim");
        assert!(verify(bad, &table(), &proof, &mut verifier_t).is_err());
    }

    #[test]
    fn bound_formula() {
        // |T| = 4, n = 8: vanishing numerator `4 * 7`, over degree-8 Z_H.
        assert_eq!(membership_bound(4, 8, 0), 20);
        assert_eq!(membership_bound(4, 8, 8), 52);
    }

    fn zk_rng() -> crate::rng::ChaCha20 {
        crate::rng::ChaCha20::new([55u8; 32], [66u8; 12])
    }

    /// ZK variant: masked LDEs are larger (M = 128), so the final size must
    /// give a power-of-four ratio (128 / 8).
    fn test_params_zk(value: u32) -> Params {
        Params::new(8, 8, 8, 8, Field::new(value)).unwrap()
    }

    #[test]
    fn zk_member_verifies_with_same_verify() {
        let params = test_params_zk(40);
        let mut prover_t = Transcript::new(b"table-zk");
        let proof = prove_zk(params, &table(), 8, &mut zk_rng(), &mut prover_t).unwrap();
        let mut verifier_t = Transcript::new(b"table-zk");
        verify(params, &table(), &proof, &mut verifier_t).unwrap();
    }

    #[test]
    fn zk_openings_hide_value() {
        // Same table, two different members, same stream position pattern:
        // blinded openings must differ from plain ones and from each other
        // only by randomness (here: differ from the plain opening).
        let params = test_params(10);
        let params_zk = test_params_zk(10);
        let mut t1 = Transcript::new(b"table-diverge");
        let plain = prove(params, &table(), &mut t1).unwrap();
        let mut t2 = Transcript::new(b"table-diverge");
        let blinded = prove_zk(params_zk, &table(), 8, &mut zk_rng(), &mut t2).unwrap();
        assert_ne!(plain.openings[0].v, blinded.openings[0].v);
        let mut t3 = Transcript::new(b"table-diverge");
        let rerun = prove_zk(params_zk, &table(), 8, &mut zk_rng(), &mut t3).unwrap();
        assert_eq!(blinded, rerun);
    }

    #[test]
    fn zk_non_member_still_rejected() {
        let params = test_params_zk(99);
        let mut prover_t = Transcript::new(b"table-zknon");
        let proof = prove_zk(params, &table(), 8, &mut zk_rng(), &mut prover_t).unwrap();
        let mut verifier_t = Transcript::new(b"table-zknon");
        assert!(verify(params, &table(), &proof, &mut verifier_t).is_err());
    }

    #[test]
    fn zk_rejects_few_maskers() {
        let params = test_params_zk(10);
        let mut t = Transcript::new(b"table-fewmask");
        assert!(prove_zk(
            params,
            &table(),
            params.num_queries - 1,
            &mut zk_rng(),
            &mut t
        )
        .is_err());
    }
}
