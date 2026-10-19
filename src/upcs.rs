//! FRI-backed univariate polynomial commitments with point evaluations (`v1`).
//!
//! [`commit`] fixes a coefficient polynomial in a Merkle tree over its
//! bit-reversed LDE on the [`LDE_SHIFT`] coset. [`open`] proves
//! `g(beta) = y` without revealing `g`:
//!
//! 1. FRI proves the committed `g` low-degree (bound `n - 1`,
//!    `n = poly_len`); its base Merkle root must equal the commitment root;
//! 2. the prover commits the quotient `q = (g - y) / (X - beta)` and proves
//!    it low-degree with a second FRI instance;
//! 3. the verifier samples the quotient's FRI query positions and checks
//!    `(X - beta) * q = g - y` at each, opening `g` there with a Merkle path.
//!
//! # Soundness
//!
//! FRI certifies both `g` and `q` are low-degree (their commitments are
//! bound to the transcript, and the `g` FRI base root is the statement
//! commitment). The difference `(X - beta) * q - (g - y)` then has degree
//! below `n`; it is checked at the quotient's `num_queries` random coset
//! points, so a nonzero difference is missed with probability at most
//! `(n - 1) / lde_len = 1 / blowup` per query. It is therefore the zero
//! polynomial and `g(beta) = y`.
//!
//! The commitment root, dimensions, point, and value are absorbed before
//! any challenge. Cap height must be `0` so the FRI base root (the
//! statement) covers every leaf the opening paths touch.
//!
//! # Scope (`v1`)
//!
//! Transparent (hash-only) and **not hiding**: FRI is a low-degree test,
//! not a zero-knowledge protocol. Proofs carry two FRI instances plus one
//! Merkle path per query. Batch and multi-point openings are roadmap work.
//!
//! [`LDE_SHIFT`]: crate::fri::LDE_SHIFT

use crate::babybear::Field;
use crate::codec::{Reader, Writer, MAX_QUERIES, VERSION};
use crate::error::{Error, Result};
use crate::fri::{self, LDE_SHIFT};
use crate::merkle::MerkleTree;
use crate::ntt;
use crate::transcript::Transcript;

/// Public commitment to a coefficient polynomial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment {
    /// Merkle root over the bit-reversed LDE evaluations (4-byte leaves).
    pub root: [u8; 32],
    /// Number of coefficients (`2^k`).
    pub poly_len: usize,
    /// LDE expansion factor used when committing.
    pub blowup: usize,
}

impl Commitment {
    /// Canonical bytes: version, root, dimensions.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.byte(VERSION);
        writer.bytes(&self.root);
        writer.u64_le(self.poly_len as u64);
        writer.u64_le(self.blowup as u64);
        writer.finish()
    }

    /// Decode [`Commitment::to_bytes`] output, rejecting anything else.
    ///
    /// Shape-checked only; soundness checks happen in [`verify`].
    ///
    /// # Errors
    /// Returns [`Error::MalformedInput`] on any encoding violation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        reader.version()?;
        let root = reader.digest()?;
        let poly_len = usize::try_from(reader.u64_le()?).map_err(|_| Error::MalformedInput {
            reason: "poly_len exceeds platform width",
        })?;
        let blowup = usize::try_from(reader.u64_le()?).map_err(|_| Error::MalformedInput {
            reason: "blowup exceeds platform width",
        })?;
        reader.end()?;
        Ok(Self {
            root,
            poly_len,
            blowup,
        })
    }
}

/// Prover-side commitment data: coefficients, LDE, and evaluation tree.
#[derive(Clone, Debug)]
pub struct ProverState {
    coeffs: Vec<Field>,
    lde: Vec<Field>,
    tree: MerkleTree,
    commitment: Commitment,
}

impl ProverState {
    /// The public commitment.
    #[must_use]
    pub const fn commitment(&self) -> &Commitment {
        &self.commitment
    }

    /// Coefficients in ascending order.
    #[must_use]
    pub fn coeffs(&self) -> &[Field] {
        &self.coeffs
    }
}

/// One Merkle opening of the committed polynomial at a query position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opening {
    /// Claimed evaluation at the position.
    pub value: Field,
    /// Full Merkle path (leaf to root).
    pub path: Vec<([u8; 32], bool)>,
}

/// Evaluation-opening proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// FRI commitment to `g` (base root equals the statement commitment).
    pub g_commitment: fri::Commitment,
    /// FRI low-degree proof for `g`.
    pub g_fri: fri::Proof,
    /// FRI commitment to the quotient `(g - y) / (X - beta)`.
    pub q_commitment: fri::Commitment,
    /// FRI low-degree proof for the quotient.
    pub q_fri: fri::Proof,
    /// Openings of `g` at the quotient's query positions, in FRI order.
    pub openings: Vec<Opening>,
}

impl Proof {
    /// Canonical bytes: version, both FRI commitment/proof pairs, then one
    /// `(value, path)` group per quotient query.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.byte(VERSION);
        self.g_commitment.write_body(&mut writer);
        self.g_fri.write_body(&mut writer);
        self.q_commitment.write_body(&mut writer);
        self.q_fri.write_body(&mut writer);
        writer.count(self.openings.len());
        for opening in &self.openings {
            writer.field(opening.value);
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
        let mut reader = Reader::new(bytes);
        reader.version()?;
        let g_commitment = fri::Commitment::read_body(&mut reader)?;
        let g_fri = fri::Proof::read_body(&mut reader)?;
        let q_commitment = fri::Commitment::read_body(&mut reader)?;
        let q_fri = fri::Proof::read_body(&mut reader)?;
        let mut openings = Vec::new();
        for _ in 0..reader.count(MAX_QUERIES)? {
            openings.push(Opening {
                value: reader.field()?,
                path: reader.path()?,
            });
        }
        reader.end()?;
        Ok(Self {
            g_commitment,
            g_fri,
            q_commitment,
            q_fri,
            openings,
        })
    }
}

/// Commit to `coeffs` with the given LDE `blowup`.
///
/// The tree covers `coeffs.len() * blowup` bit-reversed coset evaluations.
///
/// # Errors
/// Returns [`Error::EmptyInput`] for empty coefficients,
/// [`Error::InvalidDomainSize`] for non-power-of-two lengths or oversized
/// domains, and [`Error::InvalidBlowup`] for a blowup below two or not a
/// power of two.
pub fn commit(coeffs: &[Field], blowup: usize) -> Result<ProverState> {
    let lde_len = check_dims(coeffs.len(), blowup)?;
    let mut lde = ntt::evaluate_on_coset(coeffs, blowup, LDE_SHIFT)?;
    ntt::bit_reverse_permute(&mut lde);
    if lde.len() != lde_len {
        return Err(Error::InvalidDomainSize { size: lde.len() });
    }
    let tree = tree_over(&lde)?;
    let commitment = Commitment {
        root: tree.root(),
        poly_len: coeffs.len(),
        blowup,
    };
    Ok(ProverState {
        coeffs: coeffs.to_vec(),
        lde,
        tree,
        commitment,
    })
}

/// Prove `g(beta) = value`, with FRI low-degree proofs for `g` and its
/// quotient.
///
/// `params.blowup` must match the commitment's blowup, `params.cap_height`
/// must be `0`, and `value` must be the true evaluation.
///
/// # Errors
/// Returns [`Error::MalformedInput`] when `value` is not the evaluation or
/// the cap height is nonzero, [`Error::InvalidBlowup`] on parameter
/// mismatch, or any FRI/Merkle error.
pub fn open(
    state: &ProverState,
    point: Field,
    value: Field,
    params: fri::Params,
    transcript: &mut Transcript,
) -> Result<Proof> {
    if state.commitment.blowup != params.blowup {
        return Err(Error::InvalidBlowup {
            factor: params.blowup,
        });
    }
    if params.cap_height != 0 {
        return Err(Error::MalformedInput {
            reason: "upcs openings require cap_height = 0",
        });
    }
    if ntt::evaluate(&state.coeffs, point) != value {
        return Err(Error::MalformedInput {
            reason: "claimed evaluation does not match the committed polynomial",
        });
    }
    let quotient = quotient(&state.coeffs, point, value)?;
    open_with_quotient(state, point, value, &quotient, params, transcript)
}

/// Prover body with an explicit quotient.
///
/// Exposed to tests so the verifier's quotient check can be exercised with a
/// deliberately wrong quotient.
fn open_with_quotient(
    state: &ProverState,
    point: Field,
    value: Field,
    quotient: &[Field],
    params: fri::Params,
    transcript: &mut Transcript,
) -> Result<Proof> {
    absorb_statement(transcript, &state.commitment, point, value);

    // Low-degree proof for `g`, and cross-check that the FRI base tree is the
    // statement commitment (both cover the same bit-reversed LDE).
    let g_state = fri::commit(&state.coeffs, params, transcript)?;
    let g_commitment = fri::public_commitment(&g_state);
    if g_commitment.caps.first().and_then(|cap| cap.first()) != Some(&state.commitment.root) {
        return Err(Error::MalformedInput {
            reason: "FRI base root does not match the commitment root",
        });
    }
    let (g_fri, _) = fri::open(&g_state, transcript)?;

    // Low-degree proof for the quotient; its query points drive the
    // evaluation check.
    let q_state = fri::commit(quotient, params, transcript)?;
    let q_commitment = fri::public_commitment(&q_state);
    let (q_fri, indices) = fri::open(&q_state, transcript)?;

    let mut openings = Vec::with_capacity(indices.len());
    for index in indices {
        openings.push(Opening {
            value: state.lde[index],
            path: state.tree.prove(index)?,
        });
    }
    Ok(Proof {
        g_commitment,
        g_fri,
        q_commitment,
        q_fri,
        openings,
    })
}

/// Verify `g(beta) = value` against a commitment.
///
/// # Errors
/// Returns [`Error::FriVerificationFailed`] when any check fails,
/// [`Error::BadMerklePath`] for malformed openings, or dimension errors for
/// invalid commitments or nonzero cap heights.
pub fn verify(
    commitment: &Commitment,
    point: Field,
    value: Field,
    proof: &Proof,
    params: fri::Params,
    transcript: &mut Transcript,
) -> Result<()> {
    let lde_len = check_dims(commitment.poly_len, commitment.blowup)?;
    if commitment.blowup != params.blowup {
        return Err(Error::InvalidBlowup {
            factor: params.blowup,
        });
    }
    if params.cap_height != 0 {
        return Err(Error::MalformedInput {
            reason: "upcs openings require cap_height = 0",
        });
    }
    absorb_statement(transcript, commitment, point, value);

    // Replay both FRI instances in the prover's order. The first query set is
    // unused beyond the low-degree check; the quotient's drives the opening.
    fri::verify(&proof.g_commitment, &proof.g_fri, params, transcript)?;
    let indices = fri::verify(&proof.q_commitment, &proof.q_fri, params, transcript)?;

    if proof.g_commitment.lde_len != lde_len
        || proof.g_commitment.poly_len != commitment.poly_len
        || proof.g_commitment.degree_bound != commitment.poly_len - 1
        || proof.g_commitment.caps.first().and_then(|cap| cap.first()) != Some(&commitment.root)
        || proof.q_commitment.lde_len != lde_len
        || proof.q_commitment.poly_len != commitment.poly_len
        || proof.q_commitment.degree_bound != commitment.poly_len - 1
        || proof.g_commitment.caps.len() < 2
        || proof.q_commitment.caps.len() < 2
        || proof.openings.len() != indices.len()
    {
        return Err(Error::FriVerificationFailed);
    }
    let depth = usize::try_from(lde_len.trailing_zeros())
        .map_err(|_| Error::InvalidDomainSize { size: lde_len })?;

    for ((query, opening), &index) in proof
        .q_fri
        .queries
        .iter()
        .zip(&proof.openings)
        .zip(&indices)
    {
        let Some(fold) = query.folds.first() else {
            return Err(Error::FriVerificationFailed);
        };
        let base = index / 4 * 4;
        let Some(q_value) = fold.values.get(index - base) else {
            return Err(Error::FriVerificationFailed);
        };
        if opening.path.len() != depth {
            return Err(Error::BadMerklePath);
        }
        if !MerkleTree::verify(
            &commitment.root,
            &opening.value.to_le_bytes(),
            index,
            &opening.path,
        ) {
            return Err(Error::BadMerklePath);
        }
        let z = fri::point_at(lde_len, 0, index)?;
        if (z - point) * *q_value != opening.value - value {
            return Err(Error::FriVerificationFailed);
        }
    }
    Ok(())
}

/// Validate commitment dimensions and return the LDE length.
fn check_dims(poly_len: usize, blowup: usize) -> Result<usize> {
    if poly_len == 0 {
        return Err(Error::EmptyInput);
    }
    if !poly_len.is_power_of_two() {
        return Err(Error::InvalidDomainSize { size: poly_len });
    }
    if blowup < 2 || !blowup.is_power_of_two() {
        return Err(Error::InvalidBlowup { factor: blowup });
    }
    let lde_len = poly_len
        .checked_mul(blowup)
        .ok_or(Error::InvalidDomainSize { size: poly_len })?;
    if lde_len > (1usize << Field::TWO_ADICITY) {
        return Err(Error::InvalidDomainSize { size: lde_len });
    }
    Ok(lde_len)
}

/// Absorb the statement before deriving any challenge.
fn absorb_statement(
    transcript: &mut Transcript,
    commitment: &Commitment,
    point: Field,
    value: Field,
) {
    transcript.absorb(b"upcs/root", &commitment.root);
    let mut writer = Writer::new();
    writer.u64_le(commitment.poly_len as u64);
    writer.u64_le(commitment.blowup as u64);
    writer.field(point);
    writer.field(value);
    transcript.absorb(b"upcs/statement", &writer.finish());
}

/// Merkle tree over 4-byte LDE leaves.
fn tree_over(lde: &[Field]) -> Result<MerkleTree> {
    let mut flat = vec![0u8; 4 * lde.len()];
    for (chunk, value) in flat.chunks_exact_mut(4).zip(lde) {
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    MerkleTree::from_flat(&flat, 4)
}

/// Synthetic division `(g - value) / (X - point)`, padded to `deg(g) + 1`.
///
/// Returns [`Error::MalformedInput`] when the division is not exact (the
/// claimed value is wrong). The quotient's leading coefficient is zero.
fn quotient(coeffs: &[Field], point: Field, value: Field) -> Result<Vec<Field>> {
    let n = coeffs.len();
    let mut q = vec![Field::ZERO; n];
    if n == 1 {
        if coeffs[0] != value {
            return Err(Error::MalformedInput {
                reason: "claimed evaluation does not divide the polynomial",
            });
        }
        return Ok(q);
    }
    // Descending synthetic division by (X - point).
    let mut carry = coeffs[n - 1];
    q[n - 2] = carry;
    for i in (1..n - 1).rev() {
        carry = coeffs[i] + point * carry;
        q[i - 1] = carry;
    }
    let remainder = (coeffs[0] - value) + point * q[0];
    if remainder != Field::ZERO {
        return Err(Error::MalformedInput {
            reason: "claimed evaluation does not divide the polynomial",
        });
    }
    Ok(q)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(poly_len: usize) -> fri::Params {
        let blowup = 8;
        let lde_len = poly_len * blowup;
        let log_m = lde_len.trailing_zeros();
        let final_size = if log_m % 2 == 0 { 4 } else { 2 };
        fri::Params::new(blowup, 8, final_size).unwrap()
    }

    fn poly(n: usize) -> Vec<Field> {
        (0..n)
            .map(|i| Field::new(u32::try_from(i).unwrap() * 7 + 3))
            .collect()
    }

    fn prove_roundtrip(coeffs: &[Field], point: Field) -> (Commitment, fri::Params, Field, Proof) {
        let params = params(coeffs.len());
        let state = commit(coeffs, params.blowup).unwrap();
        let commitment = state.commitment().clone();
        let value = ntt::evaluate(coeffs, point);
        let mut prover_t = Transcript::new(b"upcs-test");
        let proof = open(&state, point, value, params, &mut prover_t).unwrap();
        (commitment, params, value, proof)
    }

    fn verify_with(
        commitment: &Commitment,
        point: Field,
        value: Field,
        proof: &Proof,
        params: fri::Params,
    ) -> Result<()> {
        let mut verifier_t = Transcript::new(b"upcs-test");
        verify(commitment, point, value, proof, params, &mut verifier_t)
    }

    #[test]
    fn honest_openings_verify() {
        for n in [1usize, 2, 4, 8, 16, 64] {
            let coeffs = poly(n);
            for point in [Field::ZERO, Field::ONE, Field::new(7), Field::new(123_456)] {
                let (commitment, params, value, proof) = prove_roundtrip(&coeffs, point);
                verify_with(&commitment, point, value, &proof, params).unwrap();
            }
        }
    }

    #[test]
    fn wrong_value_is_rejected() {
        let coeffs = poly(8);
        let point = Field::new(5);
        let (commitment, params, value, proof) = prove_roundtrip(&coeffs, point);
        assert!(verify_with(&commitment, point, value + Field::ONE, &proof, params).is_err());
        assert!(verify_with(&commitment, point, value, &proof, params).is_ok());
    }

    #[test]
    fn wrong_point_is_rejected() {
        let coeffs = poly(16);
        let point = Field::new(9);
        let (commitment, params, value, proof) = prove_roundtrip(&coeffs, point);
        assert!(verify_with(&commitment, point + Field::ONE, value, &proof, params).is_err());
    }

    #[test]
    fn wrong_commitment_is_rejected() {
        let coeffs = poly(8);
        let point = Field::new(3);
        let (_, params, value, proof) = prove_roundtrip(&coeffs, point);
        let mut other = coeffs.clone();
        other[0] += Field::ONE;
        let state = commit(&other, params.blowup).unwrap();
        assert!(verify_with(state.commitment(), point, value, &proof, params).is_err());
    }

    #[test]
    fn tampered_leaf_is_rejected() {
        let coeffs = poly(8);
        let point = Field::new(11);
        let (commitment, params, value, mut proof) = prove_roundtrip(&coeffs, point);
        proof.openings[0].value += Field::ONE;
        assert!(verify_with(&commitment, point, value, &proof, params).is_err());
    }

    #[test]
    fn tampered_path_is_rejected() {
        let coeffs = poly(8);
        let point = Field::new(13);
        let (commitment, params, value, mut proof) = prove_roundtrip(&coeffs, point);
        let (sibling, _) = proof.openings[0].path[0];
        let mut flipped = sibling;
        flipped[0] ^= 1;
        proof.openings[0].path[0].0 = flipped;
        assert!(verify_with(&commitment, point, value, &proof, params).is_err());
    }

    #[test]
    fn tampered_commitments_are_rejected() {
        let coeffs = poly(8);
        let point = Field::new(17);
        let (commitment, params, value, mut proof) = prove_roundtrip(&coeffs, point);
        proof.g_commitment.caps[0][0][0] ^= 1;
        assert!(verify_with(&commitment, point, value, &proof, params).is_err());

        let (commitment, params, value, mut proof) = prove_roundtrip(&coeffs, point);
        proof.q_commitment.caps[0][0][0] ^= 1;
        assert!(verify_with(&commitment, point, value, &proof, params).is_err());
    }

    #[test]
    fn tampered_fri_proof_is_rejected() {
        let coeffs = poly(8);
        let point = Field::new(19);
        let (commitment, params, value, mut proof) = prove_roundtrip(&coeffs, point);
        proof.q_fri.queries[0].folds[0].values[0] += Field::ONE;
        assert!(verify_with(&commitment, point, value, &proof, params).is_err());

        let (commitment, params, value, mut proof) = prove_roundtrip(&coeffs, point);
        proof.g_fri.queries[0].folds[0].values[0] += Field::ONE;
        assert!(verify_with(&commitment, point, value, &proof, params).is_err());

        let (commitment, params, value, mut proof) = prove_roundtrip(&coeffs, point);
        proof.q_commitment.lde_len *= 2;
        assert!(verify_with(&commitment, point, value, &proof, params).is_err());
    }

    #[test]
    fn wrong_quotient_is_rejected() {
        let coeffs = poly(8);
        let point = Field::new(23);
        let value = ntt::evaluate(&coeffs, point);
        let params = params(coeffs.len());
        let state = commit(&coeffs, params.blowup).unwrap();
        let mut bad = quotient(&coeffs, point, value).unwrap();
        bad[0] += Field::ONE;
        let mut prover_t = Transcript::new(b"upcs-test");
        let proof = open_with_quotient(&state, point, value, &bad, params, &mut prover_t).unwrap();
        assert!(verify_with(state.commitment(), point, value, &proof, params).is_err());
    }

    #[test]
    fn malformed_proofs_fail_closed() {
        let coeffs = poly(8);
        let point = Field::new(29);
        let (commitment, params, value, proof) = prove_roundtrip(&coeffs, point);
        let bytes = proof.to_bytes();
        assert_eq!(Proof::from_bytes(&bytes).unwrap(), proof);
        assert!(Proof::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(Proof::from_bytes(&trailing).is_err());
        let mut wrong_version = bytes.clone();
        wrong_version[0] ^= 0xff;
        assert!(Proof::from_bytes(&wrong_version).is_err());

        let mut short = proof.clone();
        short.openings[0].path.pop();
        assert!(verify_with(&commitment, point, value, &short, params).is_err());

        let mut duplicated = proof;
        let extra = duplicated.openings[0].clone();
        duplicated.openings.push(extra);
        assert!(verify_with(&commitment, point, value, &duplicated, params).is_err());
    }

    #[test]
    fn commitments_roundtrip_and_reject_garbage() {
        let state = commit(&poly(8), 8).unwrap();
        let bytes = state.commitment().to_bytes();
        assert_eq!(Commitment::from_bytes(&bytes).unwrap(), *state.commitment());
        assert!(Commitment::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(Commitment::from_bytes(&trailing).is_err());
    }

    #[test]
    fn rejects_bad_commitment_shapes() {
        assert!(commit(&[], 8).is_err());
        assert!(commit(&poly(6), 8).is_err());
        assert!(commit(&poly(8), 1).is_err());
        assert!(commit(&poly(8), 3).is_err());
        let state = commit(&poly(8), 8).unwrap();
        let mut bad = state.commitment().clone();
        bad.poly_len = 6;
        let point = Field::new(2);
        let value = ntt::evaluate(&poly(8), point);
        let mut prover_t = Transcript::new(b"upcs-test");
        let proof = open(&state, point, value, params(8), &mut prover_t).unwrap();
        assert!(verify_with(&bad, point, value, &proof, params(8)).is_err());
    }

    #[test]
    fn open_rejects_wrong_value_and_blowup() {
        let coeffs = poly(8);
        let point = Field::new(31);
        let state = commit(&coeffs, 8).unwrap();
        let value = ntt::evaluate(&coeffs, point);
        let mut transcript = Transcript::new(b"upcs-test");
        assert!(open(
            &state,
            point,
            value + Field::ONE,
            params(8),
            &mut transcript
        )
        .is_err());
        let mut transcript = Transcript::new(b"upcs-test");
        let other = fri::Params::new(16, 8, 8).unwrap();
        assert!(open(&state, point, value, other, &mut transcript).is_err());
        let mut capped = params(8);
        capped.cap_height = 1;
        let mut transcript = Transcript::new(b"upcs-test");
        assert!(open(&state, point, value, capped, &mut transcript).is_err());
    }

    #[test]
    fn statement_is_transcript_bound() {
        let coeffs = poly(8);
        let point = Field::new(37);
        let (commitment, params, value, proof) = prove_roundtrip(&coeffs, point);
        let mut other_t = Transcript::new(b"upcs-other-domain");
        assert!(verify(&commitment, point, value, &proof, params, &mut other_t).is_err());
    }
}
