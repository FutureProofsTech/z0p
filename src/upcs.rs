//! FRI-backed univariate polynomial commitments with point evaluations (`v1`).
//!
//! [`commit`] fixes a coefficient polynomial in a Merkle tree over its
//! bit-reversed LDE on the [`LDE_SHIFT`] coset. [`open`] proves
//! `g(beta) = y` without revealing `g`:
//!
//! 1. FRI proves the committed `g` low-degree (bound `n - 1`,
//!    `n = poly_len`); its base Merkle root must equal the commitment root;
//! 2. the prover commits the quotient `q = (g - y) / (X - beta)` with
//!    degree bound `n - 2` and proves it low-degree with a second FRI
//!    instance;
//! 3. the verifier samples the quotient's FRI query positions and checks
//!    `(X - beta) * q = g - y` at each, opening `g` there with a Merkle path.
//!
//! [`open_multi`] generalises this to `g(p_j) = y_j` for `k` distinct
//! points. Let `I` interpolate the claims and `Z = prod_j (X - p_j)`; the
//! prover commits `q = (g - I) / Z` with degree bound `n - k - 1` and the
//! verifier checks `g(z) = I(z) + Z(z) q(z)` at the quotient's query
//! points. When `k = n`, `I` determines `g` and `q` is the zero polynomial.
//! At most [`MAX_POINTS`] points and at most `n` points are accepted.
//!
//! # Soundness
//!
//! FRI certifies both `g` and `q` are low-degree (their commitments are
//! bound to the transcript, and the `g` FRI base root is the statement
//! commitment). The identity difference then has degree below `n`; it is
//! checked at the quotient's `num_queries` random coset points, so a
//! nonzero difference is missed with probability at most
//! `(n - 1) / lde_len = 1 / blowup` per query. For multi-point openings the
//! same bound holds: `g - I - Z q` has degree below `n`, because `q` has
//! degree below `n - k`. It is therefore the zero polynomial and all
//! claimed evaluations are correct.
//!
//! The commitment root, dimensions, points, and values are absorbed before
//! any challenge. Cap height must be `0` so the FRI base root (the
//! statement) covers every leaf the opening paths touch.
//!
//! # Scope (`v1`)
//!
//! Transparent (hash-only) and **not hiding**: FRI is a low-degree test,
//! not a zero-knowledge protocol. Proofs carry two FRI instances plus one
//! Merkle path per query. Single- and multi-point openings for one
//! polynomial are implemented; batching across distinct polynomials is
//! roadmap work.
//!
//! [`LDE_SHIFT`]: crate::fri::LDE_SHIFT

use crate::babybear::Field;
use crate::codec::{Reader, Writer, MAX_QUERIES, VERSION};
use crate::error::{Error, Result};
use crate::ext4::Ext4;
use crate::fri::{self, LDE_SHIFT};
use crate::merkle::MerkleTree;
use crate::ntt;
use crate::transcript::Transcript;

/// Maximum number of distinct points in one multi-point opening.
pub const MAX_POINTS: usize = 16;

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
    coeffs: Vec<Ext4>,
    lde: Vec<Ext4>,
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
    pub fn coeffs(&self) -> &[Ext4] {
        &self.coeffs
    }
}

/// One Merkle opening of the committed polynomial at a query position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opening {
    /// Claimed evaluation at the position.
    pub value: Ext4,
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
            writer.ext4(opening.value);
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
                value: reader.ext4()?,
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
    let coeffs: Vec<Ext4> = coeffs.iter().copied().map(Ext4::from_base).collect();
    commit_ext(&coeffs, blowup)
}

/// Commit extension-field coefficients.
///
/// # Errors
/// Same shape errors as [`commit`].
pub fn commit_ext(coeffs: &[Ext4], blowup: usize) -> Result<ProverState> {
    let lde_len = check_dims(coeffs.len(), blowup)?;
    let mut lde = ntt::evaluate_on_coset_ext(coeffs, blowup, LDE_SHIFT)?;
    ntt::bit_reverse_permute_ext(&mut lde);
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
    point: Ext4,
    value: Ext4,
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
    if ntt::evaluate_ext(&state.coeffs, point) != value {
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
    point: Ext4,
    value: Ext4,
    quotient: &[Ext4],
    params: fri::Params,
    transcript: &mut Transcript,
) -> Result<Proof> {
    absorb_statement(transcript, &state.commitment, point, value);

    // Low-degree proof for `g`, and cross-check that the FRI base tree is the
    // statement commitment (both cover the same bit-reversed LDE).
    let g_state = fri::commit_ext(&state.coeffs, params, transcript)?;
    let g_commitment = fri::public_commitment(&g_state);
    if g_commitment.caps.first().and_then(|cap| cap.first()) != Some(&state.commitment.root) {
        return Err(Error::MalformedInput {
            reason: "FRI base root does not match the commitment root",
        });
    }
    let (g_fri, _) = fri::open(&g_state, transcript)?;

    // Low-degree proof for the quotient; its query points drive the
    // evaluation check. The true quotient has degree at most `n - 2`, so
    // declare that tight bound rather than the commitment default `n - 1`.
    let mut padded = quotient.to_vec();
    padded.resize(state.commitment.poly_len, Ext4::ZERO);
    let q_lde = ntt::evaluate_on_coset_ext(&padded, params.blowup, LDE_SHIFT)?;
    let degree_bound = state.commitment.poly_len.saturating_sub(2);
    let q_state = fri::commit_ext_evals(&q_lde, degree_bound, params, transcript)?;
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

/// Prove `g(point_j) = value_j` for several distinct points with one
/// quotient and one FRI pair.
///
/// Values are computed from the committed polynomial and returned in point
/// order. The quotient is `(g - I) / Z`, where `I` interpolates the claims
/// and `Z = prod_j (X - point_j)`. When the point count equals the
/// coefficient count, `I` determines `g` and the quotient is zero.
///
/// # Errors
/// Returns [`Error::MalformedInput`] for an empty, duplicate, oversized, or
/// too-long point set, [`Error::InvalidBlowup`] on parameter mismatch, and
/// propagates FRI/Merkle errors.
pub fn open_multi(
    state: &ProverState,
    points: &[Ext4],
    params: fri::Params,
    transcript: &mut Transcript,
) -> Result<(Proof, Vec<Ext4>)> {
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
    if points.is_empty() {
        return Err(Error::EmptyInput);
    }
    if points.len() > MAX_POINTS {
        return Err(Error::MalformedInput {
            reason: "too many multi-point openings",
        });
    }
    let values: Vec<Ext4> = points
        .iter()
        .map(|point| ntt::evaluate_ext(&state.coeffs, *point))
        .collect();
    check_points(state.commitment.poly_len, points, &values)?;

    let (quotient, degree_bound) = if points.len() == state.commitment.poly_len {
        (vec![Ext4::ZERO], 0)
    } else {
        let interp = interpolate(points, &values)?;
        let vanishing = interpolation_vanishing(points);
        let mut numerator = state.coeffs.clone();
        for (slot, coefficient) in numerator.iter_mut().zip(&interp) {
            *slot -= *coefficient;
        }
        let quotient = divide_exact(&numerator, &vanishing)?;
        let degree_bound = state.commitment.poly_len - points.len() - 1;
        (quotient, degree_bound)
    };

    let proof = open_multi_with_quotient(
        state,
        points,
        &values,
        &quotient,
        degree_bound,
        params,
        transcript,
    )?;
    Ok((proof, values))
}

/// Prover body with an explicit quotient, exposed to tests.
fn open_multi_with_quotient(
    state: &ProverState,
    points: &[Ext4],
    values: &[Ext4],
    quotient: &[Ext4],
    degree_bound: usize,
    params: fri::Params,
    transcript: &mut Transcript,
) -> Result<Proof> {
    check_points(state.commitment.poly_len, points, values)?;
    if quotient.len() > state.commitment.poly_len {
        return Err(Error::MalformedInput {
            reason: "quotient is longer than the committed polynomial",
        });
    }
    absorb_statement_multi(transcript, &state.commitment, points, values);

    let g_state = fri::commit_ext(&state.coeffs, params, transcript)?;
    let g_commitment = fri::public_commitment(&g_state);
    if g_commitment.caps.first().and_then(|cap| cap.first()) != Some(&state.commitment.root) {
        return Err(Error::MalformedInput {
            reason: "FRI base root does not match the commitment root",
        });
    }
    let (g_fri, _) = fri::open(&g_state, transcript)?;

    let mut padded = quotient.to_vec();
    padded.resize(state.commitment.poly_len, Ext4::ZERO);
    let q_lde = ntt::evaluate_on_coset_ext(&padded, params.blowup, LDE_SHIFT)?;
    let q_state = fri::commit_ext_evals(&q_lde, degree_bound, params, transcript)?;
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

/// Verify a multi-point opening.
///
/// # Errors
/// Returns [`Error::MalformedInput`] for invalid point/value sets,
/// [`Error::FriVerificationFailed`] when any check fails,
/// [`Error::BadMerklePath`] for malformed openings, or dimension errors for
/// invalid commitments or nonzero cap heights.
pub fn verify_multi(
    commitment: &Commitment,
    points: &[Ext4],
    values: &[Ext4],
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
    check_points(commitment.poly_len, points, values)?;
    let degree_bound = if points.len() == commitment.poly_len {
        0
    } else {
        commitment.poly_len - points.len() - 1
    };

    absorb_statement_multi(transcript, commitment, points, values);

    fri::verify(&proof.g_commitment, &proof.g_fri, params, transcript)?;
    let indices = fri::verify(&proof.q_commitment, &proof.q_fri, params, transcript)?;

    if proof.g_commitment.lde_len != lde_len
        || proof.g_commitment.poly_len != commitment.poly_len
        || proof.g_commitment.degree_bound != commitment.poly_len - 1
        || proof.g_commitment.caps.first().and_then(|cap| cap.first()) != Some(&commitment.root)
        || proof.q_commitment.lde_len != lde_len
        || proof.q_commitment.poly_len != lde_len
        || proof.q_commitment.degree_bound != degree_bound
        || proof.g_commitment.caps.len() < 2
        || proof.q_commitment.caps.len() < 2
        || proof.openings.len() != indices.len()
    {
        return Err(Error::FriVerificationFailed);
    }
    let depth = usize::try_from(lde_len.trailing_zeros())
        .map_err(|_| Error::InvalidDomainSize { size: lde_len })?;
    let interp = interpolate(points, values)?;
    let vanishing = interpolation_vanishing(points);

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
        let expected = eval_poly(&interp, Ext4::from_base(z))
            + eval_poly(&vanishing, Ext4::from_base(z)) * *q_value;
        if opening.value != expected {
            return Err(Error::FriVerificationFailed);
        }
    }
    Ok(())
}

/// Verify `g(beta) = value` against a commitment.
///
/// # Errors
/// Returns [`Error::FriVerificationFailed`] when any check fails,
/// [`Error::BadMerklePath`] for malformed openings, or dimension errors for
/// invalid commitments or nonzero cap heights.
pub fn verify(
    commitment: &Commitment,
    point: Ext4,
    value: Ext4,
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
        || proof.q_commitment.poly_len != lde_len
        || proof.q_commitment.degree_bound != commitment.poly_len.saturating_sub(2)
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
        if (Ext4::from_base(z) - point) * *q_value != opening.value - value {
            return Err(Error::FriVerificationFailed);
        }
    }
    Ok(())
}

/// Validate a multi-point statement.
fn check_points(poly_len: usize, points: &[Ext4], values: &[Ext4]) -> Result<()> {
    if points.is_empty() {
        return Err(Error::EmptyInput);
    }
    if points.len() != values.len() {
        return Err(Error::MalformedInput {
            reason: "point and value counts differ",
        });
    }
    if points.len() > MAX_POINTS {
        return Err(Error::MalformedInput {
            reason: "too many multi-point openings",
        });
    }
    if points.len() > poly_len {
        return Err(Error::MalformedInput {
            reason: "more points than polynomial coefficients",
        });
    }
    for (index, point) in points.iter().enumerate() {
        if points[..index].contains(point) {
            return Err(Error::MalformedInput {
                reason: "duplicate multi-point opening point",
            });
        }
    }
    Ok(())
}

/// Interpolate `(points, values)` into ascending coefficients.
fn interpolate(points: &[Ext4], values: &[Ext4]) -> Result<Vec<Ext4>> {
    if points.len() != values.len() || points.is_empty() {
        return Err(Error::MalformedInput {
            reason: "invalid interpolation statement",
        });
    }
    let k = points.len();
    let mut coefficients = vec![Ext4::ZERO; k];
    for (j, &point_j) in points.iter().enumerate() {
        let mut basis = vec![Ext4::ZERO; k];
        basis[0] = Ext4::ONE;
        let mut degree = 0;
        let mut denominator = Ext4::ONE;
        for (m, &point_m) in points.iter().enumerate() {
            if m == j {
                continue;
            }
            let mut next = vec![Ext4::ZERO; k];
            for (i, &coefficient) in basis.iter().enumerate().take(degree + 1) {
                next[i] -= point_m * coefficient;
                next[i + 1] += coefficient;
            }
            basis = next;
            degree += 1;
            denominator *= point_j - point_m;
        }
        let scale = values[j] * denominator.inv();
        for (coefficient, basis_coefficient) in coefficients.iter_mut().zip(&basis) {
            *coefficient += *basis_coefficient * scale;
        }
    }
    Ok(coefficients)
}

/// Vanishing polynomial `prod_j (X - point_j)` in ascending coefficients.
fn interpolation_vanishing(points: &[Ext4]) -> Vec<Ext4> {
    let mut polynomial = vec![Ext4::ONE];
    for &point in points {
        let mut next = vec![Ext4::ZERO; polynomial.len() + 1];
        for (i, &coefficient) in polynomial.iter().enumerate() {
            next[i] -= point * coefficient;
            next[i + 1] += coefficient;
        }
        polynomial = next;
    }
    polynomial
}

/// Exact division by a monic vanishing polynomial.
fn divide_exact(numerator: &[Ext4], divisor: &[Ext4]) -> Result<Vec<Ext4>> {
    let Some(&leading) = divisor.last() else {
        return Err(Error::MalformedInput {
            reason: "empty divisor",
        });
    };
    let k = divisor.len() - 1;
    if k == 0 || leading != Ext4::ONE || numerator.len() < k {
        return Err(Error::MalformedInput {
            reason: "invalid vanishing polynomial",
        });
    }
    let mut remainder = numerator.to_vec();
    let mut quotient = vec![Ext4::ZERO; numerator.len() - k];
    for i in (k..numerator.len()).rev() {
        let coefficient = remainder[i];
        quotient[i - k] = coefficient;
        for (j, &divisor_coefficient) in divisor.iter().enumerate() {
            remainder[i - k + j] -= coefficient * divisor_coefficient;
        }
    }
    if remainder[..k].iter().any(|value| *value != Ext4::ZERO) {
        return Err(Error::MalformedInput {
            reason: "polynomial division is not exact",
        });
    }
    Ok(quotient)
}

/// Horner evaluation of ascending coefficients.
fn eval_poly(coefficients: &[Ext4], point: Ext4) -> Ext4 {
    let mut value = Ext4::ZERO;
    for &coefficient in coefficients.iter().rev() {
        value = value * point + coefficient;
    }
    value
}

/// Absorb a multi-point statement before deriving any challenge.
fn absorb_statement_multi(
    transcript: &mut Transcript,
    commitment: &Commitment,
    points: &[Ext4],
    values: &[Ext4],
) {
    transcript.absorb(b"upcs-multi/root", &commitment.root);
    let mut writer = Writer::new();
    writer.u64_le(commitment.poly_len as u64);
    writer.u64_le(commitment.blowup as u64);
    writer.count(points.len());
    for point in points {
        writer.ext4(*point);
    }
    for value in values {
        writer.ext4(*value);
    }
    transcript.absorb(b"upcs-multi/statement", &writer.finish());
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
    point: Ext4,
    value: Ext4,
) {
    transcript.absorb(b"upcs/root", &commitment.root);
    let mut writer = Writer::new();
    writer.u64_le(commitment.poly_len as u64);
    writer.u64_le(commitment.blowup as u64);
    writer.ext4(point);
    writer.ext4(value);
    transcript.absorb(b"upcs/statement", &writer.finish());
}

/// Merkle tree over 16-byte extension-field leaves.
fn tree_over(lde: &[Ext4]) -> Result<MerkleTree> {
    let mut flat = vec![0u8; 16 * lde.len()];
    for (chunk, value) in flat.chunks_exact_mut(16).zip(lde) {
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    MerkleTree::from_flat(&flat, 16)
}

/// Synthetic division `(g - value) / (X - point)`, padded to `deg(g) + 1`.
///
/// Returns [`Error::MalformedInput`] when the division is not exact (the
/// claimed value is wrong). The quotient's leading coefficient is zero.
fn quotient(coeffs: &[Ext4], point: Ext4, value: Ext4) -> Result<Vec<Ext4>> {
    let n = coeffs.len();
    let mut q = vec![Ext4::ZERO; n];
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
    if remainder != Ext4::ZERO {
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

    fn ext_poly(coeffs: &[Field]) -> Vec<Ext4> {
        coeffs.iter().copied().map(Ext4::from_base).collect()
    }

    fn prove_roundtrip(coeffs: &[Field], point: Field) -> (Commitment, fri::Params, Ext4, Proof) {
        let params = params(coeffs.len());
        let state = commit(coeffs, params.blowup).unwrap();
        let commitment = state.commitment().clone();
        let point = Ext4::from_base(point);
        let value = ntt::evaluate_ext(state.coeffs(), point);
        let mut prover_t = Transcript::new(b"upcs-test");
        let proof = open(&state, point, value, params, &mut prover_t).unwrap();
        (commitment, params, value, proof)
    }

    fn verify_with(
        commitment: &Commitment,
        point: Field,
        value: Ext4,
        proof: &Proof,
        params: fri::Params,
    ) -> Result<()> {
        let mut verifier_t = Transcript::new(b"upcs-test");
        verify(
            commitment,
            Ext4::from_base(point),
            value,
            proof,
            params,
            &mut verifier_t,
        )
    }

    fn multi_points(_poly_len: usize, k: usize) -> Vec<Ext4> {
        (0..k)
            .map(|i| Ext4::from_base(Field::new(u32::try_from(i).unwrap() * 5 + 2)))
            .collect()
    }

    fn prove_multi_roundtrip(
        coeffs: &[Field],
        points: &[Ext4],
    ) -> (Commitment, fri::Params, Vec<Ext4>, Proof) {
        let params = params(coeffs.len());
        let state = commit(coeffs, params.blowup).unwrap();
        let commitment = state.commitment().clone();
        let mut prover_t = Transcript::new(b"upcs-multi-test");
        let (proof, values) = open_multi(&state, points, params, &mut prover_t).unwrap();
        (commitment, params, values, proof)
    }

    fn verify_multi_with(
        commitment: &Commitment,
        points: &[Ext4],
        values: &[Ext4],
        proof: &Proof,
        params: fri::Params,
    ) -> Result<()> {
        let mut verifier_t = Transcript::new(b"upcs-multi-test");
        verify_multi(commitment, points, values, proof, params, &mut verifier_t)
    }

    #[test]
    fn honest_openings_verify() {
        for n in [1usize, 2, 4, 8, 16, 64] {
            let coeffs = poly(n);
            for point in [Field::ZERO, Field::ONE, Field::new(7), Field::new(123_456)] {
                let (commitment, params, value, proof) = prove_roundtrip(&coeffs, point);
                assert_eq!(proof.q_commitment.degree_bound, n.saturating_sub(2));
                verify_with(&commitment, point, value, &proof, params).unwrap();
            }
        }
    }

    #[test]
    fn wrong_value_is_rejected() {
        let coeffs = poly(8);
        let point = Field::new(5);
        let (commitment, params, value, proof) = prove_roundtrip(&coeffs, point);
        assert!(verify_with(&commitment, point, value + Ext4::ONE, &proof, params).is_err());
        assert!(verify_with(&commitment, point, value, &proof, params).is_ok());
    }

    #[test]
    fn wrong_point_is_rejected() {
        let coeffs = poly(16);
        let point = Field::new(9);
        let (commitment, params, value, proof) = prove_roundtrip(&coeffs, point);
        let mut verifier_t = Transcript::new(b"upcs-test");
        assert!(verify(
            &commitment,
            Ext4::from_base(point) + Ext4::ONE,
            value,
            &proof,
            params,
            &mut verifier_t,
        )
        .is_err());
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
        proof.openings[0].value += Ext4::ONE;
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
        proof.q_fri.queries[0].folds[0].values[0] += Ext4::ONE;
        assert!(verify_with(&commitment, point, value, &proof, params).is_err());

        let (commitment, params, value, mut proof) = prove_roundtrip(&coeffs, point);
        proof.g_fri.queries[0].folds[0].values[0] += Ext4::ONE;
        assert!(verify_with(&commitment, point, value, &proof, params).is_err());

        let (commitment, params, value, mut proof) = prove_roundtrip(&coeffs, point);
        proof.q_commitment.lde_len *= 2;
        assert!(verify_with(&commitment, point, value, &proof, params).is_err());
    }

    #[test]
    fn wrong_quotient_is_rejected() {
        let coeffs = poly(8);
        let point = Field::new(23);
        let ext_coeffs = ext_poly(&coeffs);
        let point = Ext4::from_base(point);
        let value = ntt::evaluate_ext(&ext_coeffs, point);
        let params = params(coeffs.len());
        let state = commit(&coeffs, params.blowup).unwrap();
        let mut bad = quotient(&ext_coeffs, point, value).unwrap();
        bad[0] += Ext4::ONE;
        let mut prover_t = Transcript::new(b"upcs-test");
        let proof = open_with_quotient(&state, point, value, &bad, params, &mut prover_t).unwrap();
        let mut verifier_t = Transcript::new(b"upcs-test");
        assert!(verify(
            state.commitment(),
            point,
            value,
            &proof,
            params,
            &mut verifier_t
        )
        .is_err());
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
        let ext_point = Ext4::from_base(point);
        let value = ntt::evaluate_ext(&ext_poly(&poly(8)), ext_point);
        let mut prover_t = Transcript::new(b"upcs-test");
        let proof = open(&state, ext_point, value, params(8), &mut prover_t).unwrap();
        assert!(verify_with(&bad, point, value, &proof, params(8)).is_err());
    }

    #[test]
    fn open_rejects_wrong_value_and_blowup() {
        let coeffs = poly(8);
        let point = Field::new(31);
        let ext_point = Ext4::from_base(point);
        let state = commit(&coeffs, 8).unwrap();
        let value = ntt::evaluate_ext(state.coeffs(), ext_point);
        let mut transcript = Transcript::new(b"upcs-test");
        assert!(open(
            &state,
            ext_point,
            value + Ext4::ONE,
            params(8),
            &mut transcript
        )
        .is_err());
        let mut transcript = Transcript::new(b"upcs-test");
        let other = fri::Params::new(16, 8, 8).unwrap();
        assert!(open(&state, ext_point, value, other, &mut transcript).is_err());
        let mut capped = params(8);
        capped.cap_height = 1;
        let mut transcript = Transcript::new(b"upcs-test");
        assert!(open(&state, ext_point, value, capped, &mut transcript).is_err());
    }

    #[test]
    fn statement_is_transcript_bound() {
        let coeffs = poly(8);
        let point = Field::new(37);
        let (commitment, params, value, proof) = prove_roundtrip(&coeffs, point);
        let mut other_t = Transcript::new(b"upcs-other-domain");
        assert!(verify(
            &commitment,
            Ext4::from_base(point),
            value,
            &proof,
            params,
            &mut other_t
        )
        .is_err());
    }

    #[test]
    fn honest_multi_openings_verify() {
        for n in [2usize, 4, 8, 16] {
            let coeffs = poly(n);
            for k in 1..=n.min(MAX_POINTS) {
                let points = multi_points(n, k);
                let (commitment, params, values, proof) = prove_multi_roundtrip(&coeffs, &points);
                verify_multi_with(&commitment, &points, &values, &proof, params).unwrap();
                let ext_coeffs = ext_poly(&coeffs);
                for (point, value) in points.iter().zip(&values) {
                    assert_eq!(ntt::evaluate_ext(&ext_coeffs, *point), *value);
                }
            }
        }
    }

    #[test]
    fn multi_wrong_value_is_rejected() {
        let coeffs = poly(8);
        let points = multi_points(8, 3);
        let (commitment, params, mut values, proof) = prove_multi_roundtrip(&coeffs, &points);
        values[1] += Ext4::ONE;
        assert!(verify_multi_with(&commitment, &points, &values, &proof, params).is_err());
    }

    #[test]
    fn multi_wrong_point_is_rejected() {
        let coeffs = poly(16);
        let points = multi_points(16, 4);
        let (commitment, params, values, proof) = prove_multi_roundtrip(&coeffs, &points);
        let mut other = points;
        other[2] += Ext4::ONE;
        assert!(verify_multi_with(&commitment, &other, &values, &proof, params).is_err());
    }

    #[test]
    fn multi_duplicate_points_are_rejected() {
        let coeffs = poly(8);
        let state = commit(&coeffs, 8).unwrap();
        let points = [
            Ext4::from_base(Field::new(3)),
            Ext4::from_base(Field::new(3)),
        ];
        let mut transcript = Transcript::new(b"upcs-multi-test");
        assert!(open_multi(&state, &points, params(8), &mut transcript).is_err());

        let points = multi_points(8, 2);
        let (commitment, params, values, proof) = prove_multi_roundtrip(&coeffs, &points);
        let duplicated = [points[0], points[0]];
        assert!(verify_multi_with(&commitment, &duplicated, &values, &proof, params).is_err());
    }

    #[test]
    fn multi_point_count_limits_are_enforced() {
        let coeffs = poly(32);
        let state = commit(&coeffs, 8).unwrap();
        let too_many = multi_points(32, MAX_POINTS + 1);
        let mut transcript = Transcript::new(b"upcs-multi-test");
        assert!(open_multi(&state, &too_many, params(32), &mut transcript).is_err());

        let n = 8;
        let points = multi_points(n, n);
        let (commitment, params, values, proof) = prove_multi_roundtrip(&coeffs[..n], &points);
        let mut too_many_points = points;
        too_many_points.push(Ext4::from_base(Field::new(100)));
        let mut too_many_values = values;
        too_many_values.push(Ext4::ZERO);
        assert!(verify_multi_with(
            &commitment,
            &too_many_points,
            &too_many_values,
            &proof,
            params
        )
        .is_err());
    }

    #[test]
    fn multi_full_degree_point_set_uses_zero_quotient() {
        let coeffs = poly(8);
        let points = multi_points(8, 8);
        let (commitment, params, values, proof) = prove_multi_roundtrip(&coeffs, &points);
        assert_eq!(proof.q_commitment.degree_bound, 0);
        verify_multi_with(&commitment, &points, &values, &proof, params).unwrap();
    }

    #[test]
    fn multi_wrong_quotient_is_rejected() {
        let coeffs = poly(8);
        let points = multi_points(8, 3);
        let params = params(8);
        let state = commit(&coeffs, params.blowup).unwrap();
        let ext_coeffs = ext_poly(&coeffs);
        let values: Vec<Ext4> = points
            .iter()
            .map(|point| ntt::evaluate_ext(&ext_coeffs, *point))
            .collect();
        let interp = interpolate(&points, &values).unwrap();
        let vanishing = interpolation_vanishing(&points);
        let mut numerator = ext_coeffs;
        for (slot, coefficient) in numerator.iter_mut().zip(&interp) {
            *slot -= *coefficient;
        }
        let mut quotient = divide_exact(&numerator, &vanishing).unwrap();
        quotient[0] += Ext4::ONE;
        let mut prover_t = Transcript::new(b"upcs-multi-test");
        let proof = open_multi_with_quotient(
            &state,
            &points,
            &values,
            &quotient,
            8 - points.len() - 1,
            params,
            &mut prover_t,
        )
        .unwrap();
        assert!(verify_multi_with(state.commitment(), &points, &values, &proof, params).is_err());
    }

    #[test]
    fn multi_tampering_is_rejected() {
        let coeffs = poly(8);
        let points = multi_points(8, 3);
        let (commitment, params, values, proof) = prove_multi_roundtrip(&coeffs, &points);

        let mut bad = proof.clone();
        bad.g_commitment.caps[0][0][0] ^= 1;
        assert!(verify_multi_with(&commitment, &points, &values, &bad, params).is_err());

        let mut bad = proof.clone();
        bad.q_commitment.caps[0][0][0] ^= 1;
        assert!(verify_multi_with(&commitment, &points, &values, &bad, params).is_err());

        let mut bad = proof.clone();
        bad.q_commitment.degree_bound += 1;
        assert!(verify_multi_with(&commitment, &points, &values, &bad, params).is_err());

        let mut bad = proof.clone();
        bad.openings[0].value += Ext4::ONE;
        assert!(verify_multi_with(&commitment, &points, &values, &bad, params).is_err());

        let mut bad = proof;
        bad.openings[0].path.pop();
        assert!(verify_multi_with(&commitment, &points, &values, &bad, params).is_err());
    }

    #[test]
    fn multi_proofs_roundtrip() {
        let coeffs = poly(8);
        let points = multi_points(8, 4);
        let (commitment, params, values, proof) = prove_multi_roundtrip(&coeffs, &points);
        let bytes = proof.to_bytes();
        let decoded = Proof::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, proof);
        verify_multi_with(&commitment, &points, &values, &decoded, params).unwrap();
        assert!(Proof::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(Proof::from_bytes(&trailing).is_err());
    }

    #[test]
    fn multi_statement_is_transcript_bound() {
        let coeffs = poly(8);
        let points = multi_points(8, 3);
        let (commitment, params, values, proof) = prove_multi_roundtrip(&coeffs, &points);
        let mut other_t = Transcript::new(b"upcs-multi-other-domain");
        assert!(verify_multi(&commitment, &points, &values, &proof, params, &mut other_t).is_err());
    }

    #[test]
    fn interpolation_matches_claims() {
        let points = multi_points(8, 5);
        let values: Vec<Ext4> = points
            .iter()
            .map(|point| *point * *point + Ext4::from_base(Field::new(7)))
            .collect();
        let interp = interpolate(&points, &values).unwrap();
        for (point, value) in points.iter().zip(&values) {
            assert_eq!(eval_poly(&interp, *point), *value);
        }
        let vanishing = interpolation_vanishing(&points);
        for point in &points {
            assert_eq!(eval_poly(&vanishing, *point), Ext4::ZERO);
        }
        assert_eq!(*vanishing.last().unwrap(), Ext4::ONE);
    }
}
