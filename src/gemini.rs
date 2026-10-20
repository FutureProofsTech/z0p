//! Gemini-style multilinear polynomial commitments (`v1`).
//!
//! [`commit`] commits the coefficient encoding of a multilinear polynomial:
//! for `n` variables and monomial coefficients `c_b`, the univariate
//! polynomial `g_0(X) = sum_b c_b X^index(b)` is committed with [`upcs`].
//! [`commit_evals`] converts hypercube evaluations to those coefficients with
//! the Moebius transform; evaluation order matches [`crate::mle::Mle`]
//! (index most-significant-bit first, point coordinates most-significant
//! first).
//!
//! [`open`] proves `f(r) = y` by folding the coefficient polynomial one
//! variable at a time (least-significant coordinate first):
//! `g_i(Y) = A_i(Y) + r_i B_i(Y)` where `g_{i-1}(X) = A_i(X^2) + X B_i(X^2)`.
//! The prover commits `g_1, ..., g_{n-1}` and checks, for each `i < n`, the
//! fold identity at a nonzero random `beta_i`:
//!
//! ```text
//! g_i(beta^2) = (g_{i-1}(beta) + g_{i-1}(-beta)) / 2
//!             + r_i (g_{i-1}(beta) - g_{i-1}(-beta)) / (2 beta)
//! ```
//!
//! with the final public-point check `g_{n-1}(r_0) = y`. Zero coordinates
//! need no special case (the odd part is multiplied by `r_i = 0`).
//!
//! Every layer is opened **once** with a multi-point [`upcs`] proof at all
//! points its relations use: `g_0` at `beta_1, -beta_1`; interior `g_i` at
//! `beta_i^2, beta_{i+1}, -beta_{i+1}`; and `g_{n-1}` at
//! `beta_{n-1}^2, r_0`. Layer commitments are absorbed before the `beta_i`
//! are sampled, so this construction is transparent and hash-only.
//!
//! # Soundness
//!
//! Each layer is a low-degree polynomial certified by `upcs`. A fold
//! identity has degree below `2^{n-i+1}`, so one random check per layer
//! misses a nonzero identity with probability at most `2^{n-i+1} / p^4`.
//! Over `n` layers the algebraic error is at most `n 2^n / p^4` (below
//! `2^-99` for `n = 20`). Fold betas, unfolding coordinates, and `upcs`
//! evaluation points all live in the quartic extension field. Treat the
//! query/PoW bit level as conjectured and size instances accordingly.
//!
//! For `n >= 1` the proof carries one multi-point `upcs` opening per layer
//! and `n - 1` layer commitments (`n = 0` carries one opening and no
//! layers), so it is `O(n)` openings and not constant-size. Each opening
//! batches the two or three evaluation points of its layer behind one
//! FRI pair and one quotient. Batch/multilinear FRI (BaseFold/WHIR) is the
//! roadmap replacement. Proofs are not hiding.
//!
//! [`Mle`]: crate::mle::Mle

use crate::babybear::Field;
use crate::codec::{Reader, Writer, MAX_QUERIES, VERSION};
use crate::error::{Error, Result};
use crate::ext4::Ext4;
use crate::fri;
use crate::transcript::Transcript;
use crate::upcs;

/// Maximum variable count (coefficient vectors up to `2^20`).
pub const MAX_VARS: usize = 20;

#[allow(clippy::cast_possible_truncation)]
const MAX_LAYERS: u32 = MAX_VARS as u32;
#[allow(clippy::cast_possible_truncation)]
const MAX_VALUES: u32 = 3 * MAX_VARS as u32;
#[allow(clippy::cast_possible_truncation)]
const MAX_OPENINGS: u32 = MAX_VARS as u32;
const MAX_PROOF_BYTES: u32 = 1 << 27;

/// Prover/verifier parameters for Gemini openings.
///
/// `blowup` must be at least `8` and match the commitment. `num_queries`
/// and `grinding_bits` size the inner FRI instances. Final-layer size and
/// cap height are derived per layer (caps are disabled because `upcs`
/// requires a single base root).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// LDE expansion factor (`>= 8`, power of two).
    pub blowup: usize,
    /// FRI query count per `upcs` instance (`>= 1`).
    pub num_queries: usize,
    /// FRI proof-of-work difficulty in leading-zero bits.
    pub grinding_bits: u32,
}

impl Params {
    /// Validate and construct parameters.
    ///
    /// # Errors
    /// Returns [`Error::InvalidBlowup`] for a blowup below `8` or not a
    /// power of two, [`Error::NoQueries`] for zero queries, or
    /// [`Error::MalformedInput`] for counts or grinding above protocol caps.
    pub fn new(blowup: usize, num_queries: usize, grinding_bits: u32) -> Result<Self> {
        let params = Self {
            blowup,
            num_queries,
            grinding_bits,
        };
        params.validate()?;
        Ok(params)
    }

    /// Re-check every invariant (fields are public).
    fn validate(&self) -> Result<()> {
        validate_blowup(self.blowup)?;
        if self.num_queries == 0 {
            return Err(Error::NoQueries);
        }
        if self.num_queries > MAX_QUERIES as usize {
            return Err(Error::MalformedInput {
                reason: "num_queries above protocol cap",
            });
        }
        if self.grinding_bits > 32 {
            return Err(Error::MalformedInput {
                reason: "grinding_bits above 32",
            });
        }
        Ok(())
    }

    /// Inner FRI parameters for a layer of `poly_len` coefficients.
    fn layer(&self, poly_len: usize) -> Result<fri::Params> {
        let lde_len = poly_len
            .checked_mul(self.blowup)
            .ok_or(Error::InvalidDomainSize { size: poly_len })?;
        let log_m = lde_len.trailing_zeros();
        let final_size = if log_m % 2 == 0 { 4 } else { 2 };
        Ok(fri::Params::new(self.blowup, self.num_queries, final_size)?
            .with_grinding_bits(self.grinding_bits))
    }
}

/// Public commitment to the coefficient encoding of a multilinear polynomial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment {
    root: [u8; 32],
    n_vars: usize,
    blowup: usize,
}

impl Commitment {
    /// Merkle root of the bit-reversed LDE of `g_0`.
    #[must_use]
    pub const fn root(&self) -> &[u8; 32] {
        &self.root
    }

    /// Number of variables.
    #[must_use]
    pub const fn n_vars(&self) -> usize {
        self.n_vars
    }

    /// LDE expansion factor.
    #[must_use]
    pub const fn blowup(&self) -> usize {
        self.blowup
    }

    /// Number of coefficients (`2^n_vars`).
    #[must_use]
    pub fn poly_len(&self) -> usize {
        1usize << self.n_vars
    }

    /// Canonical bytes: version, root, dimensions.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.byte(VERSION);
        writer.bytes(&self.root);
        writer.u64_le(self.n_vars as u64);
        writer.u64_le(self.blowup as u64);
        writer.finish()
    }

    /// Decode [`Commitment::to_bytes`] output, rejecting anything else.
    ///
    /// Shape-checked only; soundness checks happen in [`verify`].
    ///
    /// # Errors
    /// Returns [`Error::MalformedInput`] on any encoding violation,
    /// including a variable count above [`MAX_VARS`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        reader.version()?;
        let root = reader.digest()?;
        let n_vars = reader.dimension()?;
        if n_vars > MAX_VARS {
            return Err(Error::MalformedInput {
                reason: "n_vars above protocol cap",
            });
        }
        let blowup = reader.dimension()?;
        reader.end()?;
        Ok(Self {
            root,
            n_vars,
            blowup,
        })
    }

    /// The equivalent [`upcs`] commitment to `g_0`.
    fn to_upcs(&self) -> upcs::Commitment {
        upcs::Commitment {
            root: self.root,
            poly_len: self.poly_len(),
            blowup: self.blowup,
        }
    }
}

/// Prover-side commitment data.
#[derive(Clone, Debug)]
pub struct ProverState {
    top: upcs::ProverState,
    commitment: Commitment,
}

impl ProverState {
    /// The public commitment.
    #[must_use]
    pub const fn commitment(&self) -> &Commitment {
        &self.commitment
    }
}

/// One point-opening proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// Commitments to the folded layers `g_1, ..., g_{n-1}`.
    pub layers: Vec<upcs::Commitment>,
    /// Layer-opening values, layer by layer and point by point.
    pub values: Vec<Ext4>,
    /// One multi-point `upcs` opening per layer, `g_0` first.
    pub openings: Vec<upcs::Proof>,
}

impl Proof {
    /// Canonical bytes: version, layer commitments, values, opening blobs.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.byte(VERSION);
        writer.count(self.layers.len());
        for layer in &self.layers {
            writer.bytes(&layer.root);
            writer.u64_le(layer.poly_len as u64);
            writer.u64_le(layer.blowup as u64);
        }
        writer.count(self.values.len());
        for value in &self.values {
            writer.ext4(*value);
        }
        writer.count(self.openings.len());
        for opening in &self.openings {
            let body = opening.to_bytes();
            writer.count(body.len());
            writer.bytes(&body);
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
        let mut layers = Vec::new();
        for _ in 0..reader.count(MAX_LAYERS)? {
            layers.push(upcs::Commitment {
                root: reader.digest()?,
                poly_len: reader.dimension()?,
                blowup: reader.dimension()?,
            });
        }
        let mut values = Vec::new();
        for _ in 0..reader.count(MAX_VALUES)? {
            values.push(reader.ext4()?);
        }
        let mut openings = Vec::new();
        for _ in 0..reader.count(MAX_OPENINGS)? {
            let len = reader.count(MAX_PROOF_BYTES)?;
            openings.push(upcs::Proof::from_bytes(reader.take_bytes(len)?)?);
        }
        reader.end()?;
        Ok(Self {
            layers,
            values,
            openings,
        })
    }
}

/// Commit to multilinear monomial coefficients.
///
/// `coeffs` is indexed most-significant-bit first, matching
/// [`crate::mle::Mle`]: coefficient `b` multiplies
/// `prod_i point[i]^{b_i}` with `b_0` the most-significant bit of `b`.
///
/// # Errors
/// Returns [`Error::EmptyInput`] for empty input,
/// [`Error::InvalidDomainSize`] for non-power-of-two lengths or more than
/// [`MAX_VARS`] variables, and [`Error::InvalidBlowup`] below `8`.
pub fn commit(coeffs: &[Field], blowup: usize) -> Result<ProverState> {
    let n_vars = n_vars_for_len(coeffs.len())?;
    validate_blowup(blowup)?;
    let top = upcs::commit(coeffs, blowup)?;
    let commitment = Commitment {
        root: top.commitment().root,
        n_vars,
        blowup,
    };
    Ok(ProverState { top, commitment })
}

/// Commit a multilinear polynomial from hypercube evaluations.
///
/// Applies the Moebius transform to obtain the monomial coefficients, then
/// calls [`commit`]. Evaluation order matches [`crate::mle::Mle`].
///
/// # Errors
/// Returns the same errors as [`commit`].
pub fn commit_evals(evals: &[Field], blowup: usize) -> Result<ProverState> {
    let coeffs = coeffs_from_evals(evals)?;
    commit(&coeffs, blowup)
}

/// Prove `f(point) = value` for a committed multilinear polynomial.
///
/// `params.blowup` must match the commitment. The transcript absorbs the
/// statement and layer commitments before sampling fold challenges, so
/// prover and verifier must start from identical transcript state.
///
/// # Errors
/// Returns [`Error::MalformedInput`] when the point dimension or claimed
/// value is wrong, [`Error::InvalidBlowup`] on a parameter mismatch, and
/// propagates `upcs`/FRI errors.
pub fn open(
    state: &ProverState,
    point: &[Ext4],
    value: Ext4,
    params: Params,
    transcript: &mut Transcript,
) -> Result<Proof> {
    params.validate()?;
    validate_blowup(state.commitment.blowup)?;
    if state.commitment.blowup != params.blowup {
        return Err(Error::InvalidBlowup {
            factor: params.blowup,
        });
    }
    let n_vars = state.commitment.n_vars;
    if point.len() != n_vars {
        return Err(Error::MalformedInput {
            reason: "point dimension must match n_vars",
        });
    }

    let mut current = state.top.coeffs().to_vec();
    let mut layer_polys = Vec::with_capacity(n_vars.saturating_sub(1));
    for i in 1..=n_vars {
        let coordinate = point[n_vars - i];
        current = fold(&current, coordinate);
        if i < n_vars {
            layer_polys.push(current.clone());
        }
    }
    if current[0] != value {
        return Err(Error::MalformedInput {
            reason: "claimed evaluation does not match the multilinear polynomial",
        });
    }

    let mut layer_states = Vec::with_capacity(layer_polys.len());
    for coeffs in &layer_polys {
        layer_states.push(upcs::commit_ext(coeffs, params.blowup)?);
    }
    let layer_commitments: Vec<upcs::Commitment> = layer_states
        .iter()
        .map(|state| state.commitment().clone())
        .collect();

    absorb_statement(transcript, &state.commitment, point, value);
    absorb_layers(transcript, &layer_commitments);

    let mut betas = Vec::with_capacity(n_vars.saturating_sub(1));
    for _ in 1..n_vars {
        betas.push(challenge_nonzero(transcript)?);
    }

    let final_point = if n_vars == 0 { Ext4::ZERO } else { point[0] };
    let mut states = Vec::with_capacity(n_vars.max(1));
    states.push(&state.top);
    states.extend(layer_states.iter());

    let mut values = Vec::with_capacity(if n_vars <= 1 { 1 } else { 3 * n_vars - 2 });
    let mut openings = Vec::with_capacity(n_vars.max(1));
    for (index, layer_state) in states.iter().enumerate() {
        let points = layer_points(index, n_vars, &betas, final_point);
        let layer_params = params.layer(layer_state.coeffs().len())?;
        let (opening, layer_values) =
            upcs::open_multi(layer_state, &points, layer_params, transcript)?;
        values.extend(layer_values);
        openings.push(opening);
    }
    let Some(&final_value) = values.last() else {
        return Err(Error::MalformedInput {
            reason: "empty layer values",
        });
    };
    if final_value != value {
        return Err(Error::MalformedInput {
            reason: "claimed evaluation does not match the multilinear polynomial",
        });
    }

    Ok(Proof {
        layers: layer_commitments,
        values,
        openings,
    })
}

/// Verify a multilinear evaluation proof.
///
/// # Errors
/// Returns [`Error::MalformedInput`] for shape or dimension mismatches,
/// [`Error::InvalidBlowup`] on parameter mismatch, and
/// [`Error::FriVerificationFailed`] when a fold identity or an `upcs`
/// opening fails.
#[allow(clippy::too_many_lines)]
pub fn verify(
    commitment: &Commitment,
    point: &[Ext4],
    value: Ext4,
    proof: &Proof,
    params: Params,
    transcript: &mut Transcript,
) -> Result<()> {
    params.validate()?;
    validate_blowup(commitment.blowup)?;
    if commitment.blowup != params.blowup {
        return Err(Error::InvalidBlowup {
            factor: params.blowup,
        });
    }
    let n_vars = commitment.n_vars;
    if n_vars > MAX_VARS {
        return Err(Error::MalformedInput {
            reason: "n_vars above protocol cap",
        });
    }
    if point.len() != n_vars {
        return Err(Error::MalformedInput {
            reason: "point dimension must match n_vars",
        });
    }
    let expected_layers = n_vars.saturating_sub(1);
    if proof.layers.len() != expected_layers {
        return Err(Error::MalformedInput {
            reason: "layer count does not match n_vars",
        });
    }
    for (index, layer) in proof.layers.iter().enumerate() {
        let expected_poly_len = 1usize << (n_vars - index - 1);
        if layer.poly_len != expected_poly_len || layer.blowup != params.blowup {
            return Err(Error::MalformedInput {
                reason: "layer dimensions do not match n_vars",
            });
        }
    }
    let expected_values = if n_vars <= 1 { 1 } else { 3 * n_vars - 2 };
    let expected_openings = n_vars.max(1);
    if proof.values.len() != expected_values || proof.openings.len() != expected_openings {
        return Err(Error::MalformedInput {
            reason: "opening count does not match n_vars",
        });
    }

    absorb_statement(transcript, commitment, point, value);
    absorb_layers(transcript, &proof.layers);

    let mut betas = Vec::with_capacity(expected_layers);
    for _ in 0..expected_layers {
        betas.push(challenge_nonzero(transcript)?);
    }

    let top = commitment.to_upcs();
    let final_point = if n_vars == 0 { Ext4::ZERO } else { point[0] };
    let mut commitments: Vec<&upcs::Commitment> = Vec::with_capacity(n_vars.max(1));
    commitments.push(&top);
    commitments.extend(proof.layers.iter());

    let mut layer_values: Vec<Vec<Ext4>> = Vec::with_capacity(commitments.len());
    let mut cursor = 0;
    for (index, layer) in commitments.iter().enumerate() {
        let points = layer_points(index, n_vars, &betas, final_point);
        let end = cursor + points.len();
        if end > proof.values.len() {
            return Err(Error::MalformedInput {
                reason: "opening values are truncated",
            });
        }
        let values = &proof.values[cursor..end];
        let layer_params = params.layer(layer.poly_len)?;
        upcs::verify_multi(
            layer,
            &points,
            values,
            &proof.openings[index],
            layer_params,
            transcript,
        )?;
        layer_values.push(values.to_vec());
        cursor = end;
    }
    if cursor != proof.values.len() {
        return Err(Error::MalformedInput {
            reason: "opening values have trailing entries",
        });
    }

    for i in 1..n_vars {
        let coordinate = point[n_vars - i];
        let beta = betas[i - 1];
        let previous = &layer_values[i - 1];
        let (plus, minus) = if i == 1 { (0, 1) } else { (1, 2) };
        let left = previous[plus];
        let left_neg = previous[minus];
        let folded = layer_values[i][0];
        let half = Ext4::from_base(Field::TWO.inv());
        let expected = (left + left_neg) * half
            + coordinate * (left - left_neg) * (Ext4::from_base(Field::TWO) * beta).inv();
        if folded != expected {
            return Err(Error::FriVerificationFailed);
        }
    }

    let final_value = layer_values
        .last()
        .and_then(|values| values.last())
        .copied()
        .ok_or(Error::FriVerificationFailed)?;
    if final_value != value {
        return Err(Error::FriVerificationFailed);
    }
    Ok(())
}

/// Points at which layer `index` is opened by the fold checks/final claim.
fn layer_points(index: usize, n_vars: usize, betas: &[Ext4], final_point: Ext4) -> Vec<Ext4> {
    if n_vars <= 1 {
        return vec![final_point];
    }
    if index == 0 {
        return vec![betas[0], -betas[0]];
    }
    if index == n_vars - 1 {
        let beta = betas[n_vars - 2];
        return vec![beta * beta, final_point];
    }
    let previous = betas[index - 1];
    let next = betas[index];
    vec![previous * previous, next, -next]
}

/// Validate a coefficient/evaluation length and return `log2(length)`.
fn n_vars_for_len(len: usize) -> Result<usize> {
    if len == 0 {
        return Err(Error::EmptyInput);
    }
    if !len.is_power_of_two() {
        return Err(Error::InvalidDomainSize { size: len });
    }
    let n_vars = len.trailing_zeros() as usize;
    if n_vars > MAX_VARS {
        return Err(Error::InvalidDomainSize { size: len });
    }
    Ok(n_vars)
}

/// Require the multilinear LDE blowup floor used by the layer schedule.
fn validate_blowup(blowup: usize) -> Result<()> {
    if blowup < 8 || !blowup.is_power_of_two() {
        return Err(Error::InvalidBlowup { factor: blowup });
    }
    Ok(())
}

/// Fold the least-significant variable: `out[j] = in[2j] + r in[2j+1]`.
fn fold(coeffs: &[Ext4], coordinate: Ext4) -> Vec<Ext4> {
    let half = coeffs.len() / 2;
    let mut out = Vec::with_capacity(half);
    for i in 0..half {
        out.push(coeffs[2 * i] + coordinate * coeffs[2 * i + 1]);
    }
    out
}

/// Moebius transform from hypercube evaluations to monomial coefficients.
fn coeffs_from_evals(evals: &[Field]) -> Result<Vec<Field>> {
    n_vars_for_len(evals.len())?;
    let mut coeffs = evals.to_vec();
    let mut stride = 1;
    while stride < evals.len() {
        let mut base = 0;
        while base < evals.len() {
            for i in base..base + stride {
                let low = coeffs[i];
                coeffs[i + stride] -= low;
            }
            base += 2 * stride;
        }
        stride *= 2;
    }
    Ok(coeffs)
}

/// Draw a nonzero fold challenge, redrawing degenerate zeros.
fn challenge_nonzero(transcript: &mut Transcript) -> Result<Ext4> {
    for _ in 0..8 {
        let beta = transcript.challenge_ext(b"gemini/beta");
        if beta != Ext4::ZERO {
            return Ok(beta);
        }
    }
    Err(Error::MalformedInput {
        reason: "degenerate fold challenge",
    })
}

/// Absorb the public statement before sampling challenges.
fn absorb_statement(
    transcript: &mut Transcript,
    commitment: &Commitment,
    point: &[Ext4],
    value: Ext4,
) {
    let mut writer = Writer::new();
    writer.bytes(&commitment.to_bytes());
    writer.count(point.len());
    for coordinate in point {
        writer.ext4(*coordinate);
    }
    writer.ext4(value);
    transcript.absorb(b"gemini/statement", &writer.finish());
}

/// Absorb all layer commitments before sampling challenges.
fn absorb_layers(transcript: &mut Transcript, layers: &[upcs::Commitment]) {
    let mut writer = Writer::new();
    writer.count(layers.len());
    for layer in layers {
        writer.bytes(&layer.to_bytes());
    }
    transcript.absorb(b"gemini/layers", &writer.finish());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mle::Mle;

    fn params() -> Params {
        Params::new(8, 8, 0).unwrap()
    }

    fn coefficients(n_vars: usize) -> Vec<Field> {
        (0..(1usize << n_vars))
            .map(|i| Field::new(u32::try_from(i).unwrap() * 11 + 5))
            .collect()
    }

    fn point(n_vars: usize) -> Vec<Ext4> {
        (0..n_vars)
            .map(|i| {
                let i = u32::try_from(i).unwrap();
                Ext4::new(
                    Field::new(i * 3 + 2),
                    Field::new(i + 1),
                    Field::new(i * 2 + 3),
                    Field::new(i + 5),
                )
            })
            .collect()
    }

    fn direct_eval(coeffs: &[Field], point: &[Ext4]) -> Ext4 {
        let n_vars = point.len();
        let mut total = Ext4::ZERO;
        for (index, coefficient) in coeffs.iter().enumerate() {
            let mut weight = Ext4::ONE;
            for (variable, coordinate) in point.iter().enumerate() {
                if (index >> (n_vars - 1 - variable)) & 1 == 1 {
                    weight *= *coordinate;
                }
            }
            total += Ext4::from_base(*coefficient) * weight;
        }
        total
    }

    fn prove(coeffs: &[Field], point: &[Ext4]) -> (Commitment, Proof, Ext4) {
        let state = commit(coeffs, params().blowup).unwrap();
        let commitment = state.commitment().clone();
        let value = direct_eval(coeffs, point);
        let mut transcript = Transcript::new(b"gemini-test");
        let proof = open(&state, point, value, params(), &mut transcript).unwrap();
        (commitment, proof, value)
    }

    fn verify_with(
        commitment: &Commitment,
        point: &[Ext4],
        value: Ext4,
        proof: &Proof,
    ) -> Result<()> {
        let mut transcript = Transcript::new(b"gemini-test");
        verify(commitment, point, value, proof, params(), &mut transcript)
    }

    #[test]
    fn honest_openings_verify() {
        for n_vars in 0..=5 {
            let coeffs = coefficients(n_vars);
            for point in [point(n_vars), vec![Ext4::ZERO; n_vars]] {
                let (commitment, proof, value) = prove(&coeffs, &point);
                verify_with(&commitment, &point, value, &proof).unwrap();
            }
        }
    }

    #[test]
    fn commit_evals_matches_mle() {
        for n_vars in 0..=4 {
            let evals: Vec<Field> = (0..(1usize << n_vars))
                .map(|i| Field::new(u32::try_from(i).unwrap() * 7 + 3))
                .collect();
            let mle = Mle::from_base(evals.clone()).unwrap();
            let point = point(n_vars);
            let value = mle.evaluate(&point).unwrap();
            let state = commit_evals(&evals, 8).unwrap();
            let mut transcript = Transcript::new(b"gemini-test");
            let proof = open(&state, &point, value, params(), &mut transcript).unwrap();
            verify_with(state.commitment(), &point, value, &proof).unwrap();
            let mut transcript = Transcript::new(b"gemini-test");
            assert!(verify(
                state.commitment(),
                &point,
                value + Ext4::ONE,
                &proof,
                params(),
                &mut transcript
            )
            .is_err());
        }
    }

    #[test]
    fn zero_coordinates_verify() {
        let n_vars = 3;
        let coeffs = coefficients(n_vars);
        let point = vec![Ext4::ZERO, Ext4::from_base(Field::new(7)), Ext4::ZERO];
        let (commitment, proof, value) = prove(&coeffs, &point);
        verify_with(&commitment, &point, value, &proof).unwrap();
        assert!(verify_with(&commitment, &point, value + Ext4::ONE, &proof).is_err());
    }

    #[test]
    fn wrong_value_is_rejected() {
        let n_vars = 3;
        let coeffs = coefficients(n_vars);
        let point = point(n_vars);
        let (commitment, proof, value) = prove(&coeffs, &point);
        assert!(verify_with(&commitment, &point, value + Ext4::ONE, &proof).is_err());
        assert!(verify_with(&commitment, &point, value, &proof).is_ok());
    }

    #[test]
    fn wrong_point_is_rejected() {
        let n_vars = 3;
        let coeffs = coefficients(n_vars);
        let point = point(n_vars);
        let (commitment, proof, value) = prove(&coeffs, &point);
        let mut other = point.clone();
        other[1] += Ext4::ONE;
        assert!(verify_with(&commitment, &other, value, &proof).is_err());
    }

    #[test]
    fn tampered_layer_is_rejected() {
        let n_vars = 3;
        let coeffs = coefficients(n_vars);
        let point = point(n_vars);
        let (commitment, mut proof, value) = prove(&coeffs, &point);
        proof.layers[0].root[0] ^= 1;
        assert!(verify_with(&commitment, &point, value, &proof).is_err());
    }

    #[test]
    fn tampered_values_are_rejected() {
        let n_vars = 3;
        let coeffs = coefficients(n_vars);
        let point = point(n_vars);
        let (commitment, mut proof, value) = prove(&coeffs, &point);
        proof.values[0] += Ext4::ONE;
        assert!(verify_with(&commitment, &point, value, &proof).is_err());
    }

    #[test]
    fn layer_openings_are_batched() {
        let n_vars = 3;
        let coeffs = coefficients(n_vars);
        let evaluation_point = point(n_vars);
        let (_, proof, _) = prove(&coeffs, &evaluation_point);
        assert_eq!(proof.layers.len(), 2);
        assert_eq!(proof.values.len(), 7);
        assert_eq!(proof.openings.len(), 3);
        assert_eq!(proof.openings[0].q_commitment.degree_bound, 5);
        assert_eq!(proof.openings[1].q_commitment.degree_bound, 0);
        assert_eq!(proof.openings[2].q_commitment.degree_bound, 0);

        for n_vars in [0usize, 1] {
            let coeffs = coefficients(n_vars);
            let point = point(n_vars);
            let (_, proof, _) = prove(&coeffs, &point);
            assert_eq!(proof.layers.len(), 0);
            assert_eq!(proof.values.len(), 1);
            assert_eq!(proof.openings.len(), 1);
        }
    }

    #[test]
    fn tampered_openings_are_rejected() {
        let n_vars = 3;
        let coeffs = coefficients(n_vars);
        let point = point(n_vars);
        let (commitment, mut proof, value) = prove(&coeffs, &point);
        proof.openings[0].openings[0].value += Ext4::ONE;
        assert!(verify_with(&commitment, &point, value, &proof).is_err());
    }

    #[test]
    fn missing_layer_is_rejected() {
        let n_vars = 3;
        let coeffs = coefficients(n_vars);
        let point = point(n_vars);
        let (commitment, mut proof, value) = prove(&coeffs, &point);
        proof.layers.pop();
        assert!(verify_with(&commitment, &point, value, &proof).is_err());
    }

    #[test]
    fn wrong_layer_dimensions_are_rejected() {
        let n_vars = 3;
        let coeffs = coefficients(n_vars);
        let point = point(n_vars);
        let (commitment, mut proof, value) = prove(&coeffs, &point);
        proof.layers[0].poly_len *= 2;
        assert!(verify_with(&commitment, &point, value, &proof).is_err());
    }

    #[test]
    fn encoding_roundtrip() {
        let n_vars = 3;
        let coeffs = coefficients(n_vars);
        let point = point(n_vars);
        let (commitment, proof, value) = prove(&coeffs, &point);
        let commitment_bytes = commitment.to_bytes();
        let decoded = Commitment::from_bytes(&commitment_bytes).unwrap();
        assert_eq!(decoded, commitment);
        let proof_bytes = proof.to_bytes();
        let decoded = Proof::from_bytes(&proof_bytes).unwrap();
        verify_with(&commitment, &point, value, &decoded).unwrap();
        assert_eq!(decoded, proof);
        let mut bad = proof_bytes;
        bad[0] ^= 1;
        assert!(Proof::from_bytes(&bad).is_err());
        assert!(Commitment::from_bytes(&commitment_bytes[..commitment_bytes.len() - 1]).is_err());
    }

    #[test]
    fn transcript_binding_is_checked() {
        let n_vars = 3;
        let coeffs = coefficients(n_vars);
        let point = point(n_vars);
        let (commitment, proof, value) = prove(&coeffs, &point);
        let mut transcript = Transcript::new(b"gemini-other");
        assert!(verify(
            &commitment,
            &point,
            value,
            &proof,
            params(),
            &mut transcript
        )
        .is_err());
    }

    #[test]
    fn parameter_mismatches_are_rejected() {
        let n_vars = 2;
        let coeffs = coefficients(n_vars);
        let point = point(n_vars);
        let (commitment, proof, value) = prove(&coeffs, &point);
        assert!(Params::new(4, 8, 0).is_err());
        assert!(Params::new(8, 0, 0).is_err());
        assert!(Params::new(8, 8, 33).is_err());
        assert_eq!(commitment.blowup(), 8);
        let mut transcript = Transcript::new(b"gemini-test");
        assert!(verify(
            &commitment,
            &point,
            value,
            &proof,
            Params::new(16, 8, 0).unwrap(),
            &mut transcript
        )
        .is_err());
    }

    #[test]
    fn bad_shapes_are_rejected() {
        assert!(commit(&[], 8).is_err());
        assert!(commit(&[Field::ONE; 3], 8).is_err());
        assert!(commit(&[Field::ONE], 4).is_err());
        assert!(commit_evals(&[], 8).is_err());
        let state = commit(&[Field::ONE], 8).unwrap();
        let commitment = state.commitment().clone();
        let mut transcript = Transcript::new(b"gemini-test");
        assert!(open(&state, &[Ext4::ONE], Ext4::ONE, params(), &mut transcript).is_err());
        let mut transcript = Transcript::new(b"gemini-test");
        assert!(verify(
            &commitment,
            &[Ext4::ONE],
            Ext4::ONE,
            &Proof {
                layers: Vec::new(),
                values: Vec::new(),
                openings: Vec::new(),
            },
            params(),
            &mut transcript
        )
        .is_err());
    }

    #[test]
    fn prover_rejects_wrong_claim() {
        let n_vars = 3;
        let coeffs = coefficients(n_vars);
        let point = point(n_vars);
        let state = commit(&coeffs, 8).unwrap();
        let value = direct_eval(&coeffs, &point);
        let mut transcript = Transcript::new(b"gemini-test");
        assert!(open(&state, &point, value + Ext4::ONE, params(), &mut transcript).is_err());
    }
}
