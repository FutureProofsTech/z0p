//! BaseFold-style compact multilinear commitments (experimental).
//!
//! This module implements the compact-multilinear-PCS recipe from `BaseFold`:
//! commit the coefficient encoding of a multilinear polynomial with a
//! Reed-Solomon/FRI code, reduce a claimed evaluation `f(r)` to a random
//! coefficient-oracle evaluation `c(rho)` with sumcheck, then use the
//! sumcheck challenges as the FRI fold challenges so the FRI final value is
//! exactly `c(rho)`. The univariate fold is the Möbius/eq fold
//! `(1-r) E(X) + r O(X)` rather than the coefficient-encoding fold
//! `E(X) + r O(X)`, so the final constant is the multilinear evaluation of
//! the coefficient table. The result is one commitment, `O(log n)` layer
//! roots, and one pair plus one Merkle path per layer per query instead of
//! the `O(n)` openings used by [`crate::gemini`].
//!
//! # Status
//!
//! This is a prototype, not an audited construction: it is not wired into
//! the AIR/STARK stack, has no hiding layer, no Merkle caps, and no
//! end-to-end soundness proof. The query/proof-of-work schedule follows the
//! FRI heuristic in [`crate::fri`]. Treat the query bits as conjectured,
//! size instances with [`Params::for_security`], and do not deploy this as a
//! production commitment without review.
//!
//! Polynomials have at least one variable. Coefficients are base-field
//! values in multilinear (Möbius) order, matching [`crate::mle::Mle`] and
//! [`crate::gemini`]; the point and claimed value live in [`Ext4`].
//!
//! # Transcript
//!
//! Callers must start the transcript with a unique context before
//! [`open`]/[`verify`]. Both functions absorb the commitment dimensions,
//! statement, sumcheck rounds, layer roots, proof-of-work nonce, and query
//! positions in the same order.

use crate::babybear::Field;
use crate::codec::{Reader, Writer, MAX_FOLDS, MAX_QUERIES, VERSION};
use crate::error::{Error, Result};
use crate::ext4::Ext4;
use crate::merkle::{hash_leaf, hash_node, MerkleTree};
use crate::mle::Mle;
use crate::ntt::{bit_reverse_permute, bit_reverse_permute_ext, evaluate_on_coset_ext};
use crate::sumcheck::{self, Term};
use crate::transcript::Transcript;

/// Maximum variable count for this prototype (coefficient vectors up to `2^16`).
pub const MAX_VARS: usize = 16;
/// Maximum accepted sumcheck rounds.
const MAX_ROUNDS: u32 = 32;
/// Sumcheck round degree is two, hence three evaluations.
const MAX_ROUND_EVALS: u32 = 3;
/// Maximum layer roots in one proof (`MAX_VARS - 1`).
const MAX_LAYER_ROOTS: u32 = 32;
/// Largest supported expanded domain.
const MAX_DOMAIN: usize = 1 << 27;

/// Commitment parameters for a `BaseFold` opening.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// Reed-Solomon expansion factor (`>= 2`, power of two).
    pub blowup: usize,
    /// Number of FRI queries.
    pub num_queries: usize,
    /// Proof-of-work difficulty in leading-zero bits (`0` disables).
    pub grinding_bits: u32,
}

impl Params {
    /// Validate and construct parameters.
    ///
    /// # Errors
    /// Returns [`Error::InvalidBlowup`] for a blowup below two or not a
    /// power of two, [`Error::NoQueries`] for zero queries, or
    /// [`Error::MalformedInput`] for counts above protocol caps.
    pub fn new(blowup: usize, num_queries: usize, grinding_bits: u32) -> Result<Self> {
        let params = Self {
            blowup,
            num_queries,
            grinding_bits,
        };
        params.validate()?;
        Ok(params)
    }

    /// Production-shaped parameters: blowup 16, FRI queries plus grinding
    /// sized for a `target_bits` query/PoW schedule (heuristic, matching
    /// [`crate::fri::Params::for_security`]).
    ///
    /// # Errors
    /// Returns [`Error::EmptyInput`] or [`Error::InvalidDomainSize`] for an
    /// invalid coefficient count, or [`Error::MalformedInput`] above the
    /// variable cap.
    pub fn for_security(poly_len: usize, target_bits: u32) -> Result<Self> {
        if poly_len < 2 {
            return Err(Error::EmptyInput);
        }
        if !poly_len.is_power_of_two() {
            return Err(Error::InvalidDomainSize { size: poly_len });
        }
        let n_vars = usize::try_from(poly_len.trailing_zeros())
            .map_err(|_| Error::InvalidDomainSize { size: poly_len })?;
        if n_vars > MAX_VARS {
            return Err(Error::MalformedInput {
                reason: "n_vars above protocol cap",
            });
        }
        let blowup = 16;
        let (num_queries, grinding_bits) = crate::fri::tune_strength(target_bits, 2000);
        Self::new(blowup, num_queries, grinding_bits)
    }

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

    fn lde_len(&self, n_vars: usize) -> Result<usize> {
        if n_vars == 0 || n_vars > MAX_VARS {
            return Err(Error::MalformedInput {
                reason: "n_vars outside BaseFold range",
            });
        }
        let poly_len = 1usize
            .checked_shl(u32::try_from(n_vars).map_err(|_| Error::MalformedInput {
                reason: "n_vars exceeds platform width",
            })?)
            .ok_or(Error::InvalidDomainSize { size: n_vars })?;
        let lde_len = poly_len
            .checked_mul(self.blowup)
            .ok_or(Error::InvalidDomainSize { size: poly_len })?;
        if lde_len > MAX_DOMAIN {
            return Err(Error::InvalidDomainSize { size: lde_len });
        }
        Ok(lde_len)
    }
}

fn validate_blowup(blowup: usize) -> Result<()> {
    if blowup < 2 || !blowup.is_power_of_two() {
        return Err(Error::InvalidBlowup { factor: blowup });
    }
    Ok(())
}

/// Public commitment to the coefficient encoding of a multilinear polynomial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment {
    root: [u8; 32],
    n_vars: usize,
    blowup: usize,
}

impl Commitment {
    /// Canonical bytes: version, root, variable count, blowup.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.byte(VERSION);
        writer.bytes(&self.root);
        writer.u64_le(u64::try_from(self.n_vars).unwrap_or(u64::MAX));
        writer.u64_le(u64::try_from(self.blowup).unwrap_or(u64::MAX));
        writer.finish()
    }

    /// Decode a canonical commitment.
    ///
    /// # Errors
    /// Returns [`Error::MalformedInput`] for a wrong version, trailing bytes,
    /// or an out-of-range variable count/blowup.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        reader.version()?;
        let root = reader.digest()?;
        let n_vars = reader.dimension()?;
        let blowup = reader.dimension()?;
        reader.end()?;
        if n_vars == 0 || n_vars > MAX_VARS {
            return Err(Error::MalformedInput {
                reason: "n_vars outside BaseFold range",
            });
        }
        validate_blowup(blowup)?;
        let commitment = Self {
            root,
            n_vars,
            blowup,
        };
        commitment.check_domain()?;
        Ok(commitment)
    }

    /// Merkle root of the top LDE layer.
    #[must_use]
    pub const fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Number of multilinear variables.
    #[must_use]
    pub const fn n_vars(&self) -> usize {
        self.n_vars
    }

    /// LDE expansion factor.
    #[must_use]
    pub const fn blowup(&self) -> usize {
        self.blowup
    }

    fn check_domain(&self) -> Result<usize> {
        Params {
            blowup: self.blowup,
            num_queries: 1,
            grinding_bits: 0,
        }
        .lde_len(self.n_vars)
    }
}

/// Prover-side commitment data.
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
}

/// Commit to base-field multilinear coefficients (Möbius order).
///
/// # Errors
/// Returns [`Error::EmptyInput`], [`Error::InvalidDomainSize`],
/// [`Error::InvalidBlowup`], or [`Error::MalformedInput`] for invalid
/// coefficient counts or a variable count above [`MAX_VARS`].
pub fn commit(coeffs: &[Field], blowup: usize) -> Result<ProverState> {
    if coeffs.len() < 2 {
        return Err(Error::EmptyInput);
    }
    if !coeffs.len().is_power_of_two() {
        return Err(Error::InvalidDomainSize { size: coeffs.len() });
    }
    let n_vars = usize::try_from(coeffs.len().trailing_zeros())
        .map_err(|_| Error::InvalidDomainSize { size: coeffs.len() })?;
    if n_vars > MAX_VARS {
        return Err(Error::MalformedInput {
            reason: "n_vars above protocol cap",
        });
    }
    validate_blowup(blowup)?;
    let lde_len = coeffs
        .len()
        .checked_mul(blowup)
        .ok_or(Error::InvalidDomainSize { size: coeffs.len() })?;
    if lde_len > MAX_DOMAIN {
        return Err(Error::InvalidDomainSize { size: lde_len });
    }

    let ext: Vec<Ext4> = coeffs.iter().copied().map(Ext4::from_base).collect();
    let mut lde = evaluate_on_coset_ext(&ext, blowup, Field::ONE)?;
    bit_reverse_permute_ext(&mut lde);
    let tree = commit_layer(&lde)?;
    let root = tree.root();
    let commitment = Commitment {
        root,
        n_vars,
        blowup,
    };
    commitment.check_domain()?;
    Ok(ProverState {
        coeffs: ext,
        lde,
        tree,
        commitment,
    })
}

/// Sumcheck part of a `BaseFold` proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SumcheckProof {
    /// Claimed hypercube sum (the public evaluation).
    pub sum: Ext4,
    /// Round polynomials evaluated at `0..=2`.
    pub rounds: Vec<Vec<Ext4>>,
}

/// One two-value fold opening plus the Merkle path from the pair's parent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoldWitness {
    /// The two adjacent bit-reversed evaluations in the fold pair.
    pub values: [Ext4; 2],
    /// Path from the pair parent to the layer root.
    pub path: Vec<([u8; 32], bool)>,
}

/// Openings for one query index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryProof {
    /// One fold witness per layer, top first.
    pub folds: Vec<FoldWitness>,
}

/// Compact multilinear opening proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// Sumcheck reduction from `f(r)` to `c(rho)`.
    pub sumcheck: SumcheckProof,
    /// Roots of layers `1..n_vars` (the top root is in the commitment).
    pub layer_roots: Vec<[u8; 32]>,
    /// Proof-of-work nonce (`0` when grinding is disabled).
    pub pow_nonce: u64,
    /// Query openings.
    pub queries: Vec<QueryProof>,
}

impl Proof {
    /// Canonical bytes: version, sumcheck, roots, nonce, queries.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.byte(VERSION);
        writer.ext4(self.sumcheck.sum);
        writer.count(self.sumcheck.rounds.len());
        for round in &self.sumcheck.rounds {
            writer.count(round.len());
            for &value in round {
                writer.ext4(value);
            }
        }
        writer.count(self.layer_roots.len());
        for root in &self.layer_roots {
            writer.bytes(root);
        }
        writer.u64_le(self.pow_nonce);
        writer.count(self.queries.len());
        for query in &self.queries {
            writer.count(query.folds.len());
            for fold in &query.folds {
                writer.ext4(fold.values[0]);
                writer.ext4(fold.values[1]);
                writer.path(&fold.path);
            }
        }
        writer.finish()
    }

    /// Decode [`Proof::to_bytes`], rejecting non-canonical or over-cap data.
    ///
    /// # Errors
    /// Returns [`Error::MalformedInput`] on any encoding violation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        reader.version()?;
        let sum = reader.ext4()?;
        let mut rounds = Vec::new();
        for _ in 0..reader.count(MAX_ROUNDS)? {
            let mut round = Vec::new();
            for _ in 0..reader.count(MAX_ROUND_EVALS)? {
                round.push(reader.ext4()?);
            }
            rounds.push(round);
        }
        let mut layer_roots = Vec::new();
        for _ in 0..reader.count(MAX_LAYER_ROOTS)? {
            layer_roots.push(reader.digest()?);
        }
        let pow_nonce = reader.u64_le()?;
        let mut queries = Vec::new();
        for _ in 0..reader.count(MAX_QUERIES)? {
            let mut folds = Vec::new();
            for _ in 0..reader.count(MAX_FOLDS)? {
                let first = reader.ext4()?;
                let second = reader.ext4()?;
                folds.push(FoldWitness {
                    values: [first, second],
                    path: reader.path()?,
                });
            }
            queries.push(QueryProof { folds });
        }
        reader.end()?;
        let proof = Self {
            sumcheck: SumcheckProof { sum, rounds },
            layer_roots,
            pow_nonce,
            queries,
        };
        proof.check_shape()?;
        Ok(proof)
    }

    fn check_shape(&self) -> Result<()> {
        if self.layer_roots.len() > MAX_VARS {
            return Err(Error::MalformedInput {
                reason: "too many layer roots",
            });
        }
        for round in &self.sumcheck.rounds {
            if round.len() != 3 {
                return Err(Error::MalformedInput {
                    reason: "sumcheck round must have three evaluations",
                });
            }
        }
        for query in &self.queries {
            if query.folds.len() > MAX_VARS {
                return Err(Error::MalformedInput {
                    reason: "too many fold witnesses",
                });
            }
        }
        Ok(())
    }
}

/// Prove `f(point) = value` for a committed multilinear polynomial.
///
/// # Errors
/// Returns [`Error::MalformedInput`] for shape mismatches or a wrong
/// claimed evaluation, [`Error::InvalidBlowup`] on a parameter mismatch, and
/// propagates sumcheck/FRI errors.
#[allow(clippy::too_many_lines)]
pub fn open(
    state: &ProverState,
    point: &[Ext4],
    value: Ext4,
    params: Params,
    transcript: &mut Transcript,
) -> Result<Proof> {
    params.validate()?;
    let n_vars = state.commitment.n_vars;
    if point.len() != n_vars {
        return Err(Error::MalformedInput {
            reason: "point dimension must match n_vars",
        });
    }
    if state.commitment.blowup != params.blowup {
        return Err(Error::InvalidBlowup {
            factor: params.blowup,
        });
    }
    let lde_len = params.lde_len(n_vars)?;
    if state.lde.len() != lde_len {
        return Err(Error::InvalidDomainSize {
            size: state.lde.len(),
        });
    }

    absorb_statement(transcript, &state.commitment, point, value);

    let coeff_mle = Mle::new(state.coeffs.clone())?;
    let weight_mle = Mle::new(weight_table(point))?;
    let term = Term::new(Ext4::ONE, vec![0, 1]);
    let mut replay = transcript.clone();
    let sc = sumcheck::prove(&[coeff_mle.clone(), weight_mle], &[term], transcript)?;
    if sc.sum != value {
        return Err(Error::MalformedInput {
            reason: "claimed evaluation does not match the multilinear polynomial",
        });
    }
    if sc.round_evals.len() != n_vars {
        return Err(Error::MalformedInput {
            reason: "sumcheck round count does not match n_vars",
        });
    }
    let challenges = replay_sumcheck(&mut replay, &sc.round_evals, sc.sum)?;
    let fold_challenges: Vec<Ext4> = challenges.iter().rev().copied().collect();
    let final_value = coeff_mle.evaluate(&challenges)?;

    let half = Ext4::from_base(Field::new(2).inv());
    let mut layers: Vec<Vec<Ext4>> = Vec::with_capacity(n_vars + 1);
    layers.push(state.lde.clone());
    let mut trees = Vec::with_capacity(n_vars);
    trees.push(state.tree.clone());
    let mut points = bit_reversed_points(lde_len)?;
    let mut layer_roots = Vec::with_capacity(n_vars.saturating_sub(1));

    for i in 0..n_vars {
        let (next, next_points) = fold_layer(&layers[i], &points, fold_challenges[i], half)?;
        if i + 1 < n_vars {
            let tree = commit_layer(&next)?;
            let root = tree.root();
            transcript.absorb(b"basefold/layer-root", &root);
            layer_roots.push(root);
            trees.push(tree);
        }
        layers.push(next);
        points = next_points;
    }
    if layers[n_vars].len() != params.blowup
        || layers[n_vars].iter().any(|&item| item != final_value)
    {
        return Err(Error::FriVerificationFailed);
    }

    let pow_nonce = if params.grinding_bits > 0 {
        transcript.grind(b"basefold/pow", params.grinding_bits)
    } else {
        0
    };
    let pair_count = lde_len / 2;
    let mut queries = Vec::with_capacity(params.num_queries);
    for _ in 0..params.num_queries {
        let q = transcript
            .challenge_index(b"basefold/query", pair_count)
            .ok_or(Error::FriVerificationFailed)?;
        queries.push(open_query(&layers, &trees, n_vars, q)?);
    }

    Ok(Proof {
        sumcheck: SumcheckProof {
            sum: sc.sum,
            rounds: sc.round_evals,
        },
        layer_roots,
        pow_nonce,
        queries,
    })
}

/// Verify a compact multilinear opening.
///
/// # Errors
/// Returns [`Error::FriVerificationFailed`] for any failed fold, sumcheck,
/// Merkle, query, or proof-of-work check; shape errors otherwise.
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
    let n_vars = commitment.n_vars;
    if point.len() != n_vars {
        return Err(Error::MalformedInput {
            reason: "point dimension must match n_vars",
        });
    }
    if commitment.blowup != params.blowup {
        return Err(Error::InvalidBlowup {
            factor: params.blowup,
        });
    }
    let lde_len = params.lde_len(n_vars)?;
    proof.check_shape()?;
    if proof.sumcheck.rounds.len() != n_vars
        || proof.layer_roots.len() != n_vars.saturating_sub(1)
        || proof.queries.len() != params.num_queries
    {
        return Err(Error::MalformedInput {
            reason: "proof shape does not match n_vars/params",
        });
    }

    absorb_statement(transcript, commitment, point, value);

    if proof.sumcheck.sum != value {
        return Err(Error::FriVerificationFailed);
    }
    let mut expected = value;
    let mut challenges = Vec::with_capacity(n_vars);
    absorb_sumcheck(transcript, b"sumcheck/claim", &[expected]);
    for round in &proof.sumcheck.rounds {
        if round.len() != 3 || round[0] + round[1] != expected {
            return Err(Error::FriVerificationFailed);
        }
        absorb_sumcheck(transcript, b"sumcheck/round", round);
        let challenge = transcript.challenge_ext(b"sumcheck/challenge");
        challenges.push(challenge);
        expected = sumcheck::interpolate_at(round, challenge);
    }
    let weight = weight_at(point, &challenges);
    if weight == Ext4::ZERO {
        return Err(Error::FriVerificationFailed);
    }
    let final_value = expected * weight.inv();
    let fold_challenges: Vec<Ext4> = challenges.iter().rev().copied().collect();

    let mut roots = Vec::with_capacity(n_vars);
    roots.push(commitment.root);
    roots.extend_from_slice(&proof.layer_roots);
    for root in &roots[1..] {
        transcript.absorb(b"basefold/layer-root", root);
    }

    if params.grinding_bits > 0 {
        if !transcript.verify_grind(b"basefold/pow", proof.pow_nonce, params.grinding_bits) {
            return Err(Error::FriVerificationFailed);
        }
    } else if proof.pow_nonce != 0 {
        return Err(Error::FriVerificationFailed);
    }

    let half = Ext4::from_base(Field::new(2).inv());
    let pair_count = lde_len / 2;
    for query in &proof.queries {
        if query.folds.len() != n_vars {
            return Err(Error::FriVerificationFailed);
        }
        let q = transcript
            .challenge_index(b"basefold/query", pair_count)
            .ok_or(Error::FriVerificationFailed)?;
        let mut branch = q;
        let mut previous_index = 0usize;
        let mut folded: Option<Ext4> = None;
        for (i, fold) in query.folds.iter().enumerate() {
            let layer_len = lde_len
                .checked_shr(u32::try_from(i).map_err(|_| Error::FriVerificationFailed)?)
                .ok_or(Error::FriVerificationFailed)?;
            if layer_len < 2 || branch >= layer_len / 2 {
                return Err(Error::FriVerificationFailed);
            }
            let first = hash_leaf(&fold.values[0].to_le_bytes());
            let second = hash_leaf(&fold.values[1].to_le_bytes());
            let parent = hash_node(&first, &second);
            if !MerkleTree::verify_digest(&roots[i], &parent, branch, &fold.path) {
                return Err(Error::BadMerklePath);
            }
            if i > 0 {
                let opened = if previous_index & 1 == 0 {
                    fold.values[0]
                } else {
                    fold.values[1]
                };
                if folded != Some(opened) {
                    return Err(Error::FriVerificationFailed);
                }
            }
            let x = domain_point(layer_len, 2 * branch)?;
            folded = Some(fold_pair(
                fold.values[0],
                fold.values[1],
                fold_challenges[i],
                x,
                half,
            )?);
            previous_index = branch;
            branch >>= 1;
        }
        if folded != Some(final_value) {
            return Err(Error::FriVerificationFailed);
        }
    }
    Ok(())
}

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
    transcript.absorb(b"basefold/statement", &writer.finish());
}

fn absorb_sumcheck(transcript: &mut Transcript, label: &[u8], values: &[Ext4]) {
    let mut writer = Writer::new();
    for value in values {
        writer.ext4(*value);
    }
    transcript.absorb(label, &writer.finish());
}

fn replay_sumcheck(
    transcript: &mut Transcript,
    rounds: &[Vec<Ext4>],
    sum: Ext4,
) -> Result<Vec<Ext4>> {
    if rounds.len() > MAX_VARS {
        return Err(Error::MalformedInput {
            reason: "sumcheck round count above protocol cap",
        });
    }
    absorb_sumcheck(transcript, b"sumcheck/claim", &[sum]);
    let mut challenges = Vec::with_capacity(rounds.len());
    for round in rounds {
        if round.len() != 3 {
            return Err(Error::MalformedInput {
                reason: "sumcheck round must have three evaluations",
            });
        }
        absorb_sumcheck(transcript, b"sumcheck/round", round);
        challenges.push(transcript.challenge_ext(b"sumcheck/challenge"));
    }
    Ok(challenges)
}

fn weight_table(point: &[Ext4]) -> Vec<Ext4> {
    let mut table = vec![Ext4::ONE];
    for &coordinate in point {
        let mut next = Vec::with_capacity(table.len() * 2);
        for value in table {
            next.push(value);
            next.push(value * coordinate);
        }
        table = next;
    }
    table
}

fn weight_at(point: &[Ext4], challenges: &[Ext4]) -> Ext4 {
    point
        .iter()
        .zip(challenges)
        .fold(Ext4::ONE, |acc, (&coordinate, &challenge)| {
            acc * (Ext4::ONE - challenge + challenge * coordinate)
        })
}

fn fold_pair(first: Ext4, second: Ext4, challenge: Ext4, x: Field, half: Ext4) -> Result<Ext4> {
    if x == Field::ZERO {
        return Err(Error::FriVerificationFailed);
    }
    let inverse = Ext4::from_base(x.inv());
    let even = (first + second) * half;
    let odd = (first - second) * half * inverse;
    Ok((Ext4::ONE - challenge) * even + challenge * odd)
}

fn fold_layer(
    values: &[Ext4],
    points: &[Field],
    challenge: Ext4,
    half: Ext4,
) -> Result<(Vec<Ext4>, Vec<Field>)> {
    if values.len() < 2 || values.len() != points.len() || !values.len().is_power_of_two() {
        return Err(Error::InvalidDomainSize { size: values.len() });
    }
    let half_len = values.len() / 2;
    let mut folded = Vec::with_capacity(half_len);
    let mut next_points = Vec::with_capacity(half_len);
    for k in 0..half_len {
        let x = points[2 * k];
        folded.push(fold_pair(
            values[2 * k],
            values[2 * k + 1],
            challenge,
            x,
            half,
        )?);
        next_points.push(x.square());
    }
    Ok((folded, next_points))
}

fn bit_reversed_points(len: usize) -> Result<Vec<Field>> {
    if len < 2 || !len.is_power_of_two() {
        return Err(Error::InvalidDomainSize { size: len });
    }
    let omega = Field::primitive_root(len)?;
    let mut points = Vec::with_capacity(len);
    let mut current = Field::ONE;
    for _ in 0..len {
        points.push(current);
        current *= omega;
    }
    bit_reverse_permute(&mut points);
    Ok(points)
}

fn domain_point(layer_len: usize, index: usize) -> Result<Field> {
    if layer_len < 2 || !layer_len.is_power_of_two() || index >= layer_len {
        return Err(Error::InvalidDomainSize { size: layer_len });
    }
    let bits = usize::try_from(layer_len.trailing_zeros())
        .map_err(|_| Error::InvalidDomainSize { size: layer_len })?;
    let omega = Field::primitive_root(layer_len)?;
    let exponent = reverse_bits(index, bits);
    let exponent =
        u64::try_from(exponent).map_err(|_| Error::InvalidDomainSize { size: layer_len })?;
    Ok(omega.pow(exponent))
}

fn reverse_bits(value: usize, bits: usize) -> usize {
    if bits == 0 {
        return 0;
    }
    let width = usize::try_from(usize::BITS).unwrap_or(0);
    value.reverse_bits() >> (width - bits)
}

fn commit_layer(layer: &[Ext4]) -> Result<MerkleTree> {
    let mut flat = vec![0u8; 16 * layer.len()];
    for (slot, value) in flat.chunks_exact_mut(16).zip(layer) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
    MerkleTree::from_flat(&flat, 16)
}

fn open_query(
    layers: &[Vec<Ext4>],
    trees: &[MerkleTree],
    n_vars: usize,
    q: usize,
) -> Result<QueryProof> {
    let mut branch = q;
    let mut folds = Vec::with_capacity(n_vars);
    for i in 0..n_vars {
        let index = 2 * branch;
        let first = *layers
            .get(i)
            .and_then(|layer| layer.get(index))
            .ok_or(Error::FriVerificationFailed)?;
        let second = *layers
            .get(i)
            .and_then(|layer| layer.get(index + 1))
            .ok_or(Error::FriVerificationFailed)?;
        let path = trees
            .get(i)
            .ok_or(Error::FriVerificationFailed)?
            .prove(index)?;
        folds.push(FoldWitness {
            values: [first, second],
            path: path.get(1..).ok_or(Error::FriVerificationFailed)?.to_vec(),
        });
        branch >>= 1;
    }
    Ok(QueryProof { folds })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> Params {
        Params::new(4, 8, 0).unwrap()
    }

    fn coefficients(n_vars: usize) -> Vec<Field> {
        (0..(1usize << n_vars))
            .map(|i| Field::new(u32::try_from(i).unwrap() * 7 + 3))
            .collect()
    }

    fn point(n_vars: usize) -> Vec<Ext4> {
        (0..n_vars)
            .map(|i| {
                let i = u32::try_from(i).unwrap();
                Ext4::new(
                    Field::new(i * 5 + 2),
                    Field::new(i * 3 + 1),
                    Field::new(i * 7 + 4),
                    Field::new(i + 6),
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

    fn prove(n_vars: usize) -> (Commitment, Vec<Ext4>, Ext4, Proof) {
        let coeffs = coefficients(n_vars);
        let point = point(n_vars);
        let value = direct_eval(&coeffs, &point);
        let state = commit(&coeffs, params().blowup).unwrap();
        let commitment = state.commitment().clone();
        let mut transcript = Transcript::new(b"basefold-test");
        let proof = open(&state, &point, value, params(), &mut transcript).unwrap();
        (commitment, point, value, proof)
    }

    #[test]
    fn honest_openings_verify() {
        for n_vars in [1, 2, 5, 8] {
            let (commitment, point, value, proof) = prove(n_vars);
            let mut transcript = Transcript::new(b"basefold-test");
            verify(
                &commitment,
                &point,
                value,
                &proof,
                params(),
                &mut transcript,
            )
            .unwrap();
            assert_eq!(proof.layer_roots.len(), n_vars.saturating_sub(1));
            assert_eq!(proof.queries.len(), params().num_queries);
        }
    }

    #[test]
    fn wrong_point_rejected() {
        let (commitment, mut point, value, proof) = prove(4);
        point[0] += Ext4::ONE;
        let mut transcript = Transcript::new(b"basefold-test");
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
    fn wrong_commitment_rejected() {
        let (_, point, value, proof) = prove(4);
        let mut coeffs = coefficients(4);
        coeffs[0] += Field::ONE;
        let state = commit(&coeffs, params().blowup).unwrap();
        let mut transcript = Transcript::new(b"basefold-test");
        assert!(verify(
            state.commitment(),
            &point,
            value,
            &proof,
            params(),
            &mut transcript
        )
        .is_err());
    }

    #[test]
    fn tampered_sumcheck_rejected() {
        let (commitment, point, value, mut proof) = prove(4);
        proof.sumcheck.rounds[0][0] += Ext4::ONE;
        let mut transcript = Transcript::new(b"basefold-test");
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
    fn nonzero_nonce_rejected_without_grinding() {
        let (commitment, point, value, mut proof) = prove(4);
        proof.pow_nonce = 1;
        let mut transcript = Transcript::new(b"basefold-test");
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
    fn grinding_roundtrip() {
        let params = Params::new(4, 4, 8).unwrap();
        let coeffs = coefficients(4);
        let point = point(4);
        let value = direct_eval(&coeffs, &point);
        let state = commit(&coeffs, params.blowup).unwrap();
        let commitment = state.commitment().clone();
        let mut transcript = Transcript::new(b"basefold-grind");
        let proof = open(&state, &point, value, params, &mut transcript).unwrap();
        let mut transcript = Transcript::new(b"basefold-grind");
        verify(&commitment, &point, value, &proof, params, &mut transcript).unwrap();
    }

    #[test]
    fn params_mismatch_rejected() {
        let (commitment, point, value, proof) = prove(4);
        let other = Params::new(4, 7, 0).unwrap();
        let mut transcript = Transcript::new(b"basefold-test");
        assert!(verify(&commitment, &point, value, &proof, other, &mut transcript).is_err());
    }

    #[test]
    fn wrong_value_rejected() {
        let (commitment, point, value, proof) = prove(4);
        let mut transcript = Transcript::new(b"basefold-test");
        assert!(verify(
            &commitment,
            &point,
            value + Ext4::ONE,
            &proof,
            params(),
            &mut transcript
        )
        .is_err());
    }

    #[test]
    fn tampered_opening_rejected() {
        let (commitment, point, value, mut proof) = prove(4);
        proof.queries[0].folds[0].values[0] += Ext4::ONE;
        let mut transcript = Transcript::new(b"basefold-test");
        assert!(verify(
            &commitment,
            &point,
            value,
            &proof,
            params(),
            &mut transcript
        )
        .is_err());

        let (commitment, point, value, mut proof) = prove(4);
        proof.layer_roots[0][0] ^= 1;
        let mut transcript = Transcript::new(b"basefold-test");
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
    fn codec_rejects_bad_version() {
        let (_, _, _, proof) = prove(4);
        let mut bytes = proof.to_bytes();
        bytes[0] ^= 1;
        assert!(Proof::from_bytes(&bytes).is_err());

        let state = commit(&coefficients(4), params().blowup).unwrap();
        let mut bytes = state.commitment().to_bytes();
        bytes[0] ^= 1;
        assert!(Commitment::from_bytes(&bytes).is_err());
    }

    #[test]
    fn for_security_shape() {
        let params = Params::for_security(1024, 100).unwrap();
        assert_eq!(params.blowup, 16);
        assert!(params.num_queries > 0);
        assert!(params.grinding_bits <= 32);
        assert!(Params::for_security(1, 100).is_err());
        assert!(Params::for_security(3, 100).is_err());
        assert!(Params::for_security(1 << (MAX_VARS + 1), 100).is_err());
    }

    #[test]
    fn codec_roundtrip_and_trailing_reject() {
        let (_, _, _, proof) = prove(5);
        let bytes = proof.to_bytes();
        assert_eq!(Proof::from_bytes(&bytes).unwrap(), proof);
        let mut trailing = bytes;
        trailing.push(0);
        assert!(Proof::from_bytes(&trailing).is_err());

        let commitment = {
            let state = commit(&coefficients(5), params().blowup).unwrap();
            state.commitment().clone()
        };
        let encoded = commitment.to_bytes();
        assert_eq!(Commitment::from_bytes(&encoded).unwrap(), commitment);
    }

    #[test]
    fn rejects_bad_inputs() {
        assert!(commit(&[], 4).is_err());
        assert!(commit(&[Field::ONE], 4).is_err());
        assert!(commit(&[Field::ONE; 3], 4).is_err());
        assert!(Params::new(1, 1, 0).is_err());
        assert!(Params::new(4, 0, 0).is_err());

        let coeffs = coefficients(3);
        let state = commit(&coeffs, 4).unwrap();
        let too_short = point(2);
        let value = direct_eval(&coeffs, &point(3));
        let mut transcript = Transcript::new(b"basefold-test");
        assert!(open(&state, &too_short, value, params(), &mut transcript).is_err());

        let mut transcript = Transcript::new(b"basefold-test");
        let proof = open(&state, &point(3), value, params(), &mut transcript).unwrap();
        let commitment = state.commitment().clone();
        let mut transcript = Transcript::new(b"basefold-test");
        assert!(verify(
            &commitment,
            &too_short,
            value,
            &proof,
            params(),
            &mut transcript
        )
        .is_err());
    }

    #[test]
    fn proof_size_grows_with_variables() {
        let mut previous = 0;
        for n_vars in [4, 8, 12] {
            let (_, _, _, proof) = prove(n_vars);
            let bytes = proof.to_bytes().len();
            assert!(bytes > 0);
            if previous != 0 {
                assert!(bytes > previous);
            }
            previous = bytes;
        }
    }
}
