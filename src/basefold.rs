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
//! the `O(n)` openings used by [`crate::gemini`]. Optional Merkle caps
//! (see [`Params::with_cap_height`]) replace the top path steps of every
//! committed layer with one frontier of digests, so each query path shrinks
//! by up to `cap_height` steps.
//!
//! # Status
//!
//! This is a prototype, not an audited construction: it is not wired into
//! the AIR/STARK stack (it does back the committed [`crate::lookup_pcs`]
//! prototype), has no hiding layer, and no end-to-end soundness proof. The
//! query/proof-of-work schedule follows the FRI heuristic in
//! [`crate::fri`]. Treat the query bits as conjectured, size instances with
//! [`Params::for_security`], and do not deploy this as a production
//! commitment without review.
//!
//! Polynomials have at least one variable. Coefficients are in multilinear
//! (Möbius) order, matching [`crate::mle::Mle`] and [`crate::gemini`];
//! [`commit`] takes base-field coefficients and [`commit_ext`] takes
//! extension-field coefficients. Hypercube-evaluation helpers apply the
//! Möbius transform first. The point and claimed value live in [`Ext4`].
//!
//! # Transcript
//!
//! Callers must start the transcript with a unique context before
//! [`open`]/[`verify`]. Both functions absorb the commitment dimensions,
//! statement, sumcheck rounds, layer roots, proof-of-work nonce, and query
//! positions in the same order. Caps are authenticated by hashing their
//! frontier back to the commitment root (top layer) or to the proof's layer
//! roots (lower layers); they add no transcript messages beyond those roots.

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
/// Maximum Merkle cap height (`2^8` digests per cap, matching codec caps).
pub const MAX_CAP_HEIGHT: usize = 8;
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
    /// Merkle cap height: `2^cap_height` digests per layer stay in the
    /// proof instead of one root plus a longer path (`0` disables caps).
    ///
    /// Each query path shrinks by up to `cap_height` steps; the proof gains
    /// one cap frontier per committed layer. The effective height is clamped
    /// per layer to `depth - 1` (pair openings start at the parent digest).
    /// See [`Params::with_cap_height`].
    pub cap_height: usize,
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
            cap_height: 0,
        };
        params.validate()?;
        Ok(params)
    }

    /// Set the Merkle cap height (builder; default `0` = full paths).
    ///
    /// Values above [`MAX_CAP_HEIGHT`] are rejected by [`open`]/[`verify`].
    #[must_use]
    pub const fn with_cap_height(mut self, height: usize) -> Self {
        self.cap_height = height;
        self
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

    /// Validate the parameter schedule.
    ///
    /// # Errors
    /// Returns [`Error::InvalidBlowup`] for a blowup below two or not a
    /// power of two, [`Error::NoQueries`] for zero queries, or
    /// [`Error::MalformedInput`] for counts above protocol caps.
    pub fn validate(&self) -> Result<()> {
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
        if self.cap_height > MAX_CAP_HEIGHT {
            return Err(Error::MalformedInput {
                reason: "cap_height above 8",
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

/// Möbius transform from hypercube evaluations to monomial coefficients.
fn coeffs_from_evals_ext(evals: &[Ext4]) -> Result<Vec<Ext4>> {
    if evals.len() < 2 {
        return Err(Error::EmptyInput);
    }
    if !evals.len().is_power_of_two() {
        return Err(Error::InvalidDomainSize { size: evals.len() });
    }
    let n_vars = usize::try_from(evals.len().trailing_zeros())
        .map_err(|_| Error::InvalidDomainSize { size: evals.len() })?;
    if n_vars > MAX_VARS {
        return Err(Error::MalformedInput {
            reason: "n_vars above protocol cap",
        });
    }
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
            cap_height: 0,
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
    let ext: Vec<Ext4> = coeffs.iter().copied().map(Ext4::from_base).collect();
    commit_ext(&ext, blowup)
}

/// Commit to extension-field multilinear coefficients (Möbius order).
///
/// This is the [`commit`] analogue for columns whose values already live in
/// [`Ext4`], such as the quotient and multiplicity columns of
/// [`crate::lookup_pcs`]. The commitment shape is identical; only the
/// coefficient field differs.
///
/// # Errors
/// Returns [`Error::EmptyInput`], [`Error::InvalidDomainSize`],
/// [`Error::InvalidBlowup`], or [`Error::MalformedInput`] for invalid
/// coefficient counts or a variable count above [`MAX_VARS`].
pub fn commit_ext(coeffs: &[Ext4], blowup: usize) -> Result<ProverState> {
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

    let mut lde = evaluate_on_coset_ext(coeffs, blowup, Field::ONE)?;
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
        coeffs: coeffs.to_vec(),
        lde,
        tree,
        commitment,
    })
}

/// Commit a multilinear polynomial given its hypercube evaluations.
///
/// Applies the Möbius transform to obtain monomial coefficients, then calls
/// [`commit`]. Evaluation order matches [`crate::mle::Mle`].
///
/// # Errors
/// Returns the same errors as [`commit`].
pub fn commit_evals(evals: &[Field], blowup: usize) -> Result<ProverState> {
    let ext: Vec<Ext4> = evals.iter().copied().map(Ext4::from_base).collect();
    commit_evals_ext(&ext, blowup)
}

/// Commit a multilinear polynomial from extension-field hypercube
/// evaluations.
///
/// Applies the Möbius transform to obtain monomial coefficients, then calls
/// [`commit_ext`]. Evaluation order matches [`crate::mle::Mle`].
///
/// # Errors
/// Returns the same errors as [`commit_ext`].
pub fn commit_evals_ext(evals: &[Ext4], blowup: usize) -> Result<ProverState> {
    let coeffs = coeffs_from_evals_ext(evals)?;
    commit_ext(&coeffs, blowup)
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
    /// Path from the pair parent to the layer root or selected cap entry.
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
    /// One cap frontier per committed layer, top first; empty when
    /// [`Params::cap_height`] is zero.
    ///
    /// Each cap holds `2^drop` digests and hashes back to the corresponding
    /// layer root, so the top cap binds to the commitment and lower caps
    /// bind to [`Self::layer_roots`].
    pub caps: Vec<Vec<[u8; 32]>>,
    /// Proof-of-work nonce (`0` when grinding is disabled).
    pub pow_nonce: u64,
    /// Query openings.
    pub queries: Vec<QueryProof>,
}

impl Proof {
    /// Canonical bytes: version, sumcheck, roots, caps, nonce, queries.
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
        writer.count(self.caps.len());
        for cap in &self.caps {
            writer.cap(cap);
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
        let mut caps = Vec::new();
        for _ in 0..reader.count(MAX_LAYER_ROOTS)? {
            caps.push(reader.cap()?);
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
            caps,
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
        if self.caps.len() > MAX_VARS {
            return Err(Error::MalformedInput {
                reason: "too many caps",
            });
        }
        for cap in &self.caps {
            if cap.len() > (1usize << MAX_CAP_HEIGHT) {
                return Err(Error::MalformedInput {
                    reason: "cap height above protocol cap",
                });
            }
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
    let mut caps = Vec::with_capacity(n_vars);
    if params.cap_height > 0 {
        caps.push(layer_cap(&state.tree, params.cap_height));
    }

    for i in 0..n_vars {
        let (next, next_points) = fold_layer(&layers[i], &points, fold_challenges[i], half)?;
        if i + 1 < n_vars {
            let tree = commit_layer(&next)?;
            let root = tree.root();
            transcript.absorb(b"basefold/layer-root", &root);
            layer_roots.push(root);
            if params.cap_height > 0 {
                caps.push(layer_cap(&tree, params.cap_height));
            }
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
        queries.push(open_query(&layers, &trees, n_vars, q, params.cap_height)?);
    }

    Ok(Proof {
        sumcheck: SumcheckProof {
            sum: sc.sum,
            rounds: sc.round_evals,
        },
        layer_roots,
        caps,
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
    let expected_caps = if params.cap_height > 0 { n_vars } else { 0 };
    if proof.sumcheck.rounds.len() != n_vars
        || proof.layer_roots.len() != n_vars.saturating_sub(1)
        || proof.caps.len() != expected_caps
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
    if params.cap_height > 0 {
        for (i, cap) in proof.caps.iter().enumerate() {
            let layer_len = lde_len
                .checked_shr(u32::try_from(i).map_err(|_| Error::MalformedInput {
                    reason: "cap layer index exceeds u32",
                })?)
                .ok_or(Error::BadMerklePath)?;
            let drop = cap_drop(layer_len, params.cap_height);
            if cap.len() != 1usize << drop {
                return Err(Error::BadMerklePath);
            }
            if cap_root(cap) != Some(roots[i]) {
                return Err(Error::BadMerklePath);
            }
        }
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
            #[allow(clippy::cast_possible_truncation)]
            let depth = layer_len.trailing_zeros() as usize;
            let drop = cap_drop(layer_len, params.cap_height);
            if fold.path.len() != depth.saturating_sub(1).saturating_sub(drop) {
                return Err(Error::BadMerklePath);
            }
            let authenticated = if params.cap_height == 0 {
                MerkleTree::verify_digest(&roots[i], &parent, branch, &fold.path)
            } else {
                let entry = proof.caps[i]
                    .get(branch >> fold.path.len())
                    .ok_or(Error::BadMerklePath)?;
                verify_capped_digest(entry, &parent, &fold.path)
            };
            if !authenticated {
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

fn cap_drop(layer_len: usize, cap_height: usize) -> usize {
    #[allow(clippy::cast_possible_truncation)]
    let depth = layer_len.trailing_zeros() as usize;
    cap_height.min(depth.saturating_sub(1))
}

fn layer_cap(tree: &MerkleTree, cap_height: usize) -> Vec<[u8; 32]> {
    let layer_len = tree.num_leaves();
    tree.cap(cap_drop(layer_len, cap_height))
}

fn cap_root(cap: &[[u8; 32]]) -> Option<[u8; 32]> {
    if cap.is_empty() || !cap.len().is_power_of_two() {
        return None;
    }
    let mut level = cap.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            next.push(hash_node(&pair[0], &pair[1]));
        }
        level = next;
    }
    level.first().copied()
}

fn verify_capped_digest(entry: &[u8; 32], digest: &[u8; 32], path: &[([u8; 32], bool)]) -> bool {
    let mut current = *digest;
    for (sibling, is_left) in path {
        current = if *is_left {
            hash_node(&current, sibling)
        } else {
            hash_node(sibling, &current)
        };
    }
    &current == entry
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
    cap_height: usize,
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
        let drop = cap_drop(layers[i].len(), cap_height);
        let path = trees
            .get(i)
            .ok_or(Error::FriVerificationFailed)?
            .prove_capped(index, drop)?;
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

    fn direct_eval_ext(coeffs: &[Ext4], point: &[Ext4]) -> Ext4 {
        let n_vars = point.len();
        let mut total = Ext4::ZERO;
        for (index, coefficient) in coeffs.iter().enumerate() {
            let mut weight = Ext4::ONE;
            for (variable, coordinate) in point.iter().enumerate() {
                if (index >> (n_vars - 1 - variable)) & 1 == 1 {
                    weight *= *coordinate;
                }
            }
            total += *coefficient * weight;
        }
        total
    }

    fn prove_with(n_vars: usize, params: Params) -> (Commitment, Vec<Ext4>, Ext4, Proof) {
        let coeffs = coefficients(n_vars);
        let point = point(n_vars);
        let value = direct_eval(&coeffs, &point);
        let state = commit(&coeffs, params.blowup).unwrap();
        let commitment = state.commitment().clone();
        let mut transcript = Transcript::new(b"basefold-test");
        let proof = open(&state, &point, value, params, &mut transcript).unwrap();
        (commitment, point, value, proof)
    }

    fn prove(n_vars: usize) -> (Commitment, Vec<Ext4>, Ext4, Proof) {
        prove_with(n_vars, params())
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
    fn ext_coefficients_and_evaluations_roundtrip() {
        let n_vars = 4;
        let coeffs: Vec<Ext4> = (0..(1usize << n_vars))
            .map(|i| {
                let i = u32::try_from(i).unwrap();
                Ext4::new(
                    Field::new(i * 3 + 1),
                    Field::new(i * 5 + 2),
                    Field::new(i * 7 + 3),
                    Field::new(i + 4),
                )
            })
            .collect();
        let point = point(n_vars);
        let value = direct_eval_ext(&coeffs, &point);
        let state = commit_ext(&coeffs, params().blowup).unwrap();
        let commitment = state.commitment().clone();
        let mut transcript = Transcript::new(b"basefold-ext");
        let proof = open(&state, &point, value, params(), &mut transcript).unwrap();
        let mut transcript = Transcript::new(b"basefold-ext");
        verify(
            &commitment,
            &point,
            value,
            &proof,
            params(),
            &mut transcript,
        )
        .unwrap();

        let evals: Vec<Ext4> = (0..(1usize << n_vars))
            .map(|i| {
                let i = u32::try_from(i).unwrap();
                Ext4::new(
                    Field::new(i * 11 + 5),
                    Field::new(i * 13 + 6),
                    Field::new(i * 17 + 7),
                    Field::new(i + 8),
                )
            })
            .collect();
        let expected = Mle::new(evals.clone()).unwrap().evaluate(&point).unwrap();
        let state = commit_evals_ext(&evals, params().blowup).unwrap();
        let commitment = state.commitment().clone();
        let mut transcript = Transcript::new(b"basefold-ext-evals");
        let proof = open(&state, &point, expected, params(), &mut transcript).unwrap();
        let mut transcript = Transcript::new(b"basefold-ext-evals");
        verify(
            &commitment,
            &point,
            expected,
            &proof,
            params(),
            &mut transcript,
        )
        .unwrap();

        assert!(commit_ext(&[], params().blowup).is_err());
        assert!(commit_evals_ext(&[], params().blowup).is_err());
        assert!(commit_evals_ext(&[Ext4::ONE], params().blowup).is_err());
    }

    #[test]
    fn base_commit_matches_ext_commit() {
        let coeffs = coefficients(4);
        let ext: Vec<Ext4> = coeffs.iter().copied().map(Ext4::from_base).collect();
        let base = commit(&coeffs, params().blowup).unwrap();
        let extension = commit_ext(&ext, params().blowup).unwrap();
        assert_eq!(base.commitment(), extension.commitment());
    }

    #[test]
    fn capped_openings_verify_and_shrink_paths() {
        for (n_vars, cap_height) in [(2usize, 1usize), (5, 2), (8, 4)] {
            let capped = params().with_cap_height(cap_height);
            let (commitment, point, value, proof) = prove_with(n_vars, capped);
            let mut transcript = Transcript::new(b"basefold-test");
            verify(&commitment, &point, value, &proof, capped, &mut transcript).unwrap();
            assert_eq!(proof.caps.len(), n_vars);
            assert_eq!(cap_root(&proof.caps[0]), Some(commitment.root()));
            let lde_len = (1usize << n_vars) * capped.blowup;
            for i in 0..n_vars {
                let layer_len = lde_len >> i;
                let drop = cap_drop(layer_len, cap_height);
                assert_eq!(proof.caps[i].len(), 1usize << drop);
                #[allow(clippy::cast_possible_truncation)]
                let depth = layer_len.trailing_zeros() as usize;
                assert_eq!(
                    proof.queries[0].folds[i].path.len(),
                    depth - 1 - drop,
                    "layer {i} path"
                );
            }
        }

        let capped = params().with_cap_height(4);
        let (_, _, _, capped_proof) = prove_with(8, capped);
        let (_, _, _, plain_proof) = prove(8);
        assert!(capped_proof.to_bytes().len() < plain_proof.to_bytes().len());
    }

    #[test]
    fn capped_codec_roundtrip_and_tamper_rejected() {
        let capped = params().with_cap_height(2);
        let (commitment, point, value, proof) = prove_with(5, capped);
        let bytes = proof.to_bytes();
        let decoded = Proof::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, proof);
        let mut transcript = Transcript::new(b"basefold-test");
        verify(
            &commitment,
            &point,
            value,
            &decoded,
            capped,
            &mut transcript,
        )
        .unwrap();

        let mut bad = proof.clone();
        bad.caps[0][0][0] ^= 1;
        let mut transcript = Transcript::new(b"basefold-test");
        assert!(verify(&commitment, &point, value, &bad, capped, &mut transcript).is_err());

        let mut bad = proof.clone();
        bad.caps[0].pop();
        let mut transcript = Transcript::new(b"basefold-test");
        assert!(verify(&commitment, &point, value, &bad, capped, &mut transcript).is_err());

        let mut bad = proof;
        bad.caps[bad.layer_roots.len() - 1][0][0] ^= 1;
        let mut transcript = Transcript::new(b"basefold-test");
        assert!(verify(&commitment, &point, value, &bad, capped, &mut transcript).is_err());
    }

    #[test]
    fn cap_mismatch_and_height_cap_rejected() {
        let capped = params().with_cap_height(2);
        let (commitment, capped_point, capped_value, capped_proof) = prove_with(5, capped);
        let mut transcript = Transcript::new(b"basefold-test");
        assert!(verify(
            &commitment,
            &capped_point,
            capped_value,
            &capped_proof,
            params(),
            &mut transcript
        )
        .is_err());

        let (commitment, plain_point, plain_value, plain_proof) = prove(5);
        let mut transcript = Transcript::new(b"basefold-test");
        assert!(verify(
            &commitment,
            &plain_point,
            plain_value,
            &plain_proof,
            capped,
            &mut transcript
        )
        .is_err());

        let too_high = params().with_cap_height(MAX_CAP_HEIGHT + 1);
        let coeffs = coefficients(3);
        let state = commit(&coeffs, 4).unwrap();
        let high_point = point(3);
        let value = direct_eval(&coeffs, &high_point);
        let mut transcript = Transcript::new(b"basefold-test");
        assert!(open(&state, &high_point, value, too_high, &mut transcript).is_err());
    }

    #[test]
    fn cap_height_clamps_to_layer_depth() {
        for n_vars in [1usize, 2, 3] {
            for cap_height in [0usize, 1, 3, MAX_CAP_HEIGHT] {
                let capped = params().with_cap_height(cap_height);
                let (commitment, point, value, proof) = prove_with(n_vars, capped);
                let mut transcript = Transcript::new(b"basefold-test");
                verify(&commitment, &point, value, &proof, capped, &mut transcript).unwrap();
                if cap_height == 0 {
                    assert_eq!(proof.caps.len(), 0);
                } else {
                    assert_eq!(proof.caps.len(), n_vars);
                }
            }
        }
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
