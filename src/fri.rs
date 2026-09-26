//! FRI polynomial commitment over [`BabyBear`](crate::babybear::Field).
//!
//! Proves that committed evaluations are close to a low-degree polynomial.
//! Self-contained: Reed-Solomon encoding via [`crate::ntt`], Merkle
//! commitments via [`crate::merkle`], Fiat-Shamir via [`crate::transcript`].
//!
//! Two entry points share one folding core:
//! - [`commit`]: coefficients → coset LDE → FRI layers.
//! - [`commit_evals`]: caller-supplied LDE evaluations (already expanded, e.g.
//!   a STARK composition polynomial) of declared degree `<= degree_bound`.
//!
//! # Protocol (transcript labels; prover and verifier must match exactly)
//! 0. Absorb `(lde_len, poly_len, degree_bound)` under `("fri-dims", ...)`
//!    so prover-echoed dimensions bind every challenge below (otherwise
//!    third parties could mutate those proof bytes and still verify).
//! 1. Commit `layer[0]` = bit-reversed LDE evaluations.
//! 2. For each layer `i`: absorb every digest of `cap[i]` under
//!    `("fri-layer-root", ...)` (with caps disabled the cap is `[root]`,
//!    so the transcript is unchanged); if the layer
//!    is larger than `final_size`, squeeze three challenges
//!    `("fri-fold", r0[i], r1[i], r2[i])` and fold each adjacent quad
//!    `(e0, e1, e2, e3)` at domain point `x` into
//!    `A + r0*B + r1*C + r2*D`, where `P(X) = A + BX + CX^2 + DX^3` in
//!    `Y = X^4` is the even/odd-style decomposition of the unique
//!    interpolant through the quad.
//! 3. Absorb `("fri-final", final_poly_bytes)`.
//! 4. If `grinding_bits > 0`, grind `("fri-pow", nonce)` with that difficulty
//!    (proof-of-work over the full history); queries are sampled after, so
//!    they bind to the work.
//! 5. For each query: squeeze `("fri-query", index)` masked to the LDE size.
//!
//! Folding quads are groups of four adjacent indices because layer
//! evaluations are kept in bit-reversed order: reversing turns the two
//! least-significant index bits into the most significant ones, so each
//! quad sits at `(x, -x, j0*x, -j0*x)` for one fixed fourth root `j0`
//! (the same at every depth), sharing the fourth power `x^4`. The
//! decomposition quarters the degree each round; a plain linear combination
//! would not reduce the degree and would make the test vacuous.
//!
//! Leaves commit to single field elements; each query opens all four
//! members of every folded quad but carries only the middle path segment:
//! the bottom two siblings are recomputed from the four values and the
//! top steps live in the layer cap (see [`MerkleTree::cap`]).
//!
//! # Soundness notes
//! Per-query soundness is governed by the code rate and the field size.
//! Additionally [`verify`] checks the final layer by interpolation at the
//! true folded domain points: with `f` folds, the residual degree bound is
//! `degree_bound >> (2 * f)` (each fold quarters the degree), and all higher
//! divided differences must vanish.
//! Callers wanting a meaningful final check should arrange
//! `(degree_bound >> (2 * folds)) + 1 <= final_size`; for [`commit`] this
//! holds automatically (rate `1 / blowup`). A commitment declaring
//! `degree_bound >= lde_len` is rejected by [`verify`].
//!
//! # Conjectured bit-levels (Fiat-Shamir + FRI in the QROM, Johnson-radius
//! heuristic: a word `delta`-far from the Reed-Solomon code survives one
//! query with probability `<= 1 - delta`, with `delta ~= 1 - sqrt(rate)`)
//! - Bench shape (`blowup = 8`, rate `1/8`, `12` queries, no grinding):
//!   `delta ~= 0.65`, about `1.5` bits per query, roughly **18 bits** total.
//!   Fast, but not production soundness.
//! - Production shape (`blowup = 16`, rate `1/16`, `40` queries, `20`-bit
//!   grinding): `delta ~= 0.75`, about `2` bits per query, roughly
//!   **80 + 20 = 100 bits** total (queries plus proof-of-work).
//!
//! Grinding bits add one-to-one: finding a `d`-bit nonce costs the prover
//! `2^d` hashes and denies the forger a `2^-d` shortcut. Size the query
//! count from the rate first, then top up with grinding to the target.
//!
//! Merkle caps are size-only: they shorten transmitted paths without
//! changing the committed function or the query count, so the bit-levels
//! above are unaffected (fewer bytes, same challenges).

use crate::babybear::Field;
use crate::error::{Error, Result};
use crate::merkle::{hash_leaf, hash_node, MerkleTree};
use crate::ntt::{bit_reverse_permute, evaluate_on_coset};
use crate::transcript::Transcript;

/// Coset shift for every LDE domain in this crate (NTT and FRI agree).
pub const LDE_SHIFT: Field = Field::GENERATOR;

/// FRI parameters, validated at construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// Reed-Solomon expansion factor (`>= 2`, power of two).
    ///
    /// Used by [`commit`] for encoding. The [`commit_evals`] path takes
    /// already-expanded evaluations and ignores this field beyond validation.
    pub blowup: usize,
    /// Number of query openings (`>= 1`).
    pub num_queries: usize,
    /// Size of the final layer sent in the clear (power of two, `>= 1`).
    pub final_size: usize,
    /// Proof-of-work difficulty in leading-zero bits (`0` disables grinding).
    ///
    /// Adds that many conjectured soundness bits at `2^bits` prover hashes;
    /// see the module soundness notes for sizing.
    pub grinding_bits: u32,
    /// Merkle cap height: `2^cap_height` digests per layer stay in the
    /// commitment instead of one root (`0` disables caps).
    ///
    /// Each query path shrinks by up to `cap_height` steps (33 bytes
    /// each); the commitment grows by the cap digests. Clamped per layer
    /// to `depth - 2` (the verifier rebuilds the bottom two levels from
    /// the quad values). See [`crate::merkle`]; [`Params::for_security`]
    /// sizes it automatically.
    pub cap_height: usize,
}

impl Params {
    /// Validate parameters.
    ///
    /// # Errors
    /// Returns [`Error::InvalidBlowup`], [`Error::NoQueries`], or
    /// [`Error::InvalidDomainSize`] for out-of-range inputs.
    pub const fn new(blowup: usize, num_queries: usize, final_size: usize) -> Result<Self> {
        if blowup < 2 || !blowup.is_power_of_two() {
            return Err(Error::InvalidBlowup { factor: blowup });
        }
        if num_queries == 0 {
            return Err(Error::NoQueries);
        }
        if final_size == 0 || !final_size.is_power_of_two() {
            return Err(Error::InvalidDomainSize { size: final_size });
        }
        Ok(Self {
            blowup,
            num_queries,
            final_size,
            grinding_bits: 0,
            cap_height: 0,
        })
    }

    /// Set the proof-of-work difficulty (builder; default `0` = disabled).
    ///
    /// Values above `32` are rejected by the transcript at prove time via
    /// `debug_assert`; production callers should use `16..=24`.
    #[must_use]
    pub const fn with_grinding_bits(mut self, bits: u32) -> Self {
        self.grinding_bits = bits;
        self
    }

    /// Set the Merkle cap height (builder; default `0` = root only).
    ///
    /// Each layer then commits `2^cap_height` digests (clamped to
    /// `depth - 2`) and every query path shrinks by the same count.
    /// Values above `4` rarely pay; [`Params::for_security`] sizes it.
    #[must_use]
    pub const fn with_cap_height(mut self, height: usize) -> Self {
        self.cap_height = height;
        self
    }

    /// Production parameters for the [`commit`] path: blowup 16 (rate
    /// 1/16), queries plus grinding sized for `target_bits` conjectured
    /// soundness bits, and size-optimal final size and cap height.
    ///
    /// `poly_len` is the coefficient count (power of two, non-empty);
    /// the expanded LDE must fit `2^27`. Plain (non-ZK) path only;
    /// masked callers size [`commit_evals`] via their outer protocol.
    ///
    /// # Errors
    /// Returns [`Error::EmptyInput`] for empty input,
    /// [`Error::InvalidDomainSize`] for non-power-of-two lengths or an
    /// LDE above `2^27`.
    pub fn for_security(poly_len: usize, target_bits: u32) -> Result<Self> {
        if poly_len == 0 {
            return Err(Error::EmptyInput);
        }
        if !poly_len.is_power_of_two() {
            return Err(Error::InvalidDomainSize { size: poly_len });
        }
        let blowup = 16;
        let lde_len = poly_len
            .checked_mul(blowup)
            .ok_or(Error::InvalidDomainSize { size: poly_len })?;
        if lde_len > (1usize << Field::TWO_ADICITY) {
            return Err(Error::InvalidDomainSize { size: lde_len });
        }
        let (num_queries, grinding_bits) = tune_strength(target_bits, 2000);
        let (final_size, cap_height) = tune_shape(lde_len, num_queries, &[]);
        Ok(Self {
            blowup,
            num_queries,
            final_size,
            grinding_bits,
            cap_height,
        })
    }
}

/// Public commitment: one Merkle cap per FRI layer plus dimensions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment {
    /// Merkle caps, one per layer from the LDE down to the final layer.
    /// Each cap holds `2^cap_height` digests (clamped to `depth - 2`);
    /// with caps disabled it is the single root.
    pub caps: Vec<Vec<[u8; 32]>>,
    /// Length of the LDE domain.
    pub lde_len: usize,
    /// Number of polynomial coefficients committed ([`commit`] path).
    ///
    /// For [`commit_evals`] this echoes `lde_len` (message length unknown).
    pub poly_len: usize,
    /// Declared maximum degree (`< lde_len`, enforced by [`verify`]).
    pub degree_bound: usize,
}

/// Prover-side state: layer evaluations plus their Merkle trees.
#[derive(Clone, Debug)]
pub struct ProverState {
    /// Evaluations per layer, bit-reversed order, halving each round.
    pub layers: Vec<Vec<Field>>,
    /// Merkle tree per layer, parallel to `layers`.
    pub trees: Vec<MerkleTree>,
    /// Caps in layer order (derived from `trees` at commit time).
    pub caps: Vec<Vec<[u8; 32]>>,
    /// Fold challenges, three per layer transition.
    pub fold_challenges: Vec<[Field; 3]>,
    /// Length of the LDE domain.
    pub lde_len: usize,
    /// Number of coefficients ([`commit`] path) or `lde_len`.
    pub poly_len: usize,
    /// Declared maximum degree.
    pub degree_bound: usize,
    /// Parameters used.
    pub params: Params,
}

/// One folding step opening: the quad values plus one shared path.
///
/// Only the middle path segment is stored: the bottom two siblings (the
/// odd leaf's digest, then the right pair node) are recomputed from the
/// four values, and the top `drop` steps live in the layer cap instead.
/// With caps disabled the stored path runs to the root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoldWitness {
    /// Evaluations at the four quad positions.
    pub values: [Field; 4],
    /// Merkle path of the quad node (full path minus its first two steps).
    pub path: Vec<([u8; 32], bool)>,
}

/// All openings for one query index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryProof {
    /// One witness per folding step (layers minus one).
    pub folds: Vec<FoldWitness>,
}

/// FRI proof: final polynomial plus per-query openings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// Final layer in the clear.
    pub final_poly: Vec<Field>,
    /// Query openings in transcript order.
    pub queries: Vec<QueryProof>,
    /// Proof-of-work nonce for `("fri-pow", grinding_bits)` (`0` when
    /// grinding is disabled).
    pub pow_nonce: u64,
}

impl Proof {
    /// Canonical bytes: version, final polynomial, nonce, then queries.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = crate::codec::Writer::new();
        writer.byte(crate::codec::VERSION);
        self.write_body(&mut writer);
        writer.finish()
    }

    /// Decode [`Proof::to_bytes`] output, rejecting anything else.
    ///
    /// Shape-checked only; soundness checks happen in [`verify`].
    ///
    /// # Errors
    /// Returns [`Error::MalformedInput`] on any encoding violation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = crate::codec::Reader::new(bytes);
        reader.version()?;
        let proof = Self::read_body(&mut reader)?;
        reader.end()?;
        Ok(proof)
    }

    pub(crate) fn write_body(&self, writer: &mut crate::codec::Writer) {
        writer.count(self.final_poly.len());
        for value in &self.final_poly {
            writer.field(*value);
        }
        writer.u64_le(self.pow_nonce);
        writer.count(self.queries.len());
        for query in &self.queries {
            writer.count(query.folds.len());
            for fold in &query.folds {
                for value in &fold.values {
                    writer.field(*value);
                }
                writer.path(&fold.path);
            }
        }
    }

    pub(crate) fn read_body(reader: &mut crate::codec::Reader<'_>) -> Result<Self> {
        use crate::codec::{MAX_ELEMS, MAX_FOLDS, MAX_QUERIES};
        let mut final_poly = Vec::new();
        for _ in 0..reader.count(MAX_ELEMS)? {
            final_poly.push(reader.field()?);
        }
        let pow_nonce = reader.u64_le()?;
        let mut queries = Vec::new();
        for _ in 0..reader.count(MAX_QUERIES)? {
            let mut folds = Vec::new();
            for _ in 0..reader.count(MAX_FOLDS)? {
                let values = [
                    reader.field()?,
                    reader.field()?,
                    reader.field()?,
                    reader.field()?,
                ];
                let path = reader.path()?;
                folds.push(FoldWitness { values, path });
            }
            queries.push(QueryProof { folds });
        }
        Ok(Self {
            final_poly,
            queries,
            pow_nonce,
        })
    }
}

/// Commit to polynomial coefficients.
///
/// Encodes on the [`LDE_SHIFT`] coset, bit-reverses, then folds down to
/// `params.final_size`. The declared degree bound is `len - 1`.
///
/// # Errors
/// Returns [`Error`] for empty/non-power-of-two coefficient counts,
/// oversized domains, or unreachable final sizes.
pub fn commit(
    poly_coeffs: &[Field],
    params: Params,
    transcript: &mut Transcript,
) -> Result<ProverState> {
    if poly_coeffs.is_empty() {
        return Err(Error::EmptyInput);
    }
    if !poly_coeffs.len().is_power_of_two() {
        return Err(Error::InvalidDomainSize {
            size: poly_coeffs.len(),
        });
    }
    let lde = evaluate_on_coset(poly_coeffs, params.blowup, LDE_SHIFT)?;
    let degree_bound = poly_coeffs.len() - 1;
    commit_inner(lde, degree_bound, poly_coeffs.len(), params, transcript)
}

/// Commit to already-expanded LDE evaluations of declared degree.
///
/// `lde_evals` must be natural-order evaluations on the [`LDE_SHIFT`] coset
/// of size `lde_evals.len()` (power of two, `<= 2^27`), of a polynomial of
/// degree `<= degree_bound < lde_len`. Used for STARK composition polynomials
/// whose evaluations the caller already holds.
///
/// # Errors
/// Returns [`Error`] for empty/non-power-of-two inputs, oversized domains,
/// vacuous degree bounds, or unreachable final sizes.
pub fn commit_evals(
    lde_evals: &[Field],
    degree_bound: usize,
    params: Params,
    transcript: &mut Transcript,
) -> Result<ProverState> {
    if lde_evals.is_empty() {
        return Err(Error::EmptyInput);
    }
    if !lde_evals.len().is_power_of_two() || lde_evals.len() > (1usize << Field::TWO_ADICITY) {
        return Err(Error::InvalidDomainSize {
            size: lde_evals.len(),
        });
    }
    if degree_bound >= lde_evals.len() {
        return Err(Error::MalformedInput {
            reason: "degree bound must be below LDE size (rate < 1)",
        });
    }
    commit_inner(
        lde_evals.to_vec(),
        degree_bound,
        lde_evals.len(),
        params,
        transcript,
    )
}

fn commit_inner(
    mut current: Vec<Field>,
    degree_bound: usize,
    poly_len: usize,
    params: Params,
    transcript: &mut Transcript,
) -> Result<ProverState> {
    let lde_len = current.len();
    check_layers(lde_len, params.final_size)?;
    // Early rate gate (mirrors `verify`): fail at prove time, not verify.
    if lde_len < 2 || degree_bound + 1 > lde_len / 2 {
        return Err(Error::MalformedInput {
            reason: "degree bound implies rate >= 1/2",
        });
    }
    // Bind the prover-echoed dimensions before any challenge: without this,
    // `poly_len` (and small `degree_bound` shifts) ride in the proof bytes
    // without touching the transcript, so third parties could mutate proofs
    // that still verify. Mirrored exactly in [`verify`].
    transcript.absorb(b"fri-dims", &encode_dims(lde_len, poly_len, degree_bound));

    // Domain points in matching bit-reversed order, plus the fixed fourth
    // root shared by every quad at every depth (see `fold_values`).
    let mut points = coset_points(lde_len)?;
    bit_reverse_permute(&mut current);
    bit_reverse_permute(&mut points);
    let unit = Field::two_adic_generator(2)?;

    let mut layers: Vec<Vec<Field>> = Vec::new();
    let mut trees: Vec<MerkleTree> = Vec::new();
    let mut caps: Vec<Vec<[u8; 32]>> = Vec::new();
    let mut fold_challenges: Vec<[Field; 3]> = Vec::new();
    layers.push(current);
    let mut layer_points = points;

    loop {
        let idx = layers.len() - 1;
        let tree = commit_layer(&layers[idx])?;
        // One absorb per cap digest under the historic label: with caps
        // disabled the cap is `[root]` and the transcript is unchanged.
        let cap = tree.cap(fri_drop_top(tree.num_leaves(), params.cap_height));
        for digest in &cap {
            transcript.absorb(b"fri-layer-root", digest);
        }
        trees.push(tree);
        caps.push(cap);
        if layers[idx].len() == params.final_size {
            break;
        }
        let mut challenges = [Field::ZERO; 3];
        for slot in &mut challenges {
            *slot = transcript.challenge_bb(b"fri-fold");
        }
        fold_challenges.push(challenges);
        let (next_values, next_points) = fold_layer(&layers[idx], &layer_points, challenges, unit);
        layers.push(next_values);
        layer_points = next_points;
    }

    let final_poly = layers[layers.len() - 1].clone();
    transcript.absorb(b"fri-final", &encode_fields(&final_poly));

    Ok(ProverState {
        layers,
        trees,
        caps,
        fold_challenges,
        lde_len,
        poly_len,
        degree_bound,
        params,
    })
}

/// Open query positions sampled from `transcript`.
///
/// Grinds the proof-of-work nonce first (when `grinding_bits > 0`), so the
/// sampled indices bind to the work. Returns the proof together with the
/// sampled leaf indices (bit-reversed layer order). Indices are
/// verifier-recomputable and are not stored in the proof itself.
///
/// # Errors
/// Returns [`Error`] only when a Merkle opening unexpectedly fails; query
/// sampling itself is infallible.
pub fn open(state: &ProverState, transcript: &mut Transcript) -> Result<(Proof, Vec<usize>)> {
    let pow_nonce = if state.params.grinding_bits > 0 {
        transcript.grind(b"fri-pow", state.params.grinding_bits)
    } else {
        0
    };
    let mut queries = Vec::with_capacity(state.params.num_queries);
    let mut indices = Vec::with_capacity(state.params.num_queries);
    for _ in 0..state.params.num_queries {
        let leaf_index = transcript.challenge_index(b"fri-query", state.lde_len);
        queries.push(open_one(state, leaf_index)?);
        indices.push(leaf_index);
    }
    let proof = Proof {
        final_poly: state.layers[state.layers.len() - 1].clone(),
        queries,
        pow_nonce,
    };
    Ok((proof, indices))
}

/// Verify a FRI proof, replaying the transcript.
///
/// Replays fold challenges, checks Merkle paths and folding relations at
/// every query, and checks the final layer against the residual degree bound
/// by interpolation at the true folded domain points. Returns the sampled
/// query indices (bit-reversed layer order) for outer protocols that open
/// companion commitments at the same positions.
///
/// # Errors
/// Returns [`Error::FriVerificationFailed`] or [`Error::BadMerklePath`]
/// when any check fails, or dimension errors when the proof does not match
/// the commitment and parameters.
pub fn verify(
    commitment: &Commitment,
    proof: &Proof,
    params: Params,
    transcript: &mut Transcript,
) -> Result<Vec<usize>> {
    if proof.queries.len() != params.num_queries {
        return Err(Error::FriVerificationFailed);
    }
    if proof.final_poly.len() != params.final_size {
        return Err(Error::FriVerificationFailed);
    }
    if commitment.caps.is_empty() {
        return Err(Error::FriVerificationFailed);
    }
    if commitment.lde_len == 0
        || !commitment.lde_len.is_power_of_two()
        || commitment.lde_len > (1usize << Field::TWO_ADICITY)
    {
        return Err(Error::InvalidDomainSize {
            size: commitment.lde_len,
        });
    }
    if commitment.degree_bound >= commitment.lde_len {
        return Err(Error::FriVerificationFailed);
    }
    // Rate gate (load-bearing for soundness): absolute rate below one half.
    // The commitment is untrusted input — without this gate, a forger could
    // declare `bound ~= lde_len`, making the final degree check vacuous
    // while honest folding keeps every query consistent. Production callers
    // should target rate `<= 1/4` via blowup and tight bounds and size
    // `num_queries` accordingly (see soundness notes above).
    if commitment.lde_len < 2 || commitment.degree_bound + 1 > commitment.lde_len / 2 {
        return Err(Error::FriVerificationFailed);
    }
    let folds = commitment.caps.len().saturating_sub(1);
    if folds > 30 || (commitment.lde_len >> (2 * folds)) != params.final_size {
        return Err(Error::FriVerificationFailed);
    }
    // Pin cap shapes before hashing them: each layer's cap holds exactly
    // `2^drop` digests for its depth. The commitment is untrusted input;
    // without this, a bloated cap wastes hashing and a short one fails
    // confusingly late. (`i <= 30` here, so `2 * i` cannot overflow and
    // every shift below is exact.)
    for (i, cap) in commitment.caps.iter().enumerate() {
        let layer_len = commitment.lde_len >> (2 * i);
        #[allow(clippy::cast_possible_truncation)]
        let depth = layer_len.trailing_zeros() as usize;
        let drop = params.cap_height.min(depth.saturating_sub(2));
        if cap.len() != 1usize << drop {
            return Err(Error::BadMerklePath);
        }
    }

    // Replay absorptions and fold challenges exactly as the prover did,
    // starting with the dimension binding (any mutated dimension diverges
    // every challenge below, so malleated proofs fail at the queries).
    transcript.absorb(
        b"fri-dims",
        &encode_dims(
            commitment.lde_len,
            commitment.poly_len,
            commitment.degree_bound,
        ),
    );
    let mut fold_challenges = Vec::with_capacity(commitment.caps.len());
    for (i, cap) in commitment.caps.iter().enumerate() {
        for digest in cap {
            transcript.absorb(b"fri-layer-root", digest);
        }
        if i + 1 < commitment.caps.len() {
            let mut challenges = [Field::ZERO; 3];
            for slot in &mut challenges {
                *slot = transcript.challenge_bb(b"fri-fold");
            }
            fold_challenges.push(challenges);
        }
    }
    transcript.absorb(b"fri-final", &encode_fields(&proof.final_poly));

    // Proof-of-work gate: the nonce must meet the difficulty under the
    // replayed history, and later queries absorb it exactly as the prover
    // did, so they bind to the work.
    if params.grinding_bits > 0
        && !transcript.verify_grind(b"fri-pow", proof.pow_nonce, params.grinding_bits)
    {
        return Err(Error::FriVerificationFailed);
    }

    // Final degree check at the true folded domain points, plus per-layer
    // point tables for the fold terms of query verification.
    let unit = Field::two_adic_generator(2).map_err(|_| Error::FriVerificationFailed)?;
    let point_layers = all_point_layers(commitment.lde_len, params.final_size)?;
    let residual = commitment.degree_bound >> (2 * folds);
    let final_points = &point_layers[point_layers.len() - 1];
    if !check_degree(final_points, &proof.final_poly, residual) {
        return Err(Error::FriVerificationFailed);
    }

    // Query checks.
    let mut indices = Vec::with_capacity(params.num_queries);
    for _ in &proof.queries {
        indices.push(transcript.challenge_index(b"fri-query", commitment.lde_len));
    }
    for (query, &leaf_index) in proof.queries.iter().zip(&indices) {
        if query.folds.len() != folds {
            return Err(Error::FriVerificationFailed);
        }
        verify_one(&QueryCheck {
            commitment,
            proof,
            point_layers: &point_layers,
            fold_challenges: &fold_challenges,
            query,
            leaf_index,
            unit,
            cap_height: params.cap_height,
        })?;
    }
    Ok(indices)
}

/// Split a commitment into prover state-free public data.
#[must_use]
pub fn public_commitment(state: &ProverState) -> Commitment {
    Commitment {
        caps: state.caps.clone(),
        lde_len: state.lde_len,
        poly_len: state.poly_len,
        degree_bound: state.degree_bound,
    }
}

impl Commitment {
    /// Canonical bytes: version, dimensions, then caps.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = crate::codec::Writer::new();
        writer.byte(crate::codec::VERSION);
        self.write_body(&mut writer);
        writer.finish()
    }

    /// Decode [`Commitment::to_bytes`] output, rejecting anything else.
    ///
    /// Shape-checked only; soundness checks happen in [`verify`].
    ///
    /// # Errors
    /// Returns [`Error::MalformedInput`] on any encoding violation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = crate::codec::Reader::new(bytes);
        reader.version()?;
        let commitment = Self::read_body(&mut reader)?;
        reader.end()?;
        Ok(commitment)
    }

    pub(crate) fn write_body(&self, writer: &mut crate::codec::Writer) {
        writer.u64_le(self.lde_len as u64);
        writer.u64_le(self.poly_len as u64);
        writer.u64_le(self.degree_bound as u64);
        writer.count(self.caps.len());
        for cap in &self.caps {
            writer.cap(cap);
        }
    }

    pub(crate) fn read_body(reader: &mut crate::codec::Reader<'_>) -> Result<Self> {
        use crate::codec::MAX_FOLDS;
        let lde_len = reader.dimension()?;
        let poly_len = reader.dimension()?;
        let degree_bound = reader.dimension()?;
        let mut caps = Vec::new();
        for _ in 0..reader.count(MAX_FOLDS)? {
            caps.push(reader.cap()?);
        }
        Ok(Self {
            caps,
            lde_len,
            poly_len,
            degree_bound,
        })
    }
}

/// Top steps a FRI layer drops under `cap_height`.
///
/// Clamped to `depth - 2` so the verifier's quad-node recompute (bottom
/// two levels) still lands below the cap. Opened layers always hold
/// `>= 4` leaves, hence `depth >= 2`; the saturation is pure paranoia
/// for commitment-derived sizes on the verify path.
fn fri_drop_top(layer_leaves: usize, cap_height: usize) -> usize {
    #[allow(clippy::cast_possible_truncation)]
    let depth = layer_leaves.trailing_zeros() as usize;
    cap_height.min(depth.saturating_sub(2))
}

/// Leaf counts from `lde_len` down to `final_size` by quartering.
///
/// Terminates on any input (`len <= final_size` stops, so degenerate
/// sizes cannot spin); callers pass validated quartering sizes.
pub(crate) fn fri_layer_sizes(mut len: usize, final_size: usize) -> Vec<usize> {
    let mut out = Vec::new();
    loop {
        out.push(len);
        if len <= final_size {
            break;
        }
        len /= 4;
    }
    out
}

/// Estimated FRI proof bytes over `layers` (leaf counts, LDE down to
/// final, as built by [`fri_layer_sizes`]): cap digests plus per-query
/// openings (values plus middle path segments) at `num_queries`.
///
/// Mirrors the byte counter bit for bit (see benches); the pow nonce
/// adds a flat 8 bytes.
pub(crate) fn estimate_fri_bytes(layers: &[usize], num_queries: usize, cap_height: usize) -> usize {
    let mut total: usize = 24 + 8; // dimensions + pow nonce
    for (i, &leaves) in layers.iter().enumerate() {
        #[allow(clippy::cast_possible_truncation)]
        let depth = leaves.trailing_zeros() as usize;
        let drop = cap_height.min(depth.saturating_sub(2));
        total = total.saturating_add(32usize * (1usize << drop.min(16)));
        if i + 1 < layers.len() {
            let steps = depth.saturating_sub(2).saturating_sub(drop);
            total += num_queries * (16 + 33 * steps);
        }
    }
    total
}

/// Estimated column-tree proof bytes: one cap plus `num_queries`
/// openings of `value_bytes` each over `lde_len` rows.
///
/// Mirrors the byte counters (index plus fields per opening, 33 bytes
/// per stored path step).
pub(crate) fn estimate_col_bytes(
    lde_len: usize,
    num_queries: usize,
    value_bytes: usize,
    cap_height: usize,
) -> usize {
    #[allow(clippy::cast_possible_truncation)]
    let depth = lde_len.trailing_zeros() as usize;
    let drop = cap_height.min(depth);
    32usize
        .saturating_mul(1usize << drop.min(16))
        .saturating_add(num_queries * (value_bytes + 33 * (depth - drop)))
}

/// `(final_size, cap_height)` minimizing FRI plus column-tree estimates.
///
/// Finals enumerate `lde_len / 4^f` from below `lde_len` down to 1 —
/// always at least one fold (a fold-free "proof" carries no query
/// openings for outer protocols to consume) — and never above 32: the
/// final degree check costs `O(final^2)` inversions, so larger finals
/// trade a few path bytes for a slow verifier. Caps enumerate `0..=4`.
/// `columns` holds `(lde_len, value_bytes)` per column tree (empty for
/// bare FRI). Ties keep the larger final and smaller cap (fewer layers,
/// cheaper verify). Always sound: any valid final satisfies the
/// residual-degree check at rate `< 1/2`.
pub(crate) fn tune_shape(
    lde_len: usize,
    num_queries: usize,
    columns: &[(usize, usize)],
) -> (usize, usize) {
    debug_assert!(lde_len.is_power_of_two());
    let mut shifted = (lde_len / 4).max(1);
    while shifted > 32 {
        shifted /= 4;
    }
    let mut best = (shifted, 0);
    let mut best_bytes = usize::MAX;
    loop {
        // `shifted` stays `>= 1`: every candidate is a valid final size.
        let layers = fri_layer_sizes(lde_len, shifted);
        for height in 0..=4 {
            let mut total = estimate_fri_bytes(&layers, num_queries, height);
            for &(col_lde, values) in columns {
                total =
                    total.saturating_add(estimate_col_bytes(col_lde, num_queries, values, height));
            }
            if total < best_bytes {
                best_bytes = total;
                best = (shifted, height);
            }
        }
        if shifted <= 1 {
            break;
        }
        shifted /= 4;
        if shifted < 1 {
            break;
        }
    }
    best
}

/// Milli-bits per FRI query for a composition of degree `degree_bound`
/// over `lde_len` evaluations (both sides powers of two assumed).
///
/// Johnson-radius heuristic in thousandths, conservative (rounds the
/// rate up to the next power of two): rate `1/16` gives `2000`.
pub(crate) fn composition_millibits(lde_len: usize, degree_bound: usize) -> u32 {
    let den = (degree_bound + 1).next_power_of_two();
    if den == 0 || lde_len < den {
        return 500;
    }
    500 * (lde_len.trailing_zeros() - den.trailing_zeros())
}

/// `(num_queries, grinding_bits)` splitting `target_bits` between FRI
/// queries (at `millibits_per_query` thousandths of a bit each) and
/// proof-of-work.
///
/// Grinding takes up to 20 bits (half the target when smaller — a tiny
/// target should not buy absurd grinding); queries cover the rest with
/// the milli remainder rounded up, at least one query always.
pub(crate) fn tune_strength(target_bits: u32, millibits_per_query: u32) -> (usize, u32) {
    let grinding = 20.min(target_bits / 2);
    let remaining = u64::from(target_bits.saturating_sub(grinding)) * 1000;
    let per_query = u64::from(millibits_per_query.max(1));
    let queries = ((remaining + per_query - 1) / per_query).clamp(1, 1_000_000);
    #[allow(clippy::cast_possible_truncation)]
    let queries = queries as usize;
    (queries, grinding)
}
fn coset_points(len: usize) -> Result<Vec<Field>> {
    let omega = Field::primitive_root(len)?;
    let mut points = Vec::with_capacity(len);
    let mut current = LDE_SHIFT;
    for _ in 0..len {
        points.push(current);
        current *= omega;
    }
    Ok(points)
}

/// Bit-reversed initial points plus every fourth-power-folded layer down to
/// `final_size`. Layer `d` parallels FRI evaluation layer `d`, so the exact
/// first-position point is always available (its powers matter for folding).
fn all_point_layers(lde_len: usize, final_size: usize) -> Result<Vec<Vec<Field>>> {
    let mut points = coset_points(lde_len)?;
    bit_reverse_permute(&mut points);
    let mut layers = vec![points];
    while layers[layers.len() - 1].len() > final_size {
        let prev = &layers[layers.len() - 1];
        debug_assert_eq!(prev.len() % 4, 0);
        layers.push(
            prev.chunks_exact(4)
                .map(|quad| quad[0].square().square())
                .collect(),
        );
    }
    Ok(layers)
}

fn check_layers(lde_len: usize, final_size: usize) -> Result<()> {
    if final_size > lde_len || lde_len % final_size != 0 {
        return Err(Error::InvalidDomainSize { size: final_size });
    }
    // Ratio must be a power of four so quartering lands exactly.
    let ratio = lde_len / final_size;
    if !ratio.is_power_of_two() || ratio.trailing_zeros() % 2 != 0 {
        return Err(Error::InvalidDomainSize { size: final_size });
    }
    Ok(())
}

/// Bundled inputs for one query check (keeps `verify_one` readable).
struct QueryCheck<'a> {
    commitment: &'a Commitment,
    proof: &'a Proof,
    point_layers: &'a [Vec<Field>],
    fold_challenges: &'a [[Field; 3]],
    query: &'a QueryProof,
    leaf_index: usize,
    unit: Field,
    cap_height: usize,
}

fn verify_one(check: &QueryCheck<'_>) -> Result<()> {
    let mut index = check.leaf_index;
    for (depth, witness) in check.query.folds.iter().enumerate() {
        let cap = &check.commitment.caps[depth];
        let layer_len = check.commitment.lde_len >> (2 * depth);
        // The quad containing `index` starts at a multiple of four; its
        // point is the exact first-position domain element.
        let base = index / 4 * 4;
        if base + 3 >= layer_len {
            return Err(Error::FriVerificationFailed);
        }
        // Opened layers hold `>= 4` leaves here, so `depth_bits >= 2` and
        // the clamp below keeps the quad node under the cap.
        #[allow(clippy::cast_possible_truncation)]
        let depth_bits = layer_len.trailing_zeros() as usize;
        let drop = check.cap_height.min(depth_bits.saturating_sub(2));
        // Exact stored length (middle segment only): wrong-sized paths
        // could never verify, so reject before hashing them.
        if witness.path.len() != depth_bits - 2 - drop {
            return Err(Error::BadMerklePath);
        }
        // Cap entry covering `base`: each entry spans `2^(depth_bits-drop)`
        // leaves. Length-checked: the commitment is untrusted input.
        let entry = cap
            .get(base >> (depth_bits - drop))
            .ok_or(Error::BadMerklePath)?;
        let x = *check
            .point_layers
            .get(depth)
            .and_then(|layer| layer.get(base))
            .ok_or(Error::FriVerificationFailed)?;
        // Rebuild the quad node from all four values and walk the shared
        // path (the first two siblings are recomputed, not transmitted).
        let left = hash_node(
            &hash_leaf(&witness.values[0].to_le_bytes()),
            &hash_leaf(&witness.values[1].to_le_bytes()),
        );
        let right = hash_node(
            &hash_leaf(&witness.values[2].to_le_bytes()),
            &hash_leaf(&witness.values[3].to_le_bytes()),
        );
        let mut node = hash_node(&left, &right);
        for (sibling, is_left) in &witness.path {
            node = if *is_left {
                hash_node(&node, sibling)
            } else {
                hash_node(sibling, &node)
            };
        }
        if &node != entry {
            return Err(Error::BadMerklePath);
        }
        let parent = fold_values(
            witness.values,
            x.inv(),
            check.fold_challenges[depth],
            check.unit,
        );
        if depth + 1 == check.query.folds.len() {
            // Last fold lands in the final polynomial.
            let final_index = index / 4;
            if check.proof.final_poly.get(final_index) != Some(&parent) {
                return Err(Error::FriVerificationFailed);
            }
        } else {
            // Intermediate parent must match the revealed element at
            // `parent_pos` in the next layer's quad.
            let parent_pos = index / 4;
            let next = &check.query.folds[depth + 1];
            let selected = next.values[parent_pos % 4];
            if selected != parent {
                return Err(Error::FriVerificationFailed);
            }
        }
        index /= 4;
    }
    Ok(())
}

fn open_one(state: &ProverState, leaf_index: usize) -> Result<QueryProof> {
    if leaf_index >= state.lde_len {
        return Err(Error::IndexOutOfBounds {
            index: leaf_index,
            len: state.lde_len,
        });
    }
    let mut folds = Vec::with_capacity(state.layers.len() - 1);
    let mut index = leaf_index;
    for (depth, layer) in state.layers.iter().enumerate() {
        if depth + 1 >= state.layers.len() {
            break;
        }
        // Open the quad containing `index` (base multiple of four): all
        // four values plus the quad node's path, minus the bottom two
        // steps (recomputable from the values) and the top `drop` steps
        // (covered by the cap) — the same clamp the verifier applies.
        let base = index / 4 * 4;
        let values = [
            layer[base],
            layer[base + 1],
            layer[base + 2],
            layer[base + 3],
        ];
        let full_path = state.trees[depth].prove(base)?;
        let odd_digest = hash_leaf(&values[1].to_le_bytes());
        let right_node = hash_node(
            &hash_leaf(&values[2].to_le_bytes()),
            &hash_leaf(&values[3].to_le_bytes()),
        );
        debug_assert_eq!(
            full_path.first().map(|(digest, left)| (*digest, *left)),
            Some((odd_digest, true))
        );
        debug_assert_eq!(
            full_path.get(1).map(|(digest, left)| (*digest, *left)),
            Some((right_node, true))
        );
        let drop = fri_drop_top(layer.len(), state.params.cap_height);
        let stored = full_path.len().saturating_sub(2 + drop);
        let path = full_path.into_iter().skip(2).take(stored).collect();
        folds.push(FoldWitness { values, path });
        index /= 4;
    }
    Ok(QueryProof { folds })
}

/// Degree-quartering fold of adjacent quads with tracked points.
///
/// `values`/`points` are bit-reversed; quad `(4j..4j+3)` sits at
/// `(x, -x, j0*x, -j0*x)` for the fixed fourth root `unit`, sharing `x^4`.
/// Point inverses are batch-inverted once per layer (one inversion total
/// instead of one Fermat power per quad); values fold in parallel.
fn fold_layer(
    values: &[Field],
    points: &[Field],
    challenges: [Field; 3],
    unit: Field,
) -> (Vec<Field>, Vec<Field>) {
    use crate::babybear::batch_invert;
    debug_assert_eq!(values.len() % 4, 0);
    debug_assert_eq!(values.len(), points.len());
    let quarter = values.len() / 4;
    let first_points: Vec<Field> = points.chunks_exact(4).map(|quad| quad[0]).collect();
    let inv_points = batch_invert(&first_points);
    let mut next_values = vec![Field::ZERO; quarter];
    crate::par::for_each_indexed(&mut next_values, 512, |base, piece| {
        for (j, slot) in piece.iter_mut().enumerate() {
            let i = base + j;
            let quad = [
                values[4 * i],
                values[4 * i + 1],
                values[4 * i + 2],
                values[4 * i + 3],
            ];
            *slot = fold_values(quad, inv_points[i], challenges, unit);
        }
    });
    let mut next_points = Vec::with_capacity(quarter);
    for quad in points.chunks_exact(4) {
        next_points.push(quad[0].square().square());
    }
    (next_values, next_points)
}

/// Fold one quad `(x, -x, j0*x, -j0*x)` into `A + r0*B + r1*C + r2*D`,
/// where `P(X) = A + BX + CX^2 + DX^3` in `Y = X^4`.
///
/// Solved from the four evaluations: `A` is the mean, `B` and `D` come
/// from the odd/even differences against `unit = j0`, `C` from the
/// diagonal difference; divisions use `halve` plus the caller-supplied
/// `x` inverse (batch-inverted once per layer).
fn fold_values(quad: [Field; 4], inv_point: Field, challenges: [Field; 3], unit: Field) -> Field {
    let even_sum = (quad[0] + quad[1]) + (quad[2] + quad[3]);
    let odd_diff = quad[0] - quad[1];
    let skew_diff = quad[2] - quad[3];
    let mean = even_sum.halve().halve();
    let linear = (odd_diff - unit * skew_diff).halve().halve() * inv_point;
    let quadratic =
        ((quad[0] + quad[1]) - (quad[2] + quad[3])).halve().halve() * inv_point * inv_point;
    let cubic = (odd_diff + unit * skew_diff).halve().halve() * inv_point * inv_point * inv_point;
    mean + challenges[0] * linear + challenges[1] * quadratic + challenges[2] * cubic
}

/// Check `values` at distinct `points` interpolate to degree `<= bound`.
///
/// Uses divided differences: degree `<= bound` iff every difference of order
/// `> bound` vanishes. Vacuous (`true`) when `bound + 1 >= len`.
#[must_use]
pub fn check_degree(points: &[Field], values: &[Field], bound: usize) -> bool {
    debug_assert_eq!(points.len(), values.len());
    let n = values.len();
    if bound + 1 >= n {
        return true;
    }
    let mut table = values.to_vec();
    for order in 1..n {
        for i in 0..n - order {
            let denom = points[i + order] - points[i];
            if denom == Field::ZERO {
                return false;
            }
            table[i] = (table[i + 1] - table[i]) * denom.inv();
        }
        if order > bound && table[..n - order].iter().any(|&v| v != Field::ZERO) {
            return false;
        }
    }
    true
}

fn commit_layer(layer: &[Field]) -> Result<MerkleTree> {
    let mut flat = vec![0u8; 4 * layer.len()];
    for (slot, f) in flat.chunks_exact_mut(4).zip(layer.iter()) {
        slot.copy_from_slice(&f.to_le_bytes());
    }
    MerkleTree::from_flat(&flat, 4)
}

fn encode_fields(fields: &[Field]) -> Vec<u8> {
    let mut out = Vec::with_capacity(fields.len() * 4);
    for f in fields {
        out.extend_from_slice(&f.to_le_bytes());
    }
    out
}

/// Canonical dimension binding: `(lde_len, poly_len, degree_bound)` as
/// three little-endian `u64`s, absorbed under `fri-dims` by prover and
/// verifier alike.
fn encode_dims(lde_len: usize, poly_len: usize, degree_bound: usize) -> [u8; 24] {
    let mut out = [0u8; 24];
    out[..8].copy_from_slice(&(lde_len as u64).to_le_bytes());
    out[8..16].copy_from_slice(&(poly_len as u64).to_le_bytes());
    out[16..].copy_from_slice(&(degree_bound as u64).to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gf2::splitmix64;

    fn random_poly(n: usize, seed: &mut u64) -> Vec<Field> {
        (0..n).map(|_| Field::from_u64(splitmix64(seed))).collect()
    }

    fn test_params() -> Params {
        Params::new(4, 8, 1).unwrap()
    }

    #[test]
    fn rejects_bad_params() {
        assert!(Params::new(1, 8, 1).is_err());
        assert!(Params::new(3, 8, 1).is_err());
        assert!(Params::new(4, 0, 1).is_err());
        assert!(Params::new(4, 8, 3).is_err());
    }

    #[test]
    fn rejects_bad_poly() {
        let params = test_params();
        let mut t = Transcript::new(b"fri-test");
        assert!(commit(&[], params, &mut t).is_err());
        assert!(commit(&[Field::ONE; 3], params, &mut t).is_err());
    }

    #[test]
    fn honest_proof_verifies() {
        let params = test_params();
        let mut seed = 0x1234_abcd_5678_ef00u64;
        let poly = random_poly(16, &mut seed);
        let mut prover_t = Transcript::new(b"fri-e2e");
        let state = commit(&poly, params, &mut prover_t).unwrap();
        let commitment = public_commitment(&state);
        let (proof, _) = open(&state, &mut prover_t).unwrap();

        let mut verifier_t = Transcript::new(b"fri-e2e");
        verify(&commitment, &proof, params, &mut verifier_t).unwrap();
    }

    #[test]
    fn tampered_value_fails() {
        let params = test_params();
        let mut seed = 0x9999_0000_1111_2222u64;
        let poly = random_poly(16, &mut seed);
        let mut prover_t = Transcript::new(b"fri-tamper");
        let state = commit(&poly, params, &mut prover_t).unwrap();
        let commitment = public_commitment(&state);
        let (mut proof, _) = open(&state, &mut prover_t).unwrap();
        proof.queries[0].folds[0].values[0] += Field::ONE;

        let mut verifier_t = Transcript::new(b"fri-tamper");
        assert!(verify(&commitment, &proof, params, &mut verifier_t).is_err());
    }

    #[test]
    fn wrong_transcript_fails() {
        let params = test_params();
        let mut seed = 0xaaaa_bbbb_cccc_ddddu64;
        let poly = random_poly(16, &mut seed);
        let mut prover_t = Transcript::new(b"fri-A");
        let state = commit(&poly, params, &mut prover_t).unwrap();
        let commitment = public_commitment(&state);
        let (proof, _) = open(&state, &mut prover_t).unwrap();

        let mut verifier_t = Transcript::new(b"fri-B");
        assert!(verify(&commitment, &proof, params, &mut verifier_t).is_err());
    }

    #[test]
    fn larger_domain_verifies() {
        let params = Params::new(8, 12, 8).unwrap();
        let mut seed = 0x0bad_f00d_dead_beefu64;
        let poly = random_poly(64, &mut seed);
        let mut prover_t = Transcript::new(b"fri-big");
        let state = commit(&poly, params, &mut prover_t).unwrap();
        assert_eq!(state.trees.len(), 4); // 512 -> 128 -> 32 -> 8
        let commitment = public_commitment(&state);
        let (proof, _) = open(&state, &mut prover_t).unwrap();
        let mut verifier_t = Transcript::new(b"fri-big");
        verify(&commitment, &proof, params, &mut verifier_t).unwrap();
    }

    #[test]
    fn grinding_roundtrip_and_tamper() {
        // 16-bit grinding: the forged-nonce check below flakes only at
        // 2^-16 (an 8-bit gate would flake at 2^-8 — inherent to PoW
        // forgery being probabilistic, not a test bug).
        let params = Params::new(4, 8, 4).unwrap().with_grinding_bits(16);
        let mut seed = 0x600d_600d_600d_600du64;
        let poly = random_poly(16, &mut seed);
        let mut prover_t = Transcript::new(b"fri-grind");
        let state = commit(&poly, params, &mut prover_t).unwrap();
        let commitment = public_commitment(&state);
        let (proof, _) = open(&state, &mut prover_t).unwrap();

        let mut verifier_t = Transcript::new(b"fri-grind");
        verify(&commitment, &proof, params, &mut verifier_t).unwrap();

        // Forged nonce fails the proof-of-work gate.
        let mut bad = proof.clone();
        bad.pow_nonce = bad.pow_nonce.wrapping_add(1);
        let mut verifier_t = Transcript::new(b"fri-grind");
        assert!(verify(&commitment, &bad, params, &mut verifier_t).is_err());

        // Difficulty mismatch fails: a verifier expecting no work samples
        // queries from a transcript that diverges at the prover's PoW
        // absorb, so every Merkle path misses deterministically.
        let mut verifier_t = Transcript::new(b"fri-grind");
        assert!(verify(
            &commitment,
            &proof,
            Params::new(4, 8, 4).unwrap(),
            &mut verifier_t
        )
        .is_err());

        // Absurd difficulty fails deterministically: no nonce can carry
        // more than 256 leading zero bits.
        let mut impossible = params;
        impossible.grinding_bits = 300;
        let mut verifier_t = Transcript::new(b"fri-grind");
        assert!(verify(&commitment, &proof, impossible, &mut verifier_t).is_err());
    }

    #[test]
    fn rate_gate_rejects_declared_bounds() {
        // An honest proof under a tampered degree bound fails both ways:
        // raised toward the LDE size trips the rate gate, lowered below
        // the true degree trips the final low-degree check.
        let params = test_params();
        let mut seed = 0x2a2a_2a2a_2a2a_2a2au64;
        let poly = random_poly(16, &mut seed);
        let mut prover_t = Transcript::new(b"fri-rate");
        let state = commit(&poly, params, &mut prover_t).unwrap();
        let commitment = public_commitment(&state);
        let (proof, _) = open(&state, &mut prover_t).unwrap();
        assert_eq!(commitment.lde_len, 64);
        assert_eq!(commitment.degree_bound, 15);

        let mut high = commitment.clone();
        high.degree_bound = 63;
        let mut verifier_t = Transcript::new(b"fri-rate");
        assert!(verify(&high, &proof, params, &mut verifier_t).is_err());

        let mut boundary = commitment.clone();
        boundary.degree_bound = 64;
        let mut verifier_t = Transcript::new(b"fri-rate");
        assert!(verify(&boundary, &proof, params, &mut verifier_t).is_err());
    }

    #[test]
    fn lowered_bound_fails_final_check() {
        // A random word (true degree ~63) folded once keeps degree ~15
        // over 16 final points, but the declared bound 7 allows only
        // residual 1: the final divided differences cannot all vanish.
        // (Single fold keeps the true degree visible; deeper folds would
        // quarter it away — the final check only sees `true >> 2f`.)
        let params = Params::new(4, 8, 16).unwrap();
        let mut seed = 0x2b2b_2b2b_2b2b_2b2bu64;
        let random_evals: Vec<Field> = (0..64)
            .map(|_| Field::from_u64(splitmix64(&mut seed)))
            .collect();
        let mut prover_t = Transcript::new(b"fri-lowbound");
        let state = commit_evals(&random_evals, 7, params, &mut prover_t).unwrap();
        let commitment = public_commitment(&state);
        let (proof, _) = open(&state, &mut prover_t).unwrap();
        let mut verifier_t = Transcript::new(b"fri-lowbound");
        assert!(verify(&commitment, &proof, params, &mut verifier_t).is_err());
    }

    #[test]
    fn dimension_mismatch_rejects() {
        // Query count, LDE size, and final size must match the proof;
        // each mismatch fails before any hashing of openings.
        let params = test_params();
        let mut seed = 0x3b3b_3b3b_3b3b_3b3bu64;
        let poly = random_poly(16, &mut seed);
        let mut prover_t = Transcript::new(b"fri-dims");
        let state = commit(&poly, params, &mut prover_t).unwrap();
        let commitment = public_commitment(&state);
        let (proof, _) = open(&state, &mut prover_t).unwrap();

        let more_queries = Params::new(4, params.num_queries + 1, 1).unwrap();
        let mut verifier_t = Transcript::new(b"fri-dims");
        assert!(verify(&commitment, &proof, more_queries, &mut verifier_t).is_err());

        let mut big_lde = commitment.clone();
        big_lde.lde_len *= 2;
        let mut verifier_t = Transcript::new(b"fri-dims");
        assert!(verify(&big_lde, &proof, params, &mut verifier_t).is_err());

        let wrong_final = Params::new(4, params.num_queries, 8).unwrap();
        let mut verifier_t = Transcript::new(b"fri-dims");
        assert!(verify(&commitment, &proof, wrong_final, &mut verifier_t).is_err());
    }

    #[test]
    fn cap_height_mismatch_rejects() {
        // Caps are transcript-bound: proving capped and verifying
        // uncapped (or the reverse) diverges the PoW/query schedule and
        // every path misses.
        for cap_height in [1usize, 2] {
            let params = Params::new(4, 8, 4).unwrap().with_cap_height(cap_height);
            let mut seed = 0x4c4c_4c4c_4c4c_4c4cu64;
            let poly = random_poly(16, &mut seed);
            let mut prover_t = Transcript::new(b"fri-capmix");
            let state = commit(&poly, params, &mut prover_t).unwrap();
            let commitment = public_commitment(&state);
            let (proof, _) = open(&state, &mut prover_t).unwrap();

            let plain = Params::new(4, 8, 4).unwrap();
            let mut verifier_t = Transcript::new(b"fri-capmix");
            assert!(verify(&commitment, &proof, plain, &mut verifier_t).is_err());

            let mut prover_t = Transcript::new(b"fri-capmix");
            let plain_state = commit(&poly, plain, &mut prover_t).unwrap();
            let plain_commitment = public_commitment(&plain_state);
            let (plain_proof, _) = open(&plain_state, &mut prover_t).unwrap();
            let mut verifier_t = Transcript::new(b"fri-capmix");
            assert!(verify(&plain_commitment, &plain_proof, params, &mut verifier_t).is_err());
        }
    }

    #[test]
    fn malformed_shapes_rejected() {
        // Bloated caps and over-long paths fail closed before hashing:
        // neither can verify, so the shape pins reject them up front.
        let params = test_params();
        let mut seed = 0x5d5d_5d5d_5d5d_5d5du64;
        let poly = random_poly(16, &mut seed);
        let mut prover_t = Transcript::new(b"fri-shape");
        let state = commit(&poly, params, &mut prover_t).unwrap();
        let commitment = public_commitment(&state);
        let (proof, _) = open(&state, &mut prover_t).unwrap();

        let mut fat_cap = commitment.clone();
        fat_cap.caps[0].push([9u8; 32]);
        let mut verifier_t = Transcript::new(b"fri-shape");
        assert!(verify(&fat_cap, &proof, params, &mut verifier_t).is_err());

        let mut long_path = proof.clone();
        long_path.queries[0].folds[0].path.push(([9u8; 32], true));
        let mut verifier_t = Transcript::new(b"fri-shape");
        assert!(verify(&commitment, &long_path, params, &mut verifier_t).is_err());

        let mut short_path = proof.clone();
        short_path.queries[0].folds[0].path.pop();
        let mut verifier_t = Transcript::new(b"fri-shape");
        assert!(verify(&commitment, &short_path, params, &mut verifier_t).is_err());
    }

    #[test]
    fn capped_roundtrip_shrinks_paths() {
        // LDE 64: opened layers 64 (d=6) and 16 (d=4); final 4 stays root.
        for cap_height in [1usize, 2, 3] {
            let params = Params::new(4, 8, 4).unwrap().with_cap_height(cap_height);
            let mut seed = 0xc4c4_c4c4_c4c4_c4c4u64;
            let poly = random_poly(16, &mut seed);
            let mut prover_t = Transcript::new(b"fri-cap");
            let state = commit(&poly, params, &mut prover_t).unwrap();
            let commitment = public_commitment(&state);
            assert_eq!(commitment.caps[0].len(), 1usize << cap_height.min(4));
            assert_eq!(commitment.caps[1].len(), 1usize << cap_height.min(2));
            assert_eq!(commitment.caps[2].len(), 1);
            let (proof, _) = open(&state, &mut prover_t).unwrap();
            for query in &proof.queries {
                assert_eq!(query.folds.len(), 2);
                for (depth, fold) in query.folds.iter().enumerate() {
                    let d = 6 - 2 * depth;
                    let drop = cap_height.min(d - 2);
                    assert_eq!(fold.path.len(), d - 2 - drop);
                }
            }
            let mut verifier_t = Transcript::new(b"fri-cap");
            verify(&commitment, &proof, params, &mut verifier_t).unwrap();

            // Forged cap entry fails.
            let mut bad = commitment.clone();
            bad.caps[0][0][0] ^= 1;
            let mut verifier_t = Transcript::new(b"fri-cap");
            assert!(verify(&bad, &proof, params, &mut verifier_t).is_err());
        }
    }

    #[test]
    fn for_security_roundtrip() {
        // 40-bit target at rate 1/16: grinding 20 would grind a million
        // hashes, so assert the split purely and prove at a small target.
        let params = Params::for_security(16, 40).unwrap();
        assert_eq!((params.num_queries, params.grinding_bits), (10, 20));
        assert!(params.cap_height <= 4);

        let params = Params::for_security(16, 10).unwrap();
        assert_eq!((params.num_queries, params.grinding_bits), (3, 5));
        let mut seed = 0xf0f0_f0f0_f0f0_f0f0u64;
        let poly = random_poly(16, &mut seed);
        let mut prover_t = Transcript::new(b"fri-forsec");
        let state = commit(&poly, params, &mut prover_t).unwrap();
        let commitment = public_commitment(&state);
        let (proof, _) = open(&state, &mut prover_t).unwrap();
        let mut verifier_t = Transcript::new(b"fri-forsec");
        verify(&commitment, &proof, params, &mut verifier_t).unwrap();

        assert!(Params::for_security(0, 40).is_err());
        assert!(Params::for_security(3, 40).is_err());
        assert!(Params::for_security(1usize << 24, 40).is_err());
    }

    #[test]
    fn encoding_roundtrip_and_rejects() {
        let params = test_params();
        let mut seed = 0xe4e4_e4e4_e4e4_e4e4u64;
        let poly = random_poly(16, &mut seed);
        let mut prover_t = Transcript::new(b"fri-codec");
        let state = commit(&poly, params, &mut prover_t).unwrap();
        let commitment = public_commitment(&state);
        let (proof, _) = open(&state, &mut prover_t).unwrap();

        let bytes = proof.to_bytes();
        assert_eq!(Proof::from_bytes(&bytes).unwrap(), proof);
        // Decoded proofs verify: catches mirrored encode/decode bugs
        // that a pure roundtrip would miss.
        let commitment = Commitment::from_bytes(&commitment.to_bytes()).unwrap();
        let proof = Proof::from_bytes(&bytes).unwrap();
        let mut verifier_t = Transcript::new(b"fri-codec");
        verify(&commitment, &proof, params, &mut verifier_t).unwrap();
        let commitment_bytes = commitment.to_bytes();
        assert_eq!(
            Commitment::from_bytes(&commitment_bytes).unwrap(),
            commitment
        );

        // Truncated, bad version, and trailing garbage all fail.
        assert!(Proof::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        let mut bad_version = bytes.clone();
        bad_version[0] ^= 1;
        assert!(Proof::from_bytes(&bad_version).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(Proof::from_bytes(&trailing).is_err());
        assert!(Proof::from_bytes(&[]).is_err());
        // Non-canonical field element fails: the first final-poly
        // element sits right after version (1 B) plus count (4 B).
        let mut bad_field = bytes.clone();
        bad_field[5..9].copy_from_slice(&Field::MODULUS.to_le_bytes());
        assert!(Proof::from_bytes(&bad_field).is_err());
        // Commitment rejects truncation too.
        assert!(Commitment::from_bytes(&commitment_bytes[..commitment_bytes.len() - 1]).is_err());
    }

    #[test]
    fn commit_evals_roundtrip() {
        // Evaluations of a low-degree poly on the coset verify under an
        // explicit bound.
        let params = Params::new(4, 8, 4).unwrap();
        let mut seed = 0x5150_5150_5150_5150u64;
        let coeffs = random_poly(16, &mut seed);
        let lde = crate::ntt::evaluate_on_coset(&coeffs, 4, LDE_SHIFT).unwrap();
        assert_eq!(lde.len(), 64);
        let mut prover_t = Transcript::new(b"fri-evals");
        let state = commit_evals(&lde, 15, params, &mut prover_t).unwrap();
        let commitment = public_commitment(&state);
        let (proof, _) = open(&state, &mut prover_t).unwrap();
        let mut verifier_t = Transcript::new(b"fri-evals");
        verify(&commitment, &proof, params, &mut verifier_t).unwrap();
    }

    #[test]
    fn high_degree_rejected() {
        // Random evaluations are far from low-degree: a tight bound fails.
        let params = Params::new(4, 8, 4).unwrap();
        let mut seed = 0xde_ad_be_ef_00_11_22_33u64;
        let random_evals: Vec<Field> = (0..64)
            .map(|_| Field::from_u64(splitmix64(&mut seed)))
            .collect();
        let mut prover_t = Transcript::new(b"fri-highdeg");
        let state = commit_evals(&random_evals, 15, params, &mut prover_t).unwrap();
        let commitment = public_commitment(&state);
        let (proof, _) = open(&state, &mut prover_t).unwrap();
        let mut verifier_t = Transcript::new(b"fri-highdeg");
        assert!(verify(&commitment, &proof, params, &mut verifier_t).is_err());
    }

    #[test]
    fn fold_values_decomposition() {
        // Quad positions hold (x, -x, j0*x, -j0*x): folding P(x) = x + x^3
        // must yield r0 + r2... precisely r0*B + r2*D with B = D = 1, i.e.
        // r0 + r2 everywhere, regardless of x. A wrong fourth root (or
        // swapped positions) makes the result x-dependent and fails.
        let unit = Field::two_adic_generator(2).unwrap();
        assert_eq!(unit.square(), Field::new(Field::MODULUS - 1));
        let x = Field::new(123_456);
        let (r0, r1, r2) = (Field::new(7), Field::new(11), Field::new(13));
        let poly = |t: Field| t + t.square() * t;
        let e = [poly(x), poly(-x), poly(unit * x), poly(-unit * x)];
        let inv = x.inv();
        assert_eq!(fold_values(e, inv, [r0, r1, r2], unit), r0 + r2);
        // P(x) = x^2 isolates C; P constant isolates A.
        let sq = |t: Field| t.square();
        let e2 = [sq(x), sq(-x), sq(unit * x), sq(-unit * x)];
        assert_eq!(fold_values(e2, inv, [r0, r1, r2], unit), r1);
        let five = [Field::new(5); 4];
        assert_eq!(fold_values(five, inv, [r0, r1, r2], unit), Field::new(5));
    }

    #[test]
    fn degree_check_unit() {
        // Constant through 4 points passes bound 0; linear needs bound 1.
        let xs = [Field::ONE, Field::new(2), Field::new(3), Field::new(4)];
        let flat = [Field::new(7); 4];
        assert!(check_degree(&xs, &flat, 0));
        let line = [Field::ONE, Field::new(2), Field::new(3), Field::new(4)];
        assert!(!check_degree(&xs, &line, 0));
        assert!(check_degree(&xs, &line, 1));
        // Quadratic through 4 points needs bound 2.
        let quad = xs.map(|x| x * x);
        assert!(!check_degree(&xs, &quad, 1));
        assert!(check_degree(&xs, &quad, 2));
    }
}
