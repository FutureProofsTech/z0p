//! Hash-based folding / IVC accumulation over Fibonacci segments.
//!
//! Why not Nova-style folding here: Nova compresses instances through an
//! additively homomorphic commitment (elliptic-curve Pedersen/KZG). This crate
//! is hash-based by design (transparent setup, plausibly post-quantum); an EC
//! group would reintroduce trusted-setup-free but quantum-vulnerable
//! assumptions. Instead this module accumulates as production STARK systems
//! do:
//! - **Hash-chained step proofs.** Each segment of `seg_steps` Fibonacci rows
//!   is committed independently (streaming prover, `O(1)` memory per step)
//!   with explicit in/out claims; the verifier checks the chain links.
//! - **One batched FRI.** All step composition polynomials share one
//!   evaluation domain, so a transcript-random linear combination
//!   `V = sum gamma_i * C_i` is committed through a single
//!   [`crate::fri::commit_evals`]. A far-from-code step keeps the combination
//!   far with overwhelming probability over the `gamma`s, and FRI's final
//!   degree check rejects it. Verifier cost is one FRI plus `O(steps)` cheap
//!   openings instead of one FRI per step.
//!
//! The per-step relation is the [`crate::air`] Fibonacci relation in
//! quotient form: transition numerators over the transition vanishing
//! polynomial, boundaries over point vanishing polynomials. Boundary
//! constraints bind both `A` and `B` at the first and last rows, so claims
//! cannot jump between segments.

use crate::babybear::Field;
use crate::error::{Error, Result};
use crate::fri::{self, Commitment as FriCommitment, Proof as FriProof};
use crate::merkle::MerkleTree;
use crate::ntt::{evaluate_on_coset, interpolate};
use crate::transcript::Transcript;

/// Composition challenges: two transitions and four boundary claims.
const ALPHAS: usize = 6;

/// Folding parameters plus the global computation claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// Rows per segment: power of two, `>= 2`.
    pub seg_steps: usize,
    /// LDE blowup: power of two, `>= 4`.
    pub blowup: usize,
    /// FRI query count (`>= 1`).
    pub num_queries: usize,
    /// FRI final layer size (power of two, `>= 1`).
    pub final_size: usize,
    /// Proof-of-work difficulty in leading-zero bits (`0` disables grinding).
    ///
    /// Threaded into FRI and bound under `"fold/params"`.
    pub grinding_bits: u32,
    /// Merkle cap height for the column trees and FRI layers (`0` = roots).
    ///
    /// Threaded into FRI and bound under `"fold/params"`.
    pub cap_height: usize,
    /// Global input claims (first row of the first segment).
    pub in_a: Field,
    /// Global input claims (first row of the first segment).
    pub in_b: Field,
    /// Global output claim (last `B` of the last segment).
    pub out_b: Field,
}

impl Params {
    /// Validate parameters.
    ///
    /// # Errors
    /// Returns [`Error`] for out-of-range sizes or an LDE above `2^27`.
    pub const fn new(
        seg_steps: usize,
        blowup: usize,
        num_queries: usize,
        final_size: usize,
        in_a: Field,
        in_b: Field,
        out_b: Field,
    ) -> Result<Self> {
        if seg_steps < 2 || !seg_steps.is_power_of_two() {
            return Err(Error::InvalidDomainSize { size: seg_steps });
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
        let Some(lde) = seg_steps.checked_mul(blowup) else {
            return Err(Error::InvalidDomainSize { size: seg_steps });
        };
        if lde > (1usize << Field::TWO_ADICITY) {
            return Err(Error::InvalidDomainSize { size: lde });
        }
        Ok(Self {
            seg_steps,
            blowup,
            num_queries,
            final_size,
            grinding_bits: 0,
            cap_height: 0,
            in_a,
            in_b,
            out_b,
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

    /// Production parameters: blowup 16, strength sized for a `target_bits`
    /// query/grinding schedule (see the field-size ceiling in
    /// [`crate::fri`]), and size-optimal final size and cap height.
    ///
    /// The cap tunes for a single step; multi-step accumulations may bump
    /// it manually (column caps scale with the step count, FRI caps do
    /// not, so the joint optimum barely moves).
    ///
    /// # Errors
    /// Same domain errors as [`Params::new`].
    pub fn for_security(
        seg_steps: usize,
        in_a: Field,
        in_b: Field,
        out_b: Field,
        target_bits: u32,
    ) -> Result<Self> {
        if seg_steps < 2 || !seg_steps.is_power_of_two() {
            return Err(Error::InvalidDomainSize { size: seg_steps });
        }
        let blowup = 16;
        let lde_len = seg_steps
            .checked_mul(blowup)
            .ok_or(Error::InvalidDomainSize { size: seg_steps })?;
        if lde_len > (1usize << Field::TWO_ADICITY) {
            return Err(Error::InvalidDomainSize { size: lde_len });
        }
        let millibits = crate::fri::composition_millibits(lde_len, seg_steps - 1);
        let (num_queries, grinding_bits) = crate::fri::tune_strength(target_bits, millibits);
        // Step openings carry 8 index bytes plus 16 field bytes each.
        let (final_size, cap_height) =
            crate::fri::tune_shape(lde_len, num_queries, &[(lde_len, 24)]);
        Ok(Self {
            seg_steps,
            blowup,
            num_queries,
            final_size,
            grinding_bits,
            cap_height,
            in_a,
            in_b,
            out_b,
        })
    }

    /// Length of the shared step LDE domain.
    #[must_use]
    pub const fn lde_len(&self) -> usize {
        self.seg_steps * self.blowup
    }

    fn fri_params(&self) -> Result<fri::Params> {
        Ok(
            fri::Params::new(self.blowup, self.num_queries, self.final_size)?
                .with_grinding_bits(self.grinding_bits)
                .with_cap_height(self.cap_height),
        )
    }

    /// Re-check every invariant at entry points (fields are public).
    fn validate(&self) -> Result<()> {
        if self.seg_steps < 2 || !self.seg_steps.is_power_of_two() {
            return Err(Error::InvalidDomainSize {
                size: self.seg_steps,
            });
        }
        if self.blowup < 4 || !self.blowup.is_power_of_two() {
            return Err(Error::InvalidBlowup {
                factor: self.blowup,
            });
        }
        if self.num_queries == 0 {
            return Err(Error::NoQueries);
        }
        if self.final_size == 0 || !self.final_size.is_power_of_two() {
            return Err(Error::InvalidDomainSize {
                size: self.final_size,
            });
        }
        let lde = self
            .seg_steps
            .checked_mul(self.blowup)
            .ok_or(Error::InvalidDomainSize {
                size: self.seg_steps,
            })?;
        if lde > (1usize << Field::TWO_ADICITY) {
            return Err(Error::InvalidDomainSize { size: lde });
        }
        Ok(())
    }
}

/// In/out claims of one segment: row 0 and row `S-1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StepClaims {
    /// First-row values.
    pub in_a: Field,
    /// First-row values.
    pub in_b: Field,
    /// Last-row values.
    pub out_a: Field,
    /// Last-row values.
    pub out_b: Field,
}

/// One step opening at an LDE position.
///
/// `cols[2..]` are the same committed columns opened at the shifted LDE
/// index `index + lde_len / seg_steps` (mod `lde_len`), i.e. at
/// `omega_base * x`; they are authenticated by `shift_path` like the
/// primary row, so transitions never trust a separate witness column.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepOpening {
    /// Natural-order LDE index (shared across steps per query).
    pub index: usize,
    /// Columns `[A, B, A_next, B_next]` at `index` and the shifted index.
    pub cols: [Field; 4],
    /// Merkle path of the joint row leaf (`A || B`) at `index`.
    pub path: Vec<([u8; 32], bool)>,
    /// Merkle path of the joint row leaf (`A || B`) at the shifted index.
    pub shift_path: Vec<([u8; 32], bool)>,
}

/// One folded step: claims, commitments, and query openings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepProof {
    /// Segment boundary claims.
    pub claims: StepClaims,
    /// Merkle cap of the joint row LDE (`2^cap_height` digests; one root
    /// when caps are disabled).
    pub column_cap: Vec<[u8; 32]>,
    /// Openings, one per FRI query, in query order.
    pub openings: Vec<StepOpening>,
}

/// Folded IVC proof: per-step data plus one shared FRI proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IvcProof {
    /// Steps in chain order.
    pub steps: Vec<StepProof>,
    /// FRI commitment to the random combination of compositions.
    pub fri_commitment: FriCommitment,
    /// Shared FRI opening proof.
    pub fri_proof: FriProof,
}

impl IvcProof {
    /// Canonical bytes: version, steps (claims, cap, openings each),
    /// then the shared FRI commitment and proof.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = crate::codec::Writer::new();
        writer.byte(crate::codec::VERSION);
        writer.count(self.steps.len());
        for step in &self.steps {
            writer.field(step.claims.in_a);
            writer.field(step.claims.in_b);
            writer.field(step.claims.out_a);
            writer.field(step.claims.out_b);
            writer.cap(&step.column_cap);
            writer.count(step.openings.len());
            for opening in &step.openings {
                writer.u64_le(opening.index as u64);
                for value in &opening.cols {
                    writer.field(*value);
                }
                writer.path(&opening.path);
                writer.path(&opening.shift_path);
            }
        }
        self.fri_commitment.write_body(&mut writer);
        self.fri_proof.write_body(&mut writer);
        writer.finish()
    }

    /// Decode [`IvcProof::to_bytes`] output, rejecting anything else.
    ///
    /// Shape-checked only; soundness checks happen in [`verify`].
    ///
    /// # Errors
    /// Returns [`Error::MalformedInput`] on any encoding violation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        use crate::codec::{MAX_QUERIES, MAX_STEPS};
        let mut reader = crate::codec::Reader::new(bytes);
        reader.version()?;
        let mut steps = Vec::new();
        for _ in 0..reader.count(MAX_STEPS)? {
            let claims = StepClaims {
                in_a: reader.field()?,
                in_b: reader.field()?,
                out_a: reader.field()?,
                out_b: reader.field()?,
            };
            let column_cap = reader.cap()?;
            let mut openings = Vec::new();
            for _ in 0..reader.count(MAX_QUERIES)? {
                let index = reader.dimension()?;
                let cols = [
                    reader.field()?,
                    reader.field()?,
                    reader.field()?,
                    reader.field()?,
                ];
                let path = reader.path()?;
                let shift_path = reader.path()?;
                openings.push(StepOpening {
                    index,
                    cols,
                    path,
                    shift_path,
                });
            }
            steps.push(StepProof {
                claims,
                column_cap,
                openings,
            });
        }
        let fri_commitment = fri::Commitment::read_body(&mut reader)?;
        let fri_proof = fri::Proof::read_body(&mut reader)?;
        reader.end()?;
        Ok(Self {
            steps,
            fri_commitment,
            fri_proof,
        })
    }
}

/// Streaming prover accumulator: commit steps one at a time, fold once.
#[derive(Debug)]
pub struct Accumulator {
    params: Params,
    steps: Vec<StepData>,
}

/// Prover-private per-step material.
#[derive(Debug)]
struct StepData {
    claims: StepClaims,
    ldes: [Vec<Field>; 2],
    tree: MerkleTree,
    composition: Vec<Field>,
}

impl Accumulator {
    /// Create an accumulator for `params`.
    #[must_use]
    pub const fn new(params: Params) -> Self {
        Self {
            params,
            steps: Vec::new(),
        }
    }

    /// Number of segments accumulated so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// Whether no segment has been added yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Commit one segment trace (`seg_steps` rows per column).
    ///
    /// Claims are derived from the first and last rows. Columns need not
    /// satisfy the relation; invalid segments fold honestly and fail
    /// [`verify`] through FRI's final degree check.
    ///
    /// # Errors
    /// Returns [`Error::MalformedInput`] on column-length mismatch, otherwise
    /// structural domain/Merkle errors.
    pub fn add_segment(
        &mut self,
        col_a: &[Field],
        col_b: &[Field],
        transcript: &mut Transcript,
    ) -> Result<()> {
        self.params.validate()?;
        let s = self.params.seg_steps;
        if col_a.len() != s || col_b.len() != s {
            return Err(Error::MalformedInput {
                reason: "segment columns must match seg_steps",
            });
        }
        let claims = StepClaims {
            in_a: col_a[0],
            in_b: col_b[0],
            out_a: col_a[s - 1],
            out_b: col_b[s - 1],
        };
        if self.steps.is_empty() {
            absorb_params(self.params, transcript);
        }
        absorb_step(&claims, transcript);

        let omega_base = Field::primitive_root(s)?;
        let lde_cols = [
            evaluate_on_coset(
                &interpolate(col_a)?,
                self.params.blowup,
                crate::fri::LDE_SHIFT,
            )?,
            evaluate_on_coset(
                &interpolate(col_b)?,
                self.params.blowup,
                crate::fri::LDE_SHIFT,
            )?,
        ];
        let m_step = lde_cols[0].len();
        // `omega_base * x_i = x_{(i + offset)}` in LDE index space.
        let offset = m_step / s;
        let all_refs = [&lde_cols[0], &lde_cols[1]];
        let row_len = 4 * all_refs.len();
        let mut flat = vec![0u8; m_step * row_len];
        for (i, chunk) in flat.chunks_exact_mut(row_len).enumerate() {
            for (lde, slot) in all_refs.iter().zip(chunk.chunks_exact_mut(4)) {
                slot.copy_from_slice(&lde[i].to_le_bytes());
            }
        }
        let tree = MerkleTree::from_flat(&flat, row_len)?;
        let (step_drop, _) = crate::merkle::capped_shape(m_step, self.params.cap_height);
        transcript.absorb(
            b"fold/trace",
            &crate::merkle::cap_bytes(&tree.cap(step_drop)),
        );

        let mut alphas = [Field::ZERO; ALPHAS];
        for slot in &mut alphas {
            *slot = transcript.challenge_bb(b"fold/alpha");
        }
        let points = lde_points(self.params.lde_len())?;
        let w_last = omega_base.pow((s - 1) as u64);
        let composition = compose_step(
            &[&lde_cols[0][..], &lde_cols[1][..]],
            &points,
            w_last,
            claims,
            s,
            offset,
            &alphas,
        );
        self.steps.push(StepData {
            claims,
            ldes: lde_cols,
            tree,
            composition,
        });
        Ok(())
    }

    /// Fold all segments: random combination plus one shared FRI proof.
    ///
    /// # Errors
    /// Returns [`Error::EmptyInput`] with no segments, otherwise structural
    /// errors.
    pub fn finalize(self, transcript: &mut Transcript) -> Result<IvcProof> {
        if self.steps.is_empty() {
            return Err(Error::EmptyInput);
        }
        let m = self.params.lde_len();
        // Combination challenges, one per step, after every step committed.
        let mut gammas = Vec::with_capacity(self.steps.len());
        for _ in &self.steps {
            gammas.push(transcript.challenge_bb(b"fold/gamma"));
        }
        let mut combined = vec![Field::ZERO; m];
        crate::par::for_each_indexed(&mut combined, 2048, |base, piece| {
            for (j, slot) in piece.iter_mut().enumerate() {
                let i = base + j;
                let mut acc = Field::ZERO;
                for (step, &gamma) in self.steps.iter().zip(&gammas) {
                    acc += gamma * step.composition[i];
                }
                *slot = acc;
            }
        });
        let fri_params = self.params.fri_params()?;
        // Each composition has degree `< S`; the combination too.
        let fri_state =
            fri::commit_evals(&combined, self.params.seg_steps - 1, fri_params, transcript)?;
        let fri_commitment = fri::public_commitment(&fri_state);
        let (fri_proof, fri_indices) = fri::open(&fri_state, transcript)?;

        let log_m = m.trailing_zeros();
        let offset = m / self.params.seg_steps;
        let (drop, _) = crate::merkle::capped_shape(m, self.params.cap_height);
        let mut steps = Vec::with_capacity(self.steps.len());
        for step in &self.steps {
            let column_cap = step.tree.cap(drop);
            let mut openings = Vec::with_capacity(self.params.num_queries);
            for &leaf in &fri_indices {
                let index = bit_reverse_index(leaf, log_m);
                let shifted = (index + offset) % m;
                let cols = [
                    step.ldes[0][index],
                    step.ldes[1][index],
                    step.ldes[0][shifted],
                    step.ldes[1][shifted],
                ];
                let path = step.tree.prove_capped(index, drop)?;
                let shift_path = step.tree.prove_capped(shifted, drop)?;
                openings.push(StepOpening {
                    index,
                    cols,
                    path,
                    shift_path,
                });
            }
            steps.push(StepProof {
                claims: step.claims,
                column_cap,
                openings,
            });
        }
        Ok(IvcProof {
            steps,
            fri_commitment,
            fri_proof,
        })
    }
}

/// Verify a folded IVC [`IvcProof`]: chain links, then one shared FRI plus
/// per-step composition identities at the shared query positions.
///
/// # Errors
/// Returns [`Error::FriVerificationFailed`] or [`Error::BadMerklePath`] on
/// any failed check.
pub fn verify(params: Params, proof: &IvcProof, transcript: &mut Transcript) -> Result<()> {
    params.validate()?;
    if proof.steps.is_empty() {
        return Err(Error::EmptyInput);
    }
    let s = params.seg_steps;
    let m = params.lde_len();
    if m % s != 0 {
        return Err(Error::FriVerificationFailed);
    }
    // The shared FRI commitment is untrusted: pin it to the single domain,
    // composition degree, and evaluation-message length used by the prover.
    if proof.fri_commitment.lde_len != m
        || proof.fri_commitment.poly_len != m
        || proof.fri_commitment.degree_bound != s - 1
    {
        return Err(Error::FriVerificationFailed);
    }
    // Shift offset in LDE index space: `omega_base * x_i = x_{(i+offset)}`.
    let offset = m / s;
    absorb_params(params, transcript);

    check_chain(params, proof)?;

    // Replay per-step commitments and challenges.
    let omega_base = Field::primitive_root(s)?;
    let w_last = omega_base.pow((s - 1) as u64);
    let mut all_alphas: Vec<[Field; ALPHAS]> = Vec::with_capacity(proof.steps.len());
    for step in &proof.steps {
        absorb_step(&step.claims, transcript);
        transcript.absorb(b"fold/trace", &crate::merkle::cap_bytes(&step.column_cap));
        let mut alphas = [Field::ZERO; ALPHAS];
        for slot in &mut alphas {
            *slot = transcript.challenge_bb(b"fold/alpha");
        }
        all_alphas.push(alphas);
        if step.openings.len() != params.num_queries {
            return Err(Error::FriVerificationFailed);
        }
    }
    let mut gammas = Vec::with_capacity(proof.steps.len());
    for _ in &proof.steps {
        gammas.push(transcript.challenge_bb(b"fold/gamma"));
    }

    let fri_params = params.fri_params()?;
    let fri_indices = fri::verify(
        &proof.fri_commitment,
        &proof.fri_proof,
        fri_params,
        transcript,
    )?;

    let log_m = m.trailing_zeros();
    for (query_index, (query, &leaf)) in
        proof.fri_proof.queries.iter().zip(&fri_indices).enumerate()
    {
        let index = bit_reverse_index(leaf, log_m);
        // On-demand domain point (one `pow` per query): identical to the
        // full vector entry, negligible work. Shared by every step.
        let point = lde_point_at(m, index)?;
        // Combined composition value from every step at this position.
        let mut combined = Field::ZERO;
        for ((step, alphas), &gamma) in proof.steps.iter().zip(&all_alphas).zip(&gammas) {
            let opening = &step.openings[query_index];
            if opening.index != index {
                return Err(Error::FriVerificationFailed);
            }
            check_step_openings(step, opening, index, m, offset, params.cap_height)?;
            combined += gamma
                * composition_at(
                    [opening.cols[0], opening.cols[1]],
                    [opening.cols[2], opening.cols[3]],
                    point,
                    w_last,
                    step.claims,
                    s,
                    alphas,
                );
        }
        // `first` (not indexing): a degenerate commitment could carry
        // fold-free queries, and proofs are untrusted input.
        let quad = query.folds.first().ok_or(Error::FriVerificationFailed)?;
        let qval = quad.values[leaf % 4];
        if qval != combined {
            return Err(Error::FriVerificationFailed);
        }
    }
    Ok(())
}

/// Authenticate both joint rows of one step opening (the query point and
/// its `omega_base`-shift). Shapes are pinned first: the cap holds exactly
/// `2^drop` digests and every path is exactly `depth - drop` steps, so
/// malformed proofs fail before any hashing. The shifted index is
/// recomputed here, so the transition's next-row values can only be the
/// committed columns at that position.
fn check_step_openings(
    step: &StepProof,
    opening: &StepOpening,
    index: usize,
    m: usize,
    offset: usize,
    cap_height: usize,
) -> Result<()> {
    let (drop, depth) = crate::merkle::capped_shape(m, cap_height);
    if step.column_cap.len() != 1usize << drop
        || opening.path.len() != depth - drop
        || opening.shift_path.len() != depth - drop
    {
        return Err(Error::BadMerklePath);
    }
    let mut row = [0u8; 8];
    row[..4].copy_from_slice(&opening.cols[0].to_le_bytes());
    row[4..].copy_from_slice(&opening.cols[1].to_le_bytes());
    let entry = step
        .column_cap
        .get(index >> (depth - drop))
        .ok_or(Error::BadMerklePath)?;
    if !MerkleTree::verify_capped(entry, &row, index, depth, &opening.path) {
        return Err(Error::BadMerklePath);
    }
    let shifted = (index + offset) % m;
    let mut shift_row = [0u8; 8];
    shift_row[..4].copy_from_slice(&opening.cols[2].to_le_bytes());
    shift_row[4..].copy_from_slice(&opening.cols[3].to_le_bytes());
    let shift_entry = step
        .column_cap
        .get(shifted >> (depth - drop))
        .ok_or(Error::BadMerklePath)?;
    if !MerkleTree::verify_capped(shift_entry, &shift_row, shifted, depth, &opening.shift_path) {
        return Err(Error::BadMerklePath);
    }
    Ok(())
}

/// Chain-link check: segment boundaries against each other and the global
/// claims.
fn check_chain(params: Params, proof: &IvcProof) -> Result<()> {
    let first = &proof.steps[0];
    if first.claims.in_a != params.in_a || first.claims.in_b != params.in_b {
        return Err(Error::FriVerificationFailed);
    }
    for pair in proof.steps.windows(2) {
        if pair[0].claims.out_a != pair[1].claims.in_a
            || pair[0].claims.out_b != pair[1].claims.in_b
        {
            return Err(Error::FriVerificationFailed);
        }
    }
    let last = &proof.steps[proof.steps.len() - 1];
    if last.claims.out_b != params.out_b {
        return Err(Error::FriVerificationFailed);
    }
    Ok(())
}

fn absorb_params(params: Params, transcript: &mut Transcript) {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&(params.seg_steps as u64).to_le_bytes());
    buf.extend_from_slice(&(params.blowup as u64).to_le_bytes());
    buf.extend_from_slice(&(params.num_queries as u64).to_le_bytes());
    buf.extend_from_slice(&(params.final_size as u64).to_le_bytes());
    buf.extend_from_slice(&params.grinding_bits.to_le_bytes());
    buf.extend_from_slice(&(params.cap_height as u64).to_le_bytes());
    buf.extend_from_slice(&params.in_a.to_le_bytes());
    buf.extend_from_slice(&params.in_b.to_le_bytes());
    buf.extend_from_slice(&params.out_b.to_le_bytes());
    transcript.absorb(b"fold/params", &buf);
}

fn absorb_step(claims: &StepClaims, transcript: &mut Transcript) {
    let mut buf = Vec::with_capacity(16);
    buf.extend_from_slice(&claims.in_a.to_le_bytes());
    buf.extend_from_slice(&claims.in_b.to_le_bytes());
    buf.extend_from_slice(&claims.out_a.to_le_bytes());
    buf.extend_from_slice(&claims.out_b.to_le_bytes());
    transcript.absorb(b"fold/step", &buf);
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

/// Full step-composition vector on the shared LDE domain.
///
/// Batched like [`crate::air`] composition: vanishing geometric plus
/// Montgomery inversions per chunk, bit-identical to [`composition_at`].
/// Next-row values come from the same committed columns at
/// `(i + offset) mod lde_len` (see [`StepOpening`]), never a separate
/// witness column.
#[allow(clippy::too_many_arguments)]
fn compose_step(
    cols: &[&[Field]],
    points: &[Field],
    w_last: Field,
    claims: StepClaims,
    s: usize,
    offset: usize,
    alphas: &[Field; ALPHAS],
) -> Vec<Field> {
    let m = cols[0].len();
    let shifted = |j: usize, i: usize| cols[j][(i + offset) % m];
    if points.len() < 2 {
        // Degenerate (unreachable at real domain sizes): scalar fallback.
        return points
            .iter()
            .enumerate()
            .map(|(i, &point)| {
                composition_at(
                    [cols[0][i], cols[1][i]],
                    [shifted(0, i), shifted(1, i)],
                    point,
                    w_last,
                    claims,
                    s,
                    alphas,
                )
            })
            .collect();
    }
    let p0 = points[0].pow(s as u64);
    let ratio = (points[1] * points[0].inv()).pow(s as u64);
    let mut out = vec![Field::ZERO; points.len()];
    crate::par::for_each_indexed(&mut out, 2048, |base, piece| {
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
        for (j, slot) in piece.iter_mut().enumerate() {
            let i = base + j;
            let trans1 = (shifted(0, i) - cols[1][i]) * inv_z[j];
            let trans2 = (shifted(1, i) - (cols[0][i] + cols[1][i])) * inv_z[j];
            let bound_in_a = (cols[0][i] - claims.in_a) * inv_b[j];
            let bound_in_b = (cols[1][i] - claims.in_b) * inv_b[j];
            let bound_out_a = (cols[0][i] - claims.out_a) * inv_a[j];
            let bound_out_b = (cols[1][i] - claims.out_b) * inv_a[j];
            *slot = alphas[0] * trans1
                + alphas[1] * trans2
                + alphas[2] * bound_in_a
                + alphas[3] * bound_in_b
                + alphas[4] * bound_out_a
                + alphas[5] * bound_out_b;
        }
    });
    out
}

/// Step-composition value at one point (quotient form, as in [`crate::air`]).
fn composition_at(
    cols: [Field; 2],
    next: [Field; 2],
    point: Field,
    w_last: Field,
    claims: StepClaims,
    s: usize,
    alphas: &[Field; ALPHAS],
) -> Field {
    let vanishing = point.pow(s as u64) - Field::ONE;
    let z_trans = vanishing * (point - w_last).inv();
    let trans1 = (next[0] - cols[1]) * z_trans.inv();
    let trans2 = (next[1] - (cols[0] + cols[1])) * z_trans.inv();
    let bound_in_a = (cols[0] - claims.in_a) * (point - Field::ONE).inv();
    let bound_in_b = (cols[1] - claims.in_b) * (point - Field::ONE).inv();
    let bound_out_a = (cols[0] - claims.out_a) * (point - w_last).inv();
    let bound_out_b = (cols[1] - claims.out_b) * (point - w_last).inv();
    alphas[0] * trans1
        + alphas[1] * trans2
        + alphas[2] * bound_in_a
        + alphas[3] * bound_in_b
        + alphas[4] * bound_out_a
        + alphas[5] * bound_out_b
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
    use crate::air::build_trace;

    /// Chain `count` Fibonacci segments of `seg` rows from `(1, 1)`.
    fn chained_traces(seg: usize, count: usize) -> Vec<(Vec<Field>, Vec<Field>)> {
        let (mut a, mut b) = (Field::ONE, Field::ONE);
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let (ca, cb) = build_trace(a, b, seg);
            a = ca[seg - 1];
            b = cb[seg - 1];
            out.push((ca, cb));
        }
        out
    }

    fn test_params(out_b: Field) -> Params {
        Params::new(8, 8, 8, 4, Field::ONE, Field::ONE, out_b).unwrap()
    }

    fn last_b(seg: usize, count: usize) -> Field {
        let traces = chained_traces(seg, count);
        traces[count - 1].1[seg - 1]
    }

    #[test]
    fn rejects_bad_params() {
        assert!(Params::new(3, 8, 8, 4, Field::ONE, Field::ONE, Field::ONE).is_err());
        assert!(Params::new(8, 2, 8, 4, Field::ONE, Field::ONE, Field::ONE).is_err());
        assert!(Params::new(8, 8, 0, 4, Field::ONE, Field::ONE, Field::ONE).is_err());
        let huge = 1usize << (usize::BITS - 1);
        assert!(Params::new(huge, 4, 8, 4, Field::ONE, Field::ONE, Field::ONE).is_err());
    }

    #[test]
    fn forged_segment_a_jump_rejected() {
        // Bind `out_a` at the last row. Without that boundary, a prover can
        // jump A between segments while keeping B chained, and set the
        // second segment's input A arbitrarily to reach a false global B.
        let s = 8;
        let (first_a, first_b) = chained_traces(s, 1).remove(0);
        let jump = Field::new(99);
        let (second_a, second_b) = crate::air::build_trace(jump, first_b[s - 1], s);
        let target = second_b[s - 1];
        let true_out = crate::air::build_trace(Field::ONE, Field::ONE, 2 * s).1[2 * s - 1];
        assert_ne!(target, true_out);

        let params = Params::new(s, 8, 8, 4, Field::ONE, Field::ONE, target).unwrap();
        let mut prover = Transcript::new(b"fold-forge-a");
        let mut acc = Accumulator::new(params);
        acc.add_segment(&first_a, &first_b, &mut prover).unwrap();
        acc.add_segment(&second_a, &second_b, &mut prover).unwrap();

        let mut steps = acc.steps;
        steps[0].claims.out_a = jump;

        // Replay the prover transcript with the forged boundary claim and
        // recompute both compositions so the FRI commitment is internally
        // consistent with the mutated proof.
        let mut t = Transcript::new(b"fold-forge-a");
        absorb_params(params, &mut t);
        let m = params.lde_len();
        let points = lde_points(m).unwrap();
        let w_last = Field::primitive_root(s).unwrap().pow((s - 1) as u64);
        let offset = m / s;
        let (drop, _) = crate::merkle::capped_shape(m, params.cap_height);
        for step in &mut steps {
            absorb_step(&step.claims, &mut t);
            t.absorb(
                b"fold/trace",
                &crate::merkle::cap_bytes(&step.tree.cap(drop)),
            );
            let mut alphas = [Field::ZERO; ALPHAS];
            for slot in &mut alphas {
                *slot = t.challenge_bb(b"fold/alpha");
            }
            step.composition = compose_step(
                &[&step.ldes[0][..], &step.ldes[1][..]],
                &points,
                w_last,
                step.claims,
                s,
                offset,
                &alphas,
            );
        }
        let forged = Accumulator { params, steps };
        let proof = forged.finalize(&mut t).unwrap();
        let mut verifier = Transcript::new(b"fold-forge-a");
        assert!(verify(params, &proof, &mut verifier).is_err());
    }

    #[test]
    fn accumulator_starts_empty() {
        let acc = Accumulator::new(test_params(Field::ONE));
        assert!(acc.is_empty());
        assert_eq!(acc.len(), 0);
    }

    #[test]
    fn finalize_empty_fails() {
        let acc = Accumulator::new(test_params(Field::ONE));
        let mut t = Transcript::new(b"fold-empty");
        assert!(acc.finalize(&mut t).is_err());
    }

    #[test]
    fn honest_ivc_verifies() {
        let traces = chained_traces(8, 3);
        let params = test_params(last_b(8, 3));
        let mut prover_t = Transcript::new(b"fold-e2e");
        let mut acc = Accumulator::new(params);
        for (ca, cb) in &traces {
            acc.add_segment(ca, cb, &mut prover_t).unwrap();
        }
        assert_eq!(acc.len(), 3);
        let proof = acc.finalize(&mut prover_t).unwrap();
        assert_eq!(proof.steps.len(), 3);
        // One shared FRI for all three steps: 64 -> 16 -> 4.
        assert_eq!(proof.fri_commitment.caps.len(), 3);
        let mut verifier_t = Transcript::new(b"fold-e2e");
        verify(params, &proof, &mut verifier_t).unwrap();
    }

    #[test]
    fn for_security_roundtrip() {
        let traces = chained_traces(8, 2);
        let params = Params::for_security(8, Field::ONE, Field::ONE, last_b(8, 2), 12).unwrap();
        assert_eq!(params.blowup, 16);
        assert_eq!((params.num_queries, params.grinding_bits), (3, 6));
        assert!(params.cap_height <= 4);
        let mut prover_t = Transcript::new(b"fold-forsec");
        let mut acc = Accumulator::new(params);
        for (ca, cb) in &traces {
            acc.add_segment(ca, cb, &mut prover_t).unwrap();
        }
        let proof = acc.finalize(&mut prover_t).unwrap();
        let mut verifier_t = Transcript::new(b"fold-forsec");
        verify(params, &proof, &mut verifier_t).unwrap();

        assert!(Params::for_security(3, Field::ONE, Field::ONE, Field::ONE, 12).is_err());
    }

    #[test]
    fn truncated_and_swapped_openings_fail() {
        let traces = chained_traces(8, 2);
        let params = test_params(last_b(8, 2));
        let mut prover_t = Transcript::new(b"fold-shape");
        let mut acc = Accumulator::new(params);
        for (ca, cb) in &traces {
            acc.add_segment(ca, cb, &mut prover_t).unwrap();
        }
        let proof = acc.finalize(&mut prover_t).unwrap();
        // Dropped opening in one step: count mismatch.
        let mut short = proof.clone();
        short.steps[0].openings.pop();
        let mut verifier_t = Transcript::new(b"fold-shape");
        assert!(verify(params, &short, &mut verifier_t).is_err());
        // Swapped order in one step: indices miss query order.
        let mut swapped = proof.clone();
        swapped.steps[0].openings.swap(0, 1);
        let mut verifier_t = Transcript::new(b"fold-shape");
        assert!(verify(params, &swapped, &mut verifier_t).is_err());
    }

    #[test]
    fn cap_mismatch_rejects() {
        let traces = chained_traces(8, 2);
        let capped = test_params(last_b(8, 2)).with_cap_height(2);
        let mut prover_t = Transcript::new(b"fold-capmix");
        let mut acc = Accumulator::new(capped);
        for (ca, cb) in &traces {
            acc.add_segment(ca, cb, &mut prover_t).unwrap();
        }
        let proof = acc.finalize(&mut prover_t).unwrap();
        let plain = test_params(last_b(8, 2));
        let mut verifier_t = Transcript::new(b"fold-capmix");
        assert!(verify(plain, &proof, &mut verifier_t).is_err());

        let mut prover_t = Transcript::new(b"fold-capmix");
        let mut acc = Accumulator::new(plain);
        for (ca, cb) in &traces {
            acc.add_segment(ca, cb, &mut prover_t).unwrap();
        }
        let plain_proof = acc.finalize(&mut prover_t).unwrap();
        let mut verifier_t = Transcript::new(b"fold-capmix");
        assert!(verify(capped, &plain_proof, &mut verifier_t).is_err());
    }

    #[test]
    fn encoding_roundtrip_and_rejects() {
        for (label, cap) in [("fold-codec", 0usize), ("fold-codec-cap", 2usize)] {
            let traces = chained_traces(8, 2);
            let params = test_params(last_b(8, 2)).with_cap_height(cap);
            let mut prover_t = Transcript::new(label.as_bytes());
            let mut acc = Accumulator::new(params);
            for (ca, cb) in &traces {
                acc.add_segment(ca, cb, &mut prover_t).unwrap();
            }
            let proof = acc.finalize(&mut prover_t).unwrap();
            let bytes = proof.to_bytes();
            assert_eq!(IvcProof::from_bytes(&bytes).unwrap(), proof);
            // Decoded proofs verify: catches mirrored encode/decode bugs
            // that a pure roundtrip would miss.
            let mut verifier_t = Transcript::new(label.as_bytes());
            verify(
                params,
                &IvcProof::from_bytes(&bytes).unwrap(),
                &mut verifier_t,
            )
            .unwrap();
            assert!(IvcProof::from_bytes(&bytes[..bytes.len() - 1]).is_err());
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(IvcProof::from_bytes(&trailing).is_err());
        }
    }

    #[test]
    fn capped_roundtrip() {
        let traces = chained_traces(8, 3);
        let params = test_params(last_b(8, 3)).with_cap_height(2);
        let mut prover_t = Transcript::new(b"fold-cap");
        let mut acc = Accumulator::new(params);
        for (ca, cb) in &traces {
            acc.add_segment(ca, cb, &mut prover_t).unwrap();
        }
        let proof = acc.finalize(&mut prover_t).unwrap();
        for step in &proof.steps {
            assert_eq!(step.column_cap.len(), 4);
            // Column paths shrink by the cap height (depth 6 -> 4 steps).
            for opening in &step.openings {
                assert_eq!(opening.path.len(), 4);
            }
        }
        let mut verifier_t = Transcript::new(b"fold-cap");
        verify(params, &proof, &mut verifier_t).unwrap();

        // Forged cap entry fails.
        let mut bad = proof.clone();
        bad.steps[0].column_cap[0][0] ^= 1;
        let mut verifier_t = Transcript::new(b"fold-cap");
        assert!(verify(params, &bad, &mut verifier_t).is_err());
    }

    #[test]
    fn broken_chain_fails() {
        let traces = chained_traces(8, 3);
        let params = test_params(last_b(8, 3));
        let mut prover_t = Transcript::new(b"fold-chain");
        let mut acc = Accumulator::new(params);
        for (ca, cb) in &traces {
            acc.add_segment(ca, cb, &mut prover_t).unwrap();
        }
        let mut proof = acc.finalize(&mut prover_t).unwrap();
        // Rewire the middle step to different claims: links break.
        proof.steps[1].claims.in_a += Field::ONE;
        let mut verifier_t = Transcript::new(b"fold-chain");
        assert!(verify(params, &proof, &mut verifier_t).is_err());
    }

    #[test]
    fn bad_segment_rejected() {
        let traces = chained_traces(8, 3);
        let params = test_params(last_b(8, 3));
        let mut prover_t = Transcript::new(b"fold-badseg");
        let mut acc = Accumulator::new(params);
        // Poison the middle segment: the batched combination stays far from
        // low-degree and FRI's final check rejects it.
        let (mut bad_a, bad_b) = (traces[1].0.clone(), traces[1].1.clone());
        bad_a[4] += Field::ONE;
        acc.add_segment(&traces[0].0, &traces[0].1, &mut prover_t)
            .unwrap();
        acc.add_segment(&bad_a, &bad_b, &mut prover_t).unwrap();
        acc.add_segment(&traces[2].0, &traces[2].1, &mut prover_t)
            .unwrap();
        let proof = acc.finalize(&mut prover_t).unwrap();
        let mut verifier_t = Transcript::new(b"fold-badseg");
        assert!(verify(params, &proof, &mut verifier_t).is_err());
    }

    #[test]
    fn tampered_opening_fails() {
        let traces = chained_traces(8, 2);
        let params = test_params(last_b(8, 2));
        let mut prover_t = Transcript::new(b"fold-tamper");
        let mut acc = Accumulator::new(params);
        for (ca, cb) in &traces {
            acc.add_segment(ca, cb, &mut prover_t).unwrap();
        }
        let mut proof = acc.finalize(&mut prover_t).unwrap();
        proof.steps[0].openings[0].cols[1] += Field::ONE;
        let mut verifier_t = Transcript::new(b"fold-tamper");
        assert!(verify(params, &proof, &mut verifier_t).is_err());
    }

    #[test]
    fn shifted_opening_tamper_fails() {
        // The transition reads next-row values from the same committed
        // tree at the recomputed shifted index; tampering the shifted
        // values or their path must fail.
        let traces = chained_traces(8, 2);
        let params = test_params(last_b(8, 2));
        for tamper in 0..4 {
            let mut prover_t = Transcript::new(b"fold-shift-tamper");
            let mut acc = Accumulator::new(params);
            for (ca, cb) in &traces {
                acc.add_segment(ca, cb, &mut prover_t).unwrap();
            }
            let mut proof = acc.finalize(&mut prover_t).unwrap();
            let opening = &mut proof.steps[0].openings[0];
            match tamper {
                0 => opening.cols[2] += Field::ONE,
                1 => opening.cols[3] += Field::ONE,
                2 => {
                    let last = opening.shift_path.len() - 1;
                    opening.shift_path[last].1 = !opening.shift_path[last].1;
                }
                _ => {
                    opening.shift_path.pop();
                }
            }
            let mut verifier_t = Transcript::new(b"fold-shift-tamper");
            assert!(
                verify(params, &proof, &mut verifier_t).is_err(),
                "tamper {tamper}"
            );
        }
    }

    #[test]
    fn wrong_transcript_fails() {
        let traces = chained_traces(8, 2);
        let params = test_params(last_b(8, 2));
        let mut prover_t = Transcript::new(b"fold-A");
        let mut acc = Accumulator::new(params);
        for (ca, cb) in &traces {
            acc.add_segment(ca, cb, &mut prover_t).unwrap();
        }
        let proof = acc.finalize(&mut prover_t).unwrap();
        let mut verifier_t = Transcript::new(b"fold-B");
        assert!(verify(params, &proof, &mut verifier_t).is_err());
    }
}
