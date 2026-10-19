//! Recursion fragment: a STARK that re-checks one FRI query's fold chain.
//!
//! [`fri::verify`] accepts a query by walking its fold chain: the quad opened
//! at layer `d` folds with the depth challenge `c_d` into one parent value,
//! which must be the selected element of the next layer's opened quad; the
//! last parent must match `final_poly[leaf >> 2*folds]` (see
//! `fri::verify_one`). This module proves that walk as a small STARK whose
//! public statement is exactly the verifier's per-query input/output:
//!
//! - public: the outer `lde_len` and `leaf`, the per-depth fold challenges,
//!   the layer-0 quad `initial`, and the claimed final value `output`;
//! - witness: the quads `q_0..q_{folds-1}` revealed at layers `0..folds`
//!   (with `q_0 = initial`) and their fold outputs `out_d`;
//! - relation: `out_d = fold_values(q_d, 1/x_d, c_d, unit)` and
//!   `q_{d+1}[j_d] = out_d` for every step, `out_{folds-1} = output`, where
//!   `x_d` is the on-demand domain point of the opened quad and
//!   `j_d = (leaf >> (2d + 2)) & 3` is the verifier's selected position.
//!
//! # Constraints
//!
//! Trace columns `q0..q3, out` over `n = next_pow2(folds)` base rows (at
//! least two), padded after `folds` rows with `q_j = out = out_{folds-1}` so
//! the padded transition identities stay satisfied. With `I`, `c`, `e_j`,
//! `e_last` the public per-row polynomials (`1/x_d`, challenges, one-hot
//! selectors, and the last-real-row indicator):
//!
//! | constraint | divisor | quotient degree |
//! |---|---|---|
//! | `out - fold_values(q, I, c)` | `x^n - 1` | `4n - 5` |
//! | `out - Σ_j e_j · q_j(ω·x)` | `(x^n - 1)/(x - w_last)` | `n - 1` |
//! | `q_j - initial_j` (row 0) | `x - 1` | `n - 2` |
//! | `e_last · (out - output)` | `x^n - 1` | `n - 2` |
//!
//! Transition reads next-row values from the same committed columns at the
//! `omega_n`-shifted LDE index (authenticated by a second Merkle path), so the
//! chain cannot be decoupled from the committed quads. All public data is
//! absorbed under `"rec/params"`, the trace cap under `"rec/trace"`, the
//! seven composition challenges under `"rec/alpha"`, and the composition is
//! committed with [`fri::commit_evals`] at degree bound `4n - 5`.
//!
//! # Scope
//!
//! This is the recursive **arithmetic** fragment, not yet a proof about a
//! proof: it pins the fold chain algebra given `(leaf, challenges, initial,
//! output)` as public inputs, but does not itself re-verify that those came
//! from an outer commitment. Completing recursion needs additionally:
//! Merkle/BLAKE3 path verification in-AIR (commitment openings), the
//! final-layer degree check, and transcript re-derivation of the challenges —
//! the same [BLAKE3](crate::hash) primitive throughout. The fold-chain AIR is
//! the part where a naive encoding silently loses soundness, so it is pinned
//! with tamper tests here first.

use crate::babybear::Field;
use crate::error::{Error, Result};
use crate::fri::{self, Commitment as FriCommitment, Proof as FriProof};
use crate::merkle::MerkleTree;
use crate::ntt::{evaluate, evaluate_on_coset, interpolate};
use crate::transcript::Transcript;

/// Maximum fold depth supported by [`Params`].
pub const MAX_FOLDS: usize = 16;
/// Trace columns: four quad values plus the folded output.
const COLS: usize = 5;
/// Composition challenges: one per constraint row above.
const ALPHAS: usize = 7;

/// Parameters for the fold-chain fragment.
///
/// The first block is the public statement (outer FRI query data); the second
/// sizes the fragment's own FRI argument. All fields are public, so proving
/// and verifying re-validate them rather than trusting a constructor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// LDE length of the outer commitment whose query is being checked.
    pub lde_len: usize,
    /// Outer FRI query leaf index (bit-reversed layer order).
    pub leaf: usize,
    /// Number of fold rounds in the query (1 to [`MAX_FOLDS`]).
    pub folds: usize,
    /// Per-depth fold challenges (only `folds` entries are read).
    pub challenges: [[Field; 3]; MAX_FOLDS],
    /// Layer-0 quad values opened at `leaf & !3`.
    pub initial: [Field; 4],
    /// Claimed final folded value (`final_poly[leaf >> 2*folds]`).
    pub output: Field,
    /// Trace LDE blowup (power of two, `>= 4`; rate `< 1/2`).
    pub blowup: usize,
    /// FRI query count (`>= 1`).
    pub num_queries: usize,
    /// FRI final layer size (power of two, `>= 1`).
    pub final_size: usize,
    /// Proof-of-work difficulty in leading-zero bits (`0` disables grinding).
    pub grinding_bits: u32,
    /// Merkle cap height for the trace tree and FRI layers (`0` = roots).
    pub cap_height: usize,
}

impl Params {
    /// Validate shape and build parameters.
    ///
    /// # Errors
    /// Returns [`Error::MalformedInput`] for an out-of-range fold count or a
    /// mismatched challenge count, and [`Error::InvalidDomainSize`],
    /// [`Error::InvalidBlowup`], or [`Error::NoQueries`] for unusable
    /// domains or FRI sizing.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lde_len: usize,
        leaf: usize,
        folds: usize,
        challenges: &[[Field; 3]],
        initial: [Field; 4],
        output: Field,
        blowup: usize,
        num_queries: usize,
        final_size: usize,
    ) -> Result<Self> {
        if challenges.len() != folds {
            return Err(Error::MalformedInput {
                reason: "one fold challenge triple per fold depth",
            });
        }
        let mut fixed = [[Field::ZERO; 3]; MAX_FOLDS];
        for (slot, challenge) in fixed.iter_mut().zip(challenges) {
            *slot = *challenge;
        }
        let params = Self {
            lde_len,
            leaf,
            folds,
            challenges: fixed,
            initial,
            output,
            blowup,
            num_queries,
            final_size,
            grinding_bits: 0,
            cap_height: 0,
        };
        params.validate()?;
        Ok(params)
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

    /// Production parameters for the fragment: blowup 16 and strength sized
    /// for `target_bits` conjectured bits (queries + grinding), with
    /// size-optimal final layer and cap height.
    ///
    /// # Errors
    /// Same errors as [`Params::new`].
    pub fn for_security(
        lde_len: usize,
        leaf: usize,
        folds: usize,
        challenges: &[[Field; 3]],
        initial: [Field; 4],
        output: Field,
        target_bits: u32,
    ) -> Result<Self> {
        let blowup = 16;
        let n = folds.next_power_of_two().max(2);
        let lde = n
            .checked_mul(blowup)
            .ok_or(Error::InvalidDomainSize { size: n })?;
        if lde > (1usize << Field::TWO_ADICITY) {
            return Err(Error::InvalidDomainSize { size: lde });
        }
        let millibits = fri::composition_millibits(lde, 4 * n - 5);
        let (num_queries, grinding_bits) = fri::tune_strength(target_bits, millibits);
        let (final_size, cap_height) = fri::tune_shape(lde, num_queries, &[(lde, 8 + 4 * COLS)]);
        Ok(Self::new(
            lde_len,
            leaf,
            folds,
            challenges,
            initial,
            output,
            blowup,
            num_queries,
            final_size,
        )?
        .with_grinding_bits(grinding_bits)
        .with_cap_height(cap_height))
    }

    /// Number of trace rows (power of two, at least two).
    #[must_use]
    pub fn n_rows(&self) -> usize {
        self.folds.next_power_of_two().max(2)
    }

    /// Declared composition degree bound (`4n - 5`; see module docs).
    fn composition_degree_bound(&self) -> usize {
        4 * self.n_rows() - 5
    }

    fn fri_params(&self) -> Result<fri::Params> {
        Ok(
            fri::Params::new(self.blowup, self.num_queries, self.final_size)?
                .with_grinding_bits(self.grinding_bits)
                .with_cap_height(self.cap_height),
        )
    }

    /// Re-check every invariant for entry points.
    fn validate(&self) -> Result<()> {
        if self.folds == 0 || self.folds > MAX_FOLDS {
            return Err(Error::MalformedInput {
                reason: "folds must be in 1..=MAX_FOLDS",
            });
        }
        if self.lde_len < 4
            || !self.lde_len.is_power_of_two()
            || 2 * self.folds > self.lde_len.trailing_zeros() as usize
        {
            return Err(Error::InvalidDomainSize { size: self.lde_len });
        }
        if self.leaf >= self.lde_len {
            return Err(Error::IndexOutOfBounds {
                index: self.leaf,
                len: self.lde_len,
            });
        }
        for depth in 0..self.folds {
            let layer_len = self.lde_len >> (2 * depth);
            let base = (self.leaf >> (2 * depth)) & !3;
            if base + 3 >= layer_len {
                return Err(Error::IndexOutOfBounds {
                    index: self.leaf,
                    len: layer_len,
                });
            }
        }
        let n = self.n_rows();
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
        let lde = n
            .checked_mul(self.blowup)
            .ok_or(Error::InvalidDomainSize { size: n })?;
        if lde > (1usize << Field::TWO_ADICITY) {
            return Err(Error::InvalidDomainSize { size: lde });
        }
        // Rate gate: the declared composition bound must leave rate `< 1/2`.
        if self.composition_degree_bound() + 1 > lde / 2 {
            return Err(Error::InvalidBlowup {
                factor: self.blowup,
            });
        }
        Ok(())
    }
}

/// One trace opening at an LDE position.
///
/// `next` holds the same committed columns at the shifted LDE index
/// `index + lde_len_trace / n_rows` (mod `lde_len_trace`), i.e. at
/// `omega_n · x`: the transition never trusts a separate, unauthenticated
/// "next row" witness. Both rows are Merkle paths into the one trace tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opening {
    /// Natural-order LDE index.
    pub index: usize,
    /// Quad values and folded output at `index`.
    pub values: [Field; COLS],
    /// Quad values and folded output at the shifted index.
    pub next: [Field; COLS],
    /// Merkle path of the joint row at `index`.
    pub path: Vec<([u8; 32], bool)>,
    /// Merkle path of the joint row at the shifted index.
    pub shift_path: Vec<([u8; 32], bool)>,
}

/// Fold-chain proof: trace root, FRI commitment/proof, query openings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// Merkle cap of the trace LDE (`2^cap_height` digests; one root when
    /// caps are disabled).
    pub column_cap: Vec<[u8; 32]>,
    /// FRI commitment to the composition polynomial.
    pub fri_commitment: FriCommitment,
    /// FRI opening proof.
    pub fri_proof: FriProof,
    /// Trace openings, one per FRI query, in query order.
    pub openings: Vec<Opening>,
}

impl Proof {
    /// Canonical bytes: version, column cap, FRI commitment/proof, then
    /// openings (index, five fields, shifted five fields, both paths).
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
            for value in &opening.values {
                writer.field(*value);
            }
            for value in &opening.next {
                writer.field(*value);
            }
            writer.path(&opening.path);
            writer.path(&opening.shift_path);
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
            openings.push(Opening {
                index: reader.dimension()?,
                values: [
                    reader.field()?,
                    reader.field()?,
                    reader.field()?,
                    reader.field()?,
                    reader.field()?,
                ],
                next: [
                    reader.field()?,
                    reader.field()?,
                    reader.field()?,
                    reader.field()?,
                    reader.field()?,
                ],
                path: reader.path()?,
                shift_path: reader.path()?,
            });
        }
        reader.end()?;
        Ok(Self {
            column_cap,
            fri_commitment: fri_commitment.clone(),
            fri_proof: fri_proof.clone(),
            openings,
        })
    }
}

/// Prove one FRI query's fold chain.
///
/// `quads[d]` is the outer proof's opened quad at layer `d` (`d = 0` must
/// equal `params.initial`). The witness need not satisfy the chain relation:
/// proving still succeeds structurally, but [`verify`] rejects invalid chains
/// through FRI's final low-degree check (same contract as
/// [`crate::air::prove_with_trace`]).
///
/// # Errors
/// Returns [`Error::MalformedInput`] when the witness length does not match
/// `folds`, otherwise the structural errors of the domain setup.
pub fn prove(params: Params, quads: &[[Field; 4]], transcript: &mut Transcript) -> Result<Proof> {
    params.validate()?;
    let n = params.n_rows();
    let unit = Field::two_adic_generator(2)?;
    let rows = trace_columns(&params, quads, unit)?;
    let mut columns: [Vec<Field>; COLS] = std::array::from_fn(|_| Vec::with_capacity(n));
    for row in &rows {
        for (slot, value) in columns.iter_mut().zip(row) {
            slot.push(*value);
        }
    }
    let mut lde_columns: [Vec<Field>; COLS] = std::array::from_fn(|_| Vec::new());
    for (slot, column) in lde_columns.iter_mut().zip(&columns) {
        let coeffs = interpolate(column)?;
        *slot = evaluate_on_coset(&coeffs, params.blowup, fri::LDE_SHIFT)?;
    }
    let m = n * params.blowup;
    let offset = params.blowup;

    absorb_params(&params, transcript);
    // One joint tree over interleaved rows: a single path opens a whole row.
    let row_len = 4 * COLS;
    let mut flat = vec![0u8; m * row_len];
    for (i, chunk) in flat.chunks_exact_mut(row_len).enumerate() {
        for (lde, slot) in lde_columns.iter().zip(chunk.chunks_exact_mut(4)) {
            slot.copy_from_slice(&lde[i].to_le_bytes());
        }
    }
    let tree = MerkleTree::from_flat(&flat, row_len)?;
    let (drop, _) = crate::merkle::capped_shape(m, params.cap_height);
    let column_cap = tree.cap(drop);
    transcript.absorb(b"rec/trace", &crate::merkle::cap_bytes(&column_cap));

    let mut alphas = [Field::ZERO; ALPHAS];
    for slot in &mut alphas {
        *slot = transcript.challenge_bb(b"rec/alpha");
    }

    let invs = inv_values(&params)?;
    let public = public_polys(&params, &invs)?;
    let points = lde_points(m)?;
    let w_last = Field::primitive_root(n)?.pow((n - 1) as u64);
    let composition = compose(
        &lde_columns,
        &points,
        &public,
        params.initial,
        params.output,
        n,
        offset,
        w_last,
        unit,
        &alphas,
    );
    let fri_state = fri::commit_evals(
        &composition,
        params.composition_degree_bound(),
        params.fri_params()?,
        transcript,
    )?;
    let fri_commitment = fri::public_commitment(&fri_state);
    let (fri_proof, fri_indices) = fri::open(&fri_state, transcript)?;

    let log_m = m.trailing_zeros();
    let mut openings = Vec::with_capacity(params.num_queries);
    for &leaf in &fri_indices {
        let index = bit_reverse_index(leaf, log_m);
        let shifted = (index + offset) % m;
        openings.push(Opening {
            index,
            values: [
                lde_columns[0][index],
                lde_columns[1][index],
                lde_columns[2][index],
                lde_columns[3][index],
                lde_columns[4][index],
            ],
            next: [
                lde_columns[0][shifted],
                lde_columns[1][shifted],
                lde_columns[2][shifted],
                lde_columns[3][shifted],
                lde_columns[4][shifted],
            ],
            path: tree.prove_capped(index, drop)?,
            shift_path: tree.prove_capped(shifted, drop)?,
        });
    }

    Ok(Proof {
        column_cap,
        fri_commitment,
        fri_proof,
        openings,
    })
}

/// Verify a fold-chain [`Proof`] under `params`.
///
/// # Errors
/// Returns [`Error::FriVerificationFailed`] or [`Error::BadMerklePath`] on
/// any failed check.
pub fn verify(params: Params, proof: &Proof, transcript: &mut Transcript) -> Result<()> {
    params.validate()?;
    let n = params.n_rows();
    let m = proof.fri_commitment.lde_len;
    if m == 0 || !m.is_power_of_two() || m % n != 0 {
        return Err(Error::FriVerificationFailed);
    }
    let offset = m / n;
    absorb_params(&params, transcript);

    if proof.openings.len() != params.num_queries {
        return Err(Error::FriVerificationFailed);
    }
    transcript.absorb(b"rec/trace", &crate::merkle::cap_bytes(&proof.column_cap));
    let mut alphas = [Field::ZERO; ALPHAS];
    for slot in &mut alphas {
        *slot = transcript.challenge_bb(b"rec/alpha");
    }

    let fri_indices = fri::verify(
        &proof.fri_commitment,
        &proof.fri_proof,
        params.fri_params()?,
        transcript,
    )?;

    let unit = Field::two_adic_generator(2)?;
    let invs = inv_values(&params)?;
    let public = public_polys(&params, &invs)?;
    let w_last = Field::primitive_root(n)?.pow((n - 1) as u64);
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
        // Authenticate both joint rows (the query point and its
        // `omega_n`-shift). Shapes are pinned first: capped trees hold
        // exactly `2^drop` digests and every path is exactly `depth - drop`
        // steps, so malformed proofs fail before any hashing. The shifted
        // index is recomputed here, so `next` can only be the committed
        // columns at that position.
        let (drop, depth) = crate::merkle::capped_shape(m, params.cap_height);
        if proof.column_cap.len() != 1usize << drop
            || opening.path.len() != depth - drop
            || opening.shift_path.len() != depth - drop
        {
            return Err(Error::BadMerklePath);
        }
        let mut row = [0u8; 4 * COLS];
        for (slot, value) in row.chunks_exact_mut(4).zip(&opening.values) {
            slot.copy_from_slice(&value.to_le_bytes());
        }
        let entry = proof
            .column_cap
            .get(index >> (depth - drop))
            .ok_or(Error::BadMerklePath)?;
        if !MerkleTree::verify_capped(entry, &row, index, depth, &opening.path) {
            return Err(Error::BadMerklePath);
        }
        let shifted = (index + offset) % m;
        let mut shift_row = [0u8; 4 * COLS];
        for (slot, value) in shift_row.chunks_exact_mut(4).zip(&opening.next) {
            slot.copy_from_slice(&value.to_le_bytes());
        }
        let shift_entry = proof
            .column_cap
            .get(shifted >> (depth - drop))
            .ok_or(Error::BadMerklePath)?;
        if !MerkleTree::verify_capped(shift_entry, &shift_row, shifted, depth, &opening.shift_path)
        {
            return Err(Error::BadMerklePath);
        }
        let expected = composition_at(
            opening.values,
            opening.next,
            lde_point_at(m, index)?,
            &public,
            params.initial,
            params.output,
            n,
            w_last,
            unit,
            &alphas,
        );
        // FRI layer-0 value at the queried (bit-reversed) position.
        let quad = query.folds.first().ok_or(Error::FriVerificationFailed)?;
        if quad.values[leaf % 4] != expected {
            return Err(Error::FriVerificationFailed);
        }
    }
    Ok(())
}

fn absorb_params(params: &Params, transcript: &mut Transcript) {
    let folds = params.folds.min(MAX_FOLDS);
    let mut buf = Vec::with_capacity(64 + 16 * folds);
    for value in [
        params.lde_len,
        params.leaf,
        params.folds,
        params.blowup,
        params.num_queries,
        params.final_size,
    ] {
        buf.extend_from_slice(&(value as u64).to_le_bytes());
    }
    buf.extend_from_slice(&params.grinding_bits.to_le_bytes());
    buf.extend_from_slice(&(params.cap_height as u64).to_le_bytes());
    for challenge in &params.challenges[..folds] {
        for value in challenge {
            buf.extend_from_slice(&value.to_le_bytes());
        }
    }
    for value in &params.initial {
        buf.extend_from_slice(&value.to_le_bytes());
    }
    buf.extend_from_slice(&params.output.to_le_bytes());
    transcript.absorb(b"rec/params", &buf);
}

/// Public per-row data in coefficient form (all degree `< n`).
struct Public {
    inv: Vec<Field>,
    challenges: [Vec<Field>; 3],
    selectors: [Vec<Field>; 4],
    last: Vec<Field>,
}

/// `1/x_d` for real rows, `1` for padded ones (challenges are zero there).
fn inv_values(params: &Params) -> Result<Vec<Field>> {
    let n = params.n_rows();
    let mut values = Vec::with_capacity(n);
    for depth in 0..n {
        if depth < params.folds {
            let layer_len = params.lde_len >> (2 * depth);
            let base = (params.leaf >> (2 * depth)) & !3;
            if base + 3 >= layer_len {
                return Err(Error::IndexOutOfBounds {
                    index: params.leaf,
                    len: layer_len,
                });
            }
            values.push(fri::point_at(params.lde_len, depth, base)?.inv());
        } else {
            values.push(Field::ONE);
        }
    }
    Ok(values)
}

/// Build the public per-row polynomials (selectors use position `0` for the
/// last real row and padding; the output boundary reads that row directly).
fn public_polys(params: &Params, inv_values: &[Field]) -> Result<Public> {
    let n = params.n_rows();
    let mut challenges: [Vec<Field>; 3] = std::array::from_fn(|_| Vec::with_capacity(n));
    let mut selectors: [Vec<Field>; 4] = std::array::from_fn(|_| Vec::with_capacity(n));
    let mut last = Vec::with_capacity(n);
    for depth in 0..n {
        let active = depth < params.folds;
        for (i, values) in challenges.iter_mut().enumerate() {
            values.push(if active {
                params.challenges[depth][i]
            } else {
                Field::ZERO
            });
        }
        let selected = if depth + 1 < params.folds {
            (params.leaf >> (2 * depth + 2)) & 3
        } else {
            0
        };
        for (j, values) in selectors.iter_mut().enumerate() {
            values.push(if j == selected {
                Field::ONE
            } else {
                Field::ZERO
            });
        }
        last.push(if depth + 1 == params.folds {
            Field::ONE
        } else {
            Field::ZERO
        });
    }
    Ok(Public {
        inv: interpolate(inv_values)?,
        challenges: [
            interpolate(&challenges[0])?,
            interpolate(&challenges[1])?,
            interpolate(&challenges[2])?,
        ],
        selectors: [
            interpolate(&selectors[0])?,
            interpolate(&selectors[1])?,
            interpolate(&selectors[2])?,
            interpolate(&selectors[3])?,
        ],
        last: interpolate(&last)?,
    })
}

/// Witness rows: the opened quads, their fold outputs, and a consistent
/// padding that keeps every row-local transition identity satisfied.
fn trace_columns(params: &Params, quads: &[[Field; 4]], unit: Field) -> Result<Vec<[Field; COLS]>> {
    if quads.len() != params.folds {
        return Err(Error::MalformedInput {
            reason: "witness must hold one quad per fold",
        });
    }
    let n = params.n_rows();
    let invs = inv_values(params)?;
    let mut rows = Vec::with_capacity(n);
    let mut last = Field::ZERO;
    for (depth, quad) in quads.iter().enumerate() {
        let out = fri::fold_values(*quad, invs[depth], params.challenges[depth], unit);
        rows.push([quad[0], quad[1], quad[2], quad[3], out]);
        last = out;
    }
    while rows.len() < n {
        rows.push([last; COLS]);
    }
    Ok(rows)
}

/// Full composition vector on the trace LDE.
///
/// `offset = lde_len_trace / n_rows`; next-row values are the same committed
/// columns at index `(i + offset) mod lde_len_trace` (the `omega_n · x` point
/// in index space), never a separate witness column.
#[allow(clippy::too_many_arguments)]
fn compose(
    lde: &[Vec<Field>; COLS],
    points: &[Field],
    public: &Public,
    initial: [Field; 4],
    output: Field,
    n: usize,
    offset: usize,
    w_last: Field,
    unit: Field,
    alphas: &[Field; ALPHAS],
) -> Vec<Field> {
    let m = lde[0].len();
    let mut composition = Vec::with_capacity(m);
    for (i, &point) in points.iter().enumerate() {
        let shifted = (i + offset) % m;
        let values: [Field; COLS] = std::array::from_fn(|j| lde[j][i]);
        let next: [Field; COLS] = std::array::from_fn(|j| lde[j][shifted]);
        composition.push(composition_at(
            values, next, point, public, initial, output, n, w_last, unit, alphas,
        ));
    }
    composition
}

/// Composition value at one point: fold and chain quotients plus boundaries.
///
/// Shared verbatim by the prover ([`compose`]) and the verifier, so the
/// identity is bit-identical on both sides.
#[allow(clippy::too_many_arguments)]
fn composition_at(
    values: [Field; COLS],
    next: [Field; COLS],
    point: Field,
    public: &Public,
    initial: [Field; 4],
    output: Field,
    n: usize,
    w_last: Field,
    unit: Field,
    alphas: &[Field; ALPHAS],
) -> Field {
    let inv = evaluate(&public.inv, point);
    let challenges = [
        evaluate(&public.challenges[0], point),
        evaluate(&public.challenges[1], point),
        evaluate(&public.challenges[2], point),
    ];
    let last = evaluate(&public.last, point);
    let vanishing = point.pow(n as u64) - Field::ONE;
    let inv_vanishing = vanishing.inv();
    // Fold identity: degree `4n - 5` quotient.
    let fold = values[4]
        - fri::fold_values(
            [values[0], values[1], values[2], values[3]],
            inv,
            challenges,
            unit,
        );
    // Chain link: the next quad's selected element is this row's output.
    let mut selected = Field::ZERO;
    for (j, selector) in public.selectors.iter().enumerate() {
        selected += evaluate(selector, point) * next[j];
    }
    let chain = values[4] - selected;
    // Transition divisor `(x^n - 1)/(x - w_last)` (last base row exempt).
    let z_chain = vanishing * (point - w_last).inv();
    let inv_x1 = (point - Field::ONE).inv();
    let mut acc = alphas[0] * fold * inv_vanishing
        + alphas[1] * chain * z_chain.inv()
        + alphas[6] * last * (values[4] - output) * inv_vanishing;
    for (j, slot) in alphas[2..6].iter().enumerate() {
        acc += *slot * (values[j] - initial[j]) * inv_x1;
    }
    acc
}

/// Natural-order coset points `SHIFT * omega_m^i` (mirrors `air`).
fn lde_points(m: usize) -> Result<Vec<Field>> {
    let omega = Field::primitive_root(m)?;
    let mut points = Vec::with_capacity(m);
    let mut current = fri::LDE_SHIFT;
    for _ in 0..m {
        points.push(current);
        current *= omega;
    }
    Ok(points)
}

/// Single coset point `SHIFT * omega_m^index` without building the domain.
fn lde_point_at(m: usize, index: usize) -> Result<Field> {
    let omega = Field::primitive_root(m)?;
    Ok(fri::LDE_SHIFT * omega.pow(index as u64))
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

    /// Run a real FRI commit/open and return one query's fold data.
    fn outer_query(coeffs: &[Field]) -> (usize, usize, Vec<[Field; 4]>, Vec<[Field; 3]>, Field) {
        let fri_params = fri::Params::new(4, 3, 4).unwrap();
        let mut prover_t = Transcript::new(b"rec-outer");
        let state = fri::commit(coeffs, fri_params, &mut prover_t).unwrap();
        let commitment = fri::public_commitment(&state);
        let (proof, indices) = fri::open(&state, &mut prover_t).unwrap();
        let mut verifier_t = Transcript::new(b"rec-outer");
        fri::verify(&commitment, &proof, fri_params, &mut verifier_t).unwrap();
        let leaf = indices[0];
        let folds = proof.queries[0].folds.len();
        let quads: Vec<[Field; 4]> = proof.queries[0].folds.iter().map(|f| f.values).collect();
        let output = proof.final_poly[leaf >> (2 * folds)];
        (
            state.lde_len,
            leaf,
            quads,
            state.fold_challenges.clone(),
            output,
        )
    }

    fn test_params(
        lde_len: usize,
        leaf: usize,
        quads: &[[Field; 4]],
        challenges: &[[Field; 3]],
        output: Field,
    ) -> Params {
        // Trace length is `8 * n_rows`; the final size must keep the layer
        // ratio a power of four (`n_rows = 2^k`, so parity decides).
        let n = quads.len().next_power_of_two().max(2);
        let final_size = if n.trailing_zeros() % 2 == 0 { 2 } else { 4 };
        Params::new(
            lde_len,
            leaf,
            quads.len(),
            challenges,
            quads[0],
            output,
            8,
            8,
            final_size,
        )
        .unwrap()
    }

    fn roundtrip(params: &Params, quads: &[[Field; 4]]) -> Proof {
        let mut prover_t = Transcript::new(b"rec-inner");
        let proof = prove(*params, quads, &mut prover_t).unwrap();
        let mut verifier_t = Transcript::new(b"rec-inner");
        verify(*params, &proof, &mut verifier_t).unwrap();
        proof
    }

    #[test]
    fn rejects_bad_params() {
        let challenges = [[Field::ONE; 3]; 2];
        assert!(Params::new(64, 0, 0, &[], [Field::ONE; 4], Field::ONE, 8, 8, 4).is_err());
        assert!(Params::new(
            64,
            0,
            2,
            &challenges[..1],
            [Field::ONE; 4],
            Field::ONE,
            8,
            8,
            4
        )
        .is_err());
        assert!(Params::new(64, 64, 2, &challenges, [Field::ONE; 4], Field::ONE, 8, 8, 4).is_err());
        assert!(Params::new(8, 0, 2, &challenges, [Field::ONE; 4], Field::ONE, 8, 8, 4).is_err());
        assert!(Params::new(64, 0, 2, &challenges, [Field::ONE; 4], Field::ONE, 2, 8, 4).is_err());
        assert!(Params::new(64, 0, 2, &challenges, [Field::ONE; 4], Field::ONE, 8, 0, 4).is_err());
    }

    #[test]
    fn honest_two_fold_chain_verifies() {
        let coeffs: Vec<Field> = (0..16u32).map(|i| Field::new(i * 7 + 3)).collect();
        let (lde_len, leaf, quads, challenges, output) = outer_query(&coeffs);
        assert_eq!(quads.len(), 2);
        let params = test_params(lde_len, leaf, &quads, &challenges, output);
        roundtrip(&params, &quads);
    }

    #[test]
    fn honest_three_fold_chain_verifies_with_padding() {
        let coeffs: Vec<Field> = (0..64u32).map(|i| Field::new(i * 11 + 5)).collect();
        let (lde_len, leaf, quads, challenges, output) = outer_query(&coeffs);
        assert_eq!(quads.len(), 3);
        assert_eq!(
            test_params(lde_len, leaf, &quads, &challenges, output).n_rows(),
            4
        );
        let params = test_params(lde_len, leaf, &quads, &challenges, output);
        roundtrip(&params, &quads);
    }

    #[test]
    fn wrong_output_rejected() {
        let coeffs: Vec<Field> = (0..16u32).map(|i| Field::new(i * 7 + 3)).collect();
        let (lde_len, leaf, quads, challenges, output) = outer_query(&coeffs);
        let params = test_params(lde_len, leaf, &quads, &challenges, output + Field::ONE);
        let mut prover_t = Transcript::new(b"rec-inner");
        let proof = prove(params, &quads, &mut prover_t).unwrap();
        let mut verifier_t = Transcript::new(b"rec-inner");
        assert!(verify(params, &proof, &mut verifier_t).is_err());
    }

    #[test]
    fn broken_chain_rejected() {
        let coeffs: Vec<Field> = (0..64u32).map(|i| Field::new(i * 11 + 5)).collect();
        let (lde_len, leaf, quads, challenges, output) = outer_query(&coeffs);
        let mut quads = quads;
        let selected = (leaf >> 2) & 3;
        quads[1][selected] += Field::ONE;
        let params = test_params(lde_len, leaf, &quads, &challenges, output);
        let mut prover_t = Transcript::new(b"rec-inner");
        let proof = prove(params, &quads, &mut prover_t).unwrap();
        let mut verifier_t = Transcript::new(b"rec-inner");
        assert!(verify(params, &proof, &mut verifier_t).is_err());
    }

    #[test]
    fn tampered_opening_fails() {
        let coeffs: Vec<Field> = (0..16u32).map(|i| Field::new(i * 7 + 3)).collect();
        let (lde_len, leaf, quads, challenges, output) = outer_query(&coeffs);
        let params = test_params(lde_len, leaf, &quads, &challenges, output);
        let mut proof = roundtrip(&params, &quads);
        proof.openings[0].values[0] += Field::ONE;
        let mut verifier_t = Transcript::new(b"rec-inner");
        assert!(verify(params, &proof, &mut verifier_t).is_err());
    }

    #[test]
    fn shifted_opening_tamper_fails() {
        let coeffs: Vec<Field> = (0..16u32).map(|i| Field::new(i * 7 + 3)).collect();
        let (lde_len, leaf, quads, challenges, output) = outer_query(&coeffs);
        let params = test_params(lde_len, leaf, &quads, &challenges, output);
        for tamper in 0..4 {
            let mut proof = roundtrip(&params, &quads);
            let opening = &mut proof.openings[0];
            match tamper {
                0 => opening.next[4] += Field::ONE,
                1 => opening.next[0] += Field::ONE,
                2 => {
                    let last = opening.shift_path.len() - 1;
                    opening.shift_path[last].1 = !opening.shift_path[last].1;
                }
                _ => {
                    opening.shift_path.pop();
                }
            }
            let mut verifier_t = Transcript::new(b"rec-inner");
            assert!(
                verify(params, &proof, &mut verifier_t).is_err(),
                "tamper {tamper}"
            );
        }
    }

    #[test]
    fn capped_roundtrip() {
        let coeffs: Vec<Field> = (0..64u32).map(|i| Field::new(i * 11 + 5)).collect();
        let (lde_len, leaf, quads, challenges, output) = outer_query(&coeffs);
        let params = test_params(lde_len, leaf, &quads, &challenges, output).with_cap_height(1);
        roundtrip(&params, &quads);
    }

    #[test]
    fn encoding_roundtrip_and_rejects() {
        let coeffs: Vec<Field> = (0..16u32).map(|i| Field::new(i * 7 + 3)).collect();
        let (lde_len, leaf, quads, challenges, output) = outer_query(&coeffs);
        let params = test_params(lde_len, leaf, &quads, &challenges, output);
        let proof = roundtrip(&params, &quads);
        let bytes = proof.to_bytes();
        assert_eq!(Proof::from_bytes(&bytes).unwrap(), proof);
        assert!(Proof::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(Proof::from_bytes(&longer).is_err());
    }

    #[test]
    fn wrong_transcript_fails() {
        let coeffs: Vec<Field> = (0..16u32).map(|i| Field::new(i * 7 + 3)).collect();
        let (lde_len, leaf, quads, challenges, output) = outer_query(&coeffs);
        let params = test_params(lde_len, leaf, &quads, &challenges, output);
        let mut prover_t = Transcript::new(b"rec-A");
        let proof = prove(params, &quads, &mut prover_t).unwrap();
        let mut verifier_t = Transcript::new(b"rec-B");
        assert!(verify(params, &proof, &mut verifier_t).is_err());
    }

    #[test]
    fn statement_mismatch_fails() {
        let coeffs: Vec<Field> = (0..16u32).map(|i| Field::new(i * 7 + 3)).collect();
        let (lde_len, leaf, quads, challenges, output) = outer_query(&coeffs);
        let params = test_params(lde_len, leaf, &quads, &challenges, output);
        let proof = roundtrip(&params, &quads);
        let mut wrong_output = params;
        wrong_output.output += Field::ONE;
        let mut verifier_t = Transcript::new(b"rec-inner");
        assert!(verify(wrong_output, &proof, &mut verifier_t).is_err());
        let mut wrong_leaf = params;
        wrong_leaf.leaf ^= 1;
        let mut verifier_t = Transcript::new(b"rec-inner");
        assert!(verify(wrong_leaf, &proof, &mut verifier_t).is_err());
    }

    #[test]
    fn composition_degree_matches_bound() {
        let coeffs: Vec<Field> = (0..64u32).map(|i| Field::new(i * 11 + 5)).collect();
        let (lde_len, leaf, quads, challenges, output) = outer_query(&coeffs);
        let params = test_params(lde_len, leaf, &quads, &challenges, output);
        let n = params.n_rows();
        let unit = Field::two_adic_generator(2).unwrap();
        let rows = trace_columns(&params, &quads, unit).unwrap();
        let mut columns: [Vec<Field>; COLS] = std::array::from_fn(|_| Vec::with_capacity(n));
        for row in &rows {
            for (slot, value) in columns.iter_mut().zip(row) {
                slot.push(*value);
            }
        }
        let mut lde: [Vec<Field>; COLS] = std::array::from_fn(|_| Vec::new());
        for (slot, column) in lde.iter_mut().zip(&columns) {
            let coeffs = interpolate(column).unwrap();
            *slot = evaluate_on_coset(&coeffs, params.blowup, fri::LDE_SHIFT).unwrap();
        }
        let public = public_polys(&params, &inv_values(&params).unwrap()).unwrap();
        let points = lde_points(n * params.blowup).unwrap();
        let w_last = Field::primitive_root(n).unwrap().pow((n - 1) as u64);
        let alphas = [
            Field::new(11),
            Field::new(13),
            Field::new(17),
            Field::new(19),
            Field::new(23),
            Field::new(29),
            Field::new(31),
        ];
        let composition = compose(
            &lde,
            &points,
            &public,
            params.initial,
            params.output,
            n,
            params.blowup,
            w_last,
            unit,
            &alphas,
        );
        let coeffs = interpolate(&composition).unwrap();
        assert!(coeffs[params.composition_degree_bound() + 1..]
            .iter()
            .all(|c| *c == Field::ZERO));
    }
}
