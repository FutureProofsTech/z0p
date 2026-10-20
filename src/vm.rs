//! Minimal two-register straight-line program AIR.
//!
//! This is a first program-execution prototype, not a general zkVM. A public
//! program runs on a private initial register pair `(a, b)` and claims the
//! final pair. Each trace row applies one opcode:
//!
//! | opcode | effect |
//! |---|---|
//! | `Add` | `a <- a + b` |
//! | `Mul` | `a <- a * b` |
//! | `Swap` | swap `a` and `b` |
//! | `SetA(v)` | `a <- v` |
//! | `SetB(v)` | `b <- v` |
//! | `Halt` | leave both registers unchanged |
//!
//! Rows `0..program.len()` execute the program; shorter traces pad with
//! `Halt`; the last row is the public output claim and has no outgoing
//! transition. The verifier learns the program, the final registers, and a
//! STARK proof, but not the initial registers.
//!
//! The trace has two committed columns (`A`, `B`) over the same FRI
//! machinery as [`crate::air`]. Public one-hot selector polynomials identify
//! the opcode at every transition row, and public immediate polynomials
//! carry `SetA`/`SetB` constants. The composition is
//!
//! ```text
//! alpha0 * T / Z + alpha1 * U / Z
//!   + alpha2 * (A - a_last) / (x - w_last)
//!   + alpha3 * (B - b_last) / (x - w_last)
//! ```
//!
//! where `T` and `U` are the selector-weighted `A`/`B` transition
//! numerators and `Z = (x^n - 1)/(x - w_last)` excludes the final row.
//! Composition degree is below `2n - 1`, so this prototype requires blowup
//! `>= 8`; production parameters use blowup `16`.
//!
//! # Scope
//!
//! The initial state is an unconstrained witness: the statement is
//! knowledge of an initial pair that executes the public program to the
//! public output. Programs are straight-line and public; there is no control
//! flow, memory, or instruction privacy. [`prove`] is not hiding: FRI query
//! openings reveal trace values at queried positions. [`prove_zk`] masks both
//! trace columns with vanishing multiples from [`crate::blind`], making the
//! query responses independent of the private initial state when
//! `n_rand >= num_queries`; the program and final registers remain public.
//! This is an execution prototype, not a production zkVM, and it has not been
//! audited.

use crate::babybear::{batch_invert, Field};
use crate::codec::{Reader, Writer, MAX_QUERIES, VERSION};
use crate::error::{Error, Result};
use crate::ext4::Ext4;
use crate::fri::{self, Commitment as FriCommitment, Proof as FriProof};
use crate::merkle::MerkleTree;
use crate::ntt::{evaluate, evaluate_on_coset, interpolate};
use crate::transcript::Transcript;

/// Maximum number of program instructions in this prototype.
pub const MAX_PROGRAM: usize = 1 << 20;

const OP_ADD: u8 = 0;
const OP_MUL: u8 = 1;
const OP_SWAP: u8 = 2;
const OP_SET_A: u8 = 3;
const OP_SET_B: u8 = 4;
const OP_HALT: u8 = 5;
const OP_COUNT: usize = 6;
const ALPHAS: usize = 4;

/// One register-machine instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// `a <- a + b`.
    Add,
    /// `a <- a * b`.
    Mul,
    /// Swap the two registers.
    Swap,
    /// `a <- v`.
    SetA(Field),
    /// `b <- v`.
    SetB(Field),
    /// Leave both registers unchanged.
    Halt,
}

impl Op {
    const fn tag(self) -> u8 {
        match self {
            Self::Add => OP_ADD,
            Self::Mul => OP_MUL,
            Self::Swap => OP_SWAP,
            Self::SetA(_) => OP_SET_A,
            Self::SetB(_) => OP_SET_B,
            Self::Halt => OP_HALT,
        }
    }
}

/// Air parameters plus the public program and final register claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    /// Trace rows: power of two, `>= 2`.
    pub n_steps: usize,
    /// Trace LDE blowup: power of two, `>= 8` (composition rate `< 1/2`).
    pub blowup: usize,
    /// FRI query count (`>= 1`).
    pub num_queries: usize,
    /// FRI final layer size (power of two, `>= 1`).
    pub final_size: usize,
    /// Proof-of-work difficulty in leading-zero bits (`0` disables grinding).
    pub grinding_bits: u32,
    /// Merkle cap height for the column tree and FRI layers (`0` = roots).
    pub cap_height: usize,
    /// Public instruction sequence.
    pub program: Vec<Op>,
    /// Public final `A` register.
    pub a_last: Field,
    /// Public final `B` register.
    pub b_last: Field,
}

impl Params {
    /// Validate and construct parameters.
    ///
    /// # Errors
    /// Returns [`Error::InvalidDomainSize`], [`Error::InvalidBlowup`], or
    /// [`Error::NoQueries`] for unusable sizes, or [`Error::MalformedInput`]
    /// when the program is too long or above [`MAX_PROGRAM`].
    pub fn new(
        n_steps: usize,
        blowup: usize,
        num_queries: usize,
        final_size: usize,
        program: Vec<Op>,
        a_last: Field,
        b_last: Field,
    ) -> Result<Self> {
        let params = Self {
            n_steps,
            blowup,
            num_queries,
            final_size,
            grinding_bits: 0,
            cap_height: 0,
            program,
            a_last,
            b_last,
        };
        params.validate()?;
        Ok(params)
    }

    /// Set the proof-of-work difficulty (builder; default `0` = disabled).
    #[must_use]
    pub fn with_grinding_bits(mut self, bits: u32) -> Self {
        self.grinding_bits = bits;
        self
    }

    /// Set the Merkle cap height (builder; default `0` = roots only).
    #[must_use]
    pub fn with_cap_height(mut self, height: usize) -> Self {
        self.cap_height = height;
        self
    }

    /// Production parameters: blowup 16, strength sized for a
    /// `target_bits` query/grinding schedule, and size-optimal final layer
    /// and cap height.
    ///
    /// # Errors
    /// Same domain errors as [`Params::new`].
    pub fn for_security(
        n_steps: usize,
        program: Vec<Op>,
        a_last: Field,
        b_last: Field,
        target_bits: u32,
    ) -> Result<Self> {
        let mut params = Self {
            n_steps,
            blowup: 16,
            num_queries: 1,
            final_size: 1,
            grinding_bits: 0,
            cap_height: 0,
            program,
            a_last,
            b_last,
        };
        params.validate()?;
        let lde_len =
            params
                .n_steps
                .checked_mul(params.blowup)
                .ok_or(Error::InvalidDomainSize {
                    size: params.n_steps,
                })?;
        let degree_bound = params.n_steps.saturating_mul(2).saturating_sub(2);
        let millibits = fri::composition_millibits(lde_len, degree_bound);
        let (num_queries, grinding_bits) = fri::tune_strength(target_bits, millibits);
        let (final_size, cap_height) = fri::tune_shape(lde_len, num_queries, &[(lde_len, 24)]);
        params.num_queries = num_queries;
        params.final_size = final_size;
        params.grinding_bits = grinding_bits;
        params.cap_height = cap_height;
        params.validate()?;
        Ok(params)
    }

    /// Length of the LDE domain.
    #[must_use]
    pub const fn lde_len(&self) -> usize {
        self.n_steps.saturating_mul(self.blowup)
    }

    fn fri_params(&self) -> Result<fri::Params> {
        Ok(
            fri::Params::new(self.blowup, self.num_queries, self.final_size)?
                .with_grinding_bits(self.grinding_bits)
                .with_cap_height(self.cap_height),
        )
    }

    fn validate(&self) -> Result<()> {
        if self.n_steps < 2 || !self.n_steps.is_power_of_two() {
            return Err(Error::InvalidDomainSize { size: self.n_steps });
        }
        if self.blowup < 8 || !self.blowup.is_power_of_two() {
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
        if self.program.len() > MAX_PROGRAM {
            return Err(Error::MalformedInput {
                reason: "program above protocol cap",
            });
        }
        if self.program.len() > self.n_steps - 1 {
            return Err(Error::MalformedInput {
                reason: "program must leave a final trace row",
            });
        }
        let lde = self
            .n_steps
            .checked_mul(self.blowup)
            .ok_or(Error::InvalidDomainSize { size: self.n_steps })?;
        if lde > (1usize << Field::TWO_ADICITY) {
            return Err(Error::InvalidDomainSize { size: lde });
        }
        Ok(())
    }
}

/// One trace opening at an LDE position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceOpening {
    /// Natural-order LDE index.
    pub index: usize,
    /// First register column at `index`.
    pub a: Field,
    /// Second register column at `index`.
    pub b: Field,
    /// First register at the shifted index `index + lde_len / n_steps`.
    pub a_next: Field,
    /// Second register at the shifted index.
    pub b_next: Field,
    /// Merkle path of the joint row leaf (`A || B`) at `index`.
    pub path: Vec<([u8; 32], bool)>,
    /// Merkle path of the joint row leaf at the shifted index.
    pub shift_path: Vec<([u8; 32], bool)>,
}

/// Program-execution proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// Merkle cap of the joint row LDE.
    pub column_cap: Vec<[u8; 32]>,
    /// FRI commitment to the composition polynomial.
    pub fri_commitment: FriCommitment,
    /// FRI opening proof.
    pub fri_proof: FriProof,
    /// Trace openings, one per FRI query, in query order.
    pub openings: Vec<TraceOpening>,
}

impl Proof {
    /// Canonical bytes: version, column cap, FRI commitment/proof, openings.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.byte(VERSION);
        writer.cap(&self.column_cap);
        self.fri_commitment.write_body(&mut writer);
        self.fri_proof.write_body(&mut writer);
        writer.count(self.openings.len());
        for opening in &self.openings {
            writer.u64_le(opening.index as u64);
            writer.field(opening.a);
            writer.field(opening.b);
            writer.field(opening.a_next);
            writer.field(opening.b_next);
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
        let mut reader = Reader::new(bytes);
        reader.version()?;
        let column_cap = reader.cap()?;
        let fri_commitment = fri::Commitment::read_body(&mut reader)?;
        let fri_proof = fri::Proof::read_body(&mut reader)?;
        let mut openings = Vec::new();
        for _ in 0..reader.count(MAX_QUERIES)? {
            openings.push(TraceOpening {
                index: reader.dimension()?,
                a: reader.field()?,
                b: reader.field()?,
                a_next: reader.field()?,
                b_next: reader.field()?,
                path: reader.path()?,
                shift_path: reader.path()?,
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

/// Build the trace for `program` from a private initial register pair.
///
/// `n_steps` must be a power of two leaving at least one final row after the
/// program. Missing program slots and padding rows execute [`Op::Halt`].
///
/// # Errors
/// Returns [`Error::InvalidDomainSize`] for an unusable trace length or
/// [`Error::MalformedInput`] when the program does not fit.
pub fn build_trace(
    program: &[Op],
    a0: Field,
    b0: Field,
    n_steps: usize,
) -> Result<(Vec<Field>, Vec<Field>)> {
    if n_steps < 2 || !n_steps.is_power_of_two() {
        return Err(Error::InvalidDomainSize { size: n_steps });
    }
    if program.len() > n_steps - 1 {
        return Err(Error::MalformedInput {
            reason: "program must leave a final trace row",
        });
    }
    let mut a = vec![Field::ZERO; n_steps];
    let mut b = vec![Field::ZERO; n_steps];
    a[0] = a0;
    b[0] = b0;
    for i in 0..n_steps - 1 {
        let op = program.get(i).copied().unwrap_or(Op::Halt);
        let (next_a, next_b) = execute(op, a[i], b[i]);
        a[i + 1] = next_a;
        b[i + 1] = next_b;
    }
    Ok((a, b))
}

/// Prove execution of `params.program` from the private initial state.
///
/// This is the plain (non-hiding) path; use [`prove_zk`] to mask the trace.
///
/// # Errors
/// Returns structural trace/Merkle/FRI errors. A false output claim produces
/// a high-degree composition that [`verify`] rejects.
pub fn prove(params: &Params, a0: Field, b0: Field, transcript: &mut Transcript) -> Result<Proof> {
    params.validate()?;
    let (col_a, col_b) = build_trace(&params.program, a0, b0, params.n_steps)?;
    prove_with_trace(params, &col_a, &col_b, transcript)
}

/// Prove with explicit trace columns (expert API).
///
/// The columns need not satisfy the transition relation; proving still
/// succeeds structurally, but [`verify`] rejects invalid traces through the
/// composition/FRI check.
///
/// # Errors
/// Returns [`Error::MalformedInput`] on a column-length mismatch, otherwise
/// the structural errors of [`prove`].
pub fn prove_with_trace(
    params: &Params,
    col_a: &[Field],
    col_b: &[Field],
    transcript: &mut Transcript,
) -> Result<Proof> {
    params.validate()?;
    let n = params.n_steps;
    if col_a.len() != n || col_b.len() != n {
        return Err(Error::MalformedInput {
            reason: "trace columns must match n_steps",
        });
    }
    let coeff_a = interpolate(col_a)?;
    let coeff_b = interpolate(col_b)?;
    prove_from_coeffs(params, &coeff_a, &coeff_b, 2 * n - 2, transcript)
}

/// Prove zero-knowledge: mask both trace columns with
/// [`crate::blind::mask_coeffs`] (`n_rand` maskers each) before committing.
///
/// Masking preserves every base-row value, so the same [`verify`] checks the
/// same transition and boundary identities. `n_rand >= num_queries` makes the
/// query responses jointly uniform and independent of the private initial
/// state. The program and final registers remain public.
///
/// `params.final_size` must be chosen for the masked LDE (its length is
/// `n_steps + n_rand` rounded up to a power of two, times `blowup`), not for
/// the plain domain; [`Params::for_security`] sizes the plain path only.
///
/// # Errors
/// Returns [`Error::MalformedInput`] when `n_rand < num_queries`, otherwise
/// the structural errors of [`prove`], including an incompatible final layer.
pub fn prove_zk(
    params: &Params,
    a0: Field,
    b0: Field,
    n_rand: usize,
    rng: &mut crate::rng::ChaCha20,
    transcript: &mut Transcript,
) -> Result<Proof> {
    params.validate()?;
    let (col_a, col_b) = build_trace(&params.program, a0, b0, params.n_steps)?;
    prove_zk_with_trace(params, &col_a, &col_b, n_rand, rng, transcript)
}

/// Zero-knowledge variant of [`prove_with_trace`] (expert API).
///
/// The columns need not satisfy the transition relation; verification still
/// rejects invalid traces. The columns are masked as in [`prove_zk`].
///
/// # Errors
/// Returns [`Error::MalformedInput`] on a column-length mismatch or
/// `n_rand < num_queries`, otherwise the structural errors of [`prove`].
pub fn prove_zk_with_trace(
    params: &Params,
    col_a: &[Field],
    col_b: &[Field],
    n_rand: usize,
    rng: &mut crate::rng::ChaCha20,
    transcript: &mut Transcript,
) -> Result<Proof> {
    params.validate()?;
    if n_rand < params.num_queries {
        return Err(Error::MalformedInput {
            reason: "n_rand must cover num_queries for hiding",
        });
    }
    let n = params.n_steps;
    if col_a.len() != n || col_b.len() != n {
        return Err(Error::MalformedInput {
            reason: "trace columns must match n_steps",
        });
    }
    let coeff_a = interpolate(col_a)?;
    let coeff_b = interpolate(col_b)?;
    let masked_a = crate::blind::mask_coeffs(&coeff_a, n, n_rand, rng)?;
    let masked_b = crate::blind::mask_coeffs(&coeff_b, n, n_rand, rng)?;
    let degree_bound = n
        .checked_add(n_rand)
        .and_then(|total| total.checked_sub(1))
        .ok_or(Error::InvalidDomainSize { size: n })?;
    prove_from_coeffs(params, &masked_a, &masked_b, degree_bound, transcript)
}

fn prove_from_coeffs(
    params: &Params,
    coeff_a: &[Field],
    coeff_b: &[Field],
    degree_bound: usize,
    transcript: &mut Transcript,
) -> Result<Proof> {
    let n = params.n_steps;
    if coeff_a.len() != coeff_b.len() {
        return Err(Error::MalformedInput {
            reason: "trace columns must have the same length",
        });
    }
    absorb_params(params, transcript);

    let omega_base = Field::primitive_root(n)?;
    let lde_cols = [
        evaluate_on_coset(coeff_a, params.blowup, crate::fri::LDE_SHIFT)?,
        evaluate_on_coset(coeff_b, params.blowup, crate::fri::LDE_SHIFT)?,
    ];
    let m = lde_cols[0].len();
    if m % n != 0 {
        return Err(Error::MalformedInput {
            reason: "LDE length must be a multiple of n_steps",
        });
    }
    let offset = m / n;
    let row_len = 4 * lde_cols.len();
    let mut flat = vec![0u8; m * row_len];
    for (i, chunk) in flat.chunks_exact_mut(row_len).enumerate() {
        for (lde, slot) in lde_cols.iter().zip(chunk.chunks_exact_mut(4)) {
            slot.copy_from_slice(&lde[i].to_le_bytes());
        }
    }
    let tree = MerkleTree::from_flat(&flat, row_len)?;
    let (drop, _) = crate::merkle::capped_shape(m, params.cap_height);
    let column_cap = tree.cap(drop);
    transcript.absorb(b"vm/trace", &crate::merkle::cap_bytes(&column_cap));

    let alphas = [
        transcript.challenge_ext(b"vm/alpha"),
        transcript.challenge_ext(b"vm/alpha"),
        transcript.challenge_ext(b"vm/alpha"),
        transcript.challenge_ext(b"vm/alpha"),
    ];

    let polys = program_polys(&params.program, n)?;
    let coeff_len = coeff_a.len();
    let mut selectors = Vec::with_capacity(OP_COUNT);
    for selector in &polys.selectors {
        let mut extended = selector.clone();
        extended.resize(coeff_len, Field::ZERO);
        selectors.push(evaluate_on_coset(
            &extended,
            params.blowup,
            crate::fri::LDE_SHIFT,
        )?);
    }
    let mut imm = polys.imm_a.clone();
    imm.resize(coeff_len, Field::ZERO);
    let imm_a = evaluate_on_coset(&imm, params.blowup, crate::fri::LDE_SHIFT)?;
    let mut imm = polys.imm_b.clone();
    imm.resize(coeff_len, Field::ZERO);
    let imm_b = evaluate_on_coset(&imm, params.blowup, crate::fri::LDE_SHIFT)?;
    let points = lde_points(m)?;
    let w_last = omega_base.pow((n - 1) as u64);
    let composition = compose(
        &lde_cols,
        &selectors,
        &imm_a,
        &imm_b,
        &points,
        w_last,
        params.a_last,
        params.b_last,
        n,
        offset,
        &alphas,
    );

    let fri_state =
        fri::commit_ext_evals(&composition, degree_bound, params.fri_params()?, transcript)?;
    let fri_commitment = fri::public_commitment(&fri_state);
    let (fri_proof, fri_indices) = fri::open(&fri_state, transcript)?;

    let log_m = m.trailing_zeros();
    let mut openings = Vec::with_capacity(params.num_queries);
    for &leaf in &fri_indices {
        let index = bit_reverse_index(leaf, log_m);
        let shifted = (index + offset) % m;
        openings.push(TraceOpening {
            index,
            a: lde_cols[0][index],
            b: lde_cols[1][index],
            a_next: lde_cols[0][shifted],
            b_next: lde_cols[1][shifted],
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

/// Verify a program-execution proof.
///
/// # Errors
/// Returns [`Error::FriVerificationFailed`] or [`Error::BadMerklePath`] on
/// any failed check.
#[allow(clippy::too_many_lines)]
pub fn verify(params: &Params, proof: &Proof, transcript: &mut Transcript) -> Result<()> {
    params.validate()?;
    let n = params.n_steps;
    let m = proof.fri_commitment.lde_len;
    let expected_m = n
        .checked_mul(params.blowup)
        .ok_or(Error::FriVerificationFailed)?;
    if m < expected_m || m % expected_m != 0 {
        return Err(Error::FriVerificationFailed);
    }
    let degree_bound = proof.fri_commitment.degree_bound;
    if m == expected_m {
        if degree_bound != 2 * n - 2 {
            return Err(Error::FriVerificationFailed);
        }
    } else if degree_bound >= m / params.blowup {
        return Err(Error::FriVerificationFailed);
    }
    if proof.fri_commitment.poly_len != m {
        return Err(Error::FriVerificationFailed);
    }
    let offset = m / n;
    absorb_params(params, transcript);
    if proof.openings.len() != params.num_queries {
        return Err(Error::FriVerificationFailed);
    }
    transcript.absorb(b"vm/trace", &crate::merkle::cap_bytes(&proof.column_cap));
    let alphas = [
        transcript.challenge_ext(b"vm/alpha"),
        transcript.challenge_ext(b"vm/alpha"),
        transcript.challenge_ext(b"vm/alpha"),
        transcript.challenge_ext(b"vm/alpha"),
    ];

    let fri_indices = fri::verify(
        &proof.fri_commitment,
        &proof.fri_proof,
        params.fri_params()?,
        transcript,
    )?;

    let omega_base = Field::primitive_root(n)?;
    let w_last = omega_base.pow((n - 1) as u64);
    let polys = program_polys(&params.program, n)?;
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
        let (drop, depth) = crate::merkle::capped_shape(m, params.cap_height);
        if proof.column_cap.len() != 1usize << drop
            || opening.path.len() != depth - drop
            || opening.shift_path.len() != depth - drop
        {
            return Err(Error::BadMerklePath);
        }
        let mut row = [0u8; 8];
        row[..4].copy_from_slice(&opening.a.to_le_bytes());
        row[4..].copy_from_slice(&opening.b.to_le_bytes());
        let entry = proof
            .column_cap
            .get(index >> (depth - drop))
            .ok_or(Error::BadMerklePath)?;
        if !MerkleTree::verify_capped(entry, &row, index, depth, &opening.path) {
            return Err(Error::BadMerklePath);
        }
        let shifted = (index + offset) % m;
        let mut shift_row = [0u8; 8];
        shift_row[..4].copy_from_slice(&opening.a_next.to_le_bytes());
        shift_row[4..].copy_from_slice(&opening.b_next.to_le_bytes());
        let shift_entry = proof
            .column_cap
            .get(shifted >> (depth - drop))
            .ok_or(Error::BadMerklePath)?;
        if !MerkleTree::verify_capped(shift_entry, &shift_row, shifted, depth, &opening.shift_path)
        {
            return Err(Error::BadMerklePath);
        }
        let expected = composition_at(
            [opening.a, opening.b],
            [opening.a_next, opening.b_next],
            lde_point_at(m, index)?,
            w_last,
            params.a_last,
            params.b_last,
            n,
            &alphas,
            &polys,
        );
        let quad = query.folds.first().ok_or(Error::FriVerificationFailed)?;
        if quad.values[leaf % 4] != expected {
            return Err(Error::FriVerificationFailed);
        }
    }
    Ok(())
}

struct ProgramPolys {
    selectors: Vec<Vec<Field>>,
    imm_a: Vec<Field>,
    imm_b: Vec<Field>,
}

fn program_polys(program: &[Op], n: usize) -> Result<ProgramPolys> {
    let mut selectors = vec![vec![Field::ZERO; n]; OP_COUNT];
    let mut imm_a = vec![Field::ZERO; n];
    let mut imm_b = vec![Field::ZERO; n];
    for i in 0..n - 1 {
        let op = program.get(i).copied().unwrap_or(Op::Halt);
        selectors[usize::from(op.tag())][i] = Field::ONE;
        if let Op::SetA(value) = op {
            imm_a[i] = value;
        }
        if let Op::SetB(value) = op {
            imm_b[i] = value;
        }
    }
    let mut selector_coeffs = Vec::with_capacity(OP_COUNT);
    for selector in &selectors {
        selector_coeffs.push(interpolate(selector)?);
    }
    Ok(ProgramPolys {
        selectors: selector_coeffs,
        imm_a: interpolate(&imm_a)?,
        imm_b: interpolate(&imm_b)?,
    })
}

fn execute(op: Op, a: Field, b: Field) -> (Field, Field) {
    match op {
        Op::Add => (a + b, b),
        Op::Mul => (a * b, b),
        Op::Swap => (b, a),
        Op::SetA(value) => (value, b),
        Op::SetB(value) => (a, value),
        Op::Halt => (a, b),
    }
}

fn expr_values(tag: usize, a: Field, b: Field, imm_a: Field, imm_b: Field) -> (Field, Field) {
    const ADD: usize = OP_ADD as usize;
    const MUL: usize = OP_MUL as usize;
    const SWAP: usize = OP_SWAP as usize;
    const SET_A: usize = OP_SET_A as usize;
    const SET_B: usize = OP_SET_B as usize;
    match tag {
        ADD => (a + b, b),
        MUL => (a * b, b),
        SWAP => (b, a),
        SET_A => (imm_a, b),
        SET_B => (a, imm_b),
        _ => (a, b),
    }
}

#[allow(clippy::many_single_char_names, clippy::too_many_arguments)]
fn compose(
    cols: &[Vec<Field>; 2],
    selectors: &[Vec<Field>],
    imm_a: &[Field],
    imm_b: &[Field],
    points: &[Field],
    w_last: Field,
    a_last: Field,
    b_last: Field,
    n: usize,
    offset: usize,
    alphas: &[Ext4; ALPHAS],
) -> Vec<Ext4> {
    let m = points.len();
    let shifted = |j: usize, i: usize| cols[j][(i + offset) % m];
    let mut den_a = Vec::with_capacity(m);
    let mut vanishing = Vec::with_capacity(m);
    for &point in points {
        den_a.push(point - w_last);
        vanishing.push(point.pow(n as u64) - Field::ONE);
    }
    let inv_a = batch_invert(&den_a);
    let mut z_trans = Vec::with_capacity(m);
    for i in 0..m {
        z_trans.push(vanishing[i] * inv_a[i]);
    }
    let inv_z = batch_invert(&z_trans);

    let mut out = vec![Ext4::ZERO; m];
    crate::par::for_each_indexed(&mut out, 2048, |base, piece| {
        for (j, slot) in piece.iter_mut().enumerate() {
            let i = base + j;
            let a = cols[0][i];
            let b = cols[1][i];
            let a_next = shifted(0, i);
            let b_next = shifted(1, i);
            let mut trans_a = Field::ZERO;
            let mut trans_b = Field::ZERO;
            for (tag, selector_values) in selectors.iter().enumerate() {
                let selector = selector_values[i];
                if selector == Field::ZERO {
                    continue;
                }
                let (expr_a, expr_b) = expr_values(tag, a, b, imm_a[i], imm_b[i]);
                trans_a += selector * (a_next - expr_a);
                trans_b += selector * (b_next - expr_b);
            }
            let bound_a = (a - a_last) * inv_a[i];
            let bound_b = (b - b_last) * inv_a[i];
            *slot = alphas[0].mul_base(trans_a * inv_z[i])
                + alphas[1].mul_base(trans_b * inv_z[i])
                + alphas[2].mul_base(bound_a)
                + alphas[3].mul_base(bound_b);
        }
    });
    out
}

#[allow(clippy::too_many_arguments)]
fn composition_at(
    cols: [Field; 2],
    next: [Field; 2],
    point: Field,
    w_last: Field,
    a_last: Field,
    b_last: Field,
    n: usize,
    alphas: &[Ext4; ALPHAS],
    polys: &ProgramPolys,
) -> Ext4 {
    let imm_a = evaluate(&polys.imm_a, point);
    let imm_b = evaluate(&polys.imm_b, point);
    let mut trans_a = Field::ZERO;
    let mut trans_b = Field::ZERO;
    for (tag, selector_poly) in polys.selectors.iter().enumerate() {
        let selector = evaluate(selector_poly, point);
        if selector == Field::ZERO {
            continue;
        }
        let (expr_a, expr_b) = expr_values(tag, cols[0], cols[1], imm_a, imm_b);
        trans_a += selector * (next[0] - expr_a);
        trans_b += selector * (next[1] - expr_b);
    }
    let inv_a = (point - w_last).inv();
    let z_trans = (point.pow(n as u64) - Field::ONE) * inv_a;
    let inv_z = z_trans.inv();
    let bound_a = (cols[0] - a_last) * inv_a;
    let bound_b = (cols[1] - b_last) * inv_a;
    alphas[0].mul_base(trans_a * inv_z)
        + alphas[1].mul_base(trans_b * inv_z)
        + alphas[2].mul_base(bound_a)
        + alphas[3].mul_base(bound_b)
}

fn absorb_params(params: &Params, transcript: &mut Transcript) {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(params.n_steps as u64).to_le_bytes());
    buf.extend_from_slice(&(params.blowup as u64).to_le_bytes());
    buf.extend_from_slice(&(params.num_queries as u64).to_le_bytes());
    buf.extend_from_slice(&(params.final_size as u64).to_le_bytes());
    buf.extend_from_slice(&params.grinding_bits.to_le_bytes());
    buf.extend_from_slice(&(params.cap_height as u64).to_le_bytes());
    buf.extend_from_slice(&(params.program.len() as u64).to_le_bytes());
    for op in &params.program {
        buf.push(op.tag());
        if let Op::SetA(value) | Op::SetB(value) = op {
            buf.extend_from_slice(&value.to_le_bytes());
        }
    }
    buf.extend_from_slice(&params.a_last.to_le_bytes());
    buf.extend_from_slice(&params.b_last.to_le_bytes());
    transcript.absorb(b"vm/params", &buf);
}

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

fn lde_point_at(m: usize, index: usize) -> Result<Field> {
    let omega = Field::primitive_root(m)?;
    Ok(crate::fri::LDE_SHIFT * omega.pow(index as u64))
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

    fn program() -> Vec<Op> {
        vec![
            Op::SetA(Field::new(2)),
            Op::SetB(Field::new(3)),
            Op::Add,
            Op::Mul,
            Op::Swap,
            Op::Halt,
        ]
    }

    fn params() -> Params {
        Params::new(16, 8, 2, 2, program(), Field::new(3), Field::new(15))
            .unwrap()
            .with_cap_height(1)
    }

    fn sample() -> (Params, Proof) {
        let params = params();
        let mut prover = Transcript::new(b"vm-test");
        let proof = prove(&params, Field::new(10), Field::new(20), &mut prover).unwrap();
        (params, proof)
    }

    fn zk_params() -> Params {
        Params::new(16, 8, 2, 4, program(), Field::new(3), Field::new(15))
            .unwrap()
            .with_cap_height(1)
    }

    fn zk_rng() -> crate::rng::ChaCha20 {
        crate::rng::ChaCha20::new([7u8; 32], [3u8; 12])
    }

    #[test]
    fn honest_execution_verifies() {
        let (params, proof) = sample();
        let mut verifier = Transcript::new(b"vm-test");
        verify(&params, &proof, &mut verifier).unwrap();
    }

    #[test]
    fn immediates_and_swap_execute() {
        let program = vec![
            Op::SetA(Field::new(7)),
            Op::SetB(Field::new(9)),
            Op::Add,
            Op::Swap,
            Op::Halt,
        ];
        let params = Params::new(8, 8, 2, 4, program, Field::new(9), Field::new(16))
            .unwrap()
            .with_cap_height(1);
        let mut prover = Transcript::new(b"vm-immediate");
        let proof = prove(&params, Field::new(1), Field::new(2), &mut prover).unwrap();
        let mut verifier = Transcript::new(b"vm-immediate");
        verify(&params, &proof, &mut verifier).unwrap();
    }

    #[test]
    fn zk_execution_verifies() {
        let params = zk_params();
        let mut prover = Transcript::new(b"vm-zk");
        let proof = prove_zk(
            &params,
            Field::new(10),
            Field::new(20),
            8,
            &mut zk_rng(),
            &mut prover,
        )
        .unwrap();
        let mut verifier = Transcript::new(b"vm-zk");
        verify(&params, &proof, &mut verifier).unwrap();
    }

    #[test]
    fn zk_openings_differ_from_plain() {
        let (_, plain) = sample();
        let params = zk_params();
        let mut prover = Transcript::new(b"vm-test");
        let blinded = prove_zk(
            &params,
            Field::new(10),
            Field::new(20),
            8,
            &mut zk_rng(),
            &mut prover,
        )
        .unwrap();
        assert_ne!(plain.column_cap, blinded.column_cap);
        assert_ne!(plain.fri_commitment, blinded.fri_commitment);
    }

    #[test]
    fn zk_is_deterministic() {
        let params = zk_params();
        let mut first = Transcript::new(b"vm-zk-deterministic");
        let a = prove_zk(
            &params,
            Field::new(10),
            Field::new(20),
            8,
            &mut zk_rng(),
            &mut first,
        )
        .unwrap();
        let mut second = Transcript::new(b"vm-zk-deterministic");
        let b = prove_zk(
            &params,
            Field::new(10),
            Field::new(20),
            8,
            &mut zk_rng(),
            &mut second,
        )
        .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn zk_rejects_few_maskers() {
        let params = zk_params();
        let mut prover = Transcript::new(b"vm-zk-few");
        assert!(prove_zk(
            &params,
            Field::new(10),
            Field::new(20),
            params.num_queries - 1,
            &mut zk_rng(),
            &mut prover,
        )
        .is_err());
    }

    #[test]
    fn zk_tampered_opening_fails() {
        let params = zk_params();
        let mut prover = Transcript::new(b"vm-zk-tamper");
        let mut proof = prove_zk(
            &params,
            Field::new(10),
            Field::new(20),
            8,
            &mut zk_rng(),
            &mut prover,
        )
        .unwrap();
        proof.openings[0].a += Field::ONE;
        let mut verifier = Transcript::new(b"vm-zk-tamper");
        assert!(verify(&params, &proof, &mut verifier).is_err());
    }

    #[test]
    fn wrong_output_rejected() {
        let (mut params, proof) = sample();
        params.a_last = Field::new(4);
        let mut verifier = Transcript::new(b"vm-test");
        assert!(verify(&params, &proof, &mut verifier).is_err());
    }

    #[test]
    fn tampered_trace_rejected() {
        let params = params();
        let (mut a, b) = build_trace(
            &params.program,
            Field::new(10),
            Field::new(20),
            params.n_steps,
        )
        .unwrap();
        a[5] += Field::ONE;
        let mut prover = Transcript::new(b"vm-bad-trace");
        let proof = prove_with_trace(&params, &a, &b, &mut prover).unwrap();
        let mut verifier = Transcript::new(b"vm-bad-trace");
        assert!(verify(&params, &proof, &mut verifier).is_err());
    }

    #[test]
    fn different_program_rejected() {
        let (params, proof) = sample();
        let mut other = params.clone();
        other.program[2] = Op::Swap;
        let mut verifier = Transcript::new(b"vm-test");
        assert!(verify(&other, &proof, &mut verifier).is_err());
    }

    #[test]
    fn program_must_leave_final_row() {
        assert!(Params::new(4, 8, 1, 2, vec![Op::Halt; 4], Field::ZERO, Field::ZERO).is_err());
        assert!(Params::new(4, 8, 1, 2, vec![Op::Halt; 3], Field::ZERO, Field::ZERO).is_ok());
    }

    #[test]
    fn build_trace_checks_length() {
        assert!(build_trace(&[], Field::ZERO, Field::ZERO, 0).is_err());
        assert!(build_trace(&[Op::Halt; 3], Field::ZERO, Field::ZERO, 2).is_err());
    }

    #[test]
    fn production_params_verify() {
        let program = vec![
            Op::SetA(Field::new(3)),
            Op::SetB(Field::new(5)),
            Op::Mul,
            Op::Swap,
            Op::Add,
            Op::Halt,
        ];
        let (a, b) = build_trace(&program, Field::ONE, Field::ONE, 16).unwrap();
        let params = Params::for_security(16, program, a[15], b[15], 18).unwrap();
        let mut prover = Transcript::new(b"vm-production");
        let proof = prove(&params, Field::ONE, Field::ONE, &mut prover).unwrap();
        let mut verifier = Transcript::new(b"vm-production");
        verify(&params, &proof, &mut verifier).unwrap();
    }

    #[test]
    fn encoding_roundtrip_and_rejects() {
        let (_, proof) = sample();
        let bytes = proof.to_bytes();
        assert_eq!(Proof::from_bytes(&bytes).unwrap(), proof);
        assert!(Proof::from_bytes(&[]).is_err());
        assert!(Proof::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(Proof::from_bytes(&trailing).is_err());
        let mut version = bytes;
        version[0] = VERSION.wrapping_add(1);
        assert!(Proof::from_bytes(&version).is_err());
    }
}
