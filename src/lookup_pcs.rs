//! Committed `LogUp` table lookup over compact `BaseFold` openings.
//!
//! This is the committed-input companion to [`crate::lookup`]. The witness,
//! table, multiplicities, and quotient columns are committed with
//! [`crate::basefold`]; the verifier checks four sumchecks and binds every
//! final oracle value with a `BaseFold` point opening. Neither the witness nor
//! the table is sent in clear.
//!
//! For padded witness `w[0..W]` and table `t[0..T]`, the prover chooses
//! multiplicities `m` with `sum(m) = W` and shows
//!
//! ```text
//! sum_i 1/(beta + w_i) = sum_j m_j/(beta + t_j)
//! ```
//!
//! together with the read-checks `q_w*(beta + w) = 1` and
//! `q_t*(beta + t) = m`. The total-weight condition is folded into the
//! `sum-t` sumcheck with a fresh transcript challenge `gamma`:
//! `sum(q_t + gamma*m) = sum_w + gamma*W`. A witness value absent from the
//! table produces a pole mismatch, rejected by the random `beta` with
//! overwhelming probability over [`Ext4`].
//!
//! Padded slots repeat the last input value. The table padding receives zero
//! multiplicity, so the lookup statement is membership of the padded
//! witness, not just its original prefix.
//!
//! # Privacy
//! Commitments hide the columns from the wire, but this is not
//! zero-knowledge: `BaseFold` has no hiding layer, candidate inputs can be
//! tested against the commitments, and sumcheck round values are revealed.
//! Use [`crate::blind`] for hiding STARK traces; a hiding PCS and a
//! zero-knowledge sumcheck remain required for private tables.
//!
//! # Transcript
//! [`prove`] and [`verify`] absorb the five commitments, `beta`, `sum_w`,
//! all sumcheck rounds, `gamma`, and the eight `BaseFold` opening statements in
//! a fixed order. Callers must start both sides from the same unique
//! transcript context.

use crate::babybear::Field;
use crate::basefold;
use crate::codec::{Reader, Writer, VERSION};
use crate::error::{Error, Result};
use crate::ext4::Ext4;
use crate::mle::Mle;
use crate::sumcheck::{self, Proof as ScProof, Term};
use crate::transcript::Transcript;

/// Number of `BaseFold` openings in a committed lookup proof.
pub const NUM_OPENINGS: usize = 8;

/// Maximum encoded size of one nested sumcheck or `BaseFold` proof.
const MAX_NESTED_BYTES: u32 = 1 << 27;
/// Maximum encoded size of one nested commitment.
const MAX_COMMITMENT_BYTES: u32 = 1_024;
/// Maximum decoded opening list (shape checks demand [`NUM_OPENINGS`]).
const MAX_OPENINGS: u32 = 16;

/// Commitments to the five committed lookup columns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitments {
    /// Padded witness column.
    pub witness: basefold::Commitment,
    /// Padded table column.
    pub table: basefold::Commitment,
    /// Multiplicity column (`sum(m) = padded witness length`).
    pub multiplicities: basefold::Commitment,
    /// Witness quotient column `1/(beta + w)`.
    pub quot_w: basefold::Commitment,
    /// Table quotient column `m/(beta + t)`.
    pub quot_t: basefold::Commitment,
}

impl Commitments {
    /// Canonical bytes: version, then the five length-prefixed commitments.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.byte(VERSION);
        for commitment in [
            &self.witness,
            &self.table,
            &self.multiplicities,
            &self.quot_w,
            &self.quot_t,
        ] {
            let bytes = commitment.to_bytes();
            writer.count(bytes.len());
            writer.bytes(&bytes);
        }
        writer.finish()
    }

    /// Decode [`Commitments::to_bytes`] output, rejecting anything else.
    ///
    /// # Errors
    /// Returns [`Error::MalformedInput`] on any encoding violation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        reader.version()?;
        let witness = read_commitment(&mut reader)?;
        let table = read_commitment(&mut reader)?;
        let multiplicities = read_commitment(&mut reader)?;
        let quot_w = read_commitment(&mut reader)?;
        let quot_t = read_commitment(&mut reader)?;
        reader.end()?;
        Ok(Self {
            witness,
            table,
            multiplicities,
            quot_w,
            quot_t,
        })
    }

    fn absorb_prefix(&self, transcript: &mut Transcript) {
        absorb_prefix(transcript, &self.witness, &self.table, &self.multiplicities);
    }

    fn absorb_quotients(&self, transcript: &mut Transcript) {
        let mut writer = Writer::new();
        for commitment in [&self.quot_w, &self.quot_t] {
            writer.bytes(&commitment.to_bytes());
        }
        transcript.absorb(b"lookup-pcs/quotients", &writer.finish());
    }
}

/// Committed lookup proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// Rational-identity challenge.
    pub beta: Ext4,
    /// Claimed witness-side rational sum.
    pub sum_w: Ext4,
    /// Sumcheck: `sum quot_w == sum_w`.
    pub sc_sum_w: ScProof,
    /// Sumcheck: read-check `quot_w * (beta + w) = 1`.
    pub sc_read_w: ScProof,
    /// Sumcheck: `sum(quot_t + gamma*multiplicities) == sum_w + gamma*W`.
    pub sc_sum_t: ScProof,
    /// Sumcheck: read-check `quot_t * (beta + t) = multiplicities`.
    pub sc_read_t: ScProof,
    /// `BaseFold` openings, in the fixed order documented by [`NUM_OPENINGS`].
    ///
    /// `0` `quot_w` at the sum-w point, `1` `quot_w` at the read-w point,
    /// `2` witness at the read-w point, `3` `quot_t` at the sum-t point,
    /// `4` multiplicities at the sum-t point, `5` `quot_t` at the read-t
    /// point, `6` table at the read-t point, `7` multiplicities at the
    /// read-t point.
    pub openings: Vec<basefold::Proof>,
}

impl Proof {
    /// Canonical bytes: version, challenge, sum, nested sumchecks, openings.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.byte(VERSION);
        writer.ext4(self.beta);
        writer.ext4(self.sum_w);
        for proof in [
            &self.sc_sum_w,
            &self.sc_read_w,
            &self.sc_sum_t,
            &self.sc_read_t,
        ] {
            let bytes = proof.to_bytes();
            writer.count(bytes.len());
            writer.bytes(&bytes);
        }
        writer.count(self.openings.len());
        for opening in &self.openings {
            let bytes = opening.to_bytes();
            writer.count(bytes.len());
            writer.bytes(&bytes);
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
        let beta = reader.ext4()?;
        let sum_w = reader.ext4()?;
        let sc_sum_w = read_sc_proof(&mut reader)?;
        let sc_read_w = read_sc_proof(&mut reader)?;
        let sc_sum_t = read_sc_proof(&mut reader)?;
        let sc_read_t = read_sc_proof(&mut reader)?;
        let mut openings = Vec::new();
        for _ in 0..reader.count(MAX_OPENINGS)? {
            let len = reader.count(MAX_NESTED_BYTES)?;
            openings.push(basefold::Proof::from_bytes(reader.take_bytes(len)?)?);
        }
        reader.end()?;
        Ok(Self {
            beta,
            sum_w,
            sc_sum_w,
            sc_read_w,
            sc_sum_t,
            sc_read_t,
            openings,
        })
    }
}

fn read_commitment(reader: &mut Reader<'_>) -> Result<basefold::Commitment> {
    let len = reader.count(MAX_COMMITMENT_BYTES)?;
    basefold::Commitment::from_bytes(reader.take_bytes(len)?)
}

fn read_sc_proof(reader: &mut Reader<'_>) -> Result<ScProof> {
    let len = reader.count(MAX_NESTED_BYTES)?;
    ScProof::from_bytes(reader.take_bytes(len)?)
}

/// Prove that every padded witness value appears in the padded table.
///
/// Both inputs are padded internally to a power of two of at least two
/// elements by repeating the last value. Table slots outside the original
/// table receive zero multiplicity.
///
/// # Errors
/// Returns [`Error::EmptyInput`] for empty inputs,
/// [`Error::MalformedInput`] when a witness value has no table match or a
/// sampled challenge hits a pole, and propagates BaseFold/sumcheck errors.
#[allow(clippy::too_many_lines)]
pub fn prove(
    witness: &[Field],
    table: &[Field],
    params: basefold::Params,
    transcript: &mut Transcript,
) -> Result<(Commitments, Proof)> {
    if witness.is_empty() || table.is_empty() {
        return Err(Error::EmptyInput);
    }
    params.validate()?;

    let w_pad = pad_inputs(witness);
    let t_pad = pad_inputs(table);
    let multiplicity_evals = multiplicities(&w_pad, table, t_pad.len())?;
    let w_evals: Vec<Ext4> = w_pad.iter().copied().map(Ext4::from_base).collect();
    let t_evals: Vec<Ext4> = t_pad.iter().copied().map(Ext4::from_base).collect();

    let witness_state = basefold::commit_evals_ext(&w_evals, params.blowup)?;
    let table_state = basefold::commit_evals_ext(&t_evals, params.blowup)?;
    let multiplicity_state = basefold::commit_evals_ext(&multiplicity_evals, params.blowup)?;
    absorb_prefix(
        transcript,
        witness_state.commitment(),
        table_state.commitment(),
        multiplicity_state.commitment(),
    );

    let beta = transcript.challenge_ext(b"lookup-pcs/beta");
    if w_evals.iter().any(|&w| beta + w == Ext4::ZERO)
        || t_evals.iter().any(|&t| beta + t == Ext4::ZERO)
    {
        return Err(Error::MalformedInput {
            reason: "lookup challenge hit a pole",
        });
    }
    transcript.absorb_ext(b"lookup-pcs/beta", beta);

    let quot_w: Vec<Ext4> = w_evals.iter().map(|&w| (beta + w).inv()).collect();
    let quot_t: Vec<Ext4> = t_evals
        .iter()
        .zip(&multiplicity_evals)
        .map(|(&t, &m)| m * (beta + t).inv())
        .collect();
    let witness_quotient_state = basefold::commit_evals_ext(&quot_w, params.blowup)?;
    let table_quotient_state = basefold::commit_evals_ext(&quot_t, params.blowup)?;
    let commitments = Commitments {
        witness: witness_state.commitment().clone(),
        table: table_state.commitment().clone(),
        multiplicities: multiplicity_state.commitment().clone(),
        quot_w: witness_quotient_state.commitment().clone(),
        quot_t: table_quotient_state.commitment().clone(),
    };
    commitments.absorb_quotients(transcript);

    let sum_w = sum(&quot_w);
    transcript.absorb_ext(b"lookup-pcs/sum-w", sum_w);

    let n_w =
        usize::try_from(w_evals.len().trailing_zeros()).map_err(|_| Error::InvalidDomainSize {
            size: w_evals.len(),
        })?;
    let n_t =
        usize::try_from(t_evals.len().trailing_zeros()).map_err(|_| Error::InvalidDomainSize {
            size: t_evals.len(),
        })?;

    // A: sum quot_w = sum_w.
    transcript.absorb(b"lookup-pcs/ctx", b"sum-w");
    let terms_sum = [Term::new(Ext4::ONE, vec![0])];
    let mut replay = transcript.clone();
    let sc_sum_w = sumcheck::prove(&[Mle::new(quot_w.clone())?], &terms_sum, transcript)?;
    let r_sum_w = sumcheck::verify_final(n_w, 1, &terms_sum, &sc_sum_w, &mut replay)?;
    if sc_sum_w.sum != sum_w {
        return Err(Error::MalformedInput {
            reason: "sum-w claim mismatch",
        });
    }

    // B: random-equality read-check quot_w * (beta + w) = 1.
    transcript.absorb(b"lookup-pcs/ctx", b"read-w");
    let r1 = sample_point(transcript, b"lookup-pcs/r1", n_w);
    let eq_w = Mle::eq_evals(&r1);
    let shifted_w: Vec<Ext4> = w_evals.iter().map(|&w| beta + w).collect();
    let terms_read_w = read_terms(false);
    let mut replay = transcript.clone();
    let sc_read_w = sumcheck::prove(
        &[
            eq_w.clone(),
            Mle::new(quot_w.clone())?,
            Mle::new(shifted_w)?,
        ],
        &terms_read_w,
        transcript,
    )?;
    let r_read_w = sumcheck::verify_final(n_w, 3, &terms_read_w, &sc_read_w, &mut replay)?;
    if sc_read_w.sum != Ext4::ZERO {
        return Err(Error::MalformedInput {
            reason: "read-w sum mismatch",
        });
    }
    check_eq_eval(&eq_w, &r_read_w, sc_read_w.final_values[0])?;

    // C: sum(quot_t + gamma*m) = sum_w + gamma*W.
    transcript.absorb(b"lookup-pcs/ctx", b"sum-t");
    let gamma = transcript.challenge_ext(b"lookup-pcs/gamma");
    transcript.absorb_ext(b"lookup-pcs/gamma", gamma);
    let padded_witness_len = ext4_len(w_evals.len())?;
    let sum_t_claim = sum_w + gamma * padded_witness_len;
    let terms_sum_t = [Term::new(Ext4::ONE, vec![0]), Term::new(gamma, vec![1])];
    let mut replay = transcript.clone();
    let sc_sum_t = sumcheck::prove(
        &[
            Mle::new(quot_t.clone())?,
            Mle::new(multiplicity_evals.clone())?,
        ],
        &terms_sum_t,
        transcript,
    )?;
    let r_sum_t = sumcheck::verify_final(n_t, 2, &terms_sum_t, &sc_sum_t, &mut replay)?;
    if sc_sum_t.sum != sum_t_claim {
        return Err(Error::MalformedInput {
            reason: "sum-t claim mismatch",
        });
    }

    // D: random-equality read-check quot_t * (beta + t) = m.
    transcript.absorb(b"lookup-pcs/ctx", b"read-t");
    let r2 = sample_point(transcript, b"lookup-pcs/r2", n_t);
    let eq_t = Mle::eq_evals(&r2);
    let shifted_t: Vec<Ext4> = t_evals.iter().map(|&t| beta + t).collect();
    let terms_read_t = read_terms(true);
    let mut replay = transcript.clone();
    let sc_read_t = sumcheck::prove(
        &[
            eq_t.clone(),
            Mle::new(quot_t.clone())?,
            Mle::new(shifted_t)?,
            Mle::new(multiplicity_evals.clone())?,
        ],
        &terms_read_t,
        transcript,
    )?;
    let r_read_t = sumcheck::verify_final(n_t, 4, &terms_read_t, &sc_read_t, &mut replay)?;
    if sc_read_t.sum != Ext4::ZERO {
        return Err(Error::MalformedInput {
            reason: "read-t sum mismatch",
        });
    }
    check_eq_eval(&eq_t, &r_read_t, sc_read_t.final_values[0])?;

    let w_value = sc_read_w.final_values[2] - beta;
    let t_value = sc_read_t.final_values[2] - beta;
    let mut openings = Vec::with_capacity(NUM_OPENINGS);
    openings.push(open(
        &witness_quotient_state,
        &r_sum_w,
        sc_sum_w.final_values[0],
        params,
        transcript,
        b"qw-sum",
    )?);
    openings.push(open(
        &witness_quotient_state,
        &r_read_w,
        sc_read_w.final_values[1],
        params,
        transcript,
        b"qw-read",
    )?);
    openings.push(open(
        &witness_state,
        &r_read_w,
        w_value,
        params,
        transcript,
        b"w-read",
    )?);
    openings.push(open(
        &table_quotient_state,
        &r_sum_t,
        sc_sum_t.final_values[0],
        params,
        transcript,
        b"qt-sum",
    )?);
    openings.push(open(
        &multiplicity_state,
        &r_sum_t,
        sc_sum_t.final_values[1],
        params,
        transcript,
        b"m-sum",
    )?);
    openings.push(open(
        &table_quotient_state,
        &r_read_t,
        sc_read_t.final_values[1],
        params,
        transcript,
        b"qt-read",
    )?);
    openings.push(open(
        &table_state,
        &r_read_t,
        t_value,
        params,
        transcript,
        b"t-read",
    )?);
    openings.push(open(
        &multiplicity_state,
        &r_read_t,
        sc_read_t.final_values[3],
        params,
        transcript,
        b"m-read",
    )?);

    Ok((
        commitments,
        Proof {
            beta,
            sum_w,
            sc_sum_w,
            sc_read_w,
            sc_sum_t,
            sc_read_t,
            openings,
        },
    ))
}

/// Verify a committed lookup proof against its column commitments.
///
/// The verifier never sees the witness or table. It replays the transcript,
/// checks all four sumchecks, verifies the eight `BaseFold` openings, and
/// checks that the sum-t challenge binds `sum(m)` to the padded witness
/// length.
///
/// # Errors
/// Returns [`Error::FriVerificationFailed`] on any failed check, shape
/// errors, or [`Error::MalformedInput`] for mismatched commitment lengths.
#[allow(clippy::too_many_lines)]
pub fn verify(
    commitments: &Commitments,
    proof: &Proof,
    params: basefold::Params,
    transcript: &mut Transcript,
) -> Result<()> {
    params.validate()?;
    if proof.openings.len() != NUM_OPENINGS {
        return Err(Error::FriVerificationFailed);
    }
    let n_w = commitments.witness.n_vars();
    let n_t = commitments.table.n_vars();
    let witness_len = 1usize
        .checked_shl(u32::try_from(n_w).map_err(|_| Error::MalformedInput {
            reason: "witness n_vars exceeds u32",
        })?)
        .ok_or(Error::InvalidDomainSize { size: n_w })?;
    let padded_witness_len = ext4_len(witness_len)?;

    commitments.absorb_prefix(transcript);
    let beta = transcript.challenge_ext(b"lookup-pcs/beta");
    if beta != proof.beta {
        return Err(Error::FriVerificationFailed);
    }
    transcript.absorb_ext(b"lookup-pcs/beta", beta);
    commitments.absorb_quotients(transcript);
    transcript.absorb_ext(b"lookup-pcs/sum-w", proof.sum_w);

    // A.
    transcript.absorb(b"lookup-pcs/ctx", b"sum-w");
    let terms_sum = [Term::new(Ext4::ONE, vec![0])];
    let r_sum_w = sumcheck::verify_final(n_w, 1, &terms_sum, &proof.sc_sum_w, transcript)?;
    if proof.sc_sum_w.sum != proof.sum_w {
        return Err(Error::FriVerificationFailed);
    }

    // B.
    transcript.absorb(b"lookup-pcs/ctx", b"read-w");
    let r1 = sample_point(transcript, b"lookup-pcs/r1", n_w);
    let eq_w = Mle::eq_evals(&r1);
    let terms_read_w = read_terms(false);
    let r_read_w = sumcheck::verify_final(n_w, 3, &terms_read_w, &proof.sc_read_w, transcript)?;
    if proof.sc_read_w.sum != Ext4::ZERO {
        return Err(Error::FriVerificationFailed);
    }
    check_eq_eval(&eq_w, &r_read_w, proof.sc_read_w.final_values[0])?;

    // C.
    transcript.absorb(b"lookup-pcs/ctx", b"sum-t");
    let gamma = transcript.challenge_ext(b"lookup-pcs/gamma");
    transcript.absorb_ext(b"lookup-pcs/gamma", gamma);
    let sum_t_claim = proof.sum_w + gamma * padded_witness_len;
    let terms_sum_t = [Term::new(Ext4::ONE, vec![0]), Term::new(gamma, vec![1])];
    let r_sum_t = sumcheck::verify_final(n_t, 2, &terms_sum_t, &proof.sc_sum_t, transcript)?;
    if proof.sc_sum_t.sum != sum_t_claim {
        return Err(Error::FriVerificationFailed);
    }

    // D.
    transcript.absorb(b"lookup-pcs/ctx", b"read-t");
    let r2 = sample_point(transcript, b"lookup-pcs/r2", n_t);
    let eq_t = Mle::eq_evals(&r2);
    let terms_read_t = read_terms(true);
    let r_read_t = sumcheck::verify_final(n_t, 4, &terms_read_t, &proof.sc_read_t, transcript)?;
    if proof.sc_read_t.sum != Ext4::ZERO {
        return Err(Error::FriVerificationFailed);
    }
    check_eq_eval(&eq_t, &r_read_t, proof.sc_read_t.final_values[0])?;

    let w_value = proof.sc_read_w.final_values[2] - beta;
    let t_value = proof.sc_read_t.final_values[2] - beta;
    verify_open(
        &commitments.quot_w,
        &r_sum_w,
        proof.sc_sum_w.final_values[0],
        &proof.openings[0],
        params,
        transcript,
        b"qw-sum",
    )?;
    verify_open(
        &commitments.quot_w,
        &r_read_w,
        proof.sc_read_w.final_values[1],
        &proof.openings[1],
        params,
        transcript,
        b"qw-read",
    )?;
    verify_open(
        &commitments.witness,
        &r_read_w,
        w_value,
        &proof.openings[2],
        params,
        transcript,
        b"w-read",
    )?;
    verify_open(
        &commitments.quot_t,
        &r_sum_t,
        proof.sc_sum_t.final_values[0],
        &proof.openings[3],
        params,
        transcript,
        b"qt-sum",
    )?;
    verify_open(
        &commitments.multiplicities,
        &r_sum_t,
        proof.sc_sum_t.final_values[1],
        &proof.openings[4],
        params,
        transcript,
        b"m-sum",
    )?;
    verify_open(
        &commitments.quot_t,
        &r_read_t,
        proof.sc_read_t.final_values[1],
        &proof.openings[5],
        params,
        transcript,
        b"qt-read",
    )?;
    verify_open(
        &commitments.table,
        &r_read_t,
        t_value,
        &proof.openings[6],
        params,
        transcript,
        b"t-read",
    )?;
    verify_open(
        &commitments.multiplicities,
        &r_read_t,
        proof.sc_read_t.final_values[3],
        &proof.openings[7],
        params,
        transcript,
        b"m-read",
    )?;
    Ok(())
}

fn absorb_prefix(
    transcript: &mut Transcript,
    witness: &basefold::Commitment,
    table: &basefold::Commitment,
    multiplicities: &basefold::Commitment,
) {
    let mut writer = Writer::new();
    for commitment in [witness, table, multiplicities] {
        writer.bytes(&commitment.to_bytes());
    }
    transcript.absorb(b"lookup-pcs/commitments", &writer.finish());
}

fn open(
    state: &basefold::ProverState,
    point: &[Ext4],
    value: Ext4,
    params: basefold::Params,
    transcript: &mut Transcript,
    label: &[u8],
) -> Result<basefold::Proof> {
    transcript.absorb(b"lookup-pcs/open", label);
    basefold::open(state, point, value, params, transcript)
}

fn verify_open(
    commitment: &basefold::Commitment,
    point: &[Ext4],
    value: Ext4,
    proof: &basefold::Proof,
    params: basefold::Params,
    transcript: &mut Transcript,
    label: &[u8],
) -> Result<()> {
    transcript.absorb(b"lookup-pcs/open", label);
    basefold::verify(commitment, point, value, proof, params, transcript)
}

fn read_terms(with_multiplicity: bool) -> Vec<Term> {
    if with_multiplicity {
        vec![
            Term::new(Ext4::ONE, vec![0, 1, 2]),
            Term::new(Ext4::NEG_ONE, vec![0, 3]),
        ]
    } else {
        vec![
            Term::new(Ext4::ONE, vec![0, 1, 2]),
            Term::new(Ext4::NEG_ONE, vec![0]),
        ]
    }
}

fn check_eq_eval(eq: &Mle, point: &[Ext4], claimed: Ext4) -> Result<()> {
    if eq.evaluate(point)? != claimed {
        return Err(Error::FriVerificationFailed);
    }
    Ok(())
}

fn sum(values: &[Ext4]) -> Ext4 {
    values.iter().fold(Ext4::ZERO, |acc, &value| acc + value)
}

fn sample_point(transcript: &mut Transcript, label: &[u8], n_vars: usize) -> Vec<Ext4> {
    (0..n_vars)
        .map(|_| transcript.challenge_ext(label))
        .collect()
}

fn ext4_len(len: usize) -> Result<Ext4> {
    let len = u64::try_from(len).map_err(|_| Error::InvalidDomainSize { size: len })?;
    Ok(Ext4::from_base(Field::from_u64(len)))
}

/// Pad to a power of two of at least two slots by repeating the last value.
fn pad_inputs(values: &[Field]) -> Vec<Field> {
    let target = values.len().max(2).next_power_of_two();
    let mut padded = values.to_vec();
    padded.resize(target, *values.last().unwrap_or(&Field::ZERO));
    padded
}

/// Canonical first-index counts over the original table, then zero padding.
fn multiplicities(witness: &[Field], table: &[Field], padded_len: usize) -> Result<Vec<Ext4>> {
    let mut counts = vec![0u64; padded_len];
    for &value in witness {
        let position =
            table
                .iter()
                .position(|&entry| entry == value)
                .ok_or(Error::MalformedInput {
                    reason: "witness value missing from table",
                })?;
        counts[position] += 1;
    }
    Ok(counts
        .iter()
        .map(|&count| Ext4::from_base(Field::from_u64(count)))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(values: &[u32]) -> Vec<Field> {
        values.iter().map(|&value| Field::new(value)).collect()
    }

    fn params() -> basefold::Params {
        basefold::Params::new(4, 2, 0).unwrap().with_cap_height(1)
    }

    fn sample() -> (Commitments, Proof) {
        let witness = fields(&[20, 20, 30, 10, 40]);
        let table = fields(&[10, 20, 30, 40]);
        let mut prover = Transcript::new(b"lookup-pcs-test");
        prove(&witness, &table, params(), &mut prover).unwrap()
    }

    #[test]
    fn honest_committed_lookup_verifies() {
        let (commitments, proof) = sample();
        assert_eq!(proof.openings.len(), NUM_OPENINGS);
        let mut verifier = Transcript::new(b"lookup-pcs-test");
        verify(&commitments, &proof, params(), &mut verifier).unwrap();
    }

    #[test]
    fn singleton_inputs_pad_and_verify() {
        let witness = fields(&[7]);
        let table = fields(&[7]);
        let mut prover = Transcript::new(b"lookup-pcs-single");
        let (commitments, proof) = prove(&witness, &table, params(), &mut prover).unwrap();
        let mut verifier = Transcript::new(b"lookup-pcs-single");
        verify(&commitments, &proof, params(), &mut verifier).unwrap();
    }

    #[test]
    fn non_member_rejected_by_prover() {
        let witness = fields(&[99]);
        let table = fields(&[1, 2, 3, 4]);
        let mut transcript = Transcript::new(b"lookup-pcs-nonmember");
        assert!(prove(&witness, &table, params(), &mut transcript).is_err());
    }

    #[test]
    fn tampered_sumcheck_and_opening_rejected() {
        let (commitments, mut proof) = sample();
        proof.sc_read_w.sum += Ext4::ONE;
        let mut verifier = Transcript::new(b"lookup-pcs-test");
        assert!(verify(&commitments, &proof, params(), &mut verifier).is_err());

        let (commitments, mut proof) = sample();
        proof.openings[0].sumcheck.sum += Ext4::ONE;
        let mut verifier = Transcript::new(b"lookup-pcs-test");
        assert!(verify(&commitments, &proof, params(), &mut verifier).is_err());
    }

    #[test]
    fn wrong_commitment_rejected() {
        let (commitments, proof) = sample();
        let other_witness = fields(&[10, 10, 20, 20, 30]);
        let other_table = fields(&[10, 20, 30, 40]);
        let mut prover = Transcript::new(b"lookup-pcs-other");
        let (other, _) = prove(&other_witness, &other_table, params(), &mut prover).unwrap();
        let mut commitments = commitments;
        commitments.witness = other.witness;
        let mut verifier = Transcript::new(b"lookup-pcs-test");
        assert!(verify(&commitments, &proof, params(), &mut verifier).is_err());
    }

    #[test]
    fn codec_roundtrip_and_tamper_rejected() {
        let (commitments, proof) = sample();
        let commitment_bytes = commitments.to_bytes();
        assert_eq!(
            Commitments::from_bytes(&commitment_bytes).unwrap(),
            commitments
        );
        let proof_bytes = proof.to_bytes();
        let decoded = Proof::from_bytes(&proof_bytes).unwrap();
        assert_eq!(decoded, proof);
        let mut verifier = Transcript::new(b"lookup-pcs-test");
        verify(&commitments, &decoded, params(), &mut verifier).unwrap();

        assert!(Commitments::from_bytes(&[]).is_err());
        assert!(Proof::from_bytes(&[]).is_err());
        let mut trailing = proof_bytes.clone();
        trailing.push(0);
        assert!(Proof::from_bytes(&trailing).is_err());
        let mut version = proof_bytes;
        version[0] ^= 1;
        assert!(Proof::from_bytes(&version).is_err());
    }
}
