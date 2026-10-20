//! LogUp-style membership lookup: prove every witness value appears in a table.
//! For witness `w[0..N]` and table `t[0..M]` (both padded to powers of two),
//! the prover shows a multiplicity vector `m` with `sum(m) = N` and the
//! rational identity `sum_i 1/(beta + w_i) = sum_j m_j/(beta + t_j)` at a
//! verifier challenge `beta`. Four [`sumcheck`] invocations
//! establish the two sums plus the two well-formedness (`read-check`)
//! identities `q * (beta + v) = 1` / `= m` via randomized equality polynomials.
//! Because the verifier receives the witness and table in clear, it recomputes
//! the canonical first-index multiplicities and rejects any other vector; the
//! multiplicities are not free proof data.
//!
//! # Transcript discipline
//! All Fiat-Shamir steps run on one caller-provided [`Transcript`] with fixed
//! labels; [`prove`] and [`verify`] replay identical sequences, so verifiers
//! must feed the same witness and table in the same order. The `beta`
//! challenge, multiplicities, quotients, sums, and sumcheck rounds use
//! [`Ext4`]; the former ~31-bit algebraic ceiling is removed.
//!
//! # Privacy scope (`v1`)
//! Multiplicities and quotients travel in the clear: this is a sound
//! membership argument, not yet zero-knowledge. [`crate::blind`] hides
//! STARK trace/column openings; hiding lookup tables needs committed
//! sumcheck (a scheduled follow-up), so keep witnesses out of this API
//! when privacy matters.

use crate::babybear::Field;
use crate::error::{Error, Result};
use crate::ext4::Ext4;
use crate::mle::Mle;
use crate::sumcheck::{self, Proof as ScProof, Term};
use crate::transcript::Transcript;

/// `LogUp` membership proof (all vectors in index order, padded lengths).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// Verifier challenge for the rational identity.
    pub beta: Ext4,
    /// Canonical first-index counts over the padded table; the verifier
    /// recomputes and requires an exact match.
    pub multiplicities: Vec<Ext4>,
    /// `1 / (beta + w_i)` over the padded witness.
    pub quot_w: Vec<Ext4>,
    /// `m_j / (beta + t_j)` over the padded table.
    pub quot_t: Vec<Ext4>,
    /// Claimed rational sums (must be equal).
    pub sum_w: Ext4,
    /// Claimed rational sums (must be equal).
    pub sum_t: Ext4,
    /// Sumcheck: `sum quot_w == sum_w`.
    pub sc_sum_w: ScProof,
    /// Sumcheck: read-check `quot_w * (beta + w) = 1`.
    pub sc_read_w: ScProof,
    /// Sumcheck: `sum quot_t == sum_t`.
    pub sc_sum_t: ScProof,
    /// Sumcheck: read-check `quot_t * (beta + t) = m`.
    pub sc_read_t: ScProof,
}

/// Prove membership of `witness` in `table`.
///
/// Both inputs are padded internally (witness by repeating its last element,
/// table likewise with zero multiplicities for padding slots). Table
/// duplicates are assigned to their first index.
///
/// # Errors
/// Returns [`Error::EmptyInput`] for empty inputs and
/// [`Error::MalformedInput`] when a witness value has no table match.
pub fn prove(witness: &[Field], table: &[Field], transcript: &mut Transcript) -> Result<Proof> {
    if witness.is_empty() || table.is_empty() {
        return Err(Error::EmptyInput);
    }
    let (w_pad, t_pad) = pad_inputs(witness, table);
    transcript.absorb(b"lookup/witness", &encode_fields(witness));
    transcript.absorb(b"lookup/table", &encode_fields(table));

    let beta = sample_beta(transcript, &w_pad, &t_pad);

    // Multiplicities: first-index matching over the original table.
    let multiplicities = canonical_multiplicities(&w_pad, table, t_pad.len())?;

    // Quotient columns.
    let mut quot_w = Vec::with_capacity(w_pad.len());
    for &w in &w_pad {
        quot_w.push((beta + Ext4::from_base(w)).inv());
    }
    let mut quot_t = Vec::with_capacity(t_pad.len());
    for (j, &t) in t_pad.iter().enumerate() {
        quot_t.push(multiplicities[j] * (beta + Ext4::from_base(t)).inv());
    }
    let sum_w = quot_w.iter().fold(Ext4::ZERO, |a, &v| a + v);
    let sum_t = quot_t.iter().fold(Ext4::ZERO, |a, &v| a + v);

    transcript.absorb_ext(b"lookup/beta", beta);
    transcript.absorb(b"lookup/m", &encode_exts(&multiplicities));
    transcript.absorb(b"lookup/qw", &encode_exts(&quot_w));
    transcript.absorb(b"lookup/qt", &encode_exts(&quot_t));
    transcript.absorb(b"lookup/sums", &encode_exts(&[sum_w, sum_t]));

    // A: sum quot_w.
    transcript.absorb(b"lookup/ctx", b"sum-w");
    let mle_qw = Mle::new(quot_w.clone())?;
    let sc_sum_w = sumcheck::prove(&[mle_qw], &[Term::new(Ext4::ONE, vec![0])], transcript)?;

    // B: read-check quot_w * (beta + w) = 1 via random eq point.
    transcript.absorb(b"lookup/ctx", b"read-w");
    let r1 = sample_point(transcript, b"lookup/r1", n_vars_of(&quot_w));
    let sc_read_w = prove_read(transcript, &r1, &quot_w, &shifted(&w_pad, beta), None)?;
    // C: sum quot_t.
    transcript.absorb(b"lookup/ctx", b"sum-t");
    let mle_sum_t = Mle::new(quot_t.clone())?;
    let sc_sum_t = sumcheck::prove(&[mle_sum_t], &[Term::new(Ext4::ONE, vec![0])], transcript)?;

    // D: read-check quot_t * (beta + t) = m.
    transcript.absorb(b"lookup/ctx", b"read-t");
    let r2 = sample_point(transcript, b"lookup/r2", n_vars_of(&quot_t));
    let sc_read_t = prove_read(
        transcript,
        &r2,
        &quot_t,
        &shifted(&t_pad, beta),
        Some(&multiplicities),
    )?;

    Ok(Proof {
        beta,
        multiplicities,
        quot_w,
        quot_t,
        sum_w,
        sum_t,
        sc_sum_w,
        sc_read_w,
        sc_sum_t,
        sc_read_t,
    })
}

/// Verify a membership [`Proof`] against the original witness and table.
///
/// Replays the prover transcript exactly, then recomputes the canonical
/// multiplicities, checks rational-sum equality, and verifies the four
/// sumchecks.
///
/// # Errors
/// Returns [`Error::FriVerificationFailed`] on any failed check.
pub fn verify(
    witness: &[Field],
    table: &[Field],
    proof: &Proof,
    transcript: &mut Transcript,
) -> Result<()> {
    if witness.is_empty() || table.is_empty() {
        return Err(Error::EmptyInput);
    }
    let (w_pad, t_pad) = pad_inputs(witness, table);
    transcript.absorb(b"lookup/witness", &encode_fields(witness));
    transcript.absorb(b"lookup/table", &encode_fields(table));

    let beta = sample_beta(transcript, &w_pad, &t_pad);
    if beta != proof.beta {
        return Err(Error::FriVerificationFailed);
    }
    if proof.multiplicities.len() != t_pad.len()
        || proof.quot_w.len() != w_pad.len()
        || proof.quot_t.len() != t_pad.len()
    {
        return Err(Error::FriVerificationFailed);
    }
    // The verifier knows the witness and table here, so multiplicities are
    // not free proof data: recompute the canonical first-index counts and
    // require an exact match. Without this, arbitrary field "multiplicities"
    // can satisfy the two rational-sum constraints for a non-member.
    let expected = canonical_multiplicities(&w_pad, table, t_pad.len())
        .map_err(|_| Error::FriVerificationFailed)?;
    if proof.multiplicities != expected {
        return Err(Error::FriVerificationFailed);
    }
    if proof.sum_w != proof.sum_t {
        return Err(Error::FriVerificationFailed);
    }

    transcript.absorb_ext(b"lookup/beta", beta);
    transcript.absorb(b"lookup/m", &encode_exts(&proof.multiplicities));
    transcript.absorb(b"lookup/qw", &encode_exts(&proof.quot_w));
    transcript.absorb(b"lookup/qt", &encode_exts(&proof.quot_t));
    transcript.absorb(b"lookup/sums", &encode_exts(&[proof.sum_w, proof.sum_t]));

    // A.
    transcript.absorb(b"lookup/ctx", b"sum-w");
    let mle_qw = Mle::new(proof.quot_w.clone())?;
    sumcheck::verify(
        &[mle_qw],
        &[Term::new(Ext4::ONE, vec![0])],
        &proof.sc_sum_w,
        transcript,
    )?;
    if proof.sc_sum_w.sum != proof.sum_w {
        return Err(Error::FriVerificationFailed);
    }

    // B.
    transcript.absorb(b"lookup/ctx", b"read-w");
    let r1 = sample_point(transcript, b"lookup/r1", n_vars_of(&proof.quot_w));
    verify_read(
        transcript,
        &r1,
        &proof.quot_w,
        &shifted(&w_pad, beta),
        None,
        &proof.sc_read_w,
    )?;

    // C.
    transcript.absorb(b"lookup/ctx", b"sum-t");
    let mle_sum_t = Mle::new(proof.quot_t.clone())?;
    sumcheck::verify(
        &[mle_sum_t],
        &[Term::new(Ext4::ONE, vec![0])],
        &proof.sc_sum_t,
        transcript,
    )?;
    if proof.sc_sum_t.sum != proof.sum_t {
        return Err(Error::FriVerificationFailed);
    }

    // D.
    transcript.absorb(b"lookup/ctx", b"read-t");
    let r2 = sample_point(transcript, b"lookup/r2", n_vars_of(&proof.quot_t));
    verify_read(
        transcript,
        &r2,
        &proof.quot_t,
        &shifted(&t_pad, beta),
        Some(&proof.multiplicities),
        &proof.sc_read_t,
    )?;
    Ok(())
}

/// Canonical first-index multiplicity vector over the padded table.
fn canonical_multiplicities(
    witness: &[Field],
    table: &[Field],
    padded_table_len: usize,
) -> Result<Vec<Ext4>> {
    let mut counts = vec![0u64; padded_table_len];
    for &w in witness {
        let pos = table
            .iter()
            .position(|&t| t == w)
            .ok_or(Error::MalformedInput {
                reason: "witness value missing from table",
            })?;
        counts[pos] += 1;
    }
    Ok(counts
        .iter()
        .map(|&c| Ext4::from_base(Field::from_u64(c)))
        .collect())
}

/// Pad witness and table to powers of two by repeating the last element.
fn pad_inputs(witness: &[Field], table: &[Field]) -> (Vec<Field>, Vec<Field>) {
    let mut w_pad = witness.to_vec();
    w_pad.resize(
        w_pad.len().next_power_of_two(),
        *witness.last().unwrap_or(&Field::ZERO),
    );
    let mut t_pad = table.to_vec();
    t_pad.resize(
        t_pad.len().next_power_of_two(),
        *table.last().unwrap_or(&Field::ZERO),
    );
    (w_pad, t_pad)
}

/// Sample `beta` avoiding vanishing denominators, identically on both sides.
fn sample_beta(transcript: &mut Transcript, w: &[Field], t: &[Field]) -> Ext4 {
    loop {
        let beta = transcript.challenge_ext(b"lookup/beta-challenge");
        if w.iter().all(|&x| beta + Ext4::from_base(x) != Ext4::ZERO)
            && t.iter().all(|&x| beta + Ext4::from_base(x) != Ext4::ZERO)
        {
            return beta;
        }
    }
}

/// Sample an `n`-coordinate random point with a fixed label.
fn sample_point(transcript: &mut Transcript, label: &[u8], n: usize) -> Vec<Ext4> {
    (0..n).map(|_| transcript.challenge_ext(label)).collect()
}

fn n_vars_of(values: &[Ext4]) -> usize {
    values.len().trailing_zeros() as usize
}

fn shifted(values: &[Field], beta: Ext4) -> Vec<Ext4> {
    values.iter().map(|&v| beta + Ext4::from_base(v)).collect()
}

fn encode_fields(fields: &[Field]) -> Vec<u8> {
    let mut out = Vec::with_capacity(fields.len() * 4);
    for f in fields {
        out.extend_from_slice(&f.to_le_bytes());
    }
    out
}

fn encode_exts(values: &[Ext4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(values.len() * 16);
    for value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out
}

/// Read-check prover: `sum_x eq(r,x) * (q(x)*b(x) - target(x)) = 0`,
/// where `target` is absent (meaning 1) or an explicit column.
fn prove_read(
    transcript: &mut Transcript,
    r: &[Ext4],
    q: &[Ext4],
    b: &[Ext4],
    target: Option<&[Ext4]>,
) -> Result<ScProof> {
    let mle_equal = Mle::eq_evals(r);
    let mle_quot = Mle::new(q.to_vec())?;
    let mle_b = Mle::new(b.to_vec())?;
    let mles;
    let terms;
    if let Some(t) = target {
        let mle_t = Mle::new(t.to_vec())?;
        mles = vec![mle_equal, mle_quot, mle_b, mle_t];
        terms = vec![
            Term::new(Ext4::ONE, vec![0, 1, 2]),
            Term::new(Ext4::NEG_ONE, vec![0, 3]),
        ];
    } else {
        mles = vec![mle_equal, mle_quot, mle_b];
        // `-eq` via the additive inverse of one.
        terms = vec![
            Term::new(Ext4::ONE, vec![0, 1, 2]),
            Term::new(Ext4::NEG_ONE, vec![0]),
        ];
    }
    sumcheck::prove(&mles, &terms, transcript)
}

/// Read-check verifier mirrors [`prove_read`].
fn verify_read(
    transcript: &mut Transcript,
    r: &[Ext4],
    q: &[Ext4],
    b: &[Ext4],
    target: Option<&[Ext4]>,
    proof: &ScProof,
) -> Result<()> {
    let mle_equal = Mle::eq_evals(r);
    let mle_quot = Mle::new(q.to_vec())?;
    let mle_b = Mle::new(b.to_vec())?;
    if proof.sum != Ext4::ZERO {
        return Err(Error::FriVerificationFailed);
    }
    if let Some(t) = target {
        let mle_t = Mle::new(t.to_vec())?;
        let mles = [mle_equal, mle_quot, mle_b, mle_t];
        let terms = [
            Term::new(Ext4::ONE, vec![0, 1, 2]),
            Term::new(Ext4::NEG_ONE, vec![0, 3]),
        ];
        sumcheck::verify(&mles, &terms, proof, transcript)?;
    } else {
        let mles = [mle_equal, mle_quot, mle_b];
        let terms = [
            Term::new(Ext4::ONE, vec![0, 1, 2]),
            Term::new(Ext4::NEG_ONE, vec![0]),
        ];
        sumcheck::verify(&mles, &terms, proof, transcript)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(values: &[u32]) -> Vec<Field> {
        values.iter().map(|&v| Field::new(v)).collect()
    }

    #[test]
    fn rejects_empty() {
        let mut t = Transcript::new(b"lookup-empty");
        assert!(prove(&[], &fields(&[1]), &mut t).is_err());
        assert!(prove(&fields(&[1]), &[], &mut t).is_err());
    }

    #[test]
    fn rejects_non_member() {
        let mut t = Transcript::new(b"lookup-nonmember");
        assert!(prove(&fields(&[99]), &fields(&[1, 2, 3, 4]), &mut t).is_err());
    }

    #[test]
    fn honest_membership_verifies() {
        let witness = fields(&[20, 20, 30, 10, 40]);
        let table = fields(&[10, 20, 30, 40]);
        let mut pt = Transcript::new(b"lookup-e2e");
        let proof = prove(&witness, &table, &mut pt).unwrap();
        // Witness pads to [20,20,30,10,40,40,40,40]; multiplicities over
        // table [10,20,30,40] are therefore 1,2,1,4.
        assert_eq!(
            proof.multiplicities,
            vec![
                Ext4::ONE,
                Ext4::from_base(Field::new(2)),
                Ext4::ONE,
                Ext4::from_base(Field::new(4))
            ]
        );
        assert_eq!(proof.sum_w, proof.sum_t);
        let mut vt = Transcript::new(b"lookup-e2e");
        verify(&witness, &table, &proof, &mut vt).unwrap();
    }

    /// Construct a proof for a non-member by solving for fractional
    /// multiplicities that satisfy the two sum constraints. This must be
    /// rejected: multiplicities are witness counts, not free field elements.
    fn forge_nonmember(witness: &[Field], table: &[Field], transcript: &mut Transcript) -> Proof {
        let (w_pad, t_pad) = pad_inputs(witness, table);
        transcript.absorb(b"lookup/witness", &encode_fields(witness));
        transcript.absorb(b"lookup/table", &encode_fields(table));
        let beta = sample_beta(transcript, &w_pad, &t_pad);

        let quot_w: Vec<Ext4> = w_pad
            .iter()
            .map(|&w| (beta + Ext4::from_base(w)).inv())
            .collect();
        let sum_w = quot_w.iter().fold(Ext4::ZERO, |a, &v| a + v);
        let n = Ext4::from_base(Field::from_u64(w_pad.len() as u64));

        let a0 = beta + Ext4::from_base(t_pad[0]);
        let a1 = beta + Ext4::from_base(t_pad[1]);
        let m0 = a0 * (sum_w * a1 - n) * (a1 - a0).inv();
        let mut multiplicities = vec![Ext4::ZERO; t_pad.len()];
        multiplicities[0] = m0;
        multiplicities[1] = n - m0;

        let quot_t: Vec<Ext4> = t_pad
            .iter()
            .enumerate()
            .map(|(j, &t)| multiplicities[j] * (beta + Ext4::from_base(t)).inv())
            .collect();
        let sum_t = quot_t.iter().fold(Ext4::ZERO, |a, &v| a + v);

        transcript.absorb_ext(b"lookup/beta", beta);
        transcript.absorb(b"lookup/m", &encode_exts(&multiplicities));
        transcript.absorb(b"lookup/qw", &encode_exts(&quot_w));
        transcript.absorb(b"lookup/qt", &encode_exts(&quot_t));
        transcript.absorb(b"lookup/sums", &encode_exts(&[sum_w, sum_t]));

        transcript.absorb(b"lookup/ctx", b"sum-w");
        let sc_sum_w = sumcheck::prove(
            &[Mle::new(quot_w.clone()).unwrap()],
            &[Term::new(Ext4::ONE, vec![0])],
            transcript,
        )
        .unwrap();

        transcript.absorb(b"lookup/ctx", b"read-w");
        let r1 = sample_point(transcript, b"lookup/r1", n_vars_of(&quot_w));
        let sc_read_w = prove_read(transcript, &r1, &quot_w, &shifted(&w_pad, beta), None).unwrap();

        transcript.absorb(b"lookup/ctx", b"sum-t");
        let sc_sum_t = sumcheck::prove(
            &[Mle::new(quot_t.clone()).unwrap()],
            &[Term::new(Ext4::ONE, vec![0])],
            transcript,
        )
        .unwrap();

        transcript.absorb(b"lookup/ctx", b"read-t");
        let r2 = sample_point(transcript, b"lookup/r2", n_vars_of(&quot_t));
        let sc_read_t = prove_read(
            transcript,
            &r2,
            &quot_t,
            &shifted(&t_pad, beta),
            Some(&multiplicities),
        )
        .unwrap();

        Proof {
            beta,
            multiplicities,
            quot_w,
            quot_t,
            sum_w,
            sum_t,
            sc_sum_w,
            sc_read_w,
            sc_sum_t,
            sc_read_t,
        }
    }

    #[test]
    fn forged_multiplicities_rejected() {
        let witness = fields(&[99]);
        let table = fields(&[1, 2, 3, 4]);
        let mut pt = Transcript::new(b"lookup-forge");
        let proof = forge_nonmember(&witness, &table, &mut pt);
        let mut vt = Transcript::new(b"lookup-forge");
        assert!(verify(&witness, &table, &proof, &mut vt).is_err());
    }

    #[test]
    fn singleton_verifies() {
        let witness = fields(&[7]);
        let table = fields(&[7]);
        let mut pt = Transcript::new(b"lookup-single");
        let proof = prove(&witness, &table, &mut pt).unwrap();
        let mut vt = Transcript::new(b"lookup-single");
        verify(&witness, &table, &proof, &mut vt).unwrap();
    }

    #[test]
    fn tampered_multiplicity_fails() {
        let witness = fields(&[20, 30]);
        let table = fields(&[10, 20, 30, 40]);
        let mut pt = Transcript::new(b"lookup-tamper");
        let mut proof = prove(&witness, &table, &mut pt).unwrap();
        proof.multiplicities[1] += Ext4::ONE;
        let mut vt = Transcript::new(b"lookup-tamper");
        assert!(verify(&witness, &table, &proof, &mut vt).is_err());
    }

    #[test]
    fn wrong_table_fails() {
        let witness = fields(&[20, 30]);
        let table = fields(&[10, 20, 30, 40]);
        let mut pt = Transcript::new(b"lookup-wrong");
        let proof = prove(&witness, &table, &mut pt).unwrap();
        let mut vt = Transcript::new(b"lookup-wrong");
        assert!(verify(&witness, &fields(&[10, 20, 30, 41]), &proof, &mut vt).is_err());
    }
}
