//! Interactive sumcheck over [`Mle`]s: prove `sum_{x in {0,1}^n} f(x) = S`.
//!
//! The summand is a sum of terms, each a coefficient times a product of
//! [`Mle`]s: `f = sum_k c_k * prod_j mle[k_j]`. Round polynomials have degree
//! at most the largest factor count and are sent as evaluations at
//! `0, 1, .., degree`.
//!
//! # Transcript discipline
//! Callers must absorb a unique context string before invoking [`prove`] or
//! [`verify`]; internal labels (`b"sumcheck/claim"`, `b"sumcheck/round"`,
//! `b"sumcheck/challenge"`) are then collision-free across protocols.
//! [`prove`] and [`verify`] replay identical absorb/squeeze sequences.
//!
//! # Oracle model (`v1`)
//! [`verify`] evaluates the [`Mle`]s directly as the polynomial oracle.
//! [`crate::upcs`] supplies FRI-backed point openings for committed
//! univariate polynomials, and [`crate::gemini`] builds a first multilinear
//! PCS from them (`O(n)` openings); compact multilinear FRI and committed
//! oracles remain roadmap work. Sumcheck soundness below assumes a binding
//! oracle. Round challenges are drawn from [`Ext4`], so the per-round
//! algebraic error is bounded by roughly `degree / p^4`.

use crate::babybear::Field;
use crate::codec::{Reader, Writer, MAX_ELEMS, VERSION};
use crate::error::{Error, Result};
use crate::ext4::Ext4;
use crate::mle::Mle;
use crate::transcript::Transcript;

/// Maximum number of rounds accepted by the decoder (one per variable).
const MAX_ROUNDS: u32 = 32;

/// One summand term: `coeff * prod(factors)` with factors as [`Mle`] indices.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Term {
    /// Scalar coefficient.
    pub coeff: Ext4,
    /// Indices into the [`Mle`] table passed to [`prove`]/[`verify`].
    pub factors: Vec<usize>,
}

impl Term {
    /// Build a term.
    #[must_use]
    pub const fn new(coeff: Ext4, factors: Vec<usize>) -> Self {
        Self { coeff, factors }
    }
}

/// Sumcheck proof: claimed sum, round polynomials, final oracle values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// Claimed hypercube sum.
    pub sum: Ext4,
    /// Round `i` evaluations at `0..=degree`, in order.
    pub round_evals: Vec<Vec<Ext4>>,
    /// Each [`Mle`] evaluated at the full challenge point.
    pub final_values: Vec<Ext4>,
}

impl Proof {
    /// Canonical bytes: version, claimed sum, rounds, final values.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.byte(VERSION);
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
        let mut reader = Reader::new(bytes);
        reader.version()?;
        let proof = Self::read_body(&mut reader)?;
        reader.end()?;
        Ok(proof)
    }

    /// Append the version-free body.
    pub(crate) fn write_body(&self, writer: &mut Writer) {
        writer.ext4(self.sum);
        writer.count(self.round_evals.len());
        for round in &self.round_evals {
            writer.count(round.len());
            for &value in round {
                writer.ext4(value);
            }
        }
        writer.count(self.final_values.len());
        for &value in &self.final_values {
            writer.ext4(value);
        }
    }

    /// Read a version-free body.
    pub(crate) fn read_body(reader: &mut Reader<'_>) -> Result<Self> {
        let sum = reader.ext4()?;
        let mut round_evals = Vec::new();
        for _ in 0..reader.count(MAX_ROUNDS)? {
            let mut round = Vec::new();
            for _ in 0..reader.count(MAX_ELEMS)? {
                round.push(reader.ext4()?);
            }
            round_evals.push(round);
        }
        let mut final_values = Vec::new();
        for _ in 0..reader.count(MAX_ELEMS)? {
            final_values.push(reader.ext4()?);
        }
        Ok(Self {
            sum,
            round_evals,
            final_values,
        })
    }
}

/// Prove `sum f = S` for the given [`Mle`] table and [`Term`]s.
///
/// All [`Mle`]s must share the same variable count; factor indices must be
/// in range; `terms` must be non-empty.
///
/// # Errors
/// Returns [`Error`] for empty terms, dimension mismatch, or bad indices.
pub fn prove(mles: &[Mle], terms: &[Term], transcript: &mut Transcript) -> Result<Proof> {
    let n = check_shapes(mles, terms)?;
    let degree = round_degree(terms);

    let claimed = full_sum(mles, terms);
    transcript.absorb(b"sumcheck/claim", &encode_fields(&[claimed]));

    // Working buffers, one per MLE (MSB-first layout: halves split var 0).
    let mut bufs: Vec<Vec<Ext4>> = mles.iter().map(|m| m.evals().to_vec()).collect();
    let mut challenges: Vec<Ext4> = Vec::with_capacity(n);
    let mut round_evals: Vec<Vec<Ext4>> = Vec::with_capacity(n);

    for _ in 0..n {
        let mut evals = Vec::with_capacity(degree + 1);
        for k in 0..=degree {
            evals.push(round_eval(
                &bufs,
                terms,
                Ext4::from_base(Field::from_u64(k as u64)),
            ));
        }
        transcript.absorb(b"sumcheck/round", &encode_fields(&evals));
        let r = transcript.challenge_ext(b"sumcheck/challenge");
        challenges.push(r);
        round_evals.push(evals);
        for buf in &mut bufs {
            fold_halves(buf, r);
        }
    }

    let final_values: Vec<Ext4> = bufs.iter().map(|b| b[0]).collect();
    Ok(Proof {
        sum: claimed,
        round_evals,
        final_values,
    })
}

/// Verify a sumcheck [`Proof`] against in-clear [`Mle`] oracles.
///
/// Replays the prover transcript exactly and checks the round chain plus the
/// final oracle evaluations.
///
/// # Errors
/// Returns [`Error::FriVerificationFailed`] when any check fails, or shape
/// errors matching [`prove`].
pub fn verify(
    mles: &[Mle],
    terms: &[Term],
    proof: &Proof,
    transcript: &mut Transcript,
) -> Result<()> {
    let n = check_shapes(mles, terms)?;
    let degree = round_degree(terms);
    if proof.round_evals.len() != n || proof.final_values.len() != mles.len() {
        return Err(Error::FriVerificationFailed);
    }

    transcript.absorb(b"sumcheck/claim", &encode_fields(&[proof.sum]));
    let mut expected = proof.sum;
    let mut challenges: Vec<Ext4> = Vec::with_capacity(n);

    for round in &proof.round_evals {
        if round.len() != degree + 1 {
            return Err(Error::FriVerificationFailed);
        }
        if round[0] + round[1] != expected {
            return Err(Error::FriVerificationFailed);
        }
        transcript.absorb(b"sumcheck/round", &encode_fields(round));
        let r = transcript.challenge_ext(b"sumcheck/challenge");
        challenges.push(r);
        expected = interpolate_at(round, r);
    }

    // Oracle checks: each MLE at the challenge point, then the summand.
    for (mle, claimed) in mles.iter().zip(&proof.final_values) {
        if mle.evaluate(&challenges)? != *claimed {
            return Err(Error::FriVerificationFailed);
        }
    }
    if eval_summand(&proof.final_values, terms) != expected {
        return Err(Error::FriVerificationFailed);
    }
    Ok(())
}

/// Lagrange-interpolate evaluations at `0..n` to `at`.
#[must_use]
pub fn interpolate_at(evals: &[Ext4], at: Ext4) -> Ext4 {
    let n = evals.len();
    let mut acc = Ext4::ZERO;
    for (i, &eval_i) in evals.iter().enumerate() {
        let xi = Ext4::from_base(Field::from_u64(i as u64));
        let mut num = Ext4::ONE;
        let mut den = Ext4::ONE;
        for j in 0..n {
            if i == j {
                continue;
            }
            let xj = Ext4::from_base(Field::from_u64(j as u64));
            num *= at - xj;
            den *= xi - xj;
        }
        acc += eval_i * num * den.inv();
    }
    acc
}

fn check_shapes(mles: &[Mle], terms: &[Term]) -> Result<usize> {
    if terms.is_empty() {
        return Err(Error::EmptyInput);
    }
    if mles.is_empty() {
        return Err(Error::EmptyInput);
    }
    let n = mles[0].n_vars();
    if mles.iter().any(|m| m.n_vars() != n) {
        return Err(Error::MalformedInput {
            reason: "all MLEs must share n_vars",
        });
    }
    for term in terms {
        for &f in &term.factors {
            if f >= mles.len() {
                return Err(Error::IndexOutOfBounds {
                    index: f,
                    len: mles.len(),
                });
            }
        }
    }
    Ok(n)
}

fn round_degree(terms: &[Term]) -> usize {
    terms
        .iter()
        .map(|t| t.factors.len())
        .max()
        .unwrap_or(0)
        .max(1)
}

/// Full hypercube sum of the summand.
fn full_sum(mles: &[Mle], terms: &[Term]) -> Ext4 {
    let len = mles[0].len();
    let mut acc = Ext4::ZERO;
    for j in 0..len {
        let mut point = Ext4::ZERO;
        for term in terms {
            let mut prod = term.coeff;
            for &f in &term.factors {
                prod *= mles[f].evals()[j];
            }
            point += prod;
        }
        acc += point;
    }
    acc
}

/// Round polynomial at `at`: MSB-first halves are `(var_i = 0 | 1)` sides.
fn round_eval(bufs: &[Vec<Ext4>], terms: &[Term], at: Ext4) -> Ext4 {
    let half = bufs[0].len() / 2;
    let mut acc = Ext4::ZERO;
    for term in terms {
        let mut term_sum = Ext4::ZERO;
        for j in 0..half {
            let mut prod = term.coeff;
            for &f in &term.factors {
                let lo = bufs[f][j];
                let hi = bufs[f][j + half];
                prod *= lo + at * (hi - lo);
            }
            term_sum += prod;
        }
        acc += term_sum;
    }
    acc
}

/// Fold MSB-first halves with challenge `r` in place.
fn fold_halves(buf: &mut Vec<Ext4>, r: Ext4) {
    let half = buf.len() / 2;
    for j in 0..half {
        buf[j] = buf[j] + r * (buf[j + half] - buf[j]);
    }
    buf.truncate(half);
}

/// Evaluate the summand from per-MLE point values.
fn eval_summand(values: &[Ext4], terms: &[Term]) -> Ext4 {
    let mut acc = Ext4::ZERO;
    for term in terms {
        let mut prod = term.coeff;
        for &f in &term.factors {
            prod *= values[f];
        }
        acc += prod;
    }
    acc
}

fn encode_fields(fields: &[Ext4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(fields.len() * 16);
    for f in fields {
        out.extend_from_slice(&f.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_mle(n_vars: usize, seed: &mut u64) -> Mle {
        let evals = (0..(1usize << n_vars))
            .map(|_| Ext4::from_base(Field::from_u64(crate::gf2::splitmix64(seed))))
            .collect();
        Mle::new(evals).unwrap()
    }

    #[test]
    fn rejects_bad_shapes() {
        let mut t = Transcript::new(b"sc-shape");
        let m = random_mle(2, &mut 1u64);
        assert!(prove(std::slice::from_ref(&m), &[], &mut t).is_err());
        assert!(prove(&[], &[Term::new(Ext4::ONE, vec![0])], &mut t).is_err());
        let m2 = random_mle(3, &mut 2u64);
        let terms = [Term::new(Ext4::ONE, vec![0])];
        assert!(prove(&[m, m2], &terms, &mut t).is_err());
        assert!(prove(
            &[random_mle(2, &mut 3u64)],
            &[Term::new(Ext4::ONE, vec![7])],
            &mut t
        )
        .is_err());
    }

    #[test]
    fn product_sum_verifies() {
        let mut seed = 0x2222_3333_4444_5555u64;
        let (a, b) = (random_mle(4, &mut seed), random_mle(4, &mut seed));
        let terms = [Term::new(Ext4::ONE, vec![0, 1])];
        let mut pt = Transcript::new(b"sc-prod");
        let mles = [a.clone(), b.clone()];
        let proof = prove(&mles, &terms, &mut pt).unwrap();
        assert_eq!(proof.round_evals.len(), 4);
        assert_eq!(proof.round_evals[0].len(), 3); // degree 2 -> 3 points
        let mut vt = Transcript::new(b"sc-prod");
        verify(&mles, &terms, &proof, &mut vt).unwrap();
    }

    #[test]
    fn tampered_round_fails() {
        let mut seed = 0x6666_7777_8888_9999u64;
        let (a, b) = (random_mle(3, &mut seed), random_mle(3, &mut seed));
        let terms = [Term::new(Ext4::ONE, vec![0, 1])];
        let mut pt = Transcript::new(b"sc-tamper");
        let mles = [a.clone(), b.clone()];
        let mut proof = prove(&mles, &terms, &mut pt).unwrap();
        proof.round_evals[1][0] += Ext4::ONE;
        let mut vt = Transcript::new(b"sc-tamper");
        assert!(verify(&mles, &terms, &proof, &mut vt).is_err());
    }

    #[test]
    fn tampered_final_fails() {
        let mut seed = 0xaaaa_0000_bbbb_1111u64;
        let a = random_mle(3, &mut seed);
        let terms = [Term::new(Ext4::from_base(Field::new(5)), vec![0])];
        let mut pt = Transcript::new(b"sc-final");
        let mut proof = prove(std::slice::from_ref(&a), &terms, &mut pt).unwrap();
        proof.final_values[0] += Ext4::ONE;
        let mut vt = Transcript::new(b"sc-final");
        assert!(verify(&[a], &terms, &proof, &mut vt).is_err());
    }

    #[test]
    fn wrong_transcript_fails() {
        let mut seed = 0xcccc_dddd_eeee_ffffu64;
        let a = random_mle(2, &mut seed);
        let terms = [Term::new(Ext4::ONE, vec![0])];
        let mut pt = Transcript::new(b"sc-A");
        let proof = prove(std::slice::from_ref(&a), &terms, &mut pt).unwrap();
        let mut vt = Transcript::new(b"sc-B");
        assert!(verify(&[a], &terms, &proof, &mut vt).is_err());
    }

    #[test]
    fn encoding_roundtrip_and_rejects() {
        let mut seed = 0x1234_abcd_5678_ef01u64;
        let a = random_mle(3, &mut seed);
        let terms = [Term::new(Ext4::from_base(Field::new(7)), vec![0])];
        let mut transcript = Transcript::new(b"sc-encode");
        let proof = prove(std::slice::from_ref(&a), &terms, &mut transcript).unwrap();
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

    #[test]
    fn interpolate_sanity() {
        // Line through (0,1),(1,3): f(2) = 5.
        let evals = [Ext4::from_base(Field::ONE), Ext4::from_base(Field::new(3))];
        assert_eq!(
            interpolate_at(&evals, Ext4::from_base(Field::new(2))),
            Ext4::from_base(Field::new(5))
        );
    }
}
