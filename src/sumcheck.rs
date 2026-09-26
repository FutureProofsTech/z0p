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
//! [`verify`] evaluates the [`Mle`]s directly as the polynomial oracle. Wiring
//! these evaluations to FRI opening proofs is the scheduled next milestone;
//! sumcheck soundness below assumes a binding oracle.

use crate::babybear::Field;
use crate::error::{Error, Result};
use crate::mle::Mle;
use crate::transcript::Transcript;

/// One summand term: `coeff * prod(factors)` with factors as [`Mle`] indices.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Term {
    /// Scalar coefficient.
    pub coeff: Field,
    /// Indices into the [`Mle`] table passed to [`prove`]/[`verify`].
    pub factors: Vec<usize>,
}

impl Term {
    /// Build a term.
    #[must_use]
    pub const fn new(coeff: Field, factors: Vec<usize>) -> Self {
        Self { coeff, factors }
    }
}

/// Sumcheck proof: claimed sum, round polynomials, final oracle values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// Claimed hypercube sum.
    pub sum: Field,
    /// Round `i` evaluations at `0..=degree`, in order.
    pub round_evals: Vec<Vec<Field>>,
    /// Each [`Mle`] evaluated at the full challenge point.
    pub final_values: Vec<Field>,
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
    let mut bufs: Vec<Vec<Field>> = mles.iter().map(|m| m.evals().to_vec()).collect();
    let mut challenges: Vec<Field> = Vec::with_capacity(n);
    let mut round_evals: Vec<Vec<Field>> = Vec::with_capacity(n);

    for _ in 0..n {
        let mut evals = Vec::with_capacity(degree + 1);
        for k in 0..=degree {
            evals.push(round_eval(&bufs, terms, Field::from_u64(k as u64)));
        }
        transcript.absorb(b"sumcheck/round", &encode_fields(&evals));
        let r = transcript.challenge_bb(b"sumcheck/challenge");
        challenges.push(r);
        round_evals.push(evals);
        for buf in &mut bufs {
            fold_halves(buf, r);
        }
    }

    let final_values: Vec<Field> = bufs.iter().map(|b| b[0]).collect();
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
    let mut challenges: Vec<Field> = Vec::with_capacity(n);

    for round in &proof.round_evals {
        if round.len() != degree + 1 {
            return Err(Error::FriVerificationFailed);
        }
        if round[0] + round[1] != expected {
            return Err(Error::FriVerificationFailed);
        }
        transcript.absorb(b"sumcheck/round", &encode_fields(round));
        let r = transcript.challenge_bb(b"sumcheck/challenge");
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
pub fn interpolate_at(evals: &[Field], at: Field) -> Field {
    let n = evals.len();
    let mut acc = Field::ZERO;
    for (i, &eval_i) in evals.iter().enumerate() {
        let xi = Field::from_u64(i as u64);
        let mut num = Field::ONE;
        let mut den = Field::ONE;
        for j in 0..n {
            if i == j {
                continue;
            }
            let xj = Field::from_u64(j as u64);
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
fn full_sum(mles: &[Mle], terms: &[Term]) -> Field {
    let len = mles[0].len();
    let mut acc = Field::ZERO;
    for j in 0..len {
        let mut point = Field::ZERO;
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
fn round_eval(bufs: &[Vec<Field>], terms: &[Term], at: Field) -> Field {
    let half = bufs[0].len() / 2;
    let mut acc = Field::ZERO;
    for term in terms {
        let mut term_sum = Field::ZERO;
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
fn fold_halves(buf: &mut Vec<Field>, r: Field) {
    let half = buf.len() / 2;
    for j in 0..half {
        buf[j] = buf[j] + r * (buf[j + half] - buf[j]);
    }
    buf.truncate(half);
}

/// Evaluate the summand from per-MLE point values.
fn eval_summand(values: &[Field], terms: &[Term]) -> Field {
    let mut acc = Field::ZERO;
    for term in terms {
        let mut prod = term.coeff;
        for &f in &term.factors {
            prod *= values[f];
        }
        acc += prod;
    }
    acc
}

fn encode_fields(fields: &[Field]) -> Vec<u8> {
    let mut out = Vec::with_capacity(fields.len() * 4);
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
            .map(|_| Field::from_u64(crate::gf2::splitmix64(seed)))
            .collect();
        Mle::new(evals).unwrap()
    }

    #[test]
    fn rejects_bad_shapes() {
        let mut t = Transcript::new(b"sc-shape");
        let m = random_mle(2, &mut 1u64);
        assert!(prove(std::slice::from_ref(&m), &[], &mut t).is_err());
        assert!(prove(&[], &[Term::new(Field::ONE, vec![0])], &mut t).is_err());
        let m2 = random_mle(3, &mut 2u64);
        let terms = [Term::new(Field::ONE, vec![0])];
        assert!(prove(&[m, m2], &terms, &mut t).is_err());
        assert!(prove(
            &[random_mle(2, &mut 3u64)],
            &[Term::new(Field::ONE, vec![7])],
            &mut t
        )
        .is_err());
    }

    #[test]
    fn product_sum_verifies() {
        let mut seed = 0x2222_3333_4444_5555u64;
        let (a, b) = (random_mle(4, &mut seed), random_mle(4, &mut seed));
        let terms = [Term::new(Field::ONE, vec![0, 1])];
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
        let terms = [Term::new(Field::ONE, vec![0, 1])];
        let mut pt = Transcript::new(b"sc-tamper");
        let mles = [a.clone(), b.clone()];
        let mut proof = prove(&mles, &terms, &mut pt).unwrap();
        proof.round_evals[1][0] += Field::ONE;
        let mut vt = Transcript::new(b"sc-tamper");
        assert!(verify(&mles, &terms, &proof, &mut vt).is_err());
    }

    #[test]
    fn tampered_final_fails() {
        let mut seed = 0xaaaa_0000_bbbb_1111u64;
        let a = random_mle(3, &mut seed);
        let terms = [Term::new(Field::new(5), vec![0])];
        let mut pt = Transcript::new(b"sc-final");
        let mut proof = prove(std::slice::from_ref(&a), &terms, &mut pt).unwrap();
        proof.final_values[0] += Field::ONE;
        let mut vt = Transcript::new(b"sc-final");
        assert!(verify(&[a], &terms, &proof, &mut vt).is_err());
    }

    #[test]
    fn wrong_transcript_fails() {
        let mut seed = 0xcccc_dddd_eeee_ffffu64;
        let a = random_mle(2, &mut seed);
        let terms = [Term::new(Field::ONE, vec![0])];
        let mut pt = Transcript::new(b"sc-A");
        let proof = prove(std::slice::from_ref(&a), &terms, &mut pt).unwrap();
        let mut vt = Transcript::new(b"sc-B");
        assert!(verify(&[a], &terms, &proof, &mut vt).is_err());
    }

    #[test]
    fn interpolate_sanity() {
        // Line through (0,1),(1,3): f(2) = 5.
        let evals = [Field::ONE, Field::new(3)];
        assert_eq!(interpolate_at(&evals, Field::new(2)), Field::new(5));
    }
}
