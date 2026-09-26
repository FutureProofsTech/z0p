//! Multilinear polynomials in hypercube-evaluation form over [`BabyBear`].
//!
//! An [`Mle`] with `n` variables stores `2^n` evaluations ordered so that the
//! element index, read most-significant-bit first, is the variable
//! assignment: index `0` is `(0,..,0)`, index `2^n - 1` is `(1,..,1)`.
//! [`Mle::evaluate`] folds the least-significant variable first, which matches
//! [`Mle::eq_evals`] construction order; both are cross-tested.
//!
//! [`BabyBear`]: crate::babybear::Field

use crate::babybear::Field;
use crate::error::{Error, Result};

/// Dense multilinear polynomial: evaluations over `{0,1}^n`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mle {
    n_vars: usize,
    evals: Vec<Field>,
}

impl Mle {
    /// Build from hypercube evaluations.
    ///
    /// # Errors
    /// Returns [`Error::EmptyInput`] for empty input and
    /// [`Error::InvalidDomainSize`] for non-power-of-two lengths.
    pub fn new(evals: Vec<Field>) -> Result<Self> {
        if evals.is_empty() {
            return Err(Error::EmptyInput);
        }
        if !evals.len().is_power_of_two() {
            return Err(Error::InvalidDomainSize { size: evals.len() });
        }
        Ok(Self {
            n_vars: evals.len().trailing_zeros() as usize,
            evals,
        })
    }

    /// Number of variables.
    #[must_use]
    pub const fn n_vars(&self) -> usize {
        self.n_vars
    }

    /// Number of evaluations (`2^n_vars`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.evals.len()
    }

    /// Always `false`: construction rejects empty tables.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Raw evaluations in index order.
    #[must_use]
    pub fn evals(&self) -> &[Field] {
        &self.evals
    }

    /// Evaluate at `point` (`point.len() == n_vars`, MSB-first order).
    ///
    /// # Errors
    /// Returns [`Error::MalformedInput`] on dimension mismatch.
    pub fn evaluate(&self, point: &[Field]) -> Result<Field> {
        if point.len() != self.n_vars {
            return Err(Error::MalformedInput {
                reason: "point dimension must match n_vars",
            });
        }
        // Fold least-significant variable first: adjacent pairs.
        let mut buf = self.evals.clone();
        for &r in point.iter().rev() {
            let half = buf.len() / 2;
            for i in 0..half {
                buf[i] = buf[2 * i] + r * (buf[2 * i + 1] - buf[2 * i]);
            }
            buf.truncate(half);
        }
        Ok(buf[0])
    }

    /// Fix the least-significant variable at `r`, halving the table.
    #[must_use]
    pub fn fix_last(&self, r: Field) -> Self {
        let half = self.evals.len() / 2;
        let mut out = Vec::with_capacity(half.max(1));
        if self.evals.len() == 1 {
            out.push(self.evals[0]);
        } else {
            for i in 0..half {
                out.push(self.evals[2 * i] + r * (self.evals[2 * i + 1] - self.evals[2 * i]));
            }
        }
        Self {
            n_vars: self.n_vars.saturating_sub(1),
            evals: out,
        }
    }

    /// Equality-polynomial evaluations: `eq(point, x)` over the hypercube.
    ///
    /// Infallible: any point yields a valid table (`[1]` for empty points).
    /// Index order matches [`Mle::new`] (MSB-first).
    #[must_use]
    pub fn eq_evals(point: &[Field]) -> Self {
        let mut buf = vec![Field::ONE];
        for &r in point {
            let mut next = Vec::with_capacity(buf.len() * 2);
            for &v in &buf {
                next.push(v * (Field::ONE - r));
                next.push(v * r);
            }
            buf = next;
        }
        Self {
            n_vars: point.len(),
            evals: buf,
        }
    }

    /// Sum of all evaluations (the all-ones linear form).
    #[must_use]
    pub fn sum(&self) -> Field {
        self.evals.iter().fold(Field::ZERO, |acc, &v| acc + v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_tables() {
        assert_eq!(Mle::new(vec![]), Err(Error::EmptyInput));
        assert_eq!(
            Mle::new(vec![Field::ONE; 3]),
            Err(Error::InvalidDomainSize { size: 3 })
        );
    }

    #[test]
    fn corners_match() {
        // f(00)=1, f(01)=2, f(10)=3, f(11)=4.
        let mle = Mle::new(vec![
            Field::ONE,
            Field::new(2),
            Field::new(3),
            Field::new(4),
        ])
        .unwrap();
        let (zero, one) = (Field::ZERO, Field::ONE);
        assert_eq!(mle.evaluate(&[zero, zero]).unwrap(), Field::ONE);
        assert_eq!(mle.evaluate(&[zero, one]).unwrap(), Field::new(2));
        assert_eq!(mle.evaluate(&[one, zero]).unwrap(), Field::new(3));
        assert_eq!(mle.evaluate(&[one, one]).unwrap(), Field::new(4));
    }

    #[test]
    fn midpoint_matches_manual() {
        let mle = Mle::new(vec![
            Field::ONE,
            Field::new(2),
            Field::new(3),
            Field::new(4),
        ])
        .unwrap();
        let half = Field::new(2).inv(); // 1/2
                                        // (1+2+3+4)/4 = 10/4 = 5/2.
        let expected = Field::new(5) * half;
        assert_eq!(mle.evaluate(&[half, half]).unwrap(), expected);
        assert!(mle.evaluate(&[]).is_err());
    }

    #[test]
    fn eq_sums_to_one_and_symmetric() {
        let mut seed = 0x1234_5678_8765_4321u64;
        let r: Vec<Field> = (0..4)
            .map(|_| Field::from_u64(crate::gf2::splitmix64(&mut seed)))
            .collect();
        let s: Vec<Field> = (0..4)
            .map(|_| Field::from_u64(crate::gf2::splitmix64(&mut seed)))
            .collect();
        let eq_r = Mle::eq_evals(&r);
        assert_eq!(eq_r.sum(), Field::ONE);
        let left = eq_r.evaluate(&s).unwrap();
        let right = Mle::eq_evals(&s).evaluate(&r).unwrap();
        assert_eq!(left, right);
        // Direct formula check.
        let mut direct = Field::ONE;
        for (ri, si) in r.iter().zip(&s) {
            direct *= *ri * *si + (Field::ONE - *ri) * (Field::ONE - *si);
        }
        assert_eq!(left, direct);
    }

    #[test]
    fn fix_last_halves() {
        let mle = Mle::new(vec![
            Field::ONE,
            Field::new(2),
            Field::new(3),
            Field::new(4),
        ])
        .unwrap();
        let folded = mle.fix_last(Field::ZERO);
        assert_eq!(folded.evals(), &[Field::ONE, Field::new(3)]);
        assert_eq!(folded.n_vars(), 1);
    }
}
