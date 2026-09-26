//! Hiding layer: mask committed polynomials with random multiples of the
//! trace-domain vanishing polynomial.
//!
//! For base-domain size `n` with vanishing polynomial `Z_H(x) = x^n - 1`,
//! [`mask_coeffs`] maps coefficients `T` (degree `< n`) to
//! `M(x) = T(x) + Z_H(x) * R(x)` with fresh random `R` of degree `< n_rand`.
//! Because `Z_H` is zero on every base row, masked and unmasked columns
//! agree on the trace, so every AIR quotient stays exact and low-degree;
//! off-domain (at LDE query points) the mask term is nonzero and, with
//! `n_rand >= num_queries`, the per-column query responses are jointly
//! uniform and independent of the witness (Vandermonde surjectivity over
//! distinct off-domain points), giving perfect hiding of query responses.
//! Merkle roots remain computationally hiding under SHA3-256.
//!
//! Scope: this blinds STARK trace/column commitments ([`crate::air`],
//! [`crate::range`], and later [`crate::fold`]). [`crate::lookup`] and
//! [`crate::sumcheck`] still expose full tables and are not hiding.

use crate::babybear::Field;
use crate::error::{Error, Result};
use crate::rng::ChaCha20;

/// Mask coefficients with a random multiple of `x^n - 1`.
///
/// `coeffs` must have length `<= n` (base interpolant); `n` must be a power
/// of two. Returns `M = T + Z_H * R` padded to a power of two, where `R` has
/// `n_rand` uniform coefficients drawn from `rng`. `n_rand == 0` returns the
/// zero-padded clone (no hiding; useful for code-path sharing in tests).
///
/// # Errors
/// Returns [`Error::MalformedInput`] when `coeffs` is longer than `n`, and
/// [`Error::InvalidDomainSize`] for non-power-of-two `n`.
pub fn mask_coeffs(
    coeffs: &[Field],
    n: usize,
    n_rand: usize,
    rng: &mut ChaCha20,
) -> Result<Vec<Field>> {
    if !n.is_power_of_two() || n == 0 {
        return Err(Error::InvalidDomainSize { size: n });
    }
    if coeffs.len() > n {
        return Err(Error::MalformedInput {
            reason: "coefficients longer than base domain",
        });
    }
    // Random R of degree `< n_rand`: uniform field elements from the stream.
    let random: Vec<Field> = (0..n_rand).map(|_| rng.next_field()).collect();
    // `Z_H * R` with `Z_H = x^n - 1` is a shift-and-subtract (sparse).
    let mut masked = vec![Field::ZERO; n + n_rand];
    for (i, &c) in coeffs.iter().enumerate() {
        masked[i] += c;
    }
    for (i, &r) in random.iter().enumerate() {
        masked[i + n] += r;
        masked[i] -= r;
    }
    // Power-of-two length for the NTT backend (zero padding is exact).
    masked.resize(masked.len().next_power_of_two(), Field::ZERO);
    Ok(masked)
}

/// Maximum formal degree of a masked length-`n` column with `n_rand` maskers.
#[must_use]
pub const fn masked_column_degree(n: usize, n_rand: usize) -> usize {
    n + n_rand - 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntt::evaluate;

    fn test_rng() -> ChaCha20 {
        ChaCha20::new([42u8; 32], [7u8; 12])
    }

    #[test]
    fn rejects_bad_shapes() {
        let mut rng = test_rng();
        assert!(mask_coeffs(&[Field::ONE; 4], 3, 2, &mut rng).is_err());
        assert!(mask_coeffs(&[Field::ONE; 5], 4, 2, &mut rng).is_err());
    }

    #[test]
    fn agrees_on_base_domain() {
        // Masked and unmasked polys agree at every n-th root of unity.
        let n = 8;
        let coeffs = vec![Field::new(3), Field::new(5), Field::ONE];
        let mut rng = test_rng();
        let masked = mask_coeffs(&coeffs, n, 4, &mut rng).unwrap();
        let omega = Field::primitive_root(n).unwrap();
        let mut point = Field::ONE;
        for _ in 0..n {
            assert_eq!(evaluate(&coeffs, point), evaluate(&masked, point));
            point *= omega;
        }
    }

    #[test]
    fn randomizes_off_domain() {
        let n = 8;
        let coeffs = vec![Field::new(3), Field::new(5)];
        let probe = Field::new(123_456);
        let plain = evaluate(&coeffs, probe);
        let mut rng = test_rng();
        let masked = mask_coeffs(&coeffs, n, 4, &mut rng).unwrap();
        assert_ne!(evaluate(&masked, probe), plain);
        // Fresh randomness gives a fresh mask.
        let masked2 = mask_coeffs(&coeffs, n, 4, &mut rng).unwrap();
        assert_ne!(evaluate(&masked, probe), evaluate(&masked2, probe));
    }

    #[test]
    fn empty_mask_is_transparent() {
        let coeffs = vec![Field::new(9), Field::new(2)];
        let mut rng = test_rng();
        let masked = mask_coeffs(&coeffs, 4, 0, &mut rng).unwrap();
        assert_eq!(
            &masked,
            &[Field::new(9), Field::new(2), Field::ZERO, Field::ZERO]
        );
    }

    #[test]
    fn degree_and_length() {
        let coeffs = vec![Field::ONE; 16];
        let mut rng = test_rng();
        let masked = mask_coeffs(&coeffs, 16, 8, &mut rng).unwrap();
        assert_eq!(masked.len(), 32);
        assert!(masked.len().is_power_of_two());
    }
}
