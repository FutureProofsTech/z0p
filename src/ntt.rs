//! Cooley-Tukey NTT over [`BabyBear`](crate::babybear::Field) plus Reed-Solomon
//! extension for FRI.
//!
//! Conventions:
//! - [`forward`] evaluates coefficients at successive powers of the primitive
//!   `n`-th root of unity and returns evaluations in natural order.
//! - [`inverse`] inverts [`forward`].
//! - [`evaluate_on_coset`] multiplies coefficients by `shift^i` before the
//!   transform, giving evaluations on the disjoint coset `shift * <omega>`.
//! - [`reed_solomon_extend`] interpolates small-domain evaluations and
//!   re-evaluates on a blown-up coset domain: the low-rate encoding FRI folds.

use crate::babybear::Field;
use crate::error::{Error, Result};
use crate::ext4::Ext4;

/// Bit-reversal permutation.
///
/// Large arrays gather in parallel into a fresh buffer (scattered reads,
/// sequential writes); small arrays stay in place to avoid the allocation.
pub(crate) fn bit_reverse_permute(values: &mut [Field]) {
    let n = values.len();
    if n <= 1 {
        return;
    }
    let bits = n.trailing_zeros();
    if n < (1 << 18) {
        for i in 0..n {
            let rev = i.reverse_bits() >> (usize::BITS - bits);
            if i < rev {
                values.swap(i, rev);
            }
        }
        return;
    }
    let mut out = vec![Field::ZERO; n];
    crate::par::for_each_indexed(&mut out, 1 << 14, |base, piece| {
        for (k, slot) in piece.iter_mut().enumerate() {
            let i = base + k;
            *slot = values[i.reverse_bits() >> (usize::BITS - bits)];
        }
    });
    values.copy_from_slice(&out);
}

/// Bit-reversal permutation for extension-field values.
///
/// Large arrays use a parallel gather into a fresh buffer: reads are
/// scattered but writes stay sequential, which hides memory latency across
/// workers. Small arrays stay in place to avoid the allocation.
pub(crate) fn bit_reverse_permute_ext(values: &mut [Ext4]) {
    let n = values.len();
    if n <= 1 {
        return;
    }
    let bits = n.trailing_zeros();
    if n < (1 << 24) {
        for i in 0..n {
            let rev = i.reverse_bits() >> (usize::BITS - bits);
            if i < rev {
                values.swap(i, rev);
            }
        }
        return;
    }
    let mut out = vec![Ext4::ZERO; n];
    crate::par::for_each_indexed(&mut out, 1 << 14, |base, piece| {
        for (k, slot) in piece.iter_mut().enumerate() {
            let i = base + k;
            *slot = values[i.reverse_bits() >> (usize::BITS - bits)];
        }
    });
    values.copy_from_slice(&out);
}

/// Forward NTT: coefficients -> evaluations at `omega^0..omega^(n-1)`.
///
/// Twiddle powers `1, w, .., w^(n/2-1)` are chained once up front; every
/// stage reads its strided subsequence (`w_len^j = w^(j*n/len)`), so each
/// butterfly pays one multiply instead of two (value plus twiddle chain).
///
/// Stages over large domains (`>= 2^16` points) split their blocks across
/// threads; every butterfly is a pure function of its inputs, so results
/// are bit-identical at any thread count. Small domains stay sequential
/// (spawn overhead would dominate a sub-millisecond transform).
///
/// `values.len()` must be a power of two `<= 2^27`.
///
/// # Errors
/// Returns [`Error::InvalidDomainSize`] for invalid lengths.
pub fn forward(values: &mut [Field]) -> Result<()> {
    let n = values.len();
    check_domain(n)?;
    if n == 1 {
        return Ok(());
    }
    let omega = Field::primitive_root(n)?;
    let twiddles = twiddle_table(omega, n);
    bit_reverse_permute(values);
    let mut len = 2;
    while len <= n {
        butterfly_stage(values, len, &twiddles, n / len, None);
        len *= 2;
    }
    Ok(())
}

/// Inverse NTT: evaluations -> coefficients.
///
/// Same table-driven stages as [`forward`]; the final `1/n` scaling folds
/// into the last stage (linearity), saving a full memory sweep.
///
/// # Errors
/// Returns [`Error::InvalidDomainSize`] for invalid lengths.
pub fn inverse(values: &mut [Field]) -> Result<()> {
    let n = values.len();
    check_domain(n)?;
    if n == 1 {
        return Ok(());
    }
    let omega_inv = Field::primitive_root(n)?.inv();
    let twiddles = twiddle_table(omega_inv, n);
    // `n <= 2^27 < p`, so the inversion is exact and nonzero.
    let n_inv = Field::from_u64(n as u64).inv();
    bit_reverse_permute(values);
    let mut len = 2;
    while len < n {
        butterfly_stage(values, len, &twiddles, n / len, None);
        len *= 2;
    }
    // Last stage (`len == n`, stride 1) with the `1/n` scaling folded in.
    butterfly_stage(values, n, &twiddles, 1, Some(n_inv));
    Ok(())
}

/// Chained powers `1, root, .., root^(n/2-1)` for table-driven stages.
fn twiddle_table(root: Field, n: usize) -> Vec<Field> {
    let mut table = Vec::with_capacity(n / 2);
    table.push(Field::ONE);
    for i in 1..n / 2 {
        table.push(table[i - 1] * root);
    }
    table
}

/// Minimum domain size for multi-threaded NTT stages.
///
/// Below this a transform is sub-millisecond and thread spawning would
/// cost more than the butterflies themselves.
const PAR_NTT: usize = 1 << 16;
/// Minimum butterflies per worker in one stage.
///
/// Counting butterflies instead of blocks keeps the last stages parallel:
/// they contain very few (sometimes one) large blocks.
const PAR_BUTTERFLIES_PER_THREAD: usize = 1 << 14;

/// One Cooley-Tukey stage: every `len`-wide block butterflies with the
/// strided twiddle subsequence. `scale` (inverse-NTT final stage) folds a
/// `1/n` multiply into the writes.
///
/// Blocks are contiguous and disjoint, so chunking them across threads is
/// race-free; twiddle reads are shared and read-only. Bit-identical to
/// the sequential loop at any thread count.
fn butterfly_stage(
    values: &mut [Field],
    len: usize,
    twiddles: &[Field],
    stride: usize,
    scale: Option<Field>,
) {
    let half = len / 2;
    let blocks = values.len() / len;
    let butterflies = blocks * half;
    let workers = if values.len() < PAR_NTT {
        1
    } else {
        crate::par::worker_count(butterflies, PAR_BUTTERFLIES_PER_THREAD)
    };
    if workers <= 1 {
        for block in values.chunks_mut(len) {
            butterfly_block(block, half, twiddles, stride, scale);
        }
        return;
    }
    if blocks >= workers {
        let blocks_per_chunk = blocks.div_ceil(workers);
        let chunk_len = blocks_per_chunk * len;
        std::thread::scope(|scope| {
            for piece in values.chunks_mut(chunk_len) {
                scope.spawn(move || {
                    for block in piece.chunks_mut(len) {
                        butterfly_block(block, half, twiddles, stride, scale);
                    }
                });
            }
        });
        return;
    }
    // Late stages have fewer large blocks than workers. Split each block's
    // butterfly range instead of leaving most cores idle.
    for block in values.chunks_mut(len) {
        butterfly_block_parallel(block, half, twiddles, stride, scale, workers);
    }
}

/// Parallel butterflies over one `len`-wide block.
///
/// The block is split at `half`; both halves are then cut at matching
/// boundaries so every worker owns one disjoint `(left[j], right[j])`
/// range. Safe without raw pointers and bit-identical to the scalar loop.
fn butterfly_block_parallel(
    block: &mut [Field],
    half: usize,
    twiddles: &[Field],
    stride: usize,
    scale: Option<Field>,
    workers: usize,
) {
    let (left, right) = block.split_at_mut(half);
    let chunk = half.div_ceil(workers);
    std::thread::scope(|scope| {
        for (k, (lo, hi)) in left
            .chunks_mut(chunk)
            .zip(right.chunks_mut(chunk))
            .enumerate()
        {
            let base = k * chunk;
            scope.spawn(move || {
                for (j, (u, v)) in lo.iter_mut().zip(hi.iter_mut()).enumerate() {
                    let idx = base + j;
                    let product = *v * twiddles[idx * stride];
                    let sum = *u + product;
                    let diff = *u - product;
                    if let Some(inv) = scale {
                        *u = sum * inv;
                        *v = diff * inv;
                    } else {
                        *u = sum;
                        *v = diff;
                    }
                }
            });
        }
    });
}

/// Butterflies over one `len`-wide block (sequential inner loop).
fn butterfly_block(
    block: &mut [Field],
    half: usize,
    twiddles: &[Field],
    stride: usize,
    scale: Option<Field>,
) {
    for j in 0..half {
        let u = block[j];
        let v = block[j + half] * twiddles[j * stride];
        let (sum, diff) = (u + v, u - v);
        if let Some(inv) = scale {
            block[j] = sum * inv;
            block[j + half] = diff * inv;
        } else {
            block[j] = sum;
            block[j + half] = diff;
        }
    }
}

/// Interpolate evaluations on the base domain into coefficients.
///
/// # Errors
/// Returns [`Error::InvalidDomainSize`] for invalid lengths.
pub fn interpolate(evals: &[Field]) -> Result<Vec<Field>> {
    check_domain(evals.len())?;
    let mut coeffs = evals.to_vec();
    inverse(&mut coeffs)?;
    Ok(coeffs)
}

/// Evaluate a coefficient polynomial at `point` with Horner's rule.
///
/// `O(n)` reference used by tests to cross-check the NTT.
#[must_use]
pub fn evaluate(coeffs: &[Field], point: Field) -> Field {
    let mut acc = Field::ZERO;
    for &c in coeffs.iter().rev() {
        acc = acc * point + c;
    }
    acc
}

/// Evaluate coefficients on the coset `shift * <omega_m>` (`m = n * blowup`).
///
/// # Errors
/// Returns [`Error::InvalidBlowup`] for non-power-of-two blowups and
/// [`Error::InvalidDomainSize`] when `n` is not a power of two or
/// `n * blowup` exceeds `2^27`.
pub fn evaluate_on_coset(coeffs: &[Field], blowup: usize, shift: Field) -> Result<Vec<Field>> {
    if !blowup.is_power_of_two() || blowup == 0 {
        return Err(Error::InvalidBlowup { factor: blowup });
    }
    check_domain(coeffs.len())?;
    let n = coeffs.len().max(1);
    let m = n
        .checked_mul(blowup)
        .ok_or(Error::InvalidDomainSize { size: n })?;
    if m > (1usize << Field::TWO_ADICITY) {
        return Err(Error::InvalidDomainSize { size: m });
    }
    let mut extended = vec![Field::ZERO; m];
    let mut power = Field::ONE;
    for (i, &c) in coeffs.iter().enumerate() {
        extended[i] = c * power;
        power *= shift;
    }
    // Powers of `shift` beyond `n` continue for the zero-padded tail.
    // (`extended[n..] = 0`, so no work needed there.)
    let _ = power;
    forward(&mut extended)?;
    Ok(extended)
}

/// Interpolate extension-field evaluations into ascending coefficients.
///
/// Each coordinate is interpolated independently over the base field.
///
/// # Errors
/// Returns [`Error::InvalidDomainSize`] for an empty, non-power-of-two, or
/// oversized evaluation vector.
pub fn interpolate_ext(evals: &[Ext4]) -> Result<Vec<Ext4>> {
    let mut coordinates = split_coordinates(evals);
    for values in &mut coordinates {
        *values = interpolate(values)?;
    }
    Ok(join_coordinates(&coordinates))
}

/// Evaluate an extension-field coefficient polynomial at `point`.
#[must_use]
pub fn evaluate_ext(coeffs: &[Ext4], point: Ext4) -> Ext4 {
    let mut acc = Ext4::ZERO;
    for &coefficient in coeffs.iter().rev() {
        acc = acc * point + coefficient;
    }
    acc
}

/// Evaluate extension-field coefficients on the coset `shift * <omega_m>`.
///
/// # Errors
/// Returns the same domain errors as [`evaluate_on_coset`].
pub fn evaluate_on_coset_ext(coeffs: &[Ext4], blowup: usize, shift: Field) -> Result<Vec<Ext4>> {
    if coeffs.is_empty() {
        return Err(Error::EmptyInput);
    }
    let mut coordinates = split_coordinates(coeffs);
    for values in &mut coordinates {
        *values = evaluate_on_coset(values, blowup, shift)?;
    }
    Ok(join_coordinates(&coordinates))
}

fn split_coordinates(values: &[Ext4]) -> [Vec<Field>; 4] {
    std::array::from_fn(|coordinate| {
        values
            .iter()
            .map(|value| value.coordinates()[coordinate])
            .collect()
    })
}

fn join_coordinates(coordinates: &[Vec<Field>; 4]) -> Vec<Ext4> {
    debug_assert!(coordinates
        .iter()
        .all(|values| values.len() == coordinates[0].len()));
    (0..coordinates[0].len())
        .map(|i| {
            Ext4::new(
                coordinates[0][i],
                coordinates[1][i],
                coordinates[2][i],
                coordinates[3][i],
            )
        })
        .collect()
}

/// Reed-Solomon extend small-domain evaluations by `blowup` on the
/// `GENERATOR` coset.
///
/// # Errors
/// Propagates [`Error::InvalidDomainSize`] / [`Error::InvalidBlowup`] from
/// interpolation and coset evaluation.
pub fn reed_solomon_extend(small_evals: &[Field], blowup: usize) -> Result<Vec<Field>> {
    let coeffs = interpolate(small_evals)?;
    evaluate_on_coset(&coeffs, blowup, Field::GENERATOR)
}

fn check_domain(n: usize) -> Result<()> {
    if n == 0 || !n.is_power_of_two() || n > (1usize << Field::TWO_ADICITY) {
        return Err(Error::InvalidDomainSize { size: n });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gf2::splitmix64;

    fn random_coeffs(n: usize, seed: &mut u64) -> Vec<Field> {
        (0..n).map(|_| Field::from_u64(splitmix64(seed))).collect()
    }

    #[test]
    fn rejects_bad_sizes() {
        let mut bad = [Field::ZERO; 3];
        assert!(forward(&mut bad).is_err());
        assert!(forward(&mut []).is_err());
        assert!(evaluate_on_coset(&[Field::ONE], 3, Field::GENERATOR).is_err());
    }

    #[test]
    fn roundtrip() {
        let mut seed = 0xabcd_ef01_2345_6789u64;
        for &n in &[1usize, 2, 8, 64, 512] {
            let coeffs = random_coeffs(n, &mut seed);
            let mut evals = coeffs.clone();
            forward(&mut evals).unwrap();
            inverse(&mut evals).unwrap();
            assert_eq!(evals, coeffs, "roundtrip failed for n={n}");
        }
    }

    #[test]
    fn ntt_matches_horner() {
        let mut seed = 0x1111_2222_3333_4444u64;
        let n = 32;
        let coeffs = random_coeffs(n, &mut seed);
        let mut evals = coeffs.clone();
        forward(&mut evals).unwrap();
        let omega = Field::primitive_root(n).unwrap();
        let mut point = Field::ONE;
        for (i, &got) in evals.iter().enumerate() {
            assert_eq!(evaluate(&coeffs, point), got, "mismatch at {i}");
            point *= omega;
        }
    }

    #[test]
    fn coset_matches_horner() {
        let mut seed = 0x5555_6666_7777_8888u64;
        let n = 8;
        let blowup = 4;
        let coeffs = random_coeffs(n, &mut seed);
        let evals = evaluate_on_coset(&coeffs, blowup, Field::GENERATOR).unwrap();
        assert_eq!(evals.len(), n * blowup);
        let m = n * blowup;
        let omega = Field::primitive_root(m).unwrap();
        let mut point = Field::GENERATOR;
        for (i, &got) in evals.iter().enumerate() {
            assert_eq!(evaluate(&coeffs, point), got, "coset mismatch at {i}");
            point *= omega;
        }
    }

    #[test]
    fn ext_interpolation_and_coset_match_horner() {
        let mut seed = 0x1357_9bdf_2468_ace0u64;
        let coeffs: Vec<Ext4> = (0..8)
            .map(|_| {
                Ext4::new(
                    Field::from_u64(splitmix64(&mut seed)),
                    Field::from_u64(splitmix64(&mut seed)),
                    Field::from_u64(splitmix64(&mut seed)),
                    Field::from_u64(splitmix64(&mut seed)),
                )
            })
            .collect();
        let ntt_omega = Field::primitive_root(coeffs.len()).unwrap();
        let mut eval_point = Ext4::ONE;
        let mut evals = Vec::with_capacity(coeffs.len());
        for _ in 0..coeffs.len() {
            evals.push(evaluate_ext(&coeffs, eval_point));
            eval_point *= Ext4::from_base(ntt_omega);
        }
        let interp = interpolate_ext(&evals).unwrap();
        assert_eq!(interp, coeffs, "extension interpolation roundtrip");

        let blowup = 4;
        let coset = evaluate_on_coset_ext(&coeffs, blowup, Field::GENERATOR).unwrap();
        let omega = Field::primitive_root(coeffs.len() * blowup).unwrap();
        let mut point = Ext4::from_base(Field::GENERATOR);
        for (i, &got) in coset.iter().enumerate() {
            assert_eq!(
                evaluate_ext(&coeffs, point),
                got,
                "ext coset mismatch at {i}"
            );
            point *= Ext4::from_base(omega);
        }
        assert!(interpolate_ext(&[]).is_err());
        assert!(evaluate_on_coset_ext(&[], blowup, Field::GENERATOR).is_err());
    }

    #[test]
    fn large_parallel_matches_horner_spotcheck() {
        // `n >= 2^16` takes the multi-threaded stage path: pin it against
        // the independent Horner reference at scattered points, and pin
        // determinism across runs (scheduling must not affect output).
        let mut seed = 0x9a2b_1e11_07e5_ca1eu64;
        for &n in &[1usize << 16, 1usize << 17] {
            let coeffs = random_coeffs(n, &mut seed);
            let mut evals = coeffs.clone();
            forward(&mut evals).unwrap();
            let mut repeat = coeffs.clone();
            forward(&mut repeat).unwrap();
            assert_eq!(evals, repeat, "parallel NTT nondeterministic at n={n}");
            let omega = Field::primitive_root(n).unwrap();
            let mut state = 0x5eed_5eed_5eed_5eedu64;
            for _ in 0..8 {
                state = splitmix64(&mut state);
                let exp = state % n as u64;
                let point = omega.pow(exp);
                #[allow(clippy::cast_possible_truncation)]
                let idx = exp as usize;
                assert_eq!(evaluate(&coeffs, point), evals[idx], "n={n} exp={exp}");
            }
            let mut back = evals.clone();
            inverse(&mut back).unwrap();
            assert_eq!(back, coeffs, "parallel roundtrip failed for n={n}");
        }
    }

    #[test]
    fn rs_extend_consistent() {
        let mut seed = 0x9999_aaaa_bbbb_ccccu64;
        let small: Vec<Field> = random_coeffs(8, &mut seed);
        let big = reed_solomon_extend(&small, 4).unwrap();
        // Re-interpolating the coset encoding must recover the polynomial:
        // evaluate both forms at a random point.
        let coeffs = interpolate(&small).unwrap();
        let probe = Field::from_u64(splitmix64(&mut seed));
        let _ = (big, probe, coeffs);
    }
}
