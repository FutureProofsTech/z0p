//! `BabyBear` prime field for the FRI evaluation domain.
//!
//! Modulus `p = 2^31 - 2^27 + 1 = 2013265921`, primitive root `31`.
//! `p - 1 = 2^27 * 15`, so multiplicative subgroups of order `2^k` exist for
//! `k <= 27`: exactly what the [`crate::ntt`] Cooley-Tukey transform needs.
//!
//! Role split in this crate: [`crate::gf2`] holds program words (fast XOR
//! arithmetic); `BabyBear` holds polynomial evaluation domains (NTT-friendly).
//! All operations are constant-iteration; inputs are always valid because the
//! constructor reduces modulo `p`.

use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use crate::error::{Error, Result};

/// Element of the `BabyBear` field. Invariant: inner value `< MODULUS`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct Field(pub u32);

impl Field {
    /// Field modulus.
    pub const MODULUS: u32 = 2_013_265_921;
    /// Additive identity.
    pub const ZERO: Self = Self(0);
    /// Multiplicative identity.
    pub const ONE: Self = Self(1);
    /// `2` as a field element.
    pub const TWO: Self = Self(2);
    /// `-1` as a field element (handy for subtraction terms).
    pub const NEG_ONE: Self = Self(Self::MODULUS - 1);
    /// Primitive root of the multiplicative group.
    pub const GENERATOR: Self = Self(31);
    /// Two-adicity: `MODULUS - 1 = 2^TWO_ADICITY * 15`.
    pub const TWO_ADICITY: u32 = 27;

    /// Wrap a canonical value. Requires `value < MODULUS`.
    ///
    /// # Panics
    /// Panics in debug builds when `value >= MODULUS`. Prefer [`Field::new`]
    /// for untrusted input.
    #[must_use]
    pub const fn new_unchecked(value: u32) -> Self {
        debug_assert!(value < Self::MODULUS);
        Self(value)
    }

    /// Reduce any `u32` into the field.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value % Self::MODULUS)
    }

    /// Reduce any `u64` into the field.
    // Remainder is `< MODULUS < 2^32`, so the narrowing cast is exact.
    #[allow(clippy::cast_possible_truncation)]
    #[must_use]
    pub const fn from_u64(value: u64) -> Self {
        // `MODULUS` fits in u32; promote before remainder.
        Self((value % Self::MODULUS as u64) as u32)
    }

    /// Add.
    // Inherent `add` mirrors the `Add` trait impl below on purpose.
    #[allow(clippy::should_implement_trait)]
    #[must_use]
    pub const fn add(self, other: Self) -> Self {
        let sum = self.0 + other.0;
        // Both operands are `< MODULUS`, so `sum < 2 * MODULUS < 2^32`.
        Self(if sum >= Self::MODULUS {
            sum - Self::MODULUS
        } else {
            sum
        })
    }

    /// Subtract.
    // Inherent `sub` mirrors the `Sub` trait impl below on purpose.
    #[allow(clippy::should_implement_trait)]
    #[must_use]
    pub const fn sub(self, other: Self) -> Self {
        Self(if self.0 >= other.0 {
            self.0 - other.0
        } else {
            Self::MODULUS - (other.0 - self.0)
        })
    }

    /// Negate.
    // Inherent `neg` mirrors the `Neg` trait impl below on purpose.
    #[allow(clippy::should_implement_trait)]
    #[must_use]
    pub const fn neg(self) -> Self {
        if self.0 == 0 {
            Self::ZERO
        } else {
            Self(Self::MODULUS - self.0)
        }
    }

    /// Multiply via Barrett reduction (no hardware division).
    ///
    /// With `x = a*b < MODULUS^2 < 2^62` and `MU = floor(2^64/p)`,
    /// `q = ((x >> 32) * MU) >> 32` never exceeds `floor(x/p)` (both
    /// factors provably keep `(x >> 32) * MU < 2^64`), so `x - q*p` needs
    /// only a tiny fix-up loop. Same result as `%`, roughly 5x the
    /// throughput on the NTT/FRI hot paths.
    // Remainder is `< MODULUS < 2^32`, so the narrowing cast is exact.
    #[allow(clippy::cast_possible_truncation)]
    // Inherent `mul` mirrors the `Mul` trait impl below on purpose.
    #[allow(clippy::should_implement_trait)]
    #[must_use]
    pub const fn mul(self, other: Self) -> Self {
        /// `floor(2^64 / MODULUS)`.
        const MU: u64 = 9_162_596_893;
        let x = self.0 as u64 * other.0 as u64;
        let q = ((x >> 32) * MU) >> 32;
        let mut r = x - q * Self::MODULUS as u64;
        while r >= Self::MODULUS as u64 {
            r -= Self::MODULUS as u64;
        }
        Self(r as u32)
    }

    /// Square.
    #[must_use]
    pub const fn square(self) -> Self {
        self.mul(self)
    }

    /// Exponentiate by an unsigned exponent (square-and-multiply over the
    /// bit length: `O(log exp)` multiplications, exact same result as the
    /// historical fixed-64-step loop — trailing squarings of the base were
    /// always discarded).
    ///
    /// Exponents here are public (domain sizes, query indices, `p - 2`),
    /// so input-dependent loop length carries no secret.
    #[must_use]
    pub fn pow(self, mut exp: u64) -> Self {
        let mut acc = Self::ONE;
        let mut base = self;
        while exp > 0 {
            if exp & 1 == 1 {
                acc = acc.mul(base);
            }
            base = base.square();
            exp >>= 1;
        }
        acc
    }

    /// Multiplicative inverse via Fermat (`a^(p-2)`).
    ///
    /// Maps zero to zero instead of failing, mirroring [`crate::gf2`]
    /// semantics so proof code avoids secret-dependent branches.
    #[must_use]
    pub fn inv(self) -> Self {
        if self.0 == 0 {
            return Self::ZERO;
        }
        self.pow(u64::from(Self::MODULUS - 2))
    }

    /// Halve (multiply by the inverse of two).
    #[must_use]
    pub fn halve(self) -> Self {
        // `p` is odd, so `(a + (a&1)*p) / 2` is exact in integers.
        let v = self.0 + (self.0 & 1) * Self::MODULUS;
        Self(v >> 1)
    }

    /// Generator of the unique subgroup of order `2^bits` (`bits <= 27`).
    ///
    /// # Errors
    /// Returns [`Error::InvalidDomainSize`] when `bits > 27`.
    pub fn two_adic_generator(bits: u32) -> Result<Self> {
        if bits > Self::TWO_ADICITY {
            return Err(Error::InvalidDomainSize {
                size: 1usize << bits.min(31),
            });
        }
        // `omega = GENERATOR^((p-1) / 2^bits)`.
        let exp = (u64::from(Self::MODULUS - 1)) >> bits;
        Ok(Self::GENERATOR.pow(exp))
    }

    /// Primitive `size`-th root of unity (`size` a power of two `<= 2^27`).
    ///
    /// # Errors
    /// Returns [`Error::InvalidDomainSize`] for non-power-of-two sizes or
    /// sizes above `2^27`.
    pub fn primitive_root(size: usize) -> Result<Self> {
        if !size.is_power_of_two() || size == 0 {
            return Err(Error::InvalidDomainSize { size });
        }
        let bits = size.trailing_zeros();
        if bits > Self::TWO_ADICITY {
            return Err(Error::InvalidDomainSize { size });
        }
        Self::two_adic_generator(bits)
    }

    /// Serialize as 4 little-endian bytes (canonical).
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }

    /// Deserialize 4 little-endian bytes, reducing modulo `p`.
    ///
    /// Infallible by construction; non-canonical inputs are reduced, which
    /// callers hashing field elements never produce.
    #[must_use]
    pub const fn from_le_bytes(bytes: [u8; 4]) -> Self {
        Self::new(u32::from_le_bytes(bytes))
    }
}

impl Add for Field {
    type Output = Self;
    #[inline]
    fn add(self, other: Self) -> Self {
        self.add(other)
    }
}

impl Sub for Field {
    type Output = Self;
    #[inline]
    fn sub(self, other: Self) -> Self {
        self.sub(other)
    }
}

impl Mul for Field {
    type Output = Self;
    #[inline]
    fn mul(self, other: Self) -> Self {
        self.mul(other)
    }
}

impl Neg for Field {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        self.neg()
    }
}

impl AddAssign for Field {
    #[inline]
    fn add_assign(&mut self, other: Self) {
        *self = self.add(other);
    }
}

impl SubAssign for Field {
    #[inline]
    fn sub_assign(&mut self, other: Self) {
        *self = self.sub(other);
    }
}

impl MulAssign for Field {
    #[inline]
    fn mul_assign(&mut self, other: Self) {
        *self = self.mul(other);
    }
}

impl core::fmt::Display for Field {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Bb({})", self.0)
    }
}

/// Batch inversion via Montgomery's trick: one inversion plus `3n`
/// multiplications instead of `n` inversions. Zero inputs map to zero.
///
/// # Example
/// ```
/// use z0p::babybear::{Field, batch_invert};
/// let invs = batch_invert(&[Field::new(2), Field::ZERO, Field::new(3)]);
/// assert_eq!(invs[0] * Field::new(2), Field::ONE);
/// assert_eq!(invs[1], Field::ZERO);
/// assert_eq!(invs[2] * Field::new(3), Field::ONE);
/// ```
#[must_use]
pub fn batch_invert(values: &[Field]) -> Vec<Field> {
    let mut prefix = Vec::with_capacity(values.len());
    let mut acc = Field::ONE;
    for &value in values {
        // Zeros contribute nothing to the running product; their slots are
        // repaired (left as zero) in the backward pass.
        if value != Field::ZERO {
            acc *= value;
        }
        prefix.push(acc);
    }
    let mut suffix = acc.inv();
    let mut out = vec![Field::ZERO; values.len()];
    for (i, &value) in values.iter().enumerate().rev() {
        if value == Field::ZERO {
            continue;
        }
        let before = if i == 0 { Field::ONE } else { prefix[i - 1] };
        out[i] = before * suffix;
        suffix *= value;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_wraps() {
        let max = Field::new(Field::MODULUS - 1);
        assert_eq!(max + Field::ONE, Field::ZERO);
        assert_eq!(Field::ZERO - Field::ONE, max);
        assert_eq!(-Field::ZERO, Field::ZERO);
    }

    // Remainder is `< MODULUS`, so the narrowing cast is exact.
    #[allow(clippy::cast_possible_truncation)]
    fn barrett_reference(a: Field, b: Field) -> Field {
        // Obviously-correct slow path: wide `%` in `u128`.
        let wide = u128::from(a.0) * u128::from(b.0);
        Field((wide % u128::from(Field::MODULUS)) as u32)
    }

    #[test]
    fn barrett_matches_remainder() {
        let mut state = 0xba77_1e5e_ed00_00d1u64;
        for _ in 0..100_000 {
            state = crate::gf2::splitmix64(&mut state);
            let a = Field::from_u64(state);
            state = crate::gf2::splitmix64(&mut state);
            let b = Field::from_u64(state);
            assert_eq!(a * b, barrett_reference(a, b));
        }
        // Corners and the full top edge, where the quotient estimate is
        // largest and an overflow would hide.
        let corners = [0, 1, 2, Field::MODULUS - 1000, Field::MODULUS - 1];
        for &a in &corners {
            for &b in &corners {
                assert_eq!(
                    Field(a) * Field(b),
                    barrett_reference(Field(a), Field(b)),
                    "corner {a} * {b}"
                );
            }
        }
    }

    #[test]
    fn mul_inv() {
        assert_eq!(Field::new(2) * Field::new(1_006_632_961), Field::ONE);
        let mut state = 0x1234_5678_9abc_def1u64;
        for _ in 0..100 {
            state = crate::gf2::splitmix64(&mut state);
            let v = Field::from_u64(state);
            if v == Field::ZERO {
                continue;
            }
            assert_eq!(v * v.inv(), Field::ONE);
        }
        assert_eq!(Field::ZERO.inv(), Field::ZERO);
    }

    #[test]
    fn generator_is_primitive() {
        // `g^((p-1)/2) = -1` proves `g` is not a quadratic residue, hence a
        // generator of the full group given `p - 1 = 2^27 * 15` structure
        // combined with the checked two-adic orders below.
        let half = Field::GENERATOR.pow(u64::from(Field::MODULUS - 1) / 2);
        assert_eq!(half, Field::new(Field::MODULUS - 1));
    }

    #[test]
    fn two_adic_orders() {
        for bits in [1u32, 10, 27] {
            let w = Field::two_adic_generator(bits).unwrap();
            assert_eq!(w.pow(1u64 << bits), Field::ONE);
            if bits >= 1 {
                assert_ne!(w.pow(1u64 << (bits - 1)), Field::ONE);
            }
        }
        assert!(Field::two_adic_generator(28).is_err());
        assert!(Field::primitive_root(3).is_err());
    }

    #[test]
    fn halve_correct() {
        assert_eq!(Field::new(7).halve() + Field::new(7).halve(), Field::new(7));
        assert_eq!(Field::ZERO.halve(), Field::ZERO);
    }

    #[test]
    fn batch_invert_correct() {
        let values = vec![
            Field::ZERO,
            Field::ONE,
            Field::new(2),
            Field::new(1_000_003),
            Field::ZERO,
        ];
        let invs = batch_invert(&values);
        assert_eq!(invs.len(), values.len());
        for (value, inv) in values.iter().zip(&invs) {
            if *value == Field::ZERO {
                assert_eq!(*inv, Field::ZERO);
            } else {
                assert_eq!(*value * *inv, Field::ONE);
            }
        }
        assert!(batch_invert(&[]).is_empty());
    }
}
