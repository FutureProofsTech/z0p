//! Quartic extension of the `BabyBear` field.
//!
//! Challenges drawn from this field carry roughly 124 bits of algebraic
//! entropy instead of the 31 bits available in the base field. The
//! construction is a tower:
//!
//! ```text
//! F_p2 = F_p[u] / (u^2 - 11)
//! F_p4 = F_p2[v] / (v^2 - u)
//! ```
//!
//! `11` is a quadratic non-residue in `F_p`, and `u` is a non-square in
//! `F_p2`, so both steps are field extensions. An element is stored as
//! `a + b u + c v + d u v` with `[a, b, c, d]` coordinates in [`Field`].
//!
//! All operations are infallible and allocation-free. `inv(0)` maps to zero,
//! matching the base-field and binary-field conventions.

use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use crate::babybear::Field;

/// Quadratic non-residue defining `F_p2 = F_p[u]/(u^2 - 11)`.
const NONRESIDUE: Field = Field::new(11);

/// Multiplicative group order `p^4 - 1`.
const GROUP_ORDER: u128 = {
    let p = Field::MODULUS as u128;
    p * p * p * p - 1
};

/// Element of `F_{p^4}` as `a + b u + c v + d u v`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct Ext4([Field; 4]);

impl Ext4 {
    /// Additive identity.
    pub const ZERO: Self = Self([Field::ZERO; 4]);
    /// Multiplicative identity.
    pub const ONE: Self = Self([Field::ONE, Field::ZERO, Field::ZERO, Field::ZERO]);

    /// Build an element from its four coordinates.
    #[must_use]
    pub const fn new(a: Field, b: Field, c: Field, d: Field) -> Self {
        Self([a, b, c, d])
    }

    /// Embed a base-field element.
    #[must_use]
    pub const fn from_base(value: Field) -> Self {
        Self([value, Field::ZERO, Field::ZERO, Field::ZERO])
    }

    /// The four base-field coordinates.
    #[must_use]
    pub const fn coordinates(self) -> [Field; 4] {
        self.0
    }

    /// Return the base-field value when the upper coordinates are zero.
    #[must_use]
    pub fn try_to_base(self) -> Option<Field> {
        if self.0[1] == Field::ZERO && self.0[2] == Field::ZERO && self.0[3] == Field::ZERO {
            Some(self.0[0])
        } else {
            None
        }
    }

    /// Halve every coordinate (multiply by `2^-1` in the base field).
    #[must_use]
    pub fn halve(self) -> Self {
        Self(self.0.map(Field::halve))
    }

    /// Test for zero.
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.0 == [Field::ZERO; 4]
    }

    /// Add.
    // Inherent `add` mirrors the `Add` trait impl below on purpose.
    #[allow(clippy::should_implement_trait)]
    #[must_use]
    pub fn add(self, other: Self) -> Self {
        Self(std::array::from_fn(|i| self.0[i] + other.0[i]))
    }

    /// Subtract.
    // Inherent `sub` mirrors the `Sub` trait impl below on purpose.
    #[allow(clippy::should_implement_trait)]
    #[must_use]
    pub fn sub(self, other: Self) -> Self {
        Self(std::array::from_fn(|i| self.0[i] - other.0[i]))
    }

    /// Negate.
    // Inherent `neg` mirrors the `Neg` trait impl below on purpose.
    #[allow(clippy::should_implement_trait)]
    #[must_use]
    pub fn neg(self) -> Self {
        Self(self.0.map(Field::neg))
    }

    /// Multiply.
    // Inherent `mul` mirrors the `Mul` trait impl below on purpose.
    #[allow(clippy::should_implement_trait)]
    #[must_use]
    pub fn mul(self, other: Self) -> Self {
        let a = [self.0[0], self.0[1]];
        let b = [other.0[0], other.0[1]];
        let c = [self.0[2], self.0[3]];
        let d = [other.0[2], other.0[3]];
        let ac = fp2_mul(a, b);
        let bd_u = fp2_mul_u(fp2_mul(c, d));
        Self([
            ac[0] + bd_u[0],
            ac[1] + bd_u[1],
            fp2_mul(a, d)[0] + fp2_mul(c, b)[0],
            fp2_mul(a, d)[1] + fp2_mul(c, b)[1],
        ])
    }

    /// Multiply by an embedded base-field scalar (four base multiplications).
    #[must_use]
    pub fn mul_base(self, scalar: Field) -> Self {
        Self(self.0.map(|value| value * scalar))
    }

    /// Square.
    #[must_use]
    pub fn square(self) -> Self {
        self.mul(self)
    }

    /// Exponentiate by a nonnegative integer exponent.
    ///
    /// Exponents in this crate are protocol parameters or the public field
    /// order, so the loop length is not secret.
    #[must_use]
    pub fn pow(self, mut exp: u128) -> Self {
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

    /// Multiplicative inverse via Fermat (`a^(p^4 - 2)`).
    ///
    /// Maps zero to zero, consistent with [`Field::inv`].
    #[must_use]
    pub fn inv(self) -> Self {
        if self.is_zero() {
            return Self::ZERO;
        }
        self.pow(GROUP_ORDER - 1)
    }

    /// Canonical 16-byte little-endian encoding (coordinates in order).
    #[must_use]
    pub fn to_le_bytes(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        for (chunk, value) in out.chunks_exact_mut(4).zip(self.0) {
            chunk.copy_from_slice(&value.to_le_bytes());
        }
        out
    }

    /// Decode 16 little-endian bytes, reducing each coordinate modulo `p`.
    #[must_use]
    pub fn from_le_bytes(bytes: [u8; 16]) -> Self {
        let mut coords = [Field::ZERO; 4];
        for (slot, chunk) in coords.iter_mut().zip(bytes.chunks_exact(4)) {
            let mut word = [0u8; 4];
            word.copy_from_slice(chunk);
            *slot = Field::from_le_bytes(word);
        }
        Self(coords)
    }
}

/// Multiply two `F_p2` elements `(a0 + a1 u)(b0 + b1 u)`.
#[inline]
fn fp2_mul(x: [Field; 2], y: [Field; 2]) -> [Field; 2] {
    [
        x[0] * y[0] + x[1] * y[1] * NONRESIDUE,
        x[0] * y[1] + x[1] * y[0],
    ]
}

/// Multiply an `F_p2` element by `u` (`u^2 = 11`).
#[inline]
fn fp2_mul_u(x: [Field; 2]) -> [Field; 2] {
    [x[1] * NONRESIDUE, x[0]]
}

impl From<Field> for Ext4 {
    fn from(value: Field) -> Self {
        Self::from_base(value)
    }
}

impl Add for Ext4 {
    type Output = Self;
    #[inline]
    fn add(self, other: Self) -> Self {
        self.add(other)
    }
}

impl Sub for Ext4 {
    type Output = Self;
    #[inline]
    fn sub(self, other: Self) -> Self {
        self.sub(other)
    }
}

impl Mul for Ext4 {
    type Output = Self;
    #[inline]
    fn mul(self, other: Self) -> Self {
        self.mul(other)
    }
}

impl Neg for Ext4 {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        self.neg()
    }
}

impl AddAssign for Ext4 {
    #[inline]
    fn add_assign(&mut self, other: Self) {
        *self = self.add(other);
    }
}

impl SubAssign for Ext4 {
    #[inline]
    fn sub_assign(&mut self, other: Self) {
        *self = self.sub(other);
    }
}

impl MulAssign for Ext4 {
    #[inline]
    fn mul_assign(&mut self, other: Self) {
        *self = self.mul(other);
    }
}

impl Mul<Field> for Ext4 {
    type Output = Self;
    #[inline]
    fn mul(self, other: Field) -> Self {
        Self(self.0.map(|value| value * other))
    }
}

impl Add<Field> for Ext4 {
    type Output = Self;
    #[inline]
    fn add(self, other: Field) -> Self {
        Self([self.0[0] + other, self.0[1], self.0[2], self.0[3]])
    }
}

impl Sub<Field> for Ext4 {
    type Output = Self;
    #[inline]
    fn sub(self, other: Field) -> Self {
        Self([self.0[0] - other, self.0[1], self.0[2], self.0[3]])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tower_axioms_and_roundtrip() {
        let eleven = Ext4::from_base(Field::new(11));
        let u = Ext4::new(Field::ZERO, Field::ONE, Field::ZERO, Field::ZERO);
        let v = Ext4::new(Field::ZERO, Field::ZERO, Field::ONE, Field::ZERO);
        assert_eq!(u.square(), eleven);
        assert_eq!(v.square(), u);

        let a = Ext4::new(Field::new(3), Field::new(5), Field::new(7), Field::new(11));
        let b = Ext4::new(
            Field::new(13),
            Field::new(17),
            Field::new(19),
            Field::new(23),
        );
        assert_eq!(a.mul(b), b.mul(a));
        assert_eq!(a.mul(Ext4::ONE), a);
        assert_eq!(a.add(b), b.add(a));
        assert_eq!(a.mul(a.add(b)), a.mul(a).add(a.mul(b)));
        assert_eq!(a.sub(a), Ext4::ZERO);
        assert_eq!(a.mul(a.inv()), Ext4::ONE);
        assert_eq!(Ext4::ZERO.inv(), Ext4::ZERO);
        assert_eq!(
            Ext4::from_base(Field::new(7)).try_to_base(),
            Some(Field::new(7))
        );
        assert_eq!(a.try_to_base(), None);
        assert_eq!(a.halve().add(a.halve()), a);
        assert_eq!(
            a.mul_base(Field::new(7)),
            a.mul(Ext4::from_base(Field::new(7)))
        );
        assert_eq!(Ext4::from_le_bytes(a.to_le_bytes()), a);
        assert_eq!(
            Ext4::from_le_bytes([0xff; 16]),
            Ext4::new(
                Field::new(u32::MAX),
                Field::new(u32::MAX),
                Field::new(u32::MAX),
                Field::new(u32::MAX)
            )
        );
    }
}
