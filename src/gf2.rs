//! Binary fields from zero. No dependencies, portable, constant-iteration.
//!
//! - [`F8`] = `GF(2^8)`, polynomial `x^8 + x^4 + x^3 + x + 1` (`0x11B`, AES).
//! - [`F64`] = `GF(2^64)`, polynomial `x^64 + x^4 + x^3 + x + 1`.
//! - [`F128`] = `GF(2^128)`, polynomial `x^128 + x^7 + x^2 + x + 1`.
//!
//! The word layer of the prover uses [`F64`]; challenges and extension values
//! use [`F128`]. Addition is XOR. Multiplication is carryless multiply plus
//! reduction. All arithmetic loops run a fixed number of iterations.
//!
//! Field operations are infallible by design: every `u64`/`u128` bit pattern is
//! a valid element, so there is no invalid input. [`F64::inv`] and
//! [`F128::inv`] map zero to zero (documented) instead of panicking.

use core::ops::{Add, Mul};

// ---------------------------------------------------------------- F8 ---

/// Element of `GF(2^8)` (AES polynomial).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct F8(pub u8);

impl F8 {
    /// Additive identity.
    pub const ZERO: Self = Self(0);
    /// Multiplicative identity.
    pub const ONE: Self = Self(1);

    /// Add two elements (XOR).
    ///
    /// # Example
    /// ```
    /// use z0p::gf2::F8;
    /// assert_eq!(F8(0x57).add(F8(0x83)), F8(0xd4));
    /// ```
    // Inherent `add` mirrors the `Add` trait impl below on purpose so callers
    // can use method syntax without importing the trait.
    #[allow(clippy::should_implement_trait)]
    #[must_use]
    #[inline]
    pub const fn add(self, other: Self) -> Self {
        Self(self.0 ^ other.0)
    }

    /// Multiply two elements (Russian peasant, fixed 8 iterations).
    ///
    /// # Example
    /// ```
    /// use z0p::gf2::F8;
    /// assert_eq!(F8(0x57).mul(F8(0x83)), F8(0xc1));
    /// ```
    // Inherent `mul` mirrors the `Mul` trait impl below on purpose.
    #[allow(clippy::should_implement_trait)]
    #[must_use]
    pub fn mul(self, other: Self) -> Self {
        let mut a = u16::from(self.0);
        let mut b = u16::from(other.0);
        let mut acc: u16 = 0;
        for _ in 0..8 {
            let mask = b.wrapping_neg() & 1;
            // `mask` is 0 or 1 extended: branchless conditional XOR.
            acc ^= a & (0u16.wrapping_sub(mask));
            let carry = (a >> 7) & 1;
            a <<= 1;
            a ^= 0x11b & 0u16.wrapping_sub(carry);
            b >>= 1;
        }
        // Reduction keeps the value inside 8 bits.
        #[allow(clippy::cast_possible_truncation)]
        Self(acc as u8)
    }
}

// --------------------------------------------------------------- F64 ---

/// Element of `GF(2^64)`, polynomial `x^64 + x^4 + x^3 + x + 1`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct F64(pub u64);

impl F64 {
    /// Additive identity.
    pub const ZERO: Self = Self(0);
    /// Multiplicative identity.
    pub const ONE: Self = Self(1);

    /// Wrap raw bits. Every `u64` is a valid element.
    #[must_use]
    #[inline]
    pub const fn new(x: u64) -> Self {
        Self(x)
    }

    /// Add two elements (XOR).
    // Inherent `add` mirrors the `Add` trait impl below on purpose.
    #[allow(clippy::should_implement_trait)]
    #[must_use]
    #[inline]
    pub const fn add(self, other: Self) -> Self {
        Self(self.0 ^ other.0)
    }

    /// Test for zero.
    #[must_use]
    #[inline]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Square.
    #[must_use]
    pub fn square(self) -> Self {
        Self::mul(self, self)
    }

    /// Multiply with carryless product reduced by the field polynomial.
    // Inherent `mul` mirrors the `Mul` trait impl below on purpose.
    #[allow(clippy::should_implement_trait)]
    #[must_use]
    pub fn mul(self, other: Self) -> Self {
        let (hi, lo) = clmul64(self.0, other.0);
        Self(reduce127(hi, lo))
    }

    /// Exponentiate by an unsigned exponent (square-and-multiply, 64 steps).
    #[must_use]
    pub fn pow(self, mut exp: u64) -> Self {
        let mut acc = Self::ONE;
        let mut base = self;
        for _ in 0..64 {
            let bit = exp & 1;
            let stepped = base.mul(acc);
            let mask = bit.wrapping_neg();
            acc = Self((acc.0 & !mask) | (stepped.0 & mask));
            base = base.square();
            exp >>= 1;
        }
        acc
    }

    /// Multiplicative inverse via Fermat (`a^(2^64 - 2)`).
    ///
    /// Maps zero to zero instead of failing, so callers in circuit code never
    /// branch on secret zero-ness. Documented, intentional.
    #[must_use]
    pub fn inv(self) -> Self {
        if self.is_zero() {
            return Self::ZERO;
        }
        // 2^64 - 2.
        self.pow(u64::MAX - 1)
    }

    /// Serialize as little-endian bytes.
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    /// Deserialize from little-endian bytes. Infallible: all patterns valid.
    #[must_use]
    pub const fn from_le_bytes(b: [u8; 8]) -> Self {
        Self(u64::from_le_bytes(b))
    }
}

impl Add for F64 {
    type Output = Self;
    #[inline]
    fn add(self, other: Self) -> Self {
        self.add(other)
    }
}

impl Mul for F64 {
    type Output = Self;
    #[inline]
    fn mul(self, other: Self) -> Self {
        self.mul(other)
    }
}

impl core::fmt::Display for F64 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "F64({:#018x})", self.0)
    }
}

/// Carryless 64x64-bit product as 128-bit `(hi, lo)`.
/// Fixed 64 iterations with a branchless mask.
fn clmul64(a: u64, b: u64) -> (u64, u64) {
    let mut hi: u64 = 0;
    let mut lo: u64 = 0;
    for i in 0..64 {
        let mask = 0u64.wrapping_sub((b >> i) & 1);
        let (sh_hi, sh_lo) = if i == 0 {
            (0u64, a)
        } else {
            (a >> (64 - i), a << i)
        };
        hi ^= sh_hi & mask;
        lo ^= sh_lo & mask;
    }
    (hi, lo)
}

#[inline]
const fn get128(hi: u64, lo: u64, i: u32) -> u64 {
    if i < 64 {
        (lo >> i) & 1
    } else {
        (hi >> (i - 64)) & 1
    }
}

#[inline]
fn xor128(hi: &mut u64, lo: &mut u64, i: u32) {
    if i < 64 {
        *lo ^= 1u64 << i;
    } else {
        *hi ^= 1u64 << (i - 64);
    }
}

#[inline]
fn clear128(hi: &mut u64, lo: &mut u64, i: u32) {
    if i < 64 {
        *lo &= !(1u64 << i);
    } else {
        *hi &= !(1u64 << (i - 64));
    }
}

/// Reduce 128-bit `(hi, lo)` modulo `x^64 + x^4 + x^3 + x + 1`.
///
/// Uses `x^64 = x^4 + x^3 + x + 1`, descending so reduced targets are visited.
fn reduce127(mut hi: u64, mut lo: u64) -> u64 {
    for i in (64..128u32).rev() {
        if get128(hi, lo, i) == 1 {
            clear128(&mut hi, &mut lo, i);
            let b = i - 64;
            xor128(&mut hi, &mut lo, b + 4);
            xor128(&mut hi, &mut lo, b + 3);
            xor128(&mut hi, &mut lo, b + 1);
            xor128(&mut hi, &mut lo, b);
        }
    }
    debug_assert_eq!(hi, 0);
    lo
}

// -------------------------------------------------------------- F128 ---

/// Element of `GF(2^128)`, polynomial `x^128 + x^7 + x^2 + x + 1`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct F128(pub u128);

impl F128 {
    /// Additive identity.
    pub const ZERO: Self = Self(0);
    /// Multiplicative identity.
    pub const ONE: Self = Self(1);

    /// Wrap raw bits. Every `u128` is a valid element.
    #[must_use]
    #[inline]
    pub const fn new(x: u128) -> Self {
        Self(x)
    }

    /// Add two elements (XOR).
    // Inherent `add` mirrors the `Add` trait impl below on purpose.
    #[allow(clippy::should_implement_trait)]
    #[must_use]
    #[inline]
    pub const fn add(self, other: Self) -> Self {
        Self(self.0 ^ other.0)
    }

    /// Test for zero.
    #[must_use]
    #[inline]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Square.
    #[must_use]
    pub fn square(self) -> Self {
        self.mul(self)
    }

    /// Multiply with carryless product reduced by the field polynomial.
    // Inherent `mul` mirrors the `Mul` trait impl below on purpose.
    #[allow(clippy::should_implement_trait)]
    #[must_use]
    pub fn mul(self, other: Self) -> Self {
        let prod = clmul128(self.0, other.0);
        Self(reduce256(prod))
    }

    /// Exponentiate (square-and-multiply, 128 steps).
    #[must_use]
    pub fn pow(self, mut exp: u128) -> Self {
        let mut acc = Self::ONE;
        let mut base = self;
        for _ in 0..128 {
            let bit = (exp & 1) as u64;
            let stepped = base.mul(acc);
            let mask = 0u128.wrapping_sub(u128::from(bit));
            acc = Self((acc.0 & !mask) | (stepped.0 & mask));
            base = base.square();
            exp >>= 1;
        }
        acc
    }

    /// Multiplicative inverse via Fermat (`a^(2^128 - 2)`).
    ///
    /// Maps zero to zero instead of failing; see [`F64::inv`].
    #[must_use]
    pub fn inv(self) -> Self {
        if self.is_zero() {
            return Self::ZERO;
        }
        // 2^128 - 2.
        self.pow(u128::MAX - 1)
    }

    /// Embed an [`F64`] word in the low bits (subfield embedding).
    #[must_use]
    pub const fn embed_f64(x: F64) -> Self {
        Self(x.0 as u128)
    }

    /// Serialize as little-endian bytes.
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 16] {
        self.0.to_le_bytes()
    }

    /// Deserialize from little-endian bytes. Infallible: all patterns valid.
    #[must_use]
    pub const fn from_le_bytes(b: [u8; 16]) -> Self {
        Self(u128::from_le_bytes(b))
    }
}

impl Add for F128 {
    type Output = Self;
    #[inline]
    fn add(self, other: Self) -> Self {
        self.add(other)
    }
}

impl Mul for F128 {
    type Output = Self;
    #[inline]
    fn mul(self, other: Self) -> Self {
        self.mul(other)
    }
}

impl core::fmt::Display for F128 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "F128({:#034x})", self.0)
    }
}

#[inline]
const fn bit128(x: u128, i: u32) -> u64 {
    ((x >> i) & 1) as u64
}

/// Carryless 128x128-bit product as 256-bit little-endian limbs.
#[allow(clippy::cast_possible_truncation)]
fn clmul128(a: u128, b: u128) -> [u64; 4] {
    let a_lo = a as u64;
    let a_hi = (a >> 64) as u64;
    let mut r = [0u64; 4];
    for i in 0..128u32 {
        let mask = 0u64.wrapping_sub(bit128(b, i));
        // `i / 64` is 0 or 1; `ws + 2 <= 3` always holds.
        let ws = (i / 64) as usize;
        let bs = i % 64;
        let (c0, carry0, c1, carry1) = if bs == 0 {
            (a_lo, 0u64, a_hi, 0u64)
        } else {
            (a_lo << bs, a_lo >> (64 - bs), a_hi << bs, a_hi >> (64 - bs))
        };
        r[ws] ^= c0 & mask;
        r[ws + 1] ^= (carry0 ^ c1) & mask;
        r[ws + 2] ^= carry1 & mask;
    }
    r
}

#[inline]
fn get256(l: &[u64; 4], i: u32) -> u64 {
    // `i < 256`, so the limb index is 0..4.
    l[(i / 64) as usize] >> (i % 64) & 1
}

#[inline]
fn xor256(l: &mut [u64; 4], i: u32) {
    l[(i / 64) as usize] ^= 1u64 << (i % 64);
}

#[inline]
fn clear256(l: &mut [u64; 4], i: u32) {
    l[(i / 64) as usize] &= !(1u64 << (i % 64));
}

/// Reduce 256-bit limbs modulo `x^128 + x^7 + x^2 + x + 1`.
///
/// Uses `x^128 = x^7 + x^2 + x + 1`, descending.
fn reduce256(mut l: [u64; 4]) -> u128 {
    for i in (128..256u32).rev() {
        if get256(&l, i) == 1 {
            clear256(&mut l, i);
            let b = i - 128;
            xor256(&mut l, b + 7);
            xor256(&mut l, b + 2);
            xor256(&mut l, b + 1);
            xor256(&mut l, b);
        }
    }
    (u128::from(l[1]) << 64) | u128::from(l[0])
}

// ------------------------------------------------------------- utils ---

/// Deterministic `splitmix64` PRNG step.
///
/// Used by tests so the crate needs no `rand` dependency. Not cryptographic.
#[must_use]
pub fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f64_basic() {
        assert_eq!(F64::ZERO.add(F64::ONE), F64::ONE);
        let a = F64::new(0x1234_5678_9abc_def0);
        assert_eq!(a.add(a), F64::ZERO);
        assert_eq!(a.mul(F64::ZERO), F64::ZERO);
        assert_eq!(a.mul(F64::ONE), a);
    }

    #[test]
    fn f64_comm_distrib() {
        let mut s = 0x1234_5678_9abc_def1u64;
        for _ in 0..200 {
            let a = F64::new(splitmix64(&mut s));
            let b = F64::new(splitmix64(&mut s));
            let c = F64::new(splitmix64(&mut s));
            assert_eq!(a.mul(b), b.mul(a));
            assert_eq!(a.mul(b.add(c)), a.mul(b).add(a.mul(c)));
        }
    }

    #[test]
    fn f64_inv() {
        let mut s = 0xdead_beef_cafe_f00du64;
        for _ in 0..50 {
            let mut x = splitmix64(&mut s);
            if x == 0 {
                x = 1;
            }
            let a = F64::new(x);
            assert_eq!(a.mul(a.inv()), F64::ONE, "inv failed for {x:#x}");
        }
        assert_eq!(F64::ZERO.inv(), F64::ZERO);
    }

    #[test]
    fn f128_basic() {
        let a = F128::new(0x1234_5678_9abc_def0_0fed_cba9_8765_4321);
        assert_eq!(a.add(a), F128::ZERO);
        assert_eq!(a.mul(F128::ZERO), F128::ZERO);
        assert_eq!(a.mul(F128::ONE), a);
        assert_eq!(
            F128::embed_f64(F64::new(7))
                .mul(F128::embed_f64(F64::new(9)))
                .0
                & 0xFFFF,
            63
        );
    }

    #[test]
    fn f128_comm_distrib() {
        let mut s = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..100 {
            let a =
                F128::new((u128::from(splitmix64(&mut s)) << 64) | u128::from(splitmix64(&mut s)));
            let b =
                F128::new((u128::from(splitmix64(&mut s)) << 64) | u128::from(splitmix64(&mut s)));
            let c =
                F128::new((u128::from(splitmix64(&mut s)) << 64) | u128::from(splitmix64(&mut s)));
            assert_eq!(a.mul(b), b.mul(a));
            assert_eq!(a.mul(b.add(c)), a.mul(b).add(a.mul(c)));
        }
    }

    #[test]
    fn f128_inv() {
        let mut s = 0xcafe_f00d_dead_beefu64;
        for _ in 0..10 {
            let mut x = (u128::from(splitmix64(&mut s)) << 64) | u128::from(splitmix64(&mut s));
            if x == 0 {
                x = 1;
            }
            let a = F128::new(x);
            assert_eq!(a.mul(a.inv()), F128::ONE);
        }
        assert_eq!(F128::ZERO.inv(), F128::ZERO);
    }

    #[test]
    fn f8_mul_known() {
        // AES check: 0x57 * 0x83 = 0xc1.
        assert_eq!(F8(0x57).mul(F8(0x83)), F8(0xc1));
    }
}
