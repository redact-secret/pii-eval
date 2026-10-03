//! Fixed-width unsigned integer arithmetic for the exact Wilson computation.
//!
//! 512 bits is enough for every input the contracts allow (counts up to
//! 2^53 - 1, interval z up to a 2^53 - 1 mantissa at scale 12, precision up to
//! 12 digits; see `stats.rs` for the bound), but every operation is checked
//! anyway: an overflow is reported to the caller, never wrapped and never a
//! panic. Only the operations the statistics need exist: add, subtract,
//! multiply, compare, shift by one bit, exact integer square root and
//! quotient. They are bitwise or schoolbook algorithms with no data-dependent
//! allocation, so cost is bounded by the (fixed) width.

// Limb loops index two arrays at related positions (`i`, `i + 1`, `i + j`);
// the indexed form is the clearer one here.
#![allow(clippy::needless_range_loop)]

use std::cmp::Ordering;

const LIMBS: usize = 8;
const BITS: usize = LIMBS * 64;

/// An unsigned 512-bit integer, little-endian limbs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct U512([u64; LIMBS]);

impl U512 {
    pub(crate) const ZERO: U512 = U512([0; LIMBS]);

    pub(crate) fn from_u64(v: u64) -> Self {
        let mut limbs = [0; LIMBS];
        limbs[0] = v;
        U512(limbs)
    }

    pub(crate) fn from_u128(v: u128) -> Self {
        let mut limbs = [0; LIMBS];
        limbs[0] = v as u64;
        limbs[1] = (v >> 64) as u64;
        U512(limbs)
    }

    /// `10^exp`, or `None` when it does not fit.
    pub(crate) fn pow10(exp: u32) -> Option<Self> {
        let ten = U512::from_u64(10);
        let mut out = U512::from_u64(1);
        for _ in 0..exp {
            out = out.checked_mul(&ten)?;
        }
        Some(out)
    }

    pub(crate) fn is_zero(&self) -> bool {
        self.0.iter().all(|&l| l == 0)
    }

    /// The value as `u64` when it fits.
    pub(crate) fn to_u64(self) -> Option<u64> {
        if self.0[1..].iter().all(|&l| l == 0) {
            Some(self.0[0])
        } else {
            None
        }
    }

    pub(crate) fn checked_add(&self, other: &Self) -> Option<Self> {
        let mut out = [0u64; LIMBS];
        let mut carry = 0u64;
        for (i, slot) in out.iter_mut().enumerate() {
            let (a, c1) = self.0[i].overflowing_add(other.0[i]);
            let (b, c2) = a.overflowing_add(carry);
            *slot = b;
            carry = u64::from(c1) + u64::from(c2);
        }
        if carry == 0 { Some(U512(out)) } else { None }
    }

    /// `self - other`, or `None` when `other > self`.
    pub(crate) fn checked_sub(&self, other: &Self) -> Option<Self> {
        if *self < *other {
            return None;
        }
        let mut out = [0u64; LIMBS];
        let mut borrow = 0u64;
        for (i, slot) in out.iter_mut().enumerate() {
            let (a, b1) = self.0[i].overflowing_sub(other.0[i]);
            let (b, b2) = a.overflowing_sub(borrow);
            *slot = b;
            borrow = u64::from(b1) + u64::from(b2);
        }
        Some(U512(out))
    }

    pub(crate) fn checked_mul(&self, other: &Self) -> Option<Self> {
        let mut wide = [0u64; 2 * LIMBS];
        for i in 0..LIMBS {
            let mut carry = 0u128;
            for j in 0..LIMBS {
                // (2^64-1)^2 + 2 * (2^64-1) = 2^128 - 1: never overflows.
                let cur = u128::from(self.0[i]) * u128::from(other.0[j])
                    + u128::from(wide[i + j])
                    + carry;
                wide[i + j] = cur as u64;
                carry = cur >> 64;
            }
            wide[i + LIMBS] = carry as u64;
        }
        if wide[LIMBS..].iter().any(|&l| l != 0) {
            return None;
        }
        let mut out = [0u64; LIMBS];
        out.copy_from_slice(&wide[..LIMBS]);
        Some(U512(out))
    }

    pub(crate) fn mul_u64(&self, v: u64) -> Option<Self> {
        self.checked_mul(&U512::from_u64(v))
    }

    pub(crate) fn bit(&self, i: usize) -> bool {
        (self.0[i / 64] >> (i % 64)) & 1 == 1
    }

    fn set_bit(&mut self, i: usize) {
        self.0[i / 64] |= 1u64 << (i % 64);
    }

    /// Number of significant bits (0 for zero).
    pub(crate) fn bit_length(&self) -> usize {
        for i in (0..LIMBS).rev() {
            if self.0[i] != 0 {
                return i * 64 + (64 - self.0[i].leading_zeros() as usize);
            }
        }
        0
    }

    fn shr(&self, bits: usize) -> Self {
        debug_assert!(bits < 64);
        if bits == 0 {
            return *self;
        }
        let mut out = [0u64; LIMBS];
        for i in 0..LIMBS {
            let hi = if i + 1 < LIMBS { self.0[i + 1] } else { 0 };
            out[i] = (self.0[i] >> bits) | (hi << (64 - bits));
        }
        U512(out)
    }

    /// Shift left by one bit; `None` if a set bit would be lost.
    fn shl1(&self) -> Option<Self> {
        if self.0[LIMBS - 1] >> 63 == 1 {
            return None;
        }
        let mut out = [0u64; LIMBS];
        for i in 0..LIMBS {
            let lo = if i > 0 { self.0[i - 1] >> 63 } else { 0 };
            out[i] = (self.0[i] << 1) | lo;
        }
        Some(U512(out))
    }

    /// Floor of the square root (bitwise; exact for every input).
    pub(crate) fn isqrt(&self) -> Self {
        if self.is_zero() {
            return U512::ZERO;
        }
        // Highest power of four not above the value.
        let top = (self.bit_length() - 1) & !1;
        let mut bit = U512::ZERO;
        bit.set_bit(top);
        let mut rest = *self;
        let mut res = U512::ZERO;
        while !bit.is_zero() {
            // `res + bit` cannot overflow: res < 2^(top/2 + 1) and bit <= 2^top.
            let trial = res.checked_add(&bit).unwrap_or(res);
            if rest >= trial {
                rest = rest.checked_sub(&trial).unwrap_or(rest);
                res = res.shr(1).checked_add(&bit).unwrap_or(res);
            } else {
                res = res.shr(1);
            }
            bit = bit.shr(2);
        }
        res
    }

    /// Floor quotient and remainder of `self / divisor` (shift and subtract).
    /// `None` for a zero divisor or if the remainder register would overflow.
    pub(crate) fn div_rem(&self, divisor: &Self) -> Option<(Self, Self)> {
        if divisor.is_zero() {
            return None;
        }
        let mut quotient = U512::ZERO;
        let mut rem = U512::ZERO;
        for i in (0..self.bit_length().min(BITS)).rev() {
            rem = rem.shl1()?;
            if self.bit(i) {
                rem.0[0] |= 1;
            }
            if rem >= *divisor {
                rem = rem.checked_sub(divisor)?;
                quotient.set_bit(i);
            }
        }
        Some((quotient, rem))
    }
}

impl PartialOrd for U512 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for U512 {
    fn cmp(&self, other: &Self) -> Ordering {
        for i in (0..LIMBS).rev() {
            match self.0[i].cmp(&other.0[i]) {
                Ordering::Equal => {}
                unequal => return unequal,
            }
        }
        Ordering::Equal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(v: u128) -> U512 {
        U512::from_u128(v)
    }

    #[test]
    fn add_sub_mul_match_u128_when_they_fit() {
        let a = 0xFFFF_FFFF_FFFF_FFFF_FFFFu128;
        let b = 0x1234_5678_9ABC_DEF0u128;
        assert_eq!(u(a).checked_add(&u(b)), Some(u(a + b)));
        assert_eq!(u(a).checked_sub(&u(b)), Some(u(a - b)));
        assert_eq!(u(b).checked_sub(&u(a)), None);
        assert_eq!(u(b).checked_mul(&u(b)), Some(u(b * b)));
    }

    #[test]
    fn multiplication_carries_across_limbs_and_detects_overflow() {
        let big = U512::pow10(70).unwrap();
        // 10^140 fits (< 1.3e154), 10^210 does not.
        let sq = big.checked_mul(&big).unwrap();
        assert_eq!(sq, U512::pow10(140).unwrap());
        assert!(sq.checked_mul(&big).is_none());
        // (2^256 - 1)^2 = 2^512 - 2^257 + 1 fits exactly; one more limb bit would not.
        let m = U512([u64::MAX, u64::MAX, u64::MAX, u64::MAX, 0, 0, 0, 0]);
        let p = m.checked_mul(&m).unwrap();
        assert_eq!(p.0[0], 1);
        assert_eq!(p.0[4], u64::MAX - 1);
    }

    #[test]
    fn pow10_limits() {
        // 2^512 is about 1.34e154, so 10^154 fits and 10^155 does not.
        assert!(U512::pow10(154).is_some());
        assert!(U512::pow10(155).is_none());
    }

    #[test]
    fn isqrt_is_exact_floor() {
        for v in [
            0u128,
            1,
            2,
            3,
            4,
            8,
            9,
            15,
            16,
            17,
            99,
            100,
            101,
            u128::from(u64::MAX),
        ] {
            let r = u(v).isqrt().to_u64().unwrap();
            assert!(u128::from(r) * u128::from(r) <= v, "{v}");
            assert!((u128::from(r) + 1) * (u128::from(r) + 1) > v, "{v}");
        }
        // A perfect square far above u128.
        let x = U512::pow10(60).unwrap();
        let sq = x.checked_mul(&x).unwrap();
        assert_eq!(sq.isqrt(), x);
        let below = sq.checked_sub(&U512::from_u64(1)).unwrap();
        assert_eq!(below.isqrt(), x.checked_sub(&U512::from_u64(1)).unwrap());
    }

    #[test]
    fn div_rem_matches_u128() {
        for (a, b) in [
            (0u128, 7u128),
            (1, 7),
            (100, 7),
            (u128::MAX, 3),
            (u128::MAX, u128::MAX),
            (12345678901234567890123456789, 987654321),
        ] {
            let (q, r) = u(a).div_rem(&u(b)).unwrap();
            assert_eq!(q, u(a / b));
            assert_eq!(r, u(a % b));
        }
        assert!(u(1).div_rem(&U512::ZERO).is_none());
    }

    #[test]
    fn shifts_and_bit_length() {
        assert_eq!(u(0).bit_length(), 0);
        assert_eq!(u(1).bit_length(), 1);
        assert_eq!(u(1 << 100).bit_length(), 101);
        assert_eq!(u(1 << 100).shl1(), Some(u(1 << 101)));
        let mut top = U512::ZERO;
        top.set_bit(511);
        assert_eq!(top.shl1(), None);
    }
}
