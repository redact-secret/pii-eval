//! Fixed-point decimals and byte ranges.
//!
//! Contracts carry no floating-point numbers: a rate or interval endpoint is a
//! [`ScaledDecimal`] (an integer mantissa and a decimal scale), which has one
//! canonical text-free encoding, no `NaN`, no infinity and no negative zero.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::limits::MAX_SAFE_INTEGER;
use crate::reason::{Collector, Meta, Path, ReasonCode};

/// Largest decimal scale (digits after the point).
pub const MAX_DECIMAL_SCALE: u8 = 12;

/// `mantissa / 10^scale`, always non-negative.
///
/// Normalized form: the mantissa has no trailing decimal zero unless the scale
/// is zero, so every value has exactly one representation (`1.96` is
/// `{mantissa: 196, scale: 2}`; `0` is `{mantissa: 0, scale: 0}`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScaledDecimal {
    /// Unsigned integer mantissa, at most 2^53 - 1.
    pub mantissa: u64,
    /// Number of decimal places, at most 12.
    pub scale: u8,
}

impl ScaledDecimal {
    /// Zero.
    pub const ZERO: ScaledDecimal = ScaledDecimal {
        mantissa: 0,
        scale: 0,
    };

    /// Build a normalized decimal, stripping trailing decimal zeros. Returns
    /// `None` when the mantissa or scale is out of range.
    pub fn new(mut mantissa: u64, mut scale: u8) -> Option<Self> {
        if mantissa > MAX_SAFE_INTEGER || scale > MAX_DECIMAL_SCALE {
            return None;
        }
        if mantissa == 0 {
            scale = 0;
        }
        while scale > 0 && mantissa % 10 == 0 {
            mantissa /= 10;
            scale -= 1;
        }
        Some(Self { mantissa, scale })
    }

    /// True when the value is in normalized form and in range.
    pub fn is_normalized(&self) -> bool {
        self.mantissa <= MAX_SAFE_INTEGER
            && self.scale <= MAX_DECIMAL_SCALE
            && (self.scale == 0 || self.mantissa % 10 != 0)
    }

    /// True when the value is at most one (`mantissa <= 10^scale`).
    pub fn is_at_most_one(&self) -> bool {
        10u64
            .checked_pow(u32::from(self.scale))
            .is_some_and(|unit| self.mantissa <= unit)
    }

    /// Record `decimal-invalid` when not normalized.
    pub fn validate(&self, path: &Path<'_>, c: &mut Collector) {
        if !self.is_normalized() {
            c.push(ReasonCode::DecimalInvalid, path);
        }
    }
}

/// Half-open byte range `[start, end)` into the UTF-8 bytes of an original input.
///
/// Three checks are deliberately separate:
///
/// 1. [`ByteRange::validate_structure`]: `start < end` (no empty or inverted range);
/// 2. [`ByteRange::validate_bounds`]: `end <= byte length`;
/// 3. [`ByteRange::validate_boundaries`]: both ends fall on UTF-8 character
///    boundaries of the text.
///
/// Each yields its own reason code, so a length-bounded but mid-character range
/// is reported as a boundary failure, not as a bounds failure.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ByteRange {
    /// Inclusive start byte offset.
    pub start: u64,
    /// Exclusive end byte offset.
    pub end: u64,
}

impl ByteRange {
    /// Structural validity: non-empty, ordered, within the safe-integer range.
    pub fn validate_structure(&self) -> Result<(), ReasonCode> {
        if self.start >= self.end {
            Err(ReasonCode::RangeInvalid)
        } else if self.end > MAX_SAFE_INTEGER {
            Err(ReasonCode::IntegerOutOfRange)
        } else {
            Ok(())
        }
    }

    /// The end must not pass the byte length of the text.
    pub fn validate_bounds(&self, byte_len: u64) -> Result<(), ReasonCode> {
        if self.end > byte_len {
            Err(ReasonCode::RangeOutOfBounds)
        } else {
            Ok(())
        }
    }

    /// Both ends must sit on character boundaries of `text`. Call only after
    /// [`ByteRange::validate_bounds`] succeeded for the same text.
    pub fn validate_boundaries(&self, text: &str) -> Result<(), ReasonCode> {
        let on_boundary =
            |offset: u64| usize::try_from(offset).is_ok_and(|o| text.is_char_boundary(o));
        if on_boundary(self.start) && on_boundary(self.end) {
            Ok(())
        } else {
            Err(ReasonCode::RangeNotOnCharBoundary)
        }
    }

    /// All three checks against known text, reporting the first failure.
    pub fn validate_against_text(&self, text: &str) -> Result<(), ReasonCode> {
        self.validate_structure()?;
        self.validate_bounds(text.len() as u64)?;
        self.validate_boundaries(text)
    }

    /// Record the first failing check at `path`.
    pub(crate) fn check(&self, text: &str, path: &Path<'_>, c: &mut Collector) {
        if let Err(code) = self.validate_against_text(text) {
            let meta = if code == ReasonCode::RangeOutOfBounds {
                Meta::limit(text.len() as u64, self.end)
            } else {
                Meta::NONE
            };
            c.push_with(code, path, meta);
        }
    }

    /// Record only the structural check at `path` (no text available).
    pub(crate) fn check_structure(&self, path: &Path<'_>, c: &mut Collector) {
        if let Err(code) = self.validate_structure() {
            c.push(code, path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimals_normalize_and_reject_denormalized() {
        assert_eq!(ScaledDecimal::new(1960, 3), ScaledDecimal::new(196, 2));
        assert_eq!(ScaledDecimal::new(0, 5), Some(ScaledDecimal::ZERO));
        assert_eq!(ScaledDecimal::new(1_000_000, 6).unwrap().scale, 0);
        assert!(ScaledDecimal::new(1, 13).is_none());
        assert!(
            !ScaledDecimal {
                mantissa: 10,
                scale: 1
            }
            .is_normalized()
        );
        assert!(ScaledDecimal::new(1, 0).unwrap().is_at_most_one());
        assert!(!ScaledDecimal::new(11, 1).unwrap().is_at_most_one());
    }

    #[test]
    fn range_checks_are_distinct() {
        // "가" is three bytes: a range ending at byte 2 is inside the character.
        let text = "가a";
        let mid = ByteRange { start: 0, end: 2 };
        assert_eq!(mid.validate_structure(), Ok(()));
        assert_eq!(mid.validate_bounds(text.len() as u64), Ok(()));
        assert_eq!(
            mid.validate_boundaries(text),
            Err(ReasonCode::RangeNotOnCharBoundary)
        );
        assert_eq!(
            ByteRange { start: 3, end: 3 }.validate_structure(),
            Err(ReasonCode::RangeInvalid)
        );
        assert_eq!(
            ByteRange { start: 4, end: 2 }.validate_structure(),
            Err(ReasonCode::RangeInvalid)
        );
        assert_eq!(
            ByteRange { start: 0, end: 5 }.validate_against_text(text),
            Err(ReasonCode::RangeOutOfBounds)
        );
        assert_eq!(
            ByteRange { start: 0, end: 3 }.validate_against_text(text),
            Ok(())
        );
        assert_eq!(
            ByteRange { start: 3, end: 4 }.validate_against_text(text),
            Ok(())
        );
    }
}
