//! Range validation and the single adapter offset-translation function.
//!
//! Coordinates are half-open `[start, end)` byte ranges into the UTF-8 bytes of
//! the original input. Adapters receive scanner indices in some runtime unit
//! (UTF-16 code units for Node, code points for Python, bytes for Rust-native
//! scanners) and translate them exactly once, with [`translate_range`]. The
//! rest of the kernel never sees another unit.
//!
//! Rules that hold for every function here:
//!
//! - the input is never normalized: offsets are interpreted against the bytes
//!   given, so NFC and NFD spellings of the same text have different layouts;
//! - structure (`start < end`), length bound (`end <= length`) and boundary
//!   validity are separate checks with separate [`RangeError`] variants;
//! - an offset that is not on a character boundary of its unit (inside a UTF-8
//!   sequence, inside a UTF-16 surrogate pair) is rejected, never rounded;
//! - nothing panics on arbitrary bytes or offsets, including `u64::MAX`;
//! - work is linear in the text length, and the text is capped at
//!   [`MAX_TEXT_BYTES`].
//!
//! A "character boundary" is a Unicode scalar value boundary, not a grapheme
//! cluster boundary: a range may separate a base character from a following
//! combining mark.

use pii_eval_contracts::limits::{MAX_SAFE_INTEGER, MAX_TEXT_BYTES};
use pii_eval_contracts::{ByteRange, ReasonCode};

/// The unit in which an adapter's scanner reports offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OffsetUnit {
    /// UTF-8 bytes (already the canonical unit).
    Utf8Bytes,
    /// UTF-16 code units (JavaScript string indices).
    Utf16CodeUnits,
    /// Unicode scalar values (Python string indices).
    UnicodeCodePoints,
}

impl OffsetUnit {
    /// Every unit, in a fixed order.
    pub const ALL: [OffsetUnit; 3] = [
        OffsetUnit::Utf8Bytes,
        OffsetUnit::Utf16CodeUnits,
        OffsetUnit::UnicodeCodePoints,
    ];

    /// Stable wire name for adapter declarations.
    pub const fn as_str(self) -> &'static str {
        match self {
            OffsetUnit::Utf8Bytes => "utf8-bytes",
            OffsetUnit::Utf16CodeUnits => "utf16-code-units",
            OffsetUnit::UnicodeCodePoints => "unicode-code-points",
        }
    }

    /// Parse a wire name; unknown names are `None` (never a default unit).
    pub fn from_wire(name: &str) -> Option<OffsetUnit> {
        OffsetUnit::ALL.into_iter().find(|u| u.as_str() == name)
    }

    /// Width of one scalar value in this unit.
    fn width(self, ch: char) -> u64 {
        match self {
            OffsetUnit::Utf8Bytes => ch.len_utf8() as u64,
            OffsetUnit::Utf16CodeUnits => ch.len_utf16() as u64,
            OffsetUnit::UnicodeCodePoints => 1,
        }
    }
}

/// Why a range or offset was rejected. Variants are distinct on purpose: a
/// length-bounded but mid-character range is a boundary failure, not a bounds
/// failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RangeError {
    /// `start == end`: empty ranges are not valid findings or expectations.
    Empty,
    /// `start > end`.
    Inverted,
    /// An offset above 2^53 - 1, which no contract number can carry.
    OffsetTooLarge,
    /// `end` is past the length of the text (in the range's own unit).
    OutOfBounds,
    /// A UTF-8 byte offset inside a multi-byte sequence.
    NotOnCharBoundary,
    /// A UTF-16 offset between the two halves of a surrogate pair.
    InsideSurrogatePair,
    /// The input bytes are not valid UTF-8 (byte-slice entry points only).
    InvalidUtf8,
    /// The text exceeds [`MAX_TEXT_BYTES`].
    TextTooLarge,
}

impl RangeError {
    /// The contract reason code this error corresponds to. Empty and inverted
    /// ranges share `range-invalid`, as in the contracts.
    pub const fn reason_code(self) -> ReasonCode {
        match self {
            RangeError::Empty | RangeError::Inverted => ReasonCode::RangeInvalid,
            RangeError::OffsetTooLarge => ReasonCode::IntegerOutOfRange,
            RangeError::OutOfBounds => ReasonCode::RangeOutOfBounds,
            RangeError::NotOnCharBoundary | RangeError::InsideSurrogatePair => {
                ReasonCode::RangeNotOnCharBoundary
            }
            RangeError::InvalidUtf8 => ReasonCode::RangeNotOnCharBoundary,
            RangeError::TextTooLarge => ReasonCode::LimitExceeded,
        }
    }
}

impl std::fmt::Display for RangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Fixed text only: no offsets and no input bytes.
        f.write_str(match self {
            RangeError::Empty => "empty range",
            RangeError::Inverted => "inverted range",
            RangeError::OffsetTooLarge => "offset above 2^53 - 1",
            RangeError::OutOfBounds => "range past the end of the text",
            RangeError::NotOnCharBoundary => "offset inside a UTF-8 sequence",
            RangeError::InsideSurrogatePair => "offset inside a UTF-16 surrogate pair",
            RangeError::InvalidUtf8 => "input is not valid UTF-8",
            RangeError::TextTooLarge => "text exceeds the size limit",
        })
    }
}

impl std::error::Error for RangeError {}

fn check_text(text: &str) -> Result<(), RangeError> {
    if text.len() > MAX_TEXT_BYTES {
        Err(RangeError::TextTooLarge)
    } else {
        Ok(())
    }
}

/// Structural checks shared by every unit: ordered, non-empty, in safe-integer range.
fn check_structure(start: u64, end: u64) -> Result<(), RangeError> {
    if start > end {
        Err(RangeError::Inverted)
    } else if start == end {
        Err(RangeError::Empty)
    } else if end > MAX_SAFE_INTEGER {
        Err(RangeError::OffsetTooLarge)
    } else {
        Ok(())
    }
}

/// Validate a byte range against the original text: structure, then length
/// bound, then character boundaries, reporting the first failure.
///
/// Never normalizes `text`.
pub fn validate_range(text: &str, range: &ByteRange) -> Result<(), RangeError> {
    check_text(text)?;
    check_structure(range.start, range.end)?;
    if range.end > text.len() as u64 {
        return Err(RangeError::OutOfBounds);
    }
    // `end <= len <= MAX_TEXT_BYTES`, so both conversions succeed.
    let on_boundary = |o: u64| usize::try_from(o).is_ok_and(|o| text.is_char_boundary(o));
    if on_boundary(range.start) && on_boundary(range.end) {
        Ok(())
    } else {
        Err(RangeError::NotOnCharBoundary)
    }
}

/// [`validate_range`] for raw bytes: the bytes must be valid UTF-8 first.
pub fn validate_range_bytes(input: &[u8], range: &ByteRange) -> Result<(), RangeError> {
    let text = std::str::from_utf8(input).map_err(|_| RangeError::InvalidUtf8)?;
    validate_range(text, range)
}

/// Length of `text` in `unit`.
pub fn unit_length(text: &str, unit: OffsetUnit) -> Result<u64, RangeError> {
    check_text(text)?;
    Ok(match unit {
        OffsetUnit::Utf8Bytes => text.len() as u64,
        OffsetUnit::Utf16CodeUnits => text.chars().map(|c| unit.width(c)).sum(),
        OffsetUnit::UnicodeCodePoints => text.chars().count() as u64,
    })
}

/// Translate one offset in `unit` to a UTF-8 byte offset.
///
/// An offset equal to the unit length maps to the byte length. Offsets inside
/// a character (UTF-8 sequence, surrogate pair) and offsets past the end are
/// rejected with different errors.
pub fn translate_offset(text: &str, unit: OffsetUnit, offset: u64) -> Result<u64, RangeError> {
    check_text(text)?;
    if offset > MAX_SAFE_INTEGER {
        return Err(RangeError::OffsetTooLarge);
    }
    match unit {
        OffsetUnit::Utf8Bytes => {
            if offset > text.len() as u64 {
                Err(RangeError::OutOfBounds)
            } else if text.is_char_boundary(offset as usize) {
                Ok(offset)
            } else {
                Err(RangeError::NotOnCharBoundary)
            }
        }
        OffsetUnit::Utf16CodeUnits | OffsetUnit::UnicodeCodePoints => {
            let mut units = 0u64;
            for (byte, ch) in text.char_indices() {
                if units == offset {
                    return Ok(byte as u64);
                }
                let next = units + unit.width(ch);
                if offset < next {
                    // Only a surrogate pair is wider than one unit.
                    return Err(RangeError::InsideSurrogatePair);
                }
                units = next;
            }
            if units == offset {
                Ok(text.len() as u64)
            } else {
                Err(RangeError::OutOfBounds)
            }
        }
    }
}

/// Translate a half-open range in `unit` to a validated byte range: the one
/// function adapters use.
///
/// Check order: structure on the given offsets, length bound in the given
/// unit, then each end's character boundary (start before end). The result is
/// always valid for [`validate_range`] against the same text.
pub fn translate_range(
    text: &str,
    unit: OffsetUnit,
    start: u64,
    end: u64,
) -> Result<ByteRange, RangeError> {
    check_text(text)?;
    check_structure(start, end)?;
    if end > unit_length(text, unit)? {
        return Err(RangeError::OutOfBounds);
    }
    let range = ByteRange {
        start: translate_offset(text, unit, start)?,
        end: translate_offset(text, unit, end)?,
    };
    // Unit offsets are strictly ordered boundaries, so the byte range is too;
    // validating again keeps the guarantee local instead of argued.
    validate_range(text, &range)?;
    Ok(range)
}

/// Inverse of [`translate_offset`]: the offset in `unit` of the character
/// boundary at `byte`. Used by tests and by adapters that must echo a position
/// back to a scanner.
pub fn byte_to_unit_offset(text: &str, unit: OffsetUnit, byte: u64) -> Result<u64, RangeError> {
    check_text(text)?;
    if byte > text.len() as u64 {
        return Err(RangeError::OutOfBounds);
    }
    let byte = byte as usize;
    if !text.is_char_boundary(byte) {
        return Err(RangeError::NotOnCharBoundary);
    }
    Ok(text[..byte].chars().map(|c| unit.width(c)).sum())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Layout, derived by hand from the UTF-8 encoding of each scalar value:
    //   scalar  U+0061 a   U+1F600 smiley  U+D55C 한  U+0062 b  CR  LF  U+0065 e  U+0301 combining acute
    //   bytes   1          4               3          1         1   1   1          2
    //   utf16   1          2               1          1         1   1   1          1
    //   cp      1          1               1          1         1   1   1          1
    // Boundaries (byte, utf16, code point):
    //   a(0,0,0) smiley(1,1,1) 한(5,3,2) b(8,4,3) CR(9,5,4) LF(10,6,5) e(11,7,6) U+0301(12,8,7) end(14,9,8)
    const MIXED: &str = "a\u{1F600}\u{D55C}b\r\ne\u{301}";
    const BOUNDARIES: [(u64, u64, u64); 9] = [
        (0, 0, 0),
        (1, 1, 1),
        (5, 3, 2),
        (8, 4, 3),
        (9, 5, 4),
        (10, 6, 5),
        (11, 7, 6),
        (12, 8, 7),
        (14, 9, 8),
    ];

    fn br(start: u64, end: u64) -> ByteRange {
        ByteRange { start, end }
    }

    #[test]
    fn layout_fixture_matches_the_hand_table() {
        assert_eq!(MIXED.len(), 14);
        assert_eq!(unit_length(MIXED, OffsetUnit::Utf8Bytes), Ok(14));
        assert_eq!(unit_length(MIXED, OffsetUnit::Utf16CodeUnits), Ok(9));
        assert_eq!(unit_length(MIXED, OffsetUnit::UnicodeCodePoints), Ok(8));
    }

    #[test]
    fn every_boundary_translates_to_the_same_bytes() {
        for (byte, utf16, cp) in BOUNDARIES {
            assert_eq!(
                translate_offset(MIXED, OffsetUnit::Utf8Bytes, byte),
                Ok(byte)
            );
            assert_eq!(
                translate_offset(MIXED, OffsetUnit::Utf16CodeUnits, utf16),
                Ok(byte)
            );
            assert_eq!(
                translate_offset(MIXED, OffsetUnit::UnicodeCodePoints, cp),
                Ok(byte)
            );
            assert_eq!(
                byte_to_unit_offset(MIXED, OffsetUnit::Utf16CodeUnits, byte),
                Ok(utf16)
            );
            assert_eq!(
                byte_to_unit_offset(MIXED, OffsetUnit::UnicodeCodePoints, byte),
                Ok(cp)
            );
        }
    }

    #[test]
    fn the_same_finding_lands_on_the_same_bytes_in_every_unit() {
        // The Korean syllable and the CRLF pair: bytes [5,8) and [9,11).
        let korean = [
            (OffsetUnit::Utf8Bytes, 5, 8),
            (OffsetUnit::Utf16CodeUnits, 3, 4),
            (OffsetUnit::UnicodeCodePoints, 2, 3),
        ];
        let crlf = [
            (OffsetUnit::Utf8Bytes, 9, 11),
            (OffsetUnit::Utf16CodeUnits, 5, 7),
            (OffsetUnit::UnicodeCodePoints, 4, 6),
        ];
        for (unit, s, e) in korean {
            assert_eq!(translate_range(MIXED, unit, s, e), Ok(br(5, 8)));
        }
        for (unit, s, e) in crlf {
            assert_eq!(translate_range(MIXED, unit, s, e), Ok(br(9, 11)));
        }
        // The smiley is a surrogate pair in UTF-16: units [1,3) are bytes [1,5).
        assert_eq!(
            translate_range(MIXED, OffsetUnit::Utf16CodeUnits, 1, 3),
            Ok(br(1, 5))
        );
        assert_eq!(
            translate_range(MIXED, OffsetUnit::UnicodeCodePoints, 1, 2),
            Ok(br(1, 5))
        );
    }

    #[test]
    fn a_range_may_split_a_base_character_from_its_combining_mark() {
        // e is byte [11,12) and U+0301 is [12,14): both are scalar boundaries.
        assert_eq!(validate_range(MIXED, &br(11, 12)), Ok(()));
        assert_eq!(validate_range(MIXED, &br(12, 14)), Ok(()));
        assert_eq!(
            translate_range(MIXED, OffsetUnit::UnicodeCodePoints, 6, 7),
            Ok(br(11, 12))
        );
    }

    #[test]
    fn non_ascii_prefixes_shift_every_later_offset() {
        // "한글" is 6 bytes, 2 UTF-16 units, 2 code points; "x" follows.
        let text = "\u{D55C}\u{AE00}x";
        assert_eq!(
            translate_range(text, OffsetUnit::Utf16CodeUnits, 2, 3),
            Ok(br(6, 7))
        );
        assert_eq!(
            translate_range(text, OffsetUnit::UnicodeCodePoints, 2, 3),
            Ok(br(6, 7))
        );
        assert_eq!(validate_range(text, &br(6, 7)), Ok(()));
        // The same numbers as bytes are inside the second syllable.
        assert_eq!(
            validate_range(text, &br(2, 3)),
            Err(RangeError::NotOnCharBoundary)
        );
    }

    #[test]
    fn mid_character_offsets_are_rejected_not_rounded() {
        for byte in [2, 3, 4, 6, 7, 13] {
            assert_eq!(
                translate_offset(MIXED, OffsetUnit::Utf8Bytes, byte),
                Err(RangeError::NotOnCharBoundary),
                "byte {byte}"
            );
        }
        // UTF-16 offset 2 is between the surrogate halves of the smiley.
        assert_eq!(
            translate_offset(MIXED, OffsetUnit::Utf16CodeUnits, 2),
            Err(RangeError::InsideSurrogatePair)
        );
        assert_eq!(
            translate_range(MIXED, OffsetUnit::Utf16CodeUnits, 2, 3),
            Err(RangeError::InsideSurrogatePair)
        );
        assert_eq!(
            translate_range(MIXED, OffsetUnit::Utf16CodeUnits, 1, 2),
            Err(RangeError::InsideSurrogatePair)
        );
    }

    #[test]
    fn length_bounds_and_boundaries_are_distinct_errors() {
        // Byte 15 is past the end (length 14); byte 13 is inside U+0301.
        assert_eq!(
            validate_range(MIXED, &br(0, 15)),
            Err(RangeError::OutOfBounds)
        );
        assert_eq!(
            validate_range(MIXED, &br(0, 13)),
            Err(RangeError::NotOnCharBoundary)
        );
        assert_eq!(validate_range(MIXED, &br(0, 14)), Ok(()));
        // The same split in the other units.
        assert_eq!(
            translate_range(MIXED, OffsetUnit::Utf16CodeUnits, 0, 10),
            Err(RangeError::OutOfBounds)
        );
        assert_eq!(
            translate_range(MIXED, OffsetUnit::UnicodeCodePoints, 0, 9),
            Err(RangeError::OutOfBounds)
        );
        assert_eq!(
            translate_range(MIXED, OffsetUnit::Utf16CodeUnits, 0, 9),
            Ok(br(0, 14))
        );
    }

    #[test]
    fn structural_failures_come_first() {
        let text = "abc";
        assert_eq!(validate_range(text, &br(2, 2)), Err(RangeError::Empty));
        assert_eq!(validate_range(text, &br(0, 0)), Err(RangeError::Empty));
        assert_eq!(validate_range(text, &br(3, 3)), Err(RangeError::Empty));
        assert_eq!(validate_range(text, &br(3, 2)), Err(RangeError::Inverted));
        assert_eq!(validate_range(text, &br(0, 3)), Ok(()));
        assert_eq!(validate_range(text, &br(0, 1)), Ok(()));
        assert_eq!(validate_range(text, &br(2, 3)), Ok(()));
        assert_eq!(
            validate_range(text, &br(0, MAX_SAFE_INTEGER + 1)),
            Err(RangeError::OffsetTooLarge)
        );
        assert_eq!(
            validate_range(text, &br(u64::MAX - 1, u64::MAX)),
            Err(RangeError::OffsetTooLarge)
        );
        assert_eq!(
            validate_range(text, &br(0, MAX_SAFE_INTEGER)),
            Err(RangeError::OutOfBounds)
        );
        assert_eq!(
            translate_range(text, OffsetUnit::UnicodeCodePoints, 2, 1),
            Err(RangeError::Inverted)
        );
        assert_eq!(
            translate_range(text, OffsetUnit::Utf16CodeUnits, 1, 1),
            Err(RangeError::Empty)
        );
    }

    #[test]
    fn reason_codes_follow_the_contract() {
        assert_eq!(RangeError::Empty.reason_code(), ReasonCode::RangeInvalid);
        assert_eq!(RangeError::Inverted.reason_code(), ReasonCode::RangeInvalid);
        assert_eq!(
            RangeError::OutOfBounds.reason_code(),
            ReasonCode::RangeOutOfBounds
        );
        assert_eq!(
            RangeError::NotOnCharBoundary.reason_code(),
            ReasonCode::RangeNotOnCharBoundary
        );
        // Agrees with the contract's own validation on the same inputs.
        for r in [br(0, 15), br(0, 13), br(3, 3), br(4, 2)] {
            assert_eq!(
                validate_range(MIXED, &r).map_err(RangeError::reason_code),
                r.validate_against_text(MIXED)
            );
        }
    }

    #[test]
    fn invalid_utf8_is_rejected_by_the_byte_entry_point() {
        assert_eq!(
            validate_range_bytes(&[0x61, 0xFF, 0x62], &br(0, 1)),
            Err(RangeError::InvalidUtf8)
        );
        // A lone continuation byte and a truncated sequence.
        assert_eq!(
            validate_range_bytes(&[0x80], &br(0, 1)),
            Err(RangeError::InvalidUtf8)
        );
        assert_eq!(
            validate_range_bytes(&[0xED, 0x95], &br(0, 1)),
            Err(RangeError::InvalidUtf8)
        );
        assert_eq!(
            validate_range_bytes("\u{D55C}".as_bytes(), &br(0, 3)),
            Ok(())
        );
    }

    #[test]
    fn input_is_never_normalized() {
        // Precomposed U+00E9 is 2 bytes; "e" + U+0301 is 3 bytes. Same text
        // under NFC/NFD, different layouts, and each is measured as given.
        let nfc = "\u{E9}x";
        let nfd = "e\u{301}x";
        assert_eq!(nfc.len(), 3);
        assert_eq!(nfd.len(), 4);
        assert_eq!(validate_range(nfc, &br(2, 3)), Ok(()));
        assert_eq!(validate_range(nfd, &br(3, 4)), Ok(()));
        // The NFC offset is not silently re-based onto the NFD text.
        assert_eq!(
            validate_range(nfd, &br(2, 3)),
            Err(RangeError::NotOnCharBoundary)
        );
        assert_eq!(validate_range(nfc, &br(3, 4)), Err(RangeError::OutOfBounds));
        assert_eq!(
            translate_range(nfd, OffsetUnit::UnicodeCodePoints, 2, 3),
            Ok(br(3, 4))
        );
        assert_eq!(
            translate_range(nfc, OffsetUnit::UnicodeCodePoints, 1, 2),
            Ok(br(2, 3))
        );
    }

    #[test]
    fn oversize_text_and_offsets_are_bounded() {
        let big = "a".repeat(MAX_TEXT_BYTES + 1);
        assert_eq!(
            validate_range(&big, &br(0, 1)),
            Err(RangeError::TextTooLarge)
        );
        assert_eq!(
            translate_range(&big, OffsetUnit::Utf8Bytes, 0, 1),
            Err(RangeError::TextTooLarge)
        );
        assert_eq!(
            translate_offset("abc", OffsetUnit::Utf16CodeUnits, u64::MAX),
            Err(RangeError::OffsetTooLarge)
        );
        let max = "a".repeat(MAX_TEXT_BYTES);
        assert_eq!(validate_range(&max, &br(0, MAX_TEXT_BYTES as u64)), Ok(()));
    }

    #[test]
    fn unit_names_round_trip_and_unknown_names_are_refused() {
        for unit in OffsetUnit::ALL {
            assert_eq!(OffsetUnit::from_wire(unit.as_str()), Some(unit));
        }
        assert_eq!(OffsetUnit::from_wire("utf-16"), None);
        assert_eq!(OffsetUnit::from_wire(""), None);
        assert_eq!(OffsetUnit::from_wire("grapheme-clusters"), None);
    }
}
