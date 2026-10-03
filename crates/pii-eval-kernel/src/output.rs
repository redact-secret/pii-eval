//! Verification of sanitized output: what actually remained of an authored
//! occurrence, and whether anything else changed.
//!
//! A reported `redact` action is not removal (ADR 0004, ARCHITECTURE.md), so an
//! adapter that returns the sanitized text lets the executor *observe* the
//! action axis as `output-verified` (ADR 0008, section 5). The function here is
//! pure and scanner-neutral; it sees the original text, the sanitized text and
//! the authored occurrence ranges, and never the scanner's findings.
//!
//! # Model
//!
//! The authored occurrence ranges (merged where they touch or overlap) split the
//! original text into *context segments* and *protected spans*:
//! `seg0 span0 seg1 span1 ... seg(K-1) span(K-1) segK`. A sanitizer that only
//! touched the occurrences leaves every context segment intact and replaces each
//! span by anything (including nothing). So the sanitized text must start with
//! `seg0`, end with `segK`, and contain `seg1 ... seg(K-1)` in order in between;
//! the text found between consecutive segments is the *replacement region* of
//! the span between them. Segments are located leftmost, which is a stated
//! limitation: a replacement that itself contains the following context
//! segment verbatim misaligns the match and is reported as a collateral change
//! (fail closed).
//!
//! # Verdict per occurrence
//!
//! In this precedence:
//!
//! 1. `ResidualPresent` ([`OutputVerification::ResidualPresent`]) when the
//!    occurrence's exact bytes still occur in its replacement region; when the context could not be aligned the
//!    whole sanitized text is searched instead (a leak is never hidden behind a
//!    collateral finding, and a value that legitimately appears in context is
//!    then flagged, which fails closed);
//! 2. `CollateralChange` ([`OutputVerification::CollateralChange`]) when the
//!    context segments were not all preserved in order, whatever happened to
//!    the occurrence;
//! 3. `Removed` ([`OutputVerification::Removed`]) when neither applies.
//!
//! Only verbatim survival is detected: a value that is partially masked counts
//! as removed. The data is expected to be synthetic, and the verdict says
//! nothing about the quality of a mask. Work is bounded: text at most
//! `MAX_TEXT_BYTES`, sanitized text at most [`MAX_SANITIZED_BYTES`], at most
//! `MAX_EXPECTATIONS_PER_VARIANT` ranges, and one linear search per segment.

use pii_eval_contracts::limits::{MAX_EXPECTATIONS_PER_VARIANT, MAX_TEXT_BYTES};
use pii_eval_contracts::{ByteRange, OutputVerification};

use crate::range::{RangeError, validate_range};

/// Largest sanitized text accepted for verification, in bytes. A scanner may
/// return at most this much (the adapter's line bound is of the same order).
pub const MAX_SANITIZED_BYTES: usize = 8 * 1024 * 1024;

/// Why verification was refused. Input is rejected, never repaired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputError {
    /// An authored range failed validation against the original text.
    Range(RangeError),
    /// More than `MAX_EXPECTATIONS_PER_VARIANT` ranges.
    TooManyOccurrences,
    /// The original text is longer than `MAX_TEXT_BYTES`.
    TextTooLarge,
    /// The sanitized text is longer than [`MAX_SANITIZED_BYTES`].
    OutputTooLarge,
}

/// The result of verifying one variant's sanitized output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputAssessment {
    /// One verdict per input range, in the order the ranges were given.
    pub occurrences: Vec<OutputVerification>,
    /// True when every context segment was found, in order, around the
    /// replacement regions. False means a collateral change (or a misaligned
    /// match, see the module documentation).
    pub context_preserved: bool,
}

/// Verify `sanitized` against the original `text` and the authored occurrence
/// `ranges` (half-open UTF-8 byte ranges into `text`, any order, overlaps
/// allowed).
pub fn verify_output(
    text: &str,
    sanitized: &str,
    ranges: &[ByteRange],
) -> Result<OutputAssessment, OutputError> {
    if text.len() > MAX_TEXT_BYTES {
        return Err(OutputError::TextTooLarge);
    }
    if sanitized.len() > MAX_SANITIZED_BYTES {
        return Err(OutputError::OutputTooLarge);
    }
    if ranges.len() > MAX_EXPECTATIONS_PER_VARIANT {
        return Err(OutputError::TooManyOccurrences);
    }
    for range in ranges {
        validate_range(text, range).map_err(OutputError::Range)?;
    }

    // Merge touching or overlapping ranges into protected spans.
    let mut sorted: Vec<ByteRange> = ranges.to_vec();
    sorted.sort_by_key(|r| (r.start, r.end));
    let mut spans: Vec<ByteRange> = Vec::new();
    for r in sorted {
        match spans.last_mut() {
            Some(last) if r.start <= last.end => last.end = last.end.max(r.end),
            _ => spans.push(r),
        }
    }

    // Context segments around the spans, as slices of the original text.
    let at = |offset: u64| offset as usize; // validated: at most `text.len()`
    let mut segments: Vec<&str> = Vec::with_capacity(spans.len() + 1);
    let mut from = 0usize;
    for span in &spans {
        segments.push(&text[from..at(span.start)]);
        from = at(span.end);
    }
    segments.push(&text[from..]);

    // Align the segments in the sanitized text; `regions[j]` is the replacement
    // region of span `j`.
    let aligned = align(sanitized, &segments);
    let context_preserved = aligned.is_some();

    let verdict = |range: &ByteRange| {
        let value = &text[at(range.start)..at(range.end)];
        let residual = match &aligned {
            Some(regions) => {
                // The span containing this range (spans are merged, so exactly one).
                let j = spans
                    .iter()
                    .position(|s| s.start <= range.start && range.end <= s.end)
                    .unwrap_or(0);
                regions.get(j).is_some_and(|region| region.contains(value))
            }
            None => sanitized.contains(value),
        };
        if residual {
            OutputVerification::ResidualPresent
        } else if !context_preserved {
            OutputVerification::CollateralChange
        } else {
            OutputVerification::Removed
        }
    };
    Ok(OutputAssessment {
        occurrences: ranges.iter().map(verdict).collect(),
        context_preserved,
    })
}

/// Locate `segments` in `sanitized` and return the replacement regions between
/// them (one fewer than the segments), or `None` when they are not all present
/// in order.
fn align<'a>(sanitized: &'a str, segments: &[&str]) -> Option<Vec<&'a str>> {
    let (first, rest) = segments.split_first()?;
    let (last, middle) = match rest.split_last() {
        Some((last, middle)) => (*last, middle),
        // No spans: the text must be unchanged.
        None => return (sanitized == *first).then(Vec::new),
    };
    // Stripping the prefix first means an overlapping prefix and suffix cannot
    // both match the same bytes.
    let body = sanitized.strip_prefix(first)?;
    let body = body.strip_suffix(last)?;
    let mut regions = Vec::with_capacity(middle.len() + 1);
    let mut rest = body;
    for segment in middle {
        let found = rest.find(segment)?;
        regions.push(&rest[..found]);
        rest = &rest[found + segment.len()..];
    }
    regions.push(rest);
    Some(regions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use OutputVerification::*;

    fn r(start: u64, end: u64) -> ByteRange {
        ByteRange { start, end }
    }

    /// Range of `needle` in `text`.
    fn range_of(text: &str, needle: &str) -> ByteRange {
        let start = text.find(needle).unwrap();
        r(start as u64, (start + needle.len()) as u64)
    }

    #[test]
    fn a_clean_replacement_is_removed_with_context_preserved() {
        // "contact " + value + " today": the value is replaced by a marker.
        let text = "contact user@example.invalid today";
        let v = range_of(text, "user@example.invalid");
        let a = verify_output(text, "contact <R> today", &[v]).unwrap();
        assert_eq!(a.occurrences, [Removed]);
        assert!(a.context_preserved);
        // Deleting the value outright is also removal.
        let a = verify_output(text, "contact  today", &[v]).unwrap();
        assert_eq!(a.occurrences, [Removed]);
    }

    #[test]
    fn a_value_that_survives_is_residual() {
        let text = "contact user@example.invalid today";
        let v = range_of(text, "user@example.invalid");
        // Unchanged output.
        assert_eq!(
            verify_output(text, text, &[v]).unwrap().occurrences,
            [ResidualPresent]
        );
        // Marker added but the value is still there.
        let a = verify_output(text, "contact <R> user@example.invalid today", &[v]).unwrap();
        assert_eq!(a.occurrences, [ResidualPresent]);
        assert!(a.context_preserved);
    }

    #[test]
    fn a_partially_masked_value_counts_as_removed_by_design() {
        let text = "contact user@example.invalid today";
        let v = range_of(text, "user@example.invalid");
        let a = verify_output(text, "contact u***@example.invalid today", &[v]).unwrap();
        assert_eq!(a.occurrences, [Removed]);
    }

    #[test]
    fn changed_context_is_a_collateral_change_even_when_the_value_is_gone() {
        // The scanner also redacted a second, unauthored token (collateral).
        let text = "contact user@example.invalid and 0000-synthetic-token today";
        let v = range_of(text, "user@example.invalid");
        let a = verify_output(text, "contact <R> and <R> today", &[v]).unwrap();
        assert_eq!(a.occurrences, [CollateralChange]);
        assert!(!a.context_preserved);
        // A scanner that mangled the prefix.
        let a = verify_output(text, "CONTACT <R> and 0000-synthetic-token today", &[v]).unwrap();
        assert_eq!(a.occurrences, [CollateralChange]);
        // Nothing but a marker came back.
        let a = verify_output(text, "<R>", &[v]).unwrap();
        assert_eq!(a.occurrences, [CollateralChange]);
    }

    #[test]
    fn residual_takes_precedence_over_collateral() {
        let text = "contact user@example.invalid and tail";
        let v = range_of(text, "user@example.invalid");
        // Context broken (tail lost) and the value is still present: a leak is reported.
        let a = verify_output(text, "contact user@example.invalid and", &[v]).unwrap();
        assert_eq!(a.occurrences, [ResidualPresent]);
        assert!(!a.context_preserved);
    }

    #[test]
    fn two_occurrences_are_judged_in_their_own_regions() {
        // "A:" v1 " B:" v2 "." with v1 removed and v2 surviving.
        let text = "A: first-value B: second-value .";
        let v1 = range_of(text, "first-value");
        let v2 = range_of(text, "second-value");
        let a = verify_output(text, "A: <R> B: second-value .", &[v1, v2]).unwrap();
        assert_eq!(a.occurrences, [Removed, ResidualPresent]);
        // The same ranges given in the opposite order keep the input order of the verdicts.
        let a = verify_output(text, "A: <R> B: second-value .", &[v2, v1]).unwrap();
        assert_eq!(a.occurrences, [ResidualPresent, Removed]);
        // A value that also appears in another occurrence's region is not confused:
        // v1's bytes sit in v2's region, but v1's own region is clean.
        let a = verify_output(text, "A: <R> B: first-value .", &[v1, v2]).unwrap();
        assert_eq!(a.occurrences, [Removed, Removed]);
    }

    #[test]
    fn a_value_equal_to_context_elsewhere_is_not_residual_when_aligned() {
        // The authored value also appears as ordinary context text.
        let text = "ID 1234 then ID 1234 again";
        let v = r(3, 7); // the first "1234"
        let a = verify_output(text, "ID <R> then ID 1234 again", &[v]).unwrap();
        assert_eq!(a.occurrences, [Removed]);
        assert!(a.context_preserved);
    }

    #[test]
    fn touching_and_overlapping_ranges_merge_into_one_span() {
        let text = "x ABCDEF y";
        let a = r(2, 5); // ABC
        let b = r(5, 8); // DEF (touches)
        let c = r(4, 6); // overlaps both
        let out = verify_output(text, "x <R> y", &[a, b, c]).unwrap();
        assert_eq!(out.occurrences, [Removed, Removed, Removed]);
        assert!(out.context_preserved);
        let out = verify_output(text, "x ABCDEF y", &[a, b]).unwrap();
        assert_eq!(out.occurrences, [ResidualPresent, ResidualPresent]);
    }

    #[test]
    fn no_occurrences_means_the_text_must_be_unchanged() {
        let text = "nothing to remove";
        assert!(verify_output(text, text, &[]).unwrap().context_preserved);
        let a = verify_output(text, "nothing to <R>", &[]).unwrap();
        assert!(!a.context_preserved);
        assert!(a.occurrences.is_empty());
    }

    #[test]
    fn korean_combining_and_emoji_context_is_compared_by_bytes() {
        // Multi-byte context on both sides; ranges are byte offsets.
        let text = "연락처: user@example.invalid 😀 e\u{301} 끝";
        let v = range_of(text, "user@example.invalid");
        let ok = "연락처: <R> 😀 e\u{301} 끝";
        let a = verify_output(text, ok, &[v]).unwrap();
        assert_eq!(a.occurrences, [Removed]);
        assert!(a.context_preserved);
        // NFC-normalized combining mark in the output is a different byte sequence: collateral.
        let normalized = "연락처: <R> 😀 \u{e9} 끝";
        let a = verify_output(text, normalized, &[v]).unwrap();
        assert_eq!(a.occurrences, [CollateralChange]);
    }

    #[test]
    fn invalid_input_is_refused_not_repaired() {
        let text = "한국어 text";
        assert_eq!(
            verify_output(text, text, &[r(1, 2)]),
            Err(OutputError::Range(RangeError::NotOnCharBoundary))
        );
        assert_eq!(
            verify_output(text, text, &[r(3, 3)]),
            Err(OutputError::Range(RangeError::Empty))
        );
        assert_eq!(
            verify_output(text, text, &[r(0, 1000)]),
            Err(OutputError::Range(RangeError::OutOfBounds))
        );
        let many: Vec<ByteRange> = (0..=MAX_EXPECTATIONS_PER_VARIANT as u64)
            .map(|i| r(i, i + 1))
            .collect();
        let long = "x".repeat(64);
        assert_eq!(
            verify_output(&long, &long, &many),
            Err(OutputError::TooManyOccurrences)
        );
        let huge = "y".repeat(MAX_SANITIZED_BYTES + 1);
        assert_eq!(
            verify_output("abc", &huge, &[r(0, 1)]),
            Err(OutputError::OutputTooLarge)
        );
    }

    #[test]
    fn verdicts_do_not_depend_on_the_order_of_the_ranges() {
        let text = "A: first-value B: second-value C: third-value .";
        let rs = [
            range_of(text, "first-value"),
            range_of(text, "second-value"),
            range_of(text, "third-value"),
        ];
        let sanitized = "A: <R> B: second-value C: <R> .";
        let base = verify_output(text, sanitized, &rs).unwrap().occurrences;
        assert_eq!(base, [Removed, ResidualPresent, Removed]);
        for perm in [[2, 0, 1], [1, 2, 0], [2, 1, 0], [0, 2, 1], [1, 0, 2]] {
            let shuffled: Vec<ByteRange> = perm.iter().map(|&i| rs[i]).collect();
            let got = verify_output(text, sanitized, &shuffled)
                .unwrap()
                .occurrences;
            let expected: Vec<_> = perm.iter().map(|&i| base[i]).collect();
            assert_eq!(got, expected);
        }
    }
}
