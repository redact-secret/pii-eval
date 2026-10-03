//! Normalization of native findings into contract findings.
//!
//! This is where adapter output meets the kernel: each reported range is
//! converted from the scanner's declared offset unit to a validated half-open
//! UTF-8 byte range with [`translate_range`], exactly once, against the exact
//! text that was sent. A range that does not convert (empty, inverted, past the
//! end, inside a character or surrogate pair) makes the whole scan malformed
//! output; it is never clamped, rounded or dropped.

use pii_eval_contracts::Finding;
use pii_eval_kernel::{OffsetUnit, translate_range};

use crate::error::{AdapterError, LimitKind, MalformedKind};
use crate::vocab::{Mapped, RawFinding, ScannerVocabulary};

/// Findings after normalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Normalized {
    /// Contract findings in canonical order. Duplicates are kept.
    pub findings: Vec<Finding>,
    /// Native findings that were not PII observations and were not reported.
    pub skipped: u64,
}

/// Convert `raw` for `text`. `max_findings` bounds the native list before any work.
pub fn normalize_findings(
    text: &str,
    unit: OffsetUnit,
    raw: &[RawFinding],
    vocabulary: &dyn ScannerVocabulary,
    max_findings: usize,
) -> Result<Normalized, AdapterError> {
    if raw.len() > max_findings {
        return Err(AdapterError::OutputLimit(LimitKind::Findings));
    }
    let mut findings = Vec::with_capacity(raw.len());
    let mut skipped = 0u64;
    for native in raw {
        let mapped = vocabulary
            .map_finding(native)
            .map_err(AdapterError::MalformedOutput)?;
        let Mapped::Finding(mapped) = mapped else {
            skipped += 1;
            continue;
        };
        let range = translate_range(text, unit, native.start, native.end)
            .map_err(|_| AdapterError::MalformedOutput(MalformedKind::InvalidRange))?;
        findings.push(Finding {
            range,
            family: mapped.family,
            jurisdiction: mapped.jurisdiction,
            sensitive: mapped.sensitive,
            action: mapped.action,
        });
    }
    findings.sort();
    Ok(Normalized { findings, skipped })
}
