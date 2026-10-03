//! Normalization of native findings into contract findings.
//!
//! This is where adapter output meets the kernel: each reported range is
//! converted from the scanner's declared offset unit to a validated half-open
//! UTF-8 byte range, exactly once, against the exact text that was sent. A
//! range that does not convert (empty, inverted, past the end, inside a
//! character or surrogate pair) makes the whole scan malformed output; it is
//! never clamped, rounded or dropped.
//!
//! Cost: one [`RangeTranslator`] is built per text (O(text), at most 1 MiB, at
//! most 8 MiB of tables) and each finding costs O(log text). With the
//! findings bound (10,000 by default and by contract) the total work is
//! bounded by `text + findings * log(text)`; `max_findings` is checked before
//! any conversion. Measured note: 10,000 findings over a 1 MiB text normalize
//! in well under a second in a debug build (see the probe test in
//! `tests/normalize_cost.rs`).
//!
//! Each reported family and jurisdiction is also checked against what the
//! running scanner declared for its activation. A finding the scanner said it
//! could not produce is [`MalformedKind::Undeclared`], not a pass-through.

use pii_eval_contracts::{CapabilityState, Finding, ScannerCapabilities};
use pii_eval_kernel::{OffsetUnit, RangeError, RangeTranslator};

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

/// How a kernel range error is reported. Every case is malformed shim output
/// (the contract has no finer failure code for it) except an oversize text,
/// which is the caller's: the adapter refuses oversize text before sending it,
/// so that arm is unreachable in a session and is mapped for completeness.
fn range_failure(error: RangeError) -> AdapterError {
    match error {
        RangeError::TextTooLarge => AdapterError::InputTooLarge,
        RangeError::Empty
        | RangeError::Inverted
        | RangeError::OffsetTooLarge
        | RangeError::OutOfBounds
        | RangeError::NotOnCharBoundary
        | RangeError::InsideSurrogatePair
        | RangeError::InvalidUtf8 => AdapterError::MalformedOutput(MalformedKind::InvalidRange),
    }
}

/// Convert `raw` for `text`. `max_findings` bounds the native list before any
/// work; `declared` is the running scanner's capability declaration.
pub fn normalize_findings(
    text: &str,
    unit: OffsetUnit,
    raw: &[RawFinding],
    vocabulary: &dyn ScannerVocabulary,
    declared: &ScannerCapabilities,
    max_findings: usize,
) -> Result<Normalized, AdapterError> {
    if raw.len() > max_findings {
        return Err(AdapterError::OutputLimit(LimitKind::Findings));
    }
    let mut mapped_findings = Vec::new();
    let mut skipped = 0u64;
    for native in raw {
        match vocabulary
            .map_finding(native)
            .map_err(AdapterError::MalformedOutput)?
        {
            Mapped::Skip => skipped += 1,
            Mapped::Finding(mapped) => mapped_findings.push((native, mapped)),
        }
    }
    let mut findings = Vec::with_capacity(mapped_findings.len());
    if !mapped_findings.is_empty() {
        let translator = RangeTranslator::new(text, unit).map_err(range_failure)?;
        for (native, mapped) in mapped_findings {
            let undeclared = mapped
                .family
                .as_ref()
                .is_some_and(|f| declared.family_state(f) != CapabilityState::Supported)
                || mapped
                    .jurisdiction
                    .as_ref()
                    .is_some_and(|j| declared.jurisdiction_state(j) != CapabilityState::Supported);
            if undeclared {
                return Err(AdapterError::MalformedOutput(MalformedKind::Undeclared));
            }
            let range = translator
                .translate(native.start, native.end)
                .map_err(range_failure)?;
            findings.push(Finding {
                range,
                family: mapped.family,
                jurisdiction: mapped.jurisdiction,
                sensitive: mapped.sensitive,
                action: mapped.action,
            });
        }
    }
    findings.sort();
    Ok(Normalized { findings, skipped })
}
