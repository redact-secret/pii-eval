//! Probe for the normalization cost bound: the maximum number of findings over
//! the maximum text must normalize in bounded time, because conversion costs
//! one index build plus O(log n) per finding (not O(text) per finding, which
//! was about 21 s of CPU for this input before the kernel translator).
//! Needs no Node.

use std::time::{Duration, Instant};

use pii_eval_adapters::normalize::normalize_findings;
use pii_eval_adapters::redact_secret::RedactSecretVocabulary;
use pii_eval_adapters::{AdapterError, RawFinding, ScannerVocabulary};
use pii_eval_contracts::limits::{MAX_FINDINGS_PER_INPUT, MAX_TEXT_BYTES};
use pii_eval_contracts::{
    ActionCapability, CapabilityState, FamilyCapability, FamilyId, ScannerCapabilities,
};
use pii_eval_kernel::OffsetUnit;

fn declared() -> ScannerCapabilities {
    let mut caps = RedactSecretVocabulary.base_capabilities();
    caps.action = ActionCapability::SanitizedOutput;
    caps.families = vec![FamilyCapability {
        family: FamilyId::new("pii:global:email").unwrap(),
        state: CapabilityState::Supported,
    }];
    caps
}

fn finding(start: u64, end: u64) -> RawFinding {
    RawFinding {
        start,
        end,
        kind: "pii_global_email".to_owned(),
        detector: "pii-domain".to_owned(),
        action: Some("redact".to_owned()),
    }
}

#[test]
fn maximum_findings_over_maximum_text_normalize_in_bounded_time() {
    // 1 MiB of 3-byte Korean characters (1 UTF-16 unit each), the widest ratio
    // of bytes to units for the BMP.
    let text = "\u{D55C}".repeat(MAX_TEXT_BYTES / 3);
    let units = (MAX_TEXT_BYTES / 3) as u64;
    let raw: Vec<RawFinding> = (0..MAX_FINDINGS_PER_INPUT as u64)
        .map(|i| {
            let start = (i * 31) % (units - 2);
            finding(start, start + 2)
        })
        .collect();
    let started = Instant::now();
    let out = normalize_findings(
        &text,
        OffsetUnit::Utf16CodeUnits,
        &raw,
        &RedactSecretVocabulary,
        &declared(),
        MAX_FINDINGS_PER_INPUT,
    )
    .expect("normalizes");
    let elapsed = started.elapsed();
    println!(
        "normalized {} findings over {} bytes in {elapsed:?}",
        out.findings.len(),
        text.len()
    );
    assert_eq!(out.findings.len(), MAX_FINDINGS_PER_INPUT);
    // Spot check by hand: unit offset n is byte 3n.
    let first = raw[0].start;
    assert!(
        out.findings
            .iter()
            .any(|f| f.range.start == first * 3 && f.range.end == first * 3 + 6)
    );
    // Generous bound that stays far from CI noise yet far below the 21 s of the
    // per-finding O(text) scan.
    assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
}

#[test]
fn one_more_finding_than_allowed_is_refused_before_any_conversion() {
    let raw: Vec<RawFinding> = (0..=MAX_FINDINGS_PER_INPUT as u64)
        .map(|_| finding(0, 1))
        .collect();
    let err = normalize_findings(
        "ab",
        OffsetUnit::Utf16CodeUnits,
        &raw,
        &RedactSecretVocabulary,
        &declared(),
        MAX_FINDINGS_PER_INPUT,
    )
    .unwrap_err();
    assert_eq!(
        err,
        AdapterError::OutputLimit(pii_eval_adapters::error::LimitKind::Findings)
    );
}

#[test]
fn undeclared_families_and_jurisdictions_are_distinct_failures() {
    let mut ssn = finding(0, 1);
    ssn.kind = "pii_jurisdiction_us_ssn".to_owned();
    let err = normalize_findings(
        "ab",
        OffsetUnit::Utf16CodeUnits,
        &[ssn],
        &RedactSecretVocabulary,
        &declared(),
        10,
    )
    .unwrap_err();
    assert_eq!(
        err,
        AdapterError::MalformedOutput(pii_eval_adapters::error::MalformedKind::Undeclared)
    );
    // A declared family passes; an unmapped type (no family) is not an undeclared claim.
    let mut unmapped = finding(0, 1);
    unmapped.kind = "pii_novel".to_owned();
    let ok = normalize_findings(
        "ab",
        OffsetUnit::Utf16CodeUnits,
        &[finding(0, 1), unmapped],
        &RedactSecretVocabulary,
        &declared(),
        10,
    )
    .unwrap();
    assert_eq!(ok.findings.len(), 2);
}

#[test]
fn oversize_text_maps_to_the_input_error_not_to_a_scanner_range_error() {
    let big = "a".repeat(MAX_TEXT_BYTES + 1);
    let err = normalize_findings(
        &big,
        OffsetUnit::Utf16CodeUnits,
        &[finding(0, 1)],
        &RedactSecretVocabulary,
        &declared(),
        10,
    )
    .unwrap_err();
    assert_eq!(err, AdapterError::InputTooLarge);
}
