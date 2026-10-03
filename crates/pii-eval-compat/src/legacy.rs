//! `legacy-first-overlap`: the oracle's selection and outcome rules, reproduced
//! exactly and named as a migration compatibility mode.
//!
//! Source: `interpretPiiOutcome`, `rangeOutcome` and `overlaps` in
//! `benchmarks/evaluation/domains/pii/contract-model.ts` at the oracle pin.
//! Nothing here is a fix. Known quirks are kept on purpose and pinned by tests:
//!
//! - the finding that decides every axis is the **first overlapping finding in
//!   the order given**, so the result depends on input order;
//! - the overlap test is `a.start < b.end && b.start < a.end` applied to
//!   whatever numbers arrive, so an empty finding strictly inside the
//!   candidate, or an inverted one, counts as overlapping and as `partial`;
//! - an invalid-type expectation is `invalid-accepted` when *any* finding
//!   overlaps, however weak the overlap;
//! - a missing `sensitive` value reads as "not flagged";
//! - scanner capabilities are not consulted, only the presence of fields;
//! - findings are not validated against the text and nothing is deduplicated
//!   (duplicates count in `finding_count`).
//!
//! The oracle also filtered findings by file path; in the contracts a finding
//! list is already per input, so the caller passes only that input's findings.
//! Order is the caller's responsibility: the oracle used scanner emission
//! order, while a contract document stores findings in canonical order (see
//! ADR 0004, difference D2).

use std::collections::BTreeSet;

use pii_eval_contracts::{
    ByteRange, ExpectedType, FamilyId, Finding, JurisdictionCode, ObservedSummary, RangeState,
    ScannerStatus, SensitivityExpectation, SensitivityState, TypeState,
};

/// Identifier of this compatibility mode.
pub const LEGACY_RULE_ID: &str = "legacy-first-overlap";

/// The legacy protocol revision: the oracle semantics frozen as `pii-v1`
/// revision 1 by the contracts.
pub const LEGACY_PROTOCOL_REVISION: u32 = 1;

/// The authored side of the legacy interpreter: one candidate range per variant.
#[derive(Debug, Clone, Copy)]
pub struct LegacyExpectation<'a> {
    /// The expected occurrence range (the oracle's `variant.candidate`).
    pub candidate: ByteRange,
    /// Authored type expectation.
    pub expected_type: ExpectedType,
    /// Authored family.
    pub family: &'a FamilyId,
    /// Authored jurisdiction (the oracle's `scope`), if the case has one.
    pub jurisdiction: Option<&'a JurisdictionCode>,
    /// Authored sensitivity expectation.
    pub sensitivity: SensitivityExpectation,
}

/// What the scanner reported, in the order it was reported.
#[derive(Debug, Clone, Copy)]
pub struct LegacyScanner<'a> {
    /// Run status.
    pub status: ScannerStatus,
    /// Findings for this variant, **in emission order**.
    pub findings: &'a [Finding],
}

/// The legacy outcome of one variant: two axes, range and an observed summary.
/// There is no action axis in the legacy model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyOutcome {
    /// Type-identity state.
    pub type_identity: TypeState,
    /// Sensitivity-context state.
    pub sensitivity_context: SensitivityState,
    /// Range state of the first overlapping finding.
    pub range: RangeState,
    /// Count of **all** overlapping findings and their families and
    /// jurisdictions, ascending and unique.
    pub observed: ObservedSummary,
}

/// The oracle's `overlaps`, applied to any numbers.
fn overlaps(a: &ByteRange, b: &ByteRange) -> bool {
    a.start < b.end && b.start < a.end
}

/// The oracle's `rangeOutcome`.
fn range_outcome(candidate: &ByteRange, finding: Option<&Finding>) -> RangeState {
    let Some(f) = finding else {
        return RangeState::Miss;
    };
    let r = &f.range;
    if r.start == candidate.start && r.end == candidate.end {
        RangeState::Exact
    } else if r.start <= candidate.start && r.end >= candidate.end {
        RangeState::Overbroad
    } else if overlaps(candidate, r) {
        RangeState::Partial
    } else {
        RangeState::Miss
    }
}

/// The oracle's `interpretPiiOutcome` for one variant.
pub fn interpret(expected: &LegacyExpectation<'_>, scanner: &LegacyScanner<'_>) -> LegacyOutcome {
    if scanner.status != ScannerStatus::Complete {
        return LegacyOutcome {
            type_identity: TypeState::NotMeasured,
            sensitivity_context: SensitivityState::NotMeasured,
            range: RangeState::NotApplicable,
            observed: ObservedSummary {
                finding_count: 0,
                families: Vec::new(),
                jurisdictions: Vec::new(),
            },
        };
    }
    let overlapping: Vec<&Finding> = scanner
        .findings
        .iter()
        .filter(|f| overlaps(&expected.candidate, &f.range))
        .collect();
    let first = overlapping.first().copied();

    let type_identity = match expected.expected_type {
        ExpectedType::Invalid => {
            if overlapping.is_empty() {
                TypeState::InvalidCorrect
            } else {
                TypeState::InvalidAccepted
            }
        }
        ExpectedType::Valid => match first {
            None => TypeState::Miss,
            Some(f) => match &f.family {
                None => TypeState::NotMeasured,
                Some(family) if family != expected.family => {
                    let differs = expected
                        .jurisdiction
                        .is_some_and(|ej| f.jurisdiction.as_ref().is_some_and(|fj| fj != ej));
                    if differs {
                        TypeState::WrongJurisdiction
                    } else {
                        TypeState::WrongFamily
                    }
                }
                Some(_) => match (expected.jurisdiction, &f.jurisdiction) {
                    (Some(_), None) => TypeState::NotMeasured,
                    (Some(ej), Some(fj)) if fj != ej => TypeState::WrongJurisdiction,
                    _ => TypeState::Correct,
                },
            },
        },
    };

    let flagged = first.is_some_and(|f| f.sensitive == Some(true));
    let sensitivity_context = match (expected.sensitivity, flagged) {
        (SensitivityExpectation::NotEstablished, _) => SensitivityState::Unresolved,
        (SensitivityExpectation::Sensitive, true)
        | (SensitivityExpectation::NonSensitive, false) => SensitivityState::Correct,
        (SensitivityExpectation::Sensitive, false) => SensitivityState::Miss,
        (SensitivityExpectation::NonSensitive, true) => SensitivityState::FalsePositive,
    };

    let families: BTreeSet<_> = overlapping
        .iter()
        .filter_map(|f| f.family.clone())
        .collect();
    let jurisdictions: BTreeSet<_> = overlapping
        .iter()
        .filter_map(|f| f.jurisdiction.clone())
        .collect();
    LegacyOutcome {
        type_identity,
        sensitivity_context,
        range: range_outcome(&expected.candidate, first),
        observed: ObservedSummary {
            finding_count: overlapping.len() as u64,
            families: families.into_iter().collect(),
            jurisdictions: jurisdictions.into_iter().collect(),
        },
    }
}

/// The oracle's group rule for `benign-suppression-rate` and
/// `jurisdiction-collision-rate` (`accounting.ts` `groupBucket`: `group.some(event)`):
/// a case counts when ANY of its rows passes. The canonical accounting requires ALL
/// rows to pass (ADR 0008, A8); this helper exists so the difference is
/// executable, not only described. `passes` is one bool per row of the case,
/// after review-required and not-measured rows have been resolved.
pub fn legacy_any_row_passes(passes: &[bool]) -> bool {
    passes.iter().any(|p| *p)
}
