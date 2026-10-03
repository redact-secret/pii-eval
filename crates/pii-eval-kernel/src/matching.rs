//! The canonical, order-invariant matching rule (`pii-v1-canonical`).
//!
//! Specified in `docs/adr/0004-order-invariant-pii-matching.md`. The legacy
//! first-overlapping-finding rule is not here: it lives, unchanged, in
//! `pii-eval-compat` as `legacy-first-overlap`.
//!
//! The result of [`assess_variant`] is a function of the *set* of findings and
//! the *set* of expectations: findings and expectations are sorted into a
//! total canonical order first, so no input permutation can change an outcome.
//! Duplicates are kept (never merged) and counted.
//!
//! Per expected occurrence, among the findings that overlap it (its
//! candidates), one *primary* finding is selected by [`closeness`], then by
//! identity evidence, then by canonical finding order; all four
//! axes of the occurrence are judged on the primary. Other candidates remain
//! visible through the candidate count, the observed summary and the
//! per-finding [`ReportedSpan`] rows, so multi-span behavior is accounted for
//! instead of discarded.
//!
//! Capabilities are honored through the contracts' lattice: an axis whose
//! capability is unsupported (or undeclared with no evidence) is
//! `not-measured`, never a pass. Every produced row satisfies
//! `pii_eval_contracts::validate_outcome_lattice` (a test checks this).

use std::collections::BTreeSet;

pub use pii_eval_contracts::axes::OutcomeRow;
use pii_eval_contracts::limits::{
    MAX_EXPECTATIONS_PER_VARIANT, MAX_FINDINGS_PER_INPUT, MAX_TEXT_BYTES,
};
use pii_eval_contracts::{
    ActionCapability, ActionOutcome, ByteRange, CapabilityState, Expectation, ExpectedType,
    Finding, Id, JurisdictionCode, ObservedSummary, RangeState, ScannerCapabilities, ScannerStatus,
    SensitivityExpectation, SensitivityState, TypeState,
};

use crate::range::{RangeError, validate_range};

/// Identifier of the canonical matching rule.
pub const MATCHING_RULE_ID: &str = "pii-v1-canonical";

/// Protocol revision this rule belongs to: revision 2, bound in every
/// revision-2 document by `ProtocolIdentity::CANONICAL_V2` (ADR 0008; ADR 0004
/// "Contract impact" is resolved there).
pub const MATCHING_PROTOCOL_REVISION: u32 = 2;

/// Where a range failure was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subject {
    /// An authored expectation's range.
    Expectation(ByteRange),
    /// A reported finding's range.
    Finding(ByteRange),
}

/// Why an assessment was refused. Input is rejected, never repaired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssessError {
    /// A range failed validation against the original text.
    Range {
        /// Which range.
        subject: Subject,
        /// What was wrong with it.
        error: RangeError,
    },
    /// Two expectations share an occurrence id.
    DuplicateOccurrence,
    /// More than `MAX_FINDINGS_PER_INPUT` findings.
    TooManyFindings,
    /// More than `MAX_EXPECTATIONS_PER_VARIANT` expectations.
    TooManyExpectations,
    /// Text longer than `MAX_TEXT_BYTES`.
    TextTooLarge,
}

/// The authored side of one variant.
#[derive(Debug, Clone, Copy)]
pub struct VariantInput<'a> {
    /// The exact input text; ranges are byte offsets into it.
    pub text: &'a str,
    /// Case jurisdiction, or `None` for a global case.
    pub case_jurisdiction: Option<&'a JurisdictionCode>,
    /// Expected occurrences, in any order.
    pub expectations: &'a [Expectation],
}

/// What a scanner reported for one variant.
#[derive(Debug, Clone, Copy)]
pub struct ScannerView<'a> {
    /// Run status; anything but `complete` measures nothing.
    pub status: ScannerStatus,
    /// Declared capabilities.
    pub capabilities: &'a ScannerCapabilities,
    /// Findings for the variant, in any order. Duplicates are meaningful.
    pub findings: &'a [Finding],
}

/// The relation of one reported finding to one expected occurrence.
/// `None` when they do not overlap (adjacent half-open ranges do not overlap).
pub fn relation(expected: &ByteRange, reported: &ByteRange) -> Option<RangeState> {
    if !overlaps(expected, reported) {
        None
    } else if reported == expected {
        Some(RangeState::Exact)
    } else if reported.start <= expected.start && reported.end >= expected.end {
        Some(RangeState::Overbroad)
    } else {
        Some(RangeState::Partial)
    }
}

/// Half-open overlap of two validated (non-empty, ordered) ranges.
pub fn overlaps(a: &ByteRange, b: &ByteRange) -> bool {
    a.start < b.end && b.start < a.end
}

/// Range state for an occurrence given its primary finding's range (`None` is
/// a miss). Same geometry as the legacy rule, for validated ranges.
pub fn range_state(expected: &ByteRange, primary: Option<&ByteRange>) -> RangeState {
    primary
        .and_then(|p| relation(expected, p))
        .unwrap_or(RangeState::Miss)
}

/// Closeness of an overlapping finding to an expectation; smaller is closer.
/// `(rank, tightness)`:
///
/// - exact: `(0, 0)`;
/// - overbroad (reported contains expected): `(1, reported length - expected length)`,
///   the fewer extra bytes the closer;
/// - partial: `(2, expected length - overlap length)`, the more of the expected
///   range covered the closer.
///
/// Returns `None` when the ranges do not overlap.
pub fn closeness(expected: &ByteRange, reported: &ByteRange) -> Option<(u8, u64)> {
    // Saturating: total on unvalidated (empty or inverted) ranges.
    let len = |r: &ByteRange| r.end.saturating_sub(r.start);
    Some(match relation(expected, reported)? {
        RangeState::Exact => (0, 0),
        RangeState::Overbroad => (1, len(reported).saturating_sub(len(expected))),
        RangeState::Partial => {
            let overlap = expected
                .end
                .min(reported.end)
                .saturating_sub(expected.start.max(reported.start));
            (2, len(expected).saturating_sub(overlap))
        }
        // `relation` never yields these.
        RangeState::Miss | RangeState::NotApplicable => return None,
    })
}

/// How a reported finding relates to the occurrences it overlaps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpanMatch {
    /// Index into [`VariantAssessment::occurrences`] of the occurrence the
    /// finding is closest to (ties go to the lowest occurrence id).
    pub occurrence: usize,
    /// Relation to that occurrence: exact, overbroad or partial.
    pub state: RangeState,
    /// How many occurrences the finding overlaps in total (at least 1).
    pub overlapping_occurrences: u32,
}

/// One reported finding, accounted for exactly once (duplicates are separate rows).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportedSpan {
    /// The finding's byte range.
    pub range: ByteRange,
    /// Relation to the occurrences, or `None` for a finding overlapping none.
    pub matched: Option<SpanMatch>,
}

/// The assessment of one expected occurrence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OccurrenceAssessment {
    /// The expected occurrence.
    pub occurrence_id: Id,
    /// The four axes.
    pub row: OutcomeRow,
    /// Index into [`VariantAssessment::findings`] of the primary finding.
    pub primary: Option<usize>,
    /// Candidate findings (overlapping, duplicates counted), families and
    /// jurisdictions: identifiers only, never text.
    pub observed: ObservedSummary,
}

/// The assessment of one variant under one scanner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariantAssessment {
    /// Occurrences in ascending occurrence-id order.
    pub occurrences: Vec<OccurrenceAssessment>,
    /// The findings in canonical order (what `primary` indexes). Empty when
    /// the scanner measured nothing.
    pub findings: Vec<Finding>,
    /// One row per finding, in canonical order.
    pub reported: Vec<ReportedSpan>,
}

fn unmeasured_row() -> OutcomeRow {
    OutcomeRow {
        type_identity: TypeState::NotMeasured,
        sensitivity_context: SensitivityState::NotMeasured,
        range: RangeState::NotApplicable,
        action: ActionOutcome::NotMeasured,
    }
}

fn empty_summary() -> ObservedSummary {
    ObservedSummary {
        finding_count: 0,
        families: Vec::new(),
        jurisdictions: Vec::new(),
    }
}

/// Identity evidence of a finding for an expectation; smaller is stronger. Used
/// only to break ties between findings of equal closeness: 0 reports the
/// expected family (with the case jurisdiction, when the case has one), 1
/// reports another family or a mismatching jurisdiction, 2 reports no family.
fn identity_rank(e: &Expectation, case_jurisdiction: Option<&JurisdictionCode>, f: &Finding) -> u8 {
    match &f.family {
        None => 2,
        Some(family) if *family == e.family => match (case_jurisdiction, &f.jurisdiction) {
            (Some(expected), Some(reported)) if expected != reported => 1,
            (Some(_), None) => 1,
            _ => 0,
        },
        Some(_) => 1,
    }
}

/// Evidence completeness: 3 minus the number of optional fields (jurisdiction,
/// sensitivity, action) the finding reports; smaller is more complete. Breaks
/// ties after identity evidence so a finding that reports more is never
/// shadowed by an otherwise equal one that reports less.
fn completeness_rank(f: &Finding) -> u8 {
    3 - u8::from(f.jurisdiction.is_some())
        - u8::from(f.sensitive.is_some())
        - u8::from(f.action.is_some())
}

fn type_state(
    e: &Expectation,
    case_jurisdiction: Option<&JurisdictionCode>,
    caps: &ScannerCapabilities,
    primary: Option<&Finding>,
    candidates: usize,
) -> TypeState {
    // Same precedence as the contracts' lattice: an unsupported family
    // classification, expected family or expected jurisdiction leaves the axis
    // unmeasured, for valid and invalid expectations alike.
    if caps.family_classification == CapabilityState::Unsupported
        || caps.family_state(&e.family) == CapabilityState::Unsupported
        || case_jurisdiction
            .is_some_and(|j| caps.jurisdiction_state(j) == CapabilityState::Unsupported)
    {
        return TypeState::NotMeasured;
    }
    match e.type_expectation {
        ExpectedType::Invalid => {
            if candidates > 0 {
                TypeState::InvalidAccepted
            } else {
                TypeState::InvalidCorrect
            }
        }
        ExpectedType::Valid => {
            let Some(p) = primary else {
                return TypeState::Miss;
            };
            let Some(family) = &p.family else {
                return TypeState::NotMeasured;
            };
            if *family != e.family {
                let jurisdiction_differs = case_jurisdiction
                    .is_some_and(|ej| p.jurisdiction.as_ref().is_some_and(|pj| pj != ej));
                if jurisdiction_differs {
                    TypeState::WrongJurisdiction
                } else {
                    TypeState::WrongFamily
                }
            } else {
                match (case_jurisdiction, &p.jurisdiction) {
                    (Some(_), None) => TypeState::NotMeasured,
                    (Some(ej), Some(pj)) if pj != ej => TypeState::WrongJurisdiction,
                    _ => TypeState::Correct,
                }
            }
        }
    }
}

fn sensitivity_state(
    e: &Expectation,
    caps: &ScannerCapabilities,
    primary: Option<&Finding>,
) -> SensitivityState {
    if caps.sensitivity_classification == CapabilityState::Unsupported {
        return SensitivityState::NotMeasured;
    }
    if e.sensitivity == SensitivityExpectation::NotEstablished {
        return SensitivityState::Unresolved;
    }
    // Absence of a reported value is never a negative answer. The one
    // exception is no finding at all, which is a negative observation only
    // from a scanner that declares sensitivity support.
    let flagged = match primary {
        Some(p) => match p.sensitive {
            Some(flag) => flag,
            None => return SensitivityState::NotMeasured,
        },
        None if caps.sensitivity_classification == CapabilityState::Supported => false,
        None => return SensitivityState::NotMeasured,
    };
    match (e.sensitivity, flagged) {
        (SensitivityExpectation::Sensitive, true)
        | (SensitivityExpectation::NonSensitive, false) => SensitivityState::Correct,
        (SensitivityExpectation::Sensitive, false) => SensitivityState::Miss,
        (SensitivityExpectation::NonSensitive, true) => SensitivityState::FalsePositive,
        (SensitivityExpectation::NotEstablished, _) => SensitivityState::Unresolved,
    }
}

fn action_outcome(caps: &ScannerCapabilities, primary: Option<&Finding>) -> ActionOutcome {
    if caps.action == ActionCapability::Unavailable {
        return ActionOutcome::NotMeasured;
    }
    // Only a reported action is observable here. `output-verified` needs
    // sanitized output, which the kernel's matching never sees.
    match primary.and_then(|p| p.action) {
        Some(action) => ActionOutcome::Reported { action },
        None => ActionOutcome::NoActionReported,
    }
}

fn summarize(candidates: &[&Finding]) -> ObservedSummary {
    let families: BTreeSet<_> = candidates.iter().filter_map(|f| f.family.clone()).collect();
    let jurisdictions: BTreeSet<_> = candidates
        .iter()
        .filter_map(|f| f.jurisdiction.clone())
        .collect();
    ObservedSummary {
        finding_count: candidates.len() as u64,
        families: families.into_iter().collect(),
        jurisdictions: jurisdictions.into_iter().collect(),
    }
}

/// Assess one variant under one scanner with the canonical rule.
///
/// Findings and expectations may arrive in any order and the result is
/// identical. Every range is validated against `input.text` first; a failure
/// is returned as an error (the first in canonical order), never repaired.
/// A scanner that did not complete, or that cannot report ranges, measured
/// nothing: every row is unmeasured and its findings are not read.
pub fn assess_variant(
    input: &VariantInput<'_>,
    scanner: &ScannerView<'_>,
) -> Result<VariantAssessment, AssessError> {
    if input.text.len() > MAX_TEXT_BYTES {
        return Err(AssessError::TextTooLarge);
    }
    if input.expectations.len() > MAX_EXPECTATIONS_PER_VARIANT {
        return Err(AssessError::TooManyExpectations);
    }
    let mut expectations: Vec<&Expectation> = input.expectations.iter().collect();
    expectations.sort_by(|a, b| a.occurrence_id.cmp(&b.occurrence_id));
    if expectations
        .windows(2)
        .any(|w| w[0].occurrence_id == w[1].occurrence_id)
    {
        return Err(AssessError::DuplicateOccurrence);
    }
    for e in &expectations {
        validate_range(input.text, &e.range).map_err(|error| AssessError::Range {
            subject: Subject::Expectation(e.range),
            error,
        })?;
    }

    let caps = scanner.capabilities;
    if scanner.status != ScannerStatus::Complete || caps.ranges == CapabilityState::Unsupported {
        return Ok(VariantAssessment {
            occurrences: expectations
                .iter()
                .map(|e| OccurrenceAssessment {
                    occurrence_id: e.occurrence_id.clone(),
                    row: unmeasured_row(),
                    primary: None,
                    observed: empty_summary(),
                })
                .collect(),
            findings: Vec::new(),
            reported: Vec::new(),
        });
    }

    if scanner.findings.len() > MAX_FINDINGS_PER_INPUT {
        return Err(AssessError::TooManyFindings);
    }
    let mut findings: Vec<Finding> = scanner.findings.to_vec();
    findings.sort();
    for f in &findings {
        validate_range(input.text, &f.range).map_err(|error| AssessError::Range {
            subject: Subject::Finding(f.range),
            error,
        })?;
    }

    let mut occurrences = Vec::with_capacity(expectations.len());
    for e in &expectations {
        // Primary selection key: closeness, then identity evidence, then the
        // index. `findings` is in canonical order and `Finding: Ord` compares
        // every field, so the index is a total tie-break by finding value:
        // equal keys mean the same finding value, and the choice cannot
        // depend on input order.
        let mut candidates: Vec<(usize, (u8, u64))> = findings
            .iter()
            .enumerate()
            .filter_map(|(i, f)| closeness(&e.range, &f.range).map(|c| (i, c)))
            .collect();
        candidates.sort_by_key(|&(i, c)| {
            (
                c,
                identity_rank(e, input.case_jurisdiction, &findings[i]),
                completeness_rank(&findings[i]),
                i,
            )
        });
        let primary = candidates.first().map(|(i, _)| *i);
        let primary_finding = primary.map(|i| &findings[i]);
        let candidate_refs: Vec<&Finding> = candidates.iter().map(|(i, _)| &findings[*i]).collect();
        let row = OutcomeRow {
            type_identity: type_state(
                e,
                input.case_jurisdiction,
                caps,
                primary_finding,
                candidates.len(),
            ),
            sensitivity_context: sensitivity_state(e, caps, primary_finding),
            range: range_state(&e.range, primary_finding.map(|p| &p.range)),
            action: action_outcome(caps, primary_finding),
        };
        occurrences.push(OccurrenceAssessment {
            occurrence_id: e.occurrence_id.clone(),
            row,
            primary,
            observed: summarize(&candidate_refs),
        });
    }

    let reported = findings
        .iter()
        .map(|f| {
            let mut overlapping = 0u32;
            let mut best: Option<((u8, u64), usize, RangeState)> = None;
            for (k, e) in expectations.iter().enumerate() {
                if let (Some(c), Some(state)) =
                    (closeness(&e.range, &f.range), relation(&e.range, &f.range))
                {
                    overlapping += 1;
                    // Strict `<`: the lowest occurrence id wins a tie.
                    if best.is_none_or(|(bc, _, _)| c < bc) {
                        best = Some((c, k, state));
                    }
                }
            }
            ReportedSpan {
                range: f.range,
                matched: best.map(|(_, occurrence, state)| SpanMatch {
                    occurrence,
                    state,
                    overlapping_occurrences: overlapping,
                }),
            }
        })
        .collect();

    Ok(VariantAssessment {
        occurrences,
        findings,
        reported,
    })
}
