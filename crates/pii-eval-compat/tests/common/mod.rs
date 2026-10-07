//! Builders shared by the compat tests. Not part of the crate.
#![allow(dead_code)]

use pii_eval_compat::legacy::{LegacyExpectation, LegacyOutcome, LegacyScanner, interpret};
use pii_eval_contracts::{
    ActionCapability, ActionExpectation, ByteRange, CapabilityState, ContextClass,
    ContextObligation, Expectation, ExpectedType, FamilyId, Finding, Id, JurisdictionCode,
    ScannerCapabilities, ScannerStatus, SensitivityExpectation,
};
use pii_eval_kernel::{OccurrenceAssessment, ScannerView, VariantInput, assess_variant};

pub const A: &str = "연락처: kim@example.test 입니다";
pub const EMAIL: &str = "pii:global:email";
pub const PHONE: &str = "pii:global:phone";

pub fn range(start: u64, end: u64) -> ByteRange {
    ByteRange { start, end }
}

pub fn found(start: u64, end: u64, family: &str) -> Finding {
    Finding {
        range: range(start, end),
        family: Some(FamilyId::new(family).unwrap()),
        jurisdiction: None,
        sensitive: Some(true),
        action: None,
    }
}

pub fn supported() -> ScannerCapabilities {
    ScannerCapabilities {
        ranges: CapabilityState::Supported,
        family_classification: CapabilityState::Supported,
        sensitivity_classification: CapabilityState::Supported,
        jurisdiction_reporting: CapabilityState::Supported,
        action: ActionCapability::ReportedAction,
        families: vec![],
        jurisdictions: vec![],
    }
}

/// One authored occurrence, shared by the legacy and canonical sides.
#[derive(Clone)]
pub struct Case {
    pub candidate: ByteRange,
    pub expected_type: ExpectedType,
    pub family: FamilyId,
    pub jurisdiction: Option<JurisdictionCode>,
    pub sensitivity: SensitivityExpectation,
}

impl Case {
    pub fn email(sensitivity: SensitivityExpectation) -> Case {
        Case {
            candidate: range(11, 27),
            expected_type: ExpectedType::Valid,
            family: FamilyId::new(EMAIL).unwrap(),
            jurisdiction: None,
            sensitivity,
        }
    }
}

pub fn legacy(case: &Case, findings: &[Finding]) -> LegacyOutcome {
    interpret(
        &LegacyExpectation {
            candidate: case.candidate,
            expected_type: case.expected_type,
            family: &case.family,
            jurisdiction: case.jurisdiction.as_ref(),
            sensitivity: case.sensitivity,
        },
        &LegacyScanner {
            status: ScannerStatus::Complete,
            findings,
        },
    )
}

pub fn canonical_with(
    text: &str,
    case: &Case,
    findings: &[Finding],
    caps: &ScannerCapabilities,
) -> OccurrenceAssessment {
    let e = [Expectation {
        occurrence_id: Id::new("occ-a").unwrap(),
        range: Some(case.candidate),
        family: case.family.clone(),
        type_expectation: case.expected_type,
        validator: None,
        sensitivity: case.sensitivity,
        context_class: ContextClass::Neutral,
        context_obligation: ContextObligation::None,
        action: ActionExpectation::NotSpecified,
    }];
    assess_variant(
        &VariantInput {
            text,
            case_jurisdiction: case.jurisdiction.as_ref(),
            expectations: &e,
        },
        &ScannerView {
            status: ScannerStatus::Complete,
            capabilities: caps,
            findings,
        },
    )
    .expect("valid input")
    .occurrences
    .remove(0)
}

pub fn canonical(case: &Case, findings: &[Finding]) -> OccurrenceAssessment {
    canonical_with(A, case, findings, &supported())
}

/// SplitMix64, as in the kernel's property tests.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            items.swap(i, self.below(i + 1));
        }
    }
}
