//! Builders shared by the kernel's integration tests. Not part of the kernel.
#![allow(dead_code)]

use pii_eval_contracts::{
    ActionCapability, ActionExpectation, ActionKind, ByteRange, CapabilityState, ContextClass,
    ContextObligation, Expectation, ExpectedType, FamilyId, Finding, Id, JurisdictionCode,
    ScannerCapabilities, ScannerStatus, SensitivityExpectation,
};
use pii_eval_kernel::{ScannerView, VariantAssessment, VariantInput, assess_variant};

pub fn caps(state: CapabilityState) -> ScannerCapabilities {
    ScannerCapabilities {
        ranges: state,
        family_classification: state,
        sensitivity_classification: state,
        jurisdiction_reporting: state,
        action: ActionCapability::ReportedAction,
        families: vec![],
        jurisdictions: vec![],
    }
}

pub fn supported() -> ScannerCapabilities {
    caps(CapabilityState::Supported)
}

pub fn range(start: u64, end: u64) -> ByteRange {
    ByteRange { start, end }
}

pub fn exp(
    id: &str,
    start: u64,
    end: u64,
    family: &str,
    ty: ExpectedType,
    sens: SensitivityExpectation,
) -> Expectation {
    Expectation {
        occurrence_id: Id::new(id).unwrap(),
        range: Some(range(start, end)),
        family: FamilyId::new(family).unwrap(),
        type_expectation: ty,
        validator: None,
        sensitivity: sens,
        context_class: ContextClass::Neutral,
        context_obligation: ContextObligation::None,
        action: ActionExpectation::NotSpecified,
    }
}

/// A valid, sensitive occurrence of `family`.
pub fn valid(id: &str, start: u64, end: u64, family: &str) -> Expectation {
    exp(
        id,
        start,
        end,
        family,
        ExpectedType::Valid,
        SensitivityExpectation::Sensitive,
    )
}

/// A finding with a family, flagged sensitive, with no jurisdiction or action.
pub fn found(start: u64, end: u64, family: &str) -> Finding {
    Finding {
        range: range(start, end),
        family: Some(FamilyId::new(family).unwrap()),
        jurisdiction: None,
        sensitive: Some(true),
        action: None,
    }
}

pub fn with_jurisdiction(mut f: Finding, code: &str) -> Finding {
    f.jurisdiction = Some(JurisdictionCode::new(code).unwrap());
    f
}

pub fn with_sensitive(mut f: Finding, sensitive: Option<bool>) -> Finding {
    f.sensitive = sensitive;
    f
}

pub fn with_action(mut f: Finding, action: ActionKind) -> Finding {
    f.action = Some(action);
    f
}

pub fn without_family(mut f: Finding) -> Finding {
    f.family = None;
    f
}

pub fn assess(
    text: &str,
    jurisdiction: Option<&str>,
    expectations: &[Expectation],
    findings: &[Finding],
    capabilities: &ScannerCapabilities,
) -> VariantAssessment {
    let jurisdiction = jurisdiction.map(|j| JurisdictionCode::new(j).unwrap());
    assess_variant(
        &VariantInput {
            text,
            case_jurisdiction: jurisdiction.as_ref(),
            expectations,
        },
        &ScannerView {
            status: ScannerStatus::Complete,
            capabilities,
            findings,
        },
    )
    .expect("valid input")
}
