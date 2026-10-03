//! Per-variant outcome rows of the two Rust paths: the legacy compatibility
//! mode (`pii-eval-compat`, emission order, no validation) and the canonical
//! matcher (`pii-eval-kernel`, order-invariant). Test support.
#![allow(dead_code)]

use pii_eval_compat::legacy::{LegacyExpectation, LegacyOutcome, LegacyScanner, interpret};
use pii_eval_contracts::axes::OutcomeRow;
use pii_eval_contracts::{
    ActionOutcome, Finding, RangeState, ScannerCapabilities, ScannerStatus, SensitivityState,
    Strategy, TypeState,
};
use pii_eval_kernel::methods::apply_review_strategy;
use pii_eval_kernel::{AssessError, ScannerView, VariantAssessment, VariantInput, assess_variant};

use super::model::RVariant;

/// One outcome, normalized so both paths and the oracle compare field by field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row3 {
    pub type_state: TypeState,
    pub sensitivity_state: SensitivityState,
    pub range: RangeState,
    pub finding_count: u64,
    pub families: Vec<String>,
    pub jurisdictions: Vec<String>,
}

/// Gate by the variant's strategy exactly as the engine does (kernel
/// `apply_review_strategy`): a review-required variant has an unmeasured type axis.
pub fn gate(strategy: Strategy, mut row: Row3) -> Row3 {
    let gated = apply_review_strategy(
        OutcomeRow {
            type_identity: row.type_state,
            sensitivity_context: row.sensitivity_state,
            range: row.range,
            action: ActionOutcome::NotMeasured,
        },
        strategy,
    );
    row.type_state = gated.type_identity;
    row
}

fn from_legacy(o: &LegacyOutcome) -> Row3 {
    Row3 {
        type_state: o.type_identity,
        sensitivity_state: o.sensitivity_context,
        range: o.range,
        finding_count: o.observed.finding_count,
        families: o
            .observed
            .families
            .iter()
            .map(|f| f.as_str().to_owned())
            .collect(),
        jurisdictions: o
            .observed
            .jurisdictions
            .iter()
            .map(|j| j.as_str().to_owned())
            .collect(),
    }
}

/// The legacy rule over `findings` in the order given, gated.
pub fn legacy_row(v: &RVariant, status: ScannerStatus, findings: &[Finding]) -> Row3 {
    let e = &v.variant.expectations[0];
    let outcome = interpret(
        &LegacyExpectation {
            candidate: e.range,
            expected_type: e.type_expectation,
            family: &e.family,
            jurisdiction: v.case_jurisdiction.as_ref(),
            sensitivity: e.sensitivity,
        },
        &LegacyScanner { status, findings },
    );
    gate(v.variant.derivation.strategy, from_legacy(&outcome))
}

/// The canonical matcher over the same findings.
pub fn canonical_assessment(
    v: &RVariant,
    status: ScannerStatus,
    capabilities: &ScannerCapabilities,
    findings: &[Finding],
) -> Result<VariantAssessment, AssessError> {
    assess_variant(
        &VariantInput {
            text: &v.variant.text,
            case_jurisdiction: v.case_jurisdiction.as_ref(),
            expectations: &v.variant.expectations,
        },
        &ScannerView {
            status,
            capabilities,
            findings,
        },
    )
}

/// The canonical row of the first (only) occurrence, gated.
pub fn canonical_row(v: &RVariant, a: &VariantAssessment) -> Row3 {
    let o = &a.occurrences[0];
    gate(
        v.variant.derivation.strategy,
        Row3 {
            type_state: o.row.type_identity,
            sensitivity_state: o.row.sensitivity_context,
            range: o.row.range,
            finding_count: o.observed.finding_count,
            families: o
                .observed
                .families
                .iter()
                .map(|f| f.as_str().to_owned())
                .collect(),
            jurisdictions: o
                .observed
                .jurisdictions
                .iter()
                .map(|j| j.as_str().to_owned())
                .collect(),
        },
    )
}
