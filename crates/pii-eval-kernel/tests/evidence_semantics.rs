//! Independent protocol-3 vectors, no evidence importer or scanner involved.
mod common;
use common::*;
use pii_eval_contracts::*;

fn declared() -> ScannerCapabilities {
    let mut caps = supported();
    caps.families.push(FamilyCapability {
        family: FamilyId::new("pii:global:email").unwrap(),
        state: CapabilityState::Supported,
    });
    caps
}
fn negative() -> Expectation {
    let mut e = exp(
        "negative",
        0,
        1,
        "pii:global:email",
        ExpectedType::Invalid,
        SensitivityExpectation::NonSensitive,
    );
    e.range = None;
    e.evidence = Some(EvidenceSemantics {
        domains: vec![EvidenceDomain::Pii, EvidenceDomain::Phi],
        contexts: vec!["medical-record".into()],
        text_negative: true,
        authored_sensitivity: e.sensitivity,
    });
    e
}

#[test]
fn text_negative_measures_absence_and_presence_without_locating_an_occurrence() {
    let e = negative();
    let text = "x@y.z";
    for (findings, ty, sens) in [
        (vec![], TypeState::InvalidCorrect, SensitivityState::Correct),
        (
            vec![found(0, 5, "pii:global:email")],
            TypeState::InvalidAccepted,
            SensitivityState::FalsePositive,
        ),
        (
            vec![found(0, 5, "pii:global:phone")],
            TypeState::InvalidCorrect,
            SensitivityState::Correct,
        ),
    ] {
        let a = assess(text, None, std::slice::from_ref(&e), &findings, &declared());
        let o = &a.occurrences[0];
        assert_eq!(o.row.type_identity, ty);
        assert_eq!(o.row.sensitivity_context, sens);
        assert_eq!(o.row.range, RangeState::NotApplicable);
        assert_eq!(o.row.action, ActionOutcome::NotMeasured);
        assert!(o.primary.is_none());
        assert!(a.reported.iter().all(|r| r.matched.is_none()));
    }
}

#[test]
fn any_sensitive_target_finding_fails_independently_of_order() {
    let e = negative();
    let a = with_sensitive(found(0, 1, "pii:global:email"), Some(false));
    let b = found(2, 3, "pii:global:email");
    for findings in [vec![a.clone(), b.clone()], vec![b, a]] {
        let row = assess(
            "x y",
            None,
            std::slice::from_ref(&e),
            &findings,
            &declared(),
        )
        .occurrences[0]
            .row;
        assert_eq!(row.sensitivity_context, SensitivityState::FalsePositive);
    }
}

#[test]
fn missing_labels_and_unknown_capability_never_prove_absence() {
    let e = negative();
    let f = without_family(found(0, 1, "pii:global:email"));
    let row = assess("x", None, std::slice::from_ref(&e), &[f], &declared()).occurrences[0].row;
    assert_eq!(row.type_identity, TypeState::NotMeasured);
    assert_eq!(row.sensitivity_context, SensitivityState::NotMeasured);
    let mut caps = supported();
    caps.family_classification = CapabilityState::Undeclared;
    caps.sensitivity_classification = CapabilityState::Undeclared;
    let row = assess("x", None, &[e], &[], &caps).occurrences[0].row;
    assert_eq!(row.type_identity, TypeState::NotMeasured);
    assert_eq!(row.sensitivity_context, SensitivityState::NotMeasured);
}

#[test]
fn context_dependent_is_an_authored_uncertainty_not_a_binary_verdict() {
    let mut e = negative();
    e.range = Some(range(0, 1));
    e.type_expectation = ExpectedType::Valid;
    e.sensitivity = SensitivityExpectation::ContextDependent;
    let metadata = e.evidence.as_mut().unwrap();
    metadata.text_negative = false;
    metadata.authored_sensitivity = e.sensitivity;
    for findings in [vec![], vec![found(0, 1, "pii:global:email")]] {
        let row =
            assess("x", None, std::slice::from_ref(&e), &findings, &declared()).occurrences[0].row;
        assert_eq!(row.sensitivity_context, SensitivityState::Unresolved);
        assert_eq!(row.sensitivity_context.status(), AxisStatus::ReviewRequired);
    }
}

#[test]
fn an_unlabeled_finding_cannot_hide_behind_a_non_sensitive_target() {
    let e = negative();
    let benign = with_sensitive(found(0, 1, "pii:global:email"), Some(false));
    let unlabeled = without_family(found(2, 3, "pii:global:email"));
    let row = assess("x y", None, &[e], &[benign, unlabeled], &declared()).occurrences[0].row;
    assert_eq!(row.type_identity, TypeState::InvalidAccepted);
    assert_eq!(row.sensitivity_context, SensitivityState::NotMeasured);
}

#[test]
fn text_negative_uses_the_authored_jurisdiction_and_requires_missing_labels() {
    let mut e = negative();
    e.family = FamilyId::new("pii:us:ssn").unwrap();
    let mut caps = supported();
    caps.families.push(FamilyCapability {
        family: e.family.clone(),
        state: CapabilityState::Supported,
    });
    caps.jurisdictions.push(JurisdictionCapability {
        jurisdiction: JurisdictionCode::new("US").unwrap(),
        state: CapabilityState::Supported,
    });
    for (findings, ty, sensitivity) in [
        (vec![], TypeState::InvalidCorrect, SensitivityState::Correct),
        (
            vec![with_jurisdiction(found(0, 1, "pii:us:ssn"), "US")],
            TypeState::InvalidAccepted,
            SensitivityState::FalsePositive,
        ),
        (
            vec![with_jurisdiction(found(0, 1, "pii:us:ssn"), "GB")],
            TypeState::InvalidCorrect,
            SensitivityState::Correct,
        ),
        (
            vec![found(0, 1, "pii:us:ssn")],
            TypeState::NotMeasured,
            SensitivityState::NotMeasured,
        ),
    ] {
        let row =
            assess("x", Some("US"), std::slice::from_ref(&e), &findings, &caps).occurrences[0].row;
        assert_eq!(row.type_identity, ty);
        assert_eq!(row.sensitivity_context, sensitivity);
    }
}

mod acct_common;

#[test]
fn hand_counted_negative_and_context_dependent_cases_keep_independent_denominators() {
    use acct_common::{case, occ, outcomes_of, sid, snapshot_body, var};
    use pii_eval_kernel::{AuthoredIndex, ScannerInput, account_outcomes};
    let mut body = snapshot_body(vec![
        case(
            "a-negative",
            MethodId::SchemaOnly,
            "en",
            None,
            vec![var(
                "a-variant",
                ContextClass::Neutral,
                vec![occ(
                    "o1",
                    ExpectedType::Invalid,
                    SensitivityExpectation::NonSensitive,
                )],
            )],
        ),
        case(
            "b-context-dependent",
            MethodId::SchemaOnly,
            "en",
            None,
            vec![var(
                "b-variant",
                ContextClass::Neutral,
                vec![occ(
                    "o1",
                    ExpectedType::Valid,
                    SensitivityExpectation::ContextDependent,
                )],
            )],
        ),
    ]);
    for c in &mut body.cases {
        let e = &mut c.variants[0].expectations[0];
        let negative = e.type_expectation == ExpectedType::Invalid;
        if negative {
            e.range = None;
        }
        e.evidence = Some(EvidenceSemantics {
            domains: vec![EvidenceDomain::Pii, EvidenceDomain::Phi],
            contexts: vec!["medical/global/general".into()],
            text_negative: negative,
            authored_sensitivity: e.sensitivity,
        });
    }
    let mut snapshot = CorpusSnapshot::unsealed(body.clone());
    seal(&mut snapshot).unwrap();
    validate(&snapshot).unwrap();
    let rows = outcomes_of(
        "scanner",
        &body,
        &[
            (
                "a-negative",
                "a-variant",
                "o1",
                TypeState::InvalidCorrect,
                SensitivityState::Correct,
                RangeState::NotApplicable,
            ),
            (
                "b-context-dependent",
                "b-variant",
                "o1",
                TypeState::Correct,
                SensitivityState::Unresolved,
                RangeState::Exact,
            ),
        ],
    );
    let scanner = sid("scanner");
    let index = AuthoredIndex::new(&body).unwrap();
    let accounting = account_outcomes(
        &index,
        &[ScannerInput {
            id: &scanner,
            status: ScannerStatus::Complete,
        }],
        &rows,
        &Mechanics::PII_V1,
    )
    .unwrap();
    let metrics = accounting.scanners[0].overall.results();
    let get = |id| metrics.iter().find(|m| m.metric.id == id).unwrap();
    // Two independent axes for two authored cases: three measured, one
    // contextual uncertainty. No replay or domain label creates extra samples.
    assert_eq!(get(MetricId::MeasurableShare).counts.total, 4);
    assert_eq!(get(MetricId::MeasurableShare).counts.measured, 3);
    assert_eq!(get(MetricId::MeasurableShare).counts.unresolved, 1);
    assert_eq!(get(MetricId::NonSensitiveFlagRate).counts.measured, 1);
    assert_eq!(get(MetricId::NonSensitiveFlagRate).counts.numerator, 0);
    assert_eq!(get(MetricId::SensitiveMissRate).counts.eligible, 0);
    assert_eq!(get(MetricId::TypeMissRate).counts.eligible, 1);
    assert_eq!(get(MetricId::RangeCollateralRate).counts.eligible, 1);
}
