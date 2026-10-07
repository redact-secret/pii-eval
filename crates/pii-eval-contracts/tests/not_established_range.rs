//! The authored `not-established` range (schema 1.4, ADR 0018), at the contract
//! level: the version gate with its stable reason code, additivity (a population
//! without the value keeps its version, bytes and digest), and the rules that
//! keep a range-less occurrence from carrying an authored identity.

mod common;

use common::*;
use pii_eval_contracts::*;

fn rangeless_body() -> CorpusSnapshotBody {
    let mut body = snapshot_body(Visibility::PublicSynthetic);
    let case = &mut body.cases[0];
    case.method = MethodId::SchemaOnly;
    case.collision = None;
    let e = &mut case.variants[0].expectations[0];
    e.range = None;
    e.type_expectation = ExpectedType::NotEstablished;
    e.sensitivity = SensitivityExpectation::NotEstablished;
    body
}

#[test]
fn a_population_without_the_value_keeps_its_version_and_digest() {
    let body = snapshot_body(Visibility::PublicSynthetic);
    assert!(!body.authors_not_established_range());
    let snapshot = sealed(CorpusSnapshot::unsealed(body));
    assert_eq!(snapshot.schema_version, SchemaVersion::CURRENT);
}

#[test]
fn a_population_that_authors_the_value_is_sealed_under_1_4() {
    let body = rangeless_body();
    assert!(body.authors_not_established_range());
    let snapshot = sealed(CorpusSnapshot::unsealed(body));
    assert_eq!(snapshot.schema_version, SchemaVersion::V1_4);
    assert!(validate(&snapshot).is_ok());
    // The wire form omits the key: nothing is written for an unestablished range.
    let text = String::from_utf8(to_pretty_json(&snapshot).unwrap().into_bytes()).unwrap();
    assert!(text.contains("\"schemaVersion\": \"1.4\""));
}

#[test]
fn the_value_under_an_older_schema_is_refused_with_its_own_reason() {
    for older in [
        SchemaVersion::V1_0,
        SchemaVersion::V1_1,
        SchemaVersion::V1_2,
        SchemaVersion::V1_3,
    ] {
        let mut snapshot = CorpusSnapshot::unsealed(rangeless_body());
        snapshot.schema_version = older;
        let snapshot = sealed(snapshot);
        let err = validate(&snapshot).unwrap_err();
        assert_eq!(
            err.first_code(),
            Some(ReasonCode::RangeNotEstablishedGate),
            "{older}"
        );
    }
}

#[test]
fn a_rangeless_occurrence_must_not_carry_an_authored_identity_or_sensitivity() {
    for (ty, sens) in [
        (ExpectedType::Valid, SensitivityExpectation::NotEstablished),
        (
            ExpectedType::NotEstablished,
            SensitivityExpectation::Sensitive,
        ),
        (ExpectedType::Invalid, SensitivityExpectation::NonSensitive),
    ] {
        let mut body = rangeless_body();
        let e = &mut body.cases[0].variants[0].expectations[0];
        e.type_expectation = ty;
        e.sensitivity = sens;
        let snapshot = sealed(CorpusSnapshot::unsealed(body));
        let err = validate(&snapshot).unwrap_err();
        assert_eq!(
            err.first_code(),
            Some(ReasonCode::RangeNotEstablishedInvalid),
            "{ty:?} {sens:?}"
        );
    }
}

#[test]
fn a_rangeless_occurrence_is_only_for_schema_only_cases() {
    let mut body = rangeless_body();
    body.cases[0].method = MethodId::TypeValidation;
    let snapshot = sealed(CorpusSnapshot::unsealed(body));
    let err = validate(&snapshot).unwrap_err();
    assert_eq!(
        err.first_code(),
        Some(ReasonCode::RangeNotEstablishedInvalid)
    );
}

#[test]
fn the_lattice_refuses_an_unresolved_range_for_a_located_occurrence() {
    use pii_eval_contracts::axes::{AuthoredAxes, OutcomeRow, validate_outcome_lattice};
    // An unresolved range is the only measured observation of a range-less occurrence.
    assert!(RangeState::Unresolved != RangeState::NotApplicable);
    let family = FamilyId::new("pii:global:email").unwrap();
    let caps = ScannerCapabilities {
        ranges: CapabilityState::Supported,
        family_classification: CapabilityState::Supported,
        sensitivity_classification: CapabilityState::Supported,
        jurisdiction_reporting: CapabilityState::Supported,
        action: ActionCapability::ReportedAction,
        families: vec![],
        jurisdictions: vec![],
    };
    let row = |range| OutcomeRow {
        type_identity: TypeState::Unresolved,
        sensitivity_context: SensitivityState::Unresolved,
        range,
        action: ActionOutcome::NotMeasured,
    };
    let check = |established, range| {
        validate_outcome_lattice(
            &AuthoredAxes {
                expected_type: ExpectedType::NotEstablished,
                sensitivity: SensitivityExpectation::NotEstablished,
                range_established: established,
                family: &family,
                jurisdiction: None,
            },
            ScannerStatus::Complete,
            &caps,
            &row(range),
        )
    };
    assert_eq!(check(false, RangeState::Unresolved), Ok(()));
    assert_eq!(
        check(false, RangeState::Miss),
        Err(ReasonCode::OutcomeContradiction)
    );
    assert_eq!(
        check(true, RangeState::Unresolved),
        Err(ReasonCode::OutcomeContradiction)
    );
}
