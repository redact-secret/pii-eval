//! The authored `not-established` type identity (schema 1.3, ADR 0017), at the
//! contract level: the version gate with its stable reason code, additivity (a
//! population without the value keeps its version, bytes and digest), and the
//! outcome lattice.

mod common;

use common::*;
use pii_eval_contracts::*;

fn with_uncertain_identity(visibility: Visibility) -> CorpusSnapshotBody {
    let mut body = snapshot_body(visibility);
    let e = &mut body.cases[0].variants[0].expectations[0];
    e.type_expectation = ExpectedType::NotEstablished;
    body
}

#[test]
fn a_population_without_the_value_keeps_its_version_and_digest() {
    let body = snapshot_body(Visibility::PublicSynthetic);
    assert!(!body.authors_not_established_identity());
    let snapshot = sealed(CorpusSnapshot::unsealed(body));
    assert_eq!(snapshot.schema_version, SchemaVersion::CURRENT);
}

#[test]
fn a_population_that_authors_the_value_is_sealed_under_1_3() {
    let body = with_uncertain_identity(Visibility::PublicSynthetic);
    assert!(body.authors_not_established_identity());
    let snapshot = sealed(CorpusSnapshot::unsealed(body));
    assert_eq!(snapshot.schema_version, SchemaVersion::V1_3);
    assert!(validate(&snapshot).is_ok());
}

#[test]
fn the_value_under_an_older_schema_is_refused_with_its_own_reason() {
    for older in [
        SchemaVersion::V1_0,
        SchemaVersion::V1_1,
        SchemaVersion::V1_2,
    ] {
        let mut snapshot =
            CorpusSnapshot::unsealed(with_uncertain_identity(Visibility::PublicSynthetic));
        snapshot.schema_version = older;
        let snapshot = sealed(snapshot);
        let err = validate(&snapshot).unwrap_err();
        assert_eq!(
            err.first_code(),
            Some(ReasonCode::IdentityNotEstablishedGate),
            "{older}"
        );
    }
}

#[test]
fn the_lattice_makes_unresolved_the_only_measured_observation() {
    assert_eq!(
        TypeState::reachable(ExpectedType::NotEstablished),
        &[TypeState::Unresolved, TypeState::NotMeasured]
    );
    // Unresolved is reachable only from an uncertain identity.
    for t in [ExpectedType::Valid, ExpectedType::Invalid] {
        assert!(!TypeState::reachable(t).contains(&TypeState::Unresolved));
    }
    assert_eq!(TypeState::Unresolved.status(), AxisStatus::ReviewRequired);
}
