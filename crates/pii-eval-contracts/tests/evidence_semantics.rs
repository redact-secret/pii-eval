mod common;
use common::*;
use pii_eval_contracts::*;

fn body() -> CorpusSnapshotBody {
    let mut b = snapshot_body(Visibility::PublicSynthetic);
    let c = &mut b.cases[0];
    c.method = MethodId::SchemaOnly;
    c.collision = None;
    let e = &mut c.variants[0].expectations[0];
    e.range = None;
    e.type_expectation = ExpectedType::Invalid;
    e.sensitivity = SensitivityExpectation::NonSensitive;
    e.evidence = Some(EvidenceSemantics {
        domains: vec![EvidenceDomain::Pii, EvidenceDomain::Phi],
        contexts: vec!["medical-record".into()],
        text_negative: true,
        authored_sensitivity: e.sensitivity,
    });
    b
}

#[test]
fn semantic_path_requires_schema_1_5_and_protocol_3() {
    let s = sealed(CorpusSnapshot::unsealed(body()));
    assert_eq!(s.schema_version, SchemaVersion::V1_5);
    validate(&s).unwrap();
    let parsed: CorpusSnapshot = parse_default(to_pretty_json(&s).unwrap().as_bytes()).unwrap();
    assert_eq!(parsed.semantic, s.semantic);
    let mut old = s.clone();
    old.schema_version = SchemaVersion::V1_4;
    let old = sealed(old);
    assert_eq!(
        validate(&old).unwrap_err().first_code(),
        Some(ReasonCode::ProtocolBindingMismatch)
    );
}

#[test]
fn text_negative_cannot_assert_a_positive_or_invent_a_span() {
    for kind in 0..3 {
        let mut b = body();
        let e = &mut b.cases[0].variants[0].expectations[0];
        match kind {
            0 => e.type_expectation = ExpectedType::Valid,
            1 => {
                e.sensitivity = SensitivityExpectation::Sensitive;
                e.evidence.as_mut().unwrap().authored_sensitivity = e.sensitivity;
            }
            _ => e.range = Some(ByteRange { start: 0, end: 1 }),
        }
        assert!(validate(&sealed(CorpusSnapshot::unsealed(b))).is_err());
    }
}

#[test]
fn context_ids_are_bounded_sorted_unique_and_do_not_carry_free_text() {
    for ids in [
        vec!["medical".into(), "medical".into()],
        vec!["z".into(), "a".into()],
        vec!["raw patient prose".into()],
        vec!["x".repeat(129)],
        vec!["x".into(); 65],
    ] {
        let mut b = body();
        b.cases[0].variants[0].expectations[0]
            .evidence
            .as_mut()
            .unwrap()
            .contexts = ids;
        assert!(validate(&sealed(CorpusSnapshot::unsealed(b))).is_err());
    }
}
