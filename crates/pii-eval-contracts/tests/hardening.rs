//! Hardening checks found in review: closed tagged enums, redacted Debug,
//! wire-order sorting, and timestamp ordering.

mod common;

use common::*;
use pii_eval_contracts::*;

fn parses<T: serde::de::DeserializeOwned>(text: &str) -> bool {
    serde_json::from_str::<T>(text).is_ok()
}

#[test]
fn every_internally_tagged_enum_rejects_extra_keys() {
    // ProductIdentity
    assert!(parses::<ProductIdentity>(r#"{"kind":"released"}"#));
    assert!(!parses::<ProductIdentity>(
        r#"{"kind":"released","junk":1}"#
    ));
    assert!(!parses::<ProductIdentity>(&format!(
        r#"{{"kind":"released","candidateDigest":"{}"}}"#,
        "a".repeat(64)
    )));
    assert!(parses::<ProductIdentity>(&format!(
        r#"{{"kind":"candidate","candidateDigest":"{}"}}"#,
        "a".repeat(64)
    )));
    assert!(!parses::<ProductIdentity>(&format!(
        r#"{{"kind":"candidate","candidateDigest":"{}","junk":1}}"#,
        "a".repeat(64)
    )));
    // ActionOutcome: all four variants
    for ok in [
        r#"{"state":"not-measured"}"#,
        r#"{"state":"no-action-reported"}"#,
        r#"{"state":"reported","action":"redact"}"#,
        r#"{"state":"output-verified","verification":"removed"}"#,
    ] {
        assert!(parses::<ActionOutcome>(ok), "{ok}");
        let with_junk = ok.replace('}', r#","junk":1}"#);
        assert!(!parses::<ActionOutcome>(&with_junk), "{with_junk}");
    }
    // MetricValue: both variants
    assert!(parses::<MetricValue>(
        r#"{"state":"withheld","reason":"zero-denominator"}"#
    ));
    assert!(!parses::<MetricValue>(
        r#"{"state":"withheld","reason":"zero-denominator","junk":1}"#
    ));
    let measured =
        r#"{"state":"measured","point":{"mantissa":1,"scale":1},"bound":{"mantissa":2,"scale":1}}"#;
    assert!(parses::<MetricValue>(measured));
    assert!(!parses::<MetricValue>(
        &measured
            .replace('}', r#","junk":1}"#)
            .replacen(r#","junk":1}"#, "}", 2)
    ));
    // Serialization is unchanged: the clean forms round-trip byte for byte.
    assert_eq!(
        serde_json::to_string(&ActionOutcome::NotMeasured).unwrap(),
        r#"{"state":"not-measured"}"#
    );
    assert_eq!(
        serde_json::to_string(&ProductIdentity::Released).unwrap(),
        r#"{"kind":"released"}"#
    );
}

#[test]
fn debug_output_never_contains_input_text_seeds_or_identifiers() {
    let f = Fixtures::default_public();
    let secrets = [
        "example.invalid",
        "4111",
        "000-12-3456",
        "연락처",
        "seed-0001",
        "seed-v1",
        "context-email-ko-demo",
        "type-card-demo",
        "collision-us-ssn-demo",
        "synthetic-demo-population",
        "occurrence-1",
        "synthetic-source-context",
    ];
    let renderings = [
        format!("{:?}", f.snapshot),
        format!("{:#?}", f.snapshot),
        format!("{:?}", f.snapshot.semantic.cases[1].variants[0]),
        format!("{:?}", f.manifest),
        format!("{:?}", f.obs_alpha),
        format!("{:?}", f.artifact),
        format!("{:?}", f.artifact.to_public_synthetic().unwrap()),
        format!("{:?}", id("context-email-ko-demo")),
        format!("{:?}", Seed::new("seed-0001").unwrap()),
    ];
    for text in &renderings {
        for secret in secrets {
            assert!(!text.contains(secret), "Debug output leaked {secret}");
        }
    }
    // Redaction keeps the length, which is enough to debug structure.
    assert!(renderings[7].contains("redacted 21 bytes"));
}

#[test]
fn findings_sort_by_wire_string_not_declaration_order() {
    let f = Fixtures::default_public();
    let base = f.obs_alpha.semantic.inputs[0].findings[0].clone();
    let with = |action| Finding {
        action: Some(action),
        ..base.clone()
    };
    // Wire order: other < preserve < redact. Declaration order is redact, preserve, other.
    let mut ordered = f.obs_alpha.clone();
    ordered.semantic.inputs[0].findings = vec![
        Finding {
            action: None,
            ..base.clone()
        },
        with(ActionKind::Other),
        with(ActionKind::Preserve),
        with(ActionKind::Redact),
    ];
    seal(&mut ordered).unwrap();
    assert!(validate(&ordered).is_ok(), "{:?}", validate(&ordered));
    let mut reversed = ordered.clone();
    reversed.semantic.inputs[0].findings.reverse();
    seal(&mut reversed).unwrap();
    assert!(
        validate(&reversed)
            .unwrap_err()
            .contains(ReasonCode::NonCanonicalOrder)
    );
    assert!(with(ActionKind::Other) < with(ActionKind::Preserve));
    assert!(with(ActionKind::Preserve) < with(ActionKind::Redact));
}

#[test]
fn failures_and_phases_sort_by_wire_string() {
    // "cancelled" < "execution-error" < "timeout" although declaration order differs.
    assert!(FailureCode::Cancelled.as_str() < FailureCode::ExecutionError.as_str());
    assert!(FailureCode::ExecutionError.as_str() < FailureCode::Timeout.as_str());
    let f = Fixtures::default_public();
    let mut art = f.artifact.clone();
    art.semantic.scanners[1].status = ScannerStatus::Error;
    art.semantic.failures = vec![
        MeasurementFailure {
            scanner_id: sid("beta-scan"),
            code: FailureCode::Cancelled,
            affected_inputs: 1,
        },
        MeasurementFailure {
            scanner_id: sid("beta-scan"),
            code: FailureCode::Timeout,
            affected_inputs: 1,
        },
    ];
    seal(&mut art).unwrap();
    assert!(validate(&art).is_ok(), "{:?}", validate(&art));
    art.semantic.failures.reverse();
    seal(&mut art).unwrap();
    assert!(
        validate(&art)
            .unwrap_err()
            .contains(ReasonCode::NonCanonicalOrder)
    );
}

#[test]
fn timestamps_compare_by_instant_not_by_text() {
    let t = |s| TimestampUtc::new(s).unwrap();
    assert_eq!(t("1970-01-01T00:00:00Z").unix_millis(), 0);
    assert_eq!(t("1970-01-02T00:00:00.001Z").unix_millis(), 86_400_001);
    assert_eq!(t("2000-03-01T00:00:00Z").unix_millis(), 951_868_800_000);
    // Text order would put "…00Z" after "…00.500Z"; instant order does not.
    assert!(t("2026-10-02T09:00:00.500Z").unix_millis() > t("2026-10-02T09:00:00Z").unix_millis());
    assert_eq!(
        t("2026-10-02T09:00:00Z").unix_millis(),
        t("2026-10-02T09:00:00.000Z").unix_millis()
    );
}

#[test]
fn schema_version_is_part_of_the_digest_domain() {
    let f = Fixtures::default_public();
    assert_eq!(
        digest_domain(DocumentKind::CorpusSnapshot, SchemaVersion::CURRENT),
        "pii-eval.corpus-snapshot/1.0"
    );
    // The same body under another declared version has another digest.
    let body = canonical_bytes_of(&f.snapshot.semantic).unwrap();
    let v1_0 = semantic_digest(
        &digest_domain(
            DocumentKind::CorpusSnapshot,
            SchemaVersion { major: 1, minor: 0 },
        ),
        &body,
    );
    let v1_1 = semantic_digest(
        &digest_domain(
            DocumentKind::CorpusSnapshot,
            SchemaVersion { major: 1, minor: 1 },
        ),
        &body,
    );
    assert_ne!(v1_0, v1_1);
    assert_eq!(v1_0, f.snapshot.semantic_digest);
}
