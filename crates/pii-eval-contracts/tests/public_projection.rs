//! The public-synthetic boundary: protected internal records cannot become
//! public through the public serializer.
//!
//! Enforcement is by types (see the `compile_fail` doctest on
//! `serialize_public_synthetic`); these tests check the runtime refusal, the
//! shape of the public output, and the generated schema.

mod common;

use std::collections::BTreeSet;

use common::*;
use pii_eval_contracts::schema::json_schema_of;
use pii_eval_contracts::*;
use serde_json::Value;

/// Field names that carry case text, ranges, raw findings or observation
/// material. None may exist anywhere in the public artifact.
const INTERNAL_ONLY_KEYS: &[&str] = &[
    "text",
    "textDigest",
    "findings",
    "observed",
    "observationDigest",
    "inputDigest",
    "inputs",
    "expectations",
    "lineage",
    "sourceDigest",
    "sourceId",
    "sanitizedOutputDigest",
    "diagnostics",
    "start",
    "end",
];

fn keys_of_json(v: &Value, out: &mut BTreeSet<String>) {
    match v {
        Value::Object(m) => {
            for (k, child) in m {
                out.insert(k.clone());
                keys_of_json(child, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|i| keys_of_json(i, out)),
        _ => {}
    }
}

/// Property names declared anywhere in a generated JSON Schema.
fn schema_property_names(v: &Value, out: &mut BTreeSet<String>) {
    match v {
        Value::Object(m) => {
            if let Some(Value::Object(props)) = m.get("properties") {
                out.extend(props.keys().cloned());
            }
            m.values()
                .for_each(|child| schema_property_names(child, out));
        }
        Value::Array(items) => items.iter().for_each(|i| schema_property_names(i, out)),
        _ => {}
    }
}

#[test]
fn protected_runs_cannot_be_projected_whatever_the_product_identity() {
    for product in [
        ProductIdentity::Released,
        ProductIdentity::Candidate {
            candidate_digest: digest_of("candidate"),
        },
    ] {
        let f = Fixtures::build(Visibility::Protected, product);
        let err = f.artifact.to_public_synthetic().unwrap_err();
        assert_eq!(
            err.first_code(),
            Some(ReasonCode::PublicProjectionForbidden)
        );
        assert_eq!(err.errors.len(), 1);
        assert!(
            err.errors[0].path.is_empty(),
            "no detail about the protected record"
        );
    }
}

#[test]
fn public_output_has_no_internal_only_field() {
    let f = Fixtures::default_public();
    let public = f.artifact.to_public_synthetic().unwrap();
    let text = serialize_public_synthetic(&public).unwrap();
    let mut keys = BTreeSet::new();
    keys_of_json(&serde_json::from_str::<Value>(&text).unwrap(), &mut keys);
    for forbidden in INTERNAL_ONLY_KEYS {
        assert!(
            !keys.contains(*forbidden),
            "public artifact has field {forbidden}"
        );
    }
    // Sanity: the same walker finds them in the internal artifact.
    let mut internal = BTreeSet::new();
    keys_of_json(
        &serde_json::from_str::<Value>(&serialize_internal(&f.artifact).unwrap()).unwrap(),
        &mut internal,
    );
    for expected in ["observed", "observationDigest", "diagnostics"] {
        assert!(internal.contains(expected), "walker misses {expected}");
    }
    // No case text reaches the public artifact.
    for snippet in ["example.invalid", "4111", "000-12-3456", "연락처"] {
        assert!(!text.contains(snippet), "text snippet {snippet} leaked");
    }
}

#[test]
fn public_schema_declares_no_internal_only_property_and_no_protected_class() {
    let mut names = BTreeSet::new();
    let public_schema = json_schema_of(DocumentKind::PublicSyntheticArtifact);
    schema_property_names(&public_schema, &mut names);
    for forbidden in INTERNAL_ONLY_KEYS {
        assert!(
            !names.contains(*forbidden),
            "public schema declares {forbidden}"
        );
    }
    let rendered = serde_json::to_string(&public_schema).unwrap();
    assert!(rendered.contains("\"public-synthetic\""));
    assert!(
        !rendered.contains("\"protected\""),
        "protected must be unrepresentable"
    );
    // Sanity: the internal schema does declare them.
    let mut internal = BTreeSet::new();
    schema_property_names(&json_schema_of(DocumentKind::RunArtifact), &mut internal);
    assert!(internal.contains("observed") && internal.contains("diagnostics"));
}

#[test]
fn projection_is_deterministic_validated_and_separately_identified() {
    let f = Fixtures::default_public();
    let a = f.artifact.to_public_synthetic().unwrap();
    let b = f.artifact.to_public_synthetic().unwrap();
    assert_eq!(a, b);
    validate(&a).unwrap();
    assert_ne!(
        a.semantic_digest, f.artifact.semantic_digest,
        "digests are domain separated"
    );
    assert_eq!(
        a.semantic.source_artifact_digest,
        f.artifact.semantic_digest
    );
    // Timing never reaches the public artifact, and the projection round-trips.
    let text = serialize_public_synthetic(&a).unwrap();
    assert_eq!(
        parse_default::<PublicSyntheticArtifact>(text.as_bytes()).unwrap(),
        a
    );
}

#[test]
fn public_candidate_evidence_stays_candidate_evidence() {
    let candidate = ProductIdentity::Candidate {
        candidate_digest: digest_of("candidate"),
    };
    let f = Fixtures::build(Visibility::PublicSynthetic, candidate.clone());
    let public = f.artifact.to_public_synthetic().unwrap();
    assert_eq!(public.semantic.scanners[0].identity.product, candidate);
}
