//! Semantic digest determinism, canonical form hazards, and limits.

mod common;

use common::*;
use pii_eval_contracts::*;
use serde_json::Value;

/// Digest of the committed snapshot fixture. Reproduced independently by a
/// separate Python implementation of ADR 0003 (sorted keys, compact
/// separators, SHA-256 over the documented prefix); a change here means the
/// canonical form or the fixture changed and needs an ADR 0003 revision or a
/// reviewed fixture update.
const SNAPSHOT_DIGEST: &str = "c5249874335d21c02447bac23954d70e20748899f16a43efc56c5568a34a3bae";

fn next(rng: &mut u64) -> u64 {
    *rng = rng
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *rng >> 33
}

/// Write JSON with object members in a pseudo-random order and random spacing.
fn write_shuffled(v: &Value, rng: &mut u64, out: &mut String) {
    let ws = |rng: &mut u64, out: &mut String| {
        out.push_str(["", " ", "\n", "\t"][(next(rng) % 4) as usize]);
    };
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            for i in (1..keys.len()).rev() {
                keys.swap(i, (next(rng) as usize) % (i + 1));
            }
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                ws(rng, out);
                out.push_str(&serde_json::to_string(key).unwrap());
                ws(rng, out);
                out.push(':');
                ws(rng, out);
                write_shuffled(&map[key], rng, out);
            }
            ws(rng, out);
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                ws(rng, out);
                write_shuffled(item, rng, out);
            }
            out.push(']');
        }
        other => out.push_str(&serde_json::to_string(other).unwrap()),
    }
}

fn shuffled<D: Document>(doc: &D, seed: u64) -> String {
    let value = serde_json::to_value(doc).unwrap();
    let mut rng = seed;
    let mut out = String::new();
    write_shuffled(&value, &mut rng, &mut out);
    out
}

fn assert_shuffle_invariant<D: Document + PartialEq + std::fmt::Debug>(doc: &D) {
    let digest = compute_digest(doc).unwrap();
    assert_eq!(&digest, doc.claimed_digest());
    for seed in 0..25u64 {
        let text = shuffled(doc, seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let parsed: D = parse_default(text.as_bytes()).expect("shuffled member order must parse");
        assert_eq!(&parsed, doc);
        assert_eq!(compute_digest(&parsed).unwrap(), digest, "seed {seed}");
    }
}

#[test]
fn object_member_order_and_whitespace_do_not_change_the_digest() {
    let f = Fixtures::default_public();
    assert_shuffle_invariant(&f.snapshot);
    assert_shuffle_invariant(&f.manifest);
    assert_shuffle_invariant(&f.obs_alpha);
    assert_shuffle_invariant(&f.obs_beta);
    assert_shuffle_invariant(&f.artifact);
    assert_shuffle_invariant(&f.artifact.to_public_synthetic().unwrap());
}

#[test]
fn repeated_builds_serialize_and_digest_identically() {
    let first = Fixtures::default_public();
    let first_json = to_pretty_json(&first.artifact).unwrap();
    for _ in 0..25 {
        let again = Fixtures::default_public();
        assert_eq!(
            again.snapshot.semantic_digest,
            first.snapshot.semantic_digest
        );
        assert_eq!(
            again.artifact.semantic_digest,
            first.artifact.semantic_digest
        );
        assert_eq!(to_pretty_json(&again.artifact).unwrap(), first_json);
    }
}

#[test]
fn the_snapshot_digest_is_pinned() {
    assert_eq!(
        Fixtures::default_public().snapshot.semantic_digest.as_str(),
        SNAPSHOT_DIGEST
    );
}

#[test]
fn timing_diagnostics_are_outside_the_semantic_digest() {
    let f = Fixtures::default_public();
    let mut artifact = f.artifact.clone();
    artifact.diagnostics = None;
    assert_eq!(
        compute_digest(&artifact).unwrap(),
        f.artifact.semantic_digest
    );
    validate(&artifact).expect("an artifact without diagnostics is the same artifact");
    artifact.diagnostics = Some(RunDiagnostics {
        started_at: TimestampUtc::new("2030-01-01T00:00:00Z").unwrap(),
        finished_at: TimestampUtc::new("2030-01-01T09:00:00Z").unwrap(),
        duration_ms: 32_400_000,
        phases: vec![],
    });
    assert_eq!(
        compute_digest(&artifact).unwrap(),
        f.artifact.semantic_digest
    );
    validate(&artifact).expect("different timing is the same artifact");

    let mut obs = f.obs_alpha.clone();
    obs.diagnostics = None;
    assert_eq!(compute_digest(&obs).unwrap(), f.obs_alpha.semantic_digest);

    // The digested body has no timestamp-typed or duration field.
    let body = serde_json::to_string(&f.artifact.semantic).unwrap();
    for needle in [
        "startedAt",
        "finishedAt",
        "durationMs",
        "diagnostics",
        "phases",
    ] {
        assert!(
            !body.contains(needle),
            "{needle} leaked into the semantic body"
        );
    }
}

#[test]
fn every_semantic_change_changes_the_digest() {
    let f = Fixtures::default_public();
    let base = compute_digest(&f.artifact).unwrap();
    let mut seen = std::collections::BTreeSet::from([base.clone()]);
    let mut check = |change: &dyn Fn(&mut RunArtifactBody)| {
        let mut a = f.artifact.clone();
        change(&mut a.semantic);
        assert!(
            seen.insert(compute_digest(&a).unwrap()),
            "change did not alter the digest"
        );
    };
    check(&|b| b.outcomes[0].range = RangeState::Partial);
    check(&|b| b.metrics.reverse());
    check(&|b| b.completeness = Completeness::Partial);
    check(&|b| b.engine.version = ver("0.0.1"));
    check(&|b| b.mechanics.replays = 3);
    check(&|b| b.failures[0].affected_inputs = 5);
}

#[test]
fn optional_fields_are_absent_never_null() {
    let f = Fixtures::default_public();
    let value = serde_json::to_value(&f.obs_beta).unwrap();
    assert!(value["semantic"]["scanner"].get("scannerVersion").is_none());
    let canonical = String::from_utf8(canonical_bytes_of(&f.obs_beta.semantic).unwrap()).unwrap();
    assert!(!canonical.contains("null"));
    // A document that omits an optional field parses; one that says null is rejected.
    assert!(
        parse_default::<ObservationSet>(to_pretty_json(&f.obs_beta).unwrap().as_bytes()).is_ok()
    );
    let with_null = to_pretty_json(&f.obs_beta).unwrap().replace(
        "\"scannerId\": \"beta-scan\"",
        "\"scannerId\": \"beta-scan\", \"scannerVersion\": null",
    );
    assert_eq!(
        parse_default::<ObservationSet>(with_null.as_bytes())
            .unwrap_err()
            .first_code(),
        Some(ReasonCode::NullNotAllowed)
    );
}

#[test]
fn non_finite_floats_negative_zero_and_large_integers_have_no_canonical_form() {
    // serde_json maps non-finite floats to null; the canonical writer refuses null.
    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert_eq!(
            canonical_bytes_of(&bad).unwrap_err().code,
            ReasonCode::NullNotAllowed,
            "{bad}"
        );
    }
    assert_eq!(
        canonical_bytes_of(&-0.0f64).unwrap_err().code,
        ReasonCode::FloatNotAllowed
    );
    assert_eq!(
        canonical_bytes_of(&0.5f64).unwrap_err().code,
        ReasonCode::FloatNotAllowed
    );
    let safe = limits::MAX_SAFE_INTEGER;
    assert!(canonical_bytes_of(&safe).is_ok());
    assert_eq!(
        canonical_bytes_of(&(safe + 1)).unwrap_err().code,
        ReasonCode::IntegerOutOfRange
    );
    assert_eq!(
        canonical_bytes_of(&u64::MAX).unwrap_err().code,
        ReasonCode::IntegerOutOfRange
    );
    assert_eq!(
        canonical_bytes_of(&i64::MIN).unwrap_err().code,
        ReasonCode::IntegerOutOfRange
    );
    // Rates and the interval z value are scaled decimals: integers only.
    let z = canonical_bytes_of(&Mechanics::PII_V1).unwrap();
    assert_eq!(
        String::from_utf8(z).unwrap(),
        r#"{"intervalPrecision":6,"intervalZ":{"mantissa":196,"scale":2},"minDenominator":4,"replays":2}"#
    );
}

#[test]
fn array_order_is_semantic_and_unsorted_sets_are_rejected_not_normalized() {
    let f = Fixtures::default_public();
    let mut swapped = f.manifest.clone();
    swapped.semantic.scanners.swap(0, 1);
    assert_ne!(
        compute_digest(&swapped).unwrap(),
        f.manifest.semantic_digest
    );
    seal(&mut swapped).unwrap();
    assert_eq!(
        validate(&swapped).unwrap_err().first_code(),
        Some(ReasonCode::NonCanonicalOrder)
    );
}

#[test]
fn limits_are_enforced() {
    let f = Fixtures::default_public();
    // Oversized variant text.
    let mut snap = f.snapshot.clone();
    let v = &mut snap.semantic.cases[2].variants[0];
    v.text = "a".repeat(limits::MAX_TEXT_BYTES + 1);
    let err = validate(&snap).unwrap_err();
    assert!(err.contains(ReasonCode::LimitExceeded));
    let meta = err
        .errors
        .iter()
        .find(|e| e.code == ReasonCode::LimitExceeded)
        .unwrap()
        .meta;
    assert_eq!(meta.limit, Some(limits::MAX_TEXT_BYTES as u64));
    assert_eq!(meta.actual, Some(limits::MAX_TEXT_BYTES as u64 + 1));

    // Too many findings for one input.
    let mut obs = f.obs_alpha.clone();
    let one = obs.semantic.inputs[0].findings[0].clone();
    obs.semantic.inputs[0].findings = vec![one; limits::MAX_FINDINGS_PER_INPUT + 1];
    assert!(
        validate(&obs)
            .unwrap_err()
            .contains(ReasonCode::LimitExceeded)
    );

    // Document size and nesting are parse limits.
    let tiny = ParseLimits {
        max_bytes: 64,
        max_depth: 32,
    };
    let bytes = to_pretty_json(&f.manifest).unwrap();
    assert_eq!(
        parse::<RunManifest>(bytes.as_bytes(), &tiny)
            .unwrap_err()
            .first_code(),
        Some(ReasonCode::DocumentTooLarge)
    );
}
