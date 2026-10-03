//! Positive golden fixtures: committed synthetic documents that must parse,
//! validate, bind to each other, and equal what the builders produce.
//!
//! Regenerate after an intentional, reviewed contract change with
//! `PII_EVAL_UPDATE_FIXTURES=1 cargo test -p pii-eval-contracts --test golden`
//! and explain every changed field in the commit.

mod common;

use common::*;
use pii_eval_contracts::*;

fn golden_set(f: &Fixtures) -> Vec<(&'static str, String)> {
    let public = f.artifact.to_public_synthetic().expect("public projection");
    vec![
        ("snapshot.json", to_pretty_json(&f.snapshot).unwrap()),
        ("manifest.json", to_pretty_json(&f.manifest).unwrap()),
        (
            "observation-alpha.json",
            to_pretty_json(&f.obs_alpha).unwrap(),
        ),
        (
            "observation-beta.json",
            to_pretty_json(&f.obs_beta).unwrap(),
        ),
        (
            "run-artifact.json",
            serialize_internal(&f.artifact).unwrap(),
        ),
        (
            "public-synthetic-artifact.json",
            serialize_public_synthetic(&public).unwrap(),
        ),
    ]
}

#[test]
fn committed_goldens_equal_the_builders() {
    let set = golden_set(&Fixtures::default_public());
    let dir = fixtures_dir();
    if update_requested("PII_EVAL_UPDATE_FIXTURES") {
        std::fs::create_dir_all(&dir).unwrap();
        for (name, text) in &set {
            std::fs::write(dir.join(name), text).unwrap();
        }
    }
    for (name, text) in &set {
        let committed = std::fs::read_to_string(dir.join(name)).unwrap_or_else(|_| {
            panic!("missing golden {name}; run with PII_EVAL_UPDATE_FIXTURES=1")
        });
        assert_eq!(&committed, text, "golden {name} drifted");
    }
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(fixtures_dir().join(name)).unwrap()
}

#[test]
fn goldens_parse_validate_and_bind_to_each_other() {
    let snapshot: CorpusSnapshot = parse_default(&read("snapshot.json")).unwrap();
    let manifest: RunManifest = parse_default(&read("manifest.json")).unwrap();
    let alpha: ObservationSet = parse_default(&read("observation-alpha.json")).unwrap();
    let beta: ObservationSet = parse_default(&read("observation-beta.json")).unwrap();
    let artifact: RunArtifact = parse_default(&read("run-artifact.json")).unwrap();
    let public: PublicSyntheticArtifact =
        parse_default(&read("public-synthetic-artifact.json")).unwrap();

    validate_manifest_against_snapshot(&manifest, &snapshot).unwrap();
    for obs in [&alpha, &beta] {
        validate_observation_against_manifest(obs, &manifest).unwrap();
        validate_observation_against_snapshot(obs, &snapshot).unwrap();
    }
    validate_artifact_against_manifest(&artifact, &manifest).unwrap();
    validate_artifact_against_snapshot(&artifact, &snapshot).unwrap();

    // The artifact binds the observation sets by digest.
    let digests: Vec<_> = artifact
        .semantic
        .scanners
        .iter()
        .map(|s| &s.observation_digest)
        .collect();
    assert_eq!(digests, [&alpha.semantic_digest, &beta.semantic_digest]);
    // The public artifact is a projection of exactly this internal artifact.
    assert_eq!(
        public.semantic.source_artifact_digest,
        artifact.semantic_digest
    );
    assert_eq!(public, artifact.to_public_synthetic().unwrap());
}

/// The structural revision-2 set (placeholder metric values) validates and
/// binds exactly like the legacy set, and the legacy set is still valid.
#[test]
fn revision_2_documents_validate_and_bind_and_revision_1_stays_valid() {
    let legacy = Fixtures::default_public();
    let canonical = Fixtures::default_canonical();
    assert!(legacy.artifact.semantic.protocol.is_legacy());
    assert_eq!(legacy.artifact.schema_version, SchemaVersion::V1_0);
    assert!(canonical.artifact.semantic.protocol.is_canonical());
    assert_eq!(canonical.artifact.schema_version, SchemaVersion::V1_1);
    // Same population: the snapshot has no protocol identity and stays at 1.0.
    assert_eq!(legacy.snapshot, canonical.snapshot);
    for f in [&legacy, &canonical] {
        validate(&f.snapshot).unwrap();
        validate(&f.manifest).unwrap();
        validate(&f.obs_alpha).unwrap();
        validate(&f.obs_beta).unwrap();
        validate(&f.artifact).unwrap();
        validate_manifest_against_snapshot(&f.manifest, &f.snapshot).unwrap();
        validate_observation_against_manifest(&f.obs_alpha, &f.manifest).unwrap();
        validate_artifact_against_manifest(&f.artifact, &f.manifest).unwrap();
        validate_artifact_against_snapshot(&f.artifact, &f.snapshot).unwrap();
        let public = f.artifact.to_public_synthetic().unwrap();
        validate(&public).unwrap();
        // The projection is sealed under the version of its source.
        assert_eq!(public.schema_version, f.artifact.schema_version);
    }
    // Revision 2 keys metrics by scanner and omits the unkeyed list.
    let body = &canonical.artifact.semantic;
    assert!(body.metrics.is_empty());
    let keyed: Vec<_> = body
        .scanner_metrics
        .iter()
        .map(|m| m.scanner_id.as_str())
        .collect();
    assert_eq!(keyed, ["alpha-scan", "beta-scan"]);
    let text = serialize_internal(&canonical.artifact).unwrap();
    assert!(text.contains("\"scannerMetrics\""));
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert!(
        value["semantic"].get("metrics").is_none(),
        "the unkeyed list is absent on the wire"
    );
    // Both revisions round-trip through the strict parser.
    for f in [&legacy, &canonical] {
        let text = serialize_internal(&f.artifact).unwrap();
        let back: RunArtifact = parse_default(text.as_bytes()).unwrap();
        assert_eq!(back, f.artifact);
    }
    // A revision-1 reader's world is unchanged: the committed goldens are the
    // legacy set, equal to the builders (see `committed_goldens_equal_the_builders`).
    let committed: RunArtifact = parse_default(&read("run-artifact.json")).unwrap();
    assert!(committed.semantic.protocol.is_legacy());
    assert_eq!(committed.schema_version, SchemaVersion::V1_0);
}

/// ADR 0008: a context group needs at least one frame per class, not exactly
/// one (the oracle's real groups hold many); zero in a class stays incomplete.
#[test]
fn a_context_group_may_hold_several_frames_per_class() {
    let f = Fixtures::default_public();
    let mut many = f.snapshot.clone();
    {
        let case = &mut many.semantic.cases[1];
        let sensitive = case.variants[2].clone();
        let mut extra = sensitive.clone();
        extra.variant_id = id("context-email-ko-demo-sensitive-2");
        case.variants.push(extra);
        let neutral = case.variants[0].clone();
        let mut extra = neutral;
        extra.variant_id = id("context-email-ko-demo-neutral-2");
        case.variants.insert(1, extra);
        case.variants
            .sort_by(|a, b| a.variant_id.cmp(&b.variant_id));
    }
    seal(&mut many).unwrap();
    validate(&many).expect("several frames per class are a complete group");
    let mut missing = many.clone();
    missing.semantic.cases[1]
        .variants
        .retain(|v| !v.variant_id.as_str().contains("non-sensitive"));
    seal(&mut missing).unwrap();
    assert!(
        validate(&missing)
            .unwrap_err()
            .contains(ReasonCode::IncompleteContextTrio)
    );
}

#[test]
fn goldens_use_only_synthetic_reserved_values() {
    for name in ["snapshot.json", "run-artifact.json"] {
        let text = String::from_utf8(read(name)).unwrap();
        for token in text
            .split(|c: char| c.is_whitespace() || c == '"')
            .filter(|t| t.contains('@'))
        {
            assert!(
                token.ends_with(".invalid"),
                "non-reserved address in {name}"
            );
        }
    }
}

#[test]
fn a_missing_capability_is_never_success() {
    let f = Fixtures::default_public();
    let beta = &f.artifact.semantic.outcomes;
    for row in beta.iter().filter(|o| o.scanner_id.as_str() == "beta-scan") {
        assert_eq!(row.type_identity.status(), AxisStatus::NotMeasured);
        assert_eq!(row.sensitivity_context.status(), AxisStatus::NotMeasured);
        assert_eq!(row.range, RangeState::NotApplicable);
        assert_eq!(row.action, ActionOutcome::NotMeasured);
    }
}

#[test]
fn run_class_and_product_identity_are_independent() {
    let candidate = ProductIdentity::Candidate {
        candidate_digest: digest_of("alpha-candidate"),
    };
    let mut digests = Vec::new();
    for visibility in [Visibility::PublicSynthetic, Visibility::Protected] {
        for product in [ProductIdentity::Released, candidate.clone()] {
            let f = Fixtures::build(visibility, product.clone());
            validate(&f.snapshot).unwrap();
            validate(&f.manifest).unwrap();
            validate(&f.artifact).unwrap();
            validate_manifest_against_snapshot(&f.manifest, &f.snapshot).unwrap();
            validate_artifact_against_manifest(&f.artifact, &f.manifest).unwrap();
            validate_artifact_against_snapshot(&f.artifact, &f.snapshot).unwrap();
            digests.push(f.manifest.semantic_digest.clone());
            // A public-synthetic candidate run is still candidate evidence.
            let alpha = &f.artifact.semantic.scanners[0].identity.product;
            assert_eq!(
                *alpha != ProductIdentity::Released,
                product != ProductIdentity::Released
            );
        }
    }
    digests.sort();
    digests.dedup();
    assert_eq!(
        digests.len(),
        4,
        "each (class, product) pair is a distinct identity"
    );
}
