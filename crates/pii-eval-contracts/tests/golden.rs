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
