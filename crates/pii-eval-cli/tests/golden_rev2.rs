//! Golden protocol-revision-2 fixtures (`fixtures/contracts/v1/rev2/`): the
//! committed legacy snapshot measured by two fake scanners through the real
//! executor, assembler and writer, with the kernel's real accounting. They are
//! the revision-2 counterpart of the legacy P2 fixtures, which stay unchanged.
//!
//! Regenerate after an intentional, reviewed change with
//! `PII_EVAL_UPDATE_FIXTURES=1 cargo test -p pii-eval-cli --test golden_rev2`.

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use common::*;
use pii_eval_cli::assemble::ProjectionRequest;
use pii_eval_cli::exec::{CancelToken, ExecutorConfig, ResourcePolicy};
use pii_eval_cli::run::{RunConfig, RunRequest, run_and_write_with_projection};
use pii_eval_cli::write::{ArtifactWriter, OverwritePolicy};
use pii_eval_contracts::{Id, ProjectionMode, ProjectionView};
use pii_eval_contracts::{
    ObservationSet, PublicSyntheticArtifact, RunArtifact, RunManifest, parse_default,
    to_pretty_json, validate_artifact_against_manifest, validate_artifact_against_snapshot,
    validate_observation_against_manifest, validate_observation_against_snapshot,
};
use pii_eval_kernel::{
    ProjectionRoster, verify_public_artifact_accounting, verify_public_projection,
    verify_run_artifact_accounting,
};

fn rev2_dir() -> PathBuf {
    fixtures_dir().join("rev2")
}

fn generate(out: &std::path::Path) -> RunManifest {
    generate_with(out, None)
}

/// The roster of the committed projection golden (see `projection-roster.json`
/// next to it): the collision case is `oracle-plan`, the other two
/// `qualification-plan`; the type-validation case carries a control class.
fn golden_roster(snapshot: &pii_eval_contracts::CorpusSnapshot) -> ProjectionRoster {
    let id = |s: &str| Id::new(s).unwrap();
    let views = [
        ("collision-us-ssn-demo", ProjectionView::OraclePlan),
        ("context-email-ko-demo", ProjectionView::QualificationPlan),
        ("type-card-demo", ProjectionView::QualificationPlan),
    ]
    .map(|(case, view)| (id(case), view));
    ProjectionRoster::new(
        &snapshot.semantic,
        &[
            ProjectionView::OraclePlan,
            ProjectionView::QualificationPlan,
        ],
        &views,
        &[(id("type-card-demo"), id("test-value"))],
    )
    .unwrap()
}

fn generate_with(out: &std::path::Path, projection: Option<ProjectionRequest>) -> RunManifest {
    let snapshot = snapshot();
    let mut beta = FakeAdapter::new("beta-scan", 3);
    beta.unsupported = true;
    let adapters = vec![FakeAdapter::new("alpha-scan", 5), beta];
    let manifest = manifest(
        &snapshot,
        adapters.iter().map(|a| a.plan.clone()).collect(),
        limits(4, 2, 2, 8),
        mechanics(2),
    );
    run_and_write_with_projection(
        &RunRequest {
            snapshot: &snapshot,
            manifest: &manifest,
            adapters: adapters
                .into_iter()
                .map(|a| Arc::new(a) as Arc<dyn pii_eval_adapters::ScannerAdapter>)
                .collect(),
        },
        &RunConfig {
            executor: ExecutorConfig {
                max_workers: 4,
                resources: ResourcePolicy::Unenforced,
                ..ExecutorConfig::default()
            },
            diagnostics: false,
            commit_cancelled: false,
        },
        &CancelToken::new(),
        &ArtifactWriter::new(out, OverwritePolicy::Refuse),
        projection.as_ref(),
    )
    .expect("run and write");
    std::fs::write(
        out.join("manifest.json"),
        to_pretty_json(&manifest).unwrap(),
    )
    .unwrap();
    manifest
}

const FILES: [&str; 5] = [
    "manifest.json",
    "observation-alpha-scan.json",
    "observation-beta-scan.json",
    "public-synthetic-artifact.json",
    "run-artifact.json",
];

#[test]
fn committed_revision_2_goldens_equal_what_the_engine_writes() {
    let tmp = TempDir::new("golden-rev2");
    let out = tmp.0.join("out");
    generate(&out);
    if std::env::var("PII_EVAL_UPDATE_FIXTURES").is_ok_and(|v| v == "1") {
        std::fs::create_dir_all(rev2_dir()).unwrap();
        for name in FILES {
            std::fs::write(
                rev2_dir().join(name),
                std::fs::read(out.join(name)).unwrap(),
            )
            .unwrap();
        }
    }
    for name in FILES {
        let committed = std::fs::read(rev2_dir().join(name)).unwrap_or_else(|_| {
            panic!("missing golden rev2/{name}; run with PII_EVAL_UPDATE_FIXTURES=1")
        });
        assert_eq!(
            committed,
            std::fs::read(out.join(name)).unwrap(),
            "golden rev2/{name} drifted"
        );
    }
}

#[test]
fn committed_revision_2_goldens_parse_bind_and_verify() {
    let read = |n: &str| std::fs::read(rev2_dir().join(n)).unwrap();
    let snapshot = snapshot();
    let manifest: RunManifest = parse_default(&read("manifest.json")).unwrap();
    let alpha: ObservationSet = parse_default(&read("observation-alpha-scan.json")).unwrap();
    let beta: ObservationSet = parse_default(&read("observation-beta-scan.json")).unwrap();
    let artifact: RunArtifact = parse_default(&read("run-artifact.json")).unwrap();
    let public: PublicSyntheticArtifact =
        parse_default(&read("public-synthetic-artifact.json")).unwrap();
    assert!(manifest.semantic.protocol.is_canonical());
    for obs in [&alpha, &beta] {
        validate_observation_against_manifest(obs, &manifest).unwrap();
        validate_observation_against_snapshot(obs, &snapshot).unwrap();
    }
    validate_artifact_against_manifest(&artifact, &manifest).unwrap();
    validate_artifact_against_snapshot(&artifact, &snapshot).unwrap();
    // The verifier accepts the multi-scanner artifact: metrics are per scanner.
    verify_run_artifact_accounting(&artifact, &snapshot).unwrap();
    verify_public_artifact_accounting(&public, &snapshot).unwrap();
    assert_eq!(public, artifact.to_public_synthetic().unwrap());
    let digests: Vec<_> = artifact
        .semantic
        .scanners
        .iter()
        .map(|s| &s.observation_digest)
        .collect();
    assert_eq!(digests, [&alpha.semantic_digest, &beta.semantic_digest]);
    // The legacy fixtures next to them are untouched revision-1 documents.
    let legacy: RunArtifact = parse_default(&read_legacy("run-artifact.json")).unwrap();
    assert!(legacy.semantic.protocol.is_legacy());
}

fn read_legacy(name: &str) -> Vec<u8> {
    std::fs::read(fixtures_dir().join(name)).unwrap()
}

// ---------------------------------------------------------------------------
// The schema 1.2 product projection (ADR 0016)
// ---------------------------------------------------------------------------

const PROJECTION_GOLDEN: &str = "public-synthetic-artifact.projection.json";
const ROSTER_GOLDEN: &str = "projection-roster.json";

#[test]
fn the_committed_projection_golden_equals_what_the_engine_writes_and_verifies() {
    let tmp = TempDir::new("golden-rev2-projection");
    let out = tmp.0.join("out");
    generate_with(
        &out,
        Some(ProjectionRequest {
            roster: golden_roster(&snapshot()),
            mode: ProjectionMode::Exploratory,
        }),
    );
    let written = std::fs::read(out.join("public-synthetic-artifact.json")).unwrap();
    if std::env::var("PII_EVAL_UPDATE_FIXTURES").is_ok_and(|v| v == "1") {
        std::fs::write(rev2_dir().join(PROJECTION_GOLDEN), &written).unwrap();
    }
    let committed = std::fs::read(rev2_dir().join(PROJECTION_GOLDEN)).unwrap_or_else(|_| {
        panic!("missing golden rev2/{PROJECTION_GOLDEN}; run with PII_EVAL_UPDATE_FIXTURES=1")
    });
    assert_eq!(
        committed, written,
        "golden rev2/{PROJECTION_GOLDEN} drifted"
    );

    // It parses, binds, verifies (accounting and, with the roster, the block),
    // and everything outside the block equals the 1.1 golden.
    let snapshot = snapshot();
    let doc: PublicSyntheticArtifact = parse_default(&committed).unwrap();
    assert_eq!(doc.schema_version.to_string(), "1.2");
    verify_public_artifact_accounting(&doc, &snapshot).unwrap();
    verify_public_projection(&doc, &snapshot, &golden_roster(&snapshot)).unwrap();
    let plain: PublicSyntheticArtifact =
        parse_default(&std::fs::read(rev2_dir().join("public-synthetic-artifact.json")).unwrap())
            .unwrap();
    let mut stripped = doc.clone();
    stripped.semantic.product_projection = None;
    assert_eq!(stripped.semantic, plain.semantic);
}

#[test]
fn the_committed_projection_roster_is_the_one_the_golden_was_built_from() {
    let roster_text = std::fs::read_to_string(rev2_dir().join(ROSTER_GOLDEN)).unwrap();
    let tmp = TempDir::new("golden-rev2-roster");
    let path = tmp.0.join("roster.json");
    std::fs::write(&path, &roster_text).unwrap();
    let snapshot = snapshot();
    let loaded = pii_eval_cli::projection::load_roster(&path, &snapshot, None).unwrap();
    assert_eq!(loaded.digest(), golden_roster(&snapshot).digest());
}
