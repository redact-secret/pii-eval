//! Public synthetic example of an authored `not-established` type identity
//! (schema 1.3, ADR 0017): the committed revision-2 snapshot with two
//! occurrences re-authored as `not-established`, measured by the real executor,
//! assembler and writer (`fixtures/contracts/v1/rev3/`). Nothing in the
//! committed 1.0/1.1/1.2 fixtures changes.
//!
//! Regenerate after an intentional, reviewed change with
//! `PII_EVAL_UPDATE_FIXTURES=1 cargo test -p pii-eval-cli --test golden_rev3_not_established`.

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use common::*;
use pii_eval_cli::exec::{CancelToken, ExecutorConfig, ResourcePolicy};
use pii_eval_cli::run::{RunConfig, RunRequest, run_and_write_with_projection};
use pii_eval_cli::write::{ArtifactWriter, OverwritePolicy};
use pii_eval_contracts::{
    CorpusSnapshot, ExpectedType, PublicSyntheticArtifact, RunArtifact, RunManifest, SchemaVersion,
    TypeState, parse_default, seal, to_pretty_json, validate, validate_artifact_against_manifest,
    validate_artifact_against_snapshot,
};
use pii_eval_kernel::{verify_public_artifact_accounting, verify_run_artifact_accounting};

fn rev3_dir() -> PathBuf {
    fixtures_dir().join("rev3")
}

/// The committed snapshot, with the `type-card-demo` occurrences authored as
/// `not-established` (the identity is not established; the text is unchanged).
fn uncertain_snapshot() -> CorpusSnapshot {
    let mut body = snapshot().semantic;
    let case = body
        .cases
        .iter_mut()
        .find(|c| c.case_id.as_str() == "type-card-demo")
        .expect("case");
    for v in &mut case.variants {
        for e in &mut v.expectations {
            e.type_expectation = ExpectedType::NotEstablished;
        }
    }
    let mut s = CorpusSnapshot::unsealed(body);
    seal(&mut s).unwrap();
    s
}

fn generate(out: &std::path::Path, workers: usize) -> (CorpusSnapshot, RunManifest) {
    let snapshot = uncertain_snapshot();
    let adapters = vec![FakeAdapter::new("alpha-scan", 5)];
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
                max_workers: workers,
                resources: ResourcePolicy::Unenforced,
                ..ExecutorConfig::default()
            },
            diagnostics: false,
            commit_cancelled: false,
        },
        &CancelToken::new(),
        &ArtifactWriter::new(out, OverwritePolicy::Refuse),
        None,
    )
    .expect("run and write");
    std::fs::write(
        out.join("manifest.json"),
        to_pretty_json(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(
        out.join("snapshot.json"),
        to_pretty_json(&snapshot).unwrap(),
    )
    .unwrap();
    (snapshot, manifest)
}

const FILES: [&str; 5] = [
    "manifest.json",
    "observation-alpha-scan.json",
    "public-synthetic-artifact.json",
    "run-artifact.json",
    "snapshot.json",
];

#[test]
fn committed_not_established_goldens_equal_what_the_engine_writes() {
    let tmp = TempDir::new("golden-rev3");
    let out = tmp.0.join("out");
    generate(&out, 4);
    if std::env::var("PII_EVAL_UPDATE_FIXTURES").is_ok_and(|v| v == "1") {
        std::fs::create_dir_all(rev3_dir()).unwrap();
        for name in FILES {
            std::fs::write(
                rev3_dir().join(name),
                std::fs::read(out.join(name)).unwrap(),
            )
            .unwrap();
        }
    }
    for name in FILES {
        let committed = std::fs::read(rev3_dir().join(name)).unwrap_or_else(|_| {
            panic!("missing golden rev3/{name}; run with PII_EVAL_UPDATE_FIXTURES=1")
        });
        assert_eq!(
            committed,
            std::fs::read(out.join(name)).unwrap(),
            "golden rev3/{name} drifted"
        );
    }
}

#[test]
fn the_output_is_identical_for_every_worker_count() {
    let tmp = TempDir::new("golden-rev3-workers");
    let reference = tmp.0.join("w1");
    generate(&reference, 1);
    for workers in [2, 4] {
        let out = tmp.0.join(format!("w{workers}"));
        generate(&out, workers);
        for name in FILES {
            assert_eq!(
                std::fs::read(reference.join(name)).unwrap(),
                std::fs::read(out.join(name)).unwrap(),
                "{name} differs at {workers} workers"
            );
        }
    }
}

#[test]
fn the_committed_documents_parse_bind_and_verify_with_unresolved_identity() {
    let read = |n: &str| std::fs::read(rev3_dir().join(n)).unwrap();
    let snapshot: CorpusSnapshot = parse_default(&read("snapshot.json")).unwrap();
    let manifest: RunManifest = parse_default(&read("manifest.json")).unwrap();
    let artifact: RunArtifact = parse_default(&read("run-artifact.json")).unwrap();
    let public: PublicSyntheticArtifact =
        parse_default(&read("public-synthetic-artifact.json")).unwrap();
    for version in [
        snapshot.schema_version,
        artifact.schema_version,
        public.schema_version,
    ] {
        assert_eq!(version, SchemaVersion::V1_3);
    }
    validate(&snapshot).unwrap();
    validate_artifact_against_manifest(&artifact, &manifest).unwrap();
    validate_artifact_against_snapshot(&artifact, &snapshot).unwrap();
    verify_run_artifact_accounting(&artifact, &snapshot).unwrap();
    verify_public_artifact_accounting(&public, &snapshot).unwrap();
    assert_eq!(public, artifact.to_public_synthetic().unwrap());

    // Every authored not-established occurrence is observed as unresolved (or
    // not-measured), never as a pass or a fail; the other occurrences keep
    // their ordinary states. Nothing was dropped.
    let uncertain: Vec<_> = artifact
        .semantic
        .outcomes
        .iter()
        .filter(|o| o.case_id.as_str() == "type-card-demo")
        .collect();
    assert_eq!(uncertain.len(), 2);
    assert!(uncertain.iter().all(|o| matches!(
        o.type_identity,
        TypeState::Unresolved | TypeState::NotMeasured
    )));
    assert!(
        artifact
            .semantic
            .outcomes
            .iter()
            .any(|o| o.type_identity == TypeState::Unresolved)
    );
    assert_eq!(artifact.semantic.population_counts.authored_cases, 3);
}

#[test]
fn the_older_fixtures_are_untouched() {
    let rev2: RunArtifact =
        parse_default(&std::fs::read(fixtures_dir().join("rev2/run-artifact.json")).unwrap())
            .unwrap();
    assert_eq!(rev2.schema_version, SchemaVersion::V1_1);
}
