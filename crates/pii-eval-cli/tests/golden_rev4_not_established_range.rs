//! Public synthetic example of an authored `not-established` range (schema 1.4,
//! ADR 0018): the committed revision-2 snapshot plus two `schema-only` cases whose
//! occurrence is authored located nowhere (no `range`, identity and sensitivity
//! `not-established`), measured by the real executor, assembler and writer
//! (`fixtures/contracts/v1/rev4/`). Nothing in the committed 1.0 to 1.3 fixtures
//! changes.
//!
//! Regenerate after an intentional, reviewed change with
//! `PII_EVAL_UPDATE_FIXTURES=1 cargo test -p pii-eval-cli --test golden_rev4_not_established_range`.

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use common::*;
use pii_eval_cli::exec::{CancelToken, ExecutorConfig, ResourcePolicy};
use pii_eval_cli::run::{RunConfig, RunRequest, run_and_write_with_projection};
use pii_eval_cli::write::{ArtifactWriter, OverwritePolicy};
use pii_eval_contracts::{
    ActionExpectation, Case, ContextClass, ContextObligation, CorpusSnapshot, Derivation,
    Expectation, ExpectedType, FamilyId, Id, LanguageTag, Lineage, MethodId, MethodRef,
    PublicSyntheticArtifact, RangeState, ReasonCode, RunArtifact, RunManifest, SchemaVersion,
    SensitivityExpectation, SensitivityState, Sha256Digest, Strategy, TypeState, Variant,
    parse_default, seal, to_pretty_json, validate, validate_artifact_against_manifest,
    validate_artifact_against_snapshot,
};
use pii_eval_kernel::{verify_public_artifact_accounting, verify_run_artifact_accounting};

fn rev4_dir() -> PathBuf {
    fixtures_dir().join("rev4")
}

/// A schema-only case whose single occurrence the authors located nowhere.
fn undetermined_case(case_id: &str, text: &str, family: &str) -> Case {
    let id = |s: &str| Id::new(s).unwrap();
    Case {
        case_id: id(case_id),
        method: MethodId::SchemaOnly,
        lineage: Lineage {
            source_id: id("synthetic-source"),
            source_digest: Sha256Digest::of_bytes(b"synthetic"),
        },
        language: LanguageTag::new("en").unwrap(),
        jurisdiction: None,
        collision: None,
        variants: vec![Variant {
            variant_id: id(&format!("{case_id}-authored")),
            derivation: Derivation {
                strategy: Strategy::Authored,
                operator: None,
                seed: None,
            },
            text: text.to_owned(),
            text_digest: Sha256Digest::of_bytes(text.as_bytes()),
            expectations: vec![Expectation {
                occurrence_id: id("occurrence-1"),
                range: None,
                family: FamilyId::new(family).unwrap(),
                type_expectation: ExpectedType::NotEstablished,
                validator: None,
                sensitivity: SensitivityExpectation::NotEstablished,
                context_class: ContextClass::Neutral,
                context_obligation: ContextObligation::None,
                action: ActionExpectation::NotSpecified,
            }],
        }],
    }
}

/// The committed snapshot with two range-less cases added (case ids stay sorted).
fn undetermined_snapshot() -> CorpusSnapshot {
    let mut body = snapshot().semantic;
    body.cases.push(undetermined_case(
        "undetermined-address-demo",
        "client_ip=v192.168.1.7",
        "pii:global:network-address",
    ));
    body.cases.push(undetermined_case(
        "undetermined-card-demo",
        "ref 4111 1111 1111 111x end",
        "pii:global:payment-card",
    ));
    body.cases.sort_by(|a, b| a.case_id.cmp(&b.case_id));
    let mut s = CorpusSnapshot::unsealed(body);
    seal(&mut s).unwrap();
    s
}

fn generate(out: &std::path::Path, workers: usize) -> (CorpusSnapshot, RunManifest) {
    let snapshot = undetermined_snapshot();
    let adapters = vec![FakeAdapter::new("alpha-scan", 5)];
    let mut manifest = manifest(
        &snapshot,
        adapters.iter().map(|a| a.plan.clone()).collect(),
        limits(4, 2, 2, 8),
        mechanics(2),
    );
    // The range-less cases are `schema-only`: the plan must name that method.
    manifest
        .semantic
        .methods
        .push(MethodRef::frozen(MethodId::SchemaOnly));
    manifest.semantic.methods.sort_by_key(|m| m.id.as_str());
    seal(&mut manifest).unwrap();
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
fn committed_not_established_range_goldens_equal_what_the_engine_writes() {
    let tmp = TempDir::new("golden-rev4");
    let out = tmp.0.join("out");
    generate(&out, 4);
    if std::env::var("PII_EVAL_UPDATE_FIXTURES").is_ok_and(|v| v == "1") {
        std::fs::create_dir_all(rev4_dir()).unwrap();
        for name in FILES {
            std::fs::write(
                rev4_dir().join(name),
                std::fs::read(out.join(name)).unwrap(),
            )
            .unwrap();
        }
    }
    for name in FILES {
        let committed = std::fs::read(rev4_dir().join(name)).unwrap_or_else(|_| {
            panic!("missing golden rev4/{name}; run with PII_EVAL_UPDATE_FIXTURES=1")
        });
        assert_eq!(
            committed,
            std::fs::read(out.join(name)).unwrap(),
            "golden rev4/{name} drifted"
        );
    }
}

#[test]
fn the_output_is_identical_for_every_worker_count() {
    let tmp = TempDir::new("golden-rev4-workers");
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
fn the_committed_documents_parse_bind_and_verify_with_unresolved_range() {
    let read = |n: &str| std::fs::read(rev4_dir().join(n)).unwrap();
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
        assert_eq!(version, SchemaVersion::V1_4);
    }
    validate(&snapshot).unwrap();
    validate_artifact_against_manifest(&artifact, &manifest).unwrap();
    validate_artifact_against_snapshot(&artifact, &snapshot).unwrap();
    verify_run_artifact_accounting(&artifact, &snapshot).unwrap();
    verify_public_artifact_accounting(&public, &snapshot).unwrap();
    assert_eq!(public, artifact.to_public_synthetic().unwrap());

    // Both range-less cases are carried (5 authored cases, none dropped) and are
    // observed on every axis as unresolved; the located cases keep their states.
    assert_eq!(artifact.semantic.population_counts.authored_cases, 5);
    let undetermined: Vec<_> = artifact
        .semantic
        .outcomes
        .iter()
        .filter(|o| o.case_id.as_str().starts_with("undetermined-"))
        .collect();
    assert_eq!(undetermined.len(), 2);
    for o in undetermined {
        assert_eq!(o.range, RangeState::Unresolved);
        assert_eq!(o.type_identity, TypeState::Unresolved);
        assert_eq!(o.sensitivity_context, SensitivityState::Unresolved);
    }
    assert!(
        artifact
            .semantic
            .outcomes
            .iter()
            .filter(|o| !o.case_id.as_str().starts_with("undetermined-"))
            .all(|o| o.range != RangeState::Unresolved)
    );
}

#[test]
fn an_unresolved_range_under_an_older_schema_is_refused() {
    let read = |n: &str| std::fs::read(rev4_dir().join(n)).unwrap();
    let mut artifact: RunArtifact = parse_default(&read("run-artifact.json")).unwrap();
    artifact.schema_version = SchemaVersion::V1_3;
    seal(&mut artifact).unwrap();
    assert_eq!(
        validate(&artifact).unwrap_err().first_code(),
        Some(ReasonCode::RangeNotEstablishedGate)
    );
    let mut public: PublicSyntheticArtifact =
        parse_default(&read("public-synthetic-artifact.json")).unwrap();
    public.schema_version = SchemaVersion::V1_3;
    seal(&mut public).unwrap();
    assert_eq!(
        validate(&public).unwrap_err().first_code(),
        Some(ReasonCode::RangeNotEstablishedGate)
    );
}

#[test]
fn the_older_fixtures_are_untouched() {
    let rev2: RunArtifact =
        parse_default(&std::fs::read(fixtures_dir().join("rev2/run-artifact.json")).unwrap())
            .unwrap();
    assert_eq!(rev2.schema_version, SchemaVersion::V1_1);
    let rev3: RunArtifact =
        parse_default(&std::fs::read(fixtures_dir().join("rev3/run-artifact.json")).unwrap())
            .unwrap();
    assert_eq!(rev3.schema_version, SchemaVersion::V1_3);
}
