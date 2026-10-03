//! The review gate on the run and replay paths (ADR 0007, ADR 0010): a variant
//! the sealed snapshot holds for review (`review-required`) has an unmeasured
//! type axis in the artifact and in the accounting, in a run and in a replay of
//! the same observations. In-process fake scanner for the run, the built binary
//! for the replay. No Node needed.

mod cli_support;
mod common;

use std::sync::Arc;

use cli_support::{code, run_cli, s, stderr, summary};
use common::*;
use pii_eval_cli::exec::{CancelToken, ExecutorConfig, ResourcePolicy};
use pii_eval_cli::run::{RunConfig, RunRequest, run, run_and_write};
use pii_eval_cli::write::{ArtifactWriter, OverwritePolicy};
use pii_eval_contracts::{
    CorpusSnapshot, Id, OperatorRef, Strategy, TypeState, seal, to_pretty_json,
};

fn config() -> RunConfig {
    RunConfig {
        executor: ExecutorConfig {
            max_workers: 2,
            resources: ResourcePolicy::Unenforced,
            ..ExecutorConfig::default()
        },
        diagnostics: false,
        commit_cancelled: false,
    }
}

fn held_snapshot() -> (CorpusSnapshot, String) {
    let mut snapshot = snapshot();
    let variant = &mut snapshot.semantic.cases[0].variants[0];
    variant.derivation.strategy = Strategy::ReviewRequired;
    variant.derivation.operator = Some(OperatorRef {
        id: Id::new("synthetic-operator").unwrap(),
        version: 1,
    });
    let held = variant.variant_id.as_str().to_owned();
    seal(&mut snapshot).unwrap();
    (snapshot, held)
}

fn run_over(snapshot: &CorpusSnapshot) -> pii_eval_cli::run::RunOutput {
    let adapter = FakeAdapter::new("alpha-scan", 5);
    let manifest = manifest(
        snapshot,
        vec![adapter.plan.clone()],
        limits(2, 1, 1, 4),
        mechanics(2),
    );
    run(
        &RunRequest {
            snapshot,
            manifest: &manifest,
            adapters: vec![Arc::new(adapter) as Arc<dyn pii_eval_adapters::ScannerAdapter>],
        },
        &config(),
        &CancelToken::new(),
    )
    .expect("run")
}

#[test]
fn a_held_variant_has_an_unmeasured_type_axis_and_nothing_else_changes() {
    let baseline = snapshot();
    let (held_snapshot, held) = held_snapshot();
    let plain = run_over(&baseline);
    let gated = run_over(&held_snapshot);
    let (a, b) = (
        &plain.assembled.artifact.semantic.outcomes,
        &gated.assembled.artifact.semantic.outcomes,
    );
    assert_eq!(a.len(), b.len());
    let mut held_rows = 0;
    for (x, y) in a.iter().zip(b) {
        if y.variant_id.as_str() == held {
            held_rows += 1;
            assert_eq!(y.type_identity, TypeState::NotMeasured);
            // The scanner's observation is untouched: only the type axis is held.
            assert_eq!(x.observed, y.observed);
            assert_eq!(x.range, y.range);
            assert_eq!(x.sensitivity_context, y.sensitivity_context);
        } else {
            assert_eq!(x, y);
        }
    }
    assert!(held_rows > 0);
    // The artifact passes the contract validation and the accounting verifier
    // (the writer runs both) with the gated rows.
    let tmp = TempDir::new("gate-write");
    let adapter = FakeAdapter::new("alpha-scan", 5);
    let manifest = manifest(
        &held_snapshot,
        vec![adapter.plan.clone()],
        limits(2, 1, 1, 4),
        mechanics(2),
    );
    let out = tmp.0.join("out");
    run_and_write(
        &RunRequest {
            snapshot: &held_snapshot,
            manifest: &manifest,
            adapters: vec![Arc::new(adapter) as Arc<dyn pii_eval_adapters::ScannerAdapter>],
        },
        &config(),
        &CancelToken::new(),
        &ArtifactWriter::new(&out, OverwritePolicy::Refuse).with_manifest(),
    )
    .expect("a gated run writes and verifies");
    // The metrics changed with the rows: accounting saw the gated rows.
    assert_ne!(
        plain.assembled.artifact.semantic.scanner_metrics,
        gated.assembled.artifact.semantic.scanner_metrics
    );
}

#[test]
fn a_replay_gates_exactly_as_the_run_did() {
    let (snapshot, _) = held_snapshot();
    let tmp = TempDir::new("gate-replay");
    let adapter = FakeAdapter::new("alpha-scan", 5);
    let manifest = manifest(
        &snapshot,
        vec![adapter.plan.clone()],
        limits(2, 1, 1, 4),
        mechanics(2),
    );
    let run_dir = tmp.0.join("run");
    run_and_write(
        &RunRequest {
            snapshot: &snapshot,
            manifest: &manifest,
            adapters: vec![Arc::new(adapter) as Arc<dyn pii_eval_adapters::ScannerAdapter>],
        },
        &config(),
        &CancelToken::new(),
        &ArtifactWriter::new(&run_dir, OverwritePolicy::Refuse).with_manifest(),
    )
    .unwrap();
    let snapshot_path = tmp.0.join("snapshot.json");
    std::fs::write(&snapshot_path, to_pretty_json(&snapshot).unwrap()).unwrap();
    let replay_dir = tmp.0.join("replay");
    let result = run_cli(&[
        "replay",
        "--snapshot",
        s(&snapshot_path),
        "--manifest",
        s(&run_dir.join("manifest.json")),
        "--observation",
        s(&run_dir.join("observation-alpha-scan.json")),
        "--original",
        s(&run_dir.join("run-artifact.json")),
        "--out",
        s(&replay_dir),
    ]);
    assert_eq!(code(&result), 0, "{}", stderr(&result));
    assert_eq!(summary(&result)["semantic"]["parity"], "identical");
    for name in ["run-artifact.json", "public-synthetic-artifact.json"] {
        assert_eq!(
            std::fs::read(run_dir.join(name)).unwrap(),
            std::fs::read(replay_dir.join(name)).unwrap(),
            "{name}"
        );
    }
    // And the CLI's own validation accepts the gated artifact.
    let check = run_cli(&[
        "validate",
        s(&replay_dir.join("run-artifact.json")),
        "--snapshot",
        s(&snapshot_path),
        "--manifest",
        s(&replay_dir.join("manifest.json")),
    ]);
    assert_eq!(code(&check), 0, "{}", stderr(&check));
    assert_eq!(summary(&check)["semantic"]["verification"], "verified");
}
