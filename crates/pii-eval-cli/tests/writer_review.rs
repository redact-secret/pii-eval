//! Writer behavior added after review: no-overwrite publication, a stale
//! projection removed under `Replace`, and a failed final sync that is not a
//! failed run. Synthetic only.

mod common;

use std::io;
use std::sync::Arc;

use common::*;
use pii_eval_cli::assemble::Assembled;
use pii_eval_cli::exec::{CancelToken, ExecutorConfig, ResourcePolicy};
use pii_eval_cli::run::{RunConfig, RunRequest, run};
use pii_eval_cli::write::{
    ArtifactWriter, OverwritePolicy, PUBLIC_ARTIFACT_FILE, RUN_ARTIFACT_FILE, WriteError,
    WriteStage,
};
use pii_eval_contracts::{CorpusSnapshot, RunManifest};

struct Run {
    snapshot: CorpusSnapshot,
    manifest: RunManifest,
    assembled: Assembled,
    started: std::time::Instant,
}

fn produce() -> Run {
    let snapshot = snapshot();
    let adapters = vec![FakeAdapter::new("alpha-scan", 5)];
    let manifest = manifest(
        &snapshot,
        adapters.iter().map(|a| a.plan.clone()).collect(),
        limits(2, 1, 2, 2),
        mechanics(2),
    );
    let output = run(
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
                max_workers: 2,
                resources: ResourcePolicy::Unenforced,
                ..ExecutorConfig::default()
            },
            diagnostics: false,
            commit_cancelled: false,
        },
        &CancelToken::new(),
    )
    .expect("run");
    Run {
        snapshot,
        manifest,
        assembled: output.assembled,
        started: output.started,
    }
}

fn names(dir: &std::path::Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[test]
fn a_file_that_appears_between_the_check_and_the_publish_is_never_overwritten() {
    let mut run = produce();
    let tmp = TempDir::new("writer-race");
    let dir = tmp.0.join("out");
    let target = dir.join(RUN_ARTIFACT_FILE);
    let racer = target.clone();
    // A "concurrent writer" creates the commit marker just before it is published.
    let writer = ArtifactWriter::new(&dir, OverwritePolicy::Refuse).with_fault_hook(move |stage| {
        if matches!(stage, WriteStage::BeforeRename(n) if n == RUN_ARTIFACT_FILE) {
            std::fs::write(&racer, b"someone else's result")?;
        }
        Ok(())
    });
    let err = writer
        .write_run(
            &run.snapshot,
            &run.manifest,
            &mut run.assembled,
            run.started,
        )
        .unwrap_err();
    assert_eq!(err, WriteError::Exists);
    assert_eq!(std::fs::read(&target).unwrap(), b"someone else's result");
    // What this call created is rolled back; the other writer's file stays.
    assert_eq!(names(&dir), vec![RUN_ARTIFACT_FILE.to_owned()]);
}

#[test]
fn a_stale_projection_of_an_earlier_run_is_removed_when_the_new_run_has_none() {
    let mut run = produce();
    let tmp = TempDir::new("writer-stale");
    let dir = tmp.0.join("out");
    ArtifactWriter::new(&dir, OverwritePolicy::Refuse)
        .write_run(
            &run.snapshot,
            &run.manifest,
            &mut run.assembled,
            run.started,
        )
        .unwrap();
    assert!(names(&dir).contains(&PUBLIC_ARTIFACT_FILE.to_owned()));
    // The new run has no public projection (as for a protected population).
    run.assembled.public = None;
    ArtifactWriter::new(&dir, OverwritePolicy::Replace)
        .write_run(
            &run.snapshot,
            &run.manifest,
            &mut run.assembled,
            run.started,
        )
        .unwrap();
    assert!(!names(&dir).contains(&PUBLIC_ARTIFACT_FILE.to_owned()));
    assert!(names(&dir).contains(&RUN_ARTIFACT_FILE.to_owned()));
}

#[test]
fn a_failed_final_sync_is_reported_as_not_durable_and_nothing_is_rolled_back() {
    let mut run = produce();
    let tmp = TempDir::new("writer-sync");
    let dir = tmp.0.join("out");
    let writer = ArtifactWriter::new(&dir, OverwritePolicy::Refuse).with_fault_hook(|stage| {
        if matches!(stage, WriteStage::AfterCommit) {
            Err(io::Error::other("sync failed"))
        } else {
            Ok(())
        }
    });
    let err = writer
        .write_run(
            &run.snapshot,
            &run.manifest,
            &mut run.assembled,
            run.started,
        )
        .unwrap_err();
    match err {
        WriteError::CommitNotDurable { files } => {
            assert_eq!(files.last().map(String::as_str), Some(RUN_ARTIFACT_FILE));
        }
        other => panic!("expected CommitNotDurable, got {other}"),
    }
    // Every file is in place and valid: the run is committed, only durability is unconfirmed.
    assert!(names(&dir).contains(&RUN_ARTIFACT_FILE.to_owned()));
    assert!(names(&dir).iter().all(|n| !n.starts_with(".pii-eval-tmp.")));
}
