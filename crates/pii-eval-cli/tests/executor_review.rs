//! Executor behavior added after review: pin precedence, manifest-only
//! resource shares, and the refusal to commit a cancelled run. In-process
//! fakes only.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use pii_eval_adapters::AdapterError;
use pii_eval_adapters::error::PinKind;
use pii_eval_cli::exec::{CancelToken, ExecutorConfig, ResourcePolicy, effective_limits};
use pii_eval_cli::run::{RunConfig, RunError, RunRequest, run, run_and_write};
use pii_eval_cli::write::{ArtifactWriter, OverwritePolicy};
use pii_eval_contracts::{FailureCode, ScannerStatus};

fn config(max_workers: usize) -> RunConfig {
    RunConfig {
        executor: ExecutorConfig {
            max_workers,
            resources: ResourcePolicy::Unenforced,
            ..ExecutorConfig::default()
        },
        diagnostics: false,
        commit_cancelled: false,
    }
}

#[test]
fn a_changed_pin_is_the_recorded_cause_whatever_else_failed_and_whatever_the_jobs() {
    // Every session reports a changed pinned file at its end; one input also
    // crashes the session. The pin failure wins (observations of a session whose
    // pins changed are untrusted), also from sessions that died, so the recorded
    // cause does not depend on which sessions survived.
    let snapshot = snapshot();
    let mut seen = Vec::new();
    for (workers, per, batch) in [(1, 1, 1), (4, 4, 1), (4, 2, 3)] {
        let mut a = FakeAdapter::new("alpha-scan", 5);
        a.pin_check = Some(AdapterError::PinMismatch(PinKind::ArtifactDigest));
        a.failures = vec![("연락처", AdapterError::Crashed)];
        let manifest = manifest(
            &snapshot,
            vec![a.plan.clone()],
            limits(workers, per, batch, 4),
            mechanics(2),
        );
        let out = run(
            &RunRequest {
                snapshot: &snapshot,
                manifest: &manifest,
                adapters: vec![Arc::new(a) as Arc<dyn pii_eval_adapters::ScannerAdapter>],
            },
            &config(8),
            &CancelToken::new(),
        )
        .unwrap();
        let body = &out.assembled.artifact.semantic;
        seen.push((body.scanners[0].status, body.failures[0].code));
    }
    assert!(
        seen.iter()
            .all(|s| *s == (ScannerStatus::Unavailable, FailureCode::Unavailable)),
        "{seen:?}"
    );
}

#[test]
fn the_per_session_share_comes_from_the_manifest_not_from_the_host() {
    let limits = limits(4, 2, 2, 8);
    let share = |max_workers: usize| {
        let cfg = ExecutorConfig {
            max_workers,
            ..ExecutorConfig::default()
        };
        let e = effective_limits(&limits, &cfg).unwrap();
        (e.session_memory_bytes, e.session_scratch_bytes)
    };
    // One CPU or sixty-four: the share is the same, only the parallelism differs.
    assert_eq!(share(1), share(64));
    assert_eq!(share(1).0, (16u64 << 30) / 4);
}

#[test]
fn a_cancelled_run_is_not_committed_unless_explicitly_allowed() {
    let snapshot = snapshot();
    let mut slow = FakeAdapter::new("alpha-scan", 5);
    slow.delay_all = Duration::from_millis(300);
    let manifest = manifest(
        &snapshot,
        vec![slow.plan.clone()],
        limits(1, 1, 1, 1),
        mechanics(2),
    );
    let cancel = CancelToken::new();
    cancel.cancel();
    let request = RunRequest {
        snapshot: &snapshot,
        manifest: &manifest,
        adapters: vec![Arc::new(slow) as Arc<dyn pii_eval_adapters::ScannerAdapter>],
    };
    let tmp = TempDir::new("cancel-commit");
    let dir = tmp.0.join("out");
    let writer = ArtifactWriter::new(&dir, OverwritePolicy::Refuse);
    let cfg = config(8);
    let refused = run_and_write(&request, &cfg, &cancel, &writer);
    assert!(matches!(refused, Err(RunError::Cancelled)));
    assert!(!dir.exists(), "nothing was committed");
    let allowed = RunConfig {
        commit_cancelled: true,
        ..cfg
    };
    let (out, written) = run_and_write(&request, &allowed, &cancel, &writer).expect("allowed");
    assert_eq!(
        out.assembled.artifact.semantic.failures[0].code,
        FailureCode::Cancelled
    );
    assert_eq!(written.files.last().unwrap().name, "run-artifact.json");
}
