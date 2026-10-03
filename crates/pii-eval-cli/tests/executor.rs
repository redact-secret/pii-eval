//! The executor and assembler against in-process fake scanners: determinism
//! independent of scheduling, replay instability, failure recording,
//! cancellation, deadlines, concurrency bounds and sanitized-output
//! verification. Synthetic only; no process is started here.

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

use common::*;
use pii_eval_adapters::AdapterError;
use pii_eval_adapters::error::CallPhase;
use pii_eval_cli::exec::{
    CancelToken, ExecError, ExecutorConfig, ResourcePolicy, effective_limits,
};
use pii_eval_cli::run::{RunConfig, RunError, RunOutput, RunRequest, run};
use pii_eval_contracts::{
    ActionOutcome, ExecutionLimits, FailureCode, MetricId, OutputVerification, ScannerStatus,
    validate,
};
use pii_eval_kernel::verify_run_artifact_accounting;

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

fn run_with(
    adapters: Vec<FakeAdapter>,
    limits: ExecutionLimits,
    replays: u32,
    cfg: &RunConfig,
    cancel: &CancelToken,
) -> Result<RunOutput, RunError> {
    let snapshot = snapshot();
    let manifest = manifest(
        &snapshot,
        adapters.iter().map(|a| a.plan.clone()).collect(),
        limits,
        mechanics(replays),
    );
    run(
        &RunRequest {
            snapshot: &snapshot,
            manifest: &manifest,
            adapters: adapters
                .into_iter()
                .map(|a| Arc::new(a) as Arc<dyn pii_eval_adapters::ScannerAdapter>)
                .collect(),
        },
        cfg,
        cancel,
    )
}

fn ok(adapters: Vec<FakeAdapter>, limits: ExecutionLimits, replays: u32) -> RunOutput {
    run_with(adapters, limits, replays, &config(8), &CancelToken::new()).expect("run")
}

/// Two scanners: a normal one whose completion order is scrambled by delays,
/// and one that cannot start (unsupported).
fn pair() -> Vec<FakeAdapter> {
    let mut alpha = FakeAdapter::new("alpha-scan", 5);
    alpha.delays = vec![
        ("reference", Duration::from_millis(120)),
        ("card 4111 1111 1111 1111", Duration::from_millis(80)),
    ];
    let mut beta = FakeAdapter::new("beta-scan", 3);
    beta.unsupported = true;
    vec![alpha, beta]
}

fn assert_valid_and_verified(output: &RunOutput) {
    let snapshot = snapshot();
    validate(&output.assembled.artifact).expect("artifact validates");
    verify_run_artifact_accounting(&output.assembled.artifact, &snapshot)
        .expect("artifact verifies against its rows");
    for o in &output.assembled.observations {
        validate(o).expect("observation validates");
    }
}

#[test]
fn jobs_one_and_jobs_many_give_the_same_semantic_digests() {
    // (a) One manifest, different host worker caps (jobs = 1, 2, 3, 8): the
    // artifact, observation and public digests are identical.
    let mut digests = Vec::new();
    for max_workers in [1, 2, 3, 8] {
        let out = run_with(
            pair(),
            limits(8, 4, 2, 4),
            2,
            &config(max_workers),
            &CancelToken::new(),
        )
        .unwrap();
        assert_valid_and_verified(&out);
        assert!(out.effective.workers <= max_workers);
        digests.push((
            out.assembled.artifact.semantic_digest.clone(),
            out.assembled
                .observations
                .iter()
                .map(|o| o.semantic_digest.clone())
                .collect::<Vec<_>>(),
            out.assembled
                .public
                .as_ref()
                .unwrap()
                .semantic_digest
                .clone(),
        ));
    }
    assert!(
        digests.windows(2).all(|w| w[0] == w[1]),
        "the semantic digests depend on the worker cap"
    );

    // (b) The execution limits are part of the manifest (so of the manifest
    // digest the artifact binds), but everything measured is independent of
    // them: observations, rows and metrics are equal across schedules.
    let schedules = [
        (1, 1, 1, 1),
        (4, 4, 1, 2),
        (4, 2, 2, 1),
        (8, 8, 3, 64),
        (2, 1, 6, 1),
    ];
    let mut results = Vec::new();
    for (workers, per, batch, pending) in schedules {
        let out = ok(pair(), limits(workers, per, batch, pending), 2);
        assert_valid_and_verified(&out);
        let body = &out.assembled.artifact.semantic;
        results.push((
            out.assembled
                .observations
                .iter()
                .map(|o| o.semantic_digest.clone())
                .collect::<Vec<_>>(),
            body.outcomes.clone(),
            body.scanner_metrics.clone(),
            body.failures.clone(),
        ));
    }
    assert!(
        results.windows(2).all(|w| w[0] == w[1]),
        "measured results depend on the schedule"
    );
}

#[test]
fn completion_order_really_differs_from_variant_order_under_parallelism() {
    // Guards the previous test against being vacuous: with four sessions and
    // one-variant batches, the two delayed variants (indices 0 and 5) finish
    // after the quick ones. The margin (80 and 120 ms against none) is wide.
    let adapters = pair();
    let probe = Arc::clone(&adapters[0].probe);
    let out = ok(adapters, limits(4, 4, 1, 4), 2);
    assert_valid_and_verified(&out);
    // Two passes of six scans; the first pass completes before the second starts.
    let completed = probe.completed.lock().unwrap().clone();
    assert_eq!(completed.len(), 12);
    let completed = &completed[..6];
    assert!(
        !completed[0].starts_with("reference"),
        "the slow first variant finished first: {completed:?}"
    );
}

#[test]
fn repeated_runs_and_diagnostics_do_not_change_the_semantic_digest() {
    let a = ok(pair(), limits(4, 2, 2, 4), 2);
    let b = ok(pair(), limits(4, 2, 2, 4), 2);
    assert_eq!(
        a.assembled.artifact.semantic_digest,
        b.assembled.artifact.semantic_digest
    );
    let mut with = config(8);
    with.diagnostics = true;
    let c = run_with(pair(), limits(4, 2, 2, 4), 2, &with, &CancelToken::new()).unwrap();
    assert!(c.assembled.artifact.diagnostics.is_some());
    assert_eq!(
        a.assembled.artifact.semantic_digest,
        c.assembled.artifact.semantic_digest
    );
    // Timing is separated by phase and stays outside the digest.
    let phases: Vec<_> = c
        .assembled
        .artifact
        .diagnostics
        .as_ref()
        .unwrap()
        .phases
        .iter()
        .map(|p| p.phase.as_str())
        .collect();
    assert_eq!(
        phases,
        [
            "kernel-replay",
            "materialization",
            "scan",
            "scanner-startup",
            "serialization",
            "total"
        ]
    );
    // Runtime provenance is recorded for the scanner that ran, in diagnostics.
    let alpha = &c.assembled.observations[0];
    let runtime = alpha
        .diagnostics
        .as_ref()
        .unwrap()
        .runtime
        .as_ref()
        .unwrap();
    assert_eq!(runtime.runtime_name.as_str(), "fake-runtime");
    assert_eq!(runtime.runtime_version.as_ref().unwrap().as_str(), "1.2.3");
}

#[test]
fn an_unsupported_scanner_is_recorded_and_the_other_scanner_is_still_measured() {
    let out = ok(pair(), limits(4, 2, 1, 4), 2);
    let body = &out.assembled.artifact.semantic;
    assert_eq!(body.scanners[0].status, ScannerStatus::Complete);
    assert_eq!(body.scanners[1].status, ScannerStatus::Unsupported);
    assert_eq!(body.failures.len(), 1);
    assert_eq!(body.failures[0].code, FailureCode::Unsupported);
    assert_eq!(body.failures[0].affected_inputs, 6);
    // The artifact is complete (every row exists) while recording the failure.
    assert_eq!(
        body.completeness,
        pii_eval_contracts::Completeness::Complete
    );
    let beta_rows = body
        .outcomes
        .iter()
        .filter(|o| o.scanner_id.as_str() == "beta-scan");
    assert!(beta_rows.clone().count() > 0);
    assert!(
        beta_rows
            .into_iter()
            .all(|o| o.action == ActionOutcome::NotMeasured)
    );
    // Metrics are per scanner: beta's measured nothing, alpha's did.
    let measured = |i: usize| {
        body.scanner_metrics[i]
            .metrics
            .iter()
            .map(|m| m.counts.measured)
            .sum::<u64>()
    };
    assert_eq!(measured(1), 0);
    assert!(measured(0) > 0);
}

#[test]
fn nondeterministic_output_is_recorded_as_instability_not_sorted_away() {
    let mut flaky = FakeAdapter::new("alpha-scan", 5);
    flaky.flaky = true;
    // One session per pass, so pass 1 uses the 2nd (odd) session.
    let out = ok(vec![flaky], limits(1, 1, 2, 2), 2);
    assert_valid_and_verified(&out);
    let body = &out.assembled.artifact.semantic;
    assert_eq!(body.scanners[0].status, ScannerStatus::Unstable);
    assert!(!body.scanners[0].replays.agreed);
    assert_eq!(body.scanners[0].replays.count, 2);
    assert_eq!(body.failures[0].code, FailureCode::ReplayDisagreement);
    assert_eq!(body.failures[0].affected_inputs, 6, "every input disagreed");
    // No observation of an unstable scanner is kept, and nothing is measured.
    assert!(out.assembled.observations[0].semantic.inputs.is_empty());
    assert!(
        body.outcomes
            .iter()
            .all(|o| o.action == ActionOutcome::NotMeasured)
    );
}

#[test]
fn replays_are_stability_checks_not_extra_samples() {
    let one = ok(
        vec![FakeAdapter::new("alpha-scan", 5)],
        limits(2, 2, 1, 4),
        2,
    );
    let many = ok(
        vec![FakeAdapter::new("alpha-scan", 5)],
        limits(2, 2, 1, 4),
        5,
    );
    let counts = |o: &RunOutput| {
        o.assembled.artifact.semantic.scanner_metrics[0]
            .metrics
            .iter()
            .map(|m| m.counts)
            .collect::<Vec<_>>()
    };
    assert_eq!(counts(&one), counts(&many), "more passes add no samples");
    assert_eq!(
        many.assembled.artifact.semantic.scanners[0].replays.count,
        5
    );
    assert!(many.assembled.artifact.semantic.scanners[0].replays.agreed);
    // Fresh sessions per pass: five passes of one session each.
    let adapter = FakeAdapter::new("alpha-scan", 5);
    let probe = Arc::clone(&adapter.probe);
    ok(vec![adapter], limits(1, 1, 6, 1), 5);
    assert_eq!(probe.sessions_started.load(Ordering::SeqCst), 5);
}

#[test]
fn the_recorded_failure_is_the_lowest_index_whatever_the_schedule() {
    // Variant 3 (the Korean sensitive frame) times out and variant 5 (the
    // mutated card) crashes: the scanner's failure is the timeout, always.
    let mut seen = Vec::new();
    for (workers, per, batch) in [(1, 1, 1), (4, 4, 1), (4, 4, 2), (8, 2, 6)] {
        let mut bad = FakeAdapter::new("alpha-scan", 5);
        bad.failures = vec![
            ("카드", AdapterError::Crashed),
            ("연락처", AdapterError::Timeout(CallPhase::Scan)),
            ("card 4111 1111 1111 1112", AdapterError::Crashed),
        ];
        bad.delays = vec![("card 4111 1111 1111 1112", Duration::from_millis(0))];
        let good = FakeAdapter::new("beta-scan", 3);
        let out = ok(vec![bad, good], limits(workers, per, batch, 4), 2);
        assert_valid_and_verified(&out);
        let body = &out.assembled.artifact.semantic;
        assert_eq!(body.scanners[0].status, ScannerStatus::Error);
        assert_eq!(body.scanners[1].status, ScannerStatus::Complete);
        // A partial failure is never masked: it is a recorded failure, and the
        // artifact is still complete about every row.
        assert_eq!(body.failures.len(), 1);
        seen.push((body.failures[0].code, body.failures[0].affected_inputs));
        assert_eq!(
            body.completeness,
            pii_eval_contracts::Completeness::Complete
        );
    }
    assert!(
        seen.iter().all(|f| *f == (FailureCode::Timeout, 6)),
        "{seen:?}"
    );
}

#[test]
fn cancellation_is_recorded_and_stops_the_run_quickly() {
    // Cancelled before anything starts.
    let cancel = CancelToken::new();
    cancel.cancel();
    let out = run_with(pair(), limits(2, 2, 1, 2), 2, &config(8), &cancel).unwrap();
    assert_valid_and_verified(&out);
    let body = &out.assembled.artifact.semantic;
    assert_eq!(body.scanners[0].status, ScannerStatus::Error);
    assert_eq!(body.failures[0].code, FailureCode::Cancelled);

    // Cancelled while scanning: a slow scanner stops long before it would finish.
    let mut slow = FakeAdapter::new("alpha-scan", 5);
    slow.delay_all = Duration::from_millis(400);
    let cancel = CancelToken::new();
    let canceller = thread::spawn({
        let cancel = cancel.clone();
        move || {
            thread::sleep(Duration::from_millis(150));
            cancel.cancel();
        }
    });
    let started = Instant::now();
    let out = run_with(vec![slow], limits(1, 1, 1, 1), 2, &config(8), &cancel).unwrap();
    canceller.join().unwrap();
    assert_valid_and_verified(&out);
    let body = &out.assembled.artifact.semantic;
    assert_eq!(body.failures[0].code, FailureCode::Cancelled);
    assert_eq!(body.scanners[0].status, ScannerStatus::Error);
    // 12 scans at 400 ms would take 4.8 s.
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn the_scanner_deadline_is_a_total_timeout() {
    let mut slow = FakeAdapter::new("alpha-scan", 5);
    slow.delay_all = Duration::from_millis(400);
    let mut lim = limits(1, 1, 1, 1);
    lim.scanner_timeout_ms = 300;
    let started = Instant::now();
    let out = run_with(vec![slow], lim, 2, &config(8), &CancelToken::new()).unwrap();
    assert_valid_and_verified(&out);
    let body = &out.assembled.artifact.semantic;
    assert_eq!(body.scanners[0].status, ScannerStatus::Error);
    assert_eq!(body.failures[0].code, FailureCode::Timeout);
    assert!(started.elapsed() < Duration::from_secs(4));
}

#[test]
fn concurrency_never_exceeds_the_worker_cap() {
    // Two scanners share one probe: workers = 4, two sessions per scanner.
    let mut a = FakeAdapter::new("alpha-scan", 5);
    a.delay_all = Duration::from_millis(60);
    let mut b = FakeAdapter::new("beta-scan", 3);
    b.delay_all = Duration::from_millis(60);
    b.probe = Arc::clone(&a.probe);
    let probe = Arc::clone(&a.probe);
    let out = ok(vec![a, b], limits(4, 2, 1, 2), 2);
    assert_valid_and_verified(&out);
    let max = probe.max_concurrent.load(Ordering::SeqCst);
    assert!((2..=4).contains(&max), "max concurrent scans {max}");
    assert_eq!(out.effective.workers, 4);
    assert_eq!(out.effective.scanner_concurrency, 2);

    // The host cap wins over the manifest: sixteen requested, two allowed.
    let mut c = FakeAdapter::new("alpha-scan", 5);
    c.delay_all = Duration::from_millis(40);
    let probe = Arc::clone(&c.probe);
    let out = run_with(
        vec![c],
        limits(16, 16, 1, 16),
        2,
        &config(2),
        &CancelToken::new(),
    )
    .unwrap();
    assert_eq!(out.effective.workers, 2);
    assert!(probe.max_concurrent.load(Ordering::SeqCst) <= 2);
}

#[test]
fn invalid_limits_and_budgets_are_refused_before_anything_runs() {
    let cfg = ExecutorConfig {
        max_workers: 8,
        ..ExecutorConfig::default()
    };
    let bad = |mutate: &dyn Fn(&mut ExecutionLimits)| {
        let mut l = limits(4, 2, 2, 8);
        mutate(&mut l);
        effective_limits(&l, &cfg)
    };
    assert_eq!(bad(&|l| l.workers = 0), Err(ExecError::InvalidLimits));
    assert_eq!(
        bad(&|l| l.per_scanner_parallelism = 5),
        Err(ExecError::InvalidLimits)
    );
    assert_eq!(
        bad(&|l| l.batch_variants = 0),
        Err(ExecError::InvalidLimits)
    );
    assert_eq!(bad(&|l| l.pending_tasks = 0), Err(ExecError::InvalidLimits));
    assert_eq!(
        bad(&|l| l.scanner_timeout_ms = 0),
        Err(ExecError::InvalidLimits)
    );
    // 64 MiB over four sessions is 16 MiB each: below what a runtime needs.
    assert_eq!(
        bad(&|l| l.max_memory_bytes = 64 << 20),
        Err(ExecError::BudgetTooSmall)
    );
    let fine = effective_limits(&limits(4, 2, 2, 8), &cfg).unwrap();
    assert_eq!(fine.session_memory_bytes, (16u64 << 30) / 4);
    assert_eq!(fine.session_scratch_bytes, (4u64 << 30) / 4);

    // An adapter that enforces larger output bounds than the manifest is refused.
    let mut greedy = FakeAdapter::new("alpha-scan", 5);
    greedy.adapter_limits = Some(pii_eval_adapters::AdapterLimits {
        max_line_bytes: 32 << 20,
        ..pii_eval_adapters::AdapterLimits::default()
    });
    let refused = run_with(
        vec![greedy],
        limits(1, 1, 1, 1),
        2,
        &config(8),
        &CancelToken::new(),
    );
    assert!(matches!(
        refused,
        Err(RunError::Exec(ExecError::AdapterExceedsManifestBounds {
            scanner: 0
        }))
    ));
}

#[test]
fn a_run_is_refused_for_a_legacy_manifest_or_mismatched_adapters() {
    let snapshot = snapshot();
    let adapters = vec![FakeAdapter::new("alpha-scan", 5)];
    let mut manifest = manifest(
        &snapshot,
        adapters.iter().map(|a| a.plan.clone()).collect(),
        limits(1, 1, 1, 1),
        mechanics(2),
    );
    let as_arcs = |a: &[FakeAdapter]| -> Vec<Arc<dyn pii_eval_adapters::ScannerAdapter>> {
        a.iter().map(|a| Arc::new(a.clone()) as _).collect()
    };
    // No adapter for the planned scanner.
    let none = run(
        &RunRequest {
            snapshot: &snapshot,
            manifest: &manifest,
            adapters: Vec::new(),
        },
        &config(2),
        &CancelToken::new(),
    );
    assert!(matches!(none, Err(RunError::AdapterMismatch)));
    // A revision-1 manifest is readable, not runnable.
    manifest.semantic.protocol = pii_eval_contracts::ProtocolIdentity::LEGACY_V1;
    manifest.schema_version = pii_eval_contracts::SchemaVersion::V1_0;
    pii_eval_contracts::seal(&mut manifest).unwrap();
    let legacy = run(
        &RunRequest {
            snapshot: &snapshot,
            manifest: &manifest,
            adapters: as_arcs(&adapters),
        },
        &config(2),
        &CancelToken::new(),
    );
    assert!(matches!(legacy, Err(RunError::UnsupportedProtocol)));
}

#[test]
fn sanitized_output_is_verified_with_collateral_accounting() {
    let clean = FakeAdapter::new("a-clean", 1);
    let mut unchanged = FakeAdapter::new("b-unchanged", 2);
    unchanged.sanitize = Some(Sanitize::Unchanged);
    let mut collateral = FakeAdapter::new("c-collateral", 3);
    collateral.sanitize = Some(Sanitize::AlsoRedact("reference"));
    let mut reported = FakeAdapter::new("d-reported", 4);
    reported.sanitize = None;
    reported.capabilities = capabilities(false);
    let out = ok(
        vec![clean, unchanged, collateral, reported],
        limits(4, 1, 2, 4),
        2,
    );
    assert_valid_and_verified(&out);
    let rows = &out.assembled.artifact.semantic.outcomes;
    let action = |scanner: &str, case: &str| {
        rows.iter()
            .find(|o| o.scanner_id.as_str() == scanner && o.case_id.as_str() == case)
            .map(|o| o.action)
            .unwrap()
    };
    use OutputVerification::*;
    let verified = |v| ActionOutcome::OutputVerified { verification: v };
    // The collision case's text has the context word "reference".
    assert_eq!(
        action("a-clean", "collision-us-ssn-demo"),
        verified(Removed)
    );
    assert_eq!(
        action("b-unchanged", "collision-us-ssn-demo"),
        verified(ResidualPresent)
    );
    assert_eq!(
        action("c-collateral", "collision-us-ssn-demo"),
        verified(CollateralChange)
    );
    // Another case's context is untouched by the collateral scanner.
    assert_eq!(action("c-collateral", "type-card-demo"), verified(Removed));
    // A scanner without output reports an action but never asserts removal.
    assert!(matches!(
        action("d-reported", "collision-us-ssn-demo"),
        ActionOutcome::Reported { .. }
    ));
    // The observation records the digest of the sanitized output, never its text.
    let a = &out.assembled.observations[0];
    assert!(
        a.semantic
            .inputs
            .iter()
            .all(|i| i.sanitized_output_digest.is_some())
    );
    let text = serde_json::to_string(a).unwrap();
    assert!(!text.contains("<R>"), "no sanitized text in an observation");
    // The metric the action axis could never reach stays untouched by it.
    assert!(
        out.assembled.artifact.semantic.scanner_metrics[0]
            .metrics
            .iter()
            .any(|m| m.metric.id == MetricId::TypeMissRate)
    );
}
