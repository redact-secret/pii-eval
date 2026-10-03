//! Job execution on the worker pool: limits, backpressure, deduplication,
//! retry reconciliation, stale results, protected routing. Synthetic, no
//! network; waits are on conditions with generous deadlines, never on timing.

use std::sync::{Arc, Mutex};

use pii_eval_app::checks::{CheckStatus, Conclusion, RunnerOutcome};
use pii_eval_app::jobs::{FailReason, JobState};
use pii_eval_app::policy::Limits;
use pii_eval_app::ports::RunnerError;
use pii_eval_app::reason::{Decision, Disposition, Outcome, Reason};
use pii_eval_app::request::{JobId, JobIdentity, ProfileClass, Subject};
use pii_eval_app::testing::*;

fn accepted(d: &Decision) -> (JobId, Disposition) {
    match &d.outcome {
        Outcome::Accepted {
            job_id,
            disposition,
        } => (job_id.clone(), *disposition),
        other => panic!("expected accepted, got {other:?}"),
    }
}

fn rejected(d: &Decision) -> Reason {
    match &d.outcome {
        Outcome::Rejected(r) => *r,
        other => panic!("expected rejection, got {other:?}"),
    }
}

fn wait_state(env: &TestEnv, id: &JobId, what: &str, f: impl Fn(JobState) -> bool) -> JobState {
    let mut last = None;
    wait_until(what, || {
        last = env.app.job_state(id);
        last.is_some_and(&f)
    });
    last.unwrap()
}

fn terminal(env: &TestEnv, id: &JobId) -> JobState {
    wait_state(
        env,
        id,
        "job reaches a terminal state",
        JobState::is_terminal,
    )
}

#[test]
fn a_public_job_runs_on_a_worker_and_publishes_a_sanitized_check() {
    let main_thread = std::thread::current().id();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s = Arc::clone(&seen);
    let runner = FakeRunner::scripted(move |spec| {
        let t = std::thread::current();
        s.lock()
            .unwrap()
            .push((t.id(), t.name().map(str::to_owned)));
        Ok(measured_for(&spec.identity, 0))
    });
    let env = TestEnv::build(Limits::default(), runner);
    let d = env.comment("/pii-eval run");
    let (id, disposition) = accepted(&d);
    assert_eq!(disposition, Disposition::Queued);
    assert_eq!(env.runner.calls(), 0, "the handler did not run the job");
    let pool = env.app.start_workers().unwrap();
    assert_eq!(terminal(&env, &id), JobState::Completed);

    let runs = env.checks.runs();
    assert_eq!(runs.len(), 1);
    let run = &runs[0];
    assert_eq!(run.external_id, id);
    assert_eq!(run.head_sha, sha('1'));
    assert_eq!(run.status, CheckStatus::Completed);
    assert_eq!(run.conclusion, Some(Conclusion::Success));
    assert_eq!(
        run.details_url.as_deref(),
        Some(format!("https://ci.example.invalid/pii-eval/jobs/{id}").as_str())
    );
    let text = &run.output.as_ref().unwrap().summary;
    assert!(text.contains("state: complete"));
    assert!(text.contains(&format!("commit: {}", "1".repeat(40))));
    assert!(text.contains("It is not a support, release or authorization decision."));

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_ne!(seen[0].0, main_thread);
    assert!(
        seen[0]
            .1
            .as_deref()
            .is_some_and(|n| n.starts_with("pii-eval-app-worker-"))
    );
    // The runner is told identities only.
    let specs = env.runner.specs();
    assert_eq!(specs[0].job_id, id);
    assert_eq!(specs[0].attempt, 1);
    pool.shutdown();
}

#[test]
fn duplicate_requests_coalesce_and_a_published_result_is_not_rerun() {
    let env = TestEnv::new();
    let (id, first) = accepted(&env.comment("/pii-eval run"));
    assert_eq!(first, Disposition::Queued);
    // Different deliveries, same identity (even another phrasing and requester path).
    let (id2, second) = accepted(&env.comment("/pii-eval run public-default"));
    assert_eq!(id, id2);
    assert_eq!(second, Disposition::Coalesced);
    assert_eq!(env.app.queue_len(), 1, "one queue entry");
    let pool = env.app.start_workers().unwrap();
    assert_eq!(terminal(&env, &id), JobState::Completed);
    let (id3, third) = accepted(&env.comment("/pii-eval run"));
    assert_eq!(id, id3);
    assert_eq!(third, Disposition::AlreadyComplete);
    assert_eq!(env.app.queue_len(), 0);
    pool.shutdown();
    assert_eq!(env.runner.calls(), 1);
    assert_eq!(env.checks.runs().len(), 1);
}

#[test]
fn job_ids_are_deterministic_and_bound_to_the_identity() {
    let a = TestEnv::new();
    let b = TestEnv::new();
    let (ida, _) = accepted(&a.comment("/pii-eval run"));
    let (idb, _) = accepted(&b.comment("/pii-eval run"));
    assert_eq!(ida, idb, "independent services derive the same id");
    let policy = test_policy(Limits::default());
    let p = policy.profile(PUBLIC_PROFILE).unwrap();
    let expected = JobId::derive(&JobIdentity {
        repository_id: REPO,
        commit: sha('1'),
        profile_id: p.id.clone(),
        engine_version: p.engine_version.clone(),
        protocol_revision: p.protocol_revision,
        config_digest: p.config_digest.clone(),
        population_digest: p.population_digest.clone(),
        class: ProfileClass::PublicSynthetic,
    });
    assert_eq!(ida, expected);
    // Another profile or commit is another job.
    let (other_profile, _) = accepted(&a.comment("/pii-eval run public-alt"));
    assert_ne!(other_profile, ida);
    a.heads.set(REPO, Subject::PullRequest(PR), &sha('3'), REPO);
    let (other_commit, _) = accepted(&a.comment("/pii-eval run"));
    assert_ne!(other_commit, ida);
}

#[test]
fn concurrency_is_limited_to_the_worker_count() {
    let gate = Arc::new(Gate::default());
    let limits = Limits {
        workers: 2,
        queue_capacity: 16,
        ..Limits::default()
    };
    let runner = FakeRunner::complete().with_gate(Arc::clone(&gate));
    let env = TestEnv::build(limits, runner);
    let mut ids = Vec::new();
    for n in 0..6u64 {
        let pr = 100 + n;
        let c = char::from_digit(n as u32 + 1, 16).unwrap();
        env.heads.set(REPO, Subject::PullRequest(pr), &sha(c), REPO);
        let d = env.deliver(
            "issue_comment",
            &comment_payload(INSTALLATION, REPO, REPO_NAME, ACTOR, pr, "/pii-eval run"),
        );
        ids.push(accepted(&d).0);
    }
    let pool = env.app.start_workers().unwrap();
    assert_eq!(pool.size(), 2);
    wait_until("two jobs running, four waiting", || {
        env.runner.running() == 2 && env.app.queue_len() == 4
    });
    assert_eq!(env.runner.running(), 2, "never more than the worker count");
    gate.open();
    for id in &ids {
        assert_eq!(terminal(&env, id), JobState::Completed);
    }
    assert_eq!(env.runner.max_running(), 2);
    assert_eq!(env.runner.calls(), 6);
    pool.shutdown();
}

#[test]
fn a_full_queue_applies_backpressure_and_the_redelivery_succeeds() {
    let limits = Limits {
        queue_capacity: 2,
        ..Limits::default()
    };
    let env = TestEnv::build(limits, FakeRunner::complete());
    for n in 0..2u64 {
        env.heads.set(
            REPO,
            Subject::PullRequest(200 + n),
            &sha(char::from_digit(n as u32 + 4, 16).unwrap()),
            REPO,
        );
        let d = env.deliver(
            "issue_comment",
            &comment_payload(
                INSTALLATION,
                REPO,
                REPO_NAME,
                ACTOR,
                200 + n,
                "/pii-eval run",
            ),
        );
        accepted(&d);
    }
    env.heads
        .set(REPO, Subject::PullRequest(300), &sha('9'), REPO);
    let body = comment_payload(INSTALLATION, REPO, REPO_NAME, ACTOR, 300, "/pii-eval run");
    let full = env.deliver_with_id("issue_comment", "late-delivery", &body);
    assert_eq!(rejected(&full), Reason::QueueFull);
    assert_eq!(full.outcome.http_status(), 503);
    assert_eq!(env.app.queue_len(), 2, "bounded");
    let id = full.meta.job_id.clone().unwrap();
    assert!(
        env.app.job(&id).is_none(),
        "the refused job was rolled back"
    );
    assert_eq!(env.runner.calls(), 0);
    // Capacity returns once the workers drain the queue; GitHub redelivers
    // with the same id and it is accepted (the id was not consumed).
    let pool = env.app.start_workers().unwrap();
    wait_until("queue drained", || env.app.queue_len() == 0);
    let again = env.deliver_with_id("issue_comment", "late-delivery", &body);
    let (id2, _) = accepted(&again);
    assert_eq!(id, id2);
    assert_eq!(terminal(&env, &id2), JobState::Completed);
    pool.shutdown();
}

#[test]
fn the_job_store_is_bounded() {
    let limits = Limits {
        job_capacity: 2,
        queue_capacity: 2,
        ..Limits::default()
    };
    let env = TestEnv::build(limits, FakeRunner::complete());
    for n in 0..2u64 {
        env.heads.set(
            REPO,
            Subject::PullRequest(400 + n),
            &sha(char::from_digit(n as u32 + 1, 16).unwrap()),
            REPO,
        );
        accepted(&env.deliver(
            "issue_comment",
            &comment_payload(
                INSTALLATION,
                REPO,
                REPO_NAME,
                ACTOR,
                400 + n,
                "/pii-eval run",
            ),
        ));
    }
    env.heads
        .set(REPO, Subject::PullRequest(402), &sha('7'), REPO);
    let d = env.deliver(
        "issue_comment",
        &comment_payload(INSTALLATION, REPO, REPO_NAME, ACTOR, 402, "/pii-eval run"),
    );
    assert_eq!(rejected(&d), Reason::JobStoreFull);
}

#[test]
fn a_result_for_a_commit_that_is_no_longer_the_head_is_dropped() {
    let gate = Arc::new(Gate::default());
    let runner = FakeRunner::complete().with_gate(Arc::clone(&gate));
    let env = TestEnv::build(Limits::default(), runner);
    let (id, _) = accepted(&env.comment("/pii-eval run"));
    let pool = env.app.start_workers().unwrap();
    wait_until("the run started", || env.runner.running() == 1);
    // A new commit lands while the job runs.
    env.heads
        .set(REPO, Subject::PullRequest(PR), &sha('8'), REPO);
    gate.open();
    assert_eq!(terminal(&env, &id), JobState::Stale);
    let runs = env.checks.runs();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].conclusion, Some(Conclusion::Neutral));
    let text = &runs[0].output.as_ref().unwrap().summary;
    assert!(text.contains("state: superseded") && text.contains("reason: stale-head"));
    // Nothing the run produced reaches the Check.
    assert!(
        !text.contains(&"5".repeat(64)),
        "run artifact digest withheld"
    );
    assert!(!text.contains("scanner "), "scanner statuses withheld");
    // A new request for the new head is a new job.
    let (new_id, d) = accepted(&env.comment("/pii-eval run"));
    assert_ne!(new_id, id);
    assert_eq!(d, Disposition::Queued);
    assert_eq!(terminal(&env, &new_id), JobState::Completed);
    pool.shutdown();
}

#[test]
fn a_job_whose_head_moved_while_queued_never_runs() {
    let env = TestEnv::new();
    let (id, _) = accepted(&env.comment("/pii-eval run"));
    env.heads
        .set(REPO, Subject::PullRequest(PR), &sha('8'), REPO);
    let pool = env.app.start_workers().unwrap();
    assert_eq!(terminal(&env, &id), JobState::Stale);
    pool.shutdown();
    assert_eq!(env.runner.calls(), 0);
    assert!(env.checks.runs().is_empty(), "no Check for a stale request");
}

#[test]
fn an_unverifiable_head_fails_closed_and_can_be_retried() {
    let env = TestEnv::new();
    let (id, _) = accepted(&env.comment("/pii-eval run"));
    env.heads.set_failing(true);
    let pool = env.app.start_workers().unwrap();
    assert_eq!(
        terminal(&env, &id),
        JobState::Failed(FailReason::HeadUnverifiable)
    );
    assert_eq!(env.runner.calls(), 0);
    env.heads.set_failing(false);
    let (_, d) = accepted(&env.comment("/pii-eval run"));
    assert_eq!(d, Disposition::Requeued);
    assert_eq!(terminal_after_requeue(&env, &id), JobState::Completed);
    pool.shutdown();
}

fn terminal_after_requeue(env: &TestEnv, id: &JobId) -> JobState {
    wait_state(env, id, "retry completes", |s| {
        s.is_terminal() && s != JobState::Failed(FailReason::HeadUnverifiable)
    })
}

#[test]
fn a_failed_publish_is_retried_without_running_again() {
    let env = TestEnv::new();
    let (id, _) = accepted(&env.comment("/pii-eval run"));
    env.checks.fail_next_updates(1);
    let pool = env.app.start_workers().unwrap();
    assert_eq!(
        terminal(&env, &id),
        JobState::Failed(FailReason::PublishFailed)
    );
    assert!(env.app.job(&id).unwrap().pending.is_some(), "result kept");
    // A redelivery (a new request for the same identity) republishes.
    let (_, d) = accepted(&env.comment("/pii-eval run"));
    assert_eq!(d, Disposition::Requeued);
    wait_state(&env, &id, "published", |s| s == JobState::Completed);
    assert_eq!(env.runner.calls(), 1, "the measurement was not repeated");
    let runs = env.checks.runs();
    assert_eq!(runs.len(), 1, "one Check, updated in place");
    assert_eq!(runs[0].conclusion, Some(Conclusion::Success));
    assert!(env.app.job(&id).unwrap().pending.is_none());
    pool.shutdown();
}

#[test]
fn a_create_whose_response_was_lost_is_reconciled_by_external_id() {
    let env = TestEnv::new();
    let (id, _) = accepted(&env.comment("/pii-eval run"));
    env.checks.lose_next_create_response();
    let pool = env.app.start_workers().unwrap();
    assert_eq!(
        terminal(&env, &id),
        JobState::Failed(FailReason::PublishFailed)
    );
    assert_eq!(env.checks.runs().len(), 1, "GitHub did create it");
    accepted(&env.comment("/pii-eval run"));
    wait_state(&env, &id, "completed", |s| s == JobState::Completed);
    let runs = env.checks.runs();
    assert_eq!(runs.len(), 1, "found by external id, not created twice");
    assert_eq!(runs[0].conclusion, Some(Conclusion::Success));
    pool.shutdown();
}

#[test]
fn retries_are_bounded_by_max_attempts() {
    let limits = Limits {
        max_attempts: 2,
        ..Limits::default()
    };
    let runner = FakeRunner::scripted(|_| Err(RunnerError::Timeout));
    let env = TestEnv::build(limits, runner);
    let (id, _) = accepted(&env.comment("/pii-eval run"));
    let pool = env.app.start_workers().unwrap();
    assert_eq!(terminal(&env, &id), JobState::Failed(FailReason::Timeout));
    let runs = env.checks.runs();
    assert_eq!(runs[0].conclusion, Some(Conclusion::TimedOut));
    assert!(
        runs[0]
            .output
            .as_ref()
            .unwrap()
            .summary
            .contains("reason: timeout")
    );
    let (_, d) = accepted(&env.comment("/pii-eval run"));
    assert_eq!(d, Disposition::Requeued);
    wait_state(&env, &id, "second attempt", |_| env.runner.calls() == 2);
    wait_until("second attempt finished", || {
        env.app.job_state(&id) == Some(JobState::Failed(FailReason::Timeout))
            && env.app.job(&id).unwrap().attempts == 2
    });
    let d = env.comment("/pii-eval run");
    assert_eq!(rejected(&d), Reason::RetryLimit);
    assert_eq!(d.outcome.http_status(), 429);
    pool.shutdown();
    assert_eq!(env.runner.calls(), 2);
}

#[test]
fn run_outcomes_map_to_conclusions_and_never_to_a_false_success() {
    type Script = Box<dyn Fn(&JobIdentity) -> Result<RunnerOutcome, RunnerError> + Send + Sync>;
    let cases: Vec<(&str, Script, Conclusion, FailReason)> = vec![
        (
            "incomplete",
            Box::new(|i| Ok(measured_for(i, 5))),
            Conclusion::Failure,
            FailReason::RunFailed,
        ),
        (
            "identity",
            Box::new(|i| {
                let mut other = i.clone();
                other.population_digest = "7".repeat(64);
                Ok(measured_for(&other, 0))
            }),
            Conclusion::Failure,
            FailReason::IdentityMismatch,
        ),
        (
            "cli-failure",
            Box::new(|_| {
                Ok(RunnerOutcome::Failed {
                    exit_code: 6,
                    reason: "execution-refused".into(),
                })
            }),
            Conclusion::Failure,
            FailReason::RunFailed,
        ),
        (
            "cli-cancelled",
            Box::new(|_| {
                Ok(RunnerOutcome::Failed {
                    exit_code: 8,
                    reason: "cancelled".into(),
                })
            }),
            Conclusion::Cancelled,
            FailReason::Cancelled,
        ),
        (
            "refused",
            Box::new(|_| Err(RunnerError::Refused)),
            Conclusion::Failure,
            FailReason::RunnerRefused,
        ),
        (
            "changed",
            Box::new(|_| Err(RunnerError::ProfileChanged)),
            Conclusion::Failure,
            FailReason::IdentityMismatch,
        ),
        (
            "rejected",
            Box::new(|_| Err(RunnerError::SummaryRejected)),
            Conclusion::Failure,
            FailReason::RunFailed,
        ),
        (
            "internal",
            Box::new(|_| Err(RunnerError::Internal)),
            Conclusion::Failure,
            FailReason::Internal,
        ),
    ];
    for (name, script, conclusion, fail) in cases {
        let runner = FakeRunner::scripted(move |spec| script(&spec.identity));
        let env = TestEnv::build(Limits::default(), runner);
        let (id, _) = accepted(&env.comment("/pii-eval run"));
        let pool = env.app.start_workers().unwrap();
        assert_eq!(terminal(&env, &id), JobState::Failed(fail), "{name}");
        let runs = env.checks.runs();
        assert_eq!(runs[0].conclusion, Some(conclusion), "{name}");
        assert_eq!(runs[0].status, CheckStatus::Completed, "{name}");
        if name == "identity" {
            assert!(
                !runs[0]
                    .output
                    .as_ref()
                    .unwrap()
                    .summary
                    .contains(&"7".repeat(64))
            );
        }
        pool.shutdown();
    }
}

#[test]
fn a_panicking_runner_fails_the_job_and_the_worker_survives() {
    let first = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let f = Arc::clone(&first);
    let runner = FakeRunner::scripted(move |spec| {
        if f.swap(false, std::sync::atomic::Ordering::SeqCst) {
            panic!("SENTINEL-panic-text");
        }
        Ok(measured_for(&spec.identity, 0))
    });
    let limits = Limits {
        workers: 1,
        ..Limits::default()
    };
    let env = TestEnv::build(limits, runner);
    let (a, _) = accepted(&env.comment("/pii-eval run"));
    let (b, _) = accepted(&env.comment("/pii-eval run public-alt"));
    let pool = env.app.start_workers().unwrap();
    assert_eq!(terminal(&env, &a), JobState::Failed(FailReason::Internal));
    assert_eq!(
        terminal(&env, &b),
        JobState::Completed,
        "the single worker survived"
    );
    for run in env.checks.runs() {
        assert!(!run.output.unwrap().summary.contains("SENTINEL"));
    }
    pool.shutdown();
}

#[test]
fn protected_profiles_are_only_routed_to_the_custodian() {
    let env = TestEnv::new();
    let (id, _) = accepted(&env.comment("/pii-eval run protected-main"));
    let pool = env.app.start_workers().unwrap();
    assert_eq!(terminal(&env, &id), JobState::RoutedToCustodian);
    // Routed, not run: no runner call, no Check, no result.
    assert_eq!(env.runner.calls(), 0);
    assert!(env.checks.runs().is_empty());
    let subs = env.custodian.submissions();
    assert_eq!(subs.len(), 1);
    assert_eq!(subs[0].job_id, id);
    assert_eq!(subs[0].identity.class, ProfileClass::Protected);
    assert_eq!(subs[0].requester_id, ACTOR);
    // Asking again does not submit again.
    let (_, d) = accepted(&env.comment("/pii-eval run protected-main"));
    assert_eq!(d, Disposition::AlreadyRouted);
    assert_eq!(env.custodian.submissions().len(), 1);
    // A request from someone who is not on the allowlist never reaches it.
    let d = env.deliver(
        "issue_comment",
        &comment_payload(
            INSTALLATION,
            REPO,
            REPO_NAME,
            9999,
            PR,
            "/pii-eval run protected-main",
        ),
    );
    assert_eq!(rejected(&d), Reason::ActorNotAuthorized);
    // And repository B has no protected profile at all.
    env.heads
        .set(OTHER_REPO, Subject::PullRequest(PR), &sha('2'), OTHER_REPO);
    let d = env.deliver(
        "issue_comment",
        &comment_payload(
            OTHER_INSTALLATION,
            OTHER_REPO,
            "example/other",
            OTHER_ACTOR,
            PR,
            "/pii-eval run protected-main",
        ),
    );
    assert_eq!(rejected(&d), Reason::ProfileNotAllowed);
    pool.shutdown();
    assert_eq!(env.custodian.submissions().len(), 1);
}

#[test]
fn an_unavailable_custodian_fails_the_routing_and_never_falls_back_to_running() {
    let env = TestEnv::new();
    env.custodian.set_unavailable(true);
    let (id, _) = accepted(&env.comment("/pii-eval run protected-main"));
    let pool = env.app.start_workers().unwrap();
    assert_eq!(
        terminal(&env, &id),
        JobState::Failed(FailReason::CustodianUnavailable)
    );
    assert_eq!(env.runner.calls(), 0, "no fallback to a local run");
    env.custodian.set_unavailable(false);
    let (_, d) = accepted(&env.comment("/pii-eval run protected-main"));
    assert_eq!(d, Disposition::Requeued);
    wait_state(&env, &id, "routed", |s| s == JobState::RoutedToCustodian);
    pool.shutdown();
}

#[test]
fn rerequests_keep_the_profile_and_the_commit() {
    let env = TestEnv::new();
    let (id, _) = accepted(&env.comment("/pii-eval run public-alt"));
    let pool = env.app.start_workers().unwrap();
    assert_eq!(terminal(&env, &id), JobState::Completed);
    // "Re-run" on our Check: the payload carries our external id.
    let d = env.deliver(
        "check_run",
        &run_payload(
            "rerequested",
            INSTALLATION,
            REPO,
            REPO_NAME,
            ACTOR,
            &sha('1'),
            Some(PR),
            Some(id.as_str()),
        ),
    );
    let (id2, disposition) = accepted(&d);
    assert_eq!(id2, id, "the same profile and commit give the same job");
    assert_eq!(disposition, Disposition::AlreadyComplete);
    // A foreign or unknown external id falls back to the default profile.
    let d = env.deliver(
        "check_run",
        &run_payload(
            "rerequested",
            INSTALLATION,
            REPO,
            REPO_NAME,
            ACTOR,
            &sha('1'),
            Some(PR),
            Some(&"e".repeat(64)),
        ),
    );
    let (id3, _) = accepted(&d);
    assert_ne!(id3, id);
    // check_suite rerequested for the current head.
    let d = env.deliver(
        "check_suite",
        &suite_payload(
            "rerequested",
            INSTALLATION,
            REPO,
            REPO_NAME,
            ACTOR,
            &sha('1'),
            Some(PR),
        ),
    );
    assert_eq!(accepted(&d).0, id3);
    // A suite without a pull request resolves the branch.
    env.heads
        .set(REPO, Subject::Branch("feature".into()), &sha('1'), REPO);
    let d = env.deliver(
        "check_suite",
        &suite_payload(
            "rerequested",
            INSTALLATION,
            REPO,
            REPO_NAME,
            ACTOR,
            &sha('1'),
            None,
        ),
    );
    assert_eq!(accepted(&d).0, id3);
    pool.shutdown();
}

#[test]
fn shutdown_stops_admission_and_a_second_start_is_refused() {
    let env = TestEnv::new();
    let pool = env.app.start_workers().unwrap();
    assert!(env.app.start_workers().is_err());
    pool.shutdown();
    let d = env.comment("/pii-eval run");
    assert_eq!(rejected(&d), Reason::ShuttingDown);
    assert_eq!(env.app.queue_len(), 0);
}
