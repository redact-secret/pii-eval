//! Everything that reaches the (fake) GitHub Checks API is sanitized: fixed
//! vocabulary, validated fields, printable ASCII, no payload text, no secret,
//! no runner free text. Sentinels are planted everywhere untrusted text can
//! enter and must never come out.

use pii_eval_app::checks::{RunnerOutcome, guard_text};
use pii_eval_app::jobs::JobState;
use pii_eval_app::policy::Limits;
use pii_eval_app::reason::Outcome;
use pii_eval_app::testing::*;

const SENTINEL: &str = "SENTINEL-4f9c2a";

fn assert_clean(env: &TestEnv) {
    let secret = String::from_utf8_lossy(SECRET).into_owned();
    let runs = env.checks.runs();
    assert!(!runs.is_empty());
    for run in runs {
        let out = run.output.expect("output");
        for text in [&out.title, &out.summary] {
            assert!(!text.contains(SENTINEL), "sentinel leaked: {text}");
            assert!(!text.contains(&secret));
            assert!(
                text.bytes()
                    .all(|b| b == b'\n' || (0x20..0x7f).contains(&b)),
                "non-printable byte"
            );
            assert!(text.len() <= pii_eval_app::checks::MAX_SUMMARY_BYTES);
        }
        if let Some(url) = &run.details_url {
            assert!(url.starts_with("https://ci.example.invalid/"));
            assert!(!url.contains(SENTINEL));
        }
    }
}

#[test]
fn comment_text_and_runner_extras_never_reach_a_check() {
    // A comment carrying a sentinel after the command line, and a CLI summary
    // with sentinels in every place a free-text field might be copied from.
    let runner = FakeRunner::scripted(|spec| {
        let mut line: serde_json::Value =
            serde_json::from_str(&summary_line_for(&spec.identity, 0)).unwrap();
        line["extra"] = SENTINEL.into();
        line["error"] = serde_json::json!({"detail": SENTINEL, "reason": "run-failed"});
        line["semantic"]["note"] = SENTINEL.into();
        line["semantic"]["scanners"][0]["failure"] = serde_json::json!({"message": SENTINEL});
        line["outputs"] = serde_json::json!({"files": [{"name": SENTINEL}]});
        Ok(RunnerOutcome::from_summary_line(&line.to_string()).expect("extras are ignored"))
    });
    let env = TestEnv::build(Limits::default(), runner);
    let d = env.comment(&format!("/pii-eval run\n{SENTINEL}\nsecret=hunter2"));
    let Outcome::Accepted { job_id, .. } = d.outcome else {
        panic!("accepted")
    };
    let pool = env.app.start_workers().unwrap();
    wait_until("completed", || {
        env.app.job_state(&job_id) == Some(JobState::Completed)
    });
    pool.shutdown();
    assert_clean(&env);
    for run in env.checks.runs() {
        assert!(!run.output.unwrap().summary.contains("hunter2"));
    }
}

#[test]
fn a_summary_with_an_unsafe_field_becomes_a_fixed_rejection_check() {
    // The runner's own projection refuses the sentinel, which the service
    // reports as `summary-rejected` with no field copied.
    let runner = FakeRunner::scripted(|spec| {
        let mut line: serde_json::Value =
            serde_json::from_str(&summary_line_for(&spec.identity, 0)).unwrap();
        line["semantic"]["scanners"][0]["scannerId"] = SENTINEL.into();
        RunnerOutcome::from_summary_line(&line.to_string())
            .map_err(|_| pii_eval_app::ports::RunnerError::SummaryRejected)
    });
    let env = TestEnv::build(Limits::default(), runner);
    let Outcome::Accepted { job_id, .. } = env.comment("/pii-eval run").outcome else {
        panic!("accepted")
    };
    let pool = env.app.start_workers().unwrap();
    wait_until("terminal", || {
        env.app
            .job_state(&job_id)
            .is_some_and(JobState::is_terminal)
    });
    pool.shutdown();
    assert_clean(&env);
    let runs = env.checks.runs();
    let text = &runs[0].output.as_ref().unwrap().summary;
    assert!(text.contains("reason: summary-rejected"));
    assert!(!text.contains("scanner "));
}

#[test]
fn the_output_guard_is_exposed_for_the_ascii_rule() {
    assert!(guard_text("plain\ntext").is_ok());
    assert!(guard_text("na\u{ef}ve").is_err());
    assert!(guard_text("esc\u{1b}[31m").is_err());
}
