//! Reference adoption: production adapters resolve, job and stage checks still
//! refuse malformed inputs; test adapters stay out of default artifacts and
//! cannot be selected through command-line flags or environment variables.
#![cfg(unix)]

mod cli_support;
mod common;

use cli_support::*;

/// A string present in a binary only when the test adapters are compiled in.
const MARKER: &str = "pii-eval-worker-test-adapters";

fn binary_contains_marker() -> bool {
    let bytes = std::fs::read(bin()).unwrap();
    bytes.windows(MARKER.len()).any(|w| w == MARKER.as_bytes())
}

#[cfg(not(feature = "worker-test-adapters"))]
#[test]
fn the_default_binary_does_not_contain_the_test_adapters() {
    assert!(!binary_contains_marker());
    let v = run_cli(&["--version"]);
    let text = String::from_utf8(v.stdout).unwrap();
    assert_eq!(text, format!("{}\n", pii_eval_cli::version_line()));
    assert!(!text.contains("worker-test-adapters"));
}

#[cfg(feature = "worker-test-adapters")]
#[test]
fn a_feature_build_says_so_and_does_contain_the_marker_so_the_check_can_fail() {
    assert!(binary_contains_marker());
    let v = run_cli(&["--version"]);
    let text = String::from_utf8(v.stdout).unwrap();
    assert!(text.contains("worker-test-adapters"), "{text}");
    assert_eq!(
        text.trim(),
        "pii-eval 0.0.0 (bootstrap; worker-test-adapters)"
    );
}

/// Both builds use fixed production adapters.
#[test]
fn the_binary_reports_an_unreadable_job_and_prints_nothing_on_stdout() {
    for args in [
        vec!["worker-job", "--job", "/nonexistent/job.json"],
        vec!["--job", "/nonexistent/job.json"],
    ] {
        let out = run_cli(&args);
        assert_eq!(code(&out), 3, "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}: stdout must be empty");
        let err = stderr(&out);
        assert_eq!(err, "pii-eval: job-unreadable (invalid-input, exit 3)\n");
    }
}

#[test]
fn malformed_jobs_are_refused_before_stage_reads() {
    let ws = common::TempDir::new("wd-noread");
    let job = ws.0.join("job.json");
    std::fs::write(&job, "this is not even json").unwrap();
    let out = run_cli(&["worker-job", "--job", s(&job)]);
    // Adapter resolution succeeds; malformed input refuses before stage access.
    assert_eq!(code(&out), 3);
    assert!(stderr(&out).contains("job-invalid"));
}

#[test]
fn only_the_exact_custodian_shape_is_an_alias() {
    for args in [
        vec!["--job"],
        vec!["--job", "a", "b"],
        vec!["--job=a"],
        vec!["--job", "a", "--out", "x"],
        vec!["-j", "a"],
    ] {
        let out = run_cli(&args);
        assert_eq!(code(&out), 2, "{args:?}");
    }
    // `worker-job` itself needs its one option, once.
    assert_eq!(code(&run_cli(&["worker-job"])), 2);
    assert_eq!(
        code(&run_cli(&["worker-job", "--job", "a", "--job", "b"])),
        2
    );
    assert_eq!(code(&run_cli(&["worker-job", "--job", "a", "extra"])), 2);
    // The usage text names the command.
    let out = run_cli(&["bogus"]);
    assert!(stderr(&out).contains("worker-job --job FILE"));
}

#[test]
fn no_environment_variable_or_flag_selects_a_test_adapter() {
    let out = run_cli_env(
        &["worker-job", "--job", "/nonexistent"],
        &[
            ("PII_EVAL_WORKER_TEST_ADAPTERS", "1"),
            ("PII_EVAL_TEST_ADAPTERS", "1"),
            ("WORKER_TEST_ADAPTERS", "1"),
        ],
    );
    assert_eq!(code(&out), 3);
    assert!(stderr(&out).contains("job-unreadable"));
    let out = run_cli(&["worker-job", "--job", "/x", "--test-adapters"]);
    assert_eq!(code(&out), 2);
}

#[test]
fn the_test_engine_example_needs_the_feature_so_no_default_build_contains_it() {
    let manifest =
        std::fs::read_to_string(repo_root().join("crates/pii-eval-cli/Cargo.toml")).unwrap();
    let block = manifest
        .split("[[example]]")
        .nth(1)
        .expect("an [[example]] table");
    assert!(block.contains("name = \"worker_test_engine\""));
    assert!(block.contains("required-features = [\"worker-test-adapters\"]"));
    // The feature is off by default and nothing enables it.
    let features = manifest.split("[features]").nth(1).unwrap();
    assert!(features.contains("worker-test-adapters = []"));
    assert!(!manifest.contains("default = ["));
}

#[test]
fn every_worker_reason_and_slot_is_documented_and_no_exit_code_is_added() {
    let doc = std::fs::read_to_string(repo_root().join("docs/worker-job.md")).unwrap();
    for r in pii_eval_cli::worker::reason::ALL {
        assert!(doc.contains(&format!("`{r}`")), "undocumented reason {r}");
    }
    for slot in pii_eval_cli::worker::contract::Slot::ALL {
        assert!(
            doc.contains(&format!("`{}`", slot.name())),
            "{}",
            slot.name()
        );
        assert!(doc.contains(slot.question()), "{}", slot.question());
    }
    let cli = std::fs::read_to_string(repo_root().join("docs/cli.md")).unwrap();
    assert!(cli.contains("no code is added"));
}
