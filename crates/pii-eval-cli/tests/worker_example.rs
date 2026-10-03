//! The TEST-ONLY engine of the real-sandbox end to end
//! (`examples/worker_test_engine.rs`, tools/isolation/worker-e2e.mjs): it exists only
//! with the cargo feature, its `validate` equals the replica the other worker tests use,
//! and its `stage` and engine modes work with the real Node runtime (unsandboxed here;
//! the sandbox is the CI job `worker-flow`). Synthetic data only.
//!
//! The example is built on demand by the first test that needs it (dev profile, same feature).
#![cfg(all(unix, feature = "worker-test-adapters"))]

mod cli_support;
mod common;
mod worker_support;

use std::path::PathBuf;
use std::process::{Command, Output};

use cli_support::*;
use serde_json::Value;
use worker_support::replica::*;

/// The example binary, built on demand: `cargo test` compiles examples only as tests (or
/// checks them), never as the plain executable the sandbox runs, so this builds it with the
/// same feature, once, in the dev profile.
fn example() -> PathBuf {
    static BUILT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    BUILT
        .get_or_init(|| {
            let status = Command::new(option_env!("CARGO").unwrap_or("cargo"))
                .args([
                    "build",
                    "--locked",
                    "-p",
                    "pii-eval-cli",
                    "--features",
                    "worker-test-adapters",
                    "--example",
                    "worker_test_engine",
                ])
                .current_dir(repo_root())
                .status()
                .expect("cargo runs");
            assert!(status.success(), "building the example failed");
            let exe = std::env::current_exe().unwrap();
            let path = exe
                .parent()
                .and_then(|deps| deps.parent())
                .unwrap()
                .join("examples/worker_test_engine");
            assert!(path.is_file(), "the example was not built at {path:?}");
            path
        })
        .clone()
}

fn run(args: &[&str]) -> Output {
    Command::new(example()).args(args).output().unwrap()
}

fn json_line(out: &Output) -> Value {
    let text = String::from_utf8(out.stdout.clone()).unwrap();
    assert_eq!(text.matches('\n').count(), 1, "one line: {text:?}");
    serde_json::from_str(&text).unwrap()
}

#[test]
fn the_example_is_declared_test_only_and_contains_the_marker() {
    let manifest =
        std::fs::read_to_string(repo_root().join("crates/pii-eval-cli/Cargo.toml")).unwrap();
    let block = manifest
        .split("[[example]]")
        .nth(1)
        .expect("an [[example]] table");
    assert!(block.contains("name = \"worker_test_engine\""));
    assert!(block.contains("required-features = [\"worker-test-adapters\"]"));
    assert_eq!(manifest.matches("[[example]]").count(), 1);
    let bytes = std::fs::read(example()).unwrap();
    let marker = pii_eval_cli::worker::test_adapters::MARKER;
    assert!(bytes.windows(marker.len()).any(|w| w == marker.as_bytes()));
}

#[test]
fn validate_equals_the_replica_for_every_way_a_worker_can_end() {
    let ws = common::TempDir::new("we-validate");
    let dir = ws.0.join("w");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("pins.json"),
        r#"{"schema":"x","pins":{},"roster":3}"#,
    )
    .unwrap();
    let good = br#"{"schema":"private-custodian.worker-result/1","domain":"pii","protocol":{"name":"pii-v1","version":"2"},"status":"complete","roster":{"expected":3,"observed":3,"failed":0}}"#.to_vec();
    let failed = String::from_utf8(good.clone())
        .unwrap()
        .replace("\"failed\":0", "\"failed\":3")
        .into_bytes();
    let forged = String::from_utf8(good.clone())
        .unwrap()
        .replace("complete", "partial")
        .into_bytes();
    let wrong_roster = String::from_utf8(good.clone())
        .unwrap()
        .replace("\"expected\":3", "\"expected\":4")
        .into_bytes();
    let aggregates = br#"{"schema":"private-custodian.aggregates/1","domain":"pii","protocol":{"name":"pii-v1","version":"2"},"roster":{"expected":3,"observed":3,"failed":0},"cells":[{"stratum":"overall","metric":"type-miss-rate","numerator":1,"denominator":3}]}"#.to_vec();
    type Vector = (&'static str, Vec<u8>, Option<Vec<u8>>);
    let vectors: Vec<Vector> = vec![
        ("0", good.clone(), Some(aggregates.clone())),
        ("0", good.clone(), None),
        ("0", failed, None),
        ("0", forged, None),
        ("0", wrong_roster, None),
        ("0", b"not json".to_vec(), None),
        ("0", vec![b'a'; MAX_RESULT_BYTES + 1], None),
        ("3", good.clone(), Some(aggregates.clone())),
        ("signal:SIGKILL", Vec::new(), None),
        ("timeout", Vec::new(), None),
        ("output-limit", good.clone(), None),
        (
            "0",
            good,
            Some(aggregates.clone().into_iter().rev().collect()),
        ),
    ];
    for (i, (exit, stdout, agg)) in vectors.iter().enumerate() {
        let stdout_file = ws.0.join(format!("stdout-{i}"));
        std::fs::write(&stdout_file, stdout).unwrap();
        let mut args = vec![
            "validate",
            "--dir",
            s(&dir),
            "--stdout",
            s(&stdout_file),
            "--exit",
            exit,
        ];
        let agg_file = ws.0.join(format!("agg-{i}"));
        if let Some(a) = agg {
            std::fs::write(&agg_file, a).unwrap();
            args.push("--aggregates");
            args.push(s(&agg_file));
        }
        let got = json_line(&run(&args));
        let want = report_json(
            &Termination::parse(exit).unwrap(),
            stdout,
            agg.as_deref(),
            3,
        );
        assert_eq!(got, want, "vector {i}");
    }
    // Spot checks of the mapping itself (A6).
    let ok = report_json(
        &Termination::parse("0").unwrap(),
        &vectors[0].1,
        vectors[0].2.as_deref(),
        3,
    );
    assert_eq!(
        (ok["outcome"].as_str(), ok["aggregatesOk"].as_bool()),
        (Some("Success"), Some(true))
    );
    let timeout = report_json(&Termination::parse("timeout").unwrap(), &[], None, 3);
    assert_eq!(
        (timeout["outcome"].as_str(), timeout["reason"].as_str()),
        (Some("Failed"), Some("timeout"))
    );
    assert!(Termination::parse("signal:").is_none() && Termination::parse("x").is_none());
    // Usage errors are fixed text with exit 2 and nothing on stdout.
    for args in [
        vec!["validate"],
        vec!["stage", "--out"],
        vec!["bogus"],
        vec![
            "validate",
            "--dir",
            s(&dir),
            "--stdout",
            "/nonexistent",
            "--exit",
            "0",
        ],
    ] {
        let out = run(&args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(out.stdout.is_empty());
    }
}

#[test]
fn stage_builds_the_custodians_layout_and_the_engine_runs_it_with_real_node() {
    let node = node_or_return!();
    let ws = common::TempDir::new("we-stage");
    let out_dir = ws.0.join("world");
    let staged = run(&[
        "stage",
        "--out",
        s(&out_dir),
        "--node",
        s(&node),
        "--scenario",
        "normal",
        "--entries",
        "8",
    ]);
    assert_eq!(staged.status.code(), Some(0));
    assert_eq!(json_line(&staged)["roster"], 8);
    // The layout: flat files, the pins of every staged file, the authorized roster.
    assert_eq!(list_dir(&out_dir), ["input", "job", "pins.json", "stage"]);
    assert_eq!(
        list_dir(&out_dir.join("stage")),
        ["adapter", "candidate", "config", "engine", "scanner-0"]
    );
    assert_eq!(list_dir(&out_dir.join("input")).len(), 8);
    assert_eq!(list_dir(&out_dir.join("job")), ["job.json"]);
    let pins: Value =
        serde_json::from_slice(&std::fs::read(out_dir.join("pins.json")).unwrap()).unwrap();
    assert_eq!(pins["roster"], 8);
    for (name, pin) in pins["pins"].as_object().unwrap() {
        let bytes = std::fs::read(out_dir.join("stage").join(name)).unwrap();
        assert_eq!(pin.as_str().unwrap(), worker_support::sha(&bytes), "{name}");
    }
    // stage/engine is a copy of this very example; scanner-0 is the real runtime.
    assert_eq!(
        std::fs::read(out_dir.join("stage/engine")).unwrap(),
        std::fs::read(example()).unwrap()
    );
    assert_eq!(
        std::fs::read(out_dir.join("stage/scanner-0")).unwrap(),
        std::fs::read(&node).unwrap()
    );
    // The engine, as the sandbox starts it (here with explicit directories).
    let scratch = ws.0.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let engine = Command::new(out_dir.join("stage/engine"))
        .args(["--job", s(&out_dir.join("job/job.json"))])
        .args(["--stage", s(&out_dir.join("stage"))])
        .args(["--input", s(&out_dir.join("input"))])
        .args(["--scratch", s(&scratch)])
        .output()
        .unwrap();
    assert_eq!(engine.status.code(), Some(0), "{}", stderr(&engine));
    let stdout_file = ws.0.join("stdout");
    std::fs::write(&stdout_file, &engine.stdout).unwrap();
    let line = stderr(&engine)
        .lines()
        .find_map(|l| {
            l.strip_prefix("pii-eval-worker-e2e-aggregates ")
                .map(str::to_owned)
        })
        .expect("the aggregates line");
    let agg_file = ws.0.join("agg");
    std::fs::write(&agg_file, line).unwrap();
    let verdict = json_line(&run(&[
        "validate",
        "--dir",
        s(&out_dir),
        "--stdout",
        s(&stdout_file),
        "--exit",
        "0",
        "--aggregates",
        s(&agg_file),
    ]));
    assert_eq!(verdict["outcome"], "Success");
    assert_eq!(verdict["aggregatesOk"], true);
    assert_eq!(verdict["roster"]["expected"], 8);
    // The same bytes without --scratch writable: nothing else was written outside it.
    assert!(std::fs::read_dir(&scratch).unwrap().count() > 0);
}

#[test]
fn a_mismatch_scenario_is_refused_by_the_staged_engine_with_no_stdout() {
    let node = node_or_return!();
    let ws = common::TempDir::new("we-refusal");
    let out_dir = ws.0.join("world");
    let staged = run(&[
        "stage",
        "--out",
        s(&out_dir),
        "--node",
        s(&node),
        "--scenario",
        "wrong-tree-digest",
    ]);
    assert_eq!(staged.status.code(), Some(0));
    let scratch = ws.0.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let engine = Command::new(out_dir.join("stage/engine"))
        .args(["--job", s(&out_dir.join("job/job.json"))])
        .args(["--stage", s(&out_dir.join("stage"))])
        .args(["--input", s(&out_dir.join("input"))])
        .args(["--scratch", s(&scratch)])
        .output()
        .unwrap();
    assert_eq!(engine.status.code(), Some(4));
    assert!(engine.stdout.is_empty());
    assert!(stderr(&engine).starts_with("pii-eval: package-tree-digest-mismatch ("));
}
