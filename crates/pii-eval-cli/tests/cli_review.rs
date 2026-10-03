//! Review follow-ups (PR #21): argument and stdout handling, replay divergence,
//! fault-injected output failures, the review gate in the verifier, protected
//! documents in `validate`, `compare` and `replay`, and `compare` verification.
//! No Node needed. Synthetic only.

mod cli_support;
mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use cli_support::{code, run_cli, run_cli_env, s, stderr, summary};
use common::TempDir;
use pii_eval_cli::exec::{CancelToken, ExecutorConfig, ResourcePolicy};
use pii_eval_cli::run::{RunConfig, RunRequest, run_and_write};
use pii_eval_cli::write::{ArtifactWriter, OverwritePolicy};
use pii_eval_contracts::{
    CorpusSnapshot, Id, OperatorRef, RunArtifact, RunClass, RunManifest, Strategy, TypeState,
    Visibility, parse_default, seal, to_pretty_json,
};
use serde_json::Value;

fn repo() -> PathBuf {
    cli_support::repo_root()
}

fn rev2(name: &str) -> PathBuf {
    repo().join("fixtures/contracts/v1/rev2").join(name)
}

fn legacy_snapshot() -> PathBuf {
    repo().join("fixtures/contracts/v1/snapshot.json")
}

fn reason(v: &Value) -> &str {
    v["error"]["reason"].as_str().unwrap_or_default()
}

// ---------------------------------------------------------------------------
// M1, M6: arguments and stdout
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn a_non_utf8_argument_is_a_usage_error_with_one_summary_line() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    let bad = OsString::from_vec(b"\xff.json".to_vec());
    for args in [
        vec![OsString::from("validate"), bad.clone()],
        vec![bad.clone()],
        vec![OsString::from("run"), OsString::from("--config"), bad],
    ] {
        let out = Command::new(cli_support::bin())
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(code(&out), 2, "exit 2, not a panic status");
        let v = summary(&out);
        assert_eq!(reason(&v), "invalid-option-value");
        assert!(stderr(&out).contains("usage:"));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn a_stdout_write_error_other_than_a_closed_pipe_is_an_output_failure() {
    // /dev/full accepts the open and fails every write with ENOSPC.
    let full = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();
    let out = Command::new(cli_support::bin())
        .arg("--version")
        .stdout(full)
        .output()
        .unwrap();
    assert_eq!(code(&out), 7);
    assert!(stderr(&out).contains("output-write-failed"));
}

#[cfg(unix)]
#[test]
fn a_closed_stdout_pipe_is_not_a_failure_of_the_command() {
    // The reader goes away before the summary is written: the command's own
    // status stands (here: success of `--version`).
    let mut child = Command::new(cli_support::bin())
        .args([
            "validate",
            s(&cli_support::example_dir().join("snapshot.json")),
        ])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let status = child.wait().unwrap();
    assert!(matches!(status.code(), Some(0)), "{status:?}");
}

// ---------------------------------------------------------------------------
// M2a: replay-diverged
// ---------------------------------------------------------------------------

fn replay_args<'a>(
    out: &'a Path,
    manifest: &'a Path,
    original: &'a Path,
    obs: [&'a Path; 2],
    snapshot: &'a Path,
) -> Vec<String> {
    let mut a = vec![
        "replay".to_owned(),
        "--snapshot".into(),
        s(snapshot).into(),
        "--manifest".into(),
        s(manifest).into(),
        "--original".into(),
        s(original).into(),
        "--out".into(),
        s(out).into(),
    ];
    for o in obs {
        a.push("--observation".into());
        a.push(s(o).into());
    }
    a
}

#[test]
fn a_resealed_original_with_the_same_bindings_but_another_body_is_replay_diverged() {
    let tmp = TempDir::new("review-diverged");
    // Same manifest, same observations, valid verified artifact, but a row's
    // observed summary differs: it binds and verifies, and the replay cannot
    // reproduce it.
    let mut original: RunArtifact =
        parse_default(&std::fs::read(rev2("run-artifact.json")).unwrap()).unwrap();
    original.semantic.outcomes[0].observed.finding_count += 1;
    seal(&mut original).unwrap();
    let path = tmp.0.join("forged-original.json");
    std::fs::write(&path, to_pretty_json(&original).unwrap()).unwrap();
    // The forgery is itself a valid, verifiable artifact.
    let check = run_cli(&[
        "validate",
        s(&path),
        "--snapshot",
        s(&legacy_snapshot()),
        "--manifest",
        s(&rev2("manifest.json")),
    ]);
    assert_eq!(
        code(&check),
        0,
        "{}",
        String::from_utf8_lossy(&check.stdout)
    );
    let out = tmp.0.join("out");
    let args = replay_args(
        &out,
        &rev2("manifest.json"),
        &path,
        [
            &rev2("observation-alpha-scan.json"),
            &rev2("observation-beta-scan.json"),
        ],
        &legacy_snapshot(),
    );
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = run_cli(&refs);
    assert_eq!(code(&result), 4);
    let v = summary(&result);
    assert_eq!(reason(&v), "replay-diverged");
    assert_eq!(v["error"]["detail"], "run-artifact");
    assert!(!out.exists(), "nothing was written");
}

#[test]
fn replay_states_what_was_recomputed_and_what_was_carried_from_the_original() {
    let tmp = TempDir::new("review-carried");
    let args = replay_args(
        &tmp.0.join("out"),
        &rev2("manifest.json"),
        &rev2("run-artifact.json"),
        [
            &rev2("observation-alpha-scan.json"),
            &rev2("observation-beta-scan.json"),
        ],
        &legacy_snapshot(),
    );
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let v = summary(&run_cli(&refs));
    let verification = &v["semantic"]["verification"];
    assert_eq!(
        verification["carriedFromOriginal"],
        serde_json::json!(["output-verdicts", "failure-codes"])
    );
    assert!(
        verification["recomputed"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x == "matching")
    );
}

// ---------------------------------------------------------------------------
// M2b: fault-injected output failures (debug builds only)
// ---------------------------------------------------------------------------

fn faulted_replay(fault: &str, out: &Path) -> std::process::Output {
    let args = replay_args(
        out,
        &rev2("manifest.json"),
        &rev2("run-artifact.json"),
        [
            &rev2("observation-alpha-scan.json"),
            &rev2("observation-beta-scan.json"),
        ],
        &legacy_snapshot(),
    );
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_cli_env(&refs, &[("PII_EVAL_TEST_FAULT", fault)])
}

#[test]
fn an_io_error_while_writing_is_output_write_failed_and_leaves_nothing() {
    let tmp = TempDir::new("review-write-io");
    let out = tmp.0.join("out");
    let result = faulted_replay("write-io", &out);
    assert_eq!(code(&result), 7);
    assert_eq!(reason(&summary(&result)), "output-write-failed");
    // Temporaries were removed and the directory created for the run is gone.
    assert!(!out.exists(), "{:?}", cli_support::list_dir(&out));
}

#[test]
fn a_commit_that_cannot_be_confirmed_durable_is_its_own_state_with_the_files_in_place() {
    let tmp = TempDir::new("review-not-durable");
    let out = tmp.0.join("out");
    let result = faulted_replay("not-durable", &out);
    assert_eq!(code(&result), 7);
    assert_eq!(reason(&summary(&result)), "output-committed-not-durable");
    assert!(
        out.join("run-artifact.json").is_file(),
        "complete and valid"
    );
}

#[cfg(unix)]
#[test]
fn a_rollback_that_cannot_remove_what_was_renamed_is_output_partial() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = TempDir::new("review-partial");
    let out = tmp.0.join("out");
    let result = faulted_replay("partial", &out);
    let writable_anyway = std::fs::write(out.join(".probe"), b"").is_ok();
    let _ = std::fs::remove_file(out.join(".probe"));
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(code(&result), 7);
    if writable_anyway {
        // Running as a user the permission bits do not bind: the rollback worked.
        assert_eq!(reason(&summary(&result)), "output-write-failed");
    } else {
        assert_eq!(reason(&summary(&result)), "output-partial");
        assert!(
            !out.join("run-artifact.json").exists(),
            "never the commit marker"
        );
        assert!(out.join("manifest.json").exists());
    }
}

#[test]
fn unusable_output_locations_are_named_by_reason() {
    let tmp = TempDir::new("review-unusable");
    let file = tmp.0.join("file");
    std::fs::write(&file, b"x").unwrap();
    let args = replay_args(
        &file,
        &rev2("manifest.json"),
        &rev2("run-artifact.json"),
        [
            &rev2("observation-alpha-scan.json"),
            &rev2("observation-beta-scan.json"),
        ],
        &legacy_snapshot(),
    );
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let v = summary(&run_cli(&refs));
    assert_eq!(reason(&v), "output-unusable");
}

#[test]
fn replay_incomplete_observations_is_a_library_state_no_validated_input_reaches() {
    // A complete observation set that names a variant the snapshot does not
    // contain is rejected by validation before replay builds anything, so the
    // reason is unreachable through the binary (ADR 0010 C13); the library
    // function still fails closed.
    let snapshot: CorpusSnapshot =
        parse_default(&std::fs::read(legacy_snapshot()).unwrap()).unwrap();
    let manifest: RunManifest =
        parse_default(&std::fs::read(rev2("manifest.json")).unwrap()).unwrap();
    let mut set: pii_eval_contracts::ObservationSet =
        parse_default(&std::fs::read(rev2("observation-alpha-scan.json")).unwrap()).unwrap();
    set.semantic.inputs[0].variant_id = Id::new("not-in-the-snapshot").unwrap();
    let beta: pii_eval_contracts::ObservationSet =
        parse_default(&std::fs::read(rev2("observation-beta-scan.json")).unwrap()).unwrap();
    let err =
        pii_eval_cli::replay::runs_from_observations(&snapshot, &manifest, &[set, beta], None)
            .unwrap_err();
    assert_eq!(err.reason, "replay-incomplete-observations");
}

// ---------------------------------------------------------------------------
// m3: the verifier re-applies the review gate
// ---------------------------------------------------------------------------

#[test]
fn a_held_variant_scored_as_a_clean_type_pass_is_not_verified() {
    let tmp = TempDir::new("review-gate-verify");
    let mut snapshot: CorpusSnapshot =
        parse_default(&std::fs::read(legacy_snapshot()).unwrap()).unwrap();
    let held = {
        let v = &mut snapshot.semantic.cases[0].variants[0];
        v.derivation.strategy = Strategy::ReviewRequired;
        v.derivation.operator = Some(OperatorRef {
            id: Id::new("synthetic-operator").unwrap(),
            version: 1,
        });
        v.variant_id.clone()
    };
    seal(&mut snapshot).unwrap();
    let adapter = common::FakeAdapter::new("alpha-scan", 5);
    let manifest = common::manifest(
        &snapshot,
        vec![adapter.plan.clone()],
        common::limits(2, 1, 1, 4),
        common::mechanics(2),
    );
    let dir = tmp.0.join("run");
    run_and_write(
        &RunRequest {
            snapshot: &snapshot,
            manifest: &manifest,
            adapters: vec![Arc::new(adapter) as Arc<dyn pii_eval_adapters::ScannerAdapter>],
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
        &ArtifactWriter::new(&dir, OverwritePolicy::Refuse).with_manifest(),
    )
    .unwrap();
    let snap_path = tmp.0.join("snapshot.json");
    std::fs::write(&snap_path, to_pretty_json(&snapshot).unwrap()).unwrap();
    let honest = run_cli(&[
        "validate",
        s(&dir.join("run-artifact.json")),
        "--snapshot",
        s(&snap_path),
    ]);
    assert_eq!(code(&honest), 0);
    // Score the held variant as a clean type pass and reseal.
    let forged = tmp.0.join("forged.json");
    let mut artifact: RunArtifact =
        parse_default(&std::fs::read(dir.join("run-artifact.json")).unwrap()).unwrap();
    for row in artifact
        .semantic
        .outcomes
        .iter_mut()
        .filter(|r| r.variant_id == held)
    {
        row.type_identity = TypeState::Correct;
    }
    seal(&mut artifact).unwrap();
    std::fs::write(&forged, to_pretty_json(&artifact).unwrap()).unwrap();
    let result = run_cli(&["validate", s(&forged), "--snapshot", s(&snap_path)]);
    assert_eq!(
        code(&result),
        3,
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    let v = summary(&result);
    assert_eq!(reason(&v), "verification-failed");
    assert!(
        v["error"]["codes"]
            .to_string()
            .contains("outcome-contradiction"),
        "{v}"
    );
}

// ---------------------------------------------------------------------------
// m9: compare says whether it verified
// ---------------------------------------------------------------------------

#[test]
fn compare_states_that_it_did_not_verify_and_can_verify_against_a_snapshot() {
    let tmp = TempDir::new("review-compare-verify");
    let base = rev2("run-artifact.json");
    let plain = run_cli(&["compare", "--base", s(&base), "--other", s(&base)]);
    assert_eq!(code(&plain), 0);
    assert_eq!(
        summary(&plain)["semantic"]["verification"],
        serde_json::json!({"base": "not-run", "other": "not-run"})
    );
    // Fabricated metrics (the two scanners' lists swapped, resealed) read as
    // identical to themselves without verification, and are refused with it.
    let mut lie: RunArtifact = parse_default(&std::fs::read(&base).unwrap()).unwrap();
    let (a, b) = lie.semantic.scanner_metrics.split_at_mut(1);
    std::mem::swap(&mut a[0].metrics, &mut b[0].metrics);
    seal(&mut lie).unwrap();
    let lie_path = tmp.0.join("lie.json");
    std::fs::write(&lie_path, to_pretty_json(&lie).unwrap()).unwrap();
    let unverified = run_cli(&["compare", "--base", s(&lie_path), "--other", s(&lie_path)]);
    assert_eq!(code(&unverified), 0);
    assert_eq!(
        summary(&unverified)["semantic"]["verification"]["base"],
        "not-run"
    );
    let verified = run_cli(&[
        "compare",
        "--base",
        s(&lie_path),
        "--other",
        s(&lie_path),
        "--snapshot",
        s(&legacy_snapshot()),
    ]);
    assert_eq!(code(&verified), 3);
    assert_eq!(reason(&summary(&verified)), "verification-failed");
    let honest = run_cli(&[
        "compare",
        "--base",
        s(&base),
        "--other",
        s(&base),
        "--snapshot",
        s(&legacy_snapshot()),
    ]);
    assert_eq!(
        code(&honest),
        0,
        "{}",
        String::from_utf8_lossy(&honest.stdout)
    );
    assert_eq!(
        summary(&honest)["semantic"]["verification"],
        serde_json::json!({"base": "verified", "other": "verified"})
    );
}

// ---------------------------------------------------------------------------
// m8: protected documents outside `run`
// ---------------------------------------------------------------------------

struct Protected {
    tmp: TempDir,
    inside: PathBuf,
    snapshot: PathBuf,
    manifest: PathBuf,
    run_dir: PathBuf,
    job: PathBuf,
}

fn protected() -> Protected {
    use std::os::unix::fs::PermissionsExt;
    let tmp = TempDir::new("review-protected");
    let inside = tmp.0.join("custodian-in");
    let outside_out = tmp.0.join("custodian-out");
    std::fs::create_dir_all(&inside).unwrap();
    std::fs::create_dir_all(&outside_out).unwrap();
    let mut snapshot: CorpusSnapshot =
        parse_default(&std::fs::read(legacy_snapshot()).unwrap()).unwrap();
    snapshot.semantic.population.visibility = Visibility::Protected;
    seal(&mut snapshot).unwrap();
    let adapter = common::FakeAdapter::new("alpha-scan", 5);
    let mut manifest = common::manifest(
        &snapshot,
        vec![adapter.plan.clone()],
        common::limits(2, 1, 1, 4),
        common::mechanics(2),
    );
    manifest.semantic.run_class = RunClass::Protected;
    seal(&mut manifest).unwrap();
    let run_dir = inside.join("run");
    run_and_write(
        &RunRequest {
            snapshot: &snapshot,
            manifest: &manifest,
            adapters: vec![Arc::new(adapter) as Arc<dyn pii_eval_adapters::ScannerAdapter>],
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
        &ArtifactWriter::new(&run_dir, OverwritePolicy::Refuse).with_manifest(),
    )
    .unwrap();
    let snap_path = inside.join("snapshot.json");
    std::fs::write(&snap_path, to_pretty_json(&snapshot).unwrap()).unwrap();
    let man_path = inside.join("manifest.json");
    std::fs::write(&man_path, to_pretty_json(&manifest).unwrap()).unwrap();
    let digest = "0".repeat(64);
    let job = tmp.0.join("job.json");
    std::fs::write(
        &job,
        format!(
            r#"{{"schema":"pii-eval-job-context/1","jobId":"job-0001","custodian":"synthetic","runClass":"protected","populationDigest":"{digest}","manifestDigest":"{digest}","inputRoot":"{}","outputRoot":"{}"}}"#,
            s(&std::fs::canonicalize(&inside).unwrap()),
            s(&std::fs::canonicalize(&outside_out).unwrap()),
        ),
    )
    .unwrap();
    std::fs::set_permissions(&job, std::fs::Permissions::from_mode(0o600)).unwrap();
    Protected {
        tmp,
        inside,
        snapshot: snap_path,
        manifest: man_path,
        run_dir,
        job,
    }
}

#[cfg(unix)]
#[test]
fn validate_compare_and_replay_of_protected_documents_need_the_job_context_and_withhold_counts() {
    let p = protected();
    let artifact = p.run_dir.join("run-artifact.json");
    // Without a context: refused with the distinct protected-context status.
    for args in [
        vec!["validate", s(&p.snapshot)],
        vec!["validate", s(&p.manifest)],
        vec!["validate", s(&artifact)],
        vec!["compare", "--base", s(&artifact), "--other", s(&artifact)],
    ] {
        let out = run_cli(&args);
        assert_eq!(code(&out), 9, "{args:?}");
        assert_eq!(reason(&summary(&out)), "protected-context-required");
    }
    let obs = p.run_dir.join("observation-alpha-scan.json");
    let replay_out = p.tmp.0.join("custodian-out/replay");
    let replay = |extra: &[&str]| {
        let mut args = vec![
            "replay",
            "--snapshot",
            s(&p.snapshot),
            "--manifest",
            s(&p.manifest),
            "--observation",
            s(&obs),
            "--original",
            s(&artifact),
            "--out",
            s(&replay_out),
        ];
        args.extend_from_slice(extra);
        run_cli(&args)
    };
    assert_eq!(code(&replay(&[])), 9);
    // With the context: allowed, and the counts are withheld.
    let ok = run_cli(&["validate", s(&p.snapshot), "--job-context", s(&p.job)]);
    assert_eq!(code(&ok), 0, "{}", stderr(&ok));
    let v = summary(&ok);
    assert_eq!(v["semantic"]["visibility"], "protected");
    assert!(v["semantic"].get("cases").is_none() && v["semantic"].get("variants").is_none());
    assert_eq!(
        code(&run_cli(&[
            "validate",
            s(&artifact),
            "--job-context",
            s(&p.job)
        ])),
        0
    );
    let compared = run_cli(&[
        "compare",
        "--base",
        s(&artifact),
        "--other",
        s(&artifact),
        "--job-context",
        s(&p.job),
    ]);
    assert_eq!(code(&compared), 0, "{}", stderr(&compared));
    for m in summary(&compared)["semantic"]["scanners"][0]["metrics"]
        .as_array()
        .unwrap()
    {
        assert!(m["base"].get("counts").is_none() && m["base"].get("effectiveN").is_none());
        // Decided on the full results: still identical.
        assert_eq!(m["identical"], true);
    }
    // The replay's output must be inside the output root; the run directory is not.
    let bad = run_cli(&[
        "replay",
        "--snapshot",
        s(&p.snapshot),
        "--manifest",
        s(&p.manifest),
        "--observation",
        s(&obs),
        "--original",
        s(&artifact),
        "--out",
        s(&p.tmp.0.join("elsewhere")),
        "--job-context",
        s(&p.job),
    ]);
    assert_eq!(code(&bad), 9);
    assert_eq!(summary(&bad)["error"]["detail"], "output");
    let good = replay(&["--job-context", s(&p.job)]);
    assert_eq!(code(&good), 0, "{}", stderr(&good));
}

#[cfg(unix)]
#[test]
fn a_symlink_or_dotdot_that_leaves_the_input_root_is_outside() {
    let p = protected();
    let outside = p.tmp.0.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::copy(&p.snapshot, outside.join("snapshot.json")).unwrap();
    // A symlink inside the root that points out of it.
    let link = p.inside.join("escape");
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    let via_link = link.join("snapshot.json");
    let out = run_cli(&["validate", s(&via_link), "--job-context", s(&p.job)]);
    assert_eq!(code(&out), 9);
    assert_eq!(reason(&summary(&out)), "protected-path-outside-context");
    // A path that starts inside and climbs out with `..`.
    let dotdot = p.inside.join("../outside/snapshot.json");
    let out = run_cli(&["validate", s(&dotdot), "--job-context", s(&p.job)]);
    assert_eq!(code(&out), 9);
    assert_eq!(reason(&summary(&out)), "protected-path-outside-context");
    // The same file addressed inside the root is fine.
    let ok = run_cli(&["validate", s(&p.snapshot), "--job-context", s(&p.job)]);
    assert_eq!(code(&ok), 0);
}
