//! End-to-end tests of `validate`, `compare`, usage handling and the stdout and
//! stderr contract, through the built binary and the committed synthetic
//! fixtures. No scanner and no Node are needed here.

mod cli_support;
mod common;

use std::path::{Path, PathBuf};

use cli_support::*;
use common::TempDir;
use pii_eval_contracts::{
    CorpusSnapshot, Document, RunArtifact, RunManifest, parse_default, seal, to_pretty_json,
};
use serde_json::Value;

fn legacy(name: &str) -> PathBuf {
    repo_root().join("fixtures/contracts/v1").join(name)
}

fn rev2(name: &str) -> PathBuf {
    repo_root().join("fixtures/contracts/v1/rev2").join(name)
}

/// Parse, mutate, reseal and write a document; returns the new path.
fn mutate<D: Document>(from: &Path, to: &Path, f: impl FnOnce(&mut D)) -> PathBuf {
    let mut doc: D = parse_default(&std::fs::read(from).unwrap()).unwrap();
    f(&mut doc);
    seal(&mut doc).unwrap();
    std::fs::write(to, to_pretty_json(&doc).unwrap()).unwrap();
    to.to_path_buf()
}

fn reason(v: &Value) -> &str {
    v["error"]["reason"].as_str().unwrap_or_default()
}

fn codes(v: &Value) -> Vec<String> {
    v["error"]["codes"]
        .as_array()
        .map(|a| a.iter().map(|c| c.as_str().unwrap().to_owned()).collect())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Usage, version, help, stdout and stderr
// ---------------------------------------------------------------------------

#[test]
fn version_and_help_print_one_human_block_and_exit_zero() {
    let v = run_cli(&["--version"]);
    assert_eq!(code(&v), 0);
    assert_eq!(
        String::from_utf8(v.stdout).unwrap(),
        format!("{}\n", pii_eval_cli::version_line())
    );
    let h = run_cli(&["--help"]);
    assert_eq!(code(&h), 0);
    let text = String::from_utf8(h.stdout.clone()).unwrap();
    for command in ["run", "replay", "validate", "compare"] {
        assert!(text.contains(&format!("pii-eval {command}")), "{command}");
    }
    assert!(stderr(&h).is_empty());
}

#[test]
fn usage_errors_exit_2_with_a_summary_on_stdout_and_usage_on_stderr() {
    let secret = "zq-secret-value-7731";
    let cases: Vec<(Vec<&str>, &str)> = vec![
        (vec![], "missing-command"),
        (vec!["frobnicate"], "unknown-command"),
        (vec!["run"], "missing-required-option"),
        (vec!["run", "--config"], "missing-value"),
        (
            vec!["run", "--config", "a", "--config", "b"],
            "duplicate-option",
        ),
        (
            vec!["run", "--config", "a", "--zq-secret-value-7731", "x"],
            "unknown-option",
        ),
        (
            vec!["run", "--config", "a", "zq-secret-value-7731"],
            "unexpected-argument",
        ),
        (vec!["validate"], "missing-required-option"),
        (vec!["validate", "a", "b"], "unexpected-argument"),
        (vec!["compare", "--base", "a"], "missing-required-option"),
        (
            vec!["replay", "--snapshot", "a", "--manifest", "b", "--out", "c"],
            "missing-required-option",
        ),
        (vec!["--version", "x"], "unexpected-argument"),
        (vec!["validate", "-x"], "unknown-option"),
    ];
    for (args, expected) in cases {
        let out = run_cli(&args);
        assert_eq!(code(&out), 2, "{args:?}");
        let v = summary(&out);
        assert_eq!(reason(&v), expected, "{args:?}");
        assert_eq!(v["state"], "error");
        assert_eq!(v["exit"]["name"], "usage-error");
        let err = stderr(&out);
        assert!(err.contains("usage:"), "{args:?}");
        assert!(!err.contains(secret) && !v.to_string().contains(secret));
    }
}

#[test]
fn replay_digest_and_overwrite_options_are_validated_as_usage() {
    let out = run_cli(&[
        "replay",
        "--snapshot",
        "a",
        "--manifest",
        "b",
        "--observation",
        "c",
        "--out",
        "d",
        "--overwrite",
        "sometimes",
    ]);
    assert_eq!(code(&out), 2);
    assert_eq!(reason(&summary(&out)), "invalid-option-value");
    let out = run_cli(&[
        "replay",
        "--snapshot",
        "a",
        "--manifest",
        "b",
        "--observation",
        "c",
        "--out",
        "d",
        "--expect-manifest-digest",
        "not-a-digest",
    ]);
    assert_eq!(code(&out), 2);
}

// ---------------------------------------------------------------------------
// validate
// ---------------------------------------------------------------------------

struct Expect {
    args: Vec<String>,
    exit: i32,
    state: &'static str,
    verification: &'static str,
    kind: &'static str,
    legacy: Option<bool>,
}

fn ex(
    args: &[&Path],
    exit: i32,
    state: &'static str,
    verification: &'static str,
    kind: &'static str,
    legacy: Option<bool>,
) -> Expect {
    Expect {
        args: args.iter().map(|p| s(p).to_owned()).collect(),
        exit,
        state,
        verification,
        kind,
        legacy,
    }
}

#[test]
fn validate_reports_every_committed_document_with_the_right_verification_state() {
    let snapshot = legacy("snapshot.json");
    // Revision 1 (legacy): readable, structurally valid; artifacts are not
    // verifiable. Revision 2 manifests carry no verification of their own.
    let cases = vec![
        ex(
            &[&snapshot],
            0,
            "valid",
            "not-applicable",
            "corpus-snapshot",
            None,
        ),
        ex(
            &[&legacy("manifest.json")],
            0,
            "valid",
            "not-applicable",
            "run-manifest",
            Some(true),
        ),
        ex(
            &[&legacy("observation-alpha.json")],
            0,
            "valid",
            "not-applicable",
            "observation-set",
            Some(true),
        ),
        ex(
            &[&rev2("manifest.json")],
            0,
            "valid",
            "not-applicable",
            "run-manifest",
            Some(false),
        ),
    ];
    let mut v = run_cli(&["validate", s(&legacy("run-artifact.json"))]);
    assert_eq!(
        code(&v),
        11,
        "legacy artifact is readable but not verifiable"
    );
    let summary_value = summary(&v);
    assert_eq!(summary_value["state"], "valid-legacy-not-verifiable");
    assert_eq!(
        summary_value["semantic"]["verification"],
        "not-verifiable-legacy"
    );
    assert_eq!(reason(&summary_value), "legacy-not-verifiable");
    v = run_cli(&[
        "validate",
        s(&legacy("public-synthetic-artifact.json")),
        "--snapshot",
        s(&snapshot),
    ]);
    assert_eq!(code(&v), 11);

    for case in cases {
        let args: Vec<&str> = std::iter::once("validate")
            .chain(case.args.iter().map(String::as_str))
            .collect();
        let out = run_cli(&args);
        assert_eq!(code(&out), case.exit, "{args:?}");
        let v = summary(&out);
        assert_eq!(v["state"], case.state);
        assert_eq!(v["semantic"]["verification"], case.verification);
        assert_eq!(v["semantic"]["kind"], case.kind);
        if let Some(l) = case.legacy {
            assert_eq!(v["semantic"]["protocol"]["legacy"], l, "{args:?}");
        }
    }
}

#[test]
fn validate_binds_and_verifies_revision_2_documents() {
    let snapshot = legacy("snapshot.json");
    let out = run_cli(&[
        "validate",
        s(&rev2("manifest.json")),
        "--snapshot",
        s(&snapshot),
    ]);
    assert_eq!(code(&out), 0);
    assert_eq!(summary(&out)["semantic"]["bindingsChecked"][0], "snapshot");

    let out = run_cli(&[
        "validate",
        s(&rev2("run-artifact.json")),
        "--snapshot",
        s(&snapshot),
        "--manifest",
        s(&rev2("manifest.json")),
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let v = summary(&out);
    assert_eq!(v["semantic"]["verification"], "verified");
    assert_eq!(
        v["semantic"]["bindingsChecked"],
        serde_json::json!(["manifest", "snapshot"])
    );
    assert_eq!(v["semantic"]["protocol"]["revision"], 2);

    let out = run_cli(&[
        "validate",
        s(&rev2("public-synthetic-artifact.json")),
        "--snapshot",
        s(&snapshot),
    ]);
    assert_eq!(code(&out), 0);
    assert_eq!(summary(&out)["semantic"]["verification"], "verified");

    // Without the snapshot the verifier cannot run: stated, not implied.
    let out = run_cli(&["validate", s(&rev2("run-artifact.json"))]);
    assert_eq!(code(&out), 0);
    assert_eq!(summary(&out)["semantic"]["verification"], "not-run");

    let out = run_cli(&[
        "validate",
        s(&rev2("observation-alpha-scan.json")),
        "--snapshot",
        s(&snapshot),
        "--manifest",
        s(&rev2("manifest.json")),
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
}

#[test]
fn validate_rejects_a_tampered_metric_and_a_resealed_lie() {
    let tmp = TempDir::new("validate-tamper");
    let snapshot = legacy("snapshot.json");
    // Swap the metric lists of the two scanners and reseal: structurally valid
    // (each list is a well-formed list of the ten metrics) but not what the rows
    // of either scanner say, so the verifier recomputes them and refuses it.
    let lie = mutate::<RunArtifact>(&rev2("run-artifact.json"), &tmp.0.join("lie.json"), |a| {
        let (first, second) = a.semantic.scanner_metrics.split_at_mut(1);
        std::mem::swap(&mut first[0].metrics, &mut second[0].metrics);
    });
    let out = run_cli(&["validate", s(&lie), "--snapshot", s(&snapshot)]);
    assert_eq!(code(&out), 3, "{}", String::from_utf8_lossy(&out.stdout));
    assert_eq!(reason(&summary(&out)), "verification-failed");
    // Without the snapshot the same file is structurally valid: the verifier
    // is what catches it, and the summary says it did not run.
    let out = run_cli(&["validate", s(&lie)]);
    assert_eq!(code(&out), 0);
    assert_eq!(summary(&out)["semantic"]["verification"], "not-run");
    // A hand edit without resealing is a digest mismatch.
    let edited = tmp.0.join("edited.json");
    let text = std::fs::read_to_string(rev2("run-artifact.json")).unwrap();
    std::fs::write(&edited, text.replacen("\"complete\"", "\"partial\"", 1)).unwrap();
    let out = run_cli(&["validate", s(&edited)]);
    assert_eq!(code(&out), 3);
    assert!(codes(&summary(&out)).contains(&"semantic-digest-mismatch".to_owned()));
}

#[test]
fn validate_cross_document_mismatches_are_provenance_failures() {
    let tmp = TempDir::new("validate-binding");
    let other_snapshot =
        mutate::<CorpusSnapshot>(&legacy("snapshot.json"), &tmp.0.join("other.json"), |s| {
            s.semantic.population.population_version += 1;
        });
    let out = run_cli(&[
        "validate",
        s(&rev2("manifest.json")),
        "--snapshot",
        s(&other_snapshot),
    ]);
    assert_eq!(code(&out), 4);
    let v = summary(&out);
    assert_eq!(reason(&v), "provenance-mismatch");
    assert!(codes(&v).contains(&"population-binding-mismatch".to_owned()));
    // An artifact does not bind to a manifest it was not produced from.
    let other_manifest =
        mutate::<RunManifest>(&rev2("manifest.json"), &tmp.0.join("m.json"), |m| {
            m.semantic.mechanics.replays += 1;
        });
    let out = run_cli(&[
        "validate",
        s(&rev2("run-artifact.json")),
        "--manifest",
        s(&other_manifest),
    ]);
    assert_eq!(code(&out), 4);
}

#[test]
fn validate_options_that_do_not_apply_are_usage_errors_and_kinds_are_enforced() {
    let snapshot = legacy("snapshot.json");
    let out = run_cli(&["validate", s(&snapshot), "--snapshot", s(&snapshot)]);
    assert_eq!(code(&out), 2);
    let out = run_cli(&["validate", s(&snapshot), "--kind", "run-manifest"]);
    assert_eq!(code(&out), 3);
    assert_eq!(reason(&summary(&out)), "kind-mismatch");
    let out = run_cli(&["validate", s(&snapshot), "--kind", "corpus-snapshot"]);
    assert_eq!(code(&out), 0);
    let out = run_cli(&["validate", s(&snapshot), "--kind", "nonsense"]);
    assert_eq!(code(&out), 2);
}

/// Every committed negative fixture is rejected with its documented reason code,
/// as invalid input, and never as success.
#[test]
fn every_negative_fixture_is_rejected_with_its_reason_code() {
    let dir = repo_root().join("fixtures/contracts/v1/negative");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let parts: Vec<&str> = name.trim_end_matches(".json").split("__").collect();
        assert_eq!(parts.len(), 3, "{name}");
        let out = run_cli(&["validate", s(&path), "--kind", parts[0]]);
        assert_eq!(
            code(&out),
            3,
            "{name}: {}",
            String::from_utf8_lossy(&out.stdout)
        );
        let v = summary(&out);
        assert_eq!(v["state"], "error", "{name}");
        // The fixture's name states the reason code it must produce.
        let listed = codes(&v);
        assert!(listed.contains(&parts[1].to_owned()), "{name}: {listed:?}");
        checked += 1;
    }
    assert!(checked >= 100, "{checked} negative fixtures");
}

#[test]
fn validate_never_echoes_input_text_values_keys_or_paths() {
    let tmp = TempDir::new("validate-echo");
    let marker = "ZQMARKER7731";
    let docs: Vec<(String, String)> = vec![
        (
            "unknown-field".into(),
            format!(
                r#"{{"schema":"pii-eval.corpus-snapshot","schemaVersion":"1.0","{marker}":1}}"#
            ),
        ),
        (
            "duplicate-key".into(),
            format!(r#"{{"schema":"pii-eval.corpus-snapshot","{marker}":1,"{marker}":2}}"#),
        ),
        (
            "bad-value".into(),
            format!(r#"{{"schema":"{marker}","schemaVersion":"1.0"}}"#),
        ),
        (
            "bad-version".into(),
            format!(r#"{{"schema":"pii-eval.corpus-snapshot","schemaVersion":"{marker}"}}"#),
        ),
        ("not-json".into(), format!("{marker} not json")),
        (
            "float".into(),
            format!(r#"{{"schema":"pii-eval.corpus-snapshot","{marker}":1.5}}"#),
        ),
        (
            "null".into(),
            format!(r#"{{"schema":"pii-eval.corpus-snapshot","{marker}":null}}"#),
        ),
    ];
    for (name, text) in docs {
        let path = tmp.0.join(format!("{marker}-{name}.json"));
        std::fs::write(&path, text).unwrap();
        let out = run_cli(&["validate", s(&path)]);
        assert_eq!(code(&out), 3, "{name}");
        let all = format!("{}{}", String::from_utf8_lossy(&out.stdout), stderr(&out));
        assert!(!all.contains(marker), "{name} echoed input text: {all}");
    }
    // A missing file's name is not echoed either.
    let missing = tmp.0.join(format!("{marker}-missing.json"));
    let out = run_cli(&["validate", s(&missing)]);
    assert_eq!(code(&out), 3);
    assert_eq!(reason(&summary(&out)), "input-unreadable");
    let all = format!("{}{}", String::from_utf8_lossy(&out.stdout), stderr(&out));
    assert!(!all.contains(marker));
}

#[test]
fn oversized_and_non_regular_inputs_are_refused_without_reading_them() {
    let tmp = TempDir::new("validate-size");
    let big = tmp.0.join("big.json");
    let file = std::fs::File::create(&big).unwrap();
    file.set_len(33 * 1024 * 1024).unwrap();
    let out = run_cli(&["validate", s(&big)]);
    assert_eq!(code(&out), 3);
    assert_eq!(reason(&summary(&out)), "input-too-large");
    let out = run_cli(&["validate", s(&tmp.0)]);
    assert_eq!(code(&out), 3);
    assert_eq!(reason(&summary(&out)), "input-unreadable");
}

// ---------------------------------------------------------------------------
// compare
// ---------------------------------------------------------------------------

#[test]
fn comparing_an_artifact_with_itself_reports_identical_states_and_no_ranking() {
    let a = rev2("run-artifact.json");
    let out = run_cli(&["compare", "--base", s(&a), "--other", s(&a)]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let v = summary(&out);
    assert_eq!(v["state"], "compared");
    let sem = &v["semantic"];
    assert_eq!(sem["interpretation"], "descriptive-only");
    assert_eq!(sem["pairing"], "by-id");
    assert_eq!(sem["refusals"], serde_json::json!([]));
    let scanners = sem["scanners"].as_array().unwrap();
    assert_eq!(scanners.len(), 2);
    for sc in scanners {
        assert_eq!(sc["identityChanges"], serde_json::json!({}));
        for m in sc["metrics"].as_array().unwrap() {
            let rel = m["relation"].as_str().unwrap();
            assert!(["identical", "withheld-in-both"].contains(&rel), "{rel}");
        }
        assert_eq!(sc["metrics"].as_array().unwrap().len(), 10);
    }
    // No field of the output ranks or scores anything.
    let text = v.to_string();
    for banned in ["better", "worse", "winner", "rank", "score"] {
        assert!(!text.contains(banned), "{banned}");
    }
}

#[test]
fn comparison_reports_identity_changes_and_withheld_states_per_scanner_and_metric() {
    let tmp = TempDir::new("compare-subject");
    // The same population, the same protocol: only the scanner's identity and
    // metric state differ (the subject of the comparison).
    let changed = mutate::<RunArtifact>(&rev2("run-artifact.json"), &tmp.0.join("b.json"), |a| {
        a.semantic.scanners[0].identity.scanner_version =
            Some(pii_eval_contracts::VersionString::new("9.9.9").unwrap());
    });
    let out = run_cli(&[
        "compare",
        "--base",
        s(&rev2("run-artifact.json")),
        "--other",
        s(&changed),
    ]);
    assert_eq!(code(&out), 0, "{}", String::from_utf8_lossy(&out.stdout));
    let v = summary(&out);
    let first = &v["semantic"]["scanners"][0];
    assert_eq!(first["identityChanges"]["scannerVersion"]["other"], "9.9.9");
    assert!(first["identityChanges"]["scannerVersion"]["base"].is_string());
    assert_eq!(
        v["semantic"]["subject"]["artifactDigest"]["base"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert_ne!(
        v["semantic"]["subject"]["artifactDigest"]["base"],
        v["semantic"]["subject"]["artifactDigest"]["other"]
    );
    // Every metric entry carries both sides' states, withheld ones included.
    let metrics = first["metrics"].as_array().unwrap();
    assert!(metrics.iter().any(|m| m["relation"] == "withheld-in-both"));
}

#[test]
fn comparison_refuses_different_populations_protocols_kinds_and_legacy_artifacts() {
    let tmp = TempDir::new("compare-refuse");
    let base = rev2("run-artifact.json");
    let other_population = mutate::<RunArtifact>(&base, &tmp.0.join("p.json"), |a| {
        a.semantic.population.population_version += 1;
    });
    let out = run_cli(&[
        "compare",
        "--base",
        s(&base),
        "--other",
        s(&other_population),
    ]);
    assert_eq!(code(&out), 10);
    let v = summary(&out);
    assert_eq!(v["state"], "incomparable");
    assert_eq!(reason(&v), "incomparable");
    assert!(
        v["semantic"]["refusals"]
            .as_array()
            .unwrap()
            .contains(&"population-differs".into())
    );

    let other_mechanics = mutate::<RunArtifact>(&base, &tmp.0.join("m.json"), |a| {
        a.semantic.mechanics.replays += 1;
    });
    let out = run_cli(&[
        "compare",
        "--base",
        s(&base),
        "--other",
        s(&other_mechanics),
    ]);
    assert_eq!(code(&out), 10);
    assert!(
        summary(&out)["semantic"]["refusals"]
            .as_array()
            .unwrap()
            .contains(&"mechanics-differs".into())
    );

    let public = rev2("public-synthetic-artifact.json");
    let out = run_cli(&["compare", "--base", s(&base), "--other", s(&public)]);
    assert_eq!(code(&out), 10);
    assert!(
        summary(&out)["semantic"]["refusals"]
            .as_array()
            .unwrap()
            .contains(&"artifact-kinds-differ".into())
    );

    let out = run_cli(&[
        "compare",
        "--base",
        s(&base),
        "--other",
        s(&legacy("run-artifact.json")),
    ]);
    assert_eq!(code(&out), 10);
    let refusals = summary(&out)["semantic"]["refusals"].clone();
    assert!(
        refusals
            .as_array()
            .unwrap()
            .contains(&"legacy-protocol-revision".into())
    );
    assert!(
        refusals
            .as_array()
            .unwrap()
            .contains(&"protocol-differs".into())
    );
}

#[test]
fn comparing_public_projections_works_and_non_artifacts_are_invalid_input() {
    let p = rev2("public-synthetic-artifact.json");
    let out = run_cli(&["compare", "--base", s(&p), "--other", s(&p)]);
    assert_eq!(code(&out), 0);
    assert_eq!(
        summary(&out)["semantic"]["kind"],
        "public-synthetic-artifact"
    );
    let out = run_cli(&[
        "compare",
        "--base",
        s(&legacy("snapshot.json")),
        "--other",
        s(&p),
    ]);
    assert_eq!(code(&out), 3);
    assert_eq!(reason(&summary(&out)), "kind-mismatch");
    let out = run_cli(&["compare", "--base", "/nonexistent/x.json", "--other", s(&p)]);
    assert_eq!(code(&out), 3);
}
