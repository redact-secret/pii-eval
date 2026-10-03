//! End-to-end tests of `replay` over the committed revision-2 goldens. No
//! scanner exists on this path and none is launched: the tests run with no
//! `node` and no scanner package reachable, with a decoy `node` on `PATH` that
//! records its own execution, and a source guard forbids process APIs in the
//! replay modules. Synthetic only.

mod cli_support;
mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use cli_support::*;
use common::TempDir;
use pii_eval_contracts::{
    ObservationSet, RunArtifact, RunManifest, ScannerStatus, Sha256Digest, parse_default, seal,
    to_pretty_json,
};
use serde_json::Value;

fn legacy_snapshot() -> PathBuf {
    repo_root().join("fixtures/contracts/v1/snapshot.json")
}

fn rev2(name: &str) -> PathBuf {
    repo_root().join("fixtures/contracts/v1/rev2").join(name)
}

struct Replay<'a> {
    snapshot: PathBuf,
    manifest: PathBuf,
    observations: Vec<PathBuf>,
    original: Option<PathBuf>,
    out: &'a Path,
    extra: Vec<String>,
}

impl<'a> Replay<'a> {
    fn golden(out: &'a Path) -> Self {
        Replay {
            snapshot: legacy_snapshot(),
            manifest: rev2("manifest.json"),
            observations: vec![
                rev2("observation-alpha-scan.json"),
                rev2("observation-beta-scan.json"),
            ],
            original: Some(rev2("run-artifact.json")),
            out,
            extra: Vec::new(),
        }
    }

    fn args(&self) -> Vec<String> {
        let mut a = vec![
            "replay".to_owned(),
            "--snapshot".into(),
            s(&self.snapshot).into(),
            "--manifest".into(),
            s(&self.manifest).into(),
            "--out".into(),
            s(self.out).into(),
        ];
        for o in &self.observations {
            a.push("--observation".into());
            a.push(s(o).into());
        }
        if let Some(o) = &self.original {
            a.push("--original".into());
            a.push(s(o).into());
        }
        a.extend(self.extra.clone());
        a
    }

    fn run(&self) -> std::process::Output {
        let args = self.args();
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        run_cli(&refs)
    }
}

fn reason(v: &Value) -> &str {
    v["error"]["reason"].as_str().unwrap_or_default()
}

const FILES: [&str; 5] = [
    "manifest.json",
    "observation-alpha-scan.json",
    "observation-beta-scan.json",
    "public-synthetic-artifact.json",
    "run-artifact.json",
];

#[test]
fn replay_reproduces_the_committed_run_byte_for_byte_and_reports_parity() {
    let tmp = TempDir::new("replay-golden");
    let out = tmp.0.join("out");
    let result = Replay::golden(&out).run();
    // The golden run had an unsupported scanner: the replay says so (exit 5)
    // instead of reporting a clean success.
    assert_eq!(code(&result), 5, "{}", stderr(&result));
    let v = summary(&result);
    assert_eq!(v["state"], "incomplete");
    assert_eq!(v["semantic"]["parity"], "identical");
    assert_eq!(v["semantic"]["scannersLaunched"], 0);
    for name in FILES {
        assert_eq!(
            std::fs::read(out.join(name)).unwrap(),
            std::fs::read(rev2(name)).unwrap(),
            "{name}"
        );
    }
    // The semantic digests equal the original's.
    let original: RunArtifact =
        parse_default(&std::fs::read(rev2("run-artifact.json")).unwrap()).unwrap();
    assert_eq!(
        v["semantic"]["runArtifactDigest"].as_str().unwrap(),
        original.semantic_digest.as_str()
    );
    let statuses: Vec<&str> = v["semantic"]["scanners"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["status"].as_str().unwrap())
        .collect();
    assert_eq!(statuses, ["complete", "unsupported"]);
    // Files are private.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for name in FILES {
            let mode = std::fs::metadata(out.join(name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{name}");
        }
    }
}

#[test]
fn replay_is_deterministic_across_runs_and_input_order() {
    let tmp = TempDir::new("replay-determinism");
    let (a, b) = (tmp.0.join("a"), tmp.0.join("b"));
    let first = Replay::golden(&a).run();
    let mut reversed = Replay::golden(&b);
    reversed.observations.reverse();
    let second = reversed.run();
    assert_eq!(first.stdout, second.stdout, "summaries are byte-identical");
    for name in FILES {
        assert_eq!(
            std::fs::read(a.join(name)).unwrap(),
            std::fs::read(b.join(name)).unwrap(),
            "{name}"
        );
    }
}

#[test]
fn replay_launches_no_scanner_and_needs_no_node() {
    let tmp = TempDir::new("replay-no-process");
    // A decoy `node` that records that it was executed; the replay's PATH holds
    // nothing else. The scanner package and shim paths named by the manifest's
    // identities do not exist anywhere in this scratch tree.
    let bin_dir = tmp.0.join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let marker = tmp.0.join("node-was-executed");
    let decoy = bin_dir.join("node");
    std::fs::write(&decoy, format!("#!/bin/sh\ntouch '{}'\n", marker.display())).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&decoy, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let out = tmp.0.join("out");
    let replay = Replay::golden(&out);
    let args = replay.args();
    let result = Command::new(bin())
        .args(&args)
        .env_clear()
        .env("PATH", &bin_dir)
        .output()
        .unwrap();
    assert_eq!(code(&result), 5, "{}", stderr(&result));
    assert!(!marker.exists(), "no process named node was started");
    assert_eq!(summary(&result)["semantic"]["parity"], "identical");
}

#[test]
fn replay_modules_use_no_process_or_adapter_api() {
    // The source guard behind the behavioural test above: the modules that
    // implement replay do not even name the process or adapter APIs.
    for file in ["src/cmd_replay.rs", "src/replay.rs"] {
        let text =
            std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(file)).unwrap();
        // Strip comments: documentation may state what is not done.
        let code: String = text
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for banned in [
            "std::process",
            "Command::new",
            "pii_eval_adapters",
            "ScannerAdapter",
            "ScanSession",
            ".start(",
            "spawn(",
        ] {
            assert!(!code.contains(banned), "{file} mentions {banned}");
        }
    }
}

#[test]
fn replay_requires_the_original_when_it_cannot_know_failures_or_output_verdicts() {
    let tmp = TempDir::new("replay-original");
    let out = tmp.0.join("out");
    let mut replay = Replay::golden(&out);
    replay.original = None;
    let result = replay.run();
    assert_eq!(code(&result), 3);
    assert_eq!(reason(&summary(&result)), "replay-original-required");
    assert!(!out.exists(), "nothing was created");
}

#[test]
fn replay_rejects_changed_inputs_settings_and_identities() {
    let tmp = TempDir::new("replay-reject");
    let t = &tmp.0;
    let out = t.join("out");

    // 1. A changed observation (edited, not resealed): digest mismatch, invalid input.
    let alpha = std::fs::read_to_string(rev2("observation-alpha-scan.json")).unwrap();
    let edited = t.join("edited.json");
    std::fs::write(&edited, alpha.replacen("\"replays\"", "\"replaysX\"", 1)).unwrap();
    let mut r = Replay::golden(&out);
    r.observations[0] = edited;
    let result = r.run();
    assert_eq!(code(&result), 3);
    assert_eq!(reason(&summary(&result)), "document-invalid");

    // 2. A changed input digest (resealed): the observation no longer binds to
    // the snapshot's inputs.
    let moved = t.join("moved.json");
    let mut obs: ObservationSet = parse_default(alpha.as_bytes()).unwrap();
    obs.semantic.inputs[0].input_digest = Sha256Digest::of_bytes(b"another input");
    seal(&mut obs).unwrap();
    std::fs::write(&moved, to_pretty_json(&obs).unwrap()).unwrap();
    let mut r = Replay::golden(&out);
    r.observations[0] = moved;
    let result = r.run();
    assert_eq!(code(&result), 4);
    assert_eq!(reason(&summary(&result)), "provenance-mismatch");
    assert!(!out.exists());

    // 3. A changed scanner identity (resealed observation): not the plan's scanner.
    let renamed = t.join("renamed.json");
    let mut obs: ObservationSet = parse_default(alpha.as_bytes()).unwrap();
    obs.semantic.scanner.scanner_version =
        Some(pii_eval_contracts::VersionString::new("9.9.9").unwrap());
    seal(&mut obs).unwrap();
    std::fs::write(&renamed, to_pretty_json(&obs).unwrap()).unwrap();
    let mut r = Replay::golden(&out);
    r.observations[0] = renamed;
    assert_eq!(code(&r.run()), 4);

    // 4. A changed setting in the manifest (resealed): the observations, the
    // original and the pinned digest all disagree.
    let manifest_path = t.join("manifest.json");
    let mut manifest: RunManifest =
        parse_default(&std::fs::read(rev2("manifest.json")).unwrap()).unwrap();
    manifest.semantic.mechanics.replays += 1;
    seal(&mut manifest).unwrap();
    std::fs::write(&manifest_path, to_pretty_json(&manifest).unwrap()).unwrap();
    let mut r = Replay::golden(&out);
    r.manifest = manifest_path;
    assert_eq!(code(&r.run()), 4);

    // 5. A pinned digest that does not match.
    let mut r = Replay::golden(&out);
    r.extra = vec!["--expect-manifest-digest".into(), "0".repeat(64)];
    let result = r.run();
    assert_eq!(code(&result), 4);
    assert_eq!(summary(&result)["error"]["detail"], "manifest-digest");
    let mut r = Replay::golden(&out);
    r.extra = vec!["--expect-snapshot-digest".into(), "1".repeat(64)];
    assert_eq!(summary(&r.run())["error"]["detail"], "snapshot-digest");

    // 6. A different population.
    let other = t.join("other-snapshot.json");
    let mut snap: pii_eval_contracts::CorpusSnapshot =
        parse_default(&std::fs::read(legacy_snapshot()).unwrap()).unwrap();
    snap.semantic.population.population_version += 1;
    seal(&mut snap).unwrap();
    std::fs::write(&other, to_pretty_json(&snap).unwrap()).unwrap();
    let mut r = Replay::golden(&out);
    r.snapshot = other;
    assert_eq!(code(&r.run()), 4);

    // 7. A scanner missing, and a scanner repeated.
    let mut r = Replay::golden(&out);
    r.observations.pop();
    assert_eq!(code(&r.run()), 4);
    let mut r = Replay::golden(&out);
    r.observations[1] = r.observations[0].clone();
    assert_eq!(code(&r.run()), 3);

    // 8. An original that is not the run these observations came from.
    let mut r = Replay::golden(&out);
    r.original = Some(repo_root().join("fixtures/contracts/v1/run-artifact.json"));
    let result = r.run();
    assert_ne!(code(&result), 0);
    assert!(matches!(code(&result), 3 | 4));

    // None of the rejections created or changed anything.
    assert!(!out.exists());
}

#[test]
fn replay_refuses_legacy_manifests_and_unusable_outputs() {
    let tmp = TempDir::new("replay-output");
    let out = tmp.0.join("out");
    let mut r = Replay::golden(&out);
    r.manifest = repo_root().join("fixtures/contracts/v1/manifest.json");
    r.observations = vec![repo_root().join("fixtures/contracts/v1/observation-alpha.json")];
    r.original = None;
    let result = r.run();
    assert_eq!(code(&result), 3);
    assert_eq!(reason(&summary(&result)), "protocol-revision-unsupported");

    // An existing result is never overwritten by default.
    let first = Replay::golden(&out).run();
    assert_eq!(code(&first), 5);
    let before = std::fs::read(out.join("run-artifact.json")).unwrap();
    let again = Replay::golden(&out).run();
    assert_eq!(code(&again), 7);
    assert_eq!(reason(&summary(&again)), "output-exists");
    assert_eq!(
        std::fs::read(out.join("run-artifact.json")).unwrap(),
        before
    );
    // `--overwrite replace` is explicit.
    let mut replace = Replay::golden(&out);
    replace.extra = vec!["--overwrite".into(), "replace".into()];
    assert_eq!(code(&replace.run()), 5);

    // A symlink or a file where the directory belongs.
    #[cfg(unix)]
    {
        let link = tmp.0.join("link");
        std::os::unix::fs::symlink(&out, &link).unwrap();
        let result = Replay::golden(&link).run();
        assert_eq!(code(&result), 7);
        assert_eq!(summary(&result)["error"]["detail"], "symlink");
    }
    let file = tmp.0.join("file");
    std::fs::write(&file, b"x").unwrap();
    let result = Replay::golden(&file).run();
    assert_eq!(code(&result), 7);
    assert_eq!(summary(&result)["error"]["detail"], "not-a-directory");
    let missing_parent = tmp.0.join("no/such/parent");
    let result = Replay::golden(&missing_parent).run();
    assert_eq!(code(&result), 7);
}

/// A replay over a scanner-complete run (alpha only, as a one-scanner plan)
/// needs no original when the scanner returned no sanitized output; the golden
/// scanner does return output, so this checks the rule from the other side:
/// statuses other than complete are the ones that need the original.
#[test]
fn the_original_is_needed_exactly_for_incomplete_scanners_and_output_verdicts() {
    let alpha: ObservationSet =
        parse_default(&std::fs::read(rev2("observation-alpha-scan.json")).unwrap()).unwrap();
    let beta: ObservationSet =
        parse_default(&std::fs::read(rev2("observation-beta-scan.json")).unwrap()).unwrap();
    assert_eq!(alpha.semantic.status, ScannerStatus::Complete);
    assert!(
        alpha
            .semantic
            .inputs
            .iter()
            .any(|i| i.sanitized_output_digest.is_some())
    );
    assert_ne!(beta.semantic.status, ScannerStatus::Complete);
    assert!(pii_eval_cli::replay::needs_original(std::slice::from_ref(
        &alpha
    )));
    assert!(pii_eval_cli::replay::needs_original(&[beta]));
    let mut quiet = alpha;
    for input in &mut quiet.semantic.inputs {
        input.sanitized_output_digest = None;
    }
    assert!(!pii_eval_cli::replay::needs_original(&[quiet]));
}
