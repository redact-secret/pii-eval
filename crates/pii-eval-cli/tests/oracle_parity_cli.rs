//! The CLI over the parity population (P9, ADR 0011): the documents the engine
//! writes for the frozen observations are byte-identical at one and four workers,
//! `pii-eval validate` verifies them against the snapshot, and `pii-eval replay`
//! re-derives the artifact from the observation sets alone, byte for byte.
//! Needs no Node and no scanner: the adapters replay the frozen observations in
//! process.

mod parity;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use parity::engine::write_engine_run;
use parity::model::*;
use serde_json::Value;

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> TempDir {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "pii-eval-parity-{}-{}-{label}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn cli(args: &[&str]) -> (i32, Value) {
    let out = Command::new(env!("CARGO_BIN_EXE_pii-eval"))
        .args(args)
        .env_remove("PII_EVAL_JOB_CONTEXT")
        .output()
        .expect("the binary runs");
    let text = String::from_utf8(out.stdout).expect("stdout is UTF-8");
    assert_eq!(text.matches('\n').count(), 1, "stdout is one line");
    (
        out.status.code().expect("exited normally"),
        serde_json::from_str(&text).expect("stdout is JSON"),
    )
}

fn s(p: &Path) -> &str {
    p.to_str().expect("UTF-8 path")
}

#[test]
fn the_cli_validates_and_replays_the_engine_documents_and_workers_do_not_matter() {
    let ds = Dataset::load();
    let rc = rust_corpus(&ds.input, &ds.export);
    let one = TempDir::new("one");
    let four = TempDir::new("four");
    let names = write_engine_run(&ds, &rc, 1, &one.0.join("run"));
    assert_eq!(names, write_engine_run(&ds, &rc, 4, &four.0.join("run")));
    // Jobs invariance at file level: every document is byte-identical.
    for name in &names {
        assert_eq!(
            std::fs::read(one.0.join("run").join(name)).unwrap(),
            std::fs::read(four.0.join("run").join(name)).unwrap(),
            "{name} differs between one and four workers"
        );
    }
    assert!(names.iter().any(|n| n == "run-artifact.json"));
    assert_eq!(
        names
            .iter()
            .filter(|n| n.starts_with("observation-"))
            .count(),
        8
    );

    let dir = one.0.join("run");
    let snapshot = dir.join("snapshot.json");
    let manifest = dir.join("manifest.json");
    let artifact = dir.join("run-artifact.json");

    // validate: every document, then the artifact with its accounting verified.
    let (code, summary) = cli(&["validate", s(&snapshot)]);
    assert_eq!(code, 0, "{summary}");
    let (code, summary) = cli(&["validate", s(&manifest), "--snapshot", s(&snapshot)]);
    assert_eq!(code, 0, "{summary}");
    let (code, summary) = cli(&[
        "validate",
        s(&artifact),
        "--snapshot",
        s(&snapshot),
        "--manifest",
        s(&manifest),
    ]);
    assert_eq!(code, 0, "{summary}");
    assert_eq!(summary["semantic"]["verification"], "verified", "{summary}");
    let public = dir.join("public-synthetic-artifact.json");
    let (code, summary) = cli(&["validate", s(&public), "--snapshot", s(&snapshot)]);
    assert_eq!(code, 0, "{summary}");

    // replay: the observation sets alone (and the original, because failed scanners
    // carry their failure codes there) re-derive the artifact; the files are byte-identical.
    let observations: Vec<PathBuf> = names
        .iter()
        .filter(|n| n.starts_with("observation-"))
        .map(|n| dir.join(n))
        .collect();
    let replayed = one.0.join("replay");
    let mut args = vec![
        "replay".to_owned(),
        "--snapshot".to_owned(),
        s(&snapshot).to_owned(),
        "--manifest".to_owned(),
        s(&manifest).to_owned(),
        "--original".to_owned(),
        s(&artifact).to_owned(),
        "--out".to_owned(),
        s(&replayed).to_owned(),
    ];
    for o in &observations {
        args.push("--observation".to_owned());
        args.push(s(o).to_owned());
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let (code, summary) = cli(&refs);
    // Four scanners did not complete (unsupported, unavailable, error, unstable): the replay is
    // exit 5 and `incomplete`, never a clean success (docs/cli.md), and its parity is identical.
    assert_eq!(code, 5, "{summary}");
    assert_eq!(summary["state"], "incomplete");
    assert_eq!(summary["semantic"]["parity"], "identical", "{summary}");
    assert_eq!(
        summary["semantic"]["verification"]["carriedFromOriginal"],
        serde_json::json!(["failure-codes"])
    );
    for name in names.iter().filter(|n| n.as_str() != "snapshot.json") {
        assert_eq!(
            std::fs::read(dir.join(name)).unwrap(),
            std::fs::read(replayed.join(name)).unwrap(),
            "the replay of {name} differs from the original"
        );
    }
}
