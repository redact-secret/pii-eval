//! Fixtures of the dependency-free consumer example (`examples/consumer/`),
//! produced by the REAL engine through the built binary, and the example run
//! end to end over fresh engine output. Synthetic data only, the inert fake
//! scanner package. Needs Node and `ps`.
//!
//! Populations: A version 1 (later superseded), A version 2 (the head), B
//! version 1 (a second, separately identified population with different
//! content), and A version 2 measured with a different candidate build (the
//! wrong-candidate artifact). The internal run artifact of A version 2 is kept
//! as the "internal artifact is not consumable" negative.
//!
//! Regenerate after an intentional change with
//! `PII_EVAL_UPDATE_FIXTURES=1 cargo test -p pii-eval-cli --test consumer_fixtures`.
#![cfg(unix)]

mod cli_support;
mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use cli_support::*;
use common::TempDir;
use pii_eval_contracts::{CorpusSnapshot, ENGINE_VERSION, Id, seal, to_pretty_json};
use serde_json::{Value, json};

const NAMES: [&str; 9] = [
    "population-a-v1.public-synthetic-artifact.json",
    "population-a-v2.public-synthetic-artifact.json",
    "population-a-v2.other-candidate.public-synthetic-artifact.json",
    "population-a-v2.run-artifact.json",
    "population-b-v1.public-synthetic-artifact.json",
    "pins.json",
    "population-a-v2.projection.public-synthetic-artifact.json",
    "pins.projection.json",
    "projection-roster.json",
];

fn consumer_dir() -> PathBuf {
    repo_root().join("examples/consumer")
}

fn fixtures_dir() -> PathBuf {
    consumer_dir().join("fixtures")
}

struct Measured {
    public: Vec<u8>,
    internal: Vec<u8>,
}

fn population(id: &str, version: u32, drop_first_case: bool) -> CorpusSnapshot {
    let mut snapshot = read_snapshot(&example_dir().join("snapshot.json"));
    snapshot.semantic.population.population_id = Id::new(id).unwrap();
    snapshot.semantic.population.population_version = version;
    if drop_first_case {
        snapshot.semantic.cases.remove(0);
    }
    seal(&mut snapshot).unwrap();
    snapshot
}

/// One official public-synthetic run of `snapshot` over `package`, through the
/// binary; the documents it wrote.
fn measure(label: &str, node: &Path, snapshot: &CorpusSnapshot, package: &Path) -> Measured {
    measure_with(label, node, snapshot, package, false)
}

/// [`measure`], optionally with the product projection (schema 1.2) built from
/// the example roster, whose digest the official configuration pins.
fn measure_with(
    label: &str,
    node: &Path,
    snapshot: &CorpusSnapshot,
    package: &Path,
    projection: bool,
) -> Measured {
    let tmp = TempDir::new(label);
    let snapshot_path = tmp.0.join("snapshot.json");
    std::fs::write(&snapshot_path, to_pretty_json(snapshot).unwrap()).unwrap();
    let manifest = manifest_for(snapshot, package, node, limits(2, 1), 2);
    let manifest_path = tmp.0.join("manifest.json");
    write_manifest(&manifest_path, &manifest);
    let mut spec = ConfigSpec::new(&snapshot_path, &manifest_path, package);
    spec.mode = "official";
    spec.snapshot_digest = Some(snapshot.semantic_digest.as_str());
    spec.manifest_digest = Some(manifest.semantic_digest.as_str());
    let mut extra = format!(
        r#","engineVersion": "{ENGINE_VERSION}","protocol": {{"id": "pii-v1", "revision": 2}}"#
    );
    if projection {
        let roster_path = example_dir().join("projection-roster.json");
        let roster =
            pii_eval_cli::projection::load_roster(&roster_path, snapshot, None).expect("roster");
        extra.push_str(&format!(
            r#","projection": {{"roster": {{"path": "{}", "rosterDigest": "{}"}}}}"#,
            s(&roster_path),
            roster.digest().as_str()
        ));
    }
    spec.extra_top = &extra;
    let config = tmp.0.join("run-config.json");
    std::fs::write(&config, spec.json()).unwrap();
    let out = tmp.0.join("out");
    let result = run_cli(&[
        "run",
        "--config",
        s(&config),
        "--node",
        s(node),
        "--out",
        s(&out),
    ]);
    assert_eq!(code(&result), 0, "{}", stderr(&result));
    Measured {
        public: std::fs::read(out.join("public-synthetic-artifact.json")).unwrap(),
        internal: std::fs::read(out.join("run-artifact.json")).unwrap(),
    }
}

fn json_of(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}

fn pretty(v: &Value) -> Vec<u8> {
    let mut text = serde_json::to_string_pretty(v).unwrap();
    text.push('\n');
    text.into_bytes()
}

/// The pins a benchmarks-side consumer would record from the qualified runs: the
/// head of A, B, and the retired digests of A's earlier version.
fn pins_for(a1: &Value, a2: &Value, b1: &Value) -> Value {
    let pin = |label: &str, art: &Value, retired: Vec<&Value>| {
        let sem = &art["semantic"];
        json!({
            "label": label,
            "population": sem["population"],
            "runClass": sem["runClass"],
            "artifactDigest": art["semanticDigest"],
            "manifestDigest": sem["manifestDigest"],
            "retiredArtifactDigests": retired.iter().map(|r| r["semanticDigest"].clone()).collect::<Vec<_>>(),
            "retiredManifestDigests": retired.iter().map(|r| r["semantic"]["manifestDigest"].clone()).collect::<Vec<_>>(),
            "scanners": sem["scanners"].as_array().unwrap().iter().map(|s| s["identity"].clone()).collect::<Vec<_>>(),
        })
    };
    let head = &a2["semantic"];
    json!({
        "schema": "pii-eval-consumer-pins/1",
        "engine": head["engine"],
        "protocol": head["protocol"],
        "artifactSchema": {"id": a2["schema"], "version": a2["schemaVersion"]},
        "requireComplete": true,
        "populations": [
            pin("population-a", a2, vec![a1]),
            pin("population-b", b1, vec![]),
        ],
    })
}

/// Pins for the projected artifact: schema 1.2, and the views, mode and roster
/// digest the caller requires.
fn projection_pins_for(a2: &Value) -> Value {
    let sem = &a2["semantic"];
    let block = &sem["productProjection"];
    json!({
        "schema": "pii-eval-consumer-pins/1",
        "engine": sem["engine"],
        "protocol": sem["protocol"],
        "artifactSchema": {"id": a2["schema"], "version": a2["schemaVersion"]},
        "requireComplete": true,
        "populations": [{
            "label": "population-a",
            "population": sem["population"],
            "runClass": sem["runClass"],
            "artifactDigest": a2["semanticDigest"],
            "manifestDigest": sem["manifestDigest"],
            "retiredArtifactDigests": [],
            "retiredManifestDigests": [],
            "projection": {
                "requiredViews": block["requiredViews"],
                "mode": block["rows"][0]["mode"],
                "rosterDigest": block["rosterDigest"],
            },
            "scanners": sem["scanners"].as_array().unwrap().iter().map(|s| s["identity"].clone()).collect::<Vec<_>>(),
        }],
    })
}

fn generated(node: &Path) -> Vec<(&'static str, Vec<u8>)> {
    let a1 = measure(
        "cf-a1",
        node,
        &population("consumer-population-a", 1, false),
        &fake_core_dir(),
    );
    let a2_snapshot = population("consumer-population-a", 2, false);
    let a2 = measure("cf-a2", node, &a2_snapshot, &fake_core_dir());
    let b1 = measure(
        "cf-b1",
        node,
        &population("consumer-population-b", 1, true),
        &fake_core_dir(),
    );
    // Another candidate build of the same scanner: an extra file changes the
    // package tree digest (the candidate digest) and nothing else.
    let other_tmp = TempDir::new("cf-other-package");
    let other_package = other_tmp.0.join("package");
    copy_dir(&fake_core_dir(), &other_package);
    std::fs::write(other_package.join("BUILD-NOTE.txt"), "another build\n").unwrap();
    let other = measure("cf-other", node, &a2_snapshot, &other_package);
    let pins = pins_for(
        &json_of(&a1.public),
        &json_of(&a2.public),
        &json_of(&b1.public),
    );
    // Population A version 2 again, now with the product projection (schema 1.2).
    let projected = measure_with(
        "cf-a2-projection",
        node,
        &a2_snapshot,
        &fake_core_dir(),
        true,
    );
    let projection_pins = projection_pins_for(&json_of(&projected.public));
    vec![
        (NAMES[0], a1.public),
        (NAMES[1], a2.public),
        (NAMES[2], other.public),
        (NAMES[3], a2.internal),
        (NAMES[4], b1.public),
        (NAMES[5], pretty(&pins)),
        (NAMES[6], projected.public),
        (NAMES[7], pretty(&projection_pins)),
        (
            NAMES[8],
            std::fs::read(example_dir().join("projection-roster.json")).unwrap(),
        ),
    ]
}

#[test]
fn committed_consumer_fixtures_equal_what_the_engine_produces() {
    let node = node_or_return!();
    let update = std::env::var("PII_EVAL_UPDATE_FIXTURES").is_ok_and(|v| v == "1");
    let first = generated(&node);
    if update {
        std::fs::create_dir_all(fixtures_dir()).unwrap();
        for (name, bytes) in &first {
            std::fs::write(fixtures_dir().join(name), bytes).unwrap();
        }
    }
    for (name, bytes) in &first {
        let committed = std::fs::read(fixtures_dir().join(name)).unwrap_or_else(|_| {
            panic!("missing examples/consumer/fixtures/{name}; run with PII_EVAL_UPDATE_FIXTURES=1")
        });
        assert_eq!(
            &committed, bytes,
            "examples/consumer/fixtures/{name} drifted"
        );
    }
    // Deterministic across repeated runs (the second set is generated afresh).
    assert_eq!(first, generated(&node), "repeated engine runs differ");
}

fn consume(args: &[&str]) -> (i32, Value) {
    let out = Command::new(node().expect("node"))
        .arg(consumer_dir().join("consume.mjs"))
        .args(args)
        .output()
        .expect("node runs");
    let text = String::from_utf8(out.stdout).unwrap();
    (
        out.status.code().unwrap(),
        serde_json::from_str(&text).unwrap_or(Value::Null),
    )
}

#[test]
fn the_consumer_accepts_fresh_engine_output_and_rejects_the_negative_artifacts() {
    let _node = node_or_return!();
    let dir = fixtures_dir();
    let f = |n: &str| s(&dir.join(n)).to_owned();
    let pins = f("pins.json");
    // The two pinned populations, side by side, never pooled.
    let (status, report) = consume(&["--pins", &pins, &f(NAMES[1]), &f(NAMES[4])]);
    assert_eq!(status, 0, "{report}");
    assert_eq!(report["decision"], "none");
    assert_eq!(report["pooling"], "none");
    assert_eq!(report["populations"].as_array().unwrap().len(), 2);
    // A stale artifact next to the head: rejected with its reason, so exit 1.
    let (status, report) = consume(&["--pins", &pins, &f(NAMES[0]), &f(NAMES[1]), &f(NAMES[4])]);
    assert_eq!(status, 1);
    assert_eq!(
        report["rejections"][0]["reasons"][0]["code"],
        "artifact-superseded"
    );
    // The projected artifact of the same population, under its own pins (1.2).
    let projection_pins = f("pins.projection.json");
    let (status, report) = consume(&["--pins", &projection_pins, &f(NAMES[6])]);
    assert_eq!(status, 0, "{report}");
    assert_eq!(report["pooling"], "none");
    assert_eq!(
        report["populations"][0]["productProjection"]["rows"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    // The 1.1 pins refuse the 1.2 artifact (and the other way round): no silent upgrade.
    let (status, report) = consume(&["--pins", &pins, &f(NAMES[6]), &f(NAMES[4])]);
    assert_eq!(status, 1);
    assert!(report.to_string().contains("schema-version-unsupported"));
    // The wrong candidate, and the internal artifact.
    let (status, report) = consume(&["--pins", &pins, &f(NAMES[2]), &f(NAMES[4])]);
    assert_eq!(status, 1);
    assert!(report.to_string().contains("scanner-artifact-mismatch"));
    let (status, report) = consume(&["--pins", &pins, &f(NAMES[3]), &f(NAMES[4])]);
    assert_eq!(status, 1);
    assert!(
        report
            .to_string()
            .contains("internal-artifact-not-consumable")
    );
}
