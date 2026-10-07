//! The committed first public-synthetic measurement over the pii-evidence
//! snapshot (docs/measurements/pii-evidence-public-pii-phi-2026-10-07-9d4e8e036bbb).
//!
//! No scanner runs here and no network is used: the snapshot is the vendored
//! copy, the corpus is re-derived by the importer, and the committed
//! observation set is REPLAYED. That is what the replay is for: it re-derives
//! the artifacts from the observations alone and must reproduce the committed
//! semantic digests and bytes. The live execution is manual
//! (`tools/pii-evidence/reproduce.mjs`); this test only reads its record.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

const DIR: &str = "docs/measurements/pii-evidence-public-pii-phi-2026-10-07-9d4e8e036bbb";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn measurement(name: &str) -> PathBuf {
    root().join(DIR).join(name)
}

fn json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

static N: AtomicU64 = AtomicU64::new(0);

struct Tmp(PathBuf);
impl Tmp {
    fn new(label: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "pii-eval-measurement-{}-{}-{label}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn evidence(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pii-eval-evidence"))
        .args(args)
        .output()
        .unwrap()
}

fn engine(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pii-eval"))
        .args(args)
        .env_remove("PII_EVAL_JOB_CONTEXT")
        .output()
        .unwrap()
}

fn summary(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout).unwrap()
}

/// Import the vendored snapshot into a fresh directory.
fn imported(tmp: &Tmp) -> (PathBuf, Value) {
    let out = tmp.0.join("import");
    let snapshot =
        root().join("fixtures/pii-evidence/snapshots/public-pii-phi/2026-10-07/9d4e8e036bbb");
    let pin = root().join("fixtures/pii-evidence/pin.json");
    let r = evidence(&[
        "import",
        "--snapshot-dir",
        s(&snapshot),
        "--pin",
        s(&pin),
        "--out",
        s(&out),
    ]);
    assert_eq!(
        r.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&r.stderr)
    );
    (out.join("snapshot.json"), summary(&r))
}

#[test]
fn the_record_matches_the_committed_artifacts_and_the_importer() {
    let record = json(&measurement("provenance.json"));
    let tmp = Tmp::new("record");
    let (_, imported) = imported(&tmp);
    let digests = &record["digests"];
    assert_eq!(
        imported["semantic"]["population"]["semanticDigest"],
        digests["populationDigest"]
    );
    assert_eq!(
        imported["semantic"]["binding"]["semanticDigest"],
        digests["bindingDigest"]
    );

    let manifest = json(&measurement("manifest.json"));
    let public = json(&measurement("public-synthetic-artifact.json"));
    let internal = json(&measurement("run-artifact.json"));
    let observation = json(&measurement("observation-redact-secret-core.json"));
    assert_eq!(manifest["semanticDigest"], digests["manifestDigest"]);
    assert_eq!(public["semanticDigest"], digests["publicArtifactDigest"]);
    assert_eq!(internal["semanticDigest"], digests["runArtifactDigest"]);
    assert_eq!(observation["semanticDigest"], digests["observationDigest"]);
    // Every committed file is the one the record names.
    for (name, want) in record["files"].as_object().unwrap() {
        let bytes = std::fs::read(measurement(name)).unwrap();
        let got = pii_eval_contracts::Sha256Digest::of_bytes(&bytes);
        assert_eq!(got.as_str(), want.as_str().unwrap(), "{name}");
    }
}

#[test]
fn the_measurement_is_public_synthetic_released_pinned_and_complete() {
    let record = json(&measurement("provenance.json"));
    let manifest = json(&measurement("manifest.json"));
    let public = json(&measurement("public-synthetic-artifact.json"));
    let m = &manifest["semantic"];
    assert_eq!(m["runClass"], "public-synthetic");
    assert_eq!(m["population"]["visibility"], "public-synthetic");
    assert_eq!(m["engine"]["version"], record["engine"]["version"]);
    assert_eq!(m["protocol"]["id"], "pii-v1");
    assert_eq!(m["protocol"]["version"], 2);
    let id = &m["scanners"][0]["identity"];
    assert_eq!(id["product"]["kind"], "released");
    assert_eq!(id["scannerVersion"], "0.1.0-beta.12");
    assert_eq!(
        id["artifactDigest"],
        record["scanner"]["artifacts"]["packageTreeSha256"]
    );
    assert_eq!(
        id["configurationDigest"],
        record["scanner"]["configuration"]["configurationDigest"]
    );
    assert_eq!(
        id["activationDigest"],
        record["scanner"]["configuration"]["activationDigest"]
    );
    assert_eq!(public["semantic"]["completeness"], "complete");
    assert_eq!(public["semantic"]["populationCounts"]["variants"], 139);
    assert_eq!(public["semantic"]["populationCounts"]["authoredCases"], 55);
    // Execution and replay are recorded as different kinds of provenance.
    assert_eq!(record["execution"]["kind"], "execution");
    assert_eq!(record["replay"]["kind"], "replay");
    assert_eq!(record["replay"]["scannersLaunched"], 0);
    assert!(record["notAClaim"].as_array().unwrap().len() >= 4);
    // No protected infrastructure or product policy appears anywhere in the record.
    // (the `notAClaim` statements name what is excluded, so they are left out of the scan).
    let mut scanned = record.clone();
    scanned.as_object_mut().unwrap().remove("notAClaim");
    let mut texts = vec![serde_json::to_string(&scanned).unwrap()];
    for name in [
        "manifest.json",
        "public-synthetic-artifact.json",
        "run-config.json",
    ] {
        texts.push(std::fs::read_to_string(measurement(name)).unwrap());
    }
    for text in texts {
        let text = text.to_ascii_lowercase();
        for word in [
            "ledger",
            "custodian",
            "protected\"",
            "production key",
            "apikey",
            "secret_key",
        ] {
            assert!(!text.contains(word), "{word}");
        }
    }
}

#[test]
fn validate_verifies_the_committed_artifacts_against_the_re_derived_corpus() {
    let tmp = Tmp::new("validate");
    let (snapshot, _) = imported(&tmp);
    let manifest = measurement("manifest.json");
    for (kind, file, extra) in [
        ("corpus-snapshot", snapshot.clone(), vec![]),
        (
            "run-manifest",
            manifest.clone(),
            vec!["--snapshot", s(&snapshot)],
        ),
        (
            "run-artifact",
            measurement("run-artifact.json"),
            vec!["--snapshot", s(&snapshot), "--manifest", s(&manifest)],
        ),
        (
            "public-synthetic-artifact",
            measurement("public-synthetic-artifact.json"),
            vec!["--snapshot", s(&snapshot)],
        ),
    ] {
        let mut args = vec!["validate", s(&file), "--kind", kind];
        args.extend(extra);
        let r = engine(&args);
        assert_eq!(
            r.status.code(),
            Some(0),
            "{kind}: {}",
            String::from_utf8_lossy(&r.stderr)
        );
    }
}

#[test]
fn replay_reproduces_the_committed_semantic_result_without_launching_a_scanner() {
    let record = json(&measurement("provenance.json"));
    let digests = &record["digests"];
    let tmp = Tmp::new("replay");
    let (snapshot, _) = imported(&tmp);
    let out = tmp.0.join("replayed");
    let r = engine(&[
        "replay",
        "--snapshot",
        s(&snapshot),
        "--manifest",
        s(&measurement("manifest.json")),
        "--observation",
        s(&measurement("observation-redact-secret-core.json")),
        "--original",
        s(&measurement("run-artifact.json")),
        "--out",
        s(&out),
        "--expect-snapshot-digest",
        digests["populationDigest"].as_str().unwrap(),
        "--expect-manifest-digest",
        digests["manifestDigest"].as_str().unwrap(),
    ]);
    assert_eq!(
        r.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&r.stderr)
    );
    let sum = summary(&r);
    assert_eq!(sum["semantic"]["parity"], "identical");
    assert_eq!(sum["semantic"]["scannersLaunched"], 0);
    assert_eq!(
        sum["semantic"]["runArtifactDigest"],
        digests["runArtifactDigest"]
    );
    assert_eq!(
        sum["semantic"]["publicArtifactDigest"],
        digests["publicArtifactDigest"]
    );
    for name in [
        "manifest.json",
        "observation-redact-secret-core.json",
        "public-synthetic-artifact.json",
        "run-artifact.json",
    ] {
        assert_eq!(
            std::fs::read(out.join(name)).unwrap(),
            std::fs::read(measurement(name)).unwrap(),
            "{name} differs after replay"
        );
    }
}

#[test]
fn replay_rejects_a_changed_observation_a_wrong_pin_and_a_foreign_snapshot() {
    let record = json(&measurement("provenance.json"));
    let digests = &record["digests"];
    let tmp = Tmp::new("replay-negative");
    let (snapshot, _) = imported(&tmp);
    let manifest = measurement("manifest.json");
    let original = measurement("run-artifact.json");
    let observation = measurement("observation-redact-secret-core.json");
    let pin_snapshot = digests["populationDigest"].as_str().unwrap();

    // A changed observation: one digit of a recorded range moves.
    let mut tampered: Value = json(&observation);
    let findings = tampered["semantic"]["inputs"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|i| i["findings"].as_array().is_some_and(|f| !f.is_empty()));
    let bad = tmp.0.join("observation-tampered.json");
    match findings {
        Some(input) => {
            let f = &mut input["findings"][0];
            let start = f["range"]["start"].as_u64().unwrap();
            f["range"]["start"] = Value::from(start + 1);
        }
        None => {
            // This observation reports no finding; change the scanner binding instead.
            tampered["semantic"]["scannerId"] = Value::from("other-scanner");
        }
    }
    std::fs::write(&bad, serde_json::to_vec_pretty(&tampered).unwrap()).unwrap();
    let r = engine(&[
        "replay",
        "--snapshot",
        s(&snapshot),
        "--manifest",
        s(&manifest),
        "--observation",
        s(&bad),
        "--original",
        s(&original),
        "--out",
        s(&tmp.0.join("o1")),
    ]);
    assert!(
        matches!(r.status.code(), Some(3 | 4)),
        "{:?}",
        r.status.code()
    );
    assert!(!tmp.0.join("o1").join("run-artifact.json").exists());

    // A wrong pinned population digest.
    let r = engine(&[
        "replay",
        "--snapshot",
        s(&snapshot),
        "--manifest",
        s(&manifest),
        "--observation",
        s(&observation),
        "--original",
        s(&original),
        "--out",
        s(&tmp.0.join("o2")),
        "--expect-snapshot-digest",
        &"0".repeat(64),
    ]);
    assert_eq!(r.status.code(), Some(4));

    // A wrong pinned manifest digest.
    let r = engine(&[
        "replay",
        "--snapshot",
        s(&snapshot),
        "--manifest",
        s(&manifest),
        "--observation",
        s(&observation),
        "--original",
        s(&original),
        "--out",
        s(&tmp.0.join("o3")),
        "--expect-snapshot-digest",
        pin_snapshot,
        "--expect-manifest-digest",
        &"0".repeat(64),
    ]);
    assert_eq!(r.status.code(), Some(4));

    // Without the original, a scanner that returned sanitized output cannot be replayed.
    let r = engine(&[
        "replay",
        "--snapshot",
        s(&snapshot),
        "--manifest",
        s(&manifest),
        "--observation",
        s(&observation),
        "--out",
        s(&tmp.0.join("o4")),
    ]);
    assert_ne!(r.status.code(), Some(0));
}

/// Hand-checkable accounting: every outcome row of the committed artifact must
/// be a state the authored expectation can reach (ADR 0017, ADR 0018), and the
/// row tallies must equal the corpus's own counts.
#[test]
fn every_outcome_row_follows_its_authored_expectation() {
    let tmp = Tmp::new("outcomes");
    let (snapshot_path, _) = imported(&tmp);
    let snapshot = json(&snapshot_path);
    let mut authored = std::collections::BTreeMap::new();
    for case in snapshot["semantic"]["cases"].as_array().unwrap() {
        for variant in case["variants"].as_array().unwrap() {
            let e = &variant["expectations"][0];
            authored.insert(
                variant["variantId"].as_str().unwrap().to_owned(),
                (
                    e["typeExpectation"].as_str().unwrap().to_owned(),
                    e["sensitivity"].as_str().unwrap().to_owned(),
                    e.get("range").is_some(),
                ),
            );
        }
    }
    let internal = json(&measurement("run-artifact.json"));
    let rows = internal["semantic"]["outcomes"].as_array().unwrap();
    assert_eq!(rows.len(), 139, "one row per occurrence");
    let (mut located, mut rangeless) = (0, 0);
    for row in rows {
        let (type_expectation, sensitivity, has_range) =
            &authored[row["variantId"].as_str().unwrap()];
        let (t, s, r, a) = (
            row["typeIdentity"].as_str().unwrap(),
            row["sensitivityContext"].as_str().unwrap(),
            row["range"].as_str().unwrap(),
            row["action"]["state"].as_str().unwrap(),
        );
        // `unresolved` is the only observation of `not-established`, and nothing else reaches it.
        assert_eq!(
            t == "unresolved",
            type_expectation == "not-established",
            "{row}"
        );
        assert_eq!(s == "unresolved", sensitivity == "not-established", "{row}");
        if *has_range {
            located += 1;
            assert_ne!(r, "unresolved");
        } else {
            rangeless += 1;
            assert_eq!(
                (t, s, r, a),
                ("unresolved", "unresolved", "unresolved", "not-measured")
            );
        }
    }
    assert_eq!((located, rangeless), (98, 41));
}
