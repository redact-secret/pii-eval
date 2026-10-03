//! Public-release hygiene (P12): the repository's committed documents expose no
//! protected population and no custodian ledger material, and the public
//! artifact schema cannot represent either. Cheap structural checks over the
//! working tree; they are a tripwire, not a history scan (use the
//! `scan-secrets-in-history` skill before publication, SECURITY.md).
//!
//! Scope of the tree walk: every file below the repository root except build
//! output and tool state at the ROOT only (`target`, `.git`, `.claude`,
//! `node_modules`, `graft`). It does not read `.git`. The detectors are pure
//! functions with a negative control, so the scan is shown able to fail.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::Value;

const SELF: &str = "crates/pii-eval-cli/tests/public_release_hygiene.rs";

/// Directories skipped, at the repository root only.
const ROOT_SKIPS: [&str; 5] = ["target", ".git", ".claude", "node_modules", "graft"];

fn root() -> PathBuf {
    std::fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .expect("repository root")
}

fn walk(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        if depth == 0 && ROOT_SKIPS.contains(&name.as_str()) {
            continue;
        }
        let path = entry.path();
        if entry.file_type().unwrap().is_dir() {
            walk(&path, depth + 1, out);
        } else {
            out.push(path);
        }
    }
}

fn files() -> Vec<PathBuf> {
    let mut all = Vec::new();
    walk(&root(), 0, &mut all);
    all.sort();
    assert!(all.len() > 100, "the walk found the repository");
    all
}

fn rel(p: &Path) -> String {
    p.strip_prefix(root())
        .unwrap()
        .to_string_lossy()
        .replace('\\', "/")
}

/// Field names of private-custodian's INTERNAL records (its contracts doc lists
/// them as never public). No committed JSON document of this repository may
/// carry one: they belong to the custody ledger, not to a measurement.
const LEDGER_KEYS: [&str; 12] = [
    "ledger",
    "reservation",
    "reservationId",
    "reservation_id",
    "budget",
    "budgetScope",
    "receipt",
    "internalReceipt",
    "approval",
    "approver",
    "signature",
    "attempt",
];

/// Where a protected document is allowed to appear: the negative contract
/// fixtures, whose whole purpose is to be rejected.
fn protected_allowed(path: &str) -> bool {
    path.starts_with("fixtures/contracts/v1/negative/")
}

/// Every object member name, and whether any object says it is protected
/// (`visibility` or `runClass` equal to `protected`) or is a custodian job
/// context (which carries input and output roots).
struct Facts {
    keys: BTreeSet<String>,
    strings: Vec<String>,
    protected: bool,
    job_context: bool,
}

fn facts(v: &Value, f: &mut Facts) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                f.keys.insert(k.clone());
                if (k == "visibility" || k == "runClass") && x == "protected" {
                    f.protected = true;
                }
                if k == "schema" && x == "pii-eval-job-context/1" {
                    f.job_context = true;
                }
                facts(x, f);
            }
        }
        Value::Array(a) => a.iter().for_each(|x| facts(x, f)),
        Value::String(s) => f.strings.push(s.clone()),
        _ => {}
    }
}

/// Violations of one committed JSON document; empty when it is clean.
fn json_violations(name: &str, text: &str) -> Vec<String> {
    let Ok(doc) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    let mut f = Facts {
        keys: BTreeSet::new(),
        strings: Vec::new(),
        protected: false,
        job_context: false,
    };
    facts(&doc, &mut f);
    let mut out = Vec::new();
    for key in LEDGER_KEYS {
        if f.keys.contains(key) {
            out.push(format!("{name} has the custody-ledger field name `{key}`"));
        }
    }
    if !protected_allowed(name) {
        if f.protected {
            out.push(format!("{name} is, or names, a protected document"));
        }
        if f.job_context {
            out.push(format!("{name} is a custodian job context"));
        }
    }
    // Custodian document tags other than the engine-facing inputs would mean a
    // ledger or receipt document was committed.
    for s in &f.strings {
        if let Some(tag) = s.strip_prefix("private-custodian.") {
            let ok = ["worker-result/", "aggregates/", "worker-job/"]
                .iter()
                .any(|p| tag.starts_with(p));
            if !ok {
                out.push(format!("{name} carries a custodian document tag `{s}`"));
            }
        }
    }
    out
}

const KEY_MARKERS: [&str; 4] = [
    "-----BEGIN PRIVATE KEY",
    "-----BEGIN RSA PRIVATE KEY",
    "-----BEGIN OPENSSH PRIVATE KEY",
    "-----BEGIN EC PRIVATE KEY",
];

const INTERNAL_TAGS: [&str; 4] = [
    "private-custodian.internal-receipt/",
    "private-custodian.execution/",
    "private-custodian.reservation/",
    "private-custodian.approval/",
];

/// Violations of one committed text file.
fn text_violations(name: &str, text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for marker in KEY_MARKERS {
        if text.contains(marker) {
            out.push(format!("{name} contains key material"));
        }
    }
    for tag in INTERNAL_TAGS {
        if text.contains(tag) {
            out.push(format!("{name} contains the custodian internal tag {tag}"));
        }
    }
    out
}

#[test]
fn no_committed_json_document_is_protected_or_carries_ledger_fields() {
    let mut checked = 0;
    for path in files() {
        let name = rel(&path);
        if !name.ends_with(".json") || name.starts_with("schemas/") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        if serde_json::from_str::<Value>(&text).is_ok() {
            checked += 1;
        }
        let v = json_violations(&name, &text);
        assert!(v.is_empty(), "{v:?}");
    }
    assert!(
        checked > 50,
        "the scan covered the committed documents ({checked})"
    );
}

#[test]
fn no_committed_file_holds_key_material_or_a_custodian_internal_record() {
    for path in files() {
        let name = rel(&path);
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        // This file names the markers it looks for; it is the only exemption, by exact path.
        if name == SELF {
            continue;
        }
        let v = text_violations(&name, &text);
        assert!(v.is_empty(), "{v:?}");
    }
}

#[test]
fn the_detectors_can_fail_negative_control() {
    // The same functions the tree scan uses, over in-memory documents that must be flagged.
    let protected = r#"{"semantic":{"population":{"visibility":"protected"}}}"#;
    assert!(!json_violations("x.json", protected).is_empty());
    let protected_class = r#"{"semantic":{"runClass":"protected"}}"#;
    assert!(!json_violations("x.json", protected_class).is_empty());
    // ...but the negative contract fixtures may be protected.
    assert!(json_violations("fixtures/contracts/v1/negative/a.json", protected_class).is_empty());
    let job = r#"{"schema":"pii-eval-job-context/1","jobId":"x"}"#;
    assert!(!json_violations("x.json", job).is_empty());
    for key in LEDGER_KEYS {
        let doc = format!(r#"{{"a":{{"{key}":1}}}}"#);
        assert!(!json_violations("x.json", &doc).is_empty(), "{key}");
    }
    let tag = r#"{"schema":"private-custodian.internal-receipt/1"}"#;
    assert!(!json_violations("x.json", tag).is_empty());
    let allowed = r#"{"schema":"private-custodian.worker-result/1"}"#;
    assert!(json_violations("x.json", allowed).is_empty());
    assert!(!text_violations("x.txt", &format!("{}\nabc", KEY_MARKERS[0])).is_empty());
    assert!(!text_violations("x.txt", INTERNAL_TAGS[1]).is_empty());
    assert!(text_violations("x.txt", "plain text").is_empty());

    // The walk itself: a directory of the same name is skipped at the root only.
    let tmp = std::env::temp_dir().join(format!("pii-eval-hygiene-{}", std::process::id()));
    std::fs::create_dir_all(tmp.join("target")).unwrap();
    std::fs::create_dir_all(tmp.join("docs/target")).unwrap();
    std::fs::write(tmp.join("target/skipped.json"), "{}").unwrap();
    std::fs::write(tmp.join("docs/target/seen.json"), "{}").unwrap();
    let mut found = Vec::new();
    walk(&tmp, 0, &mut found);
    let names: Vec<String> = found
        .iter()
        .map(|p| p.strip_prefix(&tmp).unwrap().to_string_lossy().into_owned())
        .collect();
    std::fs::remove_dir_all(&tmp).unwrap();
    assert_eq!(names, ["docs/target/seen.json"]);
}

#[test]
fn the_public_artifact_schema_cannot_represent_protected_or_raw_data() {
    let text =
        std::fs::read_to_string(root().join("schemas/public-synthetic-artifact.v1.schema.json"))
            .unwrap();
    let schema: Value = serde_json::from_str(&text).unwrap();
    // Every property name the public artifact can carry.
    fn names(v: &Value, out: &mut BTreeSet<String>) {
        match v {
            Value::Object(m) => {
                if let Some(Value::Object(props)) = m.get("properties") {
                    out.extend(props.keys().cloned());
                }
                m.values().for_each(|x| names(x, out));
            }
            Value::Array(a) => a.iter().for_each(|x| names(x, out)),
            _ => {}
        }
    }
    let mut all = BTreeSet::new();
    names(&schema, &mut all);
    for forbidden in [
        "text",
        "seed",
        "stdout",
        "stderr",
        "sanitizedOutput",
        "path",
        "findings",
        "observed",
        "observationDigest",
        "textDigest",
        "ledger",
        "receipt",
        "reservation",
        "budget",
        "approval",
        "signature",
        "token",
        "secret",
    ] {
        assert!(
            !all.contains(forbidden),
            "the public artifact schema has a `{forbidden}` property"
        );
    }
    // The class and the visibility are single-valued types: a protected population cannot be represented.
    let defs = &schema["$defs"];
    let class = &defs["PublicSyntheticClass"];
    let values: Vec<&Value> = class
        .get("enum")
        .and_then(Value::as_array)
        .map(|a| a.iter().collect())
        .or_else(|| class.get("const").map(|c| vec![c]))
        .or_else(|| {
            class
                .get("oneOf")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|x| x.get("const")).collect())
        })
        .unwrap_or_default();
    assert_eq!(
        values,
        [&Value::String("public-synthetic".into())],
        "{class}"
    );
    // ...and the two fields that could carry a class reference exactly that type.
    let single = "#/$defs/PublicSyntheticClass";
    assert_eq!(
        defs["PublicSyntheticArtifactBody"]["properties"]["runClass"]["$ref"],
        single
    );
    assert_eq!(
        defs["PublicPopulationBinding"]["properties"]["visibility"]["$ref"],
        single
    );
    // Every object type of the artifact is closed: an extra member cannot ride along.
    let mut open = Vec::new();
    for (name, def) in defs.as_object().unwrap() {
        if def.get("properties").is_some() && def["additionalProperties"] != false {
            open.push(name.clone());
        }
    }
    assert_eq!(schema["additionalProperties"], false, "top level is closed");
    assert!(open.is_empty(), "open object types: {open:?}");
}

#[test]
fn the_documents_state_that_the_engine_does_not_publish_protected_results() {
    // The statements consumers and the custodian rely on, kept where they can be read.
    let boundary = std::fs::read_to_string(root().join("docs/custodian-boundary.md"))
        .expect("docs/custodian-boundary.md");
    for needle in [
        "The engine never publishes a protected result",
        "ground_truth",
        "attests execution identity, not truth",
    ] {
        assert!(
            boundary.contains(needle),
            "docs/custodian-boundary.md lost: {needle}"
        );
    }
    let security = std::fs::read_to_string(root().join("SECURITY.md")).unwrap();
    assert!(
        security.contains("custodian-boundary.md"),
        "SECURITY.md links the boundary document"
    );
}
