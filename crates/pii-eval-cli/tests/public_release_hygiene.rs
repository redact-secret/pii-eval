//! Public-release hygiene (P12): the repository's committed documents expose no
//! protected population and no custodian ledger material, and the public
//! artifact schema cannot represent either. Cheap structural checks over the
//! working tree; they are a tripwire, not a history scan (use the
//! `scan-secrets-in-history` skill before publication, SECURITY.md).
//!
//! Scope of the tree walk: every file below the repository root except build
//! output and tool state. It does not read `.git`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::Value;

fn root() -> PathBuf {
    std::fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .expect("repository root")
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        if matches!(
            name.as_str(),
            "target" | ".git" | ".claude" | "node_modules" | "graft"
        ) {
            continue;
        }
        let path = entry.path();
        if entry.file_type().unwrap().is_dir() {
            walk(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn files() -> Vec<PathBuf> {
    let mut all = Vec::new();
    walk(&root(), &mut all);
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

fn keys_and_strings(v: &Value, keys: &mut BTreeSet<String>, strings: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                keys.insert(k.clone());
                keys_and_strings(x, keys, strings);
            }
        }
        Value::Array(a) => a.iter().for_each(|x| keys_and_strings(x, keys, strings)),
        Value::String(s) => strings.push(s.clone()),
        _ => {}
    }
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

/// Where a protected-visibility document is allowed to appear: the negative
/// contract fixtures, whose whole purpose is to be rejected.
fn protected_allowed(path: &str) -> bool {
    path.starts_with("fixtures/contracts/v1/negative/")
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
        let Ok(doc) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        checked += 1;
        let (mut keys, mut strings) = (BTreeSet::new(), Vec::new());
        keys_and_strings(&doc, &mut keys, &mut strings);
        for key in LEDGER_KEYS {
            assert!(
                !keys.contains(key),
                "{name} has the custody-ledger field name `{key}`"
            );
        }
        if !protected_allowed(&name) {
            let protected = keys.contains("visibility") && strings.iter().any(|s| s == "protected")
                || strings.iter().any(|s| s == "job-context-protected");
            assert!(!protected, "{name} is, or names, a protected document");
        }
        // Custodian document tags other than the two engine-facing inputs would mean a
        // ledger or receipt document was committed.
        for s in &strings {
            if let Some(tag) = s.strip_prefix("private-custodian.") {
                assert!(
                    tag.starts_with("worker-result/")
                        || tag.starts_with("aggregates/")
                        || tag.starts_with("worker-job/"),
                    "{name} carries a custodian document tag `{s}`"
                );
            }
        }
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
        // This test names the markers it looks for; it is the only file that may.
        if name.ends_with("public_release_hygiene.rs") {
            continue;
        }
        for marker in [
            "-----BEGIN PRIVATE KEY",
            "-----BEGIN RSA PRIVATE KEY",
            "-----BEGIN OPENSSH PRIVATE KEY",
            "-----BEGIN EC PRIVATE KEY",
        ] {
            assert!(!text.contains(marker), "{name} contains key material");
        }
        // A custodian INTERNAL schema tag in any committed file would mean a
        // ledger record was copied here (documents may name the contracts by
        // their public names; the internal tags are listed in custodian docs).
        for tag in [
            "private-custodian.internal-receipt/",
            "private-custodian.execution/",
            "private-custodian.reservation/",
            "private-custodian.approval/",
        ] {
            assert!(
                !text.contains(tag),
                "{name} contains the custodian internal tag {tag}"
            );
        }
    }
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
    let class = &schema["$defs"]["PublicSyntheticClass"];
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
