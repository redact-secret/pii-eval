//! Schema drift: the generated JSON Schemas, registry and reason-code catalog
//! must equal the committed files under `schemas/`.
//!
//! After an intentional, reviewed contract change, regenerate with
//! `PII_EVAL_UPDATE_SCHEMAS=1 cargo test -p pii-eval-contracts --test schema_drift`
//! and describe every changed field in the commit (see ADR 0002 for what is a
//! breaking change).

mod common;

use std::collections::BTreeSet;
use std::path::Path;

use common::*;
use pii_eval_contracts::schema::{generated_files, json_schema_of, reason_codes_json};
use pii_eval_contracts::*;

fn files_under(dir: &Path, prefix: &str, out: &mut BTreeSet<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let name = format!("{prefix}{}", entry.file_name().to_string_lossy());
        if entry.file_type().unwrap().is_dir() {
            files_under(&entry.path(), &format!("{name}/"), out);
        } else {
            out.insert(name);
        }
    }
}

#[test]
fn committed_schemas_equal_generated_schemas() {
    let dir = schemas_dir();
    let files = generated_files();
    if update_requested("PII_EVAL_UPDATE_SCHEMAS") {
        for file in &files {
            let path = dir.join(&file.path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, &file.contents).unwrap();
        }
    }
    let mut drift = Vec::new();
    for file in &files {
        match std::fs::read_to_string(dir.join(&file.path)) {
            Ok(committed) if committed == file.contents => {}
            Ok(_) => drift.push(format!("{} differs from the generated schema", file.path)),
            Err(_) => drift.push(format!("{} is not committed", file.path)),
        }
    }
    let expected: BTreeSet<String> = files.iter().map(|f| f.path.clone()).collect();
    let mut on_disk = BTreeSet::new();
    files_under(&dir, "", &mut on_disk);
    for stale in on_disk.difference(&expected) {
        drift.push(format!("{stale} is committed but no longer generated"));
    }
    assert!(
        drift.is_empty(),
        "schema drift (regenerate with PII_EVAL_UPDATE_SCHEMAS=1 after review):\n{}",
        drift.join("\n")
    );
}

#[test]
fn generation_is_deterministic_across_runs() {
    let first = generated_files();
    for _ in 0..5 {
        assert_eq!(generated_files(), first);
    }
    for file in &first {
        assert!(
            file.contents.ends_with("}\n") && !file.contents.ends_with("\n\n"),
            "{}",
            file.path
        );
        serde_json::from_str::<serde_json::Value>(&file.contents).expect("generated file is JSON");
    }
}

#[test]
fn schema_ids_carry_the_schema_version() {
    for kind in DocumentKind::ALL {
        let schema = json_schema_of(kind);
        let id = schema["$id"].as_str().unwrap();
        assert_eq!(
            id,
            format!(
                "urn:pii-eval:schema:{}:{SCHEMA_MAJOR}.{SCHEMA_MINOR}",
                kind.schema_file_stem()
            )
        );
        // The `schema` field is pinned to exactly the document kind.
        let text = serde_json::to_string(&schema).unwrap();
        assert!(text.contains(kind.schema_id()), "{id}");
    }
}

#[test]
fn every_schema_closes_its_objects() {
    // deny_unknown_fields must reach the schema: no open object definitions.
    fn walk(v: &serde_json::Value, path: &str, open: &mut Vec<String>) {
        if let serde_json::Value::Object(m) = v {
            if m.get("type").and_then(|t| t.as_str()) == Some("object")
                && m.contains_key("properties")
                && m.get("additionalProperties") != Some(&serde_json::Value::Bool(false))
            {
                open.push(path.to_owned());
            }
            for (k, child) in m {
                walk(child, &format!("{path}/{k}"), open);
            }
        } else if let serde_json::Value::Array(items) = v {
            for (i, child) in items.iter().enumerate() {
                walk(child, &format!("{path}/{i}"), open);
            }
        }
    }
    for kind in DocumentKind::ALL {
        let mut open = Vec::new();
        walk(&json_schema_of(kind), kind.schema_file_stem(), &mut open);
        assert!(open.is_empty(), "open object schemas: {open:?}");
    }
}

#[test]
fn reason_code_catalog_lists_every_code() {
    let catalog = reason_codes_json();
    let listed: BTreeSet<&str> = catalog["codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap())
        .collect();
    let all: BTreeSet<&str> = ReasonCode::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(listed, all);
}
