//! The documented CLI contract (docs/cli.md) and the implementation agree: the
//! frozen exit-code table, the reason codes, the configuration fields and the
//! stdout summary shape. No Node needed.

mod cli_support;
mod common;

use std::collections::BTreeSet;

use cli_support::*;
use pii_eval_cli::status::{Exit, reason};

fn doc() -> String {
    std::fs::read_to_string(repo_root().join("docs/cli.md")).expect("docs/cli.md")
}

#[test]
fn the_exit_code_table_in_the_docs_is_the_frozen_table() {
    let doc = doc();
    for exit in Exit::ALL {
        let row = format!("| {} | `{}` |", exit.code(), exit.name());
        assert!(doc.contains(&row), "docs/cli.md lacks the row {row}");
    }
    // Exactly twelve rows: a new status is a contract change that must edit both.
    let rows = doc
        .lines()
        .filter(|l| {
            let mut cells = l.split('|').map(str::trim);
            cells.next() == Some("")
                && cells.next().is_some_and(|c| c.parse::<u8>().is_ok())
                && cells.next().is_some_and(|c| c.starts_with('`'))
        })
        .count();
    assert_eq!(rows, Exit::ALL.len());
}

#[test]
fn every_reason_code_is_documented_and_every_documented_code_exists() {
    let doc = doc();
    for code in reason::ALL {
        assert!(
            doc.contains(&format!("`{code}`")),
            "undocumented reason {code}"
        );
    }
    // The exit-by-exit list names only existing codes.
    let known: BTreeSet<&str> = reason::ALL.iter().copied().collect();
    let list = doc
        .split("Reason codes (`error.reason`), by exit:")
        .nth(1)
        .unwrap()
        .split("`output-committed-not-durable` means")
        .next()
        .unwrap();
    for token in list.split('`').skip(1).step_by(2) {
        assert!(
            known.contains(token),
            "documented reason {token} does not exist"
        );
    }
}

#[test]
fn every_configuration_field_is_documented() {
    let doc = doc();
    for field in [
        "schema",
        "mode",
        "runClass",
        "product",
        "engineVersion",
        "protocol",
        "snapshot",
        "manifest",
        "scanners",
        "host",
        "output",
        "projection",
        "roster",
        "rosterDigest",
        "semanticDigest",
        "adapter",
        "node",
        "shim",
        "package",
        "treeSha256",
        "entry",
        "version",
        "extraArtifacts",
        "limits",
        "startupTimeoutMs",
        "callTimeoutMs",
        "maxWorkers",
        "resources",
        "diagnostics",
        "scratchDir",
        "minSessionMemoryBytes",
        "dir",
        "overwrite",
        // The job context.
        "jobId",
        "custodian",
        "populationDigest",
        "manifestDigest",
        "candidateDigest",
        "inputRoot",
        "outputRoot",
    ] {
        assert!(
            doc.contains(&format!("\"{field}\"")),
            "docs/cli.md lacks the field {field}"
        );
    }
    for schema in [
        "pii-eval-run-config/1",
        "pii-eval-job-context/1",
        "pii-eval-summary/1",
    ] {
        assert!(doc.contains(schema), "{schema}");
    }
}

#[test]
fn the_committed_example_configurations_parse_with_the_documented_schema() {
    for name in ["run-config.json", "run-config.official.json"] {
        let text = std::fs::read_to_string(example_dir().join(name)).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["schema"], pii_eval_cli::config::CONFIG_SCHEMA);
    }
    // A configuration the parser accepts, parsed through the library as the
    // binary does.
    let text = std::fs::read(example_dir().join("run-config.official.json")).unwrap();
    let parsed = pii_eval_cli::config::RunConfig::parse(&text, &example_dir()).unwrap();
    assert_eq!(parsed.mode, pii_eval_cli::config::Mode::Official);
    assert!(parsed.snapshot.digest.is_some() && parsed.manifest.digest.is_some());
}

#[test]
fn the_summary_shape_documented_for_stdout_is_what_the_binary_prints() {
    let out = run_cli(&["validate", s(&example_dir().join("snapshot.json"))]);
    let v = summary(&out);
    let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        ["command", "engine", "exit", "schema", "semantic", "state"],
        "keys are in ascending order"
    );
    assert_eq!(v["schema"], "pii-eval-summary/1");
    // No timestamps and no paths in the semantic part.
    let text = v["semantic"].to_string();
    assert!(!text.contains(s(&repo_root())));
}
