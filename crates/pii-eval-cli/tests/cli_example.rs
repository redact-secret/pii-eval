//! The clean-checkout example (`examples/quickstart/`) and the command
//! sequence documented in `docs/cli.md`, run end to end through the built
//! binary. Offline, synthetic data only, the inert fake scanner package.
//!
//! Regenerate the committed example documents after an intentional change with
//! `PII_EVAL_UPDATE_FIXTURES=1 cargo test -p pii-eval-cli --test cli_example`.
#![cfg(unix)]

mod cli_support;
mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use cli_support::*;
use common::TempDir;
use pii_eval_adapters::sha256_of_tree;
use pii_eval_contracts::{ENGINE_VERSION, to_pretty_json};

const FAKE_CORE_REL: &str = "../../crates/pii-eval-adapters/tests/fixtures/fake-core";
const SHIM_REL: &str = "../../crates/pii-eval-adapters/shims/node/redact-secret-core.mjs";

/// `projection` is `None` for no projection, else the roster pin (`""` for none).
fn config_text(
    official: bool,
    snapshot_digest: &str,
    manifest_digest: &str,
    tree: &str,
    projection: Option<&str>,
) -> String {
    let pins = if official {
        format!(
            r#"  "engineVersion": "{ENGINE_VERSION}",
  "protocol": {{"id": "pii-v1", "revision": 2}},
  "snapshot": {{"path": "snapshot.json", "semanticDigest": "{snapshot_digest}"}},
  "manifest": {{"path": "manifest.json", "semanticDigest": "{manifest_digest}"}},
"#
        )
    } else {
        "  \"snapshot\": {\"path\": \"snapshot.json\"},\n  \"manifest\": {\"path\": \"manifest.json\"},\n"
            .to_owned()
    };
    format!(
        r#"{{
  "schema": "pii-eval-run-config/1",
  "mode": "{mode}",
  "runClass": "public-synthetic",
  "product": "candidate",
{pins}  "scanners": [
    {{
      "adapter": "redact-secret-core",
      "shim": {{"path": "{SHIM_REL}"}},
      "package": {{
        "dir": "{FAKE_CORE_REL}",
        "entry": "lib/index.js",
        "version": "0.1.0-beta.12",
        "treeSha256": "{tree}"
      }}
    }}
  ],
  "host": {{"maxWorkers": 2, "resources": "enforce"}}{projection}
}}
"#,
        mode = if official { "official" } else { "exploratory" },
        projection = match projection {
            None => String::new(),
            Some("") => ",\n  \"projection\": {\"roster\": {\"path\": \"projection-roster.json\"}}"
                .to_owned(),
            Some(d) => format!(
                ",\n  \"projection\": {{\"roster\": {{\"path\": \"projection-roster.json\", \"rosterDigest\": \"{d}\"}}}}"
            ),
        },
    )
}

/// What the example directory must contain, generated from the real adapter
/// plan: (file name, bytes).
fn generated_example() -> Vec<(&'static str, Vec<u8>)> {
    let snapshot = read_snapshot(&example_dir().join("snapshot.json"));
    // Only the plan is derived here (no process starts), so any existing
    // absolute executable satisfies the adapter specification.
    let exe = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
    let manifest = manifest_for(&snapshot, &fake_core_dir(), &exe, limits(2, 1), 2);
    let tree = sha256_of_tree(&fake_core_dir()).unwrap();
    let roster = pii_eval_cli::projection::load_roster(
        &example_dir().join("projection-roster.json"),
        &snapshot,
        None,
    )
    .expect("the example roster binds to the example snapshot");
    vec![
        (
            "manifest.json",
            to_pretty_json(&manifest).unwrap().into_bytes(),
        ),
        (
            "run-config.json",
            config_text(false, "", "", tree.as_str(), None).into_bytes(),
        ),
        (
            "run-config.projection.json",
            config_text(false, "", "", tree.as_str(), Some("")).into_bytes(),
        ),
        (
            "run-config.official.projection.json",
            config_text(
                true,
                snapshot.semantic_digest.as_str(),
                manifest.semantic_digest.as_str(),
                tree.as_str(),
                Some(roster.digest().as_str()),
            )
            .into_bytes(),
        ),
        (
            "run-config.official.json",
            config_text(
                true,
                snapshot.semantic_digest.as_str(),
                manifest.semantic_digest.as_str(),
                tree.as_str(),
                None,
            )
            .into_bytes(),
        ),
    ]
}

#[test]
fn committed_example_documents_equal_what_the_engine_derives() {
    let update = std::env::var("PII_EVAL_UPDATE_FIXTURES").is_ok_and(|v| v == "1");
    for (name, bytes) in generated_example() {
        let path = example_dir().join(name);
        if update {
            std::fs::write(&path, &bytes).unwrap();
        }
        let committed = std::fs::read(&path).unwrap_or_else(|_| {
            panic!("missing examples/quickstart/{name}; run with PII_EVAL_UPDATE_FIXTURES=1")
        });
        assert_eq!(committed, bytes, "examples/quickstart/{name} drifted");
    }
}

/// The fenced shell block that follows the `quickstart-commands` marker of
/// docs/cli.md, as one argument vector per `pii-eval` command.
fn documented_commands() -> Vec<Vec<String>> {
    let doc = std::fs::read_to_string(repo_root().join("docs/cli.md")).expect("docs/cli.md");
    let after = doc
        .split("<!-- quickstart-commands -->")
        .nth(1)
        .expect("marker present");
    let block = after
        .split("```sh")
        .nth(1)
        .expect("sh block")
        .split("```")
        .next()
        .unwrap();
    let mut commands = Vec::new();
    let mut joined = String::new();
    for line in block.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(prefix) = line.strip_suffix('\\') {
            joined.push_str(prefix);
            joined.push(' ');
            continue;
        }
        joined.push_str(line);
        if joined.trim_start().starts_with("pii-eval ") {
            commands.push(
                joined
                    .split_whitespace()
                    .skip(1)
                    .map(|w| w.trim_matches('"').to_owned())
                    .collect(),
            );
        }
        joined.clear();
    }
    commands
}

fn substitute(arg: &str, node: &Path, out: &Path) -> String {
    arg.replace("$NODE", s(node)).replace("$OUT", s(out))
}

#[test]
fn the_documented_quickstart_sequence_runs_offline_and_every_step_succeeds() {
    let node = node_or_return!();
    let tmp = TempDir::new("quickstart");
    let out: PathBuf = tmp.0.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let commands = documented_commands();
    assert!(
        commands.len() >= 8,
        "the documented sequence is not trivial"
    );
    let mut seen = Vec::new();
    for args in &commands {
        let args: Vec<String> = args.iter().map(|a| substitute(a, &node, &out)).collect();
        seen.push(args[0].clone());
        let output = Command::new(bin())
            .args(&args)
            .current_dir(repo_root())
            .env_remove("PII_EVAL_JOB_CONTEXT")
            // Offline by construction: no proxy, no registry, nothing to reach.
            .env("NO_PROXY", "*")
            .output()
            .expect("binary runs");
        assert_eq!(
            code(&output),
            0,
            "documented command failed: {} -> {}\n{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            stderr(&output)
        );
        let value = self::summary(&output);
        assert_eq!(value["exit"]["code"], 0);
    }
    for command in ["run", "replay", "validate", "compare"] {
        assert!(seen.iter().any(|c| c == command), "{command} is documented");
    }
    // The documented outputs exist.
    for dir in ["run", "replay"] {
        for file in [
            "manifest.json",
            "run-artifact.json",
            "public-synthetic-artifact.json",
        ] {
            assert!(out.join(dir).join(file).is_file(), "{dir}/{file}");
        }
    }
}
