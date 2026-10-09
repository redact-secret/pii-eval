//! The `pii-eval-evidence` commands: `verify`, `import` and `plan`.
//!
//! A separate binary from `pii-eval` on purpose: the five-command CLI contract
//! (docs/cli.md) stays as it is, and the evidence consumer is a population
//! authoring step that runs BEFORE `pii-eval run`. Like the main CLI, stdout is
//! one JSON line, stderr one fixed-vocabulary line, and no input text, matched
//! value or path is ever printed.
//!
//! ```text
//! pii-eval-evidence verify --snapshot-dir DIR --pin FILE
//! pii-eval-evidence import --snapshot-dir DIR --pin FILE --out DIR
//! pii-eval-evidence plan   --config FILE [--node PATH] [--replays N] [--activation SELECTORS]
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use pii_eval_contracts::{
    CorpusSnapshot, ENGINE_NAME, ENGINE_VERSION, Sha256Digest, parse_default, to_pretty_json,
};
use serde_json::{Map, Value, json};

use super::files::read_dir;
use super::map::{binding_json, map, map_semantic, snapshot_json};
use super::pin::SnapshotPin;
use super::plan::{default_limits, manifest, plans_from_config_with_activation};
use super::verify::{Verified, verify};
use super::{CONTRACT_NAME, CONTRACT_VERSION, EvidenceError, reason};
use crate::config::{MAX_CONFIG_BYTES, RunConfig};
use crate::files::read_input;
use crate::status::Exit;

/// `schema` of the summary line.
pub const SUMMARY_SCHEMA: &str = "pii-eval-evidence-summary/1";
/// Usage text.
pub const USAGE: &str = "usage: pii-eval-evidence verify --snapshot-dir DIR --pin FILE | \
import --snapshot-dir DIR --pin FILE --out DIR [--mapping-revision 3] | plan --config FILE [--node PATH] [--replays N] [--activation SELECTORS]";

/// The rendered result of one invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    /// Exit status.
    pub exit: Exit,
    /// One JSON line.
    pub stdout: String,
    /// A fixed-vocabulary diagnostic (empty on success).
    pub stderr: String,
}

fn usage(detail: &str) -> EvidenceError {
    EvidenceError {
        code: "usage",
        exit: Exit::Usage,
        at: detail.to_owned(),
    }
}

fn parse_options(
    args: &[String],
    allowed: &[&str],
) -> Result<BTreeMap<String, String>, EvidenceError> {
    let mut out = BTreeMap::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let Some(name) = a.strip_prefix("--") else {
            return Err(usage("unexpected-argument"));
        };
        if !allowed.contains(&name) {
            return Err(usage("unknown-option"));
        }
        let value = it.next().ok_or_else(|| usage("missing-value"))?;
        if out.insert(name.to_owned(), value.clone()).is_some() {
            return Err(usage("duplicate-option"));
        }
    }
    Ok(out)
}

fn required<'a>(o: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str, EvidenceError> {
    o.get(name)
        .map(String::as_str)
        .ok_or_else(|| usage("missing-required-option"))
}

fn read_pin(path: &str) -> Result<SnapshotPin, EvidenceError> {
    let bytes = read_input(Path::new(path), 1 << 20, "pin")
        .map_err(|_| EvidenceError::invalid(reason::PIN_INVALID, "pin"))?;
    SnapshotPin::parse(&bytes)
}

fn load(o: &BTreeMap<String, String>) -> Result<(SnapshotPin, Verified), EvidenceError> {
    let pin = read_pin(required(o, "pin")?)?;
    let files = read_dir(Path::new(required(o, "snapshot-dir")?))?;
    let verified = verify(&files, &pin)?;
    Ok((pin, verified))
}

fn sha_of(text: &str) -> String {
    Sha256Digest::of_bytes(text.as_bytes()).as_str().to_owned()
}

fn verified_summary(v: &Verified) -> Value {
    json!({
        "contract": {"name": CONTRACT_NAME, "version": CONTRACT_VERSION},
        "snapshotId": v.manifest.id,
        "contentDigest": v.manifest.content_digest,
        "manifestSha256": v.manifest_sha256,
        "population": v.manifest.population,
        "counts": {
            "cases": v.cases.len(),
            "fixtures": v.fixtures.len(),
            "skipped": v.skipped.len(),
        },
    })
}

fn run(command: &str, args: &[String]) -> Result<(Value, Option<Value>), EvidenceError> {
    match command {
        "verify" => {
            let o = parse_options(args, &["snapshot-dir", "pin"])?;
            let (_, v) = load(&o)?;
            Ok((verified_summary(&v), None))
        }
        "import" => {
            let o = parse_options(args, &["snapshot-dir", "pin", "out", "mapping-revision"])?;
            let out = PathBuf::from(required(&o, "out")?);
            let (pin, v) = load(&o)?;
            let mapped = match o.get("mapping-revision").map(String::as_str) {
                None => map(&v, &pin)?,
                Some("3") => map_semantic(&v, &pin)?,
                _ => return Err(usage("invalid-mapping-revision")),
            };
            let snapshot = snapshot_json(&mapped)?;
            let binding = binding_json(&mapped)?;
            if out.exists() && std::fs::read_dir(&out).map_or(true, |mut d| d.next().is_some()) {
                return Err(EvidenceError::invalid(
                    reason::MAPPING_INVALID,
                    "output-not-empty",
                ));
            }
            std::fs::create_dir_all(&out)
                .and_then(|()| std::fs::write(out.join("snapshot.json"), &snapshot))
                .and_then(|()| std::fs::write(out.join("binding.json"), &binding))
                .map_err(|_| {
                    EvidenceError::invalid(reason::MAPPING_INVALID, "output-unwritable")
                })?;
            let mut semantic = verified_summary(&v);
            semantic["population"] = json!({
                "id": mapped.snapshot.semantic.population.population_id.as_str(),
                "version": mapped.snapshot.semantic.population.population_version,
                "semanticDigest": mapped.snapshot.semantic_digest.as_str(),
                "schemaVersion": mapped.snapshot.schema_version.to_string(),
                "visibility": "public-synthetic",
            });
            semantic["binding"] = json!({
                "semanticDigest": mapped.binding["semanticDigest"],
                "counts": mapped.binding["semantic"]["counts"],
                "losses": mapped.binding["semantic"]["losses"],
            });
            let outputs = json!({
                "snapshot.json": {"bytes": snapshot.len(), "sha256": sha_of(&snapshot)},
                "binding.json": {"bytes": binding.len(), "sha256": sha_of(&binding)},
            });
            Ok((semantic, Some(outputs)))
        }
        "plan" => {
            let o = parse_options(args, &["config", "node", "replays", "activation"])?;
            let config_path = PathBuf::from(required(&o, "config")?);
            let bytes = read_input(&config_path, MAX_CONFIG_BYTES, "run-config")
                .map_err(|_| EvidenceError::invalid(reason::PLAN_INVALID, "run-config"))?;
            let base = config_path.parent().unwrap_or_else(|| Path::new("."));
            let config = RunConfig::parse(&bytes, base)
                .map_err(|_| EvidenceError::invalid(reason::PLAN_INVALID, "run-config"))?;
            let snapshot_bytes = read_input(
                &config.snapshot.path,
                pii_eval_contracts::limits::MAX_DOCUMENT_BYTES,
                "snapshot",
            )
            .map_err(|_| EvidenceError::invalid(reason::PLAN_INVALID, "snapshot"))?;
            let snapshot: CorpusSnapshot = parse_default(&snapshot_bytes)
                .map_err(|_| EvidenceError::invalid(reason::PLAN_INVALID, "snapshot"))?;
            let replays: u32 = match o.get("replays") {
                Some(r) => r.parse().map_err(|_| usage("invalid-option-value"))?,
                None => 2,
            };
            let node = o.get("node").map(PathBuf::from);
            let plans = plans_from_config_with_activation(
                &config,
                &snapshot,
                node.as_deref(),
                o.get("activation").map(String::as_str),
            )?;
            let manifest = manifest(&snapshot, plans, default_limits(), replays)?;
            let text = to_pretty_json(&manifest)
                .map_err(|_| EvidenceError::invalid(reason::PLAN_INVALID, "manifest"))?;
            if config.manifest.path.exists() {
                return Err(EvidenceError::invalid(
                    reason::PLAN_INVALID,
                    "manifest-exists",
                ));
            }
            std::fs::write(&config.manifest.path, &text)
                .map_err(|_| EvidenceError::invalid(reason::PLAN_INVALID, "manifest-unwritable"))?;
            Ok((
                json!({
                    "manifestSemanticDigest": manifest.semantic_digest.as_str(),
                    "populationDigest": snapshot.semantic_digest.as_str(),
                    "scanners": manifest.semantic.scanners.len(),
                }),
                Some(json!({"manifest.json": {"bytes": text.len(), "sha256": sha_of(&text)}})),
            ))
        }
        _ => Err(usage("unknown-command")),
    }
}

/// Execute one invocation.
pub fn execute(args: &[String]) -> Rendered {
    let mut envelope = Map::new();
    envelope.insert("schema".into(), json!(SUMMARY_SCHEMA));
    envelope.insert(
        "engine".into(),
        json!({"name": ENGINE_NAME, "version": ENGINE_VERSION}),
    );
    let Some(command) = args.first() else {
        return finish(envelope, None, Err(usage("missing-command")));
    };
    envelope.insert("command".into(), json!(command));
    let result = run(command, &args[1..]);
    finish(envelope, Some(command.as_str()), result)
}

fn finish(
    mut envelope: Map<String, Value>,
    _command: Option<&str>,
    result: Result<(Value, Option<Value>), EvidenceError>,
) -> Rendered {
    let (exit, stderr) = match result {
        Ok((semantic, outputs)) => {
            envelope.insert("state".into(), json!("accepted"));
            envelope.insert("semantic".into(), semantic);
            if let Some(outputs) = outputs {
                envelope.insert("outputs".into(), outputs);
            }
            (Exit::Success, String::new())
        }
        Err(e) => {
            envelope.insert("state".into(), json!("refused"));
            envelope.insert("error".into(), json!({"reason": e.code, "at": e.at}));
            let mut line = e.human();
            line.push('\n');
            if e.exit == Exit::Usage {
                line.push_str(USAGE);
                line.push('\n');
            }
            (e.exit, line)
        }
    };
    envelope.insert(
        "exit".into(),
        json!({"code": exit.code(), "name": exit.name()}),
    );
    let mut stdout = serde_json::to_string(&Value::Object(envelope)).unwrap_or_default();
    stdout.push('\n');
    Rendered {
        exit,
        stdout,
        stderr,
    }
}
