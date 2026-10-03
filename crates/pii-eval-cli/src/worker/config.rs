//! `pii-eval-worker-config/1`: the staged `config` file (PROPOSED, engine-owned,
//! opaque to the custodian; the custodian pins its SHA-256 as the plan's
//! `config_digest`).
//!
//! Closed JSON, strict (no duplicate key, no `null`, no float, no unknown
//! field), at most [`MAX_CONFIG_BYTES`]:
//!
//! ```json
//! {
//!   "schema": "pii-eval-worker-config/1",
//!   "protocol": {"name": "pii-v1", "version": "2"},
//!   "runClass": "protected",
//!   "population": {"digest": "<64 hex: semantic digest of the assembled snapshot>"},
//!   "snapshot": {"population": {...}, "generation": {...}},
//!   "manifest": { ...a complete pii-eval.run-manifest document... },
//!   "product": "candidate",
//!   "artifacts": {
//!     "engine":    {"sha256": "sha256:<hex>"},
//!     "adapter":   {"bundleDigest": "sha256:<hex>"},
//!     "candidate": {"bundleDigest": "sha256:<hex>", "treeDigest": "<hex>",
//!                   "entry": "dist/index.js", "version": "0.1.0-beta.12"},
//!     "runtime":   {"sha256": "sha256:<hex>"}
//!   },
//!   "resources": {"maxWorkers": 2, "startupTimeoutMs": 30000, "callTimeoutMs": 30000}
//! }
//! ```
//!
//! It holds digests and numbers, never a path: every path comes from the stage
//! layout and the fixed staged names, so a hostile configuration can make the
//! run fail but cannot make it read outside stage, input or scratch. `entry` is
//! a relative path of normal components inside the extracted package.
//! `resources` is optional; the executor limits themselves are the manifest's.

use std::path::PathBuf;

use pii_eval_contracts::{
    GenerationRules, ParseLimits, Population, RunClass, RunManifest, VersionString, parse_strict,
    validate,
};
use serde_json::{Map, Value};

use crate::config::ProductKind;
use crate::status::Failure;
use crate::worker::digest::{
    BundleDigest, CustodianDigest, EngineDigest, RuntimeDigest, TreeDigest,
};
use crate::worker::job::{protocol_name, protocol_version};
use crate::worker::reason;

/// `schema` of the worker configuration.
pub const WORKER_CONFIG_SCHEMA: &str = "pii-eval-worker-config/1";
/// Largest configuration, in bytes.
pub const MAX_CONFIG_BYTES: usize = 1 << 20;
/// Most workers a configuration may ask for.
pub const MAX_WORKERS: usize = 64;
/// Longest scanner timeout a configuration may set, in milliseconds.
pub const MAX_TIMEOUT_MS: u64 = 600_000;

/// A parsed worker configuration.
#[derive(Debug, Clone)]
pub struct WorkerConfig {
    /// Claimed run class.
    pub run_class: RunClass,
    /// Population pin: the semantic digest of the assembled snapshot.
    pub population: EngineDigest,
    /// Header the cases are assembled under.
    pub header_population: Population,
    /// Generation rules of the snapshot.
    pub generation: GenerationRules,
    /// The manifest the run executes.
    pub manifest: RunManifest,
    /// Released or candidate.
    pub product: ProductKind,
    /// Engine file pin.
    pub engine: CustodianDigest,
    /// Adapter bundle pin.
    pub adapter_bundle: BundleDigest,
    /// Candidate bundle pin.
    pub candidate_bundle: BundleDigest,
    /// Package tree pin.
    pub tree: TreeDigest,
    /// Entry file relative to the package root.
    pub entry: PathBuf,
    /// Package version.
    pub version: VersionString,
    /// Node runtime pin.
    pub runtime: RuntimeDigest,
    /// Cap on concurrent sessions.
    pub max_workers: usize,
    /// Scanner startup timeout.
    pub startup_timeout_ms: Option<u64>,
    /// Scan call timeout.
    pub call_timeout_ms: Option<u64>,
}

fn bad(detail: &str) -> Failure {
    reason::invalid(reason::WORKER_CONFIG_INVALID, detail)
}

fn object<'a>(
    v: &'a Value,
    at: &str,
    required: &[&str],
    optional: &[&str],
) -> Result<&'a Map<String, Value>, Failure> {
    let m = v.as_object().ok_or_else(|| bad(at))?;
    let known = |k: &String| required.contains(&k.as_str()) || optional.contains(&k.as_str());
    if m.keys().any(|k| !known(k)) || required.iter().any(|k| !m.contains_key(*k)) {
        return Err(bad(at));
    }
    Ok(m)
}

fn text<'a>(m: &'a Map<String, Value>, key: &str, at: &str) -> Result<&'a str, Failure> {
    m.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| bad(&format!("{at}.{key}")))
}

/// Parse and check a worker configuration.
pub fn parse(bytes: &[u8]) -> Result<WorkerConfig, Failure> {
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(reason::invalid(reason::WORKER_CONFIG_TOO_LARGE, ""));
    }
    let value = parse_strict(
        bytes,
        &ParseLimits {
            max_bytes: MAX_CONFIG_BYTES,
            max_depth: 32,
        },
    )
    .map_err(|_| bad("json"))?;
    let top = object(
        &value,
        "config",
        &[
            "schema",
            "protocol",
            "runClass",
            "population",
            "snapshot",
            "manifest",
            "product",
            "artifacts",
        ],
        &["resources"],
    )?;
    if text(top, "schema", "config")? != WORKER_CONFIG_SCHEMA {
        return Err(bad("schema"));
    }
    let protocol = object(&top["protocol"], "protocol", &["name", "version"], &[])?;
    if text(protocol, "name", "protocol")? != protocol_name()
        || text(protocol, "version", "protocol")? != protocol_version()
    {
        return Err(reason::mismatch(reason::JOB_PROTOCOL_MISMATCH, "config"));
    }
    let run_class = match text(top, "runClass", "config")? {
        "protected" => RunClass::Protected,
        "public-synthetic" => RunClass::PublicSynthetic,
        _ => return Err(bad("runClass")),
    };
    let population = object(&top["population"], "population", &["digest"], &[])?;
    let population = EngineDigest::parse(text(population, "digest", "population")?)
        .map_err(|_| bad("population.digest"))?;
    let header = object(
        &top["snapshot"],
        "snapshot",
        &["population", "generation"],
        &[],
    )?;
    let header_population: Population = serde_json::from_value(header["population"].clone())
        .map_err(|_| bad("snapshot.population"))?;
    let generation: GenerationRules = serde_json::from_value(header["generation"].clone())
        .map_err(|_| bad("snapshot.generation"))?;
    let manifest: RunManifest =
        serde_json::from_value(top["manifest"].clone()).map_err(|_| bad("manifest"))?;
    validate(&manifest).map_err(|_| bad("manifest"))?;
    let product = match text(top, "product", "config")? {
        "released" => ProductKind::Released,
        "candidate" => ProductKind::Candidate,
        _ => return Err(bad("product")),
    };

    let artifacts = object(
        &top["artifacts"],
        "artifacts",
        &["engine", "adapter", "candidate", "runtime"],
        &[],
    )?;
    let digest_field = |obj: &Map<String, Value>, key: &str, at: &str| {
        CustodianDigest::parse(text(obj, key, at)?).map_err(|_| bad(&format!("{at}.{key}")))
    };
    let engine = object(&artifacts["engine"], "artifacts.engine", &["sha256"], &[])?;
    let engine = digest_field(engine, "sha256", "artifacts.engine")?;
    let adapter = object(
        &artifacts["adapter"],
        "artifacts.adapter",
        &["bundleDigest"],
        &[],
    )?;
    let adapter_bundle =
        BundleDigest::new(digest_field(adapter, "bundleDigest", "artifacts.adapter")?);
    let candidate = object(
        &artifacts["candidate"],
        "artifacts.candidate",
        &["bundleDigest", "treeDigest", "entry", "version"],
        &[],
    )?;
    let candidate_bundle = BundleDigest::new(digest_field(
        candidate,
        "bundleDigest",
        "artifacts.candidate",
    )?);
    let tree = TreeDigest::parse(text(candidate, "treeDigest", "artifacts.candidate")?)
        .map_err(|_| bad("artifacts.candidate.treeDigest"))?;
    let entry = text(candidate, "entry", "artifacts.candidate")?;
    let entry_path = std::path::Path::new(entry);
    let entry_ok = !entry.is_empty()
        && !entry.contains('\0')
        && entry_path.is_relative()
        && entry_path
            .components()
            .all(|c| matches!(c, std::path::Component::Normal(_)));
    if !entry_ok {
        return Err(bad("artifacts.candidate.entry"));
    }
    let version = VersionString::new(text(candidate, "version", "artifacts.candidate")?)
        .map_err(|_| bad("artifacts.candidate.version"))?;
    let runtime = object(&artifacts["runtime"], "artifacts.runtime", &["sha256"], &[])?;
    let runtime = RuntimeDigest::new(digest_field(runtime, "sha256", "artifacts.runtime")?);

    let mut max_workers = 1usize;
    let (mut startup_timeout_ms, mut call_timeout_ms) = (None, None);
    if let Some(r) = top.get("resources") {
        let r = object(
            r,
            "resources",
            &[],
            &["maxWorkers", "startupTimeoutMs", "callTimeoutMs"],
        )?;
        let number = |key: &str, max: u64| -> Result<Option<u64>, Failure> {
            match r.get(key) {
                None => Ok(None),
                Some(v) => v
                    .as_u64()
                    .filter(|n| (1..=max).contains(n))
                    .map(Some)
                    .ok_or_else(|| bad(&format!("resources.{key}"))),
            }
        };
        if let Some(n) = number("maxWorkers", MAX_WORKERS as u64)? {
            max_workers = n as usize;
        }
        startup_timeout_ms = number("startupTimeoutMs", MAX_TIMEOUT_MS)?;
        call_timeout_ms = number("callTimeoutMs", MAX_TIMEOUT_MS)?;
    }
    Ok(WorkerConfig {
        run_class,
        population,
        header_population,
        generation,
        manifest,
        product,
        engine,
        adapter_bundle,
        candidate_bundle,
        tree,
        entry: PathBuf::from(entry),
        version,
        runtime,
        max_workers,
        startup_timeout_ms,
        call_timeout_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_configurations_fail_with_the_fixed_reason_and_no_echo() {
        let secret = "zq-secret-7731";
        for bytes in [
            "".to_owned(),
            "null".to_owned(),
            "{}".to_owned(),
            format!(r#"{{"{secret}":1}}"#),
            format!(r#"{{"schema":"pii-eval-worker-config/1","{secret}":1}}"#),
        ] {
            let f = parse(bytes.as_bytes()).unwrap_err();
            assert_eq!(f.reason, reason::WORKER_CONFIG_INVALID);
            assert!(!f.human().contains(secret));
        }
        let big = vec![b' '; MAX_CONFIG_BYTES + 1];
        assert_eq!(
            parse(&big).unwrap_err().reason,
            reason::WORKER_CONFIG_TOO_LARGE
        );
    }
}
