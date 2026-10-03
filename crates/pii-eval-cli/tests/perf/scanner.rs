//! Scanner startup and execution measurements, and the documents for a full
//! `pii-eval run` (P10, ADR 0013). Separate from the kernel measurements on purpose:
//! these include a Node process, the shim and the scanner package.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use pii_eval_adapters::redact_secret::{
    CoreAdapterConfig, CorePin, PINNED_VERSION, REAL_ENTRY_RELATIVE, RELEASED_PACKAGE_TREE_SHA256,
    SHIM_SHA256, core_adapter, parameters, shim_path_in_source_tree,
};
use pii_eval_adapters::{AdapterLimits, ScannerAdapter, sha256_of_tree};
use pii_eval_contracts::{
    ActivationSelector, ScannerConfiguration, Sha256Digest, VersionString, to_pretty_json,
};
use serde_json::{Value, json};

use crate::perf::{Workload, manifest_of, prepare};

fn node_path() -> PathBuf {
    let path = std::env::var_os("PATH").expect("PATH");
    let found = std::env::split_paths(&path)
        .map(|d| d.join("node"))
        .find(|p| p.is_file())
        .expect("node on PATH");
    std::fs::canonicalize(found).expect("node path")
}

fn configuration() -> ScannerConfiguration {
    ScannerConfiguration {
        parameters: parameters(),
        activation: vec![
            ActivationSelector::new("pii:global").unwrap(),
            ActivationSelector::new("pii:us").unwrap(),
        ],
    }
}

/// `pin`: `candidate` (the inert fake package, entry `lib/index.js`, identified by
/// its tree digest) or `released` (the real `@redact-secret/core` 0.1.0-beta.12,
/// entry `dist/index.js`, the released tree digest).
pub fn adapter_for(package: &Path, pin: &str) -> (Arc<dyn ScannerAdapter>, &'static str) {
    let package = &std::fs::canonicalize(package).expect("package directory");
    let (entry, core_pin) = match pin {
        "candidate" => {
            let tree = sha256_of_tree(package).expect("package tree");
            (
                "lib/index.js",
                CorePin::candidate(VersionString::new(PINNED_VERSION).unwrap(), tree),
            )
        }
        "released" => (REAL_ENTRY_RELATIVE, CorePin::released_beta12()),
        other => panic!("unknown pin {other}"),
    };
    let adapter = core_adapter(CoreAdapterConfig {
        node: node_path(),
        shim: std::fs::canonicalize(shim_path_in_source_tree()).expect("shim"),
        package_dir: package.to_path_buf(),
        entry_relative: entry.into(),
        pin: core_pin,
        shim_sha256: Sha256Digest::new(SHIM_SHA256).unwrap(),
        extra_artifacts: Vec::new(),
        limits: AdapterLimits::default(),
    })
    .expect("adapter specification");
    (Arc::new(adapter), entry)
}

fn stats(mut v: Vec<f64>) -> Value {
    v.sort_by(f64::total_cmp);
    let n = v.len();
    if n == 0 {
        return json!({ "n": 0 });
    }
    let at = |q: f64| v[((n - 1) as f64 * q).round() as usize];
    json!({ "n": n, "min": v[0], "median": at(0.5), "p95": at(0.95), "max": v[n - 1], "sum": v.iter().sum::<f64>() })
}

/// Startup (plan derivation with pin verification, process spawn and handshake)
/// and per-scan latency through the real process adapter, over `texts` inputs.
pub fn measure_scanner(
    package: &Path,
    pin: &str,
    texts: usize,
    sessions: usize,
    workload: Option<(&Path, &Path)>,
) -> Value {
    let corpus_texts: Vec<String> = match workload {
        Some((w, o)) => {
            let w = crate::perf::load(w, o).expect("workload");
            prepare(&w)
                .corpus
                .variants
                .iter()
                .map(|v| v.variant.text.clone())
                .collect()
        }
        None => (0..64)
            .map(|i| format!("{i}: contact person@example.invalid ssn=123-45-6789 value {i}"))
            .collect(),
    };
    let (adapter, entry) = adapter_for(package, pin);
    let t = Instant::now();
    let plan = adapter.plan(configuration()).expect("plan");
    let plan_ms = t.elapsed().as_secs_f64() * 1000.0;
    let mut startup = Vec::new();
    let mut scan_all = Vec::new();
    let mut per_scan = Vec::new();
    let mut findings = 0u64;
    let mut bytes = 0u64;
    let mut finish = Vec::new();
    for _ in 0..sessions {
        let t = Instant::now();
        let mut session = adapter
            .start(&plan)
            .unwrap_or_else(|_| panic!("scanner start"));
        startup.push(t.elapsed().as_secs_f64() * 1000.0);
        let t_all = Instant::now();
        for i in 0..texts {
            let text = &corpus_texts[i % corpus_texts.len()];
            let t = Instant::now();
            let out = session.scan(text).unwrap_or_else(|_| panic!("scan"));
            per_scan.push(t.elapsed().as_secs_f64() * 1000.0);
            findings += out.findings.len() as u64;
            bytes += text.len() as u64;
        }
        scan_all.push(t_all.elapsed().as_secs_f64() * 1000.0);
        let t = Instant::now();
        let _ = session.finish();
        drop(session);
        finish.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    json!({
        "mode": "scanner", "pin": pin, "entry": entry, "texts": texts, "sessions": sessions,
        "planMs": plan_ms, "startupMs": startup, "scanAllMs": scan_all, "finishMs": finish,
        "perScanMs": stats(per_scan), "findings": findings, "textBytes": bytes,
    })
}

/// Write `snapshot.json`, `manifest.json` and `run-config.json` for a full
/// `pii-eval run --config <dir>/run-config.json --node <node> --out <dir>/out`.
/// The manifest allows `workers` concurrent sessions of its single scanner, and
/// the host cap is the same number, so `workers` is the concurrency of the run.
pub fn emit_cli(
    w: &Workload,
    dir: &Path,
    package: &Path,
    pin: &str,
    workers: u32,
    replays: u32,
) -> Value {
    let p = prepare(w);
    let (adapter, entry) = adapter_for(package, pin);
    let plan = adapter.plan(configuration()).expect("plan");
    let mut p = p;
    p.plans = vec![plan];
    p.scanner_ids = vec!["redact-secret-core".to_owned()];
    let manifest = manifest_of(&p, workers, 2, workers, replays);
    std::fs::create_dir_all(dir).expect("dir");
    let dir = &std::fs::canonicalize(dir).expect("dir");
    let snapshot = dir.join("snapshot.json");
    let manifest_path = dir.join("manifest.json");
    std::fs::write(&snapshot, to_pretty_json(&p.snapshot).unwrap()).unwrap();
    std::fs::write(&manifest_path, to_pretty_json(&manifest).unwrap()).unwrap();
    let package = &std::fs::canonicalize(package).expect("package directory");
    let tree = sha256_of_tree(package).expect("tree");
    let (product, version) = if pin == "released" {
        ("released", PINNED_VERSION)
    } else {
        ("candidate", PINNED_VERSION)
    };
    let _ = RELEASED_PACKAGE_TREE_SHA256;
    let config = format!(
        r#"{{
  "schema": "pii-eval-run-config/1",
  "mode": "exploratory",
  "runClass": "public-synthetic",
  "product": "{product}",
  "snapshot": {{"path": "{snapshot}"}},
  "manifest": {{"path": "{manifest}"}},
  "scanners": [{{
    "adapter": "redact-secret-core",
    "shim": {{"path": "{shim}"}},
    "package": {{"dir": "{package}", "entry": "{entry}", "version": "{version}", "treeSha256": "{tree}"}}
  }}],
  "host": {{"maxWorkers": {workers}, "resources": "enforce", "diagnostics": true}}
}}
"#,
        snapshot = snapshot.display(),
        manifest = manifest_path.display(),
        shim = std::fs::canonicalize(shim_path_in_source_tree())
            .unwrap()
            .display(),
        package = package.display(),
        tree = tree.as_str(),
    );
    std::fs::write(dir.join("run-config.json"), config).unwrap();
    json!({
        "mode": "emit-cli",
        "node": node_path().display().to_string(),
        "workers": workers,
        "snapshotDigest": p.snapshot.semantic_digest.as_str(),
        "manifestDigest": manifest.semantic_digest.as_str(),
        "variants": p.counts.variants, "textBytes": p.counts.text_bytes,
    })
}
