//! Helpers for the end-to-end CLI tests: the built binary, the inert fake
//! scanner package, run configurations and synthetic documents. Synthetic only.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

use pii_eval_adapters::redact_secret::{
    CoreAdapterConfig, CorePin, PINNED_VERSION, SHIM_SHA256, core_adapter, parameters,
    shim_path_in_source_tree,
};
use pii_eval_adapters::{AdapterLimits, ScannerAdapter, sha256_of_tree};
use pii_eval_contracts::{
    ActivationSelector, CorpusSnapshot, ExecutionLimits, Mechanics, RunManifest,
    ScannerConfiguration, Sha256Digest, VersionString, parse_default, to_pretty_json,
};
use serde_json::Value;

pub fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pii-eval")
}

pub fn repo_root() -> PathBuf {
    std::fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .expect("repository root")
}

pub fn example_dir() -> PathBuf {
    repo_root().join("examples/quickstart")
}

pub fn fake_core_dir() -> PathBuf {
    repo_root().join("crates/pii-eval-adapters/tests/fixtures/fake-core")
}

pub fn shim_path() -> PathBuf {
    std::fs::canonicalize(shim_path_in_source_tree()).expect("shim exists")
}

/// Node, or `None` after printing why (and a panic when CI requires it).
pub fn node() -> Option<PathBuf> {
    let found = std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|d| d.join("node"))
            .find(|p| p.is_file())
    });
    if found.is_none() {
        assert!(
            std::env::var("PII_EVAL_REQUIRE_NODE").as_deref() != Ok("1"),
            "node is required (PII_EVAL_REQUIRE_NODE=1) but was not found"
        );
        eprintln!("SKIPPED: node not found on PATH");
    }
    found
}

#[macro_export]
macro_rules! node_or_return {
    () => {
        match $crate::cli_support::node() {
            Some(n) => n,
            None => return,
        }
    };
}

pub fn run_cli(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .env_remove("PII_EVAL_JOB_CONTEXT")
        .output()
        .expect("binary runs")
}

pub fn run_cli_env(args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(bin());
    cmd.args(args).env_remove("PII_EVAL_JOB_CONTEXT");
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("binary runs")
}

pub fn code(out: &Output) -> i32 {
    out.status.code().expect("exited normally")
}

pub fn summary(out: &Output) -> Value {
    let text = String::from_utf8(out.stdout.clone()).expect("stdout is UTF-8");
    assert!(
        text.ends_with('\n') && text.matches('\n').count() == 1,
        "stdout is exactly one line: {text:?}"
    );
    serde_json::from_str(&text).expect("stdout is JSON")
}

pub fn stderr(out: &Output) -> String {
    String::from_utf8(out.stderr.clone()).expect("stderr is UTF-8")
}

pub fn s(p: &Path) -> &str {
    p.to_str().expect("UTF-8 path")
}

pub fn read_snapshot(path: &Path) -> CorpusSnapshot {
    parse_default(&std::fs::read(path).unwrap()).expect("snapshot parses")
}

/// The scanner configuration the example and the tests use.
pub fn core_configuration() -> ScannerConfiguration {
    ScannerConfiguration {
        parameters: parameters(),
        activation: vec![
            ActivationSelector::new("pii:global").unwrap(),
            ActivationSelector::new("pii:us").unwrap(),
        ],
    }
}

/// An adapter over the inert fake core package (used only to derive the plan).
pub fn core_adapter_for(package: &Path, node: &Path) -> Arc<dyn ScannerAdapter> {
    core_adapter_versioned(package, node, PINNED_VERSION)
}

/// Like [`core_adapter_for`] with a pinned version the package does not report
/// (a scanner whose startup identity check fails).
pub fn core_adapter_versioned(
    package: &Path,
    node: &Path,
    version: &str,
) -> Arc<dyn ScannerAdapter> {
    let tree = sha256_of_tree(package).unwrap();
    Arc::new(
        core_adapter(CoreAdapterConfig {
            node: node.to_path_buf(),
            shim: shim_path(),
            package_dir: package.to_path_buf(),
            entry_relative: "lib/index.js".into(),
            pin: CorePin::candidate(VersionString::new(version).unwrap(), tree),
            shim_sha256: Sha256Digest::new(SHIM_SHA256).unwrap(),
            extra_artifacts: Vec::new(),
            limits: AdapterLimits::default(),
        })
        .expect("adapter spec"),
    )
}

pub fn limits(workers: u32, per_scanner: u32) -> ExecutionLimits {
    ExecutionLimits {
        workers,
        per_scanner_parallelism: per_scanner,
        pending_tasks: 4,
        batch_variants: 1,
        scanner_timeout_ms: 120_000,
        max_stdout_bytes: 16 << 20,
        max_stderr_bytes: 1 << 20,
        max_memory_bytes: 16 << 30,
        max_temporary_bytes: 4 << 30,
    }
}

/// A revision-2 manifest for the snapshot and one fake-core scanner.
pub fn manifest_for(
    snapshot: &CorpusSnapshot,
    package: &Path,
    node: &Path,
    limits: ExecutionLimits,
    replays: u32,
) -> RunManifest {
    manifest_versioned(snapshot, package, node, limits, replays, PINNED_VERSION)
}

pub fn manifest_versioned(
    snapshot: &CorpusSnapshot,
    package: &Path,
    node: &Path,
    limits: ExecutionLimits,
    replays: u32,
    version: &str,
) -> RunManifest {
    let adapter = core_adapter_versioned(package, node, version);
    let plan = adapter.plan(core_configuration()).expect("plan");
    crate::common::manifest(
        snapshot,
        vec![plan],
        limits,
        Mechanics {
            replays,
            ..Mechanics::PII_V1
        },
    )
}

pub fn write_manifest(path: &Path, manifest: &RunManifest) {
    std::fs::write(path, to_pretty_json(manifest).unwrap()).unwrap();
}

/// A run configuration for the fake core package, as JSON text.
pub struct ConfigSpec<'a> {
    pub snapshot: &'a Path,
    pub manifest: &'a Path,
    pub package: &'a Path,
    pub snapshot_digest: Option<&'a str>,
    pub manifest_digest: Option<&'a str>,
    pub mode: &'a str,
    pub run_class: &'a str,
    pub product: &'a str,
    pub max_workers: u32,
    pub resources: &'a str,
    pub extra_top: &'a str,
}

impl<'a> ConfigSpec<'a> {
    pub fn new(snapshot: &'a Path, manifest: &'a Path, package: &'a Path) -> Self {
        Self {
            snapshot,
            manifest,
            package,
            snapshot_digest: None,
            manifest_digest: None,
            mode: "exploratory",
            run_class: "public-synthetic",
            product: "candidate",
            max_workers: 2,
            resources: "enforce",
            extra_top: "",
        }
    }

    pub fn json(&self) -> String {
        self.json_for(PINNED_VERSION)
    }

    pub fn json_for(&self, version: &str) -> String {
        let tree = sha256_of_tree(self.package).unwrap();
        let pin = |digest: Option<&str>| {
            digest.map_or(String::new(), |d| format!(r#","semanticDigest":"{d}""#))
        };
        format!(
            r#"{{
  "schema": "pii-eval-run-config/1",
  "mode": "{mode}",
  "runClass": "{run_class}",
  "product": "{product}",
  "snapshot": {{"path": "{snapshot}"{sd}}},
  "manifest": {{"path": "{manifest}"{md}}},
  "scanners": [{{
    "adapter": "redact-secret-core",
    "shim": {{"path": "{shim}"}},
    "package": {{"dir": "{package}", "entry": "lib/index.js", "version": "{version}", "treeSha256": "{tree}"}}
  }}],
  "host": {{"maxWorkers": {workers}, "resources": "{resources}"}}{extra}
}}
"#,
            mode = self.mode,
            run_class = self.run_class,
            product = self.product,
            snapshot = s(self.snapshot),
            manifest = s(self.manifest),
            sd = pin(self.snapshot_digest),
            md = pin(self.manifest_digest),
            shim = s(&shim_path()),
            package = s(self.package),
            version = version,
            tree = tree.as_str(),
            workers = self.max_workers,
            resources = self.resources,
            extra = self.extra_top,
        )
    }
}

pub fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// A scratch workspace with the example snapshot, a manifest for the fake core
/// package, and an exploratory configuration.
pub struct Workspace {
    pub tmp: crate::common::TempDir,
    pub snapshot: PathBuf,
    pub manifest: PathBuf,
    pub config: PathBuf,
    pub package: PathBuf,
    pub node: PathBuf,
}

impl Workspace {
    pub fn new(label: &str, node: &Path) -> Self {
        Self::with(label, node, limits(2, 1), 2, PINNED_VERSION)
    }

    pub fn with(
        label: &str,
        node: &Path,
        limits: ExecutionLimits,
        replays: u32,
        version: &str,
    ) -> Self {
        let tmp = crate::common::TempDir::new(label);
        let snapshot = tmp.0.join("snapshot.json");
        std::fs::copy(example_dir().join("snapshot.json"), &snapshot).unwrap();
        let package = tmp.0.join("package");
        copy_dir(&fake_core_dir(), &package);
        let manifest = tmp.0.join("manifest.json");
        let parsed = read_snapshot(&snapshot);
        write_manifest(
            &manifest,
            &manifest_versioned(&parsed, &package, node, limits, replays, version),
        );
        let config = tmp.0.join("run-config.json");
        std::fs::write(
            &config,
            ConfigSpec::new(&snapshot, &manifest, &package).json_for(version),
        )
        .unwrap();
        Workspace {
            tmp,
            snapshot,
            manifest,
            config,
            package,
            node: node.to_path_buf(),
        }
    }

    pub fn out(&self, name: &str) -> PathBuf {
        self.tmp.0.join(name)
    }

    pub fn run(&self, out: &Path) -> std::process::Output {
        run_cli(&[
            "run",
            "--config",
            s(&self.config),
            "--node",
            s(&self.node),
            "--out",
            s(out),
        ])
    }
}

pub fn list_dir(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}
