//! Shared helpers for the adapter integration tests. Synthetic only: the
//! scanners are inert fakes under `tests/fixtures`.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use pii_eval_adapters::redact_secret::RedactSecretVocabulary;
use pii_eval_adapters::{
    AdapterLimits, ArtifactPin, ProcessAdapter, ProcessAdapterSpec, ScanSession, ScannerAdapter,
    sha256_of_file, sha256_of_tree,
};
use pii_eval_contracts::{
    ActivationSelector, AdapterIdentity, ConfigKey, ConfigParameter, ConfigValue, ProductIdentity,
    ScannerConfiguration, ScannerId, VersionString,
};
use pii_eval_kernel::OffsetUnit;

/// A string that must never appear in any error, log or serialized artifact.
pub const SENTINEL: &str = "zq-sentinel-7731";

pub fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

pub fn fake_scanner() -> PathBuf {
    fixtures().join("fake-scanner.mjs")
}

pub fn fake_core_dir() -> PathBuf {
    fixtures().join("fake-core")
}

/// Absolute path of `node` found on `PATH`, if any.
pub fn find_node() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join("node"))
        .find(|p| p.is_file())
}

/// `node`, or `None` after printing why the test is skipped. CI sets
/// `PII_EVAL_REQUIRE_NODE=1` so a missing Node there fails instead of skipping.
pub fn node_or_skip(test: &str) -> Option<PathBuf> {
    match find_node() {
        Some(node) => Some(node),
        None => {
            assert!(
                std::env::var("PII_EVAL_REQUIRE_NODE").as_deref() != Ok("1"),
                "node is required (PII_EVAL_REQUIRE_NODE=1) but was not found on PATH"
            );
            eprintln!(
                "SKIPPED {test}: `node` not found on PATH (set PII_EVAL_REQUIRE_NODE=1 to fail instead)"
            );
            None
        }
    }
}

/// A scratch directory removed on drop.
pub struct Scratch(pub PathBuf);

impl Scratch {
    pub fn new(label: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "pii-eval-adapters-{}-{}-{label}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Scratch(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn text_param(key: &str, value: &str) -> ConfigParameter {
    ConfigParameter {
        key: ConfigKey::new(key).unwrap(),
        value: ConfigValue::Text(value.to_owned()),
    }
}

pub fn selectors(names: &[&str]) -> Vec<ActivationSelector> {
    let mut v: Vec<ActivationSelector> = names
        .iter()
        .map(|n| ActivationSelector::new(*n).unwrap())
        .collect();
    v.sort();
    v
}

pub fn fast_limits() -> AdapterLimits {
    AdapterLimits {
        startup_timeout: Duration::from_secs(10),
        call_timeout: Duration::from_secs(10),
        ..AdapterLimits::default()
    }
}

/// Spec for the fake scanner with the given fixed parameters.
pub fn fake_spec(
    node: &Path,
    params: Vec<ConfigParameter>,
    limits: AdapterLimits,
) -> ProcessAdapterSpec {
    let shim = fake_scanner();
    let core = fake_core_dir();
    ProcessAdapterSpec {
        executable: node.to_path_buf(),
        shim: ArtifactPin::file(&shim, sha256_of_file(&shim).unwrap()),
        scanner_artifact: ArtifactPin::tree(&core, sha256_of_tree(&core).unwrap()),
        scanner_entry: core.join("lib/index.js"),
        extra_artifacts: Vec::new(),
        scanner_id: ScannerId::new("fake-scanner").unwrap(),
        scanner_version: VersionString::new("1.0.0").unwrap(),
        product: ProductIdentity::Released,
        adapter: AdapterIdentity {
            adapter_id: ScannerId::new("fake-adapter").unwrap(),
            adapter_version: VersionString::new("0.0.1").unwrap(),
            normalization_version: 1,
        },
        runtime_name: "node".to_owned(),
        runtime_version_prefix: None,
        offset_unit: OffsetUnit::Utf16CodeUnits,
        inherit_env: Vec::new(),
        allowed_parameters: params,
        return_output: true,
        limits,
        vocabulary: Arc::new(RedactSecretVocabulary),
    }
}

pub fn startup_param(mode: &str) -> Vec<ConfigParameter> {
    vec![text_param("startup", mode)]
}

pub fn fake_adapter(node: &Path, startup: &str, limits: AdapterLimits) -> ProcessAdapter {
    ProcessAdapter::new(fake_spec(node, startup_param(startup), limits)).expect("valid spec")
}

pub fn configuration(startup: &str, activation: &[&str]) -> ScannerConfiguration {
    ScannerConfiguration {
        parameters: startup_param(startup),
        activation: selectors(activation),
    }
}

/// Start a session with the default `normal` startup and the given activation.
pub fn start(adapter: &ProcessAdapter, startup: &str, activation: &[&str]) -> Box<dyn ScanSession> {
    let plan = adapter
        .plan(configuration(startup, activation))
        .expect("plan");
    adapter
        .start(&plan)
        .unwrap_or_else(|f| panic!("start failed: {}", f.error))
}

/// `format!("{e}{e:?}")` of every error must be free of the sentinel.
pub fn assert_no_sentinel(rendered: &str) {
    assert!(!rendered.contains(SENTINEL), "sentinel leaked: {rendered}");
}
