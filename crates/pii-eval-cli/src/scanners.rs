//! Building the pinned scanner adapters of a run from its configuration, and
//! checking every pin before anything is executed.
//!
//! The only adapter this release builds is `@redact-secret/core` through the
//! production shim ([`pii_eval_adapters::redact_secret`]); the shim digest is
//! the shipped one and cannot be overridden by a configuration. A candidate is
//! identified by the tree digest of its package directory. Product (released or
//! candidate) is independent of the run class.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use pii_eval_adapters::error::PinKind;
use pii_eval_adapters::redact_secret::{
    CoreAdapterConfig, CorePin, PINNED_VERSION, RELEASED_PACKAGE_TREE_SHA256, SHIM_SHA256,
    core_adapter,
};
use pii_eval_adapters::{AdapterLimits, ArtifactPin, ScannerAdapter};
use pii_eval_contracts::Sha256Digest;

use crate::config::{ProductKind, ScannerConfig};
use crate::status::{Exit, Failure, reason};

/// Canonicalize a configured path or report which pin it belongs to.
fn canonical(path: &Path, slot: &str) -> Result<PathBuf, Failure> {
    std::fs::canonicalize(path).map_err(|_| Failure::provenance(slot))
}

/// Build the adapter of one configured scanner. Nothing is executed or hashed.
pub fn build_adapter(
    cfg: &ScannerConfig,
    product: ProductKind,
    node: &Path,
) -> Result<Arc<dyn ScannerAdapter>, Failure> {
    let package_dir = canonical(&cfg.package_dir, "scanner-artifact")?;
    let shim = canonical(&cfg.shim, "shim")?;
    let pin = match product {
        ProductKind::Released => {
            if cfg.version.as_str() != PINNED_VERSION {
                return Err(Failure::provenance("scanner-version"));
            }
            if cfg
                .tree_sha256
                .as_ref()
                .is_some_and(|d| d.as_str() != RELEASED_PACKAGE_TREE_SHA256)
            {
                return Err(Failure::provenance("scanner-artifact"));
            }
            CorePin::released_beta12()
        }
        ProductKind::Candidate => {
            let tree = cfg.tree_sha256.clone().ok_or_else(|| {
                Failure::config("scanners.package.treeSha256 (required for a candidate)")
            })?;
            CorePin::candidate(cfg.version.clone(), tree)
        }
    };
    let mut extra_artifacts = Vec::new();
    for e in &cfg.extra {
        let path = canonical(&e.path, "scanner-artifact")?;
        extra_artifacts.push(if e.tree {
            ArtifactPin::tree(path, e.sha256.clone())
        } else {
            ArtifactPin::file(path, e.sha256.clone())
        });
    }
    let mut limits = AdapterLimits::default();
    if let Some(ms) = cfg.startup_timeout_ms {
        limits.startup_timeout = Duration::from_millis(ms);
    }
    if let Some(ms) = cfg.call_timeout_ms {
        limits.call_timeout = Duration::from_millis(ms);
    }
    let adapter = core_adapter(CoreAdapterConfig {
        node: node.to_path_buf(),
        shim,
        package_dir,
        entry_relative: cfg.entry.clone(),
        pin,
        shim_sha256: Sha256Digest::new(SHIM_SHA256)
            .map_err(|_| Failure::new(Exit::Internal, reason::INTERNAL))?,
        extra_artifacts,
        limits,
    })
    .map_err(|e| {
        Failure::new(Exit::Execution, reason::ADAPTER_INVALID).with_detail(e.detail().to_owned())
    })?;
    Ok(Arc::new(adapter))
}

/// Hash every pinned file now and compare, before any process starts: a pin
/// that does not match is a provenance mismatch (exit 4), not a scanner that
/// later records `unavailable`. (The adapter re-verifies at start, after
/// ready and at the end of each session.)
pub fn preflight_pins(cfg: &ScannerConfig, product: ProductKind) -> Result<(), Failure> {
    let package_dir = canonical(&cfg.package_dir, "scanner-artifact")?;
    let shim = canonical(&cfg.shim, "shim")?;
    let tree = match product {
        ProductKind::Released => Sha256Digest::new(RELEASED_PACKAGE_TREE_SHA256)
            .map_err(|_| Failure::new(Exit::Internal, reason::INTERNAL))?,
        ProductKind::Candidate => cfg.tree_sha256.clone().ok_or_else(|| {
            Failure::config("scanners.package.treeSha256 (required for a candidate)")
        })?,
    };
    let shim_digest = Sha256Digest::new(SHIM_SHA256)
        .map_err(|_| Failure::new(Exit::Internal, reason::INTERNAL))?;
    let check = |pin: ArtifactPin, slot: &str| {
        pin.verify(PinKind::ArtifactDigest)
            .map_err(|_| Failure::provenance(slot))
    };
    check(ArtifactPin::file(shim, shim_digest), "shim")?;
    check(ArtifactPin::tree(package_dir, tree), "scanner-artifact")?;
    for e in &cfg.extra {
        let path = canonical(&e.path, "scanner-artifact")?;
        let pin = if e.tree {
            ArtifactPin::tree(path, e.sha256.clone())
        } else {
            ArtifactPin::file(path, e.sha256.clone())
        };
        check(pin, "scanner-artifact")?;
    }
    Ok(())
}
