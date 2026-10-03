//! The staged world, verified before any protected entry is read.
//!
//! Order (each step before the next; `launch` calls them in this order):
//!
//! 1. every staged file is a regular file: no symlink, no hard-link alias
//!    (`nlink == 1`), no group or other write bit ([`check_shape`]);
//! 2. the SHA-256 of each staged artifact equals its pin in the configuration
//!    ([`verify_file`]), each with its own reason;
//! 3. the adapter and candidate bundles are extracted into the scratch
//!    directory by the bundle adapter, and the extracted package TREE digest
//!    equals the tree pin ([`verify_tree`]): the bundle digest and the tree
//!    digest are two different typed digests, each checked on its own;
//! 4. the extracted shim equals the digest compiled into this binary.
//!
//! A hostile configuration can only make these fail: the paths come from the
//! layout and the fixed staged names, never from the configuration.

use std::path::Path;

use pii_eval_adapters::redact_secret::SHIM_SHA256;
use pii_eval_adapters::{ArtifactPin, sha256_of_tree};
use pii_eval_contracts::Sha256Digest;

use crate::status::Failure;
use crate::worker::digest::{CustodianDigest, EngineDigest, TreeDigest};
use crate::worker::reason;

/// File name of the shim inside the adapter bundle.
pub const SHIM_MEMBER: &str = "redact-secret-core.mjs";

/// A staged file must be a regular, unaliased file nobody but its owner can
/// write (the custodian stages 0500 or 0400).
pub fn check_shape(path: &Path, slot: &str) -> Result<(), Failure> {
    let invalid = || reason::mismatch(reason::STAGED_FILE_INVALID, slot);
    let meta = std::fs::symlink_metadata(path).map_err(|_| invalid())?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err(invalid());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if meta.nlink() != 1 || meta.permissions().mode() & 0o022 != 0 {
            return Err(invalid());
        }
    }
    Ok(())
}

/// Hash a staged file and compare with its pin; a difference is `mismatch`.
pub fn verify_file(
    path: &Path,
    pin: &CustodianDigest,
    mismatch: &'static str,
    slot: &str,
) -> Result<(), Failure> {
    let got = CustodianDigest::from_file(path)
        .map_err(|_| reason::mismatch(reason::STAGED_FILE_INVALID, slot))?;
    if got == *pin {
        Ok(())
    } else {
        Err(reason::mismatch(mismatch, slot))
    }
}

/// Compare the tree digest of the extracted package with its pin.
pub fn verify_tree(dir: &Path, pin: &TreeDigest) -> Result<(), Failure> {
    let got = sha256_of_tree(dir)
        .map(EngineDigest::from_contract)
        .map_err(|_| reason::mismatch(reason::PACKAGE_TREE_DIGEST_MISMATCH, "candidate"))?;
    if got == *pin.as_engine() {
        Ok(())
    } else {
        Err(reason::mismatch(
            reason::PACKAGE_TREE_DIGEST_MISMATCH,
            "candidate",
        ))
    }
}

/// Compare the extracted shim with the digest compiled into this binary.
pub fn verify_shim(shim: &Path) -> Result<(), Failure> {
    let pin = Sha256Digest::new(SHIM_SHA256).map_err(|_| {
        Failure::new(
            crate::status::Exit::Internal,
            crate::status::reason::INTERNAL,
        )
    })?;
    ArtifactPin::file(shim, pin)
        .verify(pii_eval_adapters::error::PinKind::ArtifactDigest)
        .map_err(|_| reason::mismatch(reason::SHIM_DIGEST_MISMATCH, "adapter"))
}
