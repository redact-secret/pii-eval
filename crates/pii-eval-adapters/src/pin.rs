//! File and directory pins: digests checked before anything is executed.
//!
//! A pin names a regular file or a directory tree and the SHA-256 digest it
//! must have. Symlinks are rejected anywhere inside a pinned tree and for a
//! pinned file itself, and every read is bounded.
//!
//! Tree digest (reproducible with standard tools): hash every regular file,
//! list `"<file sha256 hex>  <relative path>\n"` for all files sorted by
//! relative path bytewise (paths use `/`), and take the SHA-256 of that
//! listing. From the tree root:
//!
//! ```text
//! find . -type f | sed 's|^\./||' | LC_ALL=C sort | xargs shasum -a 256 | shasum -a 256
//! ```
//!
//! File names inside a tree must be printable ASCII without a backslash (see
//! `name_is_listable`); any other name fails the pin with
//! `artifact-bad-name`. The digest format is unchanged by that rule: it only
//! refuses trees whose listing could be ambiguous.
//!
//! Limits: per file [`MAX_ARTIFACT_BYTES`], per tree [`MAX_TREE_FILES`] files,
//! [`MAX_TREE_BYTES`] bytes and [`MAX_TREE_DEPTH`] levels.
//!
//! Residual risk, stated: verification and use are separate operations. A
//! writer with access to the pinned paths between them can swap content. The
//! custodian or runner must make scanner installs read-only for the run (P7).

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use pii_eval_contracts::Sha256Digest;

use crate::error::{AdapterError, PinKind, SpecProblem};

/// Largest single pinned file the adapter will hash (32 MiB).
pub const MAX_ARTIFACT_BYTES: u64 = 32 * 1024 * 1024;
/// Most files in a pinned tree.
pub const MAX_TREE_FILES: usize = 4096;
/// Most bytes hashed in a pinned tree (256 MiB).
pub const MAX_TREE_BYTES: u64 = 256 * 1024 * 1024;
/// Deepest directory nesting in a pinned tree.
pub const MAX_TREE_DEPTH: usize = 16;

/// What a pin names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinTarget {
    /// One regular file.
    File,
    /// A directory tree (see the module documentation for its digest).
    Tree,
}

/// A path and the SHA-256 digest it must have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactPin {
    /// Absolute path.
    pub path: PathBuf,
    /// File or tree.
    pub target: PinTarget,
    /// Expected digest.
    pub sha256: Sha256Digest,
}

impl ArtifactPin {
    /// Pin one regular file.
    pub fn file(path: impl Into<PathBuf>, sha256: Sha256Digest) -> Self {
        Self {
            path: path.into(),
            target: PinTarget::File,
            sha256,
        }
    }

    /// Pin a directory tree.
    pub fn tree(path: impl Into<PathBuf>, sha256: Sha256Digest) -> Self {
        Self {
            path: path.into(),
            target: PinTarget::Tree,
            sha256,
        }
    }

    /// Compute the digest of the pinned path now.
    pub fn digest_now(&self) -> Result<Sha256Digest, AdapterError> {
        match self.target {
            PinTarget::File => sha256_of_file(&self.path),
            PinTarget::Tree => sha256_of_tree(&self.path),
        }
    }

    /// Check the path against the pin. `mismatch` names the pin on a digest mismatch.
    pub fn verify(&self, mismatch: PinKind) -> Result<(), AdapterError> {
        if self.digest_now()? == self.sha256 {
            Ok(())
        } else {
            Err(AdapterError::PinMismatch(mismatch))
        }
    }
}

fn unreadable() -> AdapterError {
    AdapterError::PinMismatch(PinKind::ArtifactUnreadable)
}

fn read_bounded(path: &Path, remaining: &mut u64) -> Result<Vec<u8>, AdapterError> {
    let meta = fs::symlink_metadata(path).map_err(|_| unreadable())?;
    if !meta.is_file() {
        return Err(AdapterError::PinMismatch(PinKind::ArtifactNotRegularFile));
    }
    let cap = MAX_ARTIFACT_BYTES.min(*remaining);
    if meta.len() > cap {
        return Err(AdapterError::PinMismatch(PinKind::ArtifactTooLarge));
    }
    let file = File::open(path).map_err(|_| unreadable())?;
    let mut bytes = Vec::new();
    // `take` bounds the read even if the file grows after the metadata check.
    file.take(cap + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| unreadable())?;
    if bytes.len() as u64 > cap {
        return Err(AdapterError::PinMismatch(PinKind::ArtifactTooLarge));
    }
    *remaining -= bytes.len() as u64;
    Ok(bytes)
}

fn require_absolute(path: &Path) -> Result<(), AdapterError> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(AdapterError::InvalidSpec(SpecProblem::ArtifactPath))
    }
}

/// Digest of a regular file: absolute path, not a symlink, within the size bound.
pub fn sha256_of_file(path: &Path) -> Result<Sha256Digest, AdapterError> {
    require_absolute(path)?;
    let mut remaining = MAX_ARTIFACT_BYTES;
    Ok(Sha256Digest::of_bytes(&read_bounded(path, &mut remaining)?))
}

/// File names a tree pin accepts: printable ASCII (space to `~`) without a
/// backslash. Anything else is rejected rather than listed, so the listing
/// (one `"<hash>  <path>\n"` line per file) is unambiguous: a name holding a
/// newline could otherwise forge a second line, and non-NFC or look-alike
/// Unicode spellings of one name could not be told apart by a reviewer. Scanner
/// packages use ASCII file names.
fn name_is_listable(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| (0x20..=0x7e).contains(&b) && b != b'\\')
}

fn walk(
    dir: &Path,
    prefix: &str,
    depth: usize,
    remaining: &mut u64,
    out: &mut Vec<(String, Sha256Digest)>,
) -> Result<(), AdapterError> {
    if depth > MAX_TREE_DEPTH {
        return Err(AdapterError::PinMismatch(PinKind::ArtifactTooLarge));
    }
    for entry in fs::read_dir(dir).map_err(|_| unreadable())? {
        let entry = entry.map_err(|_| unreadable())?;
        let name = entry.file_name().into_string().map_err(|_| unreadable())?;
        if !name_is_listable(&name) {
            return Err(AdapterError::PinMismatch(PinKind::ArtifactBadName));
        }
        let relative = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(|_| unreadable())?;
        if meta.is_dir() {
            walk(&path, &relative, depth + 1, remaining, out)?;
        } else {
            if out.len() >= MAX_TREE_FILES {
                return Err(AdapterError::PinMismatch(PinKind::ArtifactTooLarge));
            }
            let bytes = read_bounded(&path, remaining)?;
            out.push((relative, Sha256Digest::of_bytes(&bytes)));
        }
    }
    Ok(())
}

/// Digest of a directory tree as defined in the module documentation.
pub fn sha256_of_tree(root: &Path) -> Result<Sha256Digest, AdapterError> {
    require_absolute(root)?;
    let meta = fs::symlink_metadata(root).map_err(|_| unreadable())?;
    if !meta.is_dir() {
        return Err(AdapterError::PinMismatch(PinKind::ArtifactNotRegularFile));
    }
    let mut files = Vec::new();
    let mut remaining = MAX_TREE_BYTES;
    walk(root, "", 0, &mut remaining, &mut files)?;
    files.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let mut listing = String::new();
    for (relative, digest) in &files {
        listing.push_str(digest.as_str());
        listing.push_str("  ");
        listing.push_str(relative);
        listing.push('\n');
    }
    Ok(Sha256Digest::of_bytes(listing.as_bytes()))
}
