//! Reading a local snapshot directory: bounded, regular files only.
//!
//! This is the only place the evidence consumer touches the filesystem. It
//! follows no symlink, reads no device or directory as a file, bounds the file
//! count, the size of each file and the total, and never opens a path outside
//! the directory. A hostile directory therefore costs a refusal, not memory.
//! Whether the files are the right ones is [`crate::evidence::verify`]'s job.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use super::{EvidenceError, reason};

/// Most files in a snapshot directory (a released snapshot has 10).
pub const MAX_FILES: usize = 64;
/// Largest single file, in bytes (the contracts' document cap).
pub const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;
/// Largest total, in bytes.
pub const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
/// Deepest nesting below the snapshot directory (`taxonomy/x.json` is 1).
const MAX_DEPTH: usize = 3;

/// The raw bytes of every file of a snapshot, by relative path with `/`.
#[derive(Debug, Clone, Default)]
pub struct SnapshotFiles {
    files: BTreeMap<String, Vec<u8>>,
}

impl SnapshotFiles {
    /// Build from in-memory files (tests and the archive path).
    pub fn from_map(files: BTreeMap<String, Vec<u8>>) -> Self {
        Self { files }
    }

    /// The bytes of one file.
    pub fn get(&self, path: &str) -> Option<&[u8]> {
        self.files.get(path).map(Vec::as_slice)
    }

    /// Every relative path, ascending.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.files.keys().map(String::as_str)
    }

    /// Every file, ascending by path.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.files.iter().map(|(k, v)| (k.as_str(), v.as_slice()))
    }

    /// Number of files.
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Whether there are no files.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Mutable access, for tests that tamper with a snapshot.
    pub fn into_map(self) -> BTreeMap<String, Vec<u8>> {
        self.files
    }
}

fn unreadable(at: &str) -> EvidenceError {
    EvidenceError::invalid(reason::SNAPSHOT_UNREADABLE, at)
}

/// Read every file below `dir`.
pub fn read_dir(dir: &Path) -> Result<SnapshotFiles, EvidenceError> {
    let meta = std::fs::symlink_metadata(dir).map_err(|_| unreadable("snapshot-dir"))?;
    if !meta.is_dir() {
        return Err(EvidenceError::invalid(
            reason::FILE_NOT_REGULAR,
            "snapshot-dir",
        ));
    }
    let mut out = BTreeMap::new();
    let mut total = 0u64;
    walk(dir, "", 0, &mut out, &mut total)?;
    Ok(SnapshotFiles { files: out })
}

fn walk(
    dir: &Path,
    rel: &str,
    depth: usize,
    out: &mut BTreeMap<String, Vec<u8>>,
    total: &mut u64,
) -> Result<(), EvidenceError> {
    if depth > MAX_DEPTH {
        return Err(EvidenceError::invalid(reason::FILE_NOT_REGULAR, rel));
    }
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(|_| unreadable(if rel.is_empty() { "snapshot-dir" } else { rel }))?
        .collect::<Result<_, _>>()
        .map_err(|_| unreadable(rel))?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| EvidenceError::invalid(reason::FILE_NOT_REGULAR, rel))?;
        let path = if rel.is_empty() {
            name.clone()
        } else {
            format!("{rel}/{name}")
        };
        let meta = std::fs::symlink_metadata(entry.path()).map_err(|_| unreadable(&path))?;
        let kind = meta.file_type();
        if kind.is_symlink() {
            return Err(EvidenceError::invalid(reason::FILE_NOT_REGULAR, path));
        }
        if kind.is_dir() {
            walk(&entry.path(), &path, depth + 1, out, total)?;
        } else if kind.is_file() {
            if out.len() >= MAX_FILES || meta.len() > MAX_FILE_BYTES {
                return Err(EvidenceError::invalid(reason::FILE_TOO_LARGE, path));
            }
            *total += meta.len();
            if *total > MAX_TOTAL_BYTES {
                return Err(EvidenceError::invalid(reason::FILE_TOO_LARGE, path));
            }
            let file = std::fs::File::open(entry.path()).map_err(|_| unreadable(&path))?;
            let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
            // One byte past the bound catches a file that grew after the check.
            file.take(MAX_FILE_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| unreadable(&path))?;
            if bytes.len() as u64 > MAX_FILE_BYTES {
                return Err(EvidenceError::invalid(reason::FILE_TOO_LARGE, path));
            }
            out.insert(path, bytes);
        } else {
            return Err(EvidenceError::invalid(reason::FILE_NOT_REGULAR, path));
        }
    }
    Ok(())
}
