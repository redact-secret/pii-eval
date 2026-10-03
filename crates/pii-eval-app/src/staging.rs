//! Per-job private staging of the verified run configuration (shared by the
//! runners).
//!
//! The runner reads the profile's configuration once, compares its SHA-256 with
//! the profile's pin, and writes exactly those bytes into a new private
//! directory (`0700`, file `0600`) that the worker then uses. A swap of the
//! original path after the check cannot change what runs. Because the staged
//! copy lives elsewhere, the configuration must be self-contained: every `path`
//! and `dir` value must be absolute (the CLI resolves relative ones against the
//! configuration's directory, which the copy would change).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use pii_eval_contracts::Sha256Digest;

use crate::ports::RunnerError;

/// Largest run configuration read.
pub const MAX_CONFIG_BYTES: u64 = 256 * 1024;

/// A job's private directory and the staged configuration inside it.
pub(crate) struct Staged {
    pub dir: PathBuf,
    pub config: PathBuf,
}

fn absolute_paths_only(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Object(map) => map.iter().all(|(k, v)| {
            if k == "path" || k == "dir" {
                v.as_str().is_none_or(|s| s.starts_with('/'))
            } else {
                absolute_paths_only(v)
            }
        }),
        serde_json::Value::Array(items) => items.iter().all(absolute_paths_only),
        _ => true,
    }
}

/// Verify `source` against `expected_digest` and stage a private copy under
/// `work_root/<name>`.
pub(crate) fn stage_config(
    work_root: &Path,
    name: &str,
    source: &Path,
    expected_digest: &str,
) -> Result<Staged, RunnerError> {
    let mut bytes = Vec::new();
    std::fs::File::open(source)
        .map_err(|_| RunnerError::Refused)?
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RunnerError::Refused)?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(RunnerError::Refused);
    }
    if Sha256Digest::of_bytes(&bytes).as_str() != expected_digest {
        return Err(RunnerError::ProfileChanged);
    }
    let doc: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| RunnerError::Refused)?;
    if !absolute_paths_only(&doc) {
        return Err(RunnerError::Refused);
    }
    let dir = work_root.join(name);
    match std::fs::symlink_metadata(&dir) {
        Ok(m) if m.is_dir() => {
            std::fs::remove_dir_all(&dir).map_err(|_| RunnerError::Refused)?;
        }
        Ok(_) => return Err(RunnerError::Refused),
        Err(_) => {}
    }
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&dir).map_err(|_| RunnerError::Refused)?;
    let config = dir.join("config.json");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let written = options
        .open(&config)
        .and_then(|mut f| f.write_all(&bytes).and_then(|()| f.sync_all()));
    if written.is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(RunnerError::Refused);
    }
    Ok(Staged { dir, config })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_absolute_paths_pass() {
        let ok = serde_json::json!({"a": {"path": "/x"}, "b": [{"dir": "/y"}], "mode": "official"});
        assert!(absolute_paths_only(&ok));
        for bad in [
            serde_json::json!({"snapshot": {"path": "snapshot.json"}}),
            serde_json::json!({"s": [{"package": {"dir": "../x"}}]}),
        ] {
            assert!(!absolute_paths_only(&bad));
        }
    }
}
