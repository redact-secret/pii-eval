//! Bounded input reads, output-directory preparation and protected-path
//! containment. Nothing here puts a path into an error: failures carry fixed
//! reason codes and a closed detail.

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::status::{Exit, Failure, reason};
use crate::write::OverwritePolicy;

/// Read a regular file of at most `max` bytes. A symlink to a regular file is
/// followed (an explicit input path is the operator's choice); a directory,
/// device or oversized file is refused.
pub fn read_input(path: &Path, max: usize, what: &str) -> Result<Vec<u8>, Failure> {
    let unreadable = || Failure::new(Exit::Invalid, reason::INPUT_UNREADABLE).with_detail(what);
    let meta = std::fs::metadata(path).map_err(|_| unreadable())?;
    if !meta.is_file() {
        return Err(unreadable());
    }
    if meta.len() > max as u64 {
        return Err(Failure::new(Exit::Invalid, reason::INPUT_TOO_LARGE).with_detail(what));
    }
    let file = std::fs::File::open(path).map_err(|_| unreadable())?;
    let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
    // One byte past the bound detects a file that grew after the check.
    file.take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| unreadable())?;
    if bytes.len() > max {
        return Err(Failure::new(Exit::Invalid, reason::INPUT_TOO_LARGE).with_detail(what));
    }
    Ok(bytes)
}

/// An output directory that is created before the run (so an unusable
/// location fails before any scanner starts) and removed again, if empty, when
/// the command fails before committing.
pub struct OutputDir {
    path: PathBuf,
    created: bool,
}

impl OutputDir {
    /// The directory.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Keep the directory: the documents are in place.
    pub fn commit(mut self) {
        self.created = false;
    }
}

impl Drop for OutputDir {
    fn drop(&mut self) {
        if self.created {
            // Succeeds only while the directory is empty.
            let _ = std::fs::remove_dir(&self.path);
        }
    }
}

fn unusable(detail: &str) -> Failure {
    Failure::new(Exit::Output, reason::OUTPUT_UNUSABLE).with_detail(detail)
}

/// Check (and, when absent, create with mode 0700) the output directory, and
/// refuse early what the writer would refuse late: a symlink, a non-directory,
/// an existing result under `Refuse`, a directory nobody can write to.
pub fn prepare_output(
    dir: &Path,
    names: &[String],
    overwrite: OverwritePolicy,
) -> Result<OutputDir, Failure> {
    let mut created = false;
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_symlink() => return Err(unusable("symlink")),
        Ok(m) if !m.is_dir() => return Err(unusable("not-a-directory")),
        Ok(_) => {
            for name in names {
                match std::fs::symlink_metadata(dir.join(name)) {
                    Ok(m) if m.file_type().is_symlink() => return Err(unusable("symlink")),
                    Ok(_) if overwrite == OverwritePolicy::Refuse => {
                        return Err(Failure::new(Exit::Output, reason::OUTPUT_EXISTS));
                    }
                    _ => {}
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let parent = match dir.parent() {
                Some(p) if !p.as_os_str().is_empty() => p,
                _ => Path::new("."),
            };
            if !std::fs::metadata(parent).is_ok_and(|m| m.is_dir()) {
                return Err(unusable("parent-missing"));
            }
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
            builder.create(dir).map_err(|_| unusable("not-creatable"))?;
            created = true;
        }
        Err(_) => return Err(unusable("unreadable")),
    }
    let guard = OutputDir {
        path: dir.to_path_buf(),
        created,
    };
    // A writability probe: a read-only directory must fail now, not after the scan.
    let probe = dir.join(format!(".pii-eval-tmp.probe.{}", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(&probe).map_err(|_| unusable("not-writable"))?;
    std::fs::remove_file(&probe).map_err(|_| unusable("not-writable"))?;
    Ok(guard)
}

/// `path` canonicalized, or, when it does not exist yet, its canonical parent
/// joined with the final component. `None` if neither resolves.
pub fn canonical_or_parent(path: &Path) -> Option<PathBuf> {
    if let Ok(c) = std::fs::canonicalize(path) {
        return Some(c);
    }
    let name = path.file_name()?;
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    Some(std::fs::canonicalize(parent).ok()?.join(name))
}

/// Whether `path` (after resolving symlinks and `..`) lies inside `root`.
pub fn is_inside(root: &Path, path: &Path) -> bool {
    canonical_or_parent(path).is_some_and(|p| p.starts_with(root))
}
