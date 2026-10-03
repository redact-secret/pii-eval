//! Bounded input reads, output-directory preparation and protected-path
//! containment. Nothing here puts a path into an error: failures carry fixed
//! reason codes and a closed detail.

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::status::{Exit, Failure, reason};
use crate::write::{ArtifactWriter, OverwritePolicy};

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
            #[cfg_attr(not(unix), allow(unused_mut))]
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

/// Confine the paths of a command that touches a **protected** document to the
/// custodian job context (ADR 0010 C6). Not protected: nothing to check. Protected
/// without a context (`--job-context` or `PII_EVAL_JOB_CONTEXT`): exit 9. Every
/// input must lie inside the context's input root and the output directory
/// inside its output root, after resolving symlinks and `..`. The context grants
/// no access; this only refuses.
pub fn confine(
    protected: bool,
    job_option: Option<&str>,
    inputs: &[&Path],
    output: Option<&Path>,
) -> Result<(), Failure> {
    if !protected {
        return Ok(());
    }
    let path = job_option
        .map(str::to_owned)
        .or_else(|| {
            std::env::var(crate::cmd_run::JOB_CONTEXT_ENV)
                .ok()
                .filter(|v| !v.is_empty())
        })
        .ok_or_else(|| Failure::new(Exit::ProtectedContext, reason::PROTECTED_CONTEXT_REQUIRED))?;
    let job = crate::config::JobContext::load(Path::new(&path))?;
    let outside = |detail: &str| {
        Failure::new(Exit::ProtectedContext, reason::PROTECTED_PATH_OUTSIDE).with_detail(detail)
    };
    if inputs.iter().any(|p| !is_inside(&job.input_root, p)) {
        return Err(outside("input"));
    }
    if output.is_some_and(|p| !is_inside(&job.output_root, p)) {
        return Err(outside("output"));
    }
    Ok(())
}

/// Test-only fault injection into the artifact writer, selected by the
/// environment variable `PII_EVAL_TEST_FAULT` (`write-io`, `partial`,
/// `not-durable`). It exists **only in builds with debug assertions** (every
/// `cargo test` build); a release build compiles it out, so the variable has no
/// effect there (ADR 0010 C13). It lets the end-to-end tests drive the output
/// failure exits that no ordinary input can reach.
#[cfg(debug_assertions)]
pub fn with_test_faults(writer: ArtifactWriter, dir: &Path) -> ArtifactWriter {
    use crate::write::WriteStage;
    let fault = std::env::var("PII_EVAL_TEST_FAULT").unwrap_or_default();
    let dir = dir.to_path_buf();
    match fault.as_str() {
        "write-io" => writer.with_fault_hook(|stage| match stage {
            WriteStage::TempWritten(_) => Err(std::io::Error::other("injected")),
            _ => Ok(()),
        }),
        "not-durable" => writer.with_fault_hook(|stage| match stage {
            WriteStage::AfterCommit => Err(std::io::Error::other("injected")),
            _ => Ok(()),
        }),
        // Fail the last rename after the others succeeded, with the directory
        // made unwritable so the rollback cannot remove them.
        "partial" => writer.with_fault_hook(move |stage| match stage {
            WriteStage::BeforeRename(name) if name == crate::write::RUN_ARTIFACT_FILE => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500));
                }
                let _ = &dir;
                Err(std::io::Error::other("injected"))
            }
            _ => Ok(()),
        }),
        _ => writer,
    }
}

/// Release builds: no fault injection.
#[cfg(not(debug_assertions))]
pub fn with_test_faults(writer: ArtifactWriter, _dir: &Path) -> ArtifactWriter {
    writer
}
