//! Validated, atomic artifact writing (P7, ADR 0009).
//!
//! Nothing reaches its final name until every document has been validated,
//! verified and re-parsed:
//!
//! 1. each document passes the contracts' `validate` and its cross-document
//!    bindings (observation against manifest and snapshot, artifact against
//!    manifest and snapshot);
//! 2. **the internal artifact and the public projection pass the kernel's
//!    accounting verifier**, so a metric that disagrees with its rows is never
//!    written (ADR 0005 section 8); the public projection must equal the
//!    projection of the internal artifact;
//! 3. each document is serialized and strictly parsed back to an equal value;
//! 4. each is written to a temporary file in the destination directory
//!    (`create_new`, mode 0600, `fsync`);
//! 5. the files are renamed into place, observation sets first, the public
//!    projection next and the internal run artifact **last**. Under `Refuse` a
//!    file is published with a hard link (fails if the target exists: no
//!    check-then-rename race); under `Replace` with a rename. The directory is
//!    synced **before** the commit-marker rename and again after it, and under
//!    `Replace` a stale public projection of an earlier run is removed when the
//!    new run has none. The run artifact is the commit marker: a directory
//!    without it is an incomplete run, and it binds every observation set by
//!    digest. If only the final directory sync fails the run is not failed and
//!    nothing is rolled back: [`WriteError::CommitNotDurable`] says so.
//!
//! A failure before step 5 leaves no final file and removes the temporary files.
//! A failure during step 5 rolls back the files this call created (under the
//! default `Refuse` policy) and reports [`WriteError::PartiallyCommitted`] if it
//! cannot, so a partial write is never silent. A hard crash (power loss, `SIGKILL`)
//! can leave `.pii-eval-tmp.*` files, never a half-written final file; remove
//! them with [`cleanup_stale_temps`] while no writer is running.
//!
//! Errors carry fixed text only: no path, document content or finding.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use pii_eval_contracts::{
    CorpusSnapshot, Phase, PublicSyntheticArtifact, RunArtifact, RunManifest, Sha256Digest,
    parse_default, serialize_internal, serialize_public_synthetic, to_pretty_json, validate,
    validate_artifact_against_manifest, validate_manifest_against_snapshot,
    validate_observation_against_manifest, validate_observation_against_snapshot,
};
use pii_eval_kernel::{
    VerifyFailure, verify_public_artifact_accounting, verify_run_artifact_accounting,
};

use crate::assemble::Assembled;

const TEMP_PREFIX: &str = ".pii-eval-tmp.";
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// What to do when a destination file already exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OverwritePolicy {
    /// Fail without touching anything (the default): reproducible runs never
    /// silently replace an earlier result.
    #[default]
    Refuse,
    /// Replace atomically. The old content cannot be restored on a later failure.
    Replace,
}

/// A point of the write sequence, for fault injection in tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteStage {
    /// A temporary file was written and synced.
    TempWritten(String),
    /// About to rename a file to its final name.
    BeforeRename(String),
    /// A file was renamed to its final name.
    Renamed(String),
    /// Every file is in place; the directory has not been synced yet.
    AfterCommit,
}

type Hook = Arc<dyn Fn(&WriteStage) -> io::Result<()> + Send + Sync>;

/// Why a write failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteError {
    /// A document failed contract validation or a binding check.
    Invalid,
    /// The accounting verifier rejected the artifact.
    Verification(VerifyFailure),
    /// A serialized document did not parse back to itself.
    RoundTrip,
    /// The destination is not a usable directory (missing parent, not a
    /// directory, a symlink).
    Destination,
    /// A destination file exists and the policy is `Refuse`.
    Exists,
    /// An operating-system error (kind only).
    Io(io::ErrorKind),
    /// Every file was written and is in place, complete and valid, but the final
    /// directory sync failed, so durability across a crash is not confirmed. Not
    /// a failed run: nothing is rolled back and the commit marker exists.
    CommitNotDurable {
        /// The final file names, in commit order.
        files: Vec<String>,
    },
    /// Some files were renamed into place and could not be rolled back. The
    /// listed names exist; the run artifact is absent unless it is listed.
    PartiallyCommitted {
        /// Final file names that exist.
        committed: Vec<String>,
    },
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WriteError::Invalid => f.write_str("a document failed validation"),
            WriteError::Verification(v) => write!(f, "accounting verification failed: {v}"),
            WriteError::RoundTrip => f.write_str("a serialized document did not parse back"),
            WriteError::Destination => f.write_str("the destination directory is not usable"),
            WriteError::Exists => f.write_str("a destination file already exists"),
            WriteError::Io(kind) => write!(f, "i/o error: {kind:?}"),
            WriteError::CommitNotDurable { files } => {
                write!(
                    f,
                    "committed but not confirmed durable: {} file(s)",
                    files.len()
                )
            }
            WriteError::PartiallyCommitted { committed } => {
                write!(f, "partially committed: {} file(s) exist", committed.len())
            }
        }
    }
}

impl std::error::Error for WriteError {}

/// A file that was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenFile {
    /// Final file name inside the destination directory.
    pub name: String,
    /// Size in bytes.
    pub bytes: u64,
    /// SHA-256 of the file's bytes.
    pub sha256: Sha256Digest,
}

/// What a successful write produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenRun {
    /// Files in commit order; the run artifact is last.
    pub files: Vec<WrittenFile>,
    /// Time spent validating, verifying and serializing (the diagnostics'
    /// `serialization` phase).
    pub serialization: Duration,
}

/// Writes one run's documents into a directory.
#[derive(Clone)]
pub struct ArtifactWriter {
    dir: PathBuf,
    overwrite: OverwritePolicy,
    hook: Option<Hook>,
    include_manifest: bool,
}

struct Pending {
    name: String,
    bytes: Vec<u8>,
}

/// The final file name of a scanner's observation set.
pub fn observation_file_name(scanner_id: &str) -> String {
    format!("observation-{scanner_id}.json")
}

/// The final file name of the internal run artifact (written last).
pub const RUN_ARTIFACT_FILE: &str = "run-artifact.json";
/// The final file name of the public-synthetic projection.
pub const PUBLIC_ARTIFACT_FILE: &str = "public-synthetic-artifact.json";
/// The final file name of the manifest, when the writer is asked to include it
/// ([`ArtifactWriter::with_manifest`]).
pub const MANIFEST_FILE: &str = "manifest.json";

fn io_error(e: &io::Error) -> WriteError {
    WriteError::Io(e.kind())
}

impl ArtifactWriter {
    /// A writer for `dir` (created with mode 0700 if absent; its parent must exist).
    pub fn new(dir: impl Into<PathBuf>, overwrite: OverwritePolicy) -> Self {
        Self {
            dir: dir.into(),
            overwrite,
            hook: None,
            include_manifest: false,
        }
    }

    /// Also write the manifest the run realizes (`manifest.json`) in the same
    /// commit, first in commit order, so the directory is self-describing for
    /// `replay` and `validate` and the manifest is never left behind by a failed
    /// write. Off by default (the library API is unchanged).
    pub fn with_manifest(mut self) -> Self {
        self.include_manifest = true;
        self
    }

    /// Inject a fault at a write stage. Test support: the hook can fail a stage
    /// or abort the process.
    pub fn with_fault_hook(
        mut self,
        hook: impl Fn(&WriteStage) -> io::Result<()> + Send + Sync + 'static,
    ) -> Self {
        self.hook = Some(Arc::new(hook));
        self
    }

    fn fire(&self, stage: WriteStage) -> io::Result<()> {
        self.hook.as_ref().map_or(Ok(()), |h| h(&stage))
    }

    /// Validate, verify, serialize and atomically write every document.
    ///
    /// `started` is when the run began, for the diagnostics' `total` phase. The
    /// artifact's diagnostics (when present) are updated with the measured
    /// `serialization` and `total` durations before the final serialization.
    pub fn write_run(
        &self,
        snapshot: &CorpusSnapshot,
        manifest: &RunManifest,
        assembled: &mut Assembled,
        started: Instant,
    ) -> Result<WrittenRun, WriteError> {
        let t0 = Instant::now();
        check_all(snapshot, manifest, assembled)?;
        // First serialization pass: proves round trips and measures the cost.
        let mut pending = serialize_all(assembled)?;
        if self.include_manifest {
            pending.insert(0, serialize_manifest(manifest)?);
        }
        let serialization = t0.elapsed();
        // Record the measured phases, then serialize the artifact for real.
        if let Some(diagnostics) = assembled.artifact.diagnostics.as_mut() {
            for p in &mut diagnostics.phases {
                match p.phase {
                    Phase::Serialization => {
                        p.duration_ms =
                            u64::try_from(serialization.as_millis()).unwrap_or(u64::MAX);
                    }
                    Phase::Total => {
                        p.duration_ms =
                            u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                    }
                    _ => {}
                }
            }
            diagnostics.duration_ms = diagnostics
                .phases
                .iter()
                .find(|p| p.phase == Phase::Total)
                .map_or(diagnostics.duration_ms, |p| p.duration_ms);
            // Diagnostics are not digested, but they are still validated.
            validate(&assembled.artifact).map_err(|_| WriteError::Invalid)?;
        }
        let last = pending.len() - 1;
        pending[last] = serialize_artifact(&assembled.artifact)?;
        self.commit(pending, serialization)
    }

    fn commit(
        &self,
        pending: Vec<Pending>,
        serialization: Duration,
    ) -> Result<WrittenRun, WriteError> {
        self.prepare_directory()?;
        if self.overwrite == OverwritePolicy::Refuse {
            for p in &pending {
                if std::fs::symlink_metadata(self.dir.join(&p.name)).is_ok() {
                    return Err(WriteError::Exists);
                }
            }
        } else {
            for p in &pending {
                // Never write through a symlink, whatever the policy.
                if std::fs::symlink_metadata(self.dir.join(&p.name))
                    .is_ok_and(|m| m.file_type().is_symlink())
                {
                    return Err(WriteError::Destination);
                }
            }
        }
        // Temporary files first.
        let mut temps: Vec<(PathBuf, PathBuf, &Pending)> = Vec::new();
        let cleanup = |temps: &[(PathBuf, PathBuf, &Pending)]| {
            for (temp, _, _) in temps {
                let _ = std::fs::remove_file(temp);
            }
        };
        for p in &pending {
            let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let temp = self.dir.join(format!(
                "{TEMP_PREFIX}{}.{n}.{}",
                std::process::id(),
                p.name
            ));
            // Register before creating: a half-created temp is still removed.
            temps.push((temp.clone(), self.dir.join(&p.name), p));
            let written = write_private(&temp, &p.bytes)
                .and_then(|()| self.fire(WriteStage::TempWritten(p.name.clone())));
            if let Err(e) = written {
                cleanup(&temps);
                return Err(io_error(&e));
            }
        }
        // Renames, in commit order. Under `Refuse` a file is published with a
        // hard link, which fails if the target exists (a no-overwrite primitive,
        // so a concurrent writer cannot be overwritten between a check and the
        // publish); under `Replace` it is an atomic rename.
        let mut committed: Vec<String> = Vec::new();
        let last = temps.len() - 1;
        for (i, (temp, target, p)) in temps.iter().enumerate() {
            let mut exists = false;
            let step = (|| -> io::Result<()> {
                self.fire(WriteStage::BeforeRename(p.name.clone()))?;
                if i == last {
                    // The commit marker goes in only after everything before it
                    // is durable, and a stale projection of an earlier run is
                    // gone (a new run without one must not leave the old one
                    // next to the new artifact).
                    sync_dir(&self.dir)?;
                    if self.overwrite == OverwritePolicy::Replace
                        && !pending.iter().any(|q| q.name == PUBLIC_ARTIFACT_FILE)
                    {
                        let stale = self.dir.join(PUBLIC_ARTIFACT_FILE);
                        if std::fs::symlink_metadata(&stale).is_ok_and(|m| m.is_file()) {
                            std::fs::remove_file(stale)?;
                        }
                    }
                }
                match self.overwrite {
                    OverwritePolicy::Refuse => {
                        std::fs::hard_link(temp, target).inspect_err(|e| {
                            exists = e.kind() == io::ErrorKind::AlreadyExists;
                        })?;
                        std::fs::remove_file(temp)?;
                    }
                    OverwritePolicy::Replace => std::fs::rename(temp, target)?,
                }
                committed.push(p.name.clone());
                self.fire(WriteStage::Renamed(p.name.clone()))
            })();
            if let Err(e) = step {
                cleanup(&temps);
                // Roll back what this call created (never possible to restore a
                // file that `Replace` overwrote).
                let mut stuck = Vec::new();
                for name in committed {
                    if self.overwrite == OverwritePolicy::Replace
                        || std::fs::remove_file(self.dir.join(&name)).is_err()
                    {
                        stuck.push(name);
                    }
                }
                return Err(if !stuck.is_empty() {
                    WriteError::PartiallyCommitted { committed: stuck }
                } else if exists {
                    WriteError::Exists
                } else {
                    io_error(&e)
                });
            }
        }
        // Every file is in place. A failure to make that durable is not a failed
        // run (nothing is rolled back: the files are complete and valid), and it
        // must not look like one: it is reported as its own state.
        if self
            .fire(WriteStage::AfterCommit)
            .and_then(|()| sync_dir(&self.dir))
            .is_err()
        {
            return Err(WriteError::CommitNotDurable {
                files: pending.iter().map(|p| p.name.clone()).collect(),
            });
        }
        Ok(WrittenRun {
            files: pending
                .iter()
                .map(|p| WrittenFile {
                    name: p.name.clone(),
                    bytes: p.bytes.len() as u64,
                    sha256: Sha256Digest::of_bytes(&p.bytes),
                })
                .collect(),
            serialization,
        })
    }

    fn prepare_directory(&self) -> Result<(), WriteError> {
        match std::fs::symlink_metadata(&self.dir) {
            Ok(m) if m.is_dir() && !m.file_type().is_symlink() => Ok(()),
            Ok(_) => Err(WriteError::Destination),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mut builder = std::fs::DirBuilder::new();
                #[cfg(unix)]
                std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
                builder.create(&self.dir).map_err(|e| io_error(&e))
            }
            Err(e) => Err(io_error(&e)),
        }
    }
}

/// Every validation and verification the writer owes before anything is written.
fn check_all(
    snapshot: &CorpusSnapshot,
    manifest: &RunManifest,
    assembled: &Assembled,
) -> Result<(), WriteError> {
    let invalid = |_| WriteError::Invalid;
    validate(snapshot).map_err(invalid)?;
    validate(manifest).map_err(invalid)?;
    validate_manifest_against_snapshot(manifest, snapshot).map_err(invalid)?;
    let artifact = &assembled.artifact;
    if artifact.semantic.scanners.len() != assembled.observations.len() {
        return Err(WriteError::Invalid);
    }
    for (obs, scanner) in assembled
        .observations
        .iter()
        .zip(&artifact.semantic.scanners)
    {
        validate(obs).map_err(invalid)?;
        validate_observation_against_manifest(obs, manifest).map_err(invalid)?;
        validate_observation_against_snapshot(obs, snapshot).map_err(invalid)?;
        if obs.semantic_digest != scanner.observation_digest {
            return Err(WriteError::Invalid);
        }
    }
    validate(artifact).map_err(invalid)?;
    validate_artifact_against_manifest(artifact, manifest).map_err(invalid)?;
    // The verifier is called on EVERY artifact the writer produces.
    verify_run_artifact_accounting(artifact, snapshot).map_err(WriteError::Verification)?;
    if let Some(public) = &assembled.public {
        validate(public).map_err(invalid)?;
        verify_public_artifact_accounting(public, snapshot).map_err(WriteError::Verification)?;
        let projected = artifact.to_public_synthetic().map_err(invalid)?;
        if *public != projected {
            return Err(WriteError::Invalid);
        }
    }
    Ok(())
}

fn serialize_artifact(artifact: &RunArtifact) -> Result<Pending, WriteError> {
    let text = serialize_internal(artifact).map_err(|_| WriteError::Invalid)?;
    let back: RunArtifact = parse_default(text.as_bytes()).map_err(|_| WriteError::RoundTrip)?;
    if back != *artifact {
        return Err(WriteError::RoundTrip);
    }
    Ok(Pending {
        name: RUN_ARTIFACT_FILE.to_owned(),
        bytes: text.into_bytes(),
    })
}

fn serialize_manifest(manifest: &RunManifest) -> Result<Pending, WriteError> {
    let text = to_pretty_json(manifest).map_err(|_| WriteError::Invalid)?;
    let back: RunManifest = parse_default(text.as_bytes()).map_err(|_| WriteError::RoundTrip)?;
    if back != *manifest {
        return Err(WriteError::RoundTrip);
    }
    Ok(Pending {
        name: MANIFEST_FILE.to_owned(),
        bytes: text.into_bytes(),
    })
}

fn serialize_public(public: &PublicSyntheticArtifact) -> Result<Pending, WriteError> {
    let text = serialize_public_synthetic(public).map_err(|_| WriteError::Invalid)?;
    let back: PublicSyntheticArtifact =
        parse_default(text.as_bytes()).map_err(|_| WriteError::RoundTrip)?;
    if back != *public {
        return Err(WriteError::RoundTrip);
    }
    Ok(Pending {
        name: PUBLIC_ARTIFACT_FILE.to_owned(),
        bytes: text.into_bytes(),
    })
}

/// All documents in commit order: observation sets, the public projection, then
/// the run artifact last.
fn serialize_all(assembled: &Assembled) -> Result<Vec<Pending>, WriteError> {
    let mut out = Vec::new();
    for obs in &assembled.observations {
        let text = to_pretty_json(obs).map_err(|_| WriteError::Invalid)?;
        let back: pii_eval_contracts::ObservationSet =
            parse_default(text.as_bytes()).map_err(|_| WriteError::RoundTrip)?;
        if back != *obs {
            return Err(WriteError::RoundTrip);
        }
        out.push(Pending {
            name: observation_file_name(obs.semantic.scanner.scanner_id.as_str()),
            bytes: text.into_bytes(),
        });
    }
    if let Some(public) = &assembled.public {
        out.push(serialize_public(public)?);
    }
    out.push(serialize_artifact(&assembled.artifact)?);
    Ok(out)
}

fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// Remove `.pii-eval-tmp.*` files a crashed writer left in `dir`. Only call it
/// while no writer is using the directory. Returns how many were removed.
pub fn cleanup_stale_temps(dir: &Path) -> io::Result<usize> {
    let mut removed = 0;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let is_temp = entry
            .file_name()
            .to_str()
            .is_some_and(|n| n.starts_with(TEMP_PREFIX));
        if is_temp && entry.file_type()?.is_file() {
            std::fs::remove_file(entry.path())?;
            removed += 1;
        }
    }
    Ok(removed)
}
