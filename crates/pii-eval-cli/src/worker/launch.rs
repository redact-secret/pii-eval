//! `pii-eval worker-job --job FILE`: the launcher.
//!
//! Order of work (docs/worker-job.md); each step before the next, and no
//! protected entry is read before step 6:
//!
//! 1. every adapter slot must hold an admitted adapter, else
//!    `contract-not-final: <slot>` (exit 6) and nothing is touched;
//! 2. read and check the job document;
//! 3. staged files are regular, unaliased, not group/other writable;
//! 4. parse the worker configuration; the run class must be `protected`;
//! 5. each staged artifact hashes to its pin (engine, adapter bundle, candidate
//!    bundle, runtime), then the bundles are extracted into scratch and the
//!    package TREE digest and the shim digest are checked;
//! 6. the entries listing equals the job's; each entry is read (regular file,
//!    at most 16 MiB), decoded and validated;
//! 7. the snapshot is assembled and its semantic digest equals the population
//!    pin (`population-binding-mismatch`); the manifest binds to it;
//! 8. the adapter is built and its plan must equal the manifest's;
//! 9. the SAME pipeline as `pii-eval run` runs (`crate::run::run_and_write`:
//!    bounded executor, kernel accounting, verifying atomic writer); every output
//!    file goes under the scratch directory;
//! 10. the result and (for a complete measurement) the aggregates are built and
//!     bounded; the aggregates go through the channel adapter; only then is the
//!     result returned for printing.
//!
//! A scanner crash, timeout or malformed reply is recorded in the run artifact
//! by the executor; the launcher then reports `failed = expected` and exits 0
//! (the custodian maps that to `Partial`, A6). Everything before step 9 is a
//! refusal: nothing on stdout, a non-zero exit.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use pii_eval_adapters::ScannerAdapter;
use pii_eval_contracts::{
    CorpusSnapshot, CorpusSnapshotBody, ENGINE_VERSION, ProductIdentity, ReasonCode, RunClass,
    ScannerStatus, Violations, seal, validate, validate_manifest_against_snapshot,
};

use crate::cmd_run::{exec_failure, write_failure};
use crate::config::{ProductKind, ScannerConfig};
use crate::exec::{CancelToken, ExecutorConfig};
use crate::files::{OutputDir, prepare_output};
use crate::run::{RunConfig as PipelineConfig, RunError, RunRequest, run_and_write};
use crate::scanners::build_adapter;
use crate::status::{Exit, Failure, reason as cli_reason};
use crate::worker::aggregates;
use crate::worker::bundle;
use crate::worker::contract::{
    AdapterPolicy, Adapters, BundleError, Resolved, WorkerLayout, staged,
};
use crate::worker::digest::EngineDigest;
use crate::worker::entry::{self, MAX_ENTRY_BYTES, MAX_TOTAL_ENTRY_BYTES};
use crate::worker::job::{self, Job, ReadFailure, Roster};
use crate::worker::reason;
use crate::worker::stage;
use crate::write::{
    ArtifactWriter, MANIFEST_FILE, OverwritePolicy, RUN_ARTIFACT_FILE, observation_file_name,
};

/// Directory created inside the scratch directory; everything the launcher
/// writes is below it.
pub const WORK_DIR: &str = "pii-eval-worker";

/// What one launch needs.
pub struct WorkerRequest<'a> {
    /// The job document (`--job FILE`).
    pub job: &'a Path,
    /// The adapters.
    pub adapters: &'a Adapters,
    /// Which adapter statuses may run. The binary always passes
    /// [`AdapterPolicy::Production`].
    pub policy: AdapterPolicy,
}

/// A completed launch.
#[derive(Clone)]
pub struct WorkerOutput {
    /// The one result document to print.
    pub result: String,
    /// Its counters.
    pub roster: Roster,
    /// Final status of the scanner.
    pub scanner_status: ScannerStatus,
    /// Semantic digest of the run artifact (in the scratch directory).
    pub run_artifact_digest: String,
    /// The aggregates document that was delivered, when the measurement was complete.
    pub aggregates: Option<Vec<u8>>,
    /// Directory of the run's documents (under the scratch directory).
    pub out_dir: PathBuf,
}

impl std::fmt::Debug for WorkerOutput {
    /// Counters and identities only: never the aggregates bytes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkerOutput")
            .field("roster", &self.roster)
            .field("scanner_status", &self.scanner_status)
            .field("run_artifact_digest", &self.run_artifact_digest)
            .field("aggregates_bytes", &self.aggregates.as_ref().map(Vec::len))
            .finish()
    }
}

fn layout_dir(p: &Path, what: &str) -> Result<PathBuf, Failure> {
    std::fs::canonicalize(p)
        .ok()
        .filter(|c| c.is_dir())
        .ok_or_else(|| reason::mismatch(reason::STAGED_FILE_INVALID, what))
}

fn bundle_failure(slot: &str, e: BundleError) -> Failure {
    let detail = format!("{slot}-{}", e.name());
    match e {
        BundleError::Extract => reason::output(reason::BUNDLE_EXTRACT_FAILED, &detail),
        _ => reason::invalid(reason::BUNDLE_INVALID, &detail),
    }
}

fn product_of(identity: &ProductIdentity) -> ProductKind {
    match identity {
        ProductIdentity::Released => ProductKind::Released,
        ProductIdentity::Candidate { .. } => ProductKind::Candidate,
    }
}

fn binding_failure(v: &Violations) -> Failure {
    let has = |c: ReasonCode| v.errors.iter().any(|e| e.code == c);
    if has(ReasonCode::PopulationBindingMismatch) {
        reason::mismatch(reason::POPULATION_BINDING_MISMATCH, "manifest")
    } else if has(ReasonCode::RunClassMismatch) {
        reason::mismatch(reason::RUN_CLASS_MISMATCH, "manifest")
    } else {
        reason::mismatch(reason::MANIFEST_BINDING_MISMATCH, "snapshot")
    }
}

/// Read the entries (step 6): the listing must equal the job's, every entry a
/// regular file, bounded, decoded and validated.
fn read_entries(
    resolved: &Resolved<'_>,
    input: &Path,
    job: &Job,
    config: &crate::worker::config::WorkerConfig,
) -> Result<Vec<pii_eval_contracts::Case>, Failure> {
    let listed = std::fs::read_dir(input)
        .map_err(|_| reason::mismatch(reason::ENTRIES_LISTING_MISMATCH, "input"))?;
    let mut names = Vec::new();
    for item in listed.take(job::MAX_ENTRIES + 1) {
        let item = item.map_err(|_| reason::mismatch(reason::ENTRIES_LISTING_MISMATCH, "input"))?;
        let name = item
            .file_name()
            .into_string()
            .map_err(|_| reason::mismatch(reason::ENTRIES_LISTING_MISMATCH, "input"))?;
        names.push(name);
    }
    names.sort_unstable();
    if names != job.entries {
        return Err(reason::mismatch(reason::ENTRIES_LISTING_MISMATCH, "input"));
    }
    let mut cases = Vec::with_capacity(job.entries.len());
    let mut total = 0usize;
    for name in &job.entries {
        let path = input.join(name);
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|_| reason::invalid(reason::ENTRY_UNREADABLE, ""))?;
        #[cfg(unix)]
        let aliased = std::os::unix::fs::MetadataExt::nlink(&meta) != 1;
        #[cfg(not(unix))]
        let aliased = false;
        if !meta.file_type().is_file() || aliased {
            return Err(reason::invalid(reason::ENTRY_NOT_REGULAR, ""));
        }
        let bytes = job::read_bounded(&path, MAX_ENTRY_BYTES).map_err(|e| match e {
            ReadFailure::Unreadable => reason::invalid(reason::ENTRY_UNREADABLE, ""),
            ReadFailure::TooLarge => reason::invalid(reason::ENTRY_TOO_LARGE, ""),
        })?;
        total += bytes.len();
        if total > MAX_TOTAL_ENTRY_BYTES {
            return Err(reason::invalid(reason::ENTRIES_TOO_LARGE, ""));
        }
        let case = resolved
            .entry_format
            .decode(name, &bytes)
            .map_err(|_| reason::invalid(reason::ENTRY_INVALID, ""))?;
        entry::validate_case(&config.header_population, &config.generation, &case)
            .map_err(|_| reason::invalid(reason::ENTRY_INVALID, ""))?;
        cases.push(case);
    }
    Ok(cases)
}

fn pipeline_failure(e: RunError) -> Failure {
    match e {
        RunError::Cancelled => Failure::new(Exit::Cancelled, cli_reason::CANCELLED),
        RunError::Write(w) => write_failure(&w),
        RunError::InvalidPlan => {
            Failure::new(Exit::Invalid, cli_reason::DOCUMENT_INVALID).with_detail("plan")
        }
        RunError::UnsupportedProtocol => {
            Failure::new(Exit::Invalid, cli_reason::PROTOCOL_UNSUPPORTED)
        }
        RunError::AdapterMismatch => reason::mismatch(reason::SCANNER_PLAN_MISMATCH, ""),
        RunError::Exec(x) => exec_failure(&x),
        RunError::Assemble(_) => Failure::new(Exit::Invalid, cli_reason::ASSEMBLY_FAILED),
    }
}

/// Run one worker job. `Ok` means a result document exists (complete or
/// partial); `Err` means a refusal: print nothing, exit non-zero.
pub fn run_worker_job(
    request: &WorkerRequest<'_>,
    cancel: &CancelToken,
) -> Result<WorkerOutput, Failure> {
    // 1. Nothing is touched unless every slot holds an admitted adapter.
    let resolved = request.adapters.resolve(request.policy)?;
    if !cfg!(unix) {
        return Err(Failure::new(
            Exit::Execution,
            cli_reason::PLATFORM_UNSUPPORTED,
        ));
    }
    let layout: WorkerLayout = resolved.stage_layout.layout();
    let stage_dir = layout_dir(&layout.stage, "stage")?;
    let input_dir = layout_dir(&layout.input, "input")?;
    let scratch_dir = layout_dir(&layout.scratch, "scratch")?;

    // 2. The job.
    let job = job::read_job(request.job)?;

    ensure_live(cancel)?;
    // 3. The staged files.
    for name in [
        staged::ENGINE,
        staged::ADAPTER,
        staged::CANDIDATE,
        staged::CONFIG,
        staged::RUNTIME,
    ] {
        stage::check_shape(&stage_dir.join(name), name)?;
    }

    // 4. The configuration.
    let config_bytes = job::read_bounded(
        &stage_dir.join(staged::CONFIG),
        crate::worker::config::MAX_CONFIG_BYTES,
    )
    .map_err(|e| match e {
        ReadFailure::Unreadable => reason::invalid(reason::WORKER_CONFIG_INVALID, "unreadable"),
        ReadFailure::TooLarge => reason::invalid(reason::WORKER_CONFIG_TOO_LARGE, ""),
    })?;
    let config = crate::worker::config::parse(&config_bytes)?;
    if config.run_class != RunClass::Protected
        || config.manifest.semantic.run_class != config.run_class
        || !config
            .run_class
            .matches(config.header_population.visibility)
    {
        return Err(reason::mismatch(reason::RUN_CLASS_MISMATCH, ""));
    }
    if config.manifest.semantic.scanners.len() != 1 {
        return Err(reason::invalid(reason::SCANNER_COUNT_UNSUPPORTED, ""));
    }

    // 5. Digests, extraction, tree and shim. A bundle is read ONCE: the pinned
    // digest is computed over, and the extraction reads, the same bytes.
    ensure_live(cancel)?;
    stage::verify_file(
        &stage_dir.join(staged::ENGINE),
        stage::Pinned::Engine(&config.engine),
    )?;
    stage::verify_file(
        &stage_dir.join(staged::RUNTIME),
        stage::Pinned::Runtime(&config.runtime),
    )?;
    let work = scratch_dir.join(WORK_DIR);
    create_dir(&work)?;
    let guard = WorkGuard::new(work.clone());
    let adapter_dir = work.join("adapter");
    let package_dir = work.join("candidate");
    for (name, pin, dir) in [
        (
            staged::ADAPTER,
            stage::Pinned::AdapterBundle(&config.adapter_bundle),
            &adapter_dir,
        ),
        (
            staged::CANDIDATE,
            stage::Pinned::CandidateBundle(&config.candidate_bundle),
            &package_dir,
        ),
    ] {
        let bytes = job::read_bounded(
            &stage_dir.join(name),
            bundle::MAX_BUNDLE_FILE_BYTES as usize,
        )
        .map_err(|_| reason::mismatch(reason::STAGED_FILE_INVALID, name))?;
        stage::verify_bytes(&bytes, pin)?;
        resolved
            .bundle_format
            .extract(&bytes, dir)
            .map_err(|e| bundle_failure(name, e))?;
    }
    let shim = adapter_dir.join(stage::SHIM_MEMBER);
    stage::verify_shim(&shim)?;
    stage::verify_tree(&package_dir, &config.tree)?;
    ensure_live(cancel)?;

    // 6. The entries.
    let cases = read_entries(&resolved, &input_dir, &job, &config)?;

    ensure_live(cancel)?;
    // 7. The snapshot and its bindings.
    let mut snapshot = CorpusSnapshot::unsealed(CorpusSnapshotBody {
        population: config.header_population.clone(),
        generation: config.generation.clone(),
        cases,
    });
    seal(&mut snapshot).map_err(|_| reason::invalid(reason::ENTRY_INVALID, "snapshot"))?;
    validate(&snapshot).map_err(|_| reason::invalid(reason::ENTRY_INVALID, "snapshot"))?;
    if EngineDigest::from_contract(snapshot.semantic_digest.clone()) != config.population {
        return Err(reason::mismatch(
            reason::POPULATION_BINDING_MISMATCH,
            "snapshot",
        ));
    }
    let manifest = &config.manifest;
    validate_manifest_against_snapshot(manifest, &snapshot).map_err(|v| binding_failure(&v))?;
    let m = &manifest.semantic;
    if m.engine.version.as_str() != ENGINE_VERSION {
        return Err(reason::mismatch(
            reason::MANIFEST_BINDING_MISMATCH,
            "engine",
        ));
    }
    if !m.protocol.is_canonical() {
        return Err(reason::mismatch(
            reason::MANIFEST_BINDING_MISMATCH,
            "protocol",
        ));
    }
    let plan = &m.scanners[0];
    if product_of(&plan.identity.product) != config.product {
        return Err(reason::mismatch(
            reason::MANIFEST_BINDING_MISMATCH,
            "product",
        ));
    }

    ensure_live(cancel)?;
    // 8. The adapter; its plan must equal the manifest's.
    let scanner_config = ScannerConfig {
        node: None,
        shim,
        package_dir,
        entry: config.entry.clone(),
        version: config.version.clone(),
        tree_sha256: Some(config.tree.as_engine().as_contract().clone()),
        extra: Vec::new(),
        startup_timeout_ms: config.startup_timeout_ms,
        call_timeout_ms: config.call_timeout_ms,
    };
    let adapter: Arc<dyn ScannerAdapter> = build_adapter(
        &scanner_config,
        config.product,
        &stage_dir.join(staged::RUNTIME),
    )?;
    let derived = adapter
        .plan(plan.configuration.clone())
        .map_err(|_| reason::mismatch(reason::SCANNER_PLAN_MISMATCH, ""))?;
    if derived.identity != plan.identity {
        return Err(reason::mismatch(reason::SCANNER_PLAN_MISMATCH, ""));
    }

    // 9. The same pipeline as `pii-eval run`; every file under scratch.
    ensure_live(cancel)?;
    let run_scratch = work.join("run");
    create_dir(&run_scratch)?;
    let executor = ExecutorConfig {
        max_workers: config.max_workers,
        scratch_root: Some(run_scratch),
        ..ExecutorConfig::default()
    };
    crate::exec::effective_limits(&m.limits, &executor).map_err(|e| exec_failure(&e))?;
    let out_dir = work.join("out");
    let names = vec![
        MANIFEST_FILE.to_owned(),
        observation_file_name(plan.identity.scanner_id.as_str()),
        RUN_ARTIFACT_FILE.to_owned(),
    ];
    let output: OutputDir = prepare_output(&out_dir, &names, OverwritePolicy::Refuse)?;
    let writer = ArtifactWriter::new(output.path(), OverwritePolicy::Refuse).with_manifest();
    let result = run_and_write(
        &RunRequest {
            snapshot: &snapshot,
            manifest,
            adapters: vec![adapter],
        },
        &PipelineConfig {
            executor,
            diagnostics: false,
            commit_cancelled: false,
        },
        cancel,
        &writer,
    );
    let (out, _written) = match result {
        Ok(ok) => ok,
        Err(RunError::Write(crate::write::WriteError::CommitNotDurable { files })) => {
            output.commit();
            return Err(write_failure(&crate::write::WriteError::CommitNotDurable {
                files,
            }));
        }
        Err(e) => return Err(pipeline_failure(e)),
    };
    output.commit();
    guard.keep_out();

    // 10. The result and the aggregates.
    let artifact = &out.assembled.artifact;
    let status = artifact
        .semantic
        .scanners
        .first()
        .map(|s| s.status)
        .ok_or_else(|| Failure::new(Exit::Internal, cli_reason::INTERNAL))?;
    let expected = job.entries.len() as u64;
    let roster = Roster {
        expected,
        observed: expected,
        failed: if status == ScannerStatus::Complete {
            0
        } else {
            expected
        },
    };
    let mut delivered = None;
    if roster.failed == 0 {
        let metrics = &artifact
            .semantic
            .scanner_metrics
            .first()
            .ok_or_else(|| Failure::new(Exit::Internal, cli_reason::INTERNAL))?
            .metrics;
        let document = aggregates::build(&roster, metrics, resolved.aggregate_labels)?;
        resolved
            .aggregates_channel
            .deliver(
                &WorkerLayout {
                    stage: stage_dir,
                    input: input_dir,
                    scratch: scratch_dir,
                },
                &document,
            )
            .map_err(|_| reason::output(reason::AGGREGATES_CHANNEL_FAILED, ""))?;
        delivered = Some(document);
    }
    let result = job::render_result(&roster)?;
    Ok(WorkerOutput {
        result,
        roster,
        scanner_status: status,
        run_artifact_digest: artifact.semantic_digest.as_str().to_owned(),
        aggregates: delivered,
        out_dir,
    })
}

/// Removes what the launcher created in scratch on EVERY exit path: the extracted
/// packages and the executor's scratch always; the run documents (`out`) are kept
/// only after a committed run, and only until the sandbox discards scratch.
struct WorkGuard {
    dir: PathBuf,
    keep_out: std::cell::Cell<bool>,
}

impl WorkGuard {
    fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            keep_out: std::cell::Cell::new(false),
        }
    }

    fn keep_out(&self) {
        self.keep_out.set(true);
    }
}

impl Drop for WorkGuard {
    fn drop(&mut self) {
        for name in ["adapter", "candidate", "run"] {
            let _ = std::fs::remove_dir_all(self.dir.join(name));
        }
        if !self.keep_out.get() {
            let _ = std::fs::remove_dir_all(self.dir.join("out"));
        }
        // Succeeds only when nothing is left (kept documents stay).
        let _ = std::fs::remove_dir(&self.dir);
    }
}

fn ensure_live(cancel: &CancelToken) -> Result<(), Failure> {
    if cancel.is_cancelled() {
        Err(Failure::new(Exit::Cancelled, cli_reason::CANCELLED))
    } else {
        Ok(())
    }
}

fn create_dir(path: &Path) -> Result<(), Failure> {
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(path)
        .map_err(|_| reason::output(reason::BUNDLE_EXTRACT_FAILED, "work-dir"))
}
