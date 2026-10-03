//! The run pipeline: validate the plan, execute, assemble, write.
//!
//! This is the library surface P8's `run` command will call. It performs no
//! argument parsing and prints nothing.

use std::sync::Arc;
use std::time::{Instant, SystemTime};

use pii_eval_adapters::ScannerAdapter;
use pii_eval_contracts::{
    CorpusSnapshot, RunManifest, validate, validate_manifest_against_snapshot,
};

use crate::assemble::{AssembleError, AssembleOptions, Assembled, assemble, variant_tasks};
use crate::exec::{
    CancelToken, EffectiveLimits, ExecError, ExecutionPlan, ExecutorConfig, ScannerRun,
    ScannerTask, effective_limits, execute,
};
use crate::write::{ArtifactWriter, WriteError, WrittenRun};

/// Why a run did not produce documents. A scanner that fails while running is
/// not one of these: it is recorded in the documents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunError {
    /// The snapshot or manifest is invalid or they do not bind to each other.
    InvalidPlan,
    /// The manifest is not protocol revision 2. This engine emits only revision
    /// 2; revision-1 documents are readable, not re-measured (ADR 0008).
    UnsupportedProtocol,
    /// The adapters do not match the manifest's scanners one for one.
    AdapterMismatch,
    /// The executor could not start.
    Exec(ExecError),
    /// The documents could not be assembled.
    Assemble(AssembleError),
    /// The documents could not be written.
    Write(WriteError),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::InvalidPlan => f.write_str("invalid plan"),
            RunError::UnsupportedProtocol => f.write_str("only protocol revision 2 can be run"),
            RunError::AdapterMismatch => f.write_str("adapters do not match the manifest"),
            RunError::Exec(e) => write!(f, "{e}"),
            RunError::Assemble(e) => write!(f, "{e}"),
            RunError::Write(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for RunError {}

/// Inputs of a run.
pub struct RunRequest<'a> {
    /// The population.
    pub snapshot: &'a CorpusSnapshot,
    /// The plan.
    pub manifest: &'a RunManifest,
    /// One adapter per manifest scanner, in manifest order.
    pub adapters: Vec<Arc<dyn ScannerAdapter>>,
}

/// Settings of a run beyond the manifest.
#[derive(Debug, Clone, Default)]
pub struct RunConfig {
    /// Executor host settings.
    pub executor: ExecutorConfig,
    /// Attach non-semantic diagnostics. Off gives byte-stable documents.
    pub diagnostics: bool,
}

/// What a run produced.
#[derive(Debug, Clone)]
pub struct RunOutput {
    /// The sealed documents.
    pub assembled: Assembled,
    /// The per-scanner execution results the documents were built from.
    pub runs: Vec<ScannerRun>,
    /// The limits the executor applied.
    pub effective: EffectiveLimits,
    /// When the run started (for the writer's `total` phase).
    pub started: Instant,
}

/// Validate, execute and assemble. Nothing is written.
pub fn run(
    request: &RunRequest<'_>,
    config: &RunConfig,
    cancel: &CancelToken,
) -> Result<RunOutput, RunError> {
    let started = Instant::now();
    let started_at = SystemTime::now();
    validate(request.snapshot).map_err(|_| RunError::InvalidPlan)?;
    validate(request.manifest).map_err(|_| RunError::InvalidPlan)?;
    validate_manifest_against_snapshot(request.manifest, request.snapshot)
        .map_err(|_| RunError::InvalidPlan)?;
    let m = &request.manifest.semantic;
    if !m.protocol.is_canonical() {
        return Err(RunError::UnsupportedProtocol);
    }
    if request.adapters.len() != m.scanners.len() {
        return Err(RunError::AdapterMismatch);
    }
    let tasks = variant_tasks(request.snapshot);
    let scanners: Vec<ScannerTask> = m
        .scanners
        .iter()
        .zip(&request.adapters)
        .map(|(plan, adapter)| ScannerTask {
            plan: plan.clone(),
            adapter: Arc::clone(adapter),
        })
        .collect();
    let plan = ExecutionPlan {
        variants: &tasks,
        scanners: &scanners,
        limits: m.limits,
        replays: m.mechanics.replays,
    };
    let effective = effective_limits(&m.limits, &config.executor).map_err(RunError::Exec)?;
    let runs = execute(&plan, &config.executor, cancel).map_err(RunError::Exec)?;
    let assembled = assemble(
        request.snapshot,
        request.manifest,
        &tasks,
        &runs,
        AssembleOptions {
            diagnostics: config.diagnostics,
            run_started_at: started_at,
        },
    )
    .map_err(RunError::Assemble)?;
    Ok(RunOutput {
        assembled,
        runs,
        effective,
        started,
    })
}

/// [`run`], then write the documents with `writer`.
pub fn run_and_write(
    request: &RunRequest<'_>,
    config: &RunConfig,
    cancel: &CancelToken,
    writer: &ArtifactWriter,
) -> Result<(RunOutput, WrittenRun), RunError> {
    let mut output = run(request, config, cancel)?;
    let written = writer
        .write_run(
            request.snapshot,
            request.manifest,
            &mut output.assembled,
            output.started,
        )
        .map_err(RunError::Write)?;
    Ok((output, written))
}
