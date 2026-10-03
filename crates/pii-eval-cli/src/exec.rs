//! Bounded, deterministic scanner execution (P7, ADR 0009).
//!
//! The executor runs every planned scanner over every variant of one snapshot
//! and returns, per scanner, what was observed or why nothing was. It scores
//! nothing; the kernel does that from these observations.
//!
//! # Bounds (all explicit)
//!
//! * **Workers.** At most `min(limits.workers, ExecutorConfig::max_workers)`
//!   scanner sessions run at once, across all scanners; `max_workers` defaults to
//!   the number of logical CPUs, so a plan cannot oversubscribe the host. At most
//!   `per_scanner_parallelism` sessions serve one scanner.
//! * **Pending tasks.** A bounded channel of `pending_tasks` batches of
//!   `batch_variants` variants feeds a scanner's workers; the producer blocks
//!   when it is full.
//! * **Time.** `scanner_timeout_ms` is the total wall-clock budget of one scanner
//!   (all replays). A watchdog kills the process trees of an overdue scanner; the
//!   per-call timeout is the adapter's own.
//! * **Memory and scratch.** `max_memory_bytes` and `max_temporary_bytes` are
//!   whole-run budgets, split evenly over the concurrent sessions; the
//!   [`pii_eval_adapters::Supervisor`] samples and aborts a session above its
//!   share. Each session gets its own scratch directory (mode 0700), removed when
//!   the session ends and when the run ends.
//! * **Output.** `max_stdout_bytes`/`max_stderr_bytes` must be at least what the
//!   adapter enforces; a smaller manifest bound is refused before anything runs.
//! * **Raw buffers.** Only the first pass retains observations; replay passes
//!   compare on the fly and keep a bit per input. Sanitized output is verified
//!   immediately and dropped.
//!
//! # Determinism
//!
//! Results are indexed by manifest scanner order and variant order, never by
//! completion order. A scanner failure is the failure of the **lowest variant
//! index** among those attempted, and tasks below the lowest failure always run,
//! so the recorded failure does not depend on which worker was faster (for a
//! scanner whose behavior is itself deterministic).
//!
//! # Replays
//!
//! `replays` is the number of passes over every input (the first included). Each
//! pass uses fresh scanner processes, so process-local state cannot hide
//! instability. A pass that differs from the first (findings, input digest or
//! sanitized-output digest) marks that input; any marked input makes the scanner
//! `unstable` with a `replay-disagreement` failure counting the marked inputs.
//! Replays are stability checks, not extra samples.
//!
//! Not a sandbox: see `pii_eval_adapters::control`.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, sync_channel};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use pii_eval_adapters::error::{LimitKind, MalformedKind, PinKind};
use pii_eval_adapters::{
    AbortHandle, AbortReason, AdapterError, RuntimeRecord, ScanOutput, ScanSession, ScannerAdapter,
    StartOptions, Supervisor, SupervisorError, TREE_CLEANUP_SUPPORTED,
};
use pii_eval_contracts::limits::execution::MAX_WORKERS;
use pii_eval_contracts::{
    ActionCapability, ByteRange, CapabilityState, ExecutionLimits, FailureCode, Finding, Id,
    OffsetUnitName, OutputVerification, ReplayRecord, RuntimeProvenance, ScannerCapabilities,
    ScannerId, ScannerPlan, ScannerStatus, Sha256Digest, VersionString,
};
use pii_eval_kernel::{OffsetUnit, OutputError, verify_output};

/// Smallest memory or scratch share per session the executor accepts: a Node
/// process alone needs tens of MiB, so a smaller share can never succeed.
pub const MIN_SESSION_MEMORY_BYTES: u64 = 32 * 1024 * 1024;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Cooperative cancellation. Cloning shares the flag.
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    /// A token that is not cancelled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Cancel: running sessions are killed (tree included) and no new work starts.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Whether [`CancelToken::cancel`] was called.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// Whether resource limits are enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourcePolicy {
    /// Enforce memory and scratch limits; refuse to run if the host cannot
    /// sample resource use (the default).
    Enforce,
    /// Do not enforce them. An explicit choice for hosts without `ps`; the
    /// custodian must then bound resources externally.
    Unenforced,
}

/// Host-side executor settings that are not part of the manifest.
#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    /// Hard cap on concurrent sessions, whatever the manifest asks for.
    pub max_workers: usize,
    /// Interval of the resource sampler.
    pub sample_interval: Duration,
    /// Parent of the run's scratch directories; the system temp directory by default.
    pub scratch_root: Option<PathBuf>,
    /// Resource enforcement.
    pub resources: ResourcePolicy,
    /// Refuse to run where descendants of a scanner cannot be cleaned up
    /// (non-Unix). Default `true`.
    pub require_tree_cleanup: bool,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            max_workers: thread::available_parallelism().map_or(1, usize::from),
            sample_interval: Duration::from_millis(250),
            scratch_root: None,
            resources: ResourcePolicy::Enforce,
            require_tree_cleanup: true,
        }
    }
}

/// Why a run could not be started. A scanner that fails while running is not an
/// error here: it is recorded in its [`ScannerRun`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecError {
    /// A manifest limit is zero or inconsistent.
    InvalidLimits,
    /// The adapter of a scanner enforces larger output bounds than the manifest allows.
    AdapterExceedsManifestBounds {
        /// Index of the scanner in plan order.
        scanner: usize,
    },
    /// The memory or scratch share of one session would be below
    /// [`MIN_SESSION_MEMORY_BYTES`].
    BudgetTooSmall,
    /// Resource limits are enforced but the host cannot sample them.
    ResourceMonitor(SupervisorError),
    /// Descendant cleanup is required and not available on this platform.
    TreeCleanupUnsupported,
    /// The scratch directory could not be created.
    Scratch,
    /// The adapter list does not match the plan.
    AdapterCountMismatch,
}

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecError::InvalidLimits => f.write_str("invalid execution limits"),
            ExecError::AdapterExceedsManifestBounds { scanner } => {
                write!(
                    f,
                    "adapter {scanner} enforces larger output bounds than the manifest"
                )
            }
            ExecError::BudgetTooSmall => f.write_str("per-session resource share is too small"),
            ExecError::ResourceMonitor(e) => write!(f, "resource monitor unavailable: {e:?}"),
            ExecError::TreeCleanupUnsupported => {
                f.write_str("process-tree cleanup is not supported on this platform")
            }
            ExecError::Scratch => f.write_str("scratch directory unavailable"),
            ExecError::AdapterCountMismatch => f.write_str("adapter count differs from the plan"),
        }
    }
}

impl std::error::Error for ExecError {}

/// One variant to scan: its identity, exact text and authored occurrence
/// ranges (used only for sanitized-output verification, never sent to the scanner).
#[derive(Debug, Clone)]
pub struct VariantTask<'a> {
    /// Variant id.
    pub variant_id: &'a Id,
    /// The exact input text.
    pub text: &'a str,
    /// Authored occurrence ranges, in the variant's expectation order.
    pub ranges: Vec<ByteRange>,
}

/// One planned scanner and the adapter that runs it.
#[derive(Clone)]
pub struct ScannerTask {
    /// The bound plan (identity plus configuration).
    pub plan: ScannerPlan,
    /// The adapter. Shared across threads; it only starts sessions.
    pub adapter: Arc<dyn ScannerAdapter>,
}

/// Everything the executor needs.
pub struct ExecutionPlan<'a> {
    /// Variants in canonical (snapshot) order.
    pub variants: &'a [VariantTask<'a>],
    /// Scanners in plan order (ascending by scanner id).
    pub scanners: &'a [ScannerTask],
    /// The manifest's execution limits.
    pub limits: ExecutionLimits,
    /// Passes over every input (the manifest's `mechanics.replays`).
    pub replays: u32,
}

/// What was observed for one input in the first pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedInput {
    /// Index into [`ExecutionPlan::variants`].
    pub index: usize,
    /// SHA-256 of the exact input bytes.
    pub input_digest: Sha256Digest,
    /// SHA-256 of the sanitized output, when the scanner returned one.
    pub sanitized_output_digest: Option<Sha256Digest>,
    /// Normalized findings in canonical order.
    pub findings: Vec<Finding>,
    /// One verdict per authored occurrence (variant expectation order), when
    /// sanitized output was available and verified.
    pub verification: Option<Vec<OutputVerification>>,
}

/// Sanitized failure of one scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScannerFailure {
    /// Contract failure code.
    pub code: FailureCode,
    /// Inputs left unmeasured (every input, except for a replay disagreement,
    /// which counts the inputs that disagreed).
    pub affected_inputs: u64,
}

/// Non-semantic timing of one scanner run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScannerTiming {
    /// Time spent starting sessions, summed over sessions (can exceed wall time).
    pub startup: Duration,
    /// Time spent inside scan calls, summed over calls (can exceed wall time).
    pub scan: Duration,
    /// Wall-clock time of the whole scanner run.
    pub wall: Duration,
    /// When the run started and ended, for diagnostics.
    pub started_at: SystemTime,
    /// When the run ended.
    pub finished_at: SystemTime,
    /// Highest sampled resident set of any session of this scanner, in bytes.
    pub peak_rss_bytes: u64,
}

/// The result of running one scanner.
#[derive(Debug, Clone)]
pub struct ScannerRun {
    /// The plan this scanner ran under.
    pub plan: ScannerPlan,
    /// Final status. Anything but `complete` measured nothing.
    pub status: ScannerStatus,
    /// Capabilities the scanner declared (or, for a failed start, what is known).
    pub capabilities: ScannerCapabilities,
    /// Replay record: `count` is the planned number of passes; `agreed` is false
    /// only for an unstable scanner.
    pub replays: ReplayRecord,
    /// Observations in variant order; empty unless `status` is `complete`.
    pub inputs: Vec<ObservedInput>,
    /// The failure, when status is not `complete`.
    pub failure: Option<ScannerFailure>,
    /// What actually ran, from the first session that started.
    pub runtime: Option<RuntimeProvenance>,
    /// Non-semantic timing.
    pub timing: ScannerTiming,
}

/// The limits the executor actually applied (diagnostic; not an artifact field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveLimits {
    /// Concurrent sessions across scanners.
    pub workers: usize,
    /// Sessions per scanner.
    pub per_scanner_parallelism: usize,
    /// Scanners running at once.
    pub scanner_concurrency: usize,
    /// Memory share of one session, in bytes (0 when unenforced).
    pub session_memory_bytes: u64,
    /// Scratch share of one session, in bytes (0 when unenforced).
    pub session_scratch_bytes: u64,
}

/// Compute the limits that will apply, or refuse.
pub fn effective_limits(
    limits: &ExecutionLimits,
    config: &ExecutorConfig,
) -> Result<EffectiveLimits, ExecError> {
    let positive = limits.workers > 0
        && limits.workers <= MAX_WORKERS
        && limits.per_scanner_parallelism > 0
        && limits.per_scanner_parallelism <= limits.workers
        && limits.pending_tasks > 0
        && limits.batch_variants > 0
        && limits.scanner_timeout_ms > 0
        && config.max_workers > 0;
    if !positive {
        return Err(ExecError::InvalidLimits);
    }
    let workers = (limits.workers as usize).min(config.max_workers);
    let per_scanner = (limits.per_scanner_parallelism as usize).min(workers);
    let scanner_concurrency = (workers / per_scanner).max(1);
    let sessions = (scanner_concurrency * per_scanner) as u64;
    let (memory, scratch) = if config.resources == ResourcePolicy::Enforce {
        (
            limits.max_memory_bytes / sessions,
            limits.max_temporary_bytes / sessions,
        )
    } else {
        (0, 0)
    };
    if config.resources == ResourcePolicy::Enforce
        && (memory < MIN_SESSION_MEMORY_BYTES || scratch == 0)
    {
        return Err(ExecError::BudgetTooSmall);
    }
    Ok(EffectiveLimits {
        workers,
        per_scanner_parallelism: per_scanner,
        scanner_concurrency,
        session_memory_bytes: memory,
        session_scratch_bytes: scratch,
    })
}

// ---------------------------------------------------------------------------
// Scratch directories
// ---------------------------------------------------------------------------

static SCRATCH_COUNTER: AtomicU64 = AtomicU64::new(0);

fn create_private_dir(path: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(path)
}

/// A directory removed on drop.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn create(parent: &Path, label: &str) -> std::io::Result<Self> {
        let n = SCRATCH_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!("{label}-{n}"));
        create_private_dir(&path)?;
        Ok(ScratchDir(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ---------------------------------------------------------------------------
// Watchdog: deadlines and cancellation
// ---------------------------------------------------------------------------

/// Per-scanner abort state shared by its sessions and the watchdog.
struct ScannerControl {
    deadline: Instant,
    reason: AtomicU8,
    sessions: Mutex<Vec<(u64, AbortHandle)>>,
    next: AtomicU64,
    finished: AtomicBool,
}

fn code_of(reason: AbortReason) -> u8 {
    match reason {
        AbortReason::Timeout => 1,
        AbortReason::Cancelled => 2,
        AbortReason::Memory => 3,
        AbortReason::Temporary => 4,
    }
}

impl ScannerControl {
    fn new(deadline: Instant) -> Self {
        Self {
            deadline,
            reason: AtomicU8::new(0),
            sessions: Mutex::new(Vec::new()),
            next: AtomicU64::new(0),
            finished: AtomicBool::new(false),
        }
    }

    fn reason(&self) -> Option<AbortReason> {
        match self.reason.load(Ordering::SeqCst) {
            1 => Some(AbortReason::Timeout),
            2 => Some(AbortReason::Cancelled),
            _ => None,
        }
    }

    /// Record the reason (first wins) and kill every registered session.
    fn abort(&self, reason: AbortReason) {
        let _ =
            self.reason
                .compare_exchange(0, code_of(reason), Ordering::SeqCst, Ordering::SeqCst);
        let effective = self.reason().unwrap_or(reason);
        for (_, handle) in lock(&self.sessions).iter() {
            handle.trigger(effective);
        }
    }

    fn register(&self, handle: AbortHandle) -> u64 {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        // A session that starts after the abort is killed at once.
        if let Some(reason) = self.reason() {
            handle.trigger(reason);
        }
        lock(&self.sessions).push((id, handle));
        id
    }

    fn unregister(&self, id: u64) {
        lock(&self.sessions).retain(|(i, _)| *i != id);
    }
}

struct Watchdog {
    controls: Arc<Mutex<Vec<Arc<ScannerControl>>>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Watchdog {
    fn start(cancel: CancelToken) -> Self {
        let controls: Arc<Mutex<Vec<Arc<ScannerControl>>>> = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        let (c, s) = (Arc::clone(&controls), Arc::clone(&stop));
        let handle = thread::Builder::new()
            .name("pii-eval-watchdog".to_owned())
            .spawn(move || {
                while !s.load(Ordering::SeqCst) {
                    let live: Vec<Arc<ScannerControl>> = lock(&c)
                        .iter()
                        .filter(|k| !k.finished.load(Ordering::SeqCst))
                        .cloned()
                        .collect();
                    for control in live {
                        if cancel.is_cancelled() {
                            control.abort(AbortReason::Cancelled);
                        } else if Instant::now() >= control.deadline {
                            control.abort(AbortReason::Timeout);
                        }
                    }
                    thread::sleep(Duration::from_millis(15));
                }
            })
            .ok();
        Watchdog {
            controls,
            stop,
            handle,
        }
    }

    fn register(&self, control: &Arc<ScannerControl>) {
        lock(&self.controls).push(Arc::clone(control));
    }

    fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.stop();
    }
}

// ---------------------------------------------------------------------------
// One scanner
// ---------------------------------------------------------------------------

/// The lowest-index failure of a scanner's passes.
#[derive(Default)]
struct FailureSlot {
    min_index: AtomicUsize,
    error: Mutex<Option<AdapterError>>,
    capabilities: Mutex<Option<ScannerCapabilities>>,
}

impl FailureSlot {
    fn new() -> Self {
        Self {
            min_index: AtomicUsize::new(usize::MAX),
            ..Self::default()
        }
    }

    fn record(&self, index: usize, error: AdapterError) {
        let mut slot = lock(&self.error);
        if index < self.min_index.load(Ordering::SeqCst) {
            self.min_index.store(index, Ordering::SeqCst);
            *slot = Some(error);
        }
    }

    fn min(&self) -> usize {
        self.min_index.load(Ordering::SeqCst)
    }
}

struct Batch {
    start: usize,
    end: usize,
}

struct Shared<'a> {
    plan: &'a ExecutionPlan<'a>,
    scanner: &'a ScannerTask,
    eff: EffectiveLimits,
    supervisor: Option<&'a Arc<Supervisor>>,
    scratch_root: &'a Path,
    control: Arc<ScannerControl>,
    failure: FailureSlot,
    started_session: Mutex<Option<(ScannerCapabilities, RuntimeRecord)>>,
    startup_nanos: AtomicU64,
    scan_nanos: AtomicU64,
    peak_rss: AtomicU64,
}

fn classify(error: AdapterError) -> (ScannerStatus, FailureCode) {
    match (error.scanner_status(), error.failure_code()) {
        (Some(s), Some(c)) => (s, c),
        // Caller errors say nothing about the scanner: an unusable spec means it
        // could not be run; the rest is an execution error.
        _ => match error {
            AdapterError::InvalidSpec(_) => (ScannerStatus::Unavailable, FailureCode::Unavailable),
            _ => (ScannerStatus::Error, FailureCode::ExecutionError),
        },
    }
}

fn provenance(record: &RuntimeRecord) -> Option<RuntimeProvenance> {
    let version = record.runtime_version.trim_start_matches('v');
    Some(RuntimeProvenance {
        runtime_name: ScannerId::new(record.runtime_name.clone()).ok()?,
        runtime_version: VersionString::new(version).ok(),
        scanner_version: VersionString::new(record.scanner_version.clone()).ok()?,
        offset_unit: match record.offset_unit {
            OffsetUnit::Utf8Bytes => OffsetUnitName::Utf8Bytes,
            OffsetUnit::Utf16CodeUnits => OffsetUnitName::Utf16CodeUnits,
            OffsetUnit::UnicodeCodePoints => OffsetUnitName::UnicodeCodePoints,
        },
        adapter_protocol: record
            .protocol
            .rsplit('/')
            .next()
            .and_then(|n| n.parse().ok())
            .unwrap_or(0),
        shim_digest: record.shim_digest.clone(),
        artifact_digest: record.artifact_digest.clone(),
        activation_identity_digest: record.activation_identity_digest.clone(),
    })
}

/// Start one session: scratch directory, supervision, registration with the
/// watchdog. Capabilities of every session of a scanner must agree.
fn start_session<'a>(
    shared: &Shared<'a>,
) -> Result<LiveSession, (AdapterError, Option<ScannerCapabilities>)> {
    let scratch = if shared.supervisor.is_some() {
        Some(
            ScratchDir::create(shared.scratch_root, "session").map_err(|_| {
                (
                    AdapterError::StartupFailure(pii_eval_adapters::error::StartupStage::Spawn),
                    None,
                )
            })?,
        )
    } else {
        None
    };
    let options = StartOptions {
        scratch_dir: scratch.as_ref().map(|s| s.path().to_path_buf()),
        supervisor: shared.supervisor.cloned(),
        max_rss_bytes: shared.supervisor.map(|_| shared.eff.session_memory_bytes),
        max_scratch_bytes: shared.supervisor.map(|_| shared.eff.session_scratch_bytes),
    };
    let t0 = Instant::now();
    let started = shared
        .scanner
        .adapter
        .start_with(&shared.scanner.plan, &options);
    shared
        .startup_nanos
        .fetch_add(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
    let session = started.map_err(|f| (f.error, Some(f.capabilities)))?;
    {
        let mut first = lock(&shared.started_session);
        match first.as_ref() {
            None => *first = Some((session.capabilities().clone(), session.runtime().clone())),
            Some((caps, _)) if caps != session.capabilities() => {
                return Err((AdapterError::PinMismatch(PinKind::Activation), None));
            }
            Some(_) => {}
        }
    }
    let handle = session.abort_handle();
    let id = shared.control.register(handle.clone());
    Ok(LiveSession {
        session,
        handle,
        id,
        _scratch: scratch,
    })
}

struct LiveSession {
    session: Box<dyn ScanSession>,
    handle: AbortHandle,
    id: u64,
    _scratch: Option<ScratchDir>,
}

struct RoundSink {
    observed: Mutex<Vec<ObservedInput>>,
    disagreed: Mutex<Vec<usize>>,
    completed: AtomicUsize,
}

fn same_observation(reference: &ObservedInput, now: &ScanOutput) -> bool {
    reference.findings == now.findings
        && reference.input_digest == now.input_digest
        && reference.sanitized_output_digest == now.sanitized_output_digest
}

fn worker(
    shared: &Shared<'_>,
    rx: &Mutex<Receiver<Batch>>,
    sink: &RoundSink,
    reference: Option<&[Option<ObservedInput>]>,
) {
    let mut live: Option<LiveSession> = None;
    loop {
        let batch = lock(rx).recv();
        let Ok(batch) = batch else { break };
        for index in batch.start..batch.end {
            if shared.control.reason().is_some() || index > shared.failure.min() {
                break;
            }
            if live.is_none() {
                match start_session(shared) {
                    Ok(session) => live = Some(session),
                    Err((error, caps)) => {
                        if let Some(caps) = caps {
                            lock(&shared.failure.capabilities).get_or_insert(caps);
                        }
                        shared.failure.record(index, error);
                        break;
                    }
                }
            }
            let Some(current) = live.as_mut() else { break };
            let task = &shared.plan.variants[index];
            let t0 = Instant::now();
            let result = current.session.scan(task.text);
            shared
                .scan_nanos
                .fetch_add(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
            match result {
                Err(error) => {
                    shared.failure.record(index, error);
                    if let Some(dead) = live.take() {
                        shared.control.unregister(dead.id);
                    }
                    break;
                }
                Ok(output) => match reference {
                    Some(first) => {
                        let agreed = first[index]
                            .as_ref()
                            .is_some_and(|r| same_observation(r, &output));
                        if !agreed {
                            lock(&sink.disagreed).push(index);
                        }
                        sink.completed.fetch_add(1, Ordering::Relaxed);
                    }
                    None => {
                        let verified = verify_if_available(current.session.as_ref(), task, &output);
                        match verified {
                            Ok(verification) => {
                                lock(&sink.observed).push(ObservedInput {
                                    index,
                                    input_digest: output.input_digest.clone(),
                                    sanitized_output_digest: output.sanitized_output_digest.clone(),
                                    findings: output.findings.clone(),
                                    verification,
                                });
                                sink.completed.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(error) => {
                                shared.failure.record(index, error);
                                if let Some(dead) = live.take() {
                                    dead.handle.trigger(AbortReason::Cancelled);
                                    shared.control.unregister(dead.id);
                                }
                                break;
                            }
                        }
                    }
                },
            }
        }
    }
    if let Some(mut done) = live {
        let stats = done.session.finish();
        shared
            .peak_rss
            .fetch_max(stats.peak_rss_bytes, Ordering::Relaxed);
        shared.control.unregister(done.id);
        // Observations of a session whose pinned files changed are not trusted.
        if let Some(error) = stats.pin_check {
            shared.failure.record(0, error);
        }
    }
}

fn verify_if_available(
    session: &dyn ScanSession,
    task: &VariantTask<'_>,
    output: &ScanOutput,
) -> Result<Option<Vec<OutputVerification>>, AdapterError> {
    if session.capabilities().action != ActionCapability::SanitizedOutput {
        return Ok(None);
    }
    let Some(sanitized) = output.sanitized_output.as_ref() else {
        return Ok(None);
    };
    match verify_output(task.text, sanitized.as_str(), &task.ranges) {
        Ok(assessment) => Ok(Some(assessment.occurrences)),
        Err(OutputError::OutputTooLarge) => Err(AdapterError::OutputLimit(LimitKind::Line)),
        Err(_) => Err(AdapterError::MalformedOutput(MalformedKind::Output)),
    }
}

/// One pass over every input. Returns what was collected.
struct RoundResult {
    observed: Vec<ObservedInput>,
    disagreed: Vec<usize>,
    completed: usize,
}

fn run_round(shared: &Shared<'_>, reference: Option<&[Option<ObservedInput>]>) -> RoundResult {
    let n = shared.plan.variants.len();
    let batch = shared.plan.limits.batch_variants as usize;
    let pending = shared.plan.limits.pending_tasks as usize;
    let (tx, rx) = sync_channel::<Batch>(pending);
    let rx = Mutex::new(rx);
    let sink = RoundSink {
        observed: Mutex::new(Vec::new()),
        disagreed: Mutex::new(Vec::new()),
        completed: AtomicUsize::new(0),
    };
    thread::scope(|scope| {
        for _ in 0..shared.eff.per_scanner_parallelism {
            scope.spawn(|| worker(shared, &rx, &sink, reference));
        }
        let mut start = 0;
        while start < n {
            let end = (start + batch).min(n);
            if shared.control.reason().is_some() || start > shared.failure.min() {
                break;
            }
            // Blocks when `pending_tasks` batches are queued: the bound.
            if tx.send(Batch { start, end }).is_err() {
                break;
            }
            start = end;
        }
        drop(tx);
    });
    RoundResult {
        observed: sink.observed.into_inner().unwrap_or_default(),
        disagreed: sink.disagreed.into_inner().unwrap_or_default(),
        completed: sink.completed.load(Ordering::Relaxed),
    }
}

fn run_scanner(
    shared_in: &ExecShared<'_>,
    scanner_index: usize,
    cancel: &CancelToken,
) -> ScannerRun {
    let plan = shared_in.plan;
    let scanner = &plan.scanners[scanner_index];
    let n = plan.variants.len();
    let started_at = SystemTime::now();
    let t_start = Instant::now();
    let timeout = Duration::from_millis(plan.limits.scanner_timeout_ms);
    let control = Arc::new(ScannerControl::new(t_start + timeout));
    shared_in.watchdog.register(&control);
    let shared = Shared {
        plan,
        scanner,
        eff: shared_in.eff,
        supervisor: shared_in.supervisor.as_ref(),
        scratch_root: shared_in.scratch_root.path(),
        control: Arc::clone(&control),
        failure: FailureSlot::new(),
        started_session: Mutex::new(None),
        startup_nanos: AtomicU64::new(0),
        scan_nanos: AtomicU64::new(0),
        peak_rss: AtomicU64::new(0),
    };

    let mut first_pass: Vec<Option<ObservedInput>> = Vec::new();
    let mut disagree = vec![false; n];
    let mut passes_done = 0u32;
    if cancel.is_cancelled() {
        control.abort(AbortReason::Cancelled);
    }
    for pass in 0..plan.replays {
        if control.reason().is_some() {
            break;
        }
        let reference = if pass == 0 {
            None
        } else {
            Some(first_pass.as_slice())
        };
        let round = run_round(&shared, reference);
        if shared.failure.min() != usize::MAX || round.completed != n {
            break;
        }
        if pass == 0 {
            first_pass = (0..n).map(|_| None).collect();
            for observed in round.observed {
                let i = observed.index;
                first_pass[i] = Some(observed);
            }
        }
        for i in round.disagreed {
            disagree[i] = true;
        }
        passes_done += 1;
    }
    control.finished.store(true, Ordering::SeqCst);

    // Decide the outcome.
    let started = lock(&shared.started_session).clone();
    let known_caps = lock(&shared.failure.capabilities).clone();
    let capabilities = started
        .as_ref()
        .map(|(c, _)| c.clone())
        .or(known_caps)
        .unwrap_or_else(unknown_capabilities);
    let runtime = started.as_ref().and_then(|(_, r)| provenance(r));
    let failure_error = lock(&shared.failure.error).take();
    let mut replays = ReplayRecord {
        count: plan.replays,
        agreed: true,
    };
    let all = n as u64;
    let (status, failure, inputs) = if let Some(error) = failure_error {
        let (status, code) = classify(error);
        (
            status,
            Some(ScannerFailure {
                code,
                affected_inputs: all,
            }),
            Vec::new(),
        )
    } else if passes_done < plan.replays {
        // Stopped by the deadline or a cancel before every pass finished.
        let code = match control.reason() {
            Some(AbortReason::Cancelled) => FailureCode::Cancelled,
            _ => FailureCode::Timeout,
        };
        (
            ScannerStatus::Error,
            Some(ScannerFailure {
                code,
                affected_inputs: all,
            }),
            Vec::new(),
        )
    } else if capabilities.ranges == CapabilityState::Unsupported {
        (
            ScannerStatus::Unsupported,
            Some(ScannerFailure {
                code: FailureCode::Unsupported,
                affected_inputs: all,
            }),
            Vec::new(),
        )
    } else if disagree.iter().any(|d| *d) {
        replays.agreed = false;
        let marked = disagree.iter().filter(|d| **d).count() as u64;
        (
            ScannerStatus::Unstable,
            Some(ScannerFailure {
                code: FailureCode::ReplayDisagreement,
                affected_inputs: marked,
            }),
            Vec::new(),
        )
    } else {
        let inputs: Vec<ObservedInput> = first_pass.into_iter().flatten().collect();
        (ScannerStatus::Complete, None, inputs)
    };
    ScannerRun {
        plan: scanner.plan.clone(),
        status,
        capabilities,
        replays,
        inputs,
        failure,
        runtime,
        timing: ScannerTiming {
            startup: Duration::from_nanos(shared.startup_nanos.load(Ordering::Relaxed)),
            scan: Duration::from_nanos(shared.scan_nanos.load(Ordering::Relaxed)),
            wall: t_start.elapsed(),
            started_at,
            finished_at: SystemTime::now(),
            peak_rss_bytes: shared.peak_rss.load(Ordering::Relaxed),
        },
    }
}

/// What is known about a scanner that never started: nothing is claimed.
fn unknown_capabilities() -> ScannerCapabilities {
    ScannerCapabilities {
        ranges: CapabilityState::Undeclared,
        family_classification: CapabilityState::Undeclared,
        sensitivity_classification: CapabilityState::Undeclared,
        jurisdiction_reporting: CapabilityState::Undeclared,
        action: ActionCapability::Unavailable,
        families: Vec::new(),
        jurisdictions: Vec::new(),
    }
}

struct ExecShared<'a> {
    plan: &'a ExecutionPlan<'a>,
    eff: EffectiveLimits,
    supervisor: Option<Arc<Supervisor>>,
    scratch_root: ScratchDir,
    watchdog: Watchdog,
}

/// Run every scanner over every variant. Results are in plan order.
///
/// Scanner failures are recorded in the returned runs; an `Err` means the run
/// could not start (bad limits, no resource monitor, no scratch space).
pub fn execute(
    plan: &ExecutionPlan<'_>,
    config: &ExecutorConfig,
    cancel: &CancelToken,
) -> Result<Vec<ScannerRun>, ExecError> {
    if config.require_tree_cleanup && !TREE_CLEANUP_SUPPORTED {
        return Err(ExecError::TreeCleanupUnsupported);
    }
    if plan.replays == 0 || plan.replays > 1024 {
        return Err(ExecError::InvalidLimits);
    }
    let eff = effective_limits(&plan.limits, config)?;
    for (i, scanner) in plan.scanners.iter().enumerate() {
        if let Some(adapter) = scanner.adapter.limits() {
            if adapter.max_line_bytes as u64 > plan.limits.max_stdout_bytes
                || adapter.max_stderr_bytes as u64 > plan.limits.max_stderr_bytes
            {
                return Err(ExecError::AdapterExceedsManifestBounds { scanner: i });
            }
        }
    }
    let supervisor = if config.resources == ResourcePolicy::Enforce {
        Some(Arc::new(
            Supervisor::start(config.sample_interval).map_err(ExecError::ResourceMonitor)?,
        ))
    } else {
        None
    };
    let parent = config
        .scratch_root
        .clone()
        .unwrap_or_else(std::env::temp_dir);
    let scratch_root = ScratchDir::create(&parent, &format!("pii-eval-run-{}", std::process::id()))
        .map_err(|_| ExecError::Scratch)?;
    let shared = ExecShared {
        plan,
        eff,
        supervisor,
        scratch_root,
        watchdog: Watchdog::start(cancel.clone()),
    };
    let slots: Vec<Mutex<Option<ScannerRun>>> =
        plan.scanners.iter().map(|_| Mutex::new(None)).collect();
    let next = AtomicUsize::new(0);
    thread::scope(|scope| {
        for _ in 0..eff.scanner_concurrency.min(plan.scanners.len().max(1)) {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::SeqCst);
                    if i >= plan.scanners.len() {
                        break;
                    }
                    let run = run_scanner(&shared, i, cancel);
                    *lock(&slots[i]) = Some(run);
                }
            });
        }
    });
    let mut shared = shared;
    shared.watchdog.stop();
    if let Some(supervisor) = &shared.supervisor {
        supervisor.stop();
    }
    Ok(slots
        .into_iter()
        .filter_map(|slot| slot.into_inner().unwrap_or_else(PoisonError::into_inner))
        .collect())
}
