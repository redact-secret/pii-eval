//! Process-tree control and resource supervision for scanner processes.
//!
//! This is process hygiene, **not a security sandbox** (SECURITY.md, ADR 0009).
//! It bounds what an honest or merely buggy scanner can leave behind or consume.
//! A hostile scanner can leave the process group (`setsid`, `setpgid`), read and
//! write anything the evaluator's user can, and use the network; keeping it from
//! doing so is the custodian's job (containers, cgroups, network namespaces).
//!
//! # What is provided (Unix)
//!
//! * Every scanner process is started as the leader of a **new process group**
//!   (`std::os::unix::process::CommandExt::process_group(0)`; no `unsafe`).
//! * [`AbortHandle`] signals `SIGKILL` to the whole group (`killpg`, through the
//!   `rustix` safe wrapper) on timeout, cancellation, resource-limit violation,
//!   crash, failed start, drop and normal end. While the leader is still alive
//!   the group is signalled **before** the leader is reaped, so its id cannot
//!   have been recycled. If the leader already exited by itself (it is reaped
//!   when observed), leftovers are killed only while the group still has members
//!   (a group id is not reused while a member exists), and the handle then
//!   **forgets the group**, so a recyclable id is never signalled again. The
//!   residual window (leader reaped, group emptied and its id recycled to a new
//!   group leader between the liveness test and the signal) needs a full pid
//!   wrap within microseconds and is accepted.
//! * A session can be aborted while it is still starting (pin hashing, spawn,
//!   the ready wait): the executor registers an [`AbortHandle::pending`] handle
//!   before the adapter starts and the adapter attaches the group at spawn.
//! * Because scanners lead their own process group, a terminal `Ctrl-C` does not
//!   reach them. A caller that wants interactive interruption (the P8 CLI) must
//!   install a signal handler that calls `CancelToken::cancel`.
//! * [`Supervisor`] samples, on one thread, the resident set size of every watched
//!   group (one `ps -A -o pgid=,rss=` per tick) and the size of each session's
//!   scratch directory, and aborts a session that exceeds its limit. Memory is
//!   *sampled*: a process can exceed its limit between two samples, so the limit
//!   is a bound on sustained use, not a hard cap, and the sampled peak is recorded.
//!
//! # Not provided
//!
//! * No cleanup if the evaluator itself is killed (`SIGKILL`, power loss): the
//!   scanner group keeps running until its stdin closes (a shim exits on EOF) or
//!   the operator removes it. Pair with a container or cgroup.
//! * A descendant that calls `setsid`/`setpgid` escapes the group.
//! * Windows: there is no job-object implementation. [`TREE_CLEANUP_SUPPORTED`]
//!   is `false`, [`AbortHandle`] kills only the direct child, and
//!   [`Supervisor::start`] fails, so an executor that requires tree cleanup or a
//!   memory limit refuses to start. This is untested and should be treated as
//!   unsupported.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicI32, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Whether descendants of a scanner process can be cleaned up on this platform.
pub const TREE_CLEANUP_SUPPORTED: bool = cfg!(unix);

/// Most bytes of `ps` output read per sample.
const MAX_PS_OUTPUT: u64 = 8 * 1024 * 1024;
/// Most directory entries visited when measuring a scratch directory; a larger
/// tree counts as over the limit (fail closed).
pub const MAX_SCRATCH_ENTRIES: usize = 100_000;
/// Shortest sampling interval accepted.
pub const MIN_SAMPLE_INTERVAL: Duration = Duration::from_millis(10);

/// Why a session was aborted from outside its own call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AbortReason {
    /// The executor's deadline for the scanner run passed.
    Timeout,
    /// The caller cancelled the run.
    Cancelled,
    /// The process tree's sampled resident set exceeded its limit.
    Memory,
    /// The session's scratch directory exceeded its limit.
    Temporary,
}

impl AbortReason {
    const fn code(self) -> u8 {
        match self {
            AbortReason::Timeout => 1,
            AbortReason::Cancelled => 2,
            AbortReason::Memory => 3,
            AbortReason::Temporary => 4,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(AbortReason::Timeout),
            2 => Some(AbortReason::Cancelled),
            3 => Some(AbortReason::Memory),
            4 => Some(AbortReason::Temporary),
            _ => None,
        }
    }
}

/// A process group id (the leader's pid), or nothing on platforms without
/// process groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProcessGroup(i32);

impl ProcessGroup {
    /// The group a child spawned with `process_group(0)` leads.
    pub(crate) fn of_leader(pid: u32) -> Option<Self> {
        if !TREE_CLEANUP_SUPPORTED {
            return None;
        }
        i32::try_from(pid).ok().filter(|p| *p > 1).map(ProcessGroup)
    }

    /// Send `SIGKILL` to every member. `true` when the signal was delivered.
    #[cfg(unix)]
    pub(crate) fn kill(self) -> bool {
        use rustix::process::{Pid, Signal, kill_process_group};
        Pid::from_raw(self.0).is_some_and(|pid| kill_process_group(pid, Signal::KILL).is_ok())
    }

    #[cfg(not(unix))]
    pub(crate) fn kill(self) -> bool {
        false
    }

    /// Whether the group still has a member (signal 0).
    #[cfg(unix)]
    pub(crate) fn exists(self) -> bool {
        use rustix::process::{Pid, test_kill_process_group};
        Pid::from_raw(self.0).is_some_and(|pid| test_kill_process_group(pid).is_ok())
    }

    #[cfg(not(unix))]
    pub(crate) fn exists(self) -> bool {
        false
    }
}

struct Abort {
    reason: AtomicU8,
    /// Process group id; 0 means none (not started yet, or detached after the
    /// leader was reaped).
    group: AtomicI32,
    peak_rss_kib: AtomicU64,
}

/// A cloneable, thread-safe handle that aborts one scanner session: it records
/// why, then kills the session's process tree. Idempotent: the first reason
/// wins, later calls only repeat the kill.
#[derive(Clone)]
pub struct AbortHandle(Arc<Abort>);

impl std::fmt::Debug for AbortHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AbortHandle")
            .field("reason", &self.reason())
            .finish()
    }
}

impl AbortHandle {
    pub(crate) fn new(group: Option<ProcessGroup>) -> Self {
        AbortHandle(Arc::new(Abort {
            reason: AtomicU8::new(0),
            group: AtomicI32::new(group.map_or(0, |g| g.0)),
            peak_rss_kib: AtomicU64::new(0),
        }))
    }

    /// A handle that controls nothing, for sessions that own no process (an
    /// in-process fake, or a session that already ended).
    pub fn inert() -> Self {
        AbortHandle::new(None)
    }

    /// Record `reason` (if none is recorded yet) and kill the process tree.
    /// Returns `true` when this call recorded the reason.
    pub fn trigger(&self, reason: AbortReason) -> bool {
        let first = self
            .0
            .reason
            .compare_exchange(0, reason.code(), Ordering::SeqCst, Ordering::SeqCst)
            .is_ok();
        self.kill_tree();
        first
    }

    /// The recorded reason, if the session was aborted from outside.
    pub fn reason(&self) -> Option<AbortReason> {
        AbortReason::from_code(self.0.reason.load(Ordering::SeqCst))
    }

    /// A handle for a session whose process does not exist yet. The executor
    /// registers it with its watchdog before the adapter starts, so a cancel or a
    /// deadline during pin hashing, spawn or the ready wait is not lost: the
    /// adapter attaches the process group at spawn and kills it at once if the
    /// handle was already triggered.
    pub fn pending() -> Self {
        AbortHandle::new(None)
    }

    /// Attach the process group once the process exists.
    pub(crate) fn attach(&self, group: Option<ProcessGroup>) {
        self.0
            .group
            .store(group.map_or(0, |g| g.0), Ordering::SeqCst);
        if self.reason().is_some() {
            self.kill_tree();
        }
    }

    /// Forget the group once its leader has been reaped (and any leftovers
    /// killed): the id may be recycled from then on, so it must never be
    /// signalled again.
    pub(crate) fn detach(&self) {
        self.0.group.store(0, Ordering::SeqCst);
    }

    fn group(&self) -> Option<ProcessGroup> {
        match self.0.group.load(Ordering::SeqCst) {
            0 => None,
            id => Some(ProcessGroup(id)),
        }
    }

    /// Kill every member of the process group, if there is one.
    pub(crate) fn kill_tree(&self) {
        if let Some(group) = self.group() {
            group.kill();
        }
    }

    /// Kill the group only while it still has members (after a graceful exit).
    pub(crate) fn kill_leftovers(&self) {
        if let Some(group) = self.group() {
            if group.exists() {
                group.kill();
            }
        }
    }

    /// Whether any member of the group is still alive. `false` without a group.
    pub fn tree_alive(&self) -> bool {
        self.group().is_some_and(ProcessGroup::exists)
    }

    /// The process group id, for diagnostics and tests. Never an input.
    pub fn group_id(&self) -> Option<i32> {
        self.group().map(|g| g.0)
    }

    /// Highest resident set size the supervisor sampled for this tree, in bytes
    /// (0 when it was not supervised or no sample was taken).
    pub fn sampled_peak_rss_bytes(&self) -> u64 {
        self.0
            .peak_rss_kib
            .load(Ordering::Relaxed)
            .saturating_mul(1024)
    }
}

/// Why a supervisor cannot be started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorError {
    /// This platform has no process-tree control.
    Unsupported,
    /// No `ps` executable was found at a fixed path.
    PsUnavailable,
    /// The sampling interval is below [`MIN_SAMPLE_INTERVAL`] or above one minute.
    Interval,
}

/// Limits for one watched session. `None` means "not watched for this".
#[derive(Debug, Clone, Default)]
pub struct WatchLimits {
    /// Sustained resident set size of the whole process tree, in bytes.
    pub max_rss_bytes: Option<u64>,
    /// A scratch directory and the most bytes it may hold.
    pub scratch: Option<(PathBuf, u64)>,
}

struct Watch {
    id: u64,
    abort: AbortHandle,
    limits: WatchLimits,
}

struct State {
    stop: bool,
    next_id: u64,
    watches: Vec<Watch>,
}

struct Shared {
    state: Mutex<State>,
    wake: Condvar,
    interval: Duration,
    ps: PathBuf,
}

/// One sampling thread for every watched session of an executor.
pub struct Supervisor {
    shared: Arc<Shared>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

/// Removes its session from the supervisor when dropped.
pub struct WatchGuard {
    shared: Arc<Shared>,
    id: u64,
}

/// `ps` at a fixed absolute path, never through `PATH`.
fn find_ps() -> Option<PathBuf> {
    ["/bin/ps", "/usr/bin/ps"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
}

impl Supervisor {
    /// Start the sampling thread. Fails closed on a platform or host that cannot
    /// sample (see [`SupervisorError`]); an executor with a memory limit must
    /// then refuse to run rather than run unwatched.
    pub fn start(interval: Duration) -> Result<Supervisor, SupervisorError> {
        if !TREE_CLEANUP_SUPPORTED {
            return Err(SupervisorError::Unsupported);
        }
        if !(MIN_SAMPLE_INTERVAL..=Duration::from_secs(60)).contains(&interval) {
            return Err(SupervisorError::Interval);
        }
        let ps = find_ps().ok_or(SupervisorError::PsUnavailable)?;
        // Probe once so a host where `ps` cannot sample is reported up front.
        if sample_rss(&ps).is_none() {
            return Err(SupervisorError::PsUnavailable);
        }
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                stop: false,
                next_id: 0,
                watches: Vec::new(),
            }),
            wake: Condvar::new(),
            interval,
            ps,
        });
        let worker = Arc::clone(&shared);
        let thread = thread::Builder::new()
            .name("pii-eval-supervisor".to_owned())
            .spawn(move || run(&worker))
            .map_err(|_| SupervisorError::Unsupported)?;
        Ok(Supervisor {
            shared,
            thread: Mutex::new(Some(thread)),
        })
    }

    /// Watch a session until the guard is dropped.
    pub fn watch(&self, abort: &AbortHandle, limits: WatchLimits) -> WatchGuard {
        let mut state = lock(&self.shared.state);
        let id = state.next_id;
        state.next_id += 1;
        state.watches.push(Watch {
            id,
            abort: abort.clone(),
            limits,
        });
        WatchGuard {
            shared: Arc::clone(&self.shared),
            id,
        }
    }

    /// Stop the sampling thread and wait for it. Idempotent; also done on drop.
    pub fn stop(&self) {
        lock(&self.shared.state).stop = true;
        self.shared.wake.notify_all();
        if let Some(handle) = lock(&self.thread).take() {
            let _ = handle.join();
        }
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        self.stop();
    }
}

impl Drop for WatchGuard {
    fn drop(&mut self) {
        lock(&self.shared.state)
            .watches
            .retain(|watch| watch.id != self.id);
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // A poisoned lock only means another thread panicked; the data is plain.
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Consecutive failed samples after which a memory-limited session is aborted:
/// a limit that can no longer be checked is treated as exceeded (fail closed).
const MAX_BLIND_SAMPLES: u32 = 3;
/// Longest a single `ps` run may take.
const PS_TIMEOUT: Duration = Duration::from_secs(5);

fn run(shared: &Shared) {
    let mut blind = 0u32;
    loop {
        let watches: Vec<(u64, AbortHandle, WatchLimits)> = {
            let guard = lock(&shared.state);
            let (guard, _) = shared
                .wake
                .wait_timeout_while(guard, shared.interval, |s| !s.stop)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if guard.stop {
                return;
            }
            guard
                .watches
                .iter()
                .map(|w| (w.id, w.abort.clone(), w.limits.clone()))
                .collect()
        };
        if watches.is_empty() {
            continue;
        }
        let rss = sample_rss(&shared.ps);
        blind = if rss.is_some() { 0 } else { blind + 1 };
        for (_, abort, limits) in &watches {
            if abort.reason().is_some() {
                continue;
            }
            if rss.is_none() && blind >= MAX_BLIND_SAMPLES && limits.max_rss_bytes.is_some() {
                abort.trigger(AbortReason::Memory);
                continue;
            }
            if let (Some(group), Some(by_group)) = (abort.group(), rss.as_ref()) {
                let kib = by_group.get(&group.0).copied().unwrap_or(0);
                abort.0.peak_rss_kib.fetch_max(kib, Ordering::Relaxed);
                if limits
                    .max_rss_bytes
                    .is_some_and(|max| kib.saturating_mul(1024) > max)
                {
                    abort.trigger(AbortReason::Memory);
                    continue;
                }
            }
            if let Some((dir, max)) = &limits.scratch {
                if directory_bytes(dir, MAX_SCRATCH_ENTRIES) > *max {
                    abort.trigger(AbortReason::Temporary);
                }
            }
        }
    }
}

/// Sum of the resident set sizes (KiB) per process group, from one `ps` run.
fn sample_rss(ps: &Path) -> Option<HashMap<i32, u64>> {
    let mut child = Command::new(ps)
        .args(["-A", "-o", "pgid=,rss="])
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    let (tx, rx) = std::sync::mpsc::channel();
    let reader = thread::Builder::new()
        .name("pii-eval-ps-reader".to_owned())
        .spawn(move || {
            let mut text = String::new();
            let read = (&mut stdout).take(MAX_PS_OUTPUT).read_to_string(&mut text);
            let _ = tx.send(read.ok().map(|_| text));
        });
    let text = match (reader, rx.recv_timeout(PS_TIMEOUT)) {
        (Ok(_), Ok(Some(text))) => text,
        _ => {
            // Hung, failed or unreadable: never wait for it.
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
    };
    let status = child.wait().ok()?;
    if !status.success() {
        return None;
    }
    let mut by_group: HashMap<i32, u64> = HashMap::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        if let (Some(pgid), Some(rss)) = (fields.next(), fields.next()) {
            if let (Ok(pgid), Ok(rss)) = (pgid.parse::<i32>(), rss.parse::<u64>()) {
                *by_group.entry(pgid).or_insert(0) += rss;
            }
        }
    }
    Some(by_group)
}

/// Total size of the regular files under `dir`, without following symlinks.
/// More than `max_entries` entries counts as `u64::MAX` (fail closed).
pub fn directory_bytes(dir: &Path, max_entries: usize) -> u64 {
    let mut total = 0u64;
    let mut seen = 0usize;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(path) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.flatten() {
            seen += 1;
            if seen > max_entries {
                return u64::MAX;
            }
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                stack.push(entry.path());
            } else {
                total = total.saturating_add(meta.len());
            }
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_abort_reason_wins_and_an_inert_handle_controls_nothing() {
        let handle = AbortHandle::inert();
        assert_eq!(handle.reason(), None);
        assert!(handle.trigger(AbortReason::Cancelled));
        assert!(!handle.trigger(AbortReason::Timeout));
        assert_eq!(handle.reason(), Some(AbortReason::Cancelled));
        assert!(!handle.tree_alive());
        assert_eq!(handle.group_id(), None);
    }

    #[test]
    fn reason_codes_round_trip() {
        for reason in [
            AbortReason::Timeout,
            AbortReason::Cancelled,
            AbortReason::Memory,
            AbortReason::Temporary,
        ] {
            assert_eq!(AbortReason::from_code(reason.code()), Some(reason));
        }
        assert_eq!(AbortReason::from_code(0), None);
        assert_eq!(AbortReason::from_code(9), None);
    }

    #[test]
    fn system_pids_are_never_treated_as_a_group_to_signal() {
        assert_eq!(ProcessGroup::of_leader(0), None);
        assert_eq!(ProcessGroup::of_leader(1), None);
        assert_eq!(ProcessGroup::of_leader(u32::MAX), None);
    }

    #[test]
    fn the_interval_is_bounded() {
        assert!(matches!(
            Supervisor::start(Duration::from_millis(1)),
            Err(SupervisorError::Interval) | Err(SupervisorError::Unsupported)
        ));
        assert!(matches!(
            Supervisor::start(Duration::from_secs(3600)),
            Err(SupervisorError::Interval) | Err(SupervisorError::Unsupported)
        ));
    }

    #[test]
    fn a_scratch_directory_is_measured_without_following_links() {
        let dir = std::env::temp_dir().join(format!("pii-eval-control-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("a"), vec![0u8; 100]).unwrap();
        std::fs::write(dir.join("sub").join("b"), vec![0u8; 28]).unwrap();
        assert_eq!(directory_bytes(&dir, 10), 128);
        // Too many entries: counted as over any limit.
        assert_eq!(directory_bytes(&dir, 1), u64::MAX);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
