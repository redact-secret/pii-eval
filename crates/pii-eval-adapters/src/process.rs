//! The minimal bounded process interface.
//!
//! One child process, three pipes, three helper threads:
//!
//! - a writer thread owns stdin, so a shim that never reads cannot block the
//!   caller (the caller waits on stdout with a deadline instead);
//! - a reader thread splits stdout into lines and refuses any line longer than
//!   the limit, so output memory is bounded by one line;
//! - a stderr thread drains and counts stderr up to a cap and stores nothing,
//!   so a chatty child cannot block on a full pipe and stderr text can never
//!   be surfaced.
//!
//! The process is spawned from a fixed absolute executable with structured
//! arguments (never through a shell) and a cleared environment plus an explicit
//! list, as the leader of a new process group (P7, [`crate::control`]). On
//! timeout, limit violation, crash, drop and normal end the whole group is
//! killed (descendants included) and the leader reaped; the group is signalled
//! before the reap on every failure path.
//!
//! Not provided, even here: a security sandbox. Network and filesystem
//! isolation belong to the custodian; a descendant that leaves the group
//! (`setsid`) escapes cleanup. See [`crate::control`] for the exact statement.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::thread;
use std::time::{Duration, Instant};

use crate::control::{AbortHandle, AbortReason, ProcessGroup};
use crate::error::{AdapterError, StartupStage};

/// Grace period for a clean exit after `shutdown` before the child is killed.
const EXIT_GRACE: Duration = Duration::from_secs(2);
/// How long an exit status is awaited after stdout ended.
const EXIT_PROBE: Duration = Duration::from_millis(500);

/// What to run. Every field is fixed by the adapter, never taken from a corpus,
/// a scanner response or a plan field.
#[derive(Debug, Clone)]
pub(crate) struct SpawnSpec {
    pub executable: PathBuf,
    pub args: Vec<OsString>,
    pub working_dir: PathBuf,
    pub env: Vec<(String, String)>,
}

enum LineEvent {
    Line(Vec<u8>),
    TooLong,
    Truncated,
    Eof,
}

/// Result of queueing a line.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Sent {
    Queued,
    /// The writer ended (the shim closed stdin or died); `receive` tells which.
    WriterGone,
    /// No room before the deadline.
    Timeout,
}

/// One received event.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Received {
    Line(Vec<u8>),
    Timeout,
    TooLong,
    Truncated,
    Eof,
}

pub(crate) struct ShimProcess {
    child: Option<Child>,
    to_shim: Option<SyncSender<Vec<u8>>>,
    from_shim: Receiver<LineEvent>,
    stderr_bytes: Arc<AtomicU64>,
    abort: AbortHandle,
}

fn read_lines(mut out: impl Read, max_line: usize, tx: SyncSender<LineEvent>) {
    let mut buf = [0u8; 16 * 1024];
    let mut current: Vec<u8> = Vec::new();
    loop {
        let n = match out.read(&mut buf) {
            Ok(0) | Err(_) => {
                let event = if current.is_empty() {
                    LineEvent::Eof
                } else {
                    LineEvent::Truncated
                };
                let _ = tx.send(event);
                return;
            }
            Ok(n) => n,
        };
        let mut chunk = &buf[..n];
        while let Some(pos) = chunk.iter().position(|&b| b == b'\n') {
            if current.len() + pos > max_line {
                let _ = tx.send(LineEvent::TooLong);
                return;
            }
            current.extend_from_slice(&chunk[..pos]);
            if tx
                .send(LineEvent::Line(std::mem::take(&mut current)))
                .is_err()
            {
                return;
            }
            chunk = &chunk[pos + 1..];
        }
        if current.len() + chunk.len() > max_line {
            let _ = tx.send(LineEvent::TooLong);
            return;
        }
        current.extend_from_slice(chunk);
    }
}

fn drain_stderr(mut err: impl Read, cap: u64, count: Arc<AtomicU64>) {
    let mut buf = [0u8; 8 * 1024];
    loop {
        match err.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                let seen = count.load(Ordering::Relaxed);
                count.store(seen.saturating_add(n as u64).min(cap), Ordering::Relaxed);
            }
        }
    }
}

fn write_lines(mut input: impl Write, rx: Receiver<Vec<u8>>) {
    while let Ok(bytes) = rx.recv() {
        if input
            .write_all(&bytes)
            .and_then(|()| input.flush())
            .is_err()
        {
            return;
        }
    }
}

fn wait_bounded(child: &mut Child, limit: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + limit;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            Ok(None) | Err(_) => return None,
        }
    }
}

impl ShimProcess {
    /// Spawn the child. A failure is a startup failure with no OS detail.
    pub(crate) fn spawn(
        spec: &SpawnSpec,
        max_line: usize,
        max_stderr: usize,
    ) -> Result<Self, AdapterError> {
        let startup = AdapterError::StartupFailure(StartupStage::Spawn);
        let mut command = Command::new(&spec.executable);
        command
            .args(&spec.args)
            .current_dir(&spec.working_dir)
            .env_clear()
            .envs(spec.env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // A new process group led by the child, so the whole tree can be signalled.
        #[cfg(unix)]
        std::os::unix::process::CommandExt::process_group(&mut command, 0);
        let mut child = command.spawn().map_err(|_| startup)?;
        let abort = AbortHandle::new(ProcessGroup::of_leader(child.id()));
        let (Some(stdin), Some(stdout), Some(stderr)) =
            (child.stdin.take(), child.stdout.take(), child.stderr.take())
        else {
            abort.kill_tree();
            let _ = child.kill();
            let _ = child.wait();
            return Err(startup);
        };

        let (to_shim, writer_rx) = sync_channel::<Vec<u8>>(2);
        let (line_tx, from_shim) = sync_channel::<LineEvent>(4);
        let stderr_bytes = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&stderr_bytes);

        // Helper threads end when their pipe closes; they are detached on purpose.
        thread::spawn(move || write_lines(stdin, writer_rx));
        thread::spawn(move || read_lines(stdout, max_line, line_tx));
        let cap = max_stderr as u64;
        thread::spawn(move || drain_stderr(stderr, cap, counter));

        Ok(Self {
            child: Some(child),
            to_shim: Some(to_shim),
            from_shim,
            stderr_bytes,
            abort,
        })
    }

    /// The handle that aborts this process tree from another thread.
    pub(crate) fn abort_handle(&self) -> AbortHandle {
        self.abort.clone()
    }

    /// Why the session was aborted from outside, if it was. A failure observed
    /// after an outside abort is that abort, not a crash or a protocol error.
    pub(crate) fn abort_reason(&self) -> Option<AbortReason> {
        self.abort.reason()
    }

    /// Queue one line for the shim, waiting no later than `deadline` for room.
    /// The queue is full when the writer is stuck on a shim that does not read
    /// stdin, which must surface as a timeout, never as a blocked caller.
    pub(crate) fn send(&self, bytes: Vec<u8>, deadline: Instant) -> Sent {
        let Some(tx) = self.to_shim.as_ref() else {
            return Sent::WriterGone;
        };
        let mut item = bytes;
        loop {
            match tx.try_send(item) {
                Ok(()) => return Sent::Queued,
                Err(TrySendError::Disconnected(_)) => return Sent::WriterGone,
                Err(TrySendError::Full(back)) => {
                    if Instant::now() >= deadline {
                        return Sent::Timeout;
                    }
                    item = back;
                    thread::sleep(Duration::from_millis(1));
                }
            }
        }
    }

    /// Wait for one line until `deadline`.
    pub(crate) fn receive(&self, deadline: Instant) -> Received {
        let wait = deadline.saturating_duration_since(Instant::now());
        match self.from_shim.recv_timeout(wait) {
            Ok(LineEvent::Line(bytes)) => Received::Line(bytes),
            Ok(LineEvent::TooLong) => Received::TooLong,
            Ok(LineEvent::Truncated) => Received::Truncated,
            Ok(LineEvent::Eof) | Err(RecvTimeoutError::Disconnected) => Received::Eof,
            Err(RecvTimeoutError::Timeout) => Received::Timeout,
        }
    }

    /// After stdout ended: did the process fail (`true`) or exit cleanly (`false`)?
    /// A process that is still alive after stdout closed is killed and counts as failed.
    pub(crate) fn ended_abnormally(&mut self) -> bool {
        let Some(child) = self.child.as_mut() else {
            return true;
        };
        match wait_bounded(child, EXIT_PROBE) {
            Some(status) => !status.success(),
            None => {
                self.kill();
                true
            }
        }
    }

    /// Kill the whole process tree and reap the child. Idempotent. The group is
    /// signalled while the leader is still unreaped, so its id cannot have been
    /// recycled; the leader is signalled directly as well, for platforms
    /// without process groups.
    pub(crate) fn kill(&mut self) {
        self.to_shim = None;
        self.abort.kill_tree();
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// Ask the shim to stop, then kill it if it does not exit within the grace
    /// period. Whatever the shim left behind in its group is killed either way.
    pub(crate) fn close(&mut self, shutdown_line: Vec<u8>) {
        if let Some(tx) = self.to_shim.take() {
            match tx.try_send(shutdown_line) {
                Ok(()) | Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {}
            }
            // Dropping the sender ends the writer thread and closes stdin.
        }
        if let Some(mut child) = self.child.take() {
            if wait_bounded(&mut child, EXIT_GRACE).is_none() {
                self.abort.kill_tree();
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        // The leader is gone (reaped or killed): remove any descendants it left.
        self.abort.kill_leftovers();
    }

    /// Stderr bytes counted so far, saturating at the configured cap.
    pub(crate) fn stderr_bytes(&self) -> u64 {
        self.stderr_bytes.load(Ordering::Relaxed)
    }
}

impl Drop for ShimProcess {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Resolve the executable to a canonical absolute path and require a regular file.
pub(crate) fn resolve_executable(path: &Path) -> Result<PathBuf, AdapterError> {
    use crate::error::SpecProblem;
    let bad = AdapterError::InvalidSpec(SpecProblem::Executable);
    if !path.is_absolute() {
        return Err(bad);
    }
    let canonical = std::fs::canonicalize(path).map_err(|_| bad)?;
    let meta = std::fs::metadata(&canonical).map_err(|_| bad)?;
    if meta.is_file() {
        Ok(canonical)
    } else {
        Err(bad)
    }
}
