//! A [`JobRunner`] that executes a public/synthetic profile through the CLI
//! library (`pii_eval_cli::execute` with the `run` command).
//!
//! What it runs is fixed by the deployment, not by the request: a profile id
//! maps to a run-configuration file on disk, whose SHA-256 must equal the
//! profile's pinned `config_digest`. The configuration pins the snapshot,
//! manifest and scanner package digests (the CLI verifies them before it
//! launches anything), so a request can select among allowlisted synthetic
//! populations and pinned scanner builds and nothing else. No repository
//! content, comment text or credential reaches this code: [`JobSpec`] holds
//! identities only.
//!
//! The scanner is a child process of this process and runs as the same
//! operating-system user. That is process hygiene, not isolation (ADR 0009):
//! deploy the worker so that user holds none of the App's credentials, and keep
//! the configuration directory read-only for it (the digest is checked before
//! the run, and a writable directory could be swapped in between).

use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use pii_eval_cli::exec::CancelToken;
use pii_eval_contracts::Sha256Digest;

use crate::checks::RunnerOutcome;
use crate::ports::{CancelFlag, JobRunner, JobSpec, RunnerError};
use crate::request::ProfileClass;

/// Largest run configuration read.
pub const MAX_CONFIG_BYTES: u64 = 256 * 1024;

/// Where a profile's run configuration lives.
#[derive(Clone, Debug)]
pub struct CliProfile {
    /// Absolute path of the `pii-eval-run-config/1` document.
    pub config_path: PathBuf,
    /// Absolute path of Node, when the configuration's scanner needs it.
    pub node: Option<PathBuf>,
}

/// Runs jobs through `pii_eval_cli::execute`.
#[derive(Clone, Debug)]
pub struct CliLibraryRunner {
    work_root: PathBuf,
    profiles: BTreeMap<String, CliProfile>,
    timeout: Duration,
}

impl CliLibraryRunner {
    /// `work_root` is a directory owned by the worker where per-job output
    /// directories are created and removed again; `timeout` bounds one job.
    pub fn new(
        work_root: PathBuf,
        profiles: BTreeMap<String, CliProfile>,
        timeout: Duration,
    ) -> Self {
        Self {
            work_root,
            profiles,
            timeout,
        }
    }
}

fn read_config(path: &std::path::Path) -> Result<Vec<u8>, RunnerError> {
    let file = std::fs::File::open(path).map_err(|_| RunnerError::Refused)?;
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RunnerError::Refused)?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(RunnerError::Refused);
    }
    Ok(bytes)
}

impl JobRunner for CliLibraryRunner {
    fn run(&self, spec: &JobSpec, cancel: &CancelFlag) -> Result<RunnerOutcome, RunnerError> {
        if spec.identity.class != ProfileClass::PublicSynthetic {
            return Err(RunnerError::Refused);
        }
        let profile = self
            .profiles
            .get(&spec.identity.profile_id)
            .ok_or(RunnerError::Refused)?;
        let config_digest = Sha256Digest::of_bytes(&read_config(&profile.config_path)?);
        if config_digest.as_str() != spec.identity.config_digest {
            return Err(RunnerError::ProfileChanged);
        }
        if cancel.is_cancelled() {
            return Err(RunnerError::Cancelled);
        }

        // The CLI creates the output directory itself and refuses an existing
        // one; clear a leftover of a crashed attempt (a real directory only).
        let out = self
            .work_root
            .join(format!("{}-a{}", spec.job_id, spec.attempt));
        match std::fs::symlink_metadata(&out) {
            Ok(m) if m.is_dir() => {
                std::fs::remove_dir_all(&out).map_err(|_| RunnerError::Refused)?;
            }
            Ok(_) => return Err(RunnerError::Refused),
            Err(_) => {}
        }
        let mut args: Vec<String> = vec!["run".into(), "--config".into()];
        let as_text =
            |p: &std::path::Path| p.to_str().map(str::to_owned).ok_or(RunnerError::Refused);
        args.push(as_text(&profile.config_path)?);
        args.push("--out".into());
        args.push(as_text(&out)?);
        if let Some(node) = &profile.node {
            args.push("--node".into());
            args.push(as_text(node)?);
        }

        let token = CancelToken::new();
        let timed_out = Arc::new(AtomicBool::new(false));
        let (stop, stopped) = mpsc::channel::<()>();
        let watchdog = {
            let (token, timed_out, cancel) =
                (token.clone(), Arc::clone(&timed_out), cancel.clone());
            let deadline = Instant::now() + self.timeout;
            std::thread::Builder::new()
                .name("pii-eval-app-job-watchdog".to_owned())
                .spawn(move || {
                    // Wake every 50 ms until the job ends (a message or a closed
                    // channel), the flag is set or the deadline passes.
                    while let Err(RecvTimeoutError::Timeout) =
                        stopped.recv_timeout(Duration::from_millis(50))
                    {
                        if cancel.is_cancelled() {
                            token.cancel();
                            break;
                        }
                        if Instant::now() >= deadline {
                            timed_out.store(true, Ordering::SeqCst);
                            token.cancel();
                            break;
                        }
                    }
                })
                .map_err(|_| RunnerError::Internal)?
        };

        let rendered = {
            let t = token.clone();
            pii_eval_cli::execute(&args, move || Ok(t))
        };
        let _ = stop.send(());
        let _ = watchdog.join();
        // The artifacts are the CLI's output, not ours to keep: only the
        // sanitized projection leaves this function.
        let _ = std::fs::remove_dir_all(&out);

        if timed_out.load(Ordering::SeqCst) {
            return Err(RunnerError::Timeout);
        }
        if cancel.is_cancelled() {
            return Err(RunnerError::Cancelled);
        }
        RunnerOutcome::from_summary_line(&rendered.stdout).map_err(|_| RunnerError::SummaryRejected)
    }
}
