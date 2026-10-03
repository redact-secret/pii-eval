//! **Test and development runner only.** [`InProcessCliRunner`] executes a
//! public/synthetic profile through the CLI library (`pii_eval_cli::execute`)
//! inside the App's own process.
//!
//! A scanner launched this way is a child of the process that holds the webhook
//! secret (and, in a deployment, the App private key and installation tokens),
//! under the same operating-system user. Nothing in this crate separates them.
//! A production deployment must use [`crate::external_runner::ExternalProcessRunner`]
//! with a worker command that runs as another user or in a container (the
//! separation itself is the deployment's, see docs/github-app.md); this runner
//! exists so the core can be tested end to end without one.
//!
//! What it runs is fixed by the deployment, not by the request: a profile id
//! maps to a run-configuration file whose SHA-256 must equal the profile's
//! pinned `config_digest`. The verified bytes are staged into a private
//! per-job directory and that copy is what the CLI reads, so a later swap of
//! the original path changes nothing. The configuration pins the snapshot,
//! manifest and scanner package digests (the CLI verifies them before it
//! launches anything). [`JobSpec`] holds identities only.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use pii_eval_cli::exec::CancelToken;

use crate::checks::RunnerOutcome;
use crate::ports::{CancelFlag, JobRunner, JobSpec, RunnerError};
use crate::request::ProfileClass;
use crate::staging::stage_config;

pub use crate::staging::MAX_CONFIG_BYTES;

/// Where a profile's run configuration lives.
#[derive(Clone, Debug)]
pub struct CliProfile {
    /// Absolute path of the `pii-eval-run-config/1` document (all of its
    /// `path` and `dir` values must be absolute).
    pub config_path: PathBuf,
    /// Absolute path of Node, when the configuration's scanner needs it.
    pub node: Option<PathBuf>,
}

/// Runs jobs through `pii_eval_cli::execute` in this process. Test and
/// development only; see the module documentation.
#[derive(Clone, Debug)]
pub struct InProcessCliRunner {
    work_root: PathBuf,
    profiles: BTreeMap<String, CliProfile>,
    timeout: Duration,
}

impl InProcessCliRunner {
    /// `work_root` is a directory owned by the worker where per-job private
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

impl JobRunner for InProcessCliRunner {
    fn run(&self, spec: &JobSpec, cancel: &CancelFlag) -> Result<RunnerOutcome, RunnerError> {
        if spec.identity.class != ProfileClass::PublicSynthetic {
            return Err(RunnerError::Refused);
        }
        let profile = self
            .profiles
            .get(&spec.identity.profile_id)
            .ok_or(RunnerError::Refused)?;
        if cancel.is_cancelled() {
            return Err(RunnerError::Cancelled);
        }
        let staged = stage_config(
            &self.work_root,
            &format!("{}-a{}", spec.job_id, spec.attempt),
            &profile.config_path,
            &spec.identity.config_digest,
        )?;
        let out = staged.dir.join("out");
        let result = (|| {
            let as_text =
                |p: &std::path::Path| p.to_str().map(str::to_owned).ok_or(RunnerError::Refused);
            let mut args: Vec<String> = vec!["run".into(), "--config".into()];
            args.push(as_text(&staged.config)?);
            args.push("--out".into());
            args.push(as_text(&out)?);
            if let Some(node) = &profile.node {
                args.push("--node".into());
                args.push(as_text(node)?);
            }
            self.execute(&args, cancel)
        })();
        // The artifacts are the CLI's output, not ours to keep: only the
        // sanitized projection leaves this function.
        let _ = std::fs::remove_dir_all(&staged.dir);
        result
    }
}

impl InProcessCliRunner {
    fn execute(&self, args: &[String], cancel: &CancelFlag) -> Result<RunnerOutcome, RunnerError> {
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
            pii_eval_cli::execute(args, move || Ok(t))
        };
        let _ = stop.send(());
        let _ = watchdog.join();
        if timed_out.load(Ordering::SeqCst) {
            return Err(RunnerError::Timeout);
        }
        if cancel.is_cancelled() {
            return Err(RunnerError::Cancelled);
        }
        RunnerOutcome::from_summary_line(&rendered.stdout).map_err(|_| RunnerError::SummaryRejected)
    }
}
