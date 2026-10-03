//! [`ExternalProcessRunner`]: runs a job as a **separate process** started from
//! a configured worker command, and projects its single stdout line.
//!
//! What this crate guarantees about the worker it starts:
//!
//! - a fixed absolute program path and structured arguments (no shell);
//! - a **cleared environment** plus only the variables named in the profile
//!   (names that look like credentials are refused); the App's environment, the
//!   webhook secret, the private key and tokens are never passed, and the job
//!   specification holds none;
//! - stdin and stderr are `/dev/null`, stdout is a pipe read up to a fixed bound
//!   (more is `summary-rejected`); the Rust standard library opens every
//!   descriptor close-on-exec, so descriptors this crate opened (the webhook
//!   secret file among them) are not inherited. Descriptors opened by *other*
//!   code in the host process without close-on-exec cannot be closed from safe
//!   Rust here: the host binary must not create any;
//! - a private working directory per job (`0700`), the verified run
//!   configuration staged inside it (`0600`), removed afterwards;
//! - its own process group, a wall-clock limit and cancellation: on timeout,
//!   cancel or exit the whole group is sent `SIGKILL`.
//!
//! What it does **not** do, and the deployment must: run the command as a
//! different operating-system user, in a container, or under a sandbox, so that
//! the worker cannot read the App's secret files or memory. This crate cannot
//! change user, enter a namespace or drop capabilities. The command may be the
//! `pii-eval` binary itself (same user: process hygiene only) or a wrapper that
//! does that separation; a wrapper must stay in the process group it was
//! started in (or accept that the cleanup cannot reach it), must make `{config}`
//! and `{out}` accessible to the worker, and must pass through exactly one stdout
//! line, the CLI summary.

use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::checks::{MAX_RUNNER_LINE_BYTES, RunnerOutcome};
use crate::ports::{CancelFlag, JobRunner, JobSpec, RunnerError};
use crate::request::ProfileClass;
use crate::staging::stage_config;

/// How to start the worker for one profile.
#[derive(Clone, Debug)]
pub struct ExternalProfile {
    /// Absolute path of the worker program.
    pub program: PathBuf,
    /// Arguments. `{config}`, `{out}`, `{job_id}` and `{attempt}` are replaced.
    /// For the CLI binary: `run --config {config} --out {out} ...`.
    pub args: Vec<String>,
    /// Absolute path of the run configuration whose SHA-256 is the profile's
    /// pinned digest (all of its `path` and `dir` values must be absolute).
    pub config_path: PathBuf,
    /// The only environment variables the worker receives.
    pub env: Vec<(String, String)>,
}

/// Runs jobs as separate processes.
#[derive(Clone, Debug)]
pub struct ExternalProcessRunner {
    work_root: PathBuf,
    profiles: BTreeMap<String, ExternalProfile>,
    timeout: Duration,
}

const REFUSED_NAME_FRAGMENTS: &[&str] = &[
    "SECRET",
    "TOKEN",
    "KEY",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "PRIVATE",
    "WEBHOOK",
    "GITHUB",
    "APP_ID",
];

fn env_ok(name: &str, value: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_uppercase() || b[0] == b'_')
        && b.iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
        && !REFUSED_NAME_FRAGMENTS.iter().any(|f| name.contains(f))
        && value.len() <= 4096
        && !value.contains('\0')
}

impl ExternalProcessRunner {
    /// `work_root` holds the per-job private directories; `timeout` bounds one
    /// job.
    pub fn new(
        work_root: PathBuf,
        profiles: BTreeMap<String, ExternalProfile>,
        timeout: Duration,
    ) -> Self {
        Self {
            work_root,
            profiles,
            timeout,
        }
    }
}

fn kill_group(pid: u32) {
    use rustix::process::{Pid, Signal, kill_process_group};
    if let Some(pid) = i32::try_from(pid)
        .ok()
        .filter(|p| *p > 1)
        .and_then(Pid::from_raw)
    {
        let _ = kill_process_group(pid, Signal::KILL);
    }
}

fn read_bounded(mut stdout: impl Read) -> (Vec<u8>, bool) {
    let mut buf = Vec::new();
    let _ = (&mut stdout)
        .take(MAX_RUNNER_LINE_BYTES as u64 + 1)
        .read_to_end(&mut buf);
    let overflow = buf.len() > MAX_RUNNER_LINE_BYTES;
    // Keep draining so a chatty worker never blocks on a full pipe.
    let _ = std::io::copy(&mut stdout, &mut std::io::sink());
    (buf, overflow)
}

impl JobRunner for ExternalProcessRunner {
    fn run(&self, spec: &JobSpec, cancel: &CancelFlag) -> Result<RunnerOutcome, RunnerError> {
        if spec.identity.class != ProfileClass::PublicSynthetic {
            return Err(RunnerError::Refused);
        }
        let profile = self
            .profiles
            .get(&spec.identity.profile_id)
            .ok_or(RunnerError::Refused)?;
        if !profile.program.is_absolute()
            || !profile.program.is_file()
            || !profile.env.iter().all(|(k, v)| env_ok(k, v))
        {
            return Err(RunnerError::Refused);
        }
        if cancel.is_cancelled() {
            return Err(RunnerError::Cancelled);
        }
        let staged = stage_config(
            &self.work_root,
            &format!("{}-a{}", spec.job_id, spec.attempt),
            &profile.config_path,
            &spec.identity.config_digest,
        )?;
        let result = self.spawn_and_wait(spec, profile, &staged, cancel);
        let _ = std::fs::remove_dir_all(&staged.dir);
        result
    }
}

impl ExternalProcessRunner {
    fn spawn_and_wait(
        &self,
        spec: &JobSpec,
        profile: &ExternalProfile,
        staged: &crate::staging::Staged,
        cancel: &CancelFlag,
    ) -> Result<RunnerOutcome, RunnerError> {
        let out = staged.dir.join("out");
        let (config, out_text) = (
            staged.config.to_str().ok_or(RunnerError::Refused)?,
            out.to_str().ok_or(RunnerError::Refused)?,
        );
        let args: Vec<String> = profile
            .args
            .iter()
            .map(|a| {
                a.replace("{config}", config)
                    .replace("{out}", out_text)
                    .replace("{job_id}", spec.job_id.as_str())
                    .replace("{attempt}", &spec.attempt.to_string())
            })
            .collect();
        let mut child: Child = Command::new(&profile.program)
            .args(&args)
            .env_clear()
            .envs(profile.env.iter().map(|(k, v)| (k, v)))
            .current_dir(&staged.dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .map_err(|_| RunnerError::Refused)?;
        let pid = child.id();
        let Some(stdout) = child.stdout.take() else {
            kill_group(pid);
            let _ = child.wait();
            return Err(RunnerError::Internal);
        };
        let reader = thread::Builder::new()
            .name("pii-eval-app-worker-stdout".to_owned())
            .spawn(move || read_bounded(stdout))
            .map_err(|_| {
                kill_group(pid);
                let _ = child.wait();
                RunnerError::Internal
            })?;
        let deadline = Instant::now() + self.timeout;
        let mut failure = None;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => {}
                Err(_) => {
                    failure = Some(RunnerError::Internal);
                    break;
                }
            }
            if cancel.is_cancelled() {
                failure = Some(RunnerError::Cancelled);
                break;
            }
            if Instant::now() >= deadline {
                failure = Some(RunnerError::Timeout);
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        // Whatever happened, nothing the worker started may outlive the job.
        kill_group(pid);
        let _ = child.wait();
        let (bytes, overflow) = reader.join().unwrap_or_default();
        if let Some(f) = failure {
            return Err(f);
        }
        if overflow {
            return Err(RunnerError::SummaryRejected);
        }
        let text = String::from_utf8(bytes).map_err(|_| RunnerError::SummaryRejected)?;
        RunnerOutcome::from_summary_line(&text).map_err(|_| RunnerError::SummaryRejected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_like_environment_names_are_refused() {
        assert!(env_ok("PATH", "/usr/bin"));
        assert!(env_ok("LANG", "C"));
        for bad in [
            "WEBHOOK_SECRET",
            "GITHUB_TOKEN",
            "APP_PRIVATE_KEY",
            "DB_PASSWORD",
            "lower",
            "",
        ] {
            assert!(!env_ok(bad, "x"), "{bad}");
        }
        assert!(!env_ok("PATH", "a\0b"));
    }
}
