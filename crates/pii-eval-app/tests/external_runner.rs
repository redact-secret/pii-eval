//! The external-process runner: a separate process with a scrubbed environment,
//! no inherited secrets or descriptors, bounded output, a time limit and
//! process-group cleanup. Workers here are tiny `/bin/sh` scripts written by the
//! test; no scanner, no network. Unix only.
#![cfg(unix)]

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use pii_eval_app::checks::RunnerOutcome;
use pii_eval_app::external_runner::{ExternalProcessRunner, ExternalProfile};
use pii_eval_app::policy::Limits;
use pii_eval_app::ports::{CancelFlag, JobRunner, JobSpec, RunnerError};
use pii_eval_app::request::{JobId, JobIdentity, ProfileClass};
use pii_eval_app::secret::Secret;
use pii_eval_app::testing::*;
use pii_eval_contracts::Sha256Digest;

const SENTINEL: &str = "SENTINEL-webhook-secret-must-not-reach-the-worker-0123456789";

struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Self {
        let d = std::env::temp_dir().join(format!("pii-eval-app-ext-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Dir(d)
    }
    fn path(&self) -> &Path {
        &self.0
    }
    fn count(&self) -> usize {
        std::fs::read_dir(&self.0).map_or(0, Iterator::count)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const WORKER: &str = r#"#!/bin/sh
dump="$1"; summary="$2"; mode="$3"
env > "$dump/env.txt"
printf '%s\n' "$@" > "$dump/argv.txt"
ls /dev/fd > "$dump/fds.txt"
pwd > "$dump/cwd.txt"
case "$mode" in
  hang) sleep 300 & echo $! > "$dump/child.pid.tmp"; mv "$dump/child.pid.tmp" "$dump/child.pid"; wait ;;
  big) head -c 400000 /dev/zero | tr '\0' 'a'; echo ;;
  junk) echo 'not json' ;;
  *) cat "$summary" ;;
esac
"#;

struct World {
    work: Dir,
    dump: Dir,
    src: Dir,
    identity: JobIdentity,
    program: PathBuf,
    config: PathBuf,
}

fn world(tag: &str) -> World {
    let (work, dump, src) = (
        Dir::new(&format!("{tag}-work")),
        Dir::new(&format!("{tag}-dump")),
        Dir::new(&format!("{tag}-src")),
    );
    let program = src.path().join("worker.sh");
    std::fs::write(&program, WORKER).unwrap();
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
    let config = src.path().join("config.json");
    let bytes = br#"{"schema":"pii-eval-run-config/1"}"#;
    std::fs::write(&config, bytes).unwrap();
    let identity = JobIdentity {
        repository_id: REPO,
        commit: sha('1'),
        profile_id: PUBLIC_PROFILE.to_owned(),
        engine_version: "0.0.0".to_owned(),
        protocol_revision: 2,
        config_digest: Sha256Digest::of_bytes(bytes).as_str().to_owned(),
        population_digest: "d".repeat(64),
        class: ProfileClass::PublicSynthetic,
    };
    std::fs::write(
        dump.path().join("summary.json"),
        summary_line_for(&identity, 0),
    )
    .unwrap();
    World {
        work,
        dump,
        src,
        identity,
        program,
        config,
    }
}

impl World {
    fn profile(&self, mode: &str) -> ExternalProfile {
        ExternalProfile {
            program: self.program.clone(),
            args: vec![
                self.dump.path().to_str().unwrap().to_owned(),
                self.dump
                    .path()
                    .join("summary.json")
                    .to_str()
                    .unwrap()
                    .to_owned(),
                mode.to_owned(),
                "{config}".into(),
                "{out}".into(),
                "{job_id}".into(),
                "{attempt}".into(),
            ],
            config_path: self.config.clone(),
            env: vec![
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("LANG".into(), "C".into()),
            ],
        }
    }

    fn runner(&self, profile: ExternalProfile, timeout: Duration) -> ExternalProcessRunner {
        ExternalProcessRunner::new(
            self.work.path().to_path_buf(),
            BTreeMap::from([(PUBLIC_PROFILE.to_owned(), profile)]),
            timeout,
        )
    }

    fn spec(&self) -> JobSpec {
        JobSpec {
            job_id: JobId::derive(&self.identity),
            identity: self.identity.clone(),
            attempt: 1,
        }
    }

    fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.dump.path().join(name)).unwrap()
    }
}

#[test]
fn the_worker_gets_a_scrubbed_environment_and_no_secret_or_descriptor() {
    let w = world("env");
    // The parent holds the webhook secret in memory and in an open file, and has
    // the usual inherited environment (PATH, HOME, CARGO_*, ...).
    let secret_file = w.src.path().join("webhook-secret");
    std::fs::write(&secret_file, SENTINEL).unwrap();
    std::fs::set_permissions(&secret_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let secret = Secret::from_file(&secret_file).unwrap();
    let _held_open = std::fs::File::open(&secret_file).unwrap();

    let r = w.runner(w.profile("ok"), Duration::from_secs(120));
    let outcome = r.run(&w.spec(), &CancelFlag::new()).unwrap();
    assert!(matches!(outcome, RunnerOutcome::Measured(_)));
    drop(secret);

    // Environment: only the allowlist (plus what `sh` itself adds).
    let env = w.read("env.txt");
    let keys: Vec<&str> = env.lines().filter_map(|l| l.split('=').next()).collect();
    for k in &keys {
        assert!(
            ["PATH", "LANG", "PWD", "SHLVL", "_", "OLDPWD"].contains(k),
            "unexpected variable {k}"
        );
    }
    assert!(keys.contains(&"PATH") && keys.contains(&"LANG"));
    assert!(!env.contains(SENTINEL));
    assert!(
        !env.contains("CARGO"),
        "the parent environment is not inherited"
    );
    // Arguments: structured, placeholders replaced, no secret.
    let argv = w.read("argv.txt");
    assert!(!argv.contains(SENTINEL) && !argv.contains("{config}") && !argv.contains("{out}"));
    assert!(argv.contains(&w.spec().job_id.to_string()));
    assert!(argv.lines().any(|l| l.ends_with("/config.json")));
    assert_eq!(argv.lines().last(), Some("1"), "{{attempt}}");
    // Descriptors: exactly what any plain child of this process gets (stdin,
    // stdout, stderr and what `ls` opens for /dev/fd; the platform decides how
    // many that is). The standard library opens every descriptor it creates
    // close-on-exec, so the held-open secret file is not among them.
    let baseline = Command::new("/bin/ls")
        .arg("/dev/fd")
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .unwrap();
    let base: std::collections::BTreeSet<u32> = String::from_utf8(baseline.stdout)
        .unwrap()
        .lines()
        .map(|l| l.trim().parse().unwrap())
        .collect();
    let seen: std::collections::BTreeSet<u32> = w
        .read("fds.txt")
        .lines()
        .map(|l| l.trim().parse().unwrap())
        .collect();
    assert_eq!(seen, base, "the worker inherited a descriptor");
    // A private working directory per job, removed afterwards.
    assert!(w.read("cwd.txt").trim().ends_with("-a1"));
    assert_eq!(w.work.count(), 0);
}

#[test]
fn credential_like_variables_and_unsafe_programs_are_refused_before_spawning() {
    let w = world("refuse");
    let mut p = w.profile("ok");
    p.env.push(("WEBHOOK_SECRET".into(), SENTINEL.into()));
    assert_eq!(
        w.runner(p, Duration::from_secs(60))
            .run(&w.spec(), &CancelFlag::new())
            .unwrap_err(),
        RunnerError::Refused
    );
    let mut p = w.profile("ok");
    p.program = PathBuf::from("worker.sh");
    assert_eq!(
        w.runner(p, Duration::from_secs(60))
            .run(&w.spec(), &CancelFlag::new())
            .unwrap_err(),
        RunnerError::Refused,
        "relative program"
    );
    let mut p = w.profile("ok");
    p.program = w.src.path().join("missing");
    assert_eq!(
        w.runner(p, Duration::from_secs(60))
            .run(&w.spec(), &CancelFlag::new())
            .unwrap_err(),
        RunnerError::Refused
    );
    let mut protected = w.spec();
    protected.identity.class = ProfileClass::Protected;
    assert_eq!(
        w.runner(w.profile("ok"), Duration::from_secs(60))
            .run(&protected, &CancelFlag::new())
            .unwrap_err(),
        RunnerError::Refused
    );
    // A changed configuration is refused before the worker starts.
    std::fs::write(&w.config, b"{}").unwrap();
    assert_eq!(
        w.runner(w.profile("ok"), Duration::from_secs(60))
            .run(&w.spec(), &CancelFlag::new())
            .unwrap_err(),
        RunnerError::ProfileChanged
    );
    assert!(
        !w.dump.path().join("env.txt").exists(),
        "nothing was started"
    );
    assert_eq!(w.work.count(), 0);
}

#[test]
fn output_is_bounded_and_garbage_is_rejected() {
    let w = world("output");
    for mode in ["big", "junk"] {
        let r = w.runner(w.profile(mode), Duration::from_secs(120));
        assert_eq!(
            r.run(&w.spec(), &CancelFlag::new()).unwrap_err(),
            RunnerError::SummaryRejected,
            "{mode}"
        );
    }
    assert_eq!(w.work.count(), 0);
}

fn alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn wait_pid(w: &World) -> u32 {
    let mut pid = None;
    wait_until("the worker started its child", || {
        pid = std::fs::read_to_string(w.dump.path().join("child.pid"))
            .ok()
            .and_then(|t| t.trim().parse::<u32>().ok());
        pid.is_some()
    });
    pid.unwrap()
}

#[test]
fn cancellation_kills_the_whole_process_group() {
    let w = world("cancel");
    let r = w.runner(w.profile("hang"), Duration::from_secs(600));
    let cancel = CancelFlag::new();
    let spec = w.spec();
    let (c2, spec2) = (cancel.clone(), spec);
    let handle = std::thread::spawn(move || r.run(&spec2, &c2));
    let grandchild = wait_pid(&w);
    assert!(alive(grandchild));
    cancel.cancel();
    assert_eq!(handle.join().unwrap().unwrap_err(), RunnerError::Cancelled);
    wait_until("the grandchild is gone", || !alive(grandchild));
    assert_eq!(w.work.count(), 0);
}

#[test]
fn the_time_limit_stops_a_hanging_worker_and_its_children() {
    let w = world("timeout");
    // The limit is this runner's own; a slower machine only makes it fire later.
    let r = w.runner(w.profile("hang"), Duration::from_secs(2));
    assert_eq!(
        r.run(&w.spec(), &CancelFlag::new()).unwrap_err(),
        RunnerError::Timeout
    );
    if let Some(pid) = std::fs::read_to_string(w.dump.path().join("child.pid"))
        .ok()
        .and_then(|t| t.trim().parse::<u32>().ok())
    {
        wait_until("the grandchild is gone", || !alive(pid));
    }
    assert_eq!(w.work.count(), 0);
}

#[test]
fn the_runner_works_behind_the_service_on_a_worker_pool() {
    // The same runner drives the service end to end (identity pins checked).
    let w = world("service");
    let limits = Limits::default();
    let mut policy = test_policy(limits);
    policy.profiles[0].config_digest = w.identity.config_digest.clone();
    policy.profiles[0].population_digest = w.identity.population_digest.clone();
    let runner = w.runner(w.profile("ok"), Duration::from_secs(120));
    let heads = std::sync::Arc::new(FakeHeads::default());
    heads.set(
        REPO,
        pii_eval_app::request::Subject::PullRequest(PR),
        &sha('1'),
        REPO,
    );
    let checks = std::sync::Arc::new(FakeChecks::default());
    let services = pii_eval_app::Services {
        heads: heads.clone(),
        checks: checks.clone(),
        runner: std::sync::Arc::new(runner),
        custodian: std::sync::Arc::new(pii_eval_app::ports::NoCustodian),
        clock: std::sync::Arc::new(FakeClock::default()),
    };
    let app =
        pii_eval_app::App::new(policy, Secret::new(SECRET.to_vec()).unwrap(), services).unwrap();
    let body = comment_payload(INSTALLATION, REPO, REPO_NAME, ACTOR, PR, "/pii-eval run");
    let sig = sign(SECRET, &body);
    let d = app.handle_delivery(&pii_eval_app::webhook::RawDelivery {
        event: Some("issue_comment"),
        delivery_id: Some("ext-1"),
        signature: Some(&sig),
        body: &body,
    });
    let pii_eval_app::reason::Outcome::Accepted { job_id, .. } = d.outcome else {
        panic!("accepted: {d:?}")
    };
    // The worker script prints a summary for the pins aligned above.
    let pool = app.start_workers().unwrap();
    wait_until("terminal", || {
        app.job_state(&job_id)
            .is_some_and(pii_eval_app::jobs::JobState::is_terminal)
    });
    pool.shutdown();
    assert_eq!(
        app.job_state(&job_id),
        Some(pii_eval_app::jobs::JobState::Completed)
    );
    assert_eq!(
        checks.runs()[0].conclusion,
        Some(pii_eval_app::checks::Conclusion::Success)
    );
}
