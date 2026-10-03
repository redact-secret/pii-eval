//! The real runner: a public synthetic profile executed through the CLI library
//! against the committed quickstart example (inert fake scanner package, no
//! network). Needs Node and `ps` like the CLI's own end-to-end tests
//! (`PII_EVAL_REQUIRE_NODE=1` turns a missing Node into a failure).
#![cfg(unix)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use pii_eval_app::App;
use pii_eval_app::checks::{CheckStatus, Conclusion};
use pii_eval_app::cli_runner::{CliLibraryRunner, CliProfile};
use pii_eval_app::jobs::{FailReason, JobState};
use pii_eval_app::policy::{AppPolicy, InstallationPolicy, Limits, Profile, RepositoryPolicy};
use pii_eval_app::ports::{CancelFlag, JobRunner, JobSpec, NoCustodian, RunnerError};
use pii_eval_app::reason::Outcome;
use pii_eval_app::request::{JobId, JobIdentity, ProfileClass, Subject};
use pii_eval_app::secret::Secret;
use pii_eval_app::service::Services;
use pii_eval_app::testing::*;
use pii_eval_contracts::{ENGINE_VERSION, Sha256Digest};

/// Semantic digest of `examples/quickstart/snapshot.json` (also pinned by the
/// official quickstart configuration).
const QUICKSTART_POPULATION: &str =
    "c5249874335d21c02447bac23954d70e20748899f16a43efc56c5568a34a3bae";

fn root() -> PathBuf {
    std::fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .expect("repository root")
}

fn node() -> Option<PathBuf> {
    let found = std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|d| d.join("node"))
            .find(|p| p.is_file())
    });
    if found.is_none() {
        assert!(
            std::env::var("PII_EVAL_REQUIRE_NODE").as_deref() != Ok("1"),
            "node is required (PII_EVAL_REQUIRE_NODE=1) but was not found"
        );
        eprintln!("skipping: node not found");
    }
    found
}

struct Work(PathBuf);

impl Work {
    fn new(tag: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("pii-eval-app-e2e-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Work(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn entries(&self) -> usize {
        std::fs::read_dir(&self.0).map_or(0, Iterator::count)
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn config_path() -> PathBuf {
    root().join("examples/quickstart/run-config.json")
}

fn profile(config_digest: &str) -> Profile {
    Profile {
        id: PUBLIC_PROFILE.to_owned(),
        class: ProfileClass::PublicSynthetic,
        engine_version: ENGINE_VERSION.to_owned(),
        protocol_revision: 2,
        config_digest: config_digest.to_owned(),
        population_digest: QUICKSTART_POPULATION.to_owned(),
    }
}

fn identity(p: &Profile) -> JobIdentity {
    JobIdentity {
        repository_id: REPO,
        commit: sha('1'),
        profile_id: p.id.clone(),
        engine_version: p.engine_version.clone(),
        protocol_revision: p.protocol_revision,
        config_digest: p.config_digest.clone(),
        population_digest: p.population_digest.clone(),
        class: p.class,
    }
}

fn runner(work: &Work, node: PathBuf) -> CliLibraryRunner {
    CliLibraryRunner::new(
        work.path().to_path_buf(),
        BTreeMap::from([(
            PUBLIC_PROFILE.to_owned(),
            CliProfile {
                config_path: config_path(),
                node: Some(node),
            },
        )]),
        Duration::from_secs(600),
    )
}

fn good_digest() -> String {
    Sha256Digest::of_bytes(&std::fs::read(config_path()).unwrap())
        .as_str()
        .to_owned()
}

#[test]
fn the_quickstart_profile_runs_through_the_cli_library_and_publishes_a_check() {
    let Some(node) = node() else { return };
    let work = Work::new("ok");
    let p = profile(&good_digest());
    let policy = AppPolicy {
        installations: vec![InstallationPolicy {
            id: INSTALLATION,
            repositories: vec![RepositoryPolicy {
                id: REPO,
                full_name: REPO_NAME.to_owned(),
                actors: [ACTOR].into(),
                profiles: vec![PUBLIC_PROFILE.to_owned()],
                allow_fork_heads: false,
            }],
        }],
        profiles: vec![p],
        limits: Limits::default(),
        details_base_url: None,
    };
    let heads = Arc::new(FakeHeads::default());
    heads.set(REPO, Subject::PullRequest(PR), &sha('1'), REPO);
    let checks = Arc::new(FakeChecks::default());
    let services = Services {
        heads: heads.clone(),
        checks: checks.clone(),
        runner: Arc::new(runner(&work, node)),
        custodian: Arc::new(NoCustodian),
        clock: Arc::new(FakeClock::default()),
    };
    let app = App::new(policy, Secret::new(SECRET.to_vec()).unwrap(), services).unwrap();
    let body = comment_payload(INSTALLATION, REPO, REPO_NAME, ACTOR, PR, "/pii-eval run");
    let sig = sign(SECRET, &body);
    let d = app.handle_delivery(&pii_eval_app::webhook::RawDelivery {
        event: Some("issue_comment"),
        delivery_id: Some("e2e-1"),
        signature: Some(&sig),
        body: &body,
    });
    let Outcome::Accepted { job_id, .. } = d.outcome else {
        panic!("accepted: {d:?}")
    };
    let pool = app.start_workers().unwrap();
    wait_until("the job reaches a terminal state", || {
        app.job_state(&job_id).is_some_and(JobState::is_terminal)
    });
    pool.shutdown();
    assert_eq!(app.job_state(&job_id), Some(JobState::Completed));

    let runs = checks.runs();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].status, CheckStatus::Completed);
    assert_eq!(runs[0].conclusion, Some(Conclusion::Success));
    let text = &runs[0].output.as_ref().unwrap().summary;
    assert!(text.contains("state: complete"), "{text}");
    assert!(text.contains(&format!("population-digest: {QUICKSTART_POPULATION}")));
    assert!(text.contains("scanner redact-secret-core: complete"));
    assert!(text.contains("run-artifact-digest: "));
    // No path, no host detail.
    assert!(!text.contains(work.path().to_str().unwrap()));
    assert!(!text.contains("/tmp") && !text.contains("/var/"));
    // The artifacts are the CLI's output: the worker removed them.
    assert_eq!(work.entries(), 0, "the work directory is left clean");
}

#[test]
fn a_changed_configuration_is_refused_before_anything_runs() {
    let Some(node) = node() else { return };
    let work = Work::new("changed");
    let r = runner(&work, node);
    let p = profile(&"0".repeat(64));
    let spec = JobSpec {
        job_id: JobId::derive(&identity(&p)),
        identity: identity(&p),
        attempt: 1,
    };
    assert_eq!(
        r.run(&spec, &CancelFlag::new()).unwrap_err(),
        RunnerError::ProfileChanged
    );
    assert_eq!(work.entries(), 0);
}

#[test]
fn unknown_profiles_protected_profiles_and_cancelled_jobs_are_refused() {
    let Some(node) = node() else { return };
    let work = Work::new("refused");
    let r = runner(&work, node);
    let p = profile(&good_digest());
    let mut unknown = identity(&p);
    unknown.profile_id = "not-configured".into();
    let spec = |identity: JobIdentity| JobSpec {
        job_id: JobId::derive(&identity),
        identity,
        attempt: 1,
    };
    assert_eq!(
        r.run(&spec(unknown), &CancelFlag::new()).unwrap_err(),
        RunnerError::Refused
    );
    let mut protected = identity(&p);
    protected.class = ProfileClass::Protected;
    assert_eq!(
        r.run(&spec(protected), &CancelFlag::new()).unwrap_err(),
        RunnerError::Refused,
        "the CLI runner never runs a protected profile"
    );
    let cancel = CancelFlag::new();
    cancel.cancel();
    assert_eq!(
        r.run(&spec(identity(&p)), &cancel).unwrap_err(),
        RunnerError::Cancelled
    );
    assert_eq!(work.entries(), 0);
    let _ = FailReason::Internal;
}
