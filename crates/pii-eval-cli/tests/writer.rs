//! The atomic, validated artifact writer: what reaches disk, in which order,
//! with which permissions, and what is left behind when something fails or the
//! process dies. Synthetic only.

mod common;

use std::io;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::*;
use pii_eval_cli::assemble::Assembled;
use pii_eval_cli::exec::{CancelToken, ExecutorConfig, ResourcePolicy};
use pii_eval_cli::run::{RunConfig, RunRequest, run};
use pii_eval_cli::write::{
    ArtifactWriter, OverwritePolicy, PUBLIC_ARTIFACT_FILE, RUN_ARTIFACT_FILE, WriteError,
    WriteStage, cleanup_stale_temps,
};
use pii_eval_contracts::{
    CorpusSnapshot, MetricValue, RunArtifact, RunManifest, ScaledDecimal, parse_default, seal,
};

struct Run {
    snapshot: CorpusSnapshot,
    manifest: RunManifest,
    assembled: Assembled,
    started: std::time::Instant,
}

fn produce() -> Run {
    let snapshot = snapshot();
    let mut beta = FakeAdapter::new("beta-scan", 3);
    beta.unsupported = true;
    let adapters = vec![FakeAdapter::new("alpha-scan", 5), beta];
    let manifest = manifest(
        &snapshot,
        adapters.iter().map(|a| a.plan.clone()).collect(),
        limits(2, 1, 2, 2),
        mechanics(2),
    );
    let output = run(
        &RunRequest {
            snapshot: &snapshot,
            manifest: &manifest,
            adapters: adapters
                .into_iter()
                .map(|a| Arc::new(a) as Arc<dyn pii_eval_adapters::ScannerAdapter>)
                .collect(),
        },
        &RunConfig {
            executor: ExecutorConfig {
                max_workers: 2,
                resources: ResourcePolicy::Unenforced,
                ..ExecutorConfig::default()
            },
            diagnostics: true,
            commit_cancelled: false,
        },
        &CancelToken::new(),
    )
    .expect("run");
    Run {
        snapshot,
        manifest,
        assembled: output.assembled,
        started: output.started,
    }
}

fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[test]
fn a_successful_write_commits_in_order_with_private_permissions() {
    let mut run = produce();
    let tmp = TempDir::new("writer-ok");
    let dir = tmp.0.join("out");
    let writer = ArtifactWriter::new(&dir, OverwritePolicy::Refuse);
    let written = writer
        .write_run(
            &run.snapshot,
            &run.manifest,
            &mut run.assembled,
            run.started,
        )
        .expect("written");
    let order: Vec<&str> = written.files.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(
        order,
        [
            "observation-alpha-scan.json",
            "observation-beta-scan.json",
            PUBLIC_ARTIFACT_FILE,
            RUN_ARTIFACT_FILE
        ],
        "observation sets, the projection, then the run artifact last"
    );
    // Only final files remain: no temporary file is left behind.
    assert_eq!(names(&dir).len(), 4);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for f in &written.files {
            let mode = std::fs::metadata(dir.join(&f.name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{}", f.name);
        }
        let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(dir_mode & 0o777, 0o700);
    }
    // What is on disk is what was validated: it parses strictly and the digests match.
    let artifact: RunArtifact =
        parse_default(&std::fs::read(dir.join(RUN_ARTIFACT_FILE)).unwrap()).unwrap();
    assert_eq!(artifact, run.assembled.artifact);
    for f in &written.files {
        let bytes = std::fs::read(dir.join(&f.name)).unwrap();
        assert_eq!(pii_eval_contracts::Sha256Digest::of_bytes(&bytes), f.sha256);
        assert_eq!(bytes.len() as u64, f.bytes);
    }
    // The measured serialization phase is recorded in the diagnostics.
    assert!(artifact.diagnostics.is_some());
    // The same bytes again: the writer is deterministic for the same documents.
    let again = TempDir::new("writer-again");
    let mut second = produce();
    let _ = &mut second;
    let w2 = ArtifactWriter::new(again.0.join("out"), OverwritePolicy::Refuse);
    let written2 = w2
        .write_run(
            &run.snapshot,
            &run.manifest,
            &mut run.assembled,
            run.started,
        )
        .unwrap();
    assert_eq!(written2.files[0].sha256, written.files[0].sha256);
}

#[test]
fn an_existing_destination_is_refused_or_replaced_by_policy_and_never_through_a_symlink() {
    let mut run = produce();
    let tmp = TempDir::new("writer-exists");
    let dir = tmp.0.join("out");
    let refuse = ArtifactWriter::new(&dir, OverwritePolicy::Refuse);
    refuse
        .write_run(
            &run.snapshot,
            &run.manifest,
            &mut run.assembled,
            run.started,
        )
        .unwrap();
    let before = std::fs::read(dir.join(RUN_ARTIFACT_FILE)).unwrap();
    assert_eq!(
        refuse
            .write_run(
                &run.snapshot,
                &run.manifest,
                &mut run.assembled,
                run.started
            )
            .unwrap_err(),
        WriteError::Exists
    );
    assert_eq!(names(&dir).len(), 4, "a refused write touches nothing");
    assert_eq!(std::fs::read(dir.join(RUN_ARTIFACT_FILE)).unwrap(), before);
    let replace = ArtifactWriter::new(&dir, OverwritePolicy::Replace);
    replace
        .write_run(
            &run.snapshot,
            &run.manifest,
            &mut run.assembled,
            run.started,
        )
        .expect("replace");
    assert_eq!(names(&dir).len(), 4);

    #[cfg(unix)]
    {
        // A destination that is a symlink is refused, and so is a symlinked file.
        let link = tmp.0.join("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        let through = ArtifactWriter::new(&link, OverwritePolicy::Replace);
        assert_eq!(
            through
                .write_run(
                    &run.snapshot,
                    &run.manifest,
                    &mut run.assembled,
                    run.started
                )
                .unwrap_err(),
            WriteError::Destination
        );
        let other = tmp.0.join("other");
        std::fs::create_dir(&other).unwrap();
        let victim = tmp.0.join("victim.json");
        std::fs::write(&victim, b"keep").unwrap();
        std::os::unix::fs::symlink(&victim, other.join(RUN_ARTIFACT_FILE)).unwrap();
        let w = ArtifactWriter::new(&other, OverwritePolicy::Replace);
        assert_eq!(
            w.write_run(
                &run.snapshot,
                &run.manifest,
                &mut run.assembled,
                run.started
            )
            .unwrap_err(),
            WriteError::Destination
        );
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
    }
}

#[test]
fn the_accounting_verifier_runs_on_every_artifact_and_a_bad_metric_writes_nothing() {
    let mut run = produce();
    // A metric value that the contracts accept (it is structurally fine and the
    // digest is resealed) but that is not the accounting of the rows.
    // One more sample in a numerator: every count identity still holds (and the
    // value stays withheld at this small N), so only the rows can expose it.
    let metric = run.assembled.artifact.semantic.scanner_metrics[0]
        .metrics
        .iter_mut()
        .find(|m| m.counts.numerator < m.counts.measured)
        .expect("a metric with a non-numerator sample");
    metric.counts.numerator += 1;
    assert!(matches!(metric.value, MetricValue::Withheld { .. }));
    let _ = ScaledDecimal::ZERO;
    seal(&mut run.assembled.artifact).unwrap();
    pii_eval_contracts::validate(&run.assembled.artifact).expect("contract-valid");
    let tmp = TempDir::new("writer-verify");
    let dir = tmp.0.join("out");
    let writer = ArtifactWriter::new(&dir, OverwritePolicy::Refuse);
    // The projection was built from the good artifact, so it no longer equals
    // the projection of the tampered one; both defects are refused.
    let err = writer
        .write_run(
            &run.snapshot,
            &run.manifest,
            &mut run.assembled,
            run.started,
        )
        .unwrap_err();
    assert!(matches!(err, WriteError::Verification(_)), "{err}");
    assert!(
        !dir.exists() || names(&dir).is_empty(),
        "nothing was written"
    );
}

#[test]
fn a_projection_that_is_not_the_projection_of_its_artifact_is_refused() {
    let mut run = produce();
    let mut public = run.assembled.public.clone().unwrap();
    public.semantic.completeness = pii_eval_contracts::Completeness::Partial;
    seal(&mut public).unwrap();
    run.assembled.public = Some(public);
    let tmp = TempDir::new("writer-public");
    let writer = ArtifactWriter::new(tmp.0.join("out"), OverwritePolicy::Refuse);
    assert!(
        writer
            .write_run(
                &run.snapshot,
                &run.manifest,
                &mut run.assembled,
                run.started
            )
            .is_err()
    );
    assert!(!tmp.0.join("out").exists() || names(&tmp.0.join("out")).is_empty());
}

#[test]
fn a_failure_before_the_renames_leaves_nothing_behind() {
    // Fail at every temp-write and every pre-rename stage in turn.
    for fail_at in 0..8usize {
        let mut run = produce();
        let tmp = TempDir::new("writer-fault");
        let dir = tmp.0.join("out");
        let counter = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&counter);
        let writer =
            ArtifactWriter::new(&dir, OverwritePolicy::Refuse).with_fault_hook(move |stage| {
                // Stages in order: 4 TempWritten, then BeforeRename/Renamed pairs.
                let n = c.fetch_add(1, Ordering::SeqCst);
                if n == fail_at && !matches!(stage, WriteStage::Renamed(_)) {
                    Err(io::Error::other("injected"))
                } else {
                    Ok(())
                }
            });
        let result = writer.write_run(
            &run.snapshot,
            &run.manifest,
            &mut run.assembled,
            run.started,
        );
        if result.is_ok() {
            // The injected index fell on a `Renamed` stage, which is not failed here.
            continue;
        }
        // Whatever stage failed, no final file and no temporary file remains.
        assert_eq!(names(&dir), Vec::<String>::new(), "fail_at {fail_at}");
        assert!(!matches!(
            result,
            Err(WriteError::PartiallyCommitted { .. })
        ));
    }
}

#[test]
fn a_failure_after_some_renames_rolls_back_or_says_it_could_not() {
    // Fail when the run artifact (the last file) is about to be renamed: the
    // three files already renamed are rolled back under `Refuse`.
    let mut run = produce();
    let tmp = TempDir::new("writer-rollback");
    let dir = tmp.0.join("out");
    let writer =
        ArtifactWriter::new(&dir, OverwritePolicy::Refuse).with_fault_hook(|stage| match stage {
            WriteStage::BeforeRename(n) if n == RUN_ARTIFACT_FILE => {
                Err(io::Error::other("injected"))
            }
            _ => Ok(()),
        });
    let err = writer
        .write_run(
            &run.snapshot,
            &run.manifest,
            &mut run.assembled,
            run.started,
        )
        .unwrap_err();
    assert_eq!(err, WriteError::Io(io::ErrorKind::Other));
    assert_eq!(names(&dir), Vec::<String>::new(), "rolled back completely");

    // Under `Replace` a rollback cannot restore what was overwritten, so the
    // partial state is reported, never silent.
    let mut run = produce();
    let tmp = TempDir::new("writer-partial");
    let dir = tmp.0.join("out");
    ArtifactWriter::new(&dir, OverwritePolicy::Refuse)
        .write_run(
            &run.snapshot,
            &run.manifest,
            &mut run.assembled,
            run.started,
        )
        .unwrap();
    let writer =
        ArtifactWriter::new(&dir, OverwritePolicy::Replace).with_fault_hook(|stage| match stage {
            WriteStage::BeforeRename(n) if n == RUN_ARTIFACT_FILE => {
                Err(io::Error::other("injected"))
            }
            _ => Ok(()),
        });
    let err = writer
        .write_run(
            &run.snapshot,
            &run.manifest,
            &mut run.assembled,
            run.started,
        )
        .unwrap_err();
    assert!(
        matches!(err, WriteError::PartiallyCommitted { ref committed } if committed.len() == 3)
    );
    assert!(names(&dir).iter().all(|n| !n.starts_with(".pii-eval-tmp.")));
}

/// Child half of the crash test: write, and die hard just before the commit
/// marker is renamed. Does nothing unless the parent asked for it.
#[test]
fn crash_child_entry() {
    let Ok(dir) = std::env::var("PII_EVAL_WRITER_CRASH_DIR") else {
        return;
    };
    let mut run = produce();
    let writer = ArtifactWriter::new(dir, OverwritePolicy::Refuse).with_fault_hook(|stage| {
        if matches!(stage, WriteStage::BeforeRename(n) if n == RUN_ARTIFACT_FILE) {
            std::process::abort();
        }
        Ok(())
    });
    let _ = writer.write_run(
        &run.snapshot,
        &run.manifest,
        &mut run.assembled,
        run.started,
    );
}

#[test]
fn a_hard_crash_never_leaves_a_half_written_final_file_or_a_commit_marker() {
    let tmp = TempDir::new("writer-crash");
    let dir = tmp.0.join("out");
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "crash_child_entry",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("PII_EVAL_WRITER_CRASH_DIR", &dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(!status.success(), "the child was killed by abort()");
    let present = names(&dir);
    // The commit marker is absent: the run is recognizably incomplete.
    assert!(
        !present.contains(&RUN_ARTIFACT_FILE.to_owned()),
        "{present:?}"
    );
    // Every final file that did land is complete and valid, never half written.
    for name in present
        .iter()
        .filter(|n| n.ends_with(".json") && !n.starts_with('.'))
    {
        let bytes = std::fs::read(dir.join(name)).unwrap();
        let ok = if name.starts_with("observation-") {
            parse_default::<pii_eval_contracts::ObservationSet>(&bytes).is_ok()
        } else {
            parse_default::<pii_eval_contracts::PublicSyntheticArtifact>(&bytes).is_ok()
        };
        assert!(ok, "{name} is not a valid document");
    }
    // The temporary file of the interrupted rename is left, and is removable.
    assert!(
        present.iter().any(|n| n.starts_with(".pii-eval-tmp.")),
        "{present:?}"
    );
    assert_eq!(cleanup_stale_temps(&dir).unwrap(), 1);
    assert!(names(&dir).iter().all(|n| !n.starts_with(".pii-eval-tmp.")));
}
