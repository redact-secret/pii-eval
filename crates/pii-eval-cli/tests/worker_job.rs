//! The worker-job launcher end to end, in process, with the TEST adapters
//! (feature `worker-test-adapters`): the happy path, parity with the standalone
//! pipeline, and every refusal and partial path of docs/worker-job.md with a
//! hostile or broken synthetic input. Synthetic data only.
#![cfg(all(unix, feature = "worker-test-adapters"))]

mod cli_support;
mod common;
mod worker_support;

use std::os::unix::fs::PermissionsExt;

use cli_support::*;
use pii_eval_cli::exec::CancelToken;
use pii_eval_cli::run::{RunConfig as PipelineConfig, RunRequest, run};
use pii_eval_cli::status::{Exit, reason as cli_reason};
use pii_eval_cli::worker::reason;
use pii_eval_contracts::ScannerStatus;
use serde_json::{Value, json};
use worker_support::*;

type ConfigEdit = Box<dyn Fn(&mut Value)>;

fn channel_file() -> &'static str {
    pii_eval_cli::worker::test_adapters::CHANNEL_FILE
}

fn check(world: &World, exit: Exit, expected: &str) {
    let f = world.refusal();
    assert_eq!((f.exit, f.reason), (exit, expected), "{}", f.human());
    // One fixed line; nothing on stdout for a refusal.
    let line = f.human();
    assert!(line.starts_with("pii-eval: ") && !line.contains('\n'));
    let rendered = pii_eval_cli::render_worker_result(Err(f));
    assert!(rendered.stdout.is_empty());
    assert_eq!(rendered.stderr.matches('\n').count(), 1);
    // A refusal delivered nothing.
    assert!(!world.scratch.join(channel_file()).exists());
}

fn cells(doc: &[u8]) -> Vec<(String, u64, u64)> {
    let v: Value = serde_json::from_slice(doc).unwrap();
    v["cells"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["metric"].as_str().unwrap().to_owned(),
                c["numerator"].as_u64().unwrap(),
                c["denominator"].as_u64().unwrap(),
            )
        })
        .collect()
}

fn clear_work(w: &World) {
    let _ = std::fs::remove_dir_all(w.scratch.join("pii-eval-worker"));
}

#[test]
fn a_job_runs_and_prints_one_closed_result_and_delivers_the_aggregates() {
    let node = node_or_return!();
    let w = World::build("wj-ok", &node, &Opts::default());
    let out = w.run_ok();
    assert_eq!(
        out.result,
        r#"{"domain":"pii","protocol":{"name":"pii-v1","version":"2"},"roster":{"expected":3,"failed":0,"observed":3},"schema":"private-custodian.worker-result/1","status":"complete"}"#
    );
    let rendered = pii_eval_cli::render_worker_result(Ok(out.clone()));
    assert_eq!(
        (rendered.exit, rendered.stderr.as_str()),
        (Exit::Success, "")
    );
    assert_eq!(rendered.stdout, out.result);
    assert!(rendered.stdout.len() <= 64 * 1024);
    assert_eq!(out.scanner_status, ScannerStatus::Complete);
    // The aggregates document is what the channel stored, under scratch.
    let delivered = std::fs::read(w.scratch.join(channel_file())).unwrap();
    assert_eq!(Some(delivered.clone()), out.aggregates);
    assert!(delivered.len() <= 64 * 1024);
    let c = cells(&delivered);
    // Nine cells: the test labels leave out `measurable-share` (see the
    // refusal test below for why).
    assert_eq!(c.len(), 9);
    assert!(c.iter().all(|(m, _, _)| m != "measurable-share"));
    assert!(c.iter().all(|(_, n, d)| n <= d && *d <= 3));
    // Every written file is under the scratch directory; the documents are the
    // internal ones, and no population text or case id is in the outputs.
    assert!(
        out.out_dir
            .starts_with(std::fs::canonicalize(&w.scratch).unwrap())
    );
    assert_eq!(
        list_dir(&out.out_dir),
        [
            "manifest.json",
            "observation-redact-secret-core.json",
            "run-artifact.json"
        ]
    );
    let leaked = format!("{}{}", out.result, String::from_utf8_lossy(&delivered));
    for case in &w.snapshot.semantic.cases {
        assert!(!leaked.contains(case.case_id.as_str()));
        for v in &case.variants {
            assert!(!leaked.contains(&v.text));
        }
    }
}

#[test]
fn the_same_job_gives_byte_identical_results_aggregates_and_artifact_digests() {
    let node = node_or_return!();
    let a = World::build("wj-det-a", &node, &Opts::default()).run_ok();
    let b = World::build("wj-det-b", &node, &Opts::default()).run_ok();
    assert_eq!(a.result, b.result);
    assert_eq!(a.aggregates, b.aggregates);
    assert_eq!(a.run_artifact_digest, b.run_artifact_digest);
}

#[test]
fn worker_mode_measures_exactly_what_standalone_run_measures_on_the_same_population() {
    let node = node_or_return!();
    let w = World::build("wj-parity", &node, &Opts::default());
    let worker = w.run_ok();
    // The standalone pipeline, in process, on the same snapshot and manifest and
    // the original (never bundled) package.
    let standalone = run(
        &RunRequest {
            snapshot: &w.snapshot,
            manifest: &w.manifest,
            adapters: vec![core_adapter_for(&w.package, &node)],
        },
        &PipelineConfig::default(),
        &CancelToken::new(),
    )
    .expect("standalone run");
    let artifact = &standalone.assembled.artifact;
    assert_eq!(
        artifact.semantic_digest.as_str(),
        worker.run_artifact_digest
    );
    let from_kernel: Vec<(String, u64, u64)> = artifact.semantic.scanner_metrics[0]
        .metrics
        .iter()
        .map(|m| {
            (
                m.metric.id.as_str().to_owned(),
                m.counts.numerator,
                m.counts.measured,
            )
        })
        .collect();
    assert_eq!(from_kernel.len(), 10);
    let published: Vec<(String, u64, u64)> = from_kernel
        .iter()
        .filter(|(m, _, _)| m != "measurable-share")
        .cloned()
        .collect();
    assert_eq!(cells(worker.aggregates.as_ref().unwrap()), published);
}

// --- refusals: the job ----------------------------------------------------------

#[test]
fn hostile_jobs_are_refused_before_anything_is_read() {
    let node = node_or_return!();
    let w = World::build("wj-job", &node, &Opts::default());
    let entries = w.entries.clone();
    let good = job_json(&entries);
    let cases: Vec<(String, Exit, &str)> = vec![
        (
            good.replace("\"roster\":3", "\"roster\":4"),
            Exit::Invalid,
            reason::ROSTER_MISMATCH,
        ),
        (
            good.replace("\"pii\"", "\"credential\""),
            Exit::Provenance,
            reason::JOB_DOMAIN_MISMATCH,
        ),
        (
            good.replace("\"2\"", "\"1\""),
            Exit::Provenance,
            reason::JOB_PROTOCOL_MISMATCH,
        ),
        (
            good.replacen('}', ",\"extra\":1}", 1),
            Exit::Invalid,
            reason::JOB_INVALID,
        ),
        (
            good.replace(&entries[0], "../../etc/passwd"),
            Exit::Invalid,
            reason::ENTRY_NAME_INVALID,
        ),
        (
            good.replace(&entries[1], &entries[0]),
            Exit::Invalid,
            reason::ENTRIES_DUPLICATE,
        ),
        ("not json".to_owned(), Exit::Invalid, reason::JOB_INVALID),
    ];
    for (text, exit, expected) in cases {
        w.set_job(&text);
        check(&w, exit, expected);
    }
    // Missing and oversized job files.
    std::fs::remove_file(&w.job).unwrap();
    check(&w, Exit::Invalid, reason::JOB_UNREADABLE);
    w.set_job(&" ".repeat((1 << 20) + 1));
    check(&w, Exit::Invalid, reason::JOB_TOO_LARGE);
    // Too many entries.
    let many: Vec<String> = (0..10_001).map(|i| format!("e{i}")).collect();
    w.set_job(&job_json(&many));
    check(&w, Exit::Invalid, reason::ENTRIES_TOO_MANY);
    // The world is untouched: the original job still runs.
    w.set_job(&good);
    w.run_ok();
}

// --- refusals: the entries -----------------------------------------------------

#[test]
fn a_stale_job_a_hostile_entry_or_a_bad_population_never_reaches_a_scanner() {
    let node = node_or_return!();
    let w = World::build("wj-entries", &node, &Opts::default());
    let first = w.input.join(&w.entries[0]);
    let original = std::fs::read(&first).unwrap();
    let restore = |bytes: &[u8]| {
        let _ = std::fs::remove_file(&first);
        let _ = std::fs::remove_dir(&first);
        std::fs::write(&first, bytes).unwrap();
        std::fs::set_permissions(&first, std::fs::Permissions::from_mode(0o400)).unwrap();
    };

    // Stale: an extra file, then a missing one.
    std::fs::write(w.input.join("extra-entry"), b"x").unwrap();
    check(&w, Exit::Provenance, reason::ENTRIES_LISTING_MISMATCH);
    std::fs::remove_file(w.input.join("extra-entry")).unwrap();
    std::fs::remove_file(&first).unwrap();
    check(&w, Exit::Provenance, reason::ENTRIES_LISTING_MISMATCH);

    // Not a regular file: a symlink, a directory, a hard-link alias.
    std::os::unix::fs::symlink("/etc/hosts", &first).unwrap();
    check(&w, Exit::Invalid, reason::ENTRY_NOT_REGULAR);
    std::fs::remove_file(&first).unwrap();
    std::fs::create_dir(&first).unwrap();
    check(&w, Exit::Invalid, reason::ENTRY_NOT_REGULAR);
    std::fs::remove_dir(&first).unwrap();
    restore(&original);
    let alias = w.tmp.0.join("alias");
    std::fs::hard_link(&first, &alias).unwrap();
    check(&w, Exit::Invalid, reason::ENTRY_NOT_REGULAR);
    std::fs::remove_file(&alias).unwrap();

    // Oversized: one byte over 16 MiB.
    let _ = std::fs::remove_file(&first);
    let f = std::fs::File::create(&first).unwrap();
    f.set_len(16 * 1024 * 1024 + 1).unwrap();
    drop(f);
    check(&w, Exit::Invalid, reason::ENTRY_TOO_LARGE);

    // Invalid contents: unknown field, wrong schema, a case id that is not the
    // name, an invalid range, nothing at all.
    let text = String::from_utf8(original.clone()).unwrap();
    assert!(text.contains("\"end\":"));
    let invalid: Vec<String> = vec![
        text.replacen('{', "{\"unknown\":1,", 1),
        text.replace("pii-eval-worker-entry/1", "pii-eval-worker-entry/2"),
        text.replacen(&w.entries[0], "another-case-id", 1),
        text.replacen("\"end\":", "\"end\":9999999,\"zz\":", 1),
        "{}".to_owned(),
    ];
    for bad in invalid {
        restore(bad.as_bytes());
        check(&w, Exit::Invalid, reason::ENTRY_INVALID);
    }
    // A text edit that leaves the digest stale is caught by the contract validator.
    let first_text = w.snapshot.semantic.cases[0].variants[0].text.clone();
    assert!(text.contains(&first_text));
    restore(
        text.replacen(&first_text, &format!("{first_text}!"), 1)
            .as_bytes(),
    );
    check(&w, Exit::Invalid, reason::ENTRY_INVALID);
    // The same variant id in two entries is refused when the snapshot is assembled.
    restore(&original);
    let second = w.input.join(&w.entries[1]);
    let other = String::from_utf8(std::fs::read(&second).unwrap()).unwrap();
    let a_id = w.snapshot.semantic.cases[0].variants[0]
        .variant_id
        .as_str()
        .to_owned();
    let b_id = w.snapshot.semantic.cases[1].variants[0]
        .variant_id
        .as_str()
        .to_owned();
    std::fs::remove_file(&second).unwrap();
    std::fs::write(&second, other.replace(&b_id, &a_id)).unwrap();
    std::fs::set_permissions(&second, std::fs::Permissions::from_mode(0o400)).unwrap();
    check(&w, Exit::Invalid, reason::ENTRY_INVALID);
}

#[test]
fn a_wrong_population_pin_or_run_class_is_refused_with_the_custodian_names() {
    let node = node_or_return!();
    let w = World::build("wj-bind", &node, &Opts::default());
    w.edit_config(|c| c["population"]["digest"] = json!("0".repeat(64)));
    check(&w, Exit::Provenance, reason::POPULATION_BINDING_MISMATCH);

    let w = World::build("wj-class", &node, &Opts::default());
    w.edit_config(|c| c["runClass"] = json!("public-synthetic"));
    check(&w, Exit::Provenance, reason::RUN_CLASS_MISMATCH);

    // A manifest whose body was edited without resealing is a configuration fault.
    let w = World::build("wj-manifest", &node, &Opts::default());
    w.edit_config(|c| {
        c["manifest"]["semantic"]["population"]["populationDigest"] = json!("1".repeat(64));
    });
    check(&w, Exit::Invalid, reason::WORKER_CONFIG_INVALID);

    // A resealed manifest that binds to another population.
    let w = World::build("wj-manifest2", &node, &Opts::default());
    let mut manifest = w.manifest.clone();
    manifest.semantic.population.population_digest =
        pii_eval_contracts::Sha256Digest::of_bytes(b"another population");
    pii_eval_contracts::seal(&mut manifest).unwrap();
    w.edit_config(|c| c["manifest"] = serde_json::to_value(&manifest).unwrap());
    check(&w, Exit::Provenance, reason::POPULATION_BINDING_MISMATCH);
}

// --- refusals: the configuration and the staged world ---------------------------

#[test]
fn a_hostile_configuration_can_only_fail_the_run() {
    let node = node_or_return!();
    let w = World::build("wj-config", &node, &Opts::default());
    let secret = "zq-secret-7731";
    let edits: Vec<ConfigEdit> = vec![
        Box::new(move |c| c[secret] = json!(1)),
        Box::new(|c| c["schema"] = json!("pii-eval-worker-config/2")),
        Box::new(|c| c["artifacts"]["candidate"]["entry"] = json!("../../../etc/passwd")),
        Box::new(|c| c["artifacts"]["candidate"]["entry"] = json!("/etc/passwd")),
        Box::new(|c| c["artifacts"]["engine"]["sha256"] = json!("0".repeat(64))),
        Box::new(|c| {
            c["artifacts"]["candidate"]["treeDigest"] = json!(format!("sha256:{}", "0".repeat(64)))
        }),
        Box::new(|c| c["resources"]["maxWorkers"] = json!(100_000)),
        Box::new(|c| c["resources"]["callTimeoutMs"] = json!(0)),
        Box::new(|c| c["product"] = json!("other")),
        Box::new(|c| c["artifacts"]["adapter"]["path"] = json!("/etc/passwd")),
    ];
    let pristine = w.stage_bytes("config");
    for edit in edits {
        w.stage_put("config", &pristine, 0o400);
        w.edit_config(|c| edit(c));
        let f = w.refusal();
        assert_eq!(
            (f.exit, f.reason),
            (Exit::Invalid, reason::WORKER_CONFIG_INVALID)
        );
        assert!(!f.human().contains(secret));
    }
    // A configuration over 1 MiB, and a protocol the engine does not support.
    w.stage_put("config", &vec![b' '; (1 << 20) + 1], 0o400);
    check(&w, Exit::Invalid, reason::WORKER_CONFIG_TOO_LARGE);
    w.stage_put("config", &pristine, 0o400);
    w.edit_config(|c| c["protocol"]["version"] = json!("3"));
    check(&w, Exit::Provenance, reason::JOB_PROTOCOL_MISMATCH);
}

#[test]
fn staged_files_must_be_regular_unaliased_and_not_group_or_other_writable() {
    let node = node_or_return!();
    let w = World::build("wj-shape", &node, &Opts::default());
    let engine = w.stage.join("engine");
    let original = w.stage_bytes("engine");
    // Group-writable, other-writable.
    for m in [0o520, 0o502] {
        std::fs::set_permissions(&engine, std::fs::Permissions::from_mode(m)).unwrap();
        check(&w, Exit::Provenance, reason::STAGED_FILE_INVALID);
    }
    // Symlink.
    std::fs::remove_file(&engine).unwrap();
    let target = w.tmp.0.join("elsewhere");
    std::fs::write(&target, &original).unwrap();
    std::os::unix::fs::symlink(&target, &engine).unwrap();
    check(&w, Exit::Provenance, reason::STAGED_FILE_INVALID);
    // Hard-link alias.
    std::fs::remove_file(&engine).unwrap();
    w.stage_put("engine", &original, 0o500);
    let alias = w.tmp.0.join("alias");
    std::fs::hard_link(&engine, &alias).unwrap();
    check(&w, Exit::Provenance, reason::STAGED_FILE_INVALID);
    std::fs::remove_file(&alias).unwrap();
    // Missing, and a directory.
    std::fs::remove_file(&engine).unwrap();
    check(&w, Exit::Provenance, reason::STAGED_FILE_INVALID);
    std::fs::create_dir(&engine).unwrap();
    check(&w, Exit::Provenance, reason::STAGED_FILE_INVALID);
    std::fs::remove_dir(&engine).unwrap();
    w.stage_put("engine", &original, 0o500);
    w.run_ok();
}

#[test]
fn each_digest_is_checked_on_its_own_with_its_own_reason() {
    let node = node_or_return!();
    let w = World::build("wj-digests", &node, &Opts::default());
    let (engine, adapter, candidate, runtime) = (
        w.stage_bytes("engine"),
        w.stage_bytes("adapter"),
        w.stage_bytes("candidate"),
        w.stage_bytes("scanner-0"),
    );
    let tamper = |bytes: &[u8]| {
        let mut v = bytes.to_vec();
        let last = v.len() - 1;
        v[last] ^= 1;
        v
    };
    w.stage_put("engine", &tamper(&engine), 0o500);
    check(&w, Exit::Provenance, reason::ENGINE_DIGEST_MISMATCH);
    w.stage_put("engine", &engine, 0o500);
    w.stage_put("adapter", &tamper(&adapter), 0o500);
    check(&w, Exit::Provenance, reason::ADAPTER_BUNDLE_DIGEST_MISMATCH);
    w.stage_put("adapter", &adapter, 0o500);
    w.stage_put("candidate", &tamper(&candidate), 0o500);
    check(
        &w,
        Exit::Provenance,
        reason::CANDIDATE_BUNDLE_DIGEST_MISMATCH,
    );
    w.stage_put("candidate", &candidate, 0o500);
    w.stage_put("scanner-0", &tamper(&runtime), 0o500);
    check(&w, Exit::Provenance, reason::RUNTIME_DIGEST_MISMATCH);
    w.stage_put("scanner-0", &runtime, 0o500);
    w.run_ok();
}

#[test]
fn a_bundle_digest_is_never_a_tree_digest_and_the_reverse() {
    let node = node_or_return!();
    let w = World::build("wj-typed", &node, &Opts::default());
    let pristine = w.stage_bytes("config");
    let cfg: Value = serde_json::from_slice(&pristine).unwrap();
    let bundle = cfg["artifacts"]["candidate"]["bundleDigest"]
        .as_str()
        .unwrap()
        .to_owned();
    let tree = cfg["artifacts"]["candidate"]["treeDigest"]
        .as_str()
        .unwrap()
        .to_owned();
    // Wrong syntax: a configuration fault, not a digest comparison.
    w.edit_config(|c| c["artifacts"]["candidate"]["treeDigest"] = json!(bundle.clone()));
    check(&w, Exit::Invalid, reason::WORKER_CONFIG_INVALID);
    w.stage_put("config", &pristine, 0o400);
    w.edit_config(|c| {
        c["artifacts"]["candidate"]["bundleDigest"] = json!(format!("sha256:{tree}"))
    });
    // Right syntax, wrong thing: the tree's hex as the bundle pin fails the
    // BUNDLE check; the bundle's hex as the tree pin fails the TREE check.
    check(
        &w,
        Exit::Provenance,
        reason::CANDIDATE_BUNDLE_DIGEST_MISMATCH,
    );
    w.stage_put("config", &pristine, 0o400);
    let bundle_hex = bundle.strip_prefix("sha256:").unwrap().to_owned();
    w.edit_config(|c| c["artifacts"]["candidate"]["treeDigest"] = json!(bundle_hex.clone()));
    check(&w, Exit::Provenance, reason::PACKAGE_TREE_DIGEST_MISMATCH);
}

#[test]
fn hostile_bundles_with_a_matching_pin_are_refused_by_the_only_extractor() {
    use pii_eval_cli::worker::bundle::{Member, encode};
    let node = node_or_return!();
    let w = World::build("wj-bundle", &node, &Opts::default());
    let pristine = w.stage_bytes("config");
    let raw = |path: &str, body: &[u8]| {
        let row = format!(
            r#"{{"executable":false,"path":"{path}","sha256":"{}","size":{}}}"#,
            pii_eval_contracts::Sha256Digest::of_bytes(body).as_str(),
            body.len()
        );
        let h = format!(r#"{{"members":[{row}]}}"#);
        let mut v = format!("pii-eval-bundle/1\n{}\n{h}\n", h.len()).into_bytes();
        v.extend_from_slice(body);
        v
    };
    let hostile: Vec<(&str, Vec<u8>)> = vec![
        ("zip-slip", raw("../escape", b"x")),
        ("absolute", raw("/tmp/pii-eval-escape", b"x")),
        ("backslash", raw("a\\\\b", b"x")),
        ("garbage", b"not a bundle".to_vec()),
        ("truncated", raw("a", b"x")[..30].to_vec()),
        ("trailing", [raw("a", b"x"), b"junk".to_vec()].concat()),
    ];
    for (label, bytes) in hostile {
        clear_work(&w);
        w.stage_put("config", &pristine, 0o400);
        w.stage_put("adapter", &bytes, 0o500);
        w.edit_config(|c| c["artifacts"]["adapter"]["bundleDigest"] = json!(sha(&bytes)));
        let f = w.refusal();
        assert_eq!(
            (f.exit, f.reason),
            (Exit::Invalid, reason::BUNDLE_INVALID),
            "{label}: {}",
            f.human()
        );
        assert!(f.detail.as_deref().unwrap().starts_with("adapter-"));
        assert!(!w.scratch.join("escape").exists());
        assert!(!std::path::Path::new("/tmp/pii-eval-escape").exists());
    }
    // A well-formed bundle whose shim is not the shipped one.
    let other = encode(&[Member {
        path: "redact-secret-core.mjs".into(),
        bytes: b"// not the shim".to_vec(),
        executable: false,
    }])
    .unwrap();
    clear_work(&w);
    w.stage_put("config", &pristine, 0o400);
    w.stage_put("adapter", &other, 0o500);
    w.edit_config(|c| c["artifacts"]["adapter"]["bundleDigest"] = json!(sha(&other)));
    check(&w, Exit::Provenance, reason::SHIM_DIGEST_MISMATCH);
    // A well-formed candidate bundle whose tree is not the pinned tree. The
    // adapter bundle goes back to the genuine one first.
    clear_work(&w);
    let w2 = World::build("wj-bundle2", &node, &Opts::default());
    let changed = encode(&[Member {
        path: "lib/index.js".into(),
        bytes: b"export const VERSION = 'x';".to_vec(),
        executable: false,
    }])
    .unwrap();
    w2.stage_put("candidate", &changed, 0o500);
    w2.edit_config(|c| c["artifacts"]["candidate"]["bundleDigest"] = json!(sha(&changed)));
    check(&w2, Exit::Provenance, reason::PACKAGE_TREE_DIGEST_MISMATCH);
}

#[test]
fn a_run_with_two_scanners_is_refused() {
    let node = node_or_return!();
    let w = World::build("wj-two", &node, &Opts::default());
    let mut manifest = w.manifest.clone();
    let mut second = manifest.semantic.scanners[0].clone();
    second.identity.scanner_id =
        pii_eval_contracts::ScannerId::new("redact-secret-core-b").unwrap();
    manifest.semantic.scanners.push(second);
    pii_eval_contracts::seal(&mut manifest).unwrap();
    w.edit_config(|c| c["manifest"] = serde_json::to_value(&manifest).unwrap());
    check(&w, Exit::Invalid, reason::SCANNER_COUNT_UNSUPPORTED);
}

// --- scanner failures: a partial result, exit 0 ----------------------------------

fn partial(label: &str, opts: Opts) {
    let Some(node) = node() else { return };
    let w = World::build(label, &node, &opts);
    let out = w.run_ok();
    assert_ne!(out.scanner_status, ScannerStatus::Complete, "{label}");
    assert_eq!(
        out.roster,
        pii_eval_cli::worker::job::Roster {
            expected: 3,
            observed: 3,
            failed: 3
        }
    );
    assert_eq!(
        out.aggregates, None,
        "{label}: no aggregates for a partial run"
    );
    assert!(!w.scratch.join(channel_file()).exists());
    // The run artifact records the failure (it was written and verified).
    let artifact: Value =
        serde_json::from_slice(&std::fs::read(out.out_dir.join("run-artifact.json")).unwrap())
            .unwrap();
    assert!(
        !artifact["semantic"]["failures"]
            .as_array()
            .unwrap()
            .is_empty(),
        "{label}"
    );
    let rendered = pii_eval_cli::render_worker_result(Ok(out));
    assert_eq!(rendered.exit, Exit::Success);
    assert!(rendered.stdout.contains("\"failed\":3"));
}

#[test]
fn a_scanner_crash_is_a_partial_result_not_a_refusal() {
    partial(
        "wj-crash",
        Opts {
            trigger: Some(CRASH),
            ..Opts::default()
        },
    );
}

#[test]
fn a_scanner_timeout_is_a_partial_result() {
    partial(
        "wj-timeout",
        Opts {
            trigger: Some(HANG),
            call_timeout_ms: Some(1500),
            ..Opts::default()
        },
    );
}

#[test]
fn a_malformed_scanner_reply_is_a_partial_result() {
    partial(
        "wj-garbage",
        Opts {
            trigger: Some(GARBAGE),
            ..Opts::default()
        },
    );
}

// --- cancellation -----------------------------------------------------------------

#[test]
fn a_cancelled_job_exits_8_and_leaves_no_scanner_or_artifact() {
    let node = node_or_return!();
    // Before the run: refused as cancelled, nothing started.
    let w = World::build("wj-cancel-pre", &node, &Opts::default());
    let token = CancelToken::new();
    token.cancel();
    let f = w.run(&token).unwrap_err();
    assert_eq!((f.exit, f.reason), (Exit::Cancelled, cli_reason::CANCELLED));
    // During the run: the scanner blocks forever, so the run can only end
    // through the cancellation, whenever it arrives.
    let w = World::build(
        "wj-cancel",
        &node,
        &Opts {
            trigger: Some(HANG),
            call_timeout_ms: Some(600_000),
            ..Opts::default()
        },
    );
    let token = CancelToken::new();
    let canceller = token.clone();
    let handle = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(1500));
        canceller.cancel();
    });
    let f = w.run(&token).unwrap_err();
    handle.join().unwrap();
    assert_eq!((f.exit, f.reason), (Exit::Cancelled, cli_reason::CANCELLED));
    assert_eq!(f.exit.code(), 8);
    assert!(
        !w.scratch
            .join("pii-eval-worker/out/run-artifact.json")
            .exists()
    );
    // The executor removed its scratch directories and the launcher the rest:
    // nothing it created is left in scratch.
    assert!(!w.scratch.join("pii-eval-worker").exists());
    assert!(!w.scratch.join(channel_file()).exists());
}

fn scratch_is_clean(w: &World) -> bool {
    !w.scratch.join("pii-eval-worker").exists()
}

#[test]
fn the_extracted_packages_and_work_dirs_are_removed_on_every_exit_path() {
    let node = node_or_return!();
    // Success: the extracted adapter, candidate and executor scratch are gone;
    // only the run documents stay (until the sandbox discards scratch).
    let w = World::build("wj-clean-ok", &node, &Opts::default());
    let out = w.run_ok();
    let work = w.scratch.join("pii-eval-worker");
    assert_eq!(list_dir(&work), ["out"]);
    assert!(out.out_dir.join("run-artifact.json").is_file());
    // A refusal after the extraction (population mismatch) leaves nothing.
    let w = World::build("wj-clean-refusal", &node, &Opts::default());
    w.edit_config(|c| c["population"]["digest"] = json!("0".repeat(64)));
    assert_eq!(w.refusal().reason, reason::POPULATION_BINDING_MISMATCH);
    assert!(scratch_is_clean(&w));
    // A refusal at the tree check (the packages are already extracted).
    let w = World::build("wj-clean-tree", &node, &Opts::default());
    w.edit_config(|c| c["artifacts"]["candidate"]["treeDigest"] = json!("0".repeat(64)));
    assert_eq!(w.refusal().reason, reason::PACKAGE_TREE_DIGEST_MISMATCH);
    assert!(scratch_is_clean(&w));
    // A scanner failure (partial result) keeps only the run documents.
    let w = World::build(
        "wj-clean-partial",
        &node,
        &Opts {
            trigger: Some(CRASH),
            ..Opts::default()
        },
    );
    w.run_ok();
    assert_eq!(list_dir(&w.scratch.join("pii-eval-worker")), ["out"]);
}

#[test]
fn a_token_cancelled_between_the_steps_stops_the_launch_before_the_next_one() {
    use pii_eval_cli::worker::contract::{
        Adapters, BundleError, BundleFormatAdapter, ContractStatus,
    };
    use pii_eval_cli::worker::launch::{WorkerRequest, run_worker_job};
    use pii_eval_cli::worker::test_adapters::*;
    let node = node_or_return!();
    // Cancelled while the packages are being extracted: the entries are never
    // read (the launcher stops at the next step) and nothing is left in scratch.
    struct CancelsAfterExtract(CancelToken);
    impl BundleFormatAdapter for CancelsAfterExtract {
        fn status(&self) -> ContractStatus {
            ContractStatus::TestOnly
        }
        fn extract(&self, bytes: &[u8], dest: &std::path::Path) -> Result<(), BundleError> {
            let r = TestBundle.extract(bytes, dest);
            self.0.cancel();
            r
        }
    }
    let w = World::build("wj-cancel-mid", &node, &Opts::default());
    // An unreadable entry would be refused (exit 3) if the entries were read.
    let first = w.input.join(&w.entries[0]);
    std::fs::remove_file(&first).unwrap();
    std::fs::write(&first, b"{}").unwrap();
    let token = CancelToken::new();
    let adapters = Adapters::production()
        .with_stage_layout(Box::new(TestLayout(w.layout())))
        .with_bundle_format(Box::new(CancelsAfterExtract(token.clone())))
        .with_entry_format(Box::new(TestEntry))
        .with_aggregates_channel(Box::new(FileChannel { fail: false }))
        .with_aggregate_labels(Box::new(TestLabels));
    let f = run_worker_job(
        &WorkerRequest {
            job: &w.job,
            adapters: &adapters,
            policy: POLICY,
        },
        &token,
    )
    .unwrap_err();
    assert_eq!((f.exit, f.reason), (Exit::Cancelled, cli_reason::CANCELLED));
    assert!(scratch_is_clean(&w));
    // A token cancelled before the launch stops it before the staged files are read.
    let w = World::build("wj-cancel-pre2", &node, &Opts::default());
    std::fs::remove_file(w.stage.join("config")).unwrap();
    let token = CancelToken::new();
    token.cancel();
    let f = w.run(&token).unwrap_err();
    assert_eq!((f.exit, f.reason), (Exit::Cancelled, cli_reason::CANCELLED));
}

#[test]
fn the_bundle_adapter_receives_exactly_the_bytes_whose_digest_was_pinned() {
    use pii_eval_cli::worker::contract::{
        Adapters, BundleError, BundleFormatAdapter, ContractStatus,
    };
    use pii_eval_cli::worker::launch::{WorkerRequest, run_worker_job};
    use pii_eval_cli::worker::test_adapters::*;
    use std::sync::{Arc, Mutex};
    let node = node_or_return!();
    let w = World::build("wj-onebuf", &node, &Opts::default());
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    struct Records(Arc<Mutex<Vec<String>>>);
    impl BundleFormatAdapter for Records {
        fn status(&self) -> ContractStatus {
            ContractStatus::TestOnly
        }
        fn extract(&self, bytes: &[u8], dest: &std::path::Path) -> Result<(), BundleError> {
            self.0.lock().unwrap().push(sha(bytes));
            TestBundle.extract(bytes, dest)
        }
    }
    let adapters = Adapters::production()
        .with_stage_layout(Box::new(TestLayout(w.layout())))
        .with_bundle_format(Box::new(Records(seen.clone())))
        .with_entry_format(Box::new(TestEntry))
        .with_aggregates_channel(Box::new(FileChannel { fail: false }))
        .with_aggregate_labels(Box::new(TestLabels));
    run_worker_job(
        &WorkerRequest {
            job: &w.job,
            adapters: &adapters,
            policy: POLICY,
        },
        &CancelToken::new(),
    )
    .unwrap();
    let cfg: Value = serde_json::from_slice(&w.stage_bytes("config")).unwrap();
    let pins = [
        cfg["artifacts"]["adapter"]["bundleDigest"]
            .as_str()
            .unwrap()
            .to_owned(),
        cfg["artifacts"]["candidate"]["bundleDigest"]
            .as_str()
            .unwrap()
            .to_owned(),
    ];
    assert_eq!(*seen.lock().unwrap(), pins);
}

#[test]
fn the_launch_result_debug_never_prints_the_aggregates() {
    let node = node_or_return!();
    let w = World::build("wj-debug", &node, &Opts::default());
    let out = w.run_ok();
    let text = format!("{out:?}");
    assert!(text.contains("aggregates_bytes"));
    assert!(!text.contains("numerator") && !text.contains("overall"));
}

#[test]
fn publishing_all_ten_metrics_over_a_case_roster_is_refused_not_clamped() {
    use pii_eval_cli::worker::contract::Adapters;
    use pii_eval_cli::worker::launch::{WorkerRequest, run_worker_job};
    use pii_eval_cli::worker::test_adapters::*;
    let node = node_or_return!();
    let w = World::build("wj-all-ten", &node, &Opts::default());
    let adapters = Adapters::production()
        .with_stage_layout(Box::new(TestLayout(w.layout())))
        .with_bundle_format(Box::new(TestBundle))
        .with_entry_format(Box::new(TestEntry))
        .with_aggregates_channel(Box::new(FileChannel { fail: false }))
        .with_aggregate_labels(Box::new(AllMetricLabels));
    let f = run_worker_job(
        &WorkerRequest {
            job: &w.job,
            adapters: &adapters,
            policy: POLICY,
        },
        &CancelToken::new(),
    )
    .unwrap_err();
    // `measurable-share` counts axis assertions: 5 measured over 3 entries.
    assert_eq!(
        (f.exit, f.reason),
        (Exit::Output, reason::AGGREGATES_ROSTER_VIOLATION)
    );
    assert!(!w.scratch.join(channel_file()).exists());
}

// --- delivery and bounds -----------------------------------------------------------

#[test]
fn a_failing_channel_is_an_output_failure_and_nothing_is_printed() {
    use pii_eval_cli::worker::contract::Adapters;
    use pii_eval_cli::worker::launch::{WorkerRequest, run_worker_job};
    use pii_eval_cli::worker::test_adapters::*;
    let node = node_or_return!();
    let w = World::build("wj-channel", &node, &Opts::default());
    let adapters = Adapters::production()
        .with_stage_layout(Box::new(TestLayout(w.layout())))
        .with_bundle_format(Box::new(TestBundle))
        .with_entry_format(Box::new(TestEntry))
        .with_aggregates_channel(Box::new(FileChannel { fail: true }))
        .with_aggregate_labels(Box::new(TestLabels));
    let f = run_worker_job(
        &WorkerRequest {
            job: &w.job,
            adapters: &adapters,
            policy: POLICY,
        },
        &CancelToken::new(),
    )
    .unwrap_err();
    assert_eq!(
        (f.exit, f.reason),
        (Exit::Output, reason::AGGREGATES_CHANNEL_FAILED)
    );
}

#[test]
fn aggregates_that_do_not_fit_the_roster_or_the_bounds_are_refused_never_clamped() {
    use pii_eval_cli::worker::aggregates::build;
    use pii_eval_cli::worker::contract::{AggregateLabelsAdapter, ContractStatus};
    use pii_eval_cli::worker::job::Roster;
    let node = node_or_return!();
    let w = World::build("wj-agg", &node, &Opts::default());
    let out = w.run_ok();
    let artifact: pii_eval_contracts::RunArtifact = pii_eval_contracts::parse_default(
        &std::fs::read(out.out_dir.join("run-artifact.json")).unwrap(),
    )
    .unwrap();
    let metrics = artifact.semantic.scanner_metrics[0].metrics.clone();
    struct Labels(&'static str);
    impl AggregateLabelsAdapter for Labels {
        fn status(&self) -> ContractStatus {
            ContractStatus::TestOnly
        }
        fn overall_stratum(&self) -> &str {
            self.0
        }
        fn metric(&self, id: &str) -> Option<String> {
            (id != "measurable-share").then(|| id.to_owned())
        }
    }
    let roster = |observed| Roster {
        expected: 3,
        observed,
        failed: 0,
    };
    assert!(build(&roster(3), &metrics, &Labels("overall")).is_ok());
    // A smaller observed count than some denominator: refused.
    let max_den = metrics
        .iter()
        .filter(|m| m.metric.id.as_str() != "measurable-share")
        .map(|m| m.counts.measured)
        .max()
        .unwrap();
    assert!(max_den >= 1);
    let f = build(&roster(max_den - 1), &metrics, &Labels("overall")).unwrap_err();
    assert_eq!(f.reason, reason::AGGREGATES_ROSTER_VIOLATION);
    // Labels outside the custodian's pattern.
    for bad in ["Overall", "", "has space", "-x"] {
        let f = build(&roster(3), &metrics, &Labels(bad)).unwrap_err();
        assert_eq!(f.reason, reason::AGGREGATE_LABEL_INVALID, "{bad:?}");
    }
    // More than 256 cells: refused, not truncated.
    let many: Vec<_> = (0..257).map(|_| metrics[0]).collect();
    let f = build(&roster(3), &many, &Labels("overall")).unwrap_err();
    assert_eq!(f.reason, reason::AGGREGATES_TOO_LARGE);
    // A duplicate cell (a label adapter that maps two metrics to one label).
    struct Same;
    impl AggregateLabelsAdapter for Same {
        fn status(&self) -> ContractStatus {
            ContractStatus::TestOnly
        }
        fn overall_stratum(&self) -> &str {
            "overall"
        }
        fn metric(&self, _: &str) -> Option<String> {
            Some("one".into())
        }
    }
    let f = build(&roster(3), &metrics, &Same).unwrap_err();
    assert_eq!(f.reason, reason::AGGREGATE_LABEL_INVALID);
}
