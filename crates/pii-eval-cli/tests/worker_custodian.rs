//! The whole worker flow against a REPLICA of the custodian's checks (see
//! `worker_support/replica.rs`: "replica of private-custodian@142db34, written
//! from its source; not its code"). Pinned inputs and candidate verification,
//! the inert fake scanner, measurement, `worker-result/1` and `aggregates/1`,
//! replica validation, the receipt-like roster comparison, and one negative run
//! per failure with the custodian outcome docs/custodian-contract-status.md
//! (A6) says it must produce. Synthetic data only.
#![cfg(all(unix, feature = "worker-test-adapters"))]

mod cli_support;
mod common;
mod worker_support;

use pii_eval_cli::exec::CancelToken;
use pii_eval_cli::worker::test_adapters::CHANNEL_FILE;
use serde_json::json;
use worker_support::replica::*;
use worker_support::*;

type Mutation = Box<dyn Fn(&World)>;

struct Dispatched {
    outcome: Outcome,
    reason: Reason,
    validated: Option<ValidatedResult>,
    exit: i32,
    stdout: Vec<u8>,
}

/// What the custodian does around one worker run: verify the staged identities
/// against the plan's pins before, run, verify them again after (any change is
/// Rejected whatever the worker returned), then map the process outcome.
fn dispatch(w: &World, token: &CancelToken, authorized: u64) -> Dispatched {
    let pins = w.pins();
    assert!(staged_identity_holds(&w.stage, &pins), "pre-run identity");
    let rendered = pii_eval_cli::render_worker_result(w.run(token));
    let stdout = rendered.stdout.clone().into_bytes();
    let exit = i32::from(rendered.exit.code());
    if !staged_identity_holds(&w.stage, &pins) {
        return Dispatched {
            outcome: Outcome::Rejected,
            reason: Reason::IdentityChangedAfterExecution,
            validated: None,
            exit,
            stdout,
        };
    }
    let (outcome, reason, validated) =
        map_outcome(exit, &stdout, Domain::Pii, &pii_protocol(), authorized);
    Dispatched {
        outcome,
        reason,
        validated,
        exit,
        stdout,
    }
}

fn allowlist() -> Allowlist {
    let metrics = pii_eval_contracts::METRICS
        .iter()
        .map(|m| m.id.as_str().to_owned())
        .filter(|m| m != "measurable-share")
        .collect();
    Allowlist {
        strata: vec!["overall".into()],
        metrics,
    }
}

fn artifact_ref(bytes: &[u8]) -> ArtifactRef {
    ArtifactRef {
        digest: sha(bytes),
        size: bytes.len() as u64,
        protocol: pii_protocol(),
    }
}

#[test]
fn the_job_document_the_replica_builds_is_accepted_by_the_engine() {
    let node = node_or_return!();
    let w = World::build("wc-job", &node, &Opts::default());
    let bytes = job_document(Domain::Pii, &pii_protocol(), &w.entries);
    // Same document (the custodian serializes in struct order; JSON equality).
    let theirs: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let ours: serde_json::Value = serde_json::from_str(&job_json(&w.entries)).unwrap();
    assert_eq!(theirs, ours);
    let job = pii_eval_cli::worker::job::parse_job(&bytes).unwrap();
    assert_eq!(job.entries, w.entries);
}

#[test]
fn replica_conformance_with_the_custodians_own_result_vectors() {
    // Vectors from private-custodian crates/custodian-worker/tests/staging_result.rs.
    let doc = |domain: &str, status: &str, e: u64, o: u64, f: u64| -> Vec<u8> {
        format!(
            "{{\"schema\":\"private-custodian.worker-result/1\",\"domain\":\"{domain}\",\
             \"protocol\":{{\"name\":\"pii-v1\",\"version\":\"2\"}},\"status\":\"{status}\",\
             \"roster\":{{\"expected\":{e},\"observed\":{o},\"failed\":{f}}}}}"
        )
        .into_bytes()
    };
    let p = pii_protocol();
    let ok = validate_result(&doc("pii", "complete", 5, 5, 0), Domain::Pii, &p, 5).unwrap();
    assert_eq!(ok.outcome, Outcome::Success);
    assert_eq!(ok.size as usize, doc("pii", "complete", 5, 5, 0).len());
    assert_eq!(
        validate_result(&doc("pii", "partial", 5, 3, 0), Domain::Pii, &p, 5)
            .unwrap()
            .outcome,
        Outcome::Partial
    );
    assert_eq!(
        validate_result(&doc("pii", "complete", 5, 5, 2), Domain::Pii, &p, 5)
            .unwrap()
            .outcome,
        Outcome::Partial
    );
    let bad: Vec<(Vec<u8>, Reason)> = vec![
        (b"".to_vec(), Reason::ResultMalformed),
        (b"null".to_vec(), Reason::ResultMalformed),
        (b"{}".to_vec(), Reason::ResultMalformed),
        (
            [doc("pii", "complete", 5, 5, 0), b" trailing".to_vec()].concat(),
            Reason::ResultMalformed,
        ),
        (doc("pii", "finished", 5, 5, 0), Reason::ResultMalformed),
        (
            doc("credential", "complete", 5, 5, 0),
            Reason::ResultMismatch,
        ),
        (doc("pii", "complete", 6, 6, 0), Reason::RosterMismatch),
        (doc("pii", "complete", 5, 4, 0), Reason::RosterMismatch),
        (doc("pii", "partial", 5, 5, 0), Reason::RosterMismatch),
        (doc("pii", "complete", 5, 6, 0), Reason::RosterMismatch),
        (doc("pii", "complete", 5, 5, 6), Reason::RosterMismatch),
        (vec![b'a'; MAX_RESULT_BYTES + 1], Reason::ResultOversized),
        // The remaining rows of the custodian's table (staging_result.rs), adapted
        // from its synthetic protocol to pii-v1 / 2: trailing data, another
        // protocol name or version, a free-text field, duplicate keys, another
        // schema version.
        (
            [doc("pii", "complete", 5, 5, 0), b"{}".to_vec()].concat(),
            Reason::ResultMalformed,
        ),
        (
            String::from_utf8(doc("pii", "complete", 5, 5, 0))
                .unwrap()
                .replace("pii-v1", "other-protocol")
                .into_bytes(),
            Reason::ResultMismatch,
        ),
        (
            String::from_utf8(doc("pii", "complete", 5, 5, 0))
                .unwrap()
                .replace("\"version\":\"2\"", "\"version\":\"3\"")
                .into_bytes(),
            Reason::ResultMismatch,
        ),
        (
            String::from_utf8(doc("pii", "complete", 5, 5, 0))
                .unwrap()
                .replace(
                    "\"status\"",
                    "\"message\":\"secret-shaped synthetic text\",\"status\"",
                )
                .into_bytes(),
            Reason::ResultMalformed,
        ),
        (
            String::from_utf8(doc("pii", "complete", 5, 5, 0))
                .unwrap()
                .replace("\"status\"", "\"status\":\"complete\",\"status\"")
                .into_bytes(),
            Reason::ResultMalformed,
        ),
        (
            String::from_utf8(doc("pii", "complete", 5, 5, 0))
                .unwrap()
                .replace("\"failed\":0", "\"failed\":0,\"failed\":0")
                .into_bytes(),
            Reason::ResultMalformed,
        ),
        (
            String::from_utf8(doc("pii", "complete", 5, 5, 0))
                .unwrap()
                .replace("worker-result/1", "worker-result/2")
                .into_bytes(),
            Reason::ResultMalformed,
        ),
    ];
    // An empty authorized roster is never complete.
    assert!(validate_result(&doc("pii", "complete", 0, 0, 0), Domain::Pii, &p, 0).is_err());
    for (bytes, reason) in bad {
        assert_eq!(
            validate_result(&bytes, Domain::Pii, &p, 5).err(),
            Some(reason),
            "{:?}",
            String::from_utf8_lossy(&bytes[..bytes.len().min(40)])
        );
    }
}

#[test]
fn the_whole_flow_succeeds_and_the_receipt_like_rosters_agree() {
    let node = node_or_return!();
    let w = World::build("wc-ok", &node, &Opts::default());
    let d = dispatch(&w, &CancelToken::new(), w.entries.len() as u64);
    assert_eq!(
        (d.exit, d.outcome, d.reason),
        (0, Outcome::Success, Reason::Completed)
    );
    let v = d.validated.unwrap();
    assert_eq!(
        v.roster,
        Roster {
            expected: 3,
            observed: 3,
            failed: 0
        }
    );
    // The receipt-like record: the roster of the validated result, and a
    // `result` reference to the SEPARATE aggregates document (the custodian's
    // own test assembly, c12 `assemble`).
    let aggregates = std::fs::read(w.scratch.join(CHANNEL_FILE)).unwrap();
    let cells = decode_aggregates(
        &aggregates,
        &artifact_ref(&aggregates),
        Domain::Pii,
        &pii_protocol(),
        &v.roster,
        &allowlist(),
    )
    .expect("the custodian's decode accepts the document");
    assert_eq!(cells.len(), 9);
    assert!(receipt_accepts(v.outcome, &v.roster));
    // The result reference of the receipt is NOT the aggregates reference: the
    // two documents are distinct (custodian-contract-status.md, section D).
    assert_ne!(v.digest, sha(&aggregates));
    // The numbers are the kernel's, read back from the committed artifact.
    let artifact: serde_json::Value = serde_json::from_slice(
        &std::fs::read(w.scratch.join("pii-eval-worker/out/run-artifact.json")).unwrap(),
    )
    .unwrap();
    for (_, metric, n, den) in &cells {
        let m = artifact["semantic"]["scannerMetrics"][0]["metrics"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["metric"]["id"] == *metric)
            .unwrap();
        assert_eq!(
            (
                m["counts"]["numerator"].as_u64(),
                m["counts"]["measured"].as_u64()
            ),
            (Some(*n), Some(*den))
        );
    }
    // Nothing printed besides the result.
    assert!(!d.stdout.contains(&b'\n'));
}

#[test]
fn the_aggregates_the_custodian_would_reject_are_rejected_by_the_replica_decode() {
    let node = node_or_return!();
    let w = World::build("wc-agg", &node, &Opts::default());
    let d = dispatch(&w, &CancelToken::new(), 3);
    let roster = d.validated.unwrap().roster;
    let good = std::fs::read(w.scratch.join(CHANNEL_FILE)).unwrap();
    let text = String::from_utf8(good.clone()).unwrap();
    let decode = |bytes: &[u8], r: &ArtifactRef, roster: &Roster, allow: &Allowlist| {
        decode_aggregates(bytes, r, Domain::Pii, &pii_protocol(), roster, allow).err()
    };
    let allow = allowlist();
    assert_eq!(decode(&good, &artifact_ref(&good), &roster, &allow), None);
    // The bytes are not the ones the receipt recorded.
    let mut other = good.clone();
    other.push(b' ');
    assert_eq!(
        decode(&other, &artifact_ref(&good), &roster, &allow),
        Some(DisclosureReason::ArtifactMismatch)
    );
    // A roster that differs from the receipt's.
    let wrong = Roster {
        expected: 4,
        observed: 4,
        failed: 0,
    };
    assert_eq!(
        decode(&good, &artifact_ref(&good), &wrong, &allow),
        Some(DisclosureReason::ArtifactMismatch)
    );
    // Hostile variants of the document, each bound to its own reference.
    let variants: Vec<(String, DisclosureReason)> = vec![
        (
            text.replacen('{', "{\"message\":\"x\",", 1),
            DisclosureReason::ArtifactMalformed,
        ),
        (
            text.replace(
                "private-custodian.aggregates/1",
                "private-custodian.aggregates/2",
            ),
            DisclosureReason::ArtifactMalformed,
        ),
        (
            text.replace("\"domain\":\"pii\"", "\"domain\":\"credential\""),
            DisclosureReason::ArtifactMismatch,
        ),
        (
            text.replace("\"version\":\"2\"", "\"version\":\"3\""),
            DisclosureReason::ArtifactMismatch,
        ),
        (
            text.replacen("\"denominator\":", "\"denominator\":99,\"x\":", 1),
            DisclosureReason::ArtifactMalformed,
        ),
        (
            text.replacen("\"stratum\":\"overall\"", "\"stratum\":\"language-ko\"", 1),
            DisclosureReason::StratumNotAllowed,
        ),
    ];
    for (t, reason) in variants {
        let bytes = t.into_bytes();
        assert_eq!(
            decode(&bytes, &artifact_ref(&bytes), &roster, &allow),
            Some(reason)
        );
    }
    // A denominator above `observed` is inconsistent (the custodian's rule).
    let v: serde_json::Value = serde_json::from_slice(&good).unwrap();
    let mut inflated = v.clone();
    inflated["cells"][0]["denominator"] = json!(4);
    let bytes = inflated.to_string().into_bytes();
    assert_eq!(
        decode(&bytes, &artifact_ref(&bytes), &roster, &allow),
        Some(DisclosureReason::ArtifactInconsistent)
    );
    // A metric label outside the policy allowlist.
    let narrow = Allowlist {
        strata: vec!["overall".into()],
        metrics: vec!["type-miss-rate".into()],
    };
    assert_eq!(
        decode(&good, &artifact_ref(&good), &roster, &narrow),
        Some(DisclosureReason::MetricNotAllowed)
    );
}

#[test]
fn a_scanner_failure_is_a_partial_outcome_and_no_receipt_can_carry_it() {
    let node = node_or_return!();
    let w = World::build(
        "wc-crash",
        &node,
        &Opts {
            trigger: Some(CRASH),
            ..Opts::default()
        },
    );
    let d = dispatch(&w, &CancelToken::new(), 3);
    assert_eq!(
        (d.exit, d.outcome, d.reason),
        (0, Outcome::Partial, Reason::EnginePartial)
    );
    let v = d.validated.unwrap();
    assert_eq!(
        v.roster,
        Roster {
            expected: 3,
            observed: 3,
            failed: 3
        }
    );
    // The custodian's own receipt rule accepts Partial only with observed <
    // expected: a result with observed == expected and failed items cannot be
    // turned into a receipt. Documented open item (worker-isolation.md, section 7).
    assert!(!receipt_accepts(Outcome::Partial, &v.roster));
    // No aggregates were delivered for a partial measurement.
    assert!(!w.scratch.join(CHANNEL_FILE).exists());
    // The alternative status label is not available: the custodian REJECTS a
    // `partial` whose counters say observed == expected.
    let forged = br#"{"schema":"private-custodian.worker-result/1","domain":"pii","protocol":{"name":"pii-v1","version":"2"},"status":"partial","roster":{"expected":3,"observed":3,"failed":3}}"#;
    assert_eq!(
        validate_result(forged, Domain::Pii, &pii_protocol(), 3).err(),
        Some(Reason::RosterMismatch)
    );
}

/// What the custodian itself would have caught before the run.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Defence {
    /// A file the plan pins (engine, adapter, candidate, config, scanner-N): the
    /// custodian's identity check rejects the drift BEFORE the run
    /// (`Rejected`, `identity_mismatch`). The engine's refusal is defence in depth.
    PinnedFile,
    /// The shape of `/input` (an extra or non-regular entry): the custodian's
    /// `verify_input_shape` fails the staging. Defence in depth likewise.
    InputShape,
    /// Content the custodian does not look at (the job document; the entries are
    /// opaque to it): only the engine can refuse these.
    EngineOnly,
}

/// The ENGINE's defence in depth. Every case below mutates something after the
/// plan pinned the staged world; for pinned files and the input shape the
/// custodian (replica) would reject or fail it BEFORE the worker starts, and the
/// test asserts that too. What the engine adds is that, were the mutation to
/// reach it anyway, it refuses with a non-zero exit and prints nothing, which the
/// custodian maps to `Failed` (`non_zero_exit`) and never parses.
#[test]
fn the_engines_refusals_are_defence_in_depth_and_a_failed_outcome_when_they_are_reached() {
    let node = node_or_return!();
    let mut cases: Vec<(&str, Defence, Mutation)> = Vec::new();
    cases.push((
        "job roster",
        Defence::EngineOnly,
        Box::new(|w| w.set_job(&job_json(&w.entries).replace("\"roster\":3", "\"roster\":4"))),
    ));
    cases.push((
        "job unknown field",
        Defence::EngineOnly,
        Box::new(|w| w.set_job(&job_json(&w.entries).replacen('}', ",\"x\":1}", 1))),
    ));
    cases.push((
        "stale entries",
        Defence::InputShape,
        Box::new(|w| std::fs::write(w.input.join("extra"), b"x").unwrap()),
    ));
    cases.push((
        "bad entry",
        Defence::EngineOnly,
        Box::new(|w| {
            let p = w.input.join(&w.entries[0]);
            std::fs::remove_file(&p).unwrap();
            std::fs::write(&p, b"{}").unwrap();
        }),
    ));
    cases.push((
        "population",
        Defence::PinnedFile,
        Box::new(|w| w.edit_config(|c| c["population"]["digest"] = json!("0".repeat(64)))),
    ));
    cases.push((
        "run class",
        Defence::PinnedFile,
        Box::new(|w| w.edit_config(|c| c["runClass"] = json!("public-synthetic"))),
    ));
    cases.push((
        "engine digest",
        Defence::PinnedFile,
        Box::new(|w| w.stage_put("engine", b"another engine", 0o500)),
    ));
    cases.push((
        "bundle digest",
        Defence::PinnedFile,
        Box::new(|w| w.stage_put("candidate", b"another bundle", 0o500)),
    ));
    cases.push((
        "runtime digest",
        Defence::PinnedFile,
        Box::new(|w| w.stage_put("scanner-0", b"#!/bin/sh\nexit 0\n", 0o500)),
    ));
    for (label, defence, mutate) in cases {
        let w = World::build("wc-refusal", &node, &Opts::default());
        // The plan's pins, taken as the custodian staged the world.
        let pins = w.pins();
        mutate(&w);
        match defence {
            Defence::PinnedFile => assert!(
                !staged_identity_holds(&w.stage, &pins),
                "{label}: the custodian's identity check must fail"
            ),
            Defence::InputShape => assert!(
                !input_shape_holds(&w.input, w.entries.len()),
                "{label}: the custodian's input-shape check must fail"
            ),
            Defence::EngineOnly => {
                assert!(staged_identity_holds(&w.stage, &pins), "{label}");
                assert!(input_shape_holds(&w.input, w.entries.len()), "{label}");
            }
        }
        let rendered = pii_eval_cli::render_worker_result(w.run(&CancelToken::new()));
        assert!(rendered.stdout.is_empty(), "{label}");
        assert_ne!(rendered.exit.code(), 0, "{label}");
        let (outcome, reason, v) = map_outcome(
            i32::from(rendered.exit.code()),
            rendered.stdout.as_bytes(),
            Domain::Pii,
            &pii_protocol(),
            3,
        );
        assert_eq!(
            (outcome, reason, v.is_none()),
            (Outcome::Failed, Reason::NonZeroExit, true),
            "{label}"
        );
    }
}

#[test]
fn a_cancelled_job_is_a_failed_outcome_for_the_custodian() {
    let node = node_or_return!();
    let w = World::build("wc-cancel", &node, &Opts::default());
    let token = CancelToken::new();
    token.cancel();
    let d = dispatch(&w, &token, 3);
    assert_eq!(
        (d.exit, d.outcome, d.reason),
        (8, Outcome::Failed, Reason::NonZeroExit)
    );
    assert!(d.stdout.is_empty());
}

#[test]
fn a_staged_file_changed_after_the_run_is_rejected_whatever_the_worker_printed() {
    let node = node_or_return!();
    let w = World::build("wc-drift", &node, &Opts::default());
    let pins = w.pins();
    let rendered = pii_eval_cli::render_worker_result(w.run(&CancelToken::new()));
    assert_eq!(rendered.exit.code(), 0);
    // A hostile engine would rewrite a staged artifact; the custodian's second
    // hash catches it.
    w.stage_put("scanner-0", b"#!/bin/sh\necho changed\n", 0o500);
    assert!(!staged_identity_holds(&w.stage, &pins));
}

#[test]
fn forged_results_are_rejected_not_parsed_into_a_measurement() {
    let p = pii_protocol();
    let good = br#"{"schema":"private-custodian.worker-result/1","domain":"pii","protocol":{"name":"pii-v1","version":"2"},"status":"complete","roster":{"expected":3,"observed":3,"failed":0}}"#;
    assert_eq!(map_outcome(0, good, Domain::Pii, &p, 3).0, Outcome::Success);
    // Exit 0 with another roster than the authorized one, with free text, and
    // with a non-zero exit (never parsed).
    let other = String::from_utf8(good.to_vec())
        .unwrap()
        .replace("\"expected\":3", "\"expected\":4");
    assert_eq!(
        map_outcome(0, other.as_bytes(), Domain::Pii, &p, 3).0,
        Outcome::Rejected
    );
    let text = String::from_utf8(good.to_vec())
        .unwrap()
        .replacen('{', "{\"note\":\"secret\",", 1);
    assert_eq!(
        map_outcome(0, text.as_bytes(), Domain::Pii, &p, 3).0,
        Outcome::Rejected
    );
    assert_eq!(map_outcome(3, good, Domain::Pii, &p, 3).0, Outcome::Failed);
}

#[test]
fn the_replica_maps_signal_exit_codes_and_the_two_kinds_of_staging_drift() {
    let p = pii_protocol();
    let good = br#"{"schema":"private-custodian.worker-result/1","domain":"pii","protocol":{"name":"pii-v1","version":"2"},"status":"complete","roster":{"expected":3,"observed":3,"failed":0}}"#;
    // bwrap.rs run: 128 + signal is a signal death; 128 and 193 are plain exits.
    for (code, reason) in [
        (129, Reason::Signaled),
        (137, Reason::Signaled),
        (192, Reason::Signaled),
        (128, Reason::NonZeroExit),
        (193, Reason::NonZeroExit),
        (1, Reason::NonZeroExit),
    ] {
        let (outcome, r, v) = map_outcome(code, good, Domain::Pii, &p, 3);
        assert_eq!(
            (outcome, r, v.is_none()),
            (Outcome::Failed, reason, true),
            "{code}"
        );
    }
    // A source or staged copy that differs from the plan's pin is
    // `identity_mismatch`; a staged copy that drifts AFTER staging is its own
    // reason. Both are Rejected (dispatcher.rs `pins` and `staging.verify`).
    assert_eq!(Reason::IdentityMismatch.as_str(), "identity_mismatch");
    assert_eq!(
        Reason::IdentityChangedAfterStaging.as_str(),
        "identity_changed_after_staging"
    );
    assert_ne!(
        Reason::IdentityMismatch.as_str(),
        Reason::IdentityChangedAfterStaging.as_str()
    );
}
