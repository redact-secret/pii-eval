//! Forged, replayed, unauthorized, cross-repository, stale, oversized and
//! malformed deliveries. Synthetic data, no network. Every rejection must carry
//! a stable reason code, leave no job behind and make no upstream call.

use pii_eval_app::policy::Limits;
use pii_eval_app::reason::{Decision, Disposition, Outcome, Reason};
use pii_eval_app::request::{JobId, Subject};
use pii_eval_app::testing::*;
use pii_eval_app::webhook::RawDelivery;

fn rejected(d: &Decision) -> Reason {
    match &d.outcome {
        Outcome::Rejected(r) => *r,
        other => panic!("expected a rejection, got {other:?}"),
    }
}

fn ignored(d: &Decision) -> Reason {
    match &d.outcome {
        Outcome::Ignored(r) => *r,
        other => panic!("expected ignored, got {other:?}"),
    }
}

fn job_id(d: &Decision) -> JobId {
    match &d.outcome {
        Outcome::Accepted { job_id, .. } => job_id.clone(),
        other => panic!("expected accepted, got {other:?}"),
    }
}

fn no_side_effects(env: &TestEnv) {
    assert_eq!(env.heads.calls(), 0, "no upstream lookup");
    assert_eq!(env.app.queue_len(), 0, "nothing queued");
    assert_eq!(env.runner.calls(), 0);
    assert!(env.checks.runs().is_empty());
    assert!(env.custodian.submissions().is_empty());
}

fn good_body() -> Vec<u8> {
    comment_payload(INSTALLATION, REPO, REPO_NAME, ACTOR, PR, "/pii-eval run")
}

#[test]
fn a_correct_delivery_is_accepted_and_only_queued() {
    let env = TestEnv::new();
    let d = env.comment("/pii-eval run");
    assert!(matches!(
        d.outcome,
        Outcome::Accepted {
            disposition: Disposition::Queued,
            ..
        }
    ));
    assert_eq!(d.outcome.http_status(), 202);
    assert_eq!(env.app.queue_len(), 1);
    // The handler thread never ran the job.
    assert_eq!(env.runner.calls(), 0);
    assert!(env.checks.runs().is_empty());
}

#[test]
fn forged_signatures_are_rejected_before_anything_is_read() {
    let env = TestEnv::new();
    let body = good_body();
    let cases: Vec<(Option<String>, Reason)> = vec![
        (None, Reason::SignatureMissing),
        (Some(String::new()), Reason::SignatureMalformed),
        (Some("sha256=".into()), Reason::SignatureMalformed),
        (Some("sha256=zz".into()), Reason::SignatureMalformed),
        (
            Some(sign(SECRET, &body)[7..].to_owned()),
            Reason::SignatureMalformed,
        ),
        (
            Some(sign(SECRET, &body).replace("sha256=", "sha1=")),
            Reason::SignatureMalformed,
        ),
        (
            Some(sign(SECRET, &body).to_uppercase()),
            Reason::SignatureMalformed,
        ),
        (
            Some(sign(b"another-secret-another-secret-another-secret", &body)),
            Reason::SignatureMismatch,
        ),
        (Some(sign(SECRET, b"{}")), Reason::SignatureMismatch),
        (
            Some(format!("sha256={}", "0".repeat(64))),
            Reason::SignatureMismatch,
        ),
    ];
    for (i, (sig, expected)) in cases.iter().enumerate() {
        let d = env.app.handle_delivery(&RawDelivery {
            event: Some("issue_comment"),
            delivery_id: Some("forged-delivery"),
            signature: sig.as_deref(),
            body: &body,
        });
        assert_eq!(rejected(&d), *expected, "case {i}");
        assert_eq!(d.outcome.http_status(), 401);
        assert_eq!(
            d.meta,
            Default::default(),
            "no metadata before authenticity"
        );
    }
    // A tampered body under a signature of the original body.
    let sig = sign(SECRET, &body);
    let mut tampered = body.clone();
    tampered[10] ^= 1;
    let d = env.app.handle_delivery(&RawDelivery {
        event: Some("issue_comment"),
        delivery_id: Some("forged-delivery"),
        signature: Some(&sig),
        body: &tampered,
    });
    assert_eq!(rejected(&d), Reason::SignatureMismatch);
    no_side_effects(&env);
    // Forgeries did not consume the delivery id: the genuine delivery with the
    // same id is accepted.
    let d = env.deliver_with_id("issue_comment", "forged-delivery", &body);
    assert!(matches!(d.outcome, Outcome::Accepted { .. }));
}

#[test]
fn a_replayed_delivery_is_rejected_and_adds_nothing() {
    let env = TestEnv::new();
    let body = good_body();
    let first = env.deliver_with_id("issue_comment", "same-id", &body);
    let id = job_id(&first);
    let again = env.deliver_with_id("issue_comment", "same-id", &body);
    assert_eq!(rejected(&again), Reason::DuplicateDelivery);
    assert_eq!(again.outcome.http_status(), 409);
    assert_eq!(env.app.queue_len(), 1);
    assert!(env.app.job(&id).is_some());
    // Past the id TTL (and the comment window) the same body is refused by the
    // comment age rule, not by the id store.
    env.clock.advance(Limits::default().delivery_ttl.as_secs());
    let later = env.deliver_with_id("issue_comment", "same-id", &body);
    assert_eq!(rejected(&later), Reason::CommentTooOld);
    // A genuinely new comment for the same identity coalesces into the same job.
    let fresh = env.deliver(
        "issue_comment",
        &comment_payload_full(
            INSTALLATION,
            REPO,
            REPO_NAME,
            ACTOR,
            PR,
            "/pii-eval run",
            777_001,
            BASE_TIME + Limits::default().delivery_ttl.as_secs(),
        ),
    );
    assert_eq!(
        fresh.outcome,
        Outcome::Accepted {
            job_id: id,
            disposition: Disposition::Coalesced
        }
    );
    assert_eq!(env.app.queue_len(), 1);
}

#[test]
fn delivery_headers_are_validated() {
    let env = TestEnv::new();
    let body = good_body();
    let sig = sign(SECRET, &body);
    for id in [None, Some(""), Some("has space"), Some("semi;colon")] {
        let d = env.app.handle_delivery(&RawDelivery {
            event: Some("issue_comment"),
            delivery_id: id,
            signature: Some(&sig),
            body: &body,
        });
        assert_eq!(rejected(&d), Reason::DeliveryIdInvalid, "{id:?}");
    }
    let long = "a".repeat(65);
    let d = env.app.handle_delivery(&RawDelivery {
        event: Some("issue_comment"),
        delivery_id: Some(&long),
        signature: Some(&sig),
        body: &body,
    });
    assert_eq!(rejected(&d), Reason::DeliveryIdInvalid);
    for event in [None, Some(""), Some("Issue_Comment"), Some("a b")] {
        let d = env.app.handle_delivery(&RawDelivery {
            event,
            delivery_id: Some("ok-id"),
            signature: Some(&sig),
            body: &body,
        });
        assert_eq!(rejected(&d), Reason::EventInvalid, "{event:?}");
    }
    no_side_effects(&env);
}

#[test]
fn unauthorized_actors_installations_and_repositories_are_rejected() {
    let env = TestEnv::new();
    let cmd = "/pii-eval run";
    // Actor not on the repository's allowlist (including the other repository's actor).
    for actor in [9999, OTHER_ACTOR, 1] {
        let d = env.deliver(
            "issue_comment",
            &comment_payload(INSTALLATION, REPO, REPO_NAME, actor, PR, cmd),
        );
        assert_eq!(rejected(&d), Reason::ActorNotAuthorized);
        assert_eq!(d.outcome.http_status(), 403);
    }
    // Unknown installation.
    let d = env.deliver(
        "issue_comment",
        &comment_payload(999, REPO, REPO_NAME, ACTOR, PR, cmd),
    );
    assert_eq!(rejected(&d), Reason::InstallationNotAllowlisted);
    // Unknown repository in a known installation.
    let d = env.deliver(
        "issue_comment",
        &comment_payload(INSTALLATION, 12345, "example/unknown", ACTOR, PR, cmd),
    );
    assert_eq!(rejected(&d), Reason::RepositoryNotAllowlisted);
    // The repository's id is the authority; a renamed or spoofed name is refused.
    let d = env.deliver(
        "issue_comment",
        &comment_payload(INSTALLATION, REPO, "example/renamed", ACTOR, PR, cmd),
    );
    assert_eq!(rejected(&d), Reason::RepositoryNameMismatch);
    // Name case differences are not a mismatch.
    let d = env.deliver(
        "issue_comment",
        &comment_payload(INSTALLATION, REPO, "Example/Repo", ACTOR, PR, cmd),
    );
    assert!(matches!(d.outcome, Outcome::Accepted { .. }));
    // Another actor's author_association in the payload does not matter: it is
    // never read.
    assert_eq!(env.app.queue_len(), 1);
}

#[test]
fn cross_repository_confusion_is_rejected_in_both_directions() {
    let env = TestEnv::new();
    let cmd = "/pii-eval run";
    // Installation of repository A used with repository B (and the reverse),
    // with the actor of the repository that is named.
    let d = env.deliver(
        "issue_comment",
        &comment_payload(OTHER_INSTALLATION, REPO, REPO_NAME, ACTOR, PR, cmd),
    );
    assert_eq!(rejected(&d), Reason::InstallationRepositoryMismatch);
    let d = env.deliver(
        "issue_comment",
        &comment_payload(
            INSTALLATION,
            OTHER_REPO,
            "example/other",
            OTHER_ACTOR,
            PR,
            cmd,
        ),
    );
    assert_eq!(rejected(&d), Reason::InstallationRepositoryMismatch);
    // Same for the Check events.
    let head = sha('1');
    let d = env.deliver(
        "check_suite",
        &suite_payload(
            "rerequested",
            OTHER_INSTALLATION,
            REPO,
            REPO_NAME,
            ACTOR,
            &head,
            Some(PR),
        ),
    );
    assert_eq!(rejected(&d), Reason::InstallationRepositoryMismatch);
    let d = env.deliver(
        "check_run",
        &run_payload(
            "rerequested",
            INSTALLATION,
            OTHER_REPO,
            "example/other",
            OTHER_ACTOR,
            &head,
            Some(PR),
            None,
        ),
    );
    assert_eq!(rejected(&d), Reason::InstallationRepositoryMismatch);
    no_side_effects(&env);
}

#[test]
fn a_comment_or_label_alone_grants_nothing() {
    let env = TestEnv::new();
    // Comments that are not commands are ignored without any lookup.
    for text in [
        "please run pii-eval",
        "  /pii-eval run",
        "> /pii-eval run",
        "run /pii-eval run",
        "",
    ] {
        let d = env.comment(text);
        assert_eq!(ignored(&d), Reason::NotACommand, "{text:?}");
        assert_eq!(d.outcome.http_status(), 200);
    }
    // A malformed command from an authorized actor is rejected, from an
    // unauthorized actor it is not even looked at (authorization first).
    assert_eq!(
        rejected(&env.comment("/pii-eval runx")),
        Reason::CommandMalformed
    );
    let d = env.deliver(
        "issue_comment",
        &comment_payload(INSTALLATION, REPO, REPO_NAME, 9999, PR, "/pii-eval runx"),
    );
    assert_eq!(rejected(&d), Reason::ActorNotAuthorized);
    // A label on a pull request, a push, a ping and a workflow dispatch are
    // authentic events that this service does not subscribe to.
    for event in [
        "pull_request",
        "push",
        "ping",
        "workflow_dispatch",
        "issues",
    ] {
        let body = br#"{"action":"labeled","label":{"name":"pii-eval"},"installation":{"id":7}}"#;
        let d = env.deliver(event, body);
        assert_eq!(ignored(&d), Reason::EventNotApproved, "{event}");
    }
    // An edited comment is not a request; a comment on a plain issue is not either.
    let mut v: serde_json::Value =
        serde_json::from_slice(&good_body()).expect("the builder emits JSON");
    v["action"] = "edited".into();
    assert_eq!(
        ignored(&env.deliver("issue_comment", v.to_string().as_bytes())),
        Reason::ActionNotApproved
    );
    let mut v: serde_json::Value = serde_json::from_slice(&good_body()).unwrap();
    v["issue"].as_object_mut().unwrap().remove("pull_request");
    assert_eq!(
        ignored(&env.deliver("issue_comment", v.to_string().as_bytes())),
        Reason::NotAPullRequest
    );
    // check_suite and check_run actions other than rerequested.
    let head = sha('1');
    for action in ["requested", "completed", "created"] {
        let d = env.deliver(
            "check_suite",
            &suite_payload(
                action,
                INSTALLATION,
                REPO,
                REPO_NAME,
                ACTOR,
                &head,
                Some(PR),
            ),
        );
        assert_eq!(ignored(&d), Reason::ActionNotApproved);
    }
    // A comment's claimed user must be the sender.
    let mut v: serde_json::Value = serde_json::from_slice(&good_body()).unwrap();
    v["comment"]["user"]["id"] = 7.into();
    assert_eq!(
        rejected(&env.deliver("issue_comment", v.to_string().as_bytes())),
        Reason::PayloadMalformed
    );
    no_side_effects(&env);
}

#[test]
fn oversized_payloads_are_rejected_before_the_hmac() {
    let limits = Limits {
        max_body_bytes: 1024,
        ..Limits::default()
    };
    let env = TestEnv::build(limits, FakeRunner::complete());
    let big = vec![b' '; 1025];
    // Even with a perfectly valid signature, and with a bad one: the size cap
    // answers first, so a flood of large bodies costs no hashing.
    for sig in [sign(SECRET, &big), "sha256=bad".to_owned()] {
        let d = env.app.handle_delivery(&RawDelivery {
            event: Some("issue_comment"),
            delivery_id: Some("big"),
            signature: Some(&sig),
            body: &big,
        });
        assert_eq!(rejected(&d), Reason::PayloadTooLarge);
        assert_eq!(d.outcome.http_status(), 413);
    }
    // Exactly at the cap is accepted for processing (and is then malformed JSON).
    let at_cap = vec![b' '; 1024];
    let d = env.deliver("issue_comment", &at_cap);
    assert_eq!(rejected(&d), Reason::PayloadMalformed);
    no_side_effects(&env);
}

#[test]
fn malformed_json_is_rejected_with_a_fixed_reason() {
    let env = TestEnv::new();
    let valid = String::from_utf8(good_body()).unwrap();
    let mut docs: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"not json".to_vec(),
        b"[]".to_vec(),
        b"null".to_vec(),
        b"{}".to_vec(),
        b"\xff\xfe\x00".to_vec(),
        format!("{valid} trailing").into_bytes(),
        valid.replace("\"id\":7", "\"id\":\"7\"").into_bytes(),
        valid.replace("\"id\":7", "\"id\":-7").into_bytes(),
        valid.replace("\"id\":7", "\"id\":1.5").into_bytes(),
        valid
            .replace("\"id\":7", "\"id\":18446744073709551616")
            .into_bytes(),
        valid
            .replace("\"installation\":{\"id\":7}", "\"installation\":null")
            .into_bytes(),
        valid
            .replace(
                "\"installation\":{\"id\":7}",
                "\"installation\":{\"id\":7,\"id\":8}",
            )
            .into_bytes(),
        valid
            .replace("\"number\":5", "\"number\":\"x\"")
            .into_bytes(),
        valid.replace("\"id\":7", "\"id\":0").into_bytes(),
    ];
    // A lone surrogate escape inside a field the service does not read.
    docs.push(valid.replacen('{', "{\"x\":\"\\ud800\",", 1).into_bytes());
    // Deep nesting is bounded by the parser.
    docs.push(format!("{}{}", "[".repeat(100_000), "]".repeat(100_000)).into_bytes());
    docs.push(format!("{{\"a\":{}1{}}}", "[".repeat(10_000), "]".repeat(10_000)).into_bytes());
    for (i, body) in docs.iter().enumerate() {
        let d = env.deliver("issue_comment", body);
        assert_eq!(rejected(&d), Reason::PayloadMalformed, "case {i}");
        assert_eq!(d.outcome.http_status(), 400);
    }
    // A bad head commit in a Check event.
    let mut v: serde_json::Value = serde_json::from_slice(&suite_payload(
        "rerequested",
        INSTALLATION,
        REPO,
        REPO_NAME,
        ACTOR,
        &sha('1'),
        Some(PR),
    ))
    .unwrap();
    v["check_suite"]["head_sha"] = "NOT-A-SHA".into();
    assert_eq!(
        rejected(&env.deliver("check_suite", v.to_string().as_bytes())),
        Reason::PayloadMalformed
    );
    no_side_effects(&env);
}

#[test]
fn stale_head_requests_and_fork_heads_are_rejected() {
    let env = TestEnv::new();
    // The suite names a commit that is no longer the head.
    let old = sha('9');
    let d = env.deliver(
        "check_suite",
        &suite_payload(
            "rerequested",
            INSTALLATION,
            REPO,
            REPO_NAME,
            ACTOR,
            &old,
            Some(PR),
        ),
    );
    assert_eq!(rejected(&d), Reason::StaleHead);
    let d = env.deliver(
        "check_run",
        &run_payload(
            "rerequested",
            INSTALLATION,
            REPO,
            REPO_NAME,
            ACTOR,
            &old,
            Some(PR),
            None,
        ),
    );
    assert_eq!(rejected(&d), Reason::StaleHead);
    // The current head is accepted.
    let d = env.deliver(
        "check_suite",
        &suite_payload(
            "rerequested",
            INSTALLATION,
            REPO,
            REPO_NAME,
            ACTOR,
            &sha('1'),
            Some(PR),
        ),
    );
    assert!(matches!(d.outcome, Outcome::Accepted { .. }));
    // A pull request whose head lives in another repository.
    env.heads
        .set(REPO, Subject::PullRequest(77), &sha('7'), 424242);
    let d = env.deliver(
        "issue_comment",
        &comment_payload(INSTALLATION, REPO, REPO_NAME, ACTOR, 77, "/pii-eval run"),
    );
    assert_eq!(rejected(&d), Reason::ForkHeadNotAllowed);
}

#[test]
fn profiles_must_be_allowlisted_for_the_repository() {
    let env = TestEnv::new();
    assert_eq!(
        rejected(&env.comment("/pii-eval run no-such-profile")),
        Reason::ProfileNotAllowed
    );
    // Repository B only has the default profile.
    env.heads
        .set(OTHER_REPO, Subject::PullRequest(PR), &sha('2'), OTHER_REPO);
    let d = env.deliver(
        "issue_comment",
        &comment_payload(
            OTHER_INSTALLATION,
            OTHER_REPO,
            "example/other",
            OTHER_ACTOR,
            PR,
            "/pii-eval run public-alt",
        ),
    );
    assert_eq!(rejected(&d), Reason::ProfileNotAllowed);
}

#[test]
fn an_unresolvable_head_is_transient_and_does_not_consume_the_delivery() {
    let env = TestEnv::new();
    let body = good_body();
    env.heads.set_failing(true);
    let d = env.deliver_with_id("issue_comment", "redelivered", &body);
    assert_eq!(rejected(&d), Reason::HeadUnresolvable);
    assert_eq!(d.outcome.http_status(), 503);
    assert_eq!(env.app.queue_len(), 0);
    env.heads.set_failing(false);
    // GitHub redelivers with the same id: it is processed, not a duplicate.
    let d = env.deliver_with_id("issue_comment", "redelivered", &body);
    assert!(matches!(d.outcome, Outcome::Accepted { .. }), "{d:?}");
    // A permanent rejection is re-evaluated, not remembered: ids are recorded
    // only for admitted requests, so rejected traffic cannot fill the store.
    let denied = comment_payload(INSTALLATION, REPO, REPO_NAME, 9999, PR, "/pii-eval run");
    for _ in 0..2 {
        let d = env.deliver_with_id("issue_comment", "denied", &denied);
        assert_eq!(rejected(&d), Reason::ActorNotAuthorized);
    }
}

#[test]
fn metadata_is_bounded_and_secrets_never_appear_in_debug_output() {
    let env = TestEnv::new();
    let d = env.comment("/pii-eval run\nSENTINEL-comment-text-should-never-be-echoed");
    let text = format!("{d:?} {:?} {:?}", env.app, d.meta);
    let secret = String::from_utf8_lossy(SECRET).into_owned();
    assert!(!text.contains(&secret));
    assert!(!text.contains("SENTINEL"));
    assert!(d.meta.delivery_id.as_deref().is_some_and(|s| s.len() <= 64));
    // Rejections never carry payload text either.
    let bad = env.comment("/pii-eval run SENTINEL-profile-text");
    let text = format!("{bad:?}");
    assert!(!text.contains("SENTINEL"));
    let raw = RawDelivery {
        event: Some("issue_comment"),
        delivery_id: Some("x"),
        signature: Some("sha256=SENTINEL"),
        body: b"SENTINEL",
    };
    assert!(!format!("{raw:?}").contains("SENTINEL"));
}

#[test]
fn a_captured_comment_replayed_under_fresh_delivery_ids_starts_nothing() {
    let env = TestEnv::new();
    let body = good_body();
    let first = env.deliver("issue_comment", &body);
    let id = job_id(&first);
    // The delivery id is not signed, so a replayer picks new ones. The comment
    // id is the key: one comment is one request.
    for n in 0..25 {
        let d = env.deliver_with_id("issue_comment", &format!("fresh-{n}"), &body);
        assert_eq!(rejected(&d), Reason::DuplicateComment, "replay {n}");
        assert_eq!(d.outcome.http_status(), 409);
    }
    // Even after a new commit lands (a replay would otherwise resolve to the
    // new head and start a job per commit).
    env.heads
        .set(REPO, Subject::PullRequest(PR), &sha('4'), REPO);
    let d = env.deliver_with_id("issue_comment", "fresh-after-push", &body);
    assert_eq!(rejected(&d), Reason::DuplicateComment);
    assert_eq!(env.app.queue_len(), 1, "still the one job");
    assert!(env.app.job(&id).is_some());
    // The same comment id in another repository is another request.
    assert_ne!(
        format!("{}:{}", REPO, 1),
        format!("{}:{}", OTHER_REPO, 1),
        "keys include the repository"
    );
}

#[test]
fn a_comment_outside_the_age_window_is_refused_with_bounded_skew() {
    let env = TestEnv::new();
    let l = Limits::default();
    let (max_age, skew) = (l.comment_max_age.as_secs(), l.clock_skew.as_secs());
    let at = |created: u64, id: u64| {
        env.deliver(
            "issue_comment",
            &comment_payload_full(
                INSTALLATION,
                REPO,
                REPO_NAME,
                ACTOR,
                PR,
                "/pii-eval run",
                id,
                created,
            ),
        )
    };
    assert_eq!(
        rejected(&at(BASE_TIME - max_age - 1, 1)),
        Reason::CommentTooOld
    );
    assert!(matches!(
        at(BASE_TIME - max_age, 2).outcome,
        Outcome::Accepted { .. }
    ));
    assert_eq!(
        rejected(&at(BASE_TIME + skew + 1, 3)),
        Reason::PayloadMalformed
    );
    assert!(matches!(
        at(BASE_TIME + skew, 4).outcome,
        Outcome::Accepted { .. }
    ));
    // A timestamp that does not parse is malformed.
    let mut v: serde_json::Value = serde_json::from_slice(&good_body()).unwrap();
    v["comment"]["created_at"] = "yesterday".into();
    assert_eq!(
        rejected(&env.deliver("issue_comment", v.to_string().as_bytes())),
        Reason::PayloadMalformed
    );
}

#[test]
fn floods_under_distinct_delivery_ids_cannot_evict_recent_legitimate_ids() {
    let limits = Limits {
        delivery_capacity: 8,
        ..Limits::default()
    };
    let env = TestEnv::build(limits, FakeRunner::complete());
    let body = good_body();
    assert!(matches!(
        env.deliver_with_id("issue_comment", "legit", &body).outcome,
        Outcome::Accepted { .. }
    ));
    // A replayer with a captured body, and an unauthorized-but-validly-signed
    // sender, each try to push "legit" out of an 8-entry store.
    let denied = comment_payload(INSTALLATION, REPO, REPO_NAME, 9999, PR, "/pii-eval run");
    for n in 0..100 {
        let d = env.deliver_with_id("issue_comment", &format!("flood-a-{n}"), &body);
        assert_eq!(rejected(&d), Reason::DuplicateComment);
        let d = env.deliver_with_id("issue_comment", &format!("flood-b-{n}"), &denied);
        assert_eq!(rejected(&d), Reason::ActorNotAuthorized);
    }
    let d = env.deliver_with_id("issue_comment", "legit", &body);
    assert_eq!(
        rejected(&d),
        Reason::DuplicateDelivery,
        "the id survived the floods"
    );
}
