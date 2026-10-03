//! Fixed-seed property tests of the delivery path: random bytes, every prefix
//! of a valid payload, single-byte mutations and random header values must
//! never panic and never be accepted unless they are a complete valid request.
//! (The seeds are fixed so a failure names its iteration; no `proptest`.)

use pii_eval_app::reason::{Outcome, Reason};
use pii_eval_app::testing::*;
use pii_eval_app::webhook::RawDelivery;

struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn valid() -> Vec<u8> {
    comment_payload(INSTALLATION, REPO, REPO_NAME, ACTOR, PR, "/pii-eval run")
}

#[test]
fn random_signed_bytes_are_never_accepted() {
    let env = TestEnv::new();
    let mut rng = SplitMix64(0x5eed_0001);
    for i in 0..3000 {
        let len = rng.below(400);
        let body: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        let d = env.deliver("issue_comment", &body);
        assert!(
            matches!(d.outcome, Outcome::Rejected(Reason::PayloadMalformed)),
            "iteration {i}: {:?}",
            d.outcome
        );
    }
    assert_eq!(env.app.queue_len(), 0);
}

#[test]
fn every_proper_prefix_of_a_valid_payload_is_malformed() {
    let env = TestEnv::new();
    let body = valid();
    for n in 0..body.len() {
        let d = env.deliver("issue_comment", &body[..n]);
        assert!(
            matches!(d.outcome, Outcome::Rejected(Reason::PayloadMalformed)),
            "prefix {n}: {:?}",
            d.outcome
        );
    }
    assert!(matches!(
        env.deliver("issue_comment", &body).outcome,
        Outcome::Accepted { .. }
    ));
}

#[test]
fn single_byte_mutations_never_panic_and_never_widen_authorization() {
    let env = TestEnv::new();
    let body = valid();
    let mut rng = SplitMix64(0x5eed_0002);
    for i in 0..4000 {
        let mut m = body.clone();
        let at = rng.below(m.len());
        m[at] = rng.next() as u8;
        let d = env.deliver("issue_comment", &m);
        match d.outcome {
            // A mutation may still be a valid request, but never for another
            // installation, repository or actor than the allowlist names.
            Outcome::Accepted { .. } => {
                let doc: serde_json::Value =
                    serde_json::from_slice(&m).expect("accepted bodies are JSON");
                assert_eq!(doc["installation"]["id"], INSTALLATION, "iteration {i}");
                assert_eq!(doc["repository"]["id"], REPO, "iteration {i}");
                assert_eq!(doc["sender"]["id"], ACTOR, "iteration {i}");
            }
            Outcome::Rejected(_) | Outcome::Ignored(_) => {}
        }
    }
}

#[test]
fn random_header_values_never_authenticate() {
    let env = TestEnv::new();
    let body = valid();
    let mut rng = SplitMix64(0x5eed_0003);
    for i in 0..3000 {
        let sig: String = (0..rng.below(90))
            .map(|_| char::from(0x20 + rng.below(95) as u8))
            .collect();
        let d = env.app.handle_delivery(&RawDelivery {
            event: Some("issue_comment"),
            delivery_id: Some("fuzz"),
            signature: Some(&sig),
            body: &body,
        });
        assert!(
            matches!(
                d.outcome,
                Outcome::Rejected(
                    Reason::SignatureMalformed
                        | Reason::SignatureMismatch
                        | Reason::SignatureMissing
                )
            ),
            "iteration {i}"
        );
    }
    assert_eq!(env.heads.calls(), 0);
}
