//! Webhook authenticity and strict parsing.
//!
//! Order (each step must pass before the next runs, ADR 0011 D5): body size cap,
//! `X-Hub-Signature-256` over the exact raw bytes with a constant-time compare,
//! delivery id syntax, event name, and only then JSON parsing into typed
//! structures that name just the fields the service uses. Nothing is parsed,
//! logged or echoed from a body whose signature has not verified.

use std::fmt;

use serde::Deserialize;
use serde::de::IgnoredAny;

use crate::hmac::{constant_time_eq, hmac_sha256, unhex};
use crate::reason::Reason;
use crate::request::{CommandParse, CommitSha, EventKind, parse_command};
use crate::secret::Secret;

/// One delivery as the transport saw it. Header values are `None` when absent
/// or not UTF-8.
pub struct RawDelivery<'a> {
    /// `X-GitHub-Event`.
    pub event: Option<&'a str>,
    /// `X-GitHub-Delivery`.
    pub delivery_id: Option<&'a str>,
    /// `X-Hub-Signature-256`.
    pub signature: Option<&'a str>,
    /// The exact bytes of the request body.
    pub body: &'a [u8],
}

impl fmt::Debug for RawDelivery<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The body and the signature are never printed.
        f.debug_struct("RawDelivery")
            .field("body_len", &self.body.len())
            .field("has_signature", &self.signature.is_some())
            .finish_non_exhaustive()
    }
}

/// Verify `sha256=<hex>` against the HMAC-SHA256 of `body` under `secret`.
pub fn verify_signature(secret: &Secret, header: Option<&str>, body: &[u8]) -> Result<(), Reason> {
    let header = header.ok_or(Reason::SignatureMissing)?;
    let hex = header
        .strip_prefix("sha256=")
        .ok_or(Reason::SignatureMalformed)?;
    let presented: [u8; 32] = unhex(hex).ok_or(Reason::SignatureMalformed)?;
    let expected = hmac_sha256(secret.expose(), body);
    if constant_time_eq(&expected, &presented) {
        Ok(())
    } else {
        Err(Reason::SignatureMismatch)
    }
}

/// A delivery id: 1 to 64 characters of `[0-9A-Za-z-]`.
pub fn valid_delivery_id(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// The event name class of a delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventClass {
    /// One of the approved events.
    Approved(EventKind),
    /// A well-formed name that this service does not subscribe to
    /// (`pull_request` with a label, `ping`, `workflow_dispatch`, ...).
    Other,
}

/// Classify the `X-GitHub-Event` value; a malformed name is an error.
pub fn classify_event(name: Option<&str>) -> Result<EventClass, Reason> {
    let name = name.ok_or(Reason::EventInvalid)?;
    if name.is_empty()
        || name.len() > 40
        || !name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
    {
        return Err(Reason::EventInvalid);
    }
    Ok(match name {
        "issue_comment" => EventClass::Approved(EventKind::IssueComment),
        "check_suite" => EventClass::Approved(EventKind::CheckSuite),
        "check_run" => EventClass::Approved(EventKind::CheckRun),
        _ => EventClass::Other,
    })
}

/// What a verified payload asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Trigger {
    /// A command comment on a pull request.
    Comment {
        /// The pull request number.
        pr_number: u64,
        /// The parsed command (`Run`; other values are filtered earlier).
        command: CommandParse,
    },
    /// A rerequested check suite.
    Suite {
        /// The suite's head commit.
        head_sha: CommitSha,
        /// Its branch, when present.
        head_branch: Option<String>,
        /// The first associated pull request number, when present.
        pr_number: Option<u64>,
    },
    /// A rerequested check run.
    Run {
        /// The run's head commit.
        head_sha: CommitSha,
        /// Our own `external_id` (a job id) when present.
        external_id: Option<String>,
        /// Branch of its suite, when present.
        head_branch: Option<String>,
        /// The first associated pull request number, when present.
        pr_number: Option<u64>,
    },
}

/// The fields of an approved payload the service uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedEvent {
    /// Which event.
    pub kind: EventKind,
    /// Installation id.
    pub installation_id: u64,
    /// Repository id.
    pub repository_id: u64,
    /// Repository full name.
    pub repository_name: String,
    /// The user who triggered it.
    pub sender_id: u64,
    /// The request.
    pub trigger: Trigger,
}

/// Parse result: an event, or an authentic payload that is not a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Parsed {
    /// A request to authorize.
    Event(Box<ParsedEvent>),
    /// Harmless and not for us.
    Ignored(Reason),
}

#[derive(Deserialize)]
struct Installation {
    id: u64,
}

#[derive(Deserialize)]
struct Repository {
    id: u64,
    full_name: String,
}

#[derive(Deserialize)]
struct User {
    id: u64,
}

#[derive(Deserialize)]
struct PullRequestRef {
    number: u64,
}

#[derive(Deserialize)]
struct IssueCommentPayload {
    action: String,
    installation: Installation,
    repository: Repository,
    sender: User,
    issue: Issue,
    comment: Comment,
}

#[derive(Deserialize)]
struct Issue {
    number: u64,
    pull_request: Option<IgnoredAny>,
}

#[derive(Deserialize)]
struct Comment {
    body: String,
    user: User,
}

#[derive(Deserialize)]
struct CheckSuitePayload {
    action: String,
    installation: Installation,
    repository: Repository,
    sender: User,
    check_suite: SuiteBody,
}

#[derive(Deserialize)]
struct SuiteBody {
    head_sha: String,
    head_branch: Option<String>,
    #[serde(default)]
    pull_requests: Vec<PullRequestRef>,
}

#[derive(Deserialize)]
struct CheckRunPayload {
    action: String,
    installation: Installation,
    repository: Repository,
    sender: User,
    check_run: RunBody,
}

#[derive(Deserialize)]
struct RunBody {
    head_sha: String,
    external_id: Option<String>,
    check_suite: Option<RunSuite>,
    #[serde(default)]
    pull_requests: Vec<PullRequestRef>,
}

#[derive(Deserialize)]
struct RunSuite {
    head_branch: Option<String>,
}

fn malformed<T>(_: T) -> Reason {
    Reason::PayloadMalformed
}

fn repo_name_ok(name: &str) -> bool {
    name.len() <= 201 && name.bytes().all(|b| (0x21..0x7f).contains(&b))
}

fn branch(value: Option<String>) -> Result<Option<String>, Reason> {
    match value {
        Some(b) if b.is_empty() || b.len() > 255 || b.chars().any(char::is_control) => {
            Err(Reason::PayloadMalformed)
        }
        other => Ok(other),
    }
}

fn external_id(value: Option<String>) -> Option<String> {
    // Only a value that could be one of our own job ids is kept.
    value.filter(|v| crate::request::JobId::parse(v).is_some())
}

/// Parse the body of an approved event into the fields the service uses.
/// `serde_json` rejects invalid UTF-8, trailing characters, duplicate keys in
/// the typed structs and nesting deeper than its recursion limit.
pub fn parse_payload(kind: EventKind, body: &[u8]) -> Result<Parsed, Reason> {
    // Skipping an unknown field does not validate its string escapes (a lone
    // surrogate passes), so the whole document is first validated as a value;
    // the typed parses below then reject duplicate keys in the fields we read.
    // The body is already capped, so the extra pass is bounded.
    serde_json::from_slice::<serde_json::Value>(body).map_err(malformed)?;
    match kind {
        EventKind::IssueComment => {
            let p: IssueCommentPayload = serde_json::from_slice(body).map_err(malformed)?;
            if p.action != "created" {
                return Ok(Parsed::Ignored(Reason::ActionNotApproved));
            }
            let command = parse_command(&p.comment.body);
            if command == CommandParse::NotACommand {
                return Ok(Parsed::Ignored(Reason::NotACommand));
            }
            if p.issue.pull_request.is_none() {
                return Ok(Parsed::Ignored(Reason::NotAPullRequest));
            }
            if p.comment.user.id != p.sender.id {
                return Err(Reason::PayloadMalformed);
            }
            finish(
                kind,
                &p.installation,
                &p.repository,
                &p.sender,
                Trigger::Comment {
                    pr_number: p.issue.number,
                    command,
                },
            )
        }
        EventKind::CheckSuite => {
            let p: CheckSuitePayload = serde_json::from_slice(body).map_err(malformed)?;
            if p.action != "rerequested" {
                return Ok(Parsed::Ignored(Reason::ActionNotApproved));
            }
            let head_sha =
                CommitSha::parse(&p.check_suite.head_sha).ok_or(Reason::PayloadMalformed)?;
            let trigger = Trigger::Suite {
                head_sha,
                head_branch: branch(p.check_suite.head_branch)?,
                pr_number: p.check_suite.pull_requests.first().map(|r| r.number),
            };
            finish(kind, &p.installation, &p.repository, &p.sender, trigger)
        }
        EventKind::CheckRun => {
            let p: CheckRunPayload = serde_json::from_slice(body).map_err(malformed)?;
            if p.action != "rerequested" {
                return Ok(Parsed::Ignored(Reason::ActionNotApproved));
            }
            let head_sha =
                CommitSha::parse(&p.check_run.head_sha).ok_or(Reason::PayloadMalformed)?;
            let trigger = Trigger::Run {
                head_sha,
                external_id: external_id(p.check_run.external_id),
                head_branch: branch(p.check_run.check_suite.and_then(|s| s.head_branch))?,
                pr_number: p.check_run.pull_requests.first().map(|r| r.number),
            };
            finish(kind, &p.installation, &p.repository, &p.sender, trigger)
        }
    }
}

fn finish(
    kind: EventKind,
    installation: &Installation,
    repository: &Repository,
    sender: &User,
    trigger: Trigger,
) -> Result<Parsed, Reason> {
    if installation.id == 0 || repository.id == 0 || sender.id == 0 {
        return Err(Reason::PayloadMalformed);
    }
    if !repo_name_ok(&repository.full_name) {
        return Err(Reason::PayloadMalformed);
    }
    Ok(Parsed::Event(Box::new(ParsedEvent {
        kind,
        installation_id: installation.id,
        repository_id: repository.id,
        repository_name: repository.full_name.clone(),
        sender_id: sender.id,
        trigger,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> Secret {
        Secret::new(b"unit-test-webhook-secret-0123456789".to_vec()).unwrap()
    }

    fn sign(body: &[u8]) -> String {
        format!(
            "sha256={}",
            crate::hmac::hex(&hmac_sha256(secret().expose(), body))
        )
    }

    #[test]
    fn signature_checks() {
        let s = secret();
        let body = br#"{"a":1}"#;
        let good = sign(body);
        assert_eq!(verify_signature(&s, Some(&good), body), Ok(()));
        assert_eq!(
            verify_signature(&s, None, body),
            Err(Reason::SignatureMissing)
        );
        assert_eq!(
            verify_signature(&s, Some(&good[7..]), body),
            Err(Reason::SignatureMalformed)
        );
        assert_eq!(
            verify_signature(&s, Some("sha1=abcd"), body),
            Err(Reason::SignatureMalformed)
        );
        assert_eq!(
            verify_signature(&s, Some(&good.to_uppercase()), body),
            Err(Reason::SignatureMalformed)
        );
        assert_eq!(
            verify_signature(&s, Some(&good), br#"{"a":2}"#),
            Err(Reason::SignatureMismatch)
        );
        let other = Secret::new(b"another-unit-test-secret-0123456789".to_vec()).unwrap();
        assert_eq!(
            verify_signature(&other, Some(&good), body),
            Err(Reason::SignatureMismatch)
        );
    }

    #[test]
    fn event_and_delivery_id_syntax() {
        assert_eq!(
            classify_event(Some("issue_comment")),
            Ok(EventClass::Approved(EventKind::IssueComment))
        );
        assert_eq!(classify_event(Some("pull_request")), Ok(EventClass::Other));
        assert_eq!(
            classify_event(Some("workflow_dispatch")),
            Ok(EventClass::Other)
        );
        assert_eq!(classify_event(None), Err(Reason::EventInvalid));
        assert_eq!(classify_event(Some("Issue")), Err(Reason::EventInvalid));
        assert_eq!(classify_event(Some("")), Err(Reason::EventInvalid));
        assert!(valid_delivery_id("72d3162e-cc78-11e3-81ab-4c9367dc0958"));
        assert!(!valid_delivery_id(""));
        assert!(!valid_delivery_id("a b"));
        assert!(!valid_delivery_id(&"a".repeat(65)));
    }

    #[test]
    fn debug_of_a_delivery_hides_body_and_signature() {
        let d = RawDelivery {
            event: Some("issue_comment"),
            delivery_id: Some("id"),
            signature: Some("sha256=SENTINEL"),
            body: b"SENTINEL-body",
        };
        let text = format!("{d:?}");
        assert!(!text.contains("SENTINEL"));
        assert!(text.contains("body_len"));
    }

    #[test]
    fn external_ids_that_are_not_job_ids_are_dropped() {
        assert_eq!(external_id(Some("hello".into())), None);
        assert!(external_id(Some("a".repeat(64))).is_some());
    }
}
