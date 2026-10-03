//! The evaluation request model and deterministic job identity.

use std::fmt;

use pii_eval_contracts::Sha256Digest;

/// A lowercase hexadecimal commit id (40 characters, or 64 for SHA-256 repositories).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CommitSha(String);

impl CommitSha {
    /// Validate.
    pub fn parse(text: &str) -> Option<Self> {
        let ok_len = text.len() == 40 || text.len() == 64;
        (ok_len
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        .then(|| Self(text.to_owned()))
    }

    /// The hexadecimal text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CommitSha {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CommitSha({})", self.0)
    }
}

/// What the commit is the head of, so a later head can be compared with it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Subject {
    /// A pull request of the repository.
    PullRequest(u64),
    /// A branch of the repository (at most 255 bytes, no control characters).
    Branch(String),
}

/// The approved event that asked for an evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    /// A `/pii-eval run` comment on a pull request.
    IssueComment,
    /// A `check_suite` `rerequested` event.
    CheckSuite,
    /// A `check_run` `rerequested` event.
    CheckRun,
}

impl EventKind {
    /// The `X-GitHub-Event` value.
    pub const fn as_str(self) -> &'static str {
        match self {
            EventKind::IssueComment => "issue_comment",
            EventKind::CheckSuite => "check_suite",
            EventKind::CheckRun => "check_run",
        }
    }
}

/// Which population class a profile evaluates. This repository executes only
/// `PublicSynthetic`; a `Protected` profile is routed to the custodian and
/// never authorized here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileClass {
    /// Public synthetic population: runs through the CLI library.
    PublicSynthetic,
    /// Protected population: submitted to private-custodian, never executed here.
    Protected,
}

impl ProfileClass {
    /// Wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            ProfileClass::PublicSynthetic => "public-synthetic",
            ProfileClass::Protected => "protected",
        }
    }
}

/// Everything that determines what is measured and on what the result is
/// reported. Two requests with the same identity are the same job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobIdentity {
    /// Repository id (not the name).
    pub repository_id: u64,
    /// The commit the Check is reported on.
    pub commit: CommitSha,
    /// Profile id from the policy.
    pub profile_id: String,
    /// Pinned engine version of the profile.
    pub engine_version: String,
    /// Protocol revision of the profile.
    pub protocol_revision: u32,
    /// SHA-256 of the run configuration document the profile pins.
    pub config_digest: String,
    /// Semantic digest of the population the profile pins.
    pub population_digest: String,
    /// Population class.
    pub class: ProfileClass,
}

/// Deterministic job id: SHA-256 over the length-prefixed identity fields.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct JobId(String);

/// Domain separator of the job id (a change is a new identity scheme).
pub const JOB_ID_DOMAIN: &str = "pii-eval-app-job/1";

impl JobId {
    /// Derive from an identity. The requester and delivery are deliberately not
    /// part of it: who asked does not change what is measured.
    pub fn derive(identity: &JobIdentity) -> Self {
        let mut buf = Vec::with_capacity(512);
        let mut field = |bytes: &[u8]| {
            buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            buf.extend_from_slice(bytes);
        };
        field(JOB_ID_DOMAIN.as_bytes());
        field(identity.repository_id.to_string().as_bytes());
        field(identity.commit.as_str().as_bytes());
        field(identity.profile_id.as_bytes());
        field(identity.engine_version.as_bytes());
        field(identity.protocol_revision.to_string().as_bytes());
        field(identity.config_digest.as_bytes());
        field(identity.population_digest.as_bytes());
        field(identity.class.as_str().as_bytes());
        Self(Sha256Digest::of_bytes(&buf).as_str().to_owned())
    }

    /// Parse a job id (64 lowercase hex characters).
    pub fn parse(text: &str) -> Option<Self> {
        (text.len() == 64
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        .then(|| Self(text.to_owned()))
    }

    /// The hexadecimal text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for JobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "JobId({})", self.0)
    }
}

impl fmt::Display for JobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An authorized, resolved request for one evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvaluationRequest {
    /// Installation the event arrived for.
    pub installation_id: u64,
    /// Repository id.
    pub repository_id: u64,
    /// Repository full name as allowlisted (used only to label logs and Checks).
    pub repository_name: String,
    /// The commit (the head at admission time).
    pub commit: CommitSha,
    /// What the commit is the head of.
    pub subject: Subject,
    /// Selected profile.
    pub profile_id: String,
    /// The requester's numeric user id.
    pub requester_id: u64,
    /// The delivery that carried the request.
    pub delivery_id: String,
    /// The approved event.
    pub event: EventKind,
}

/// A parsed `/pii-eval` command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommandParse {
    /// The text is not addressed to this service.
    NotACommand,
    /// Addressed to this service but not valid.
    Malformed,
    /// `/pii-eval run [profile]`.
    Run {
        /// The profile token, when given.
        profile: Option<String>,
    },
}

/// Whether `text` is a valid profile or policy token: `[a-z0-9][a-z0-9-]{0,39}`.
pub fn is_profile_token(text: &str) -> bool {
    let b = text.as_bytes();
    !b.is_empty()
        && b.len() <= 40
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// Parse the first line of a comment. The command must start at byte 0 (a quoted
/// reply or indented text is not a command) and be exactly `/pii-eval run` or
/// `/pii-eval run <profile>` with single spaces; the rest of the comment is never
/// looked at or stored.
pub fn parse_command(body: &str) -> CommandParse {
    let first = body.lines().next().unwrap_or("");
    if !first.starts_with("/pii-eval") {
        return CommandParse::NotACommand;
    }
    if first.len() > 128 {
        return CommandParse::Malformed;
    }
    match first.strip_prefix("/pii-eval run") {
        Some("") => CommandParse::Run { profile: None },
        Some(rest) => match rest.strip_prefix(' ') {
            Some(token) if is_profile_token(token) => CommandParse::Run {
                profile: Some(token.to_owned()),
            },
            _ => CommandParse::Malformed,
        },
        None => CommandParse::Malformed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> JobIdentity {
        JobIdentity {
            repository_id: 42,
            commit: CommitSha::parse(&"a".repeat(40)).unwrap(),
            profile_id: "public-default".into(),
            engine_version: "0.0.0".into(),
            protocol_revision: 2,
            config_digest: "1".repeat(64),
            population_digest: "2".repeat(64),
            class: ProfileClass::PublicSynthetic,
        }
    }

    #[test]
    fn job_id_matches_an_independent_vector() {
        // Computed with Python: sha256 over 4-byte big-endian length-prefixed fields.
        assert_eq!(
            JobId::derive(&identity()).as_str(),
            "8a4eff22b1b141c45ea711fa4af67c59d9b5c62b27e37a08132ce70ed99c15fb"
        );
    }

    #[test]
    fn every_identity_field_changes_the_id() {
        let base = JobId::derive(&identity());
        let mut variants = Vec::new();
        let mut i = identity();
        i.repository_id = 43;
        variants.push(i);
        let mut i = identity();
        i.commit = CommitSha::parse(&"b".repeat(40)).unwrap();
        variants.push(i);
        let mut i = identity();
        i.profile_id = "other".into();
        variants.push(i);
        let mut i = identity();
        i.engine_version = "0.0.1".into();
        variants.push(i);
        let mut i = identity();
        i.protocol_revision = 3;
        variants.push(i);
        let mut i = identity();
        i.config_digest = "3".repeat(64);
        variants.push(i);
        let mut i = identity();
        i.population_digest = "3".repeat(64);
        variants.push(i);
        let mut i = identity();
        i.class = ProfileClass::Protected;
        variants.push(i);
        for v in variants {
            assert_ne!(JobId::derive(&v), base);
        }
        assert_eq!(JobId::derive(&identity()), base, "deterministic");
    }

    #[test]
    fn length_prefixing_prevents_field_boundary_ambiguity() {
        let mut a = identity();
        a.profile_id = "ab".into();
        a.engine_version = "c".into();
        let mut b = identity();
        b.profile_id = "a".into();
        b.engine_version = "bc".into();
        assert_ne!(JobId::derive(&a), JobId::derive(&b));
    }

    #[test]
    fn commit_and_job_id_parsers_are_strict() {
        assert!(CommitSha::parse(&"a".repeat(40)).is_some());
        assert!(CommitSha::parse(&"a".repeat(64)).is_some());
        assert!(CommitSha::parse(&"A".repeat(40)).is_none());
        assert!(CommitSha::parse(&"a".repeat(39)).is_none());
        assert!(CommitSha::parse(&"g".repeat(40)).is_none());
        assert!(JobId::parse(&"0".repeat(64)).is_some());
        assert!(JobId::parse("zz").is_none());
    }

    #[test]
    fn command_grammar() {
        use CommandParse::*;
        assert_eq!(parse_command("looks good"), NotACommand);
        assert_eq!(parse_command(" /pii-eval run"), NotACommand);
        assert_eq!(parse_command("> /pii-eval run"), NotACommand);
        assert_eq!(parse_command("/pii-eval run"), Run { profile: None });
        assert_eq!(
            parse_command("/pii-eval run\r\nthanks"),
            Run { profile: None }
        );
        assert_eq!(
            parse_command("/pii-eval run public-default\nmore"),
            Run {
                profile: Some("public-default".into())
            }
        );
        for bad in [
            "/pii-eval",
            "/pii-eval runx",
            "/pii-eval  run",
            "/pii-eval run  x",
            "/pii-eval run X",
            "/pii-eval run a b",
            "/pii-eval run -x",
            "/pii-evalrun",
            "/pii-eval run \u{1F4A5}",
        ] {
            assert_eq!(parse_command(bad), Malformed, "{bad:?}");
        }
        let long = format!("/pii-eval run {}", "a".repeat(200));
        assert_eq!(parse_command(&long), Malformed);
    }
}
