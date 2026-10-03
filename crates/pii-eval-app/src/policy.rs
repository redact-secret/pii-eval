//! The allowlist policy: which installations, repositories, actors and
//! evaluation profiles the service accepts, and its hard limits.
//!
//! The policy is configuration supplied by the deployment (a strict JSON file,
//! `pii-eval-app-policy/1`, or built in code). It is the only source of
//! authorization: nothing in a webhook payload (a comment, a label, an
//! `author_association`) grants anything by itself. Repositories and actors are
//! bound by numeric id; names are checked only to detect a stale allowlist.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde::Deserialize;

use crate::request::{ProfileClass, is_profile_token};

/// `schema` of the policy file.
pub const POLICY_SCHEMA: &str = "pii-eval-app-policy/1";
/// Largest policy file read.
pub const MAX_POLICY_BYTES: usize = 256 * 1024;

/// Hard limits. Every one has a ceiling that validation enforces, so a bad
/// policy cannot remove a bound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Largest accepted webhook body (checked before the HMAC and any parsing).
    pub max_body_bytes: usize,
    /// Pending jobs the queue holds; a full queue answers 503 (backpressure).
    pub queue_capacity: usize,
    /// Concurrent workers (each runs one job at a time).
    pub workers: usize,
    /// Wall-clock limit of one job (the runner enforces it and kills the tree).
    pub job_timeout: Duration,
    /// Delivery ids remembered for replay protection.
    pub delivery_capacity: usize,
    /// How long a delivery id is remembered.
    pub delivery_ttl: Duration,
    /// Jobs remembered (in flight and terminal).
    pub job_capacity: usize,
    /// Runs of one job identity (the first plus retries). Counted per identity
    /// for as long as the identity or its tombstone is remembered.
    pub max_attempts: u32,
    /// A comment request older than this (by the payload's `created_at`) is
    /// refused, which bounds what a replayed comment can do.
    pub comment_max_age: Duration,
    /// Tolerated difference between the payload's clock and ours.
    pub clock_skew: Duration,
    /// Minimum time between the end of a failed or stale job and its retry.
    pub retry_cooldown: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_body_bytes: 1024 * 1024,
            queue_capacity: 16,
            workers: 2,
            job_timeout: Duration::from_secs(15 * 60),
            delivery_capacity: 4096,
            delivery_ttl: Duration::from_secs(3 * 24 * 3600),
            job_capacity: 1024,
            max_attempts: 3,
            comment_max_age: Duration::from_secs(600),
            clock_skew: Duration::from_secs(60),
            retry_cooldown: Duration::from_secs(30),
        }
    }
}

/// Ceilings the validation enforces.
pub mod ceilings {
    /// Webhook body.
    pub const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
    /// Queue.
    pub const QUEUE_CAPACITY: usize = 1024;
    /// Workers.
    pub const WORKERS: usize = 8;
    /// Job timeout in seconds.
    pub const JOB_TIMEOUT_SECS: u64 = 3600;
    /// Delivery ids.
    pub const DELIVERY_CAPACITY: usize = 1_000_000;
    /// Delivery id retention in seconds.
    pub const DELIVERY_TTL_SECS: u64 = 14 * 24 * 3600;
    /// Jobs.
    pub const JOB_CAPACITY: usize = 100_000;
    /// Attempts.
    pub const MAX_ATTEMPTS: u32 = 10;
    /// Comment age in seconds.
    pub const COMMENT_MAX_AGE_SECS: u64 = 24 * 3600;
    /// Clock skew in seconds.
    pub const CLOCK_SKEW_SECS: u64 = 600;
    /// Retry cooldown in seconds.
    pub const RETRY_COOLDOWN_SECS: u64 = 3600;
}

/// An evaluation profile: the immutable identity of what a request runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    /// Token (`[a-z0-9][a-z0-9-]{0,39}`).
    pub id: String,
    /// Public synthetic (executed here) or protected (routed to the custodian).
    pub class: ProfileClass,
    /// Pinned engine version.
    pub engine_version: String,
    /// Protocol revision.
    pub protocol_revision: u32,
    /// SHA-256 of the run configuration document the runner must use.
    pub config_digest: String,
    /// Semantic digest of the population the run must report.
    pub population_digest: String,
}

/// One allowlisted repository of an installation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryPolicy {
    /// Numeric repository id (the authority).
    pub id: u64,
    /// `owner/name`, compared case-insensitively to detect a stale allowlist.
    pub full_name: String,
    /// Numeric ids of the users who may request evaluations.
    pub actors: BTreeSet<u64>,
    /// Profiles the repository may run; the first is the default.
    pub profiles: Vec<String>,
    /// Whether a pull request whose head lives in another repository may be
    /// evaluated. Nothing from the commit is ever executed, but the Check would
    /// be attached to fork-controlled content, so the default is no.
    pub allow_fork_heads: bool,
}

/// One allowlisted installation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallationPolicy {
    /// Numeric installation id.
    pub id: u64,
    /// Its repositories.
    pub repositories: Vec<RepositoryPolicy>,
}

/// The whole policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppPolicy {
    /// Allowlisted installations.
    pub installations: Vec<InstallationPolicy>,
    /// Known profiles.
    pub profiles: Vec<Profile>,
    /// Limits.
    pub limits: Limits,
    /// Optional base of the details link on a Check (`https://...`, no query).
    pub details_base_url: Option<String>,
}

/// A policy that is not acceptable. Names a field, never a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyError(pub &'static str);

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid policy: {}", self.0)
    }
}

impl std::error::Error for PolicyError {}

fn is_hex64(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_version(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'+')
}

fn is_full_name(text: &str) -> bool {
    let mut parts = text.split('/');
    let (Some(o), Some(n), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let ok = |p: &str| {
        !p.is_empty()
            && p.len() <= 100
            && p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    };
    ok(o) && ok(n)
}

impl AppPolicy {
    /// Check every rule. A policy that fails is never used.
    pub fn validate(&self) -> Result<(), PolicyError> {
        let l = &self.limits;
        let within =
            |ok: bool, name: &'static str| if ok { Ok(()) } else { Err(PolicyError(name)) };
        within(
            (1..=ceilings::MAX_BODY_BYTES).contains(&l.max_body_bytes),
            "limits.maxBodyBytes",
        )?;
        within(
            (1..=ceilings::QUEUE_CAPACITY).contains(&l.queue_capacity),
            "limits.queueCapacity",
        )?;
        within(
            (1..=ceilings::WORKERS).contains(&l.workers),
            "limits.workers",
        )?;
        within(
            !l.job_timeout.is_zero() && l.job_timeout.as_secs() <= ceilings::JOB_TIMEOUT_SECS,
            "limits.jobTimeoutSecs",
        )?;
        within(
            (1..=ceilings::DELIVERY_CAPACITY).contains(&l.delivery_capacity),
            "limits.deliveryCapacity",
        )?;
        within(
            !l.delivery_ttl.is_zero() && l.delivery_ttl.as_secs() <= ceilings::DELIVERY_TTL_SECS,
            "limits.deliveryTtlSecs",
        )?;
        within(
            (1..=ceilings::JOB_CAPACITY).contains(&l.job_capacity),
            "limits.jobCapacity",
        )?;
        within(
            (1..=ceilings::MAX_ATTEMPTS).contains(&l.max_attempts),
            "limits.maxAttempts",
        )?;
        within(
            l.queue_capacity <= l.job_capacity,
            "limits.queueCapacity>jobCapacity",
        )?;

        let mut ids = BTreeSet::new();
        for p in &self.profiles {
            within(is_profile_token(&p.id), "profiles.id")?;
            within(ids.insert(p.id.as_str()), "profiles.id duplicate")?;
            within(is_version(&p.engine_version), "profiles.engineVersion")?;
            within(is_hex64(&p.config_digest), "profiles.configDigest")?;
            within(is_hex64(&p.population_digest), "profiles.populationDigest")?;
            within(p.protocol_revision > 0, "profiles.protocolRevision")?;
        }
        let mut installations = BTreeSet::new();
        let mut repos = BTreeSet::new();
        for i in &self.installations {
            within(i.id > 0, "installations.id")?;
            within(installations.insert(i.id), "installations.id duplicate")?;
            for r in &i.repositories {
                within(r.id > 0, "repositories.id")?;
                // One repository belongs to one installation, so a mismatch
                // between the two is unambiguous.
                within(repos.insert(r.id), "repositories.id duplicate")?;
                within(is_full_name(&r.full_name), "repositories.fullName")?;
                within(!r.actors.is_empty(), "repositories.actors empty")?;
                within(!r.actors.contains(&0), "repositories.actors")?;
                within(!r.profiles.is_empty(), "repositories.profiles empty")?;
                let mut seen = BTreeSet::new();
                for p in &r.profiles {
                    within(ids.contains(p.as_str()), "repositories.profiles unknown")?;
                    within(seen.insert(p.as_str()), "repositories.profiles duplicate")?;
                }
            }
        }
        if let Some(url) = &self.details_base_url {
            within(
                url.starts_with("https://")
                    && url.len() <= 200
                    && url.bytes().all(|b| (0x21..0x7f).contains(&b))
                    && !url.contains(['?', '#']),
                "detailsBaseUrl",
            )?;
        }
        Ok(())
    }

    /// The installation with this id.
    pub fn installation(&self, id: u64) -> Option<&InstallationPolicy> {
        self.installations.iter().find(|i| i.id == id)
    }

    /// Whether any installation lists this repository.
    pub fn repository_known(&self, repository_id: u64) -> bool {
        self.installations
            .iter()
            .any(|i| i.repositories.iter().any(|r| r.id == repository_id))
    }

    /// A profile by id.
    pub fn profile(&self, id: &str) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.id == id)
    }

    /// Parse and validate `pii-eval-app-policy/1`: strict (unknown fields and
    /// duplicate keys are errors), bounded, no secrets in it.
    pub fn from_json(bytes: &[u8]) -> Result<Self, PolicyError> {
        if bytes.len() > MAX_POLICY_BYTES {
            return Err(PolicyError("size"));
        }
        let raw: RawPolicy = serde_json::from_slice(bytes).map_err(|_| PolicyError("document"))?;
        if raw.schema != POLICY_SCHEMA {
            return Err(PolicyError("schema"));
        }
        let d = Limits::default();
        let rl = raw.limits.unwrap_or_default();
        let limits = Limits {
            max_body_bytes: rl.max_body_bytes.unwrap_or(d.max_body_bytes),
            queue_capacity: rl.queue_capacity.unwrap_or(d.queue_capacity),
            workers: rl.workers.unwrap_or(d.workers),
            job_timeout: rl
                .job_timeout_secs
                .map_or(d.job_timeout, Duration::from_secs),
            delivery_capacity: rl.delivery_capacity.unwrap_or(d.delivery_capacity),
            delivery_ttl: rl
                .delivery_ttl_secs
                .map_or(d.delivery_ttl, Duration::from_secs),
            job_capacity: rl.job_capacity.unwrap_or(d.job_capacity),
            max_attempts: rl.max_attempts.unwrap_or(d.max_attempts),
            comment_max_age: rl
                .comment_max_age_secs
                .map_or(d.comment_max_age, Duration::from_secs),
            clock_skew: rl.clock_skew_secs.map_or(d.clock_skew, Duration::from_secs),
            retry_cooldown: rl
                .retry_cooldown_secs
                .map_or(d.retry_cooldown, Duration::from_secs),
        };
        let mut profiles = Vec::new();
        for p in raw.profiles {
            let class = match p.class.as_str() {
                "public-synthetic" => ProfileClass::PublicSynthetic,
                "protected" => ProfileClass::Protected,
                _ => return Err(PolicyError("profiles.class")),
            };
            profiles.push(Profile {
                id: p.id,
                class,
                engine_version: p.engine_version,
                protocol_revision: p.protocol_revision,
                config_digest: p.config_digest,
                population_digest: p.population_digest,
            });
        }
        let mut installations = Vec::new();
        for i in raw.installations {
            let mut repositories = Vec::new();
            for r in i.repositories {
                let n = r.actors.len();
                let actors: BTreeSet<u64> = r.actors.into_iter().collect();
                if actors.len() != n {
                    return Err(PolicyError("repositories.actors duplicate"));
                }
                repositories.push(RepositoryPolicy {
                    id: r.id,
                    full_name: r.full_name,
                    actors,
                    profiles: r.profiles,
                    allow_fork_heads: r.allow_fork_heads.unwrap_or(false),
                });
            }
            installations.push(InstallationPolicy {
                id: i.id,
                repositories,
            });
        }
        let policy = AppPolicy {
            installations,
            profiles,
            limits,
            details_base_url: raw.details_base_url,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Profiles by id (for runner construction).
    pub fn profile_map(&self) -> BTreeMap<&str, &Profile> {
        self.profiles.iter().map(|p| (p.id.as_str(), p)).collect()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawPolicy {
    schema: String,
    installations: Vec<RawInstallation>,
    profiles: Vec<RawProfile>,
    limits: Option<RawLimits>,
    details_base_url: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawInstallation {
    id: u64,
    repositories: Vec<RawRepository>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawRepository {
    id: u64,
    full_name: String,
    actors: Vec<u64>,
    profiles: Vec<String>,
    allow_fork_heads: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawProfile {
    id: String,
    class: String,
    engine_version: String,
    protocol_revision: u32,
    config_digest: String,
    population_digest: String,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawLimits {
    max_body_bytes: Option<usize>,
    queue_capacity: Option<usize>,
    workers: Option<usize>,
    job_timeout_secs: Option<u64>,
    delivery_capacity: Option<usize>,
    delivery_ttl_secs: Option<u64>,
    job_capacity: Option<usize>,
    max_attempts: Option<u32>,
    comment_max_age_secs: Option<u64>,
    clock_skew_secs: Option<u64>,
    retry_cooldown_secs: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"{
      "schema": "pii-eval-app-policy/1",
      "profiles": [{"id": "public-default", "class": "public-synthetic", "engineVersion": "0.0.0",
        "protocolRevision": 2, "configDigest": "1111111111111111111111111111111111111111111111111111111111111111",
        "populationDigest": "2222222222222222222222222222222222222222222222222222222222222222"}],
      "installations": [{"id": 7, "repositories": [{"id": 42, "fullName": "example/repo",
        "actors": [1001], "profiles": ["public-default"]}]}],
      "limits": {"workers": 3}
    }"#;

    #[test]
    fn a_good_policy_loads_with_defaults() {
        let p = AppPolicy::from_json(GOOD.as_bytes()).unwrap();
        assert_eq!(p.limits.workers, 3);
        assert_eq!(p.limits.queue_capacity, Limits::default().queue_capacity);
        assert!(!p.installations[0].repositories[0].allow_fork_heads);
        assert!(p.installation(7).is_some() && p.installation(8).is_none());
    }

    #[test]
    fn unknown_fields_duplicates_and_bad_values_are_refused() {
        let bad = [
            GOOD.replace("\"limits\"", "\"extra\": 1, \"limits\""),
            GOOD.replace("pii-eval-app-policy/1", "pii-eval-app-policy/2"),
            GOOD.replace("\"workers\": 3", "\"workers\": 0"),
            GOOD.replace("\"workers\": 3", "\"workers\": 9"),
            GOOD.replace("\"workers\": 3", "\"workers\": -1"),
            GOOD.replace("\"actors\": [1001]", "\"actors\": []"),
            GOOD.replace("\"actors\": [1001]", "\"actors\": [5, 5]"),
            GOOD.replace("[\"public-default\"]", "[\"nope\"]"),
            GOOD.replace("example/repo", "no-slash"),
            GOOD.replace("public-synthetic", "public"),
            GOOD.replace("\"id\": 42", "\"id\": 0"),
            GOOD.replace("\"id\": 7,", "\"id\": 7, \"id\": 8,"),
            GOOD.replace("\"populationDigest\": \"2", "\"populationDigest\": \"G"),
        ];
        for (i, doc) in bad.iter().enumerate() {
            assert!(AppPolicy::from_json(doc.as_bytes()).is_err(), "case {i}");
        }
        assert!(AppPolicy::from_json(&vec![b' '; MAX_POLICY_BYTES + 1]).is_err());
    }

    #[test]
    fn a_repository_cannot_belong_to_two_installations() {
        let mut p = AppPolicy::from_json(GOOD.as_bytes()).unwrap();
        let mut second = p.installations[0].clone();
        second.id = 8;
        p.installations.push(second);
        assert!(p.validate().is_err());
    }

    #[test]
    fn errors_name_fields_never_values() {
        let doc = GOOD.replace("example/repo", "SENTINEL value/with/slashes");
        let e = AppPolicy::from_json(doc.as_bytes()).unwrap_err();
        assert!(!e.to_string().contains("SENTINEL"));
    }
}
