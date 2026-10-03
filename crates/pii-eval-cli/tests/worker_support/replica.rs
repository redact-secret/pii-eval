//! REPLICA of the custodian's worker-side checks, written from the source of
//! `redact-secret/private-custodian` at commit
//! 142db34dd4bc02903f47cba951a054351bb55fde; it is NOT that code and imports none
//! of it. A change in the custodian is not seen here until this file is
//! re-derived from its source.
//!
//! Replicated, with the source it was written from:
//!
//! * `job_document` and the job schema: `crates/custodian-worker/src/result.rs`;
//! * `validate_result` and its outcome mapping (A5, A6): the same file, and
//!   `docs/worker-isolation.md` section 7;
//! * the staged-file identity check (hash of each staged file against the plan's
//!   pin, before and after the run): `src/dispatcher.rs` (`pins`, `drive`) and
//!   `src/artifacts.rs` (`hash_file`);
//! * `PrivateAggregates::decode` (A11): `crates/custodian-disclosure/src/aggregate.rs`;
//! * the receipt validity rule for roster counters:
//!   `crates/custodian-contracts/src/execution.rs` (`InternalReceipt::validate`);
//! * the label and digest syntaxes (A10): `crates/custodian-contracts/src/types.rs`.
//!
//! The conformance vectors for `validate_result` are the custodian's own, from
//! `crates/custodian-worker/tests/staging_result.rs` (`doc`, the accepted rows
//! of `validator_accepts_exact_shape_and_maps_outcomes_for_both_domains` and the
//! rejected rows of `validator_rejects_malformed_inconsistent_and_oversized_results`).
//! Everything else here is synthetic.
#![allow(dead_code)]

use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2_free::sha256_hex;

/// SHA-256 without a new dependency: the contracts' digest of exact bytes.
mod sha2_free {
    pub fn sha256_hex(bytes: &[u8]) -> String {
        pii_eval_contracts::Sha256Digest::of_bytes(bytes)
            .as_str()
            .to_owned()
    }
}

pub const JOB_SCHEMA: &str = "private-custodian.worker-job/1";
pub const RESULT_SCHEMA: &str = "private-custodian.worker-result/1";
pub const AGGREGATE_SCHEMA: &str = "private-custodian.aggregates/1";
pub const MAX_RESULT_BYTES: usize = 64 * 1024;
pub const MAX_AGGREGATE_BYTES: usize = 64 * 1024;
pub const MAX_CELLS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Domain {
    Credential,
    Pii,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolRef {
    pub domain: Domain,
    pub name: String,
    pub version: String,
}

/// `[a-z0-9][a-z0-9._-]{0,63}`.
pub fn label_ok(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=64).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
        })
}

// --- job document ----------------------------------------------------------

#[derive(Serialize)]
struct WireProtocolOut<'a> {
    name: &'a str,
    version: &'a str,
}

#[derive(Serialize)]
struct JobDoc<'a> {
    schema: &'static str,
    domain: Domain,
    protocol: WireProtocolOut<'a>,
    roster: u64,
    entries: &'a [String],
}

pub fn job_document(domain: Domain, protocol: &ProtocolRef, entries: &[String]) -> Vec<u8> {
    serde_json::to_vec(&JobDoc {
        schema: JOB_SCHEMA,
        domain,
        protocol: WireProtocolOut {
            name: &protocol.name,
            version: &protocol.version,
        },
        roster: entries.len() as u64,
        entries,
    })
    .unwrap()
}

// --- result ----------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Success,
    Partial,
    Failed,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Completed,
    EnginePartial,
    ResultOversized,
    ResultMalformed,
    ResultMismatch,
    RosterMismatch,
    NonZeroExit,
    IdentityMismatch,
    IdentityChangedAfterExecution,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireProtocol {
    name: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireStatus {
    Complete,
    Partial,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRoster {
    expected: u64,
    observed: u64,
    failed: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireResult {
    schema: String,
    domain: Domain,
    protocol: WireProtocol,
    status: WireStatus,
    roster: WireRoster,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Roster {
    pub expected: u64,
    pub observed: u64,
    pub failed: u64,
}

#[derive(Debug, Clone)]
pub struct ValidatedResult {
    pub outcome: Outcome,
    pub reason: Reason,
    pub roster: Roster,
    /// `sha256:` + hex of the exact stdout bytes (the private artifact reference).
    pub digest: String,
    pub size: u64,
    pub protocol: ProtocolRef,
}

pub fn validate_result(
    stdout: &[u8],
    domain: Domain,
    protocol: &ProtocolRef,
    authorized_roster: u64,
) -> Result<ValidatedResult, Reason> {
    if stdout.len() > MAX_RESULT_BYTES {
        return Err(Reason::ResultOversized);
    }
    let w: WireResult = serde_json::from_slice(stdout).map_err(|_| Reason::ResultMalformed)?;
    if w.schema != RESULT_SCHEMA || !label_ok(&w.protocol.name) || !label_ok(&w.protocol.version) {
        return Err(Reason::ResultMalformed);
    }
    if w.domain != domain
        || w.protocol.name != protocol.name
        || w.protocol.version != protocol.version
    {
        return Err(Reason::ResultMismatch);
    }
    let r = &w.roster;
    if r.expected != authorized_roster
        || r.observed > r.expected
        || r.failed > r.observed
        || authorized_roster == 0
    {
        return Err(Reason::RosterMismatch);
    }
    let complete = r.observed == r.expected;
    match (&w.status, complete) {
        (WireStatus::Complete, true) | (WireStatus::Partial, false) => {}
        _ => return Err(Reason::RosterMismatch),
    }
    let (outcome, reason) = if complete && r.failed == 0 {
        (Outcome::Success, Reason::Completed)
    } else {
        (Outcome::Partial, Reason::EnginePartial)
    };
    Ok(ValidatedResult {
        outcome,
        reason,
        roster: Roster {
            expected: r.expected,
            observed: r.observed,
            failed: r.failed,
        },
        digest: format!("sha256:{}", sha256_hex(stdout)),
        size: stdout.len() as u64,
        protocol: protocol.clone(),
    })
}

/// A6: a worker that did not exit cleanly never has its stdout parsed.
pub fn map_outcome(
    exit_code: i32,
    stdout: &[u8],
    domain: Domain,
    protocol: &ProtocolRef,
    authorized_roster: u64,
) -> (Outcome, Reason, Option<ValidatedResult>) {
    if exit_code != 0 {
        return (Outcome::Failed, Reason::NonZeroExit, None);
    }
    match validate_result(stdout, domain, protocol, authorized_roster) {
        Ok(v) => (v.outcome, v.reason, Some(v)),
        Err(r) => (Outcome::Rejected, r, None),
    }
}

// --- staging identity ------------------------------------------------------

/// Hash of a staged file, `sha256:` syntax (`hash_file`).
pub fn hash_file(path: &Path) -> Option<String> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() {
        return None;
    }
    Some(format!("sha256:{}", sha256_hex(&std::fs::read(path).ok()?)))
}

/// Every staged file must still hash to its frozen pin.
pub fn staged_identity_holds(stage: &Path, pins: &[(String, String)]) -> bool {
    pins.iter()
        .all(|(name, pin)| hash_file(&stage.join(name)).as_deref() == Some(pin.as_str()))
}

// --- aggregates ------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisclosureReason {
    ArtifactMalformed,
    ArtifactMismatch,
    ArtifactInconsistent,
    StratumNotAllowed,
    MetricNotAllowed,
}

#[derive(Debug, Clone)]
pub struct ArtifactRef {
    pub digest: String,
    pub size: u64,
    pub protocol: ProtocolRef,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCell {
    stratum: String,
    metric: String,
    numerator: u64,
    denominator: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireAggregates {
    schema: String,
    domain: Domain,
    protocol: WireProtocol,
    roster: WireRoster,
    cells: Vec<WireCell>,
}

/// The per-domain allowlists of the disclosure policy (the allowlist check is
/// the projection's in the custodian; it is replicated here so a label the
/// policy would refuse is visible).
pub struct Allowlist {
    pub strata: Vec<String>,
    pub metrics: Vec<String>,
}

pub fn decode_aggregates(
    bytes: &[u8],
    reference: &ArtifactRef,
    domain: Domain,
    protocol: &ProtocolRef,
    roster: &Roster,
    allow: &Allowlist,
) -> Result<Vec<(String, String, u64, u64)>, DisclosureReason> {
    use DisclosureReason as D;
    if bytes.len() > MAX_AGGREGATE_BYTES {
        return Err(D::ArtifactMalformed);
    }
    if format!("sha256:{}", sha256_hex(bytes)) != reference.digest
        || bytes.len() as u64 != reference.size
    {
        return Err(D::ArtifactMismatch);
    }
    let w: WireAggregates = serde_json::from_slice(bytes).map_err(|_| D::ArtifactMalformed)?;
    if w.schema != AGGREGATE_SCHEMA || w.cells.len() > MAX_CELLS || w.cells.is_empty() {
        return Err(D::ArtifactMalformed);
    }
    for c in &w.cells {
        if !label_ok(&c.stratum) || !label_ok(&c.metric) {
            return Err(D::ArtifactMalformed);
        }
    }
    if w.domain != domain
        || w.protocol.name != protocol.name
        || w.protocol.version != protocol.version
        || reference.protocol != *protocol
    {
        return Err(D::ArtifactMismatch);
    }
    let r = (w.roster.expected, w.roster.observed, w.roster.failed);
    if r != (roster.expected, roster.observed, roster.failed) {
        return Err(D::ArtifactMismatch);
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut cells = Vec::new();
    for c in w.cells {
        if c.numerator > c.denominator || c.denominator > r.1 {
            return Err(D::ArtifactInconsistent);
        }
        if !seen.insert((c.stratum.clone(), c.metric.clone())) {
            return Err(D::ArtifactInconsistent);
        }
        if !allow.strata.contains(&c.stratum) {
            return Err(D::StratumNotAllowed);
        }
        if !allow.metrics.contains(&c.metric) {
            return Err(D::MetricNotAllowed);
        }
        cells.push((c.stratum, c.metric, c.numerator, c.denominator));
    }
    Ok(cells)
}

/// `InternalReceipt::validate` for the roster counters of an outcome.
pub fn receipt_accepts(outcome: Outcome, roster: &Roster) -> bool {
    let ok = match outcome {
        Outcome::Success => roster.observed == roster.expected,
        Outcome::Partial => roster.observed < roster.expected,
        _ => false,
    };
    ok && roster.failed <= roster.observed
}

pub fn pii_protocol() -> ProtocolRef {
    ProtocolRef {
        domain: Domain::Pii,
        name: "pii-v1".into(),
        version: "2".into(),
    }
}
