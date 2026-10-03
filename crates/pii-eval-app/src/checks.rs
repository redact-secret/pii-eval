//! Sanitized Check summaries (`pii-eval-check-summary/1`).
//!
//! A Check is public to everyone who can see the repository, so its text is
//! built only from a closed template and from fields that were validated one by
//! one: engine and protocol identity, digests, closed state and status tokens,
//! public-synthetic population counts, scanner ids and failure codes of the
//! manifest. Nothing is copied through from a runner's output: the CLI summary
//! is parsed into [`RunnerOutcome`], each field is checked against a strict
//! charset and bound, and a field that fails makes the whole projection fail
//! (reported as a fixed `summary-rejected` Check) instead of being repaired.
//! A final guard rejects any non-printable-ASCII byte and any overlong text.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde_json::Value;

use crate::policy::Profile;
use crate::request::{CommitSha, JobId};

/// `schema` of the rendered summary.
pub const CHECK_SUMMARY_SCHEMA: &str = "pii-eval-check-summary/1";
/// Name of the Check run.
pub const CHECK_NAME: &str = "pii-eval";
/// Largest rendered summary (GitHub allows 65535; the template needs far less).
pub const MAX_SUMMARY_BYTES: usize = 8 * 1024;
/// Largest accepted runner summary line.
pub const MAX_RUNNER_LINE_BYTES: usize = 256 * 1024;

/// GitHub check run conclusion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Conclusion {
    /// The measurement completed.
    Success,
    /// The measurement did not complete or the evaluation failed.
    Failure,
    /// Informational (superseded head, head not verifiable).
    Neutral,
    /// Cancelled.
    Cancelled,
    /// Exceeded the job time limit.
    TimedOut,
}

impl Conclusion {
    /// The GitHub API value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Conclusion::Success => "success",
            Conclusion::Failure => "failure",
            Conclusion::Neutral => "neutral",
            Conclusion::Cancelled => "cancelled",
            Conclusion::TimedOut => "timed_out",
        }
    }
}

/// Check run status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckStatus {
    /// Running.
    InProgress,
    /// Finished (a conclusion is set).
    Completed,
}

/// Identifier GitHub assigned to a check run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CheckRunId(pub u64);

/// The text of a Check: a fixed-vocabulary title and a sanitized summary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckOutput {
    /// Title.
    pub title: String,
    /// Summary.
    pub summary: String,
}

/// A rendered report: conclusion plus output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckReport {
    /// Conclusion.
    pub conclusion: Conclusion,
    /// Output.
    pub output: CheckOutput,
}

/// Request to create a check run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckRunCreate {
    /// Installation (the transport mints its own token; no credential is here).
    pub installation_id: u64,
    /// Repository id.
    pub repository_id: u64,
    /// Commit the Check is attached to.
    pub head_sha: CommitSha,
    /// Check name ([`CHECK_NAME`]).
    pub name: &'static str,
    /// The job id, so a retry finds the same run.
    pub external_id: JobId,
    /// Status.
    pub status: CheckStatus,
    /// Conclusion, when completed.
    pub conclusion: Option<Conclusion>,
    /// Output.
    pub output: Option<CheckOutput>,
    /// Details link.
    pub details_url: Option<String>,
}

/// Request to update a check run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckRunUpdate {
    /// Installation.
    pub installation_id: u64,
    /// Repository id.
    pub repository_id: u64,
    /// The run.
    pub check_run_id: CheckRunId,
    /// Status.
    pub status: CheckStatus,
    /// Conclusion, when completed.
    pub conclusion: Option<Conclusion>,
    /// Output.
    pub output: Option<CheckOutput>,
    /// Details link.
    pub details_url: Option<String>,
}

/// A projection failure. Never carries the rejected text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectionError(pub &'static str);

/// Whether `text` is a token: `[a-z0-9][a-z0-9._@/-]{0,63}` (state names, scanner
/// ids, failure codes, protocol ids).
fn is_token(text: &str) -> bool {
    let b = text.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| {
            c.is_ascii_lowercase()
                || c.is_ascii_digit()
                || matches!(c, b'.' | b'_' | b'@' | b'/' | b'-')
        })
}

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
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
}

/// What a run measured, as validated from the CLI summary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Measured {
    /// Exit code (0 complete, 5 scanner failure).
    pub exit_code: u8,
    /// `complete` or `incomplete`.
    pub state: String,
    /// Engine version.
    pub engine_version: String,
    /// Protocol id.
    pub protocol_id: String,
    /// Protocol revision.
    pub protocol_revision: u32,
    /// Population semantic digest.
    pub population_digest: String,
    /// Manifest semantic digest.
    pub manifest_digest: String,
    /// Run artifact semantic digest.
    pub run_artifact_digest: String,
    /// Public artifact digest.
    pub public_artifact_digest: Option<String>,
    /// Public-synthetic population counts.
    pub population_counts: BTreeMap<String, u64>,
    /// Outcome-matrix coverage token.
    pub completeness: String,
    /// `(scanner id, status)` pairs in summary order.
    pub scanners: Vec<(String, String)>,
    /// Failure code tokens.
    pub failure_codes: Vec<String>,
}

impl Measured {
    /// Whether the run reports exactly the identities the profile pins.
    pub fn matches_profile(&self, p: &Profile) -> bool {
        self.engine_version == p.engine_version
            && self.protocol_id == "pii-v1"
            && self.protocol_revision == p.protocol_revision
            && self.population_digest == p.population_digest
    }
}

/// What a runner reports for a job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunnerOutcome {
    /// Exit 0 or 5 with a validated body.
    Measured(Box<Measured>),
    /// Any other exit: the CLI's closed reason token only.
    Failed {
        /// Exit code.
        exit_code: u8,
        /// The CLI's `error.reason` token (or `unknown`).
        reason: String,
    },
}

fn get<'a>(v: &'a Value, key: &str) -> Result<&'a Value, ProjectionError> {
    v.get(key).ok_or(ProjectionError("missing-field"))
}

fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str, ProjectionError> {
    get(v, key)?.as_str().ok_or(ProjectionError("wrong-type"))
}

fn token(v: &Value, key: &str) -> Result<String, ProjectionError> {
    let t = text(v, key)?;
    is_token(t)
        .then(|| t.to_owned())
        .ok_or(ProjectionError("invalid-token"))
}

fn digest(v: &Value, key: &str) -> Result<String, ProjectionError> {
    let t = text(v, key)?;
    is_hex64(t)
        .then(|| t.to_owned())
        .ok_or(ProjectionError("invalid-digest"))
}

impl RunnerOutcome {
    /// Project the CLI's one-line summary (`pii-eval-summary/1`). Only the
    /// listed fields are read; everything else is ignored and never copied.
    pub fn from_summary_line(line: &str) -> Result<Self, ProjectionError> {
        if line.len() > MAX_RUNNER_LINE_BYTES {
            return Err(ProjectionError("too-large"));
        }
        let v: Value =
            serde_json::from_str(line.trim_end()).map_err(|_| ProjectionError("not-json"))?;
        if text(&v, "schema")? != pii_eval_cli::summary::SUMMARY_SCHEMA {
            return Err(ProjectionError("schema"));
        }
        if text(&v, "command")? != "run" {
            return Err(ProjectionError("command"));
        }
        let exit = get(&v, "exit")?;
        let code = get(exit, "code")?
            .as_u64()
            .and_then(|c| u8::try_from(c).ok())
            .ok_or(ProjectionError("exit-code"))?;
        if code != 0 && code != 5 {
            let reason = v
                .get("error")
                .and_then(|e| e.get("reason"))
                .and_then(Value::as_str)
                .filter(|r| is_token(r))
                .unwrap_or("unknown")
                .to_owned();
            return Ok(RunnerOutcome::Failed {
                exit_code: code,
                reason,
            });
        }
        let state = token(&v, "state")?;
        if (code == 0 && state != "complete") || (code == 5 && state != "incomplete") {
            return Err(ProjectionError("state-exit-mismatch"));
        }
        let engine = get(&v, "engine")?;
        let sem = get(&v, "semantic")?;
        let protocol = get(sem, "protocol")?;
        let engine_version = text(engine, "version")?;
        if !is_version(engine_version) {
            return Err(ProjectionError("invalid-version"));
        }
        // The App never publishes a protected population's results.
        if text(sem, "runClass")? != "public-synthetic" {
            return Err(ProjectionError("run-class"));
        }
        let mut counts = BTreeMap::new();
        if let Some(c) = sem.get("populationCounts").and_then(Value::as_object) {
            if c.len() > 16 {
                return Err(ProjectionError("too-many-counts"));
            }
            for (k, n) in c {
                let ok_key = !k.is_empty()
                    && k.len() <= 40
                    && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
                match (ok_key, n.as_u64()) {
                    (true, Some(n)) => {
                        counts.insert(k.clone(), n);
                    }
                    _ => return Err(ProjectionError("invalid-count")),
                }
            }
        }
        let scanners_v = get(sem, "scanners")?
            .as_array()
            .ok_or(ProjectionError("wrong-type"))?;
        if scanners_v.len() > 16 {
            return Err(ProjectionError("too-many-scanners"));
        }
        let mut scanners = Vec::new();
        for s in scanners_v {
            scanners.push((token(s, "scannerId")?, token(s, "status")?));
        }
        let codes_v = get(sem, "failureCodes")?
            .as_array()
            .ok_or(ProjectionError("wrong-type"))?;
        if codes_v.len() > 32 {
            return Err(ProjectionError("too-many-codes"));
        }
        let mut failure_codes = Vec::new();
        for c in codes_v {
            let t = c.as_str().ok_or(ProjectionError("wrong-type"))?;
            if !is_token(t) {
                return Err(ProjectionError("invalid-token"));
            }
            failure_codes.push(t.to_owned());
        }
        let public_artifact_digest = match sem.get("publicArtifactDigest") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if is_hex64(s) => Some(s.clone()),
            Some(_) => return Err(ProjectionError("invalid-digest")),
        };
        Ok(RunnerOutcome::Measured(Box::new(Measured {
            exit_code: code,
            state,
            engine_version: engine_version.to_owned(),
            protocol_id: token(protocol, "id")?,
            protocol_revision: get(protocol, "revision")?
                .as_u64()
                .and_then(|r| u32::try_from(r).ok())
                .ok_or(ProjectionError("invalid-revision"))?,
            population_digest: digest(sem, "populationDigest")?,
            manifest_digest: digest(sem, "manifestDigest")?,
            run_artifact_digest: digest(sem, "runArtifactDigest")?,
            public_artifact_digest,
            population_counts: counts,
            completeness: token(sem, "completeness")?,
            scanners,
            failure_codes,
        })))
    }
}

/// Why a run produced no measurement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureKind {
    /// The runner refused (unknown profile, unusable host).
    RunnerRefused,
    /// The pinned configuration changed or the run reported another identity.
    IdentityMismatch,
    /// Time limit.
    Timeout,
    /// Cancelled (shutdown).
    Cancelled,
    /// The runner's output could not be projected.
    SummaryRejected,
    /// The CLI reported a failure other than an incomplete measurement.
    RunFailed,
    /// Unexpected internal error.
    Internal,
}

impl FailureKind {
    /// Stable code printed in the Check.
    pub const fn code(self) -> &'static str {
        match self {
            FailureKind::RunnerRefused => "runner-refused",
            FailureKind::IdentityMismatch => "identity-mismatch",
            FailureKind::Timeout => "timeout",
            FailureKind::Cancelled => "cancelled",
            FailureKind::SummaryRejected => "summary-rejected",
            FailureKind::RunFailed => "run-failed",
            FailureKind::Internal => "internal-error",
        }
    }

    fn conclusion(self) -> Conclusion {
        match self {
            FailureKind::Timeout => Conclusion::TimedOut,
            FailureKind::Cancelled => Conclusion::Cancelled,
            _ => Conclusion::Failure,
        }
    }
}

/// The identities every report states.
#[derive(Clone, Debug)]
pub struct ReportContext<'a> {
    /// Job id.
    pub job_id: &'a JobId,
    /// Commit.
    pub commit: &'a CommitSha,
    /// Profile (identity pins).
    pub profile: &'a Profile,
}

const FOOTER: &str = "This Check reports a measurement of public synthetic data. It is not a support, release or authorization decision.";

fn header(ctx: &ReportContext<'_>, out: &mut String) {
    let _ = writeln!(out, "schema: {CHECK_SUMMARY_SCHEMA}");
    let _ = writeln!(out, "job: {}", ctx.job_id);
    let _ = writeln!(out, "commit: {}", ctx.commit.as_str());
    let _ = writeln!(out, "profile: {}", ctx.profile.id);
    let _ = writeln!(out, "run-class: {}", ctx.profile.class.as_str());
    let _ = writeln!(out, "engine: pii-eval {}", ctx.profile.engine_version);
    let _ = writeln!(
        out,
        "protocol: pii-v1 revision {}",
        ctx.profile.protocol_revision
    );
    let _ = writeln!(out, "config-digest: {}", ctx.profile.config_digest);
    let _ = writeln!(out, "population-digest: {}", ctx.profile.population_digest);
}

/// Final guard: printable ASCII and newlines only, bounded.
pub fn guard_text(text: &str) -> Result<(), ProjectionError> {
    if text.len() > MAX_SUMMARY_BYTES
        || !text
            .bytes()
            .all(|b| b == b'\n' || (0x20..0x7f).contains(&b))
    {
        return Err(ProjectionError("unsafe-output"));
    }
    Ok(())
}

fn finish(text: String) -> Result<String, ProjectionError> {
    guard_text(&text)?;
    Ok(text)
}

fn fixed(title: &str, conclusion: Conclusion, body: String) -> CheckReport {
    // A body that fails the guard falls back to a fixed text with no fields.
    let summary = finish(body).unwrap_or_else(|_| {
        format!("schema: {CHECK_SUMMARY_SCHEMA}\nstate: summary-unavailable\n{FOOTER}\n")
    });
    CheckReport {
        conclusion,
        output: CheckOutput {
            title: title.to_owned(),
            summary,
        },
    }
}

/// Report for a measurement. The run must report exactly the identities the
/// profile pins; any difference is an `identity-mismatch` report and none of the
/// run's values is shown.
pub fn report_measured(ctx: &ReportContext<'_>, m: &Measured) -> CheckReport {
    let p = ctx.profile;
    if !m.matches_profile(p) {
        return report_failure(ctx, FailureKind::IdentityMismatch);
    }
    let complete = m.exit_code == 0;
    let mut s = String::new();
    header(ctx, &mut s);
    let _ = writeln!(
        s,
        "state: {}",
        if complete { "complete" } else { "incomplete" }
    );
    let _ = writeln!(s, "completeness: {}", m.completeness);
    let _ = writeln!(s, "manifest-digest: {}", m.manifest_digest);
    let _ = writeln!(s, "run-artifact-digest: {}", m.run_artifact_digest);
    if let Some(d) = &m.public_artifact_digest {
        let _ = writeln!(s, "public-artifact-digest: {d}");
    }
    for (k, v) in &m.population_counts {
        let _ = writeln!(s, "count {k}: {v}");
    }
    for (id, status) in &m.scanners {
        let _ = writeln!(s, "scanner {id}: {status}");
    }
    if !m.failure_codes.is_empty() {
        let _ = writeln!(s, "failure-codes: {}", m.failure_codes.join(", "));
    }
    let _ = writeln!(s, "{FOOTER}");
    if complete {
        fixed(
            "PII evaluation: measurement complete",
            Conclusion::Success,
            s,
        )
    } else {
        fixed(
            "PII evaluation: measurement incomplete",
            Conclusion::Failure,
            s,
        )
    }
}

/// Report for a job that produced no measurement.
pub fn report_failure(ctx: &ReportContext<'_>, kind: FailureKind) -> CheckReport {
    let mut s = String::new();
    header(ctx, &mut s);
    let _ = writeln!(s, "state: failed");
    let _ = writeln!(s, "reason: {}", kind.code());
    let _ = writeln!(s, "{FOOTER}");
    fixed("PII evaluation: no measurement", kind.conclusion(), s)
}

/// Report for a result whose commit is no longer the head. It states the
/// identities of the request and nothing the run produced.
pub fn report_stale(ctx: &ReportContext<'_>) -> CheckReport {
    let mut s = String::new();
    header(ctx, &mut s);
    let _ = writeln!(s, "state: superseded");
    let _ = writeln!(s, "reason: stale-head");
    let _ = writeln!(s, "{FOOTER}");
    fixed(
        "PII evaluation: superseded by a newer commit",
        Conclusion::Neutral,
        s,
    )
}

/// The in-progress text of a started job.
pub fn report_started(ctx: &ReportContext<'_>) -> CheckOutput {
    let mut s = String::new();
    header(ctx, &mut s);
    let _ = writeln!(s, "state: running");
    let _ = writeln!(s, "{FOOTER}");
    fixed("PII evaluation: running", Conclusion::Neutral, s).output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::ProfileClass;

    pub(crate) fn profile() -> Profile {
        Profile {
            id: "public-default".into(),
            class: ProfileClass::PublicSynthetic,
            engine_version: "0.0.0".into(),
            protocol_revision: 2,
            config_digest: "1".repeat(64),
            population_digest: "2".repeat(64),
        }
    }

    fn line(code: u64, state: &str) -> String {
        format!(
            r#"{{"command":"run","engine":{{"name":"pii-eval","version":"0.0.0"}},"exit":{{"code":{code},"name":"x"}},"schema":"pii-eval-summary/1","semantic":{{"completeness":"full","failureCodes":[],"manifestDigest":"{m}","populationCounts":{{"authoredCases":3,"variants":9}},"populationDigest":"{p}","protocol":{{"id":"pii-v1","revision":2}},"publicArtifactDigest":"{a}","runArtifactDigest":"{r}","runClass":"public-synthetic","scanners":[{{"observationDigest":"{a}","scannerId":"redact-secret-core","status":"complete"}}]}},"state":"{state}"}}"#,
            m = "3".repeat(64),
            p = "2".repeat(64),
            a = "4".repeat(64),
            r = "5".repeat(64),
        )
    }

    fn ctx_parts() -> (JobId, CommitSha, Profile) {
        (
            JobId::parse(&"9".repeat(64)).unwrap(),
            CommitSha::parse(&"a".repeat(40)).unwrap(),
            profile(),
        )
    }

    #[test]
    fn a_complete_summary_renders_a_golden_text() {
        let (job, commit, profile) = ctx_parts();
        let ctx = ReportContext {
            job_id: &job,
            commit: &commit,
            profile: &profile,
        };
        let RunnerOutcome::Measured(m) =
            RunnerOutcome::from_summary_line(&line(0, "complete")).unwrap()
        else {
            panic!("measured")
        };
        let r = report_measured(&ctx, &m);
        assert_eq!(r.conclusion, Conclusion::Success);
        assert_eq!(r.output.title, "PII evaluation: measurement complete");
        let expected = format!(
            "schema: pii-eval-check-summary/1\njob: {j}\ncommit: {c}\nprofile: public-default\nrun-class: public-synthetic\nengine: pii-eval 0.0.0\nprotocol: pii-v1 revision 2\nconfig-digest: {d1}\npopulation-digest: {d2}\nstate: complete\ncompleteness: full\nmanifest-digest: {d3}\nrun-artifact-digest: {d5}\npublic-artifact-digest: {d4}\ncount authoredCases: 3\ncount variants: 9\nscanner redact-secret-core: complete\n{FOOTER}\n",
            j = "9".repeat(64),
            c = "a".repeat(40),
            d1 = "1".repeat(64),
            d2 = "2".repeat(64),
            d3 = "3".repeat(64),
            d4 = "4".repeat(64),
            d5 = "5".repeat(64),
        );
        assert_eq!(r.output.summary, expected);
    }

    #[test]
    fn an_incomplete_measurement_is_never_a_success() {
        let (job, commit, profile) = ctx_parts();
        let ctx = ReportContext {
            job_id: &job,
            commit: &commit,
            profile: &profile,
        };
        let RunnerOutcome::Measured(m) =
            RunnerOutcome::from_summary_line(&line(5, "incomplete")).unwrap()
        else {
            panic!("measured")
        };
        assert_eq!(report_measured(&ctx, &m).conclusion, Conclusion::Failure);
        assert!(RunnerOutcome::from_summary_line(&line(0, "incomplete")).is_err());
        assert!(RunnerOutcome::from_summary_line(&line(5, "complete")).is_err());
    }

    #[test]
    fn a_run_that_reports_another_identity_shows_none_of_its_values() {
        let (job, commit, profile) = ctx_parts();
        let ctx = ReportContext {
            job_id: &job,
            commit: &commit,
            profile: &profile,
        };
        let doc = line(0, "complete").replace(&"2".repeat(64), &"7".repeat(64));
        let RunnerOutcome::Measured(m) = RunnerOutcome::from_summary_line(&doc).unwrap() else {
            panic!("measured")
        };
        let r = report_measured(&ctx, &m);
        assert_eq!(r.conclusion, Conclusion::Failure);
        assert!(r.output.summary.contains("reason: identity-mismatch"));
        assert!(!r.output.summary.contains(&"7".repeat(64)));
        assert!(!r.output.summary.contains(&"5".repeat(64)));
    }

    #[test]
    fn other_exits_keep_only_a_closed_reason_token() {
        let doc = r#"{"command":"run","error":{"detail":"SENTINEL secret text","reason":"execution-refused"},"exit":{"code":6,"name":"execution-refused"},"schema":"pii-eval-summary/1","state":"error"}"#;
        assert_eq!(
            RunnerOutcome::from_summary_line(doc).unwrap(),
            RunnerOutcome::Failed {
                exit_code: 6,
                reason: "execution-refused".into()
            }
        );
        let doc = r#"{"command":"run","error":{"reason":"Bad Reason SENTINEL"},"exit":{"code":3,"name":"x"},"schema":"pii-eval-summary/1","state":"error"}"#;
        assert_eq!(
            RunnerOutcome::from_summary_line(doc).unwrap(),
            RunnerOutcome::Failed {
                exit_code: 3,
                reason: "unknown".into()
            }
        );
    }

    #[test]
    fn sentinels_in_any_field_reject_the_projection() {
        let good = line(0, "complete");
        let injections = [
            good.replace("redact-secret-core", "SENTINEL value"),
            good.replace("\"complete\"}]", "\"SENTINEL\\nvalue\"}]"),
            good.replace("\"full\"", "\"SENTINEL\""),
            good.replace("authoredCases", "SENTINEL-key"),
            good.replace(&"3".repeat(64), "SENTINEL"),
            good.replace(
                "\"failureCodes\":[]",
                "\"failureCodes\":[\"SENTINEL text\"]",
            ),
            good.replace("public-synthetic", "protected"),
            good.replace("\"version\":\"0.0.0\"", "\"version\":\"SENTINEL \\u0000\""),
            good.replace("pii-eval-summary/1", "pii-eval-summary/2"),
            good.replace("\"command\":\"run\"", "\"command\":\"validate\""),
        ];
        for (i, doc) in injections.iter().enumerate() {
            if *doc == good {
                continue;
            }
            assert!(
                RunnerOutcome::from_summary_line(doc).is_err(),
                "injection {i} was accepted"
            );
        }
        assert!(RunnerOutcome::from_summary_line("not json").is_err());
        assert!(RunnerOutcome::from_summary_line(&"x".repeat(MAX_RUNNER_LINE_BYTES + 1)).is_err());
    }

    #[test]
    fn unknown_fields_are_ignored_and_never_copied() {
        let doc = line(0, "complete").replace(
            "\"state\":\"complete\"",
            "\"state\":\"complete\",\"extra\":\"SENTINEL-extra\"",
        );
        let RunnerOutcome::Measured(m) = RunnerOutcome::from_summary_line(&doc).unwrap() else {
            panic!("measured")
        };
        let (job, commit, profile) = ctx_parts();
        let ctx = ReportContext {
            job_id: &job,
            commit: &commit,
            profile: &profile,
        };
        assert!(
            !report_measured(&ctx, &m)
                .output
                .summary
                .contains("SENTINEL")
        );
    }

    #[test]
    fn failure_and_stale_reports_are_fixed_text() {
        let (job, commit, profile) = ctx_parts();
        let ctx = ReportContext {
            job_id: &job,
            commit: &commit,
            profile: &profile,
        };
        let r = report_failure(&ctx, FailureKind::Timeout);
        assert_eq!(r.conclusion, Conclusion::TimedOut);
        assert!(r.output.summary.contains("reason: timeout"));
        let r = report_stale(&ctx);
        assert_eq!(r.conclusion, Conclusion::Neutral);
        assert!(r.output.summary.contains("state: superseded"));
        assert!(!r.output.summary.contains("run-artifact-digest"));
    }

    #[test]
    fn the_final_guard_rejects_non_ascii_and_overlong_text() {
        assert!(finish("ok\ntext".into()).is_ok());
        assert!(finish("caf\u{e9}".into()).is_err());
        assert!(finish("tab\there".into()).is_err());
        assert!(finish("x".repeat(MAX_SUMMARY_BYTES + 1)).is_err());
    }
}
