//! The custodian's job and result documents (Decided: A4, A5).
//!
//! Job (`private-custodian.worker-job/1`, read from `/job/job.json`):
//! `{schema, domain, protocol{name,version}, roster, entries[]}`, closed. The
//! engine checks: strict JSON with no duplicate key, at most
//! [`MAX_JOB_BYTES`], domain `pii`, the protocol this engine supports, roster
//! equal to the number of entries, entry names in the custodian's pattern, no
//! duplicate name, between 1 and [`MAX_ENTRIES`] entries.
//!
//! Result (`private-custodian.worker-result/1`, printed on stdout): closed,
//! single-line, at most [`MAX_RESULT_BYTES`].

use std::path::Path;

use pii_eval_contracts::{PROTOCOL_ID, PROTOCOL_VERSION, ParseLimits, parse_strict};
use serde_json::{Map, Value, json};

use crate::status::{Exit, Failure};
use crate::worker::reason;

/// `schema` of the job document.
pub const JOB_SCHEMA: &str = "private-custodian.worker-job/1";
/// `schema` of the result document.
pub const RESULT_SCHEMA: &str = "private-custodian.worker-result/1";
/// The domain of this engine.
pub const DOMAIN: &str = "pii";
/// Largest job document, in bytes.
pub const MAX_JOB_BYTES: usize = 1 << 20;
/// Most entries one job may list. Above it the launcher refuses
/// (`entries-too-many`); the limit is the engine's, the custodian states none.
pub const MAX_ENTRIES: usize = 10_000;
/// Largest result document (A5).
pub const MAX_RESULT_BYTES: usize = 64 * 1024;
/// Longest entry name (A3).
pub const MAX_ENTRY_NAME_BYTES: usize = 64;

/// A parsed, checked job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    /// Entry names, sorted ascending (byte order), unique.
    pub entries: Vec<String>,
}

/// The protocol name this engine supports, from the contracts.
pub fn protocol_name() -> &'static str {
    PROTOCOL_ID
}

/// The protocol version label this engine supports, from the contracts.
pub fn protocol_version() -> String {
    PROTOCOL_VERSION.to_string()
}

/// A custodian label: `[a-z0-9][a-z0-9._-]{0,63}` (A3, A10).
pub fn is_label(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=MAX_ENTRY_NAME_BYTES).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
        })
}

/// An entry name: a label without `..` (the custodian's `validate_flat_name`).
pub fn is_entry_name(s: &str) -> bool {
    is_label(s) && !s.contains("..")
}

fn closed<'a>(v: &'a Value, keys: &[&str]) -> Option<&'a Map<String, Value>> {
    let m = v.as_object()?;
    (m.len() == keys.len() && keys.iter().all(|k| m.contains_key(*k))).then_some(m)
}

/// Read a regular file of at most `max` bytes (symlink followed: the job path
/// is the custodian's argument).
pub fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>, ReadFailure> {
    use std::io::Read;
    let meta = std::fs::metadata(path).map_err(|_| ReadFailure::Unreadable)?;
    if !meta.is_file() {
        return Err(ReadFailure::Unreadable);
    }
    if meta.len() > max as u64 {
        return Err(ReadFailure::TooLarge);
    }
    let file = std::fs::File::open(path).map_err(|_| ReadFailure::Unreadable)?;
    let mut bytes = Vec::new();
    file.take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ReadFailure::Unreadable)?;
    if bytes.len() > max {
        return Err(ReadFailure::TooLarge);
    }
    Ok(bytes)
}

/// Why a bounded read failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadFailure {
    /// Missing, not a regular file, or unreadable.
    Unreadable,
    /// Over the bound.
    TooLarge,
}

/// Read and check the job document at `path`.
pub fn read_job(path: &Path) -> Result<Job, Failure> {
    let bytes = read_bounded(path, MAX_JOB_BYTES).map_err(|e| match e {
        ReadFailure::Unreadable => reason::invalid(reason::JOB_UNREADABLE, ""),
        ReadFailure::TooLarge => reason::invalid(reason::JOB_TOO_LARGE, ""),
    })?;
    parse_job(&bytes)
}

/// Check the bytes of a job document.
pub fn parse_job(bytes: &[u8]) -> Result<Job, Failure> {
    let invalid = |detail: &str| reason::invalid(reason::JOB_INVALID, detail);
    let value = parse_strict(
        bytes,
        &ParseLimits {
            max_bytes: MAX_JOB_BYTES,
            max_depth: 8,
        },
    )
    .map_err(|_| invalid("json"))?;
    let top = closed(
        &value,
        &["schema", "domain", "protocol", "roster", "entries"],
    )
    .ok_or_else(|| invalid("shape"))?;
    if top["schema"].as_str() != Some(JOB_SCHEMA) {
        return Err(invalid("schema"));
    }
    if top["domain"].as_str() != Some(DOMAIN) {
        return Err(reason::mismatch(reason::JOB_DOMAIN_MISMATCH, ""));
    }
    let protocol =
        closed(&top["protocol"], &["name", "version"]).ok_or_else(|| invalid("protocol"))?;
    if protocol["name"].as_str() != Some(protocol_name())
        || protocol["version"].as_str() != Some(protocol_version().as_str())
    {
        return Err(reason::mismatch(reason::JOB_PROTOCOL_MISMATCH, "job"));
    }
    let roster = top["roster"].as_u64().ok_or_else(|| invalid("roster"))?;
    let list = top["entries"]
        .as_array()
        .ok_or_else(|| invalid("entries"))?;
    if list.len() > MAX_ENTRIES {
        return Err(reason::invalid(reason::ENTRIES_TOO_MANY, ""));
    }
    let mut entries = Vec::with_capacity(list.len());
    for item in list {
        let name = item.as_str().filter(|n| is_entry_name(n));
        entries.push(
            name.ok_or_else(|| reason::invalid(reason::ENTRY_NAME_INVALID, ""))?
                .to_owned(),
        );
    }
    if roster != entries.len() as u64 {
        return Err(reason::invalid(reason::ROSTER_MISMATCH, ""));
    }
    if entries.is_empty() {
        return Err(invalid("entries-empty"));
    }
    entries.sort_unstable();
    if entries.windows(2).any(|w| w[0] == w[1]) {
        return Err(reason::invalid(reason::ENTRIES_DUPLICATE, ""));
    }
    Ok(Job { entries })
}

/// The roster counters of a result (A5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Roster {
    /// Entries the custodian authorized.
    pub expected: u64,
    /// Entries the engine read.
    pub observed: u64,
    /// Observed entries without a complete measurement.
    pub failed: u64,
}

impl Roster {
    /// `complete` exactly when every authorized entry was observed. The
    /// custodian rejects a `partial` whose counters say `observed == expected`
    /// and a `complete` whose counters say otherwise (A5), so the status is a
    /// function of coverage and never of `failed`; failed items make the
    /// custodian's outcome `Partial` on their own (A6).
    pub fn status(&self) -> &'static str {
        if self.observed == self.expected {
            "complete"
        } else {
            "partial"
        }
    }

    /// The roster as the closed JSON object.
    pub fn to_value(&self) -> Value {
        json!({"expected": self.expected, "observed": self.observed, "failed": self.failed})
    }
}

/// The protocol object shared by the result and aggregates documents.
pub fn protocol_value() -> Value {
    json!({"name": protocol_name(), "version": protocol_version()})
}

/// The result document, single line, no trailing newline. Refuses (never
/// truncates) above [`MAX_RESULT_BYTES`].
pub fn render_result(roster: &Roster) -> Result<String, Failure> {
    render_result_with_aggregates(roster, None)
}

/// Embed the aggregate object and bound the ENTIRE stdout document.
pub fn render_result_with_aggregates(
    roster: &Roster,
    aggregates: Option<&[u8]>,
) -> Result<String, Failure> {
    let mut value = json!({
        "schema": RESULT_SCHEMA,
        "domain": DOMAIN,
        "protocol": protocol_value(),
        "status": roster.status(),
        "roster": roster.to_value(),
    });
    if let Some(bytes) = aggregates {
        let object: Value = serde_json::from_slice(bytes)
            .map_err(|_| Failure::new(Exit::Output, reason::AGGREGATES_CHANNEL_FAILED))?;
        if !object.is_object() {
            return Err(Failure::new(
                Exit::Output,
                reason::AGGREGATES_CHANNEL_FAILED,
            ));
        }
        value["aggregates"] = object;
    }
    let text = value.to_string();
    if text.len() > MAX_RESULT_BYTES {
        return Err(Failure::new(Exit::Output, reason::RESULT_TOO_LARGE));
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(extra: &str) -> String {
        format!(
            r#"{{"schema":"{JOB_SCHEMA}","domain":"pii","protocol":{{"name":"pii-v1","version":"2"}},"roster":2,"entries":["b-1","a-1"]{extra}}}"#
        )
    }

    #[test]
    fn a_valid_job_is_accepted_and_entries_are_sorted() {
        let j = parse_job(job("").as_bytes()).unwrap();
        assert_eq!(j.entries, ["a-1", "b-1"]);
    }

    #[test]
    fn hostile_jobs_are_refused_with_fixed_reasons() {
        let secret = "zq-secret-7731";
        let cases: Vec<(String, &str)> = vec![
            (job(&format!(r#","{secret}":1"#)), reason::JOB_INVALID),
            (
                job("").replace("\"pii\"", "\"credential\""),
                reason::JOB_DOMAIN_MISMATCH,
            ),
            (
                job("").replace("\"2\"", "\"3\""),
                reason::JOB_PROTOCOL_MISMATCH,
            ),
            (
                job("").replace("pii-v1", "other"),
                reason::JOB_PROTOCOL_MISMATCH,
            ),
            (
                job("").replace("\"roster\":2", "\"roster\":3"),
                reason::ROSTER_MISMATCH,
            ),
            (
                job("").replace("\"b-1\"", "\"A-1\""),
                reason::ENTRY_NAME_INVALID,
            ),
            (
                job("").replace("\"b-1\"", "\"../x\""),
                reason::ENTRY_NAME_INVALID,
            ),
            (
                job("").replace("\"b-1\"", "\"a-1\""),
                reason::ENTRIES_DUPLICATE,
            ),
            (
                job("").replace(JOB_SCHEMA, "private-custodian.worker-job/2"),
                reason::JOB_INVALID,
            ),
            (
                job("").replace("\"roster\":2,", "\"roster\":2,\"roster\":2,"),
                reason::JOB_INVALID,
            ),
            (
                job("").replace("\"roster\":2", "\"roster\":2.0"),
                reason::JOB_INVALID,
            ),
            ("null".to_owned(), reason::JOB_INVALID),
            (
                job("")
                    .replace("[\"b-1\",\"a-1\"]", "[]")
                    .replace("\"roster\":2", "\"roster\":0"),
                reason::JOB_INVALID,
            ),
        ];
        for (text, expected) in cases {
            let f = parse_job(text.as_bytes()).unwrap_err();
            assert_eq!(f.reason, expected, "{text}");
            assert!(!f.human().contains(secret));
        }
    }

    #[test]
    fn too_many_entries_fail_closed() {
        let names: Vec<String> = (0..=MAX_ENTRIES).map(|i| format!("\"e{i}\"")).collect();
        let text = format!(
            r#"{{"schema":"{JOB_SCHEMA}","domain":"pii","protocol":{{"name":"pii-v1","version":"2"}},"roster":{},"entries":[{}]}}"#,
            names.len(),
            names.join(",")
        );
        assert!(text.len() < MAX_JOB_BYTES);
        assert_eq!(
            parse_job(text.as_bytes()).unwrap_err().reason,
            reason::ENTRIES_TOO_MANY
        );
    }

    #[test]
    fn the_status_follows_coverage_not_failures() {
        let r = |expected, observed, failed| Roster {
            expected,
            observed,
            failed,
        };
        assert_eq!(r(5, 5, 0).status(), "complete");
        assert_eq!(r(5, 5, 5).status(), "complete");
        assert_eq!(r(5, 3, 0).status(), "partial");
    }

    #[test]
    fn the_result_is_one_closed_line() {
        let text = render_result(&Roster {
            expected: 2,
            observed: 2,
            failed: 0,
        })
        .unwrap();
        assert_eq!(
            text,
            r#"{"domain":"pii","protocol":{"name":"pii-v1","version":"2"},"roster":{"expected":2,"failed":0,"observed":2},"schema":"private-custodian.worker-result/1","status":"complete"}"#
        );
        assert!(!text.contains('\n'));
    }
    #[test]
    fn embedded_aggregates_are_one_object_and_whole_output_is_bounded() {
        let r = Roster {
            expected: 3,
            observed: 3,
            failed: 0,
        };
        let text = render_result_with_aggregates(
            &r,
            Some(br#"{"schema":"private-custodian.aggregates/1"}"#),
        )
        .unwrap();
        let value: Value = serde_json::from_str(&text).unwrap();
        assert!(value["aggregates"].is_object());
        assert!(!text.contains('\n'));
        assert!(render_result_with_aggregates(&r, Some(br#""not-an-object""#)).is_err());
        let huge = json!({"padding": "x".repeat(MAX_RESULT_BYTES)}).to_string();
        assert_eq!(
            render_result_with_aggregates(&r, Some(huge.as_bytes()))
                .unwrap_err()
                .reason,
            reason::RESULT_TOO_LARGE
        );
    }
}
