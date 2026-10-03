//! The stdout summary (`pii-eval-summary/1`): one line of JSON per invocation.
//!
//! Shape (docs/cli.md): `schema`, `command` (when known), `engine`, `exit`
//! (`code`, `name`), `state`, `error` (reason, detail, contract codes; present
//! when the exit is not success), `semantic` (deterministic: digests, statuses,
//! counts; no timestamps, durations or paths) and `outputs` (written file
//! names, sizes and digests). Objects are ordered maps, so keys are always in
//! ascending order and the same inputs give the same bytes. Integers only.

use pii_eval_contracts::{ENGINE_NAME, ENGINE_VERSION};
use serde_json::{Map, Value, json};

use crate::status::{Exit, Failure};

/// `schema` of the summary.
pub const SUMMARY_SCHEMA: &str = "pii-eval-summary/1";

/// What a command that ran to a conclusion reports. A non-success `exit` here
/// (scanner failure, not verifiable) still carries a full semantic body.
#[derive(Debug, Clone)]
pub struct Report {
    /// Exit status.
    pub exit: Exit,
    /// Command-specific closed state, for example `complete`, `incomplete`.
    pub state: &'static str,
    /// Reason code when the exit is not success.
    pub reason: Option<&'static str>,
    /// The deterministic body.
    pub semantic: Value,
    /// Written files, for commands that write.
    pub outputs: Option<Value>,
}

/// The rendered result of one invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    /// Exit status.
    pub exit: Exit,
    /// Standard output: the summary line.
    pub stdout: String,
    /// Standard error: a fixed-vocabulary diagnostic (empty on success).
    pub stderr: String,
}

fn envelope(command: Option<&str>, exit: Exit, state: &str) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("schema".into(), json!(SUMMARY_SCHEMA));
    if let Some(c) = command {
        m.insert("command".into(), json!(c));
    }
    m.insert(
        "engine".into(),
        json!({"name": ENGINE_NAME, "version": ENGINE_VERSION}),
    );
    m.insert(
        "exit".into(),
        json!({"code": exit.code(), "name": exit.name()}),
    );
    m.insert("state".into(), json!(state));
    m
}

fn error_object(f: &Failure) -> Value {
    let mut e = Map::new();
    e.insert("reason".into(), json!(f.reason));
    if let Some(d) = &f.detail {
        e.insert("detail".into(), json!(d));
    }
    if !f.codes.is_empty() {
        e.insert("codes".into(), json!(f.codes));
    }
    Value::Object(e)
}

/// Render a command result.
pub fn render(command: Option<&str>, result: Result<Report, Failure>) -> Rendered {
    match result {
        Ok(report) => {
            let mut m = envelope(command, report.exit, report.state);
            let mut stderr = String::new();
            if let Some(reason) = report.reason {
                m.insert("error".into(), json!({"reason": reason}));
                stderr = format!(
                    "pii-eval: {reason} ({}, exit {})\n",
                    report.exit.name(),
                    report.exit.code()
                );
            }
            m.insert("semantic".into(), report.semantic);
            if let Some(o) = report.outputs {
                m.insert("outputs".into(), o);
            }
            finish(report.exit, m, stderr)
        }
        Err(failure) => {
            let mut m = envelope(command, failure.exit, "error");
            m.insert("error".into(), error_object(&failure));
            let stderr = format!("{}\n", failure.human());
            finish(failure.exit, m, stderr)
        }
    }
}

fn finish(exit: Exit, m: Map<String, Value>, stderr: String) -> Rendered {
    let mut stdout = Value::Object(m).to_string();
    stdout.push('\n');
    Rendered {
        exit,
        stdout,
        stderr,
    }
}

/// `{"files":[{"bytes":..,"name":..,"sha256":..}]}` for written files.
pub fn files_value(files: &[crate::write::WrittenFile]) -> Value {
    json!({
        "files": files
            .iter()
            .map(|f| json!({"bytes": f.bytes, "name": f.name, "sha256": f.sha256.as_str()}))
            .collect::<Vec<_>>()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::reason;

    #[test]
    fn success_and_failure_summaries_have_sorted_keys_and_no_paths() {
        let ok = render(
            Some("validate"),
            Ok(Report {
                exit: Exit::Success,
                state: "valid",
                reason: None,
                semantic: json!({"z": 1, "a": 2}),
                outputs: None,
            }),
        );
        assert_eq!(
            ok.stdout,
            format!(
                "{{\"command\":\"validate\",\"engine\":{{\"name\":\"{ENGINE_NAME}\",\"version\":\"{ENGINE_VERSION}\"}},\"exit\":{{\"code\":0,\"name\":\"success\"}},\"schema\":\"pii-eval-summary/1\",\"semantic\":{{\"a\":2,\"z\":1}},\"state\":\"valid\"}}\n"
            )
        );
        assert!(ok.stderr.is_empty());
        let err = render(
            None,
            Err(Failure::new(Exit::Usage, reason::UNKNOWN_COMMAND).with_detail("command")),
        );
        assert_eq!(err.exit, Exit::Usage);
        assert!(err.stdout.contains("\"state\":\"error\""));
        assert!(err.stdout.contains("\"reason\":\"unknown-command\""));
        assert!(!err.stdout.contains("\"command\":"));
        assert!(err.stderr.starts_with("pii-eval: unknown-command"));
    }
}
