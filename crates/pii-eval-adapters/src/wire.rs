//! The Rust-to-shim JSON-lines protocol, `pii-eval-adapter/1`.
//!
//! One JSON object per line, UTF-8, LF terminated, over the shim's stdin
//! (Rust to shim) and stdout (shim to Rust). The full specification is in
//! `docs/adr/0006-scanner-adapter-boundary.md`.
//!
//! Rust to shim carries only run configuration and input text:
//!
//! ```text
//! {"type":"init","protocol":"pii-eval-adapter/1","activation":[...],"parameters":{...},
//!  "returnOutput":true,"limits":{"maxInputBytes":N,"maxFindings":N}}
//! {"type":"scan","seq":N,"text":"..."}
//! {"type":"shutdown"}
//! ```
//!
//! There is no field for an expected label, range, family, case identity,
//! variant identity or seed, and the encoders below take none. Shim to Rust:
//!
//! ```text
//! {"type":"ready","protocol":"...","scanner":{"id":"..","version":".."},
//!  "runtime":{"name":"node","version":".."},"activation":"..","offsetUnit":".."}
//! {"type":"result","seq":N,"findings":[{"start":N,"end":N,"type":"..","detector":"..","action":".."}],"output":".."}
//! {"type":"error","stage":"init"|"scan","code":"<fixed code>"}
//! ```
//!
//! Parsing is strict: duplicate keys, `null`, floats, negative zero, integers
//! above 2^53 - 1, unknown fields and wrong types are all malformed output.
//! Error messages are never accepted from the shim, only fixed codes.

use pii_eval_contracts::{ConfigParameter, ConfigValue, ParseLimits, parse_strict};
use serde_json::{Map, Value, json};

use crate::error::MalformedKind;
use crate::limits::AdapterLimits;
use crate::vocab::RawFinding;

/// Protocol identifier carried in `init` and `ready`.
pub const PROTOCOL: &str = "pii-eval-adapter/1";

/// Deepest JSON nesting a shim line may use. Messages nest at most 4 levels.
pub const MAX_LINE_DEPTH: usize = 8;

fn line(value: &Value) -> Vec<u8> {
    // Serializing a `Value` cannot fail: keys are strings and there are no NaN numbers.
    let mut bytes = serde_json::to_vec(value).unwrap_or_default();
    bytes.push(b'\n');
    bytes
}

/// The `init` line.
pub fn encode_init(
    activation: &[String],
    parameters: &[ConfigParameter],
    return_output: bool,
    limits: &AdapterLimits,
) -> Vec<u8> {
    let mut params = Map::new();
    for p in parameters {
        let value = match &p.value {
            ConfigValue::Bool(b) => Value::Bool(*b),
            ConfigValue::Integer(n) => Value::from(*n),
            ConfigValue::Text(t) => Value::String(t.clone()),
        };
        params.insert(p.key.as_str().to_owned(), value);
    }
    line(&json!({
        "type": "init",
        "protocol": PROTOCOL,
        "activation": activation,
        "parameters": Value::Object(params),
        "returnOutput": return_output,
        "limits": {
            "maxInputBytes": limits.max_text_bytes,
            "maxFindings": limits.max_findings,
        },
    }))
}

/// A `scan` line: the sequence number and the exact text, nothing else.
pub fn encode_scan(seq: u64, text: &str) -> Vec<u8> {
    line(&json!({ "type": "scan", "seq": seq, "text": text }))
}

/// The `shutdown` line.
pub fn encode_shutdown() -> Vec<u8> {
    line(&json!({ "type": "shutdown" }))
}

/// The shim's `ready` message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ready {
    /// Scanner identifier the shim reports.
    pub scanner_id: String,
    /// Scanner version the shim reports.
    pub scanner_version: String,
    /// Runtime name (for example `node`).
    pub runtime_name: String,
    /// Runtime version.
    pub runtime_version: String,
    /// The scanner's own activation identity string.
    pub activation: String,
    /// Wire name of the unit offsets are reported in.
    pub offset_unit: String,
}

/// The shim's `result` message.
#[derive(Clone, PartialEq, Eq)]
pub struct ScanResult {
    /// Sequence number of the `scan` this answers.
    pub seq: u64,
    /// Native findings.
    pub findings: Vec<RawFinding>,
    /// Sanitized output text, when the scanner produces it.
    pub output: Option<String>,
}

impl std::fmt::Debug for ScanResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The output text is derived from the input and must not reach logs.
        write!(
            f,
            "ScanResult(seq={}, findings={})",
            self.seq,
            self.findings.len()
        )
    }
}

/// Stage an `error` message refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorStage {
    /// Failure while initializing.
    Init,
    /// Failure while scanning.
    Scan,
}

/// Fixed error codes a shim may send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShimErrorCode {
    /// The scanner does not support a requested selector.
    UnsupportedSelector,
    /// The scanner rejected a selector as malformed.
    InvalidSelector,
    /// The scanner could not be loaded or initialized.
    InitializationFailed,
    /// A scan call failed.
    ScannerError,
    /// The scanner's own input limit was exceeded.
    InputLimit,
    /// The scanner's own finding limit was exceeded.
    FindingLimit,
    /// The shim could not parse a line from Rust.
    ProtocolError,
}

impl ShimErrorCode {
    fn from_wire(s: &str) -> Option<Self> {
        Some(match s {
            "unsupported-selector" => Self::UnsupportedSelector,
            "invalid-selector" => Self::InvalidSelector,
            "initialization-failed" => Self::InitializationFailed,
            "scanner-error" => Self::ScannerError,
            "input-limit" => Self::InputLimit,
            "finding-limit" => Self::FindingLimit,
            "protocol-error" => Self::ProtocolError,
            _ => return None,
        })
    }
}

/// The shim's `error` message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShimError {
    /// Stage.
    pub stage: ErrorStage,
    /// Sequence number when the error answers a scan.
    pub seq: Option<u64>,
    /// Fixed code.
    pub code: ShimErrorCode,
}

/// One decoded shim line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Incoming {
    /// `ready`.
    Ready(Ready),
    /// `result`.
    Result(ScanResult),
    /// `error`.
    Error(ShimError),
}

/// Number of `"start":` keys in a raw line, an upper bound on its findings
/// that costs one pass and allocates nothing. A finding object has exactly one
/// such key and no other part of a valid line contains the byte sequence
/// unescaped (a quote inside a JSON string is always preceded by a backslash),
/// so a line with more of them than the findings limit is refused before the
/// parse tree is built.
pub fn count_finding_keys(line: &[u8]) -> usize {
    const KEY: &[u8] = b"\"start\":";
    line.windows(KEY.len()).filter(|w| *w == KEY).count()
}

fn check_fields(
    map: &Map<String, Value>,
    required: &[&str],
    optional: &[&str],
) -> Result<(), MalformedKind> {
    if map
        .keys()
        .any(|k| !required.contains(&k.as_str()) && !optional.contains(&k.as_str()))
    {
        return Err(MalformedKind::UnknownField);
    }
    if required.iter().any(|k| !map.contains_key(*k)) {
        return Err(MalformedKind::Structure);
    }
    Ok(())
}

fn string(map: &Map<String, Value>, key: &str) -> Result<String, MalformedKind> {
    match map.get(key) {
        Some(Value::String(s)) => Ok(s.clone()),
        _ => Err(MalformedKind::WrongType),
    }
}

fn unsigned(map: &Map<String, Value>, key: &str) -> Result<u64, MalformedKind> {
    map.get(key)
        .and_then(Value::as_u64)
        .ok_or(MalformedKind::WrongType)
}

fn object<'a>(
    map: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a Map<String, Value>, MalformedKind> {
    match map.get(key) {
        Some(Value::Object(o)) => Ok(o),
        _ => Err(MalformedKind::WrongType),
    }
}

fn decode_finding(value: &Value) -> Result<RawFinding, MalformedKind> {
    let Value::Object(map) = value else {
        return Err(MalformedKind::WrongType);
    };
    check_fields(map, &["start", "end", "type", "detector"], &["action"])?;
    let action = match map.get("action") {
        None => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return Err(MalformedKind::WrongType),
    };
    Ok(RawFinding {
        start: unsigned(map, "start")?,
        end: unsigned(map, "end")?,
        kind: string(map, "type")?,
        detector: string(map, "detector")?,
        action,
    })
}

/// Decode one line (without its LF). `expect_output` is whether the adapter
/// asked the shim for sanitized output; a `result` must carry `output` exactly
/// when it did.
pub fn decode(bytes: &[u8], expect_output: bool) -> Result<Incoming, MalformedKind> {
    if std::str::from_utf8(bytes).is_err() {
        return Err(MalformedKind::NotUtf8);
    }
    let limits = ParseLimits {
        max_bytes: bytes.len(),
        max_depth: MAX_LINE_DEPTH,
    };
    let value = parse_strict(bytes, &limits).map_err(|_| MalformedKind::NotJson)?;
    let Value::Object(map) = value else {
        return Err(MalformedKind::Structure);
    };
    match map.get("type").and_then(Value::as_str) {
        Some("ready") => {
            check_fields(
                &map,
                &[
                    "type",
                    "protocol",
                    "scanner",
                    "runtime",
                    "activation",
                    "offsetUnit",
                ],
                &[],
            )?;
            if string(&map, "protocol")? != PROTOCOL {
                return Err(MalformedKind::UnexpectedMessage);
            }
            let scanner = object(&map, "scanner")?;
            check_fields(scanner, &["id", "version"], &[])?;
            let runtime = object(&map, "runtime")?;
            check_fields(runtime, &["name", "version"], &[])?;
            Ok(Incoming::Ready(Ready {
                scanner_id: string(scanner, "id")?,
                scanner_version: string(scanner, "version")?,
                runtime_name: string(runtime, "name")?,
                runtime_version: string(runtime, "version")?,
                activation: string(&map, "activation")?,
                offset_unit: string(&map, "offsetUnit")?,
            }))
        }
        Some("result") => {
            check_fields(&map, &["type", "seq", "findings"], &["output"])?;
            let Some(Value::Array(items)) = map.get("findings") else {
                return Err(MalformedKind::WrongType);
            };
            let output = match (map.get("output"), expect_output) {
                (Some(Value::String(s)), true) => Some(s.clone()),
                (None, false) => None,
                (Some(Value::String(_)), false) | (None, true) => {
                    return Err(MalformedKind::Output);
                }
                (Some(_), _) => return Err(MalformedKind::WrongType),
            };
            let findings = items
                .iter()
                .map(decode_finding)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Incoming::Result(ScanResult {
                seq: unsigned(&map, "seq")?,
                findings,
                output,
            }))
        }
        Some("error") => {
            check_fields(&map, &["type", "stage", "code"], &["seq"])?;
            let stage = match string(&map, "stage")?.as_str() {
                "init" => ErrorStage::Init,
                "scan" => ErrorStage::Scan,
                _ => return Err(MalformedKind::Structure),
            };
            let seq = match map.get("seq") {
                None => None,
                Some(_) => Some(unsigned(&map, "seq")?),
            };
            let code = ShimErrorCode::from_wire(&string(&map, "code")?)
                .ok_or(MalformedKind::UnknownErrorCode)?;
            Ok(Incoming::Error(ShimError { stage, seq, code }))
        }
        Some(_) => Err(MalformedKind::UnexpectedMessage),
        None => Err(MalformedKind::Structure),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pii_eval_contracts::ConfigKey;

    fn keys(bytes: &[u8]) -> Vec<String> {
        let v: Value = serde_json::from_slice(bytes).expect("json");
        let mut k: Vec<String> = v.as_object().expect("object").keys().cloned().collect();
        k.sort();
        k
    }

    #[test]
    fn rust_to_shim_messages_carry_only_text_and_configuration() {
        let scan = encode_scan(7, "text");
        assert!(scan.ends_with(b"\n"));
        assert_eq!(keys(&scan), ["seq", "text", "type"]);
        let init = encode_init(
            &["pii:global".to_owned()],
            &[ConfigParameter {
                key: ConfigKey::new("mode").unwrap(),
                value: ConfigValue::Text("x".into()),
            }],
            true,
            &AdapterLimits::default(),
        );
        assert_eq!(
            keys(&init),
            [
                "activation",
                "limits",
                "parameters",
                "protocol",
                "returnOutput",
                "type"
            ]
        );
        assert_eq!(keys(&encode_shutdown()), ["type"]);
    }

    #[test]
    fn finding_keys_are_counted_without_parsing_and_escaped_text_is_not_counted() {
        let line = br#"{"type":"result","seq":1,"findings":[{"start":0,"end":1,"type":"t","detector":"d"},{"start":2,"end":3,"type":"t","detector":"d"}],"output":"x \"start\": y"}"#;
        assert_eq!(count_finding_keys(line), 2);
        assert!(matches!(decode(line, true), Ok(Incoming::Result(r)) if r.findings.len() == 2));
        assert_eq!(count_finding_keys(b""), 0);
    }

    #[test]
    fn decodes_a_result_and_rejects_every_malformed_shape() {
        let ok = br#"{"type":"result","seq":1,"findings":[{"start":0,"end":3,"type":"t","detector":"d","action":"redact"}],"output":"x"}"#;
        let Incoming::Result(r) = decode(ok, true).unwrap() else {
            panic!("result")
        };
        assert_eq!((r.seq, r.findings.len()), (1, 1));
        // Output must appear exactly when requested.
        assert_eq!(decode(ok, false), Err(MalformedKind::Output));
        let no_out = br#"{"type":"result","seq":1,"findings":[]}"#;
        assert_eq!(decode(no_out, true), Err(MalformedKind::Output));

        let cases: [(&[u8], MalformedKind); 9] = [
            (b"{nope", MalformedKind::NotJson),
            (b"\xff\xfe", MalformedKind::NotUtf8),
            (b"[]", MalformedKind::Structure),
            (
                br#"{"type":"result","seq":1,"seq":2,"findings":[]}"#,
                MalformedKind::NotJson,
            ),
            (
                br#"{"type":"result","seq":null,"findings":[]}"#,
                MalformedKind::NotJson,
            ),
            (
                br#"{"type":"result","seq":1.5,"findings":[]}"#,
                MalformedKind::NotJson,
            ),
            (
                br#"{"type":"result","seq":-1,"findings":[]}"#,
                MalformedKind::WrongType,
            ),
            (
                br#"{"type":"result","seq":1,"findings":[],"message":"x"}"#,
                MalformedKind::UnknownField,
            ),
            (
                br#"{"type":"error","stage":"scan","code":"boom"}"#,
                MalformedKind::UnknownErrorCode,
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(decode(input, false), Err(expected));
        }
    }
}
