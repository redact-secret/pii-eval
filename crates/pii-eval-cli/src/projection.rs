//! The caller's projection roster file (`pii-eval-projection-roster/1`) and its
//! check against a snapshot (ADR 0016).
//!
//! The roster is external input: which views a run requires, which authored case
//! belongs to which view, and optionally an opaque control class for some cases.
//! The engine holds no view policy. The file is strict JSON with closed fields;
//! errors name a field, never a value.
//!
//! ```json
//! {
//!   "schema": "pii-eval-projection-roster/1",
//!   "requiredViews": ["oracle-plan", "qualification-plan"],
//!   "views": [
//!     {"view": "oracle-plan", "cases": ["case-a", "case-b"]},
//!     {"view": "qualification-plan", "cases": ["case-c"]}
//!   ],
//!   "controlClasses": [{"class": "placeholder", "cases": ["case-b"]}]
//! }
//! ```

use std::path::Path;

use pii_eval_contracts::{
    CorpusSnapshot, Id, ParseLimits, ProjectionMode, ProjectionView, Sha256Digest, parse_strict,
};
use pii_eval_kernel::ProjectionRoster;
use serde_json::Value;

use crate::assemble::ProjectionRequest;
use crate::config::Mode;
use crate::files::read_input;
use crate::status::{Exit, Failure, reason};

/// `schema` of a projection roster file.
pub const ROSTER_SCHEMA: &str = "pii-eval-projection-roster/1";

/// Largest roster file: it lists every case id of a population.
pub const MAX_ROSTER_BYTES: usize = pii_eval_contracts::limits::MAX_DOCUMENT_BYTES;

fn invalid(field: &str) -> Failure {
    Failure::new(Exit::Invalid, reason::CONFIG_INVALID)
        .with_detail(format!("projection-roster {field}"))
}

fn closed<'a>(
    value: &'a Value,
    at: &str,
    allowed: &[&str],
) -> Result<&'a serde_json::Map<String, Value>, Failure> {
    let map = value.as_object().ok_or_else(|| invalid(at))?;
    if map.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(invalid(&format!("{at} (unknown field)")));
    }
    Ok(map)
}

fn case_list(value: &Value, at: &str) -> Result<Vec<Id>, Failure> {
    value
        .as_array()
        .ok_or_else(|| invalid(at))?
        .iter()
        .map(|v| {
            v.as_str()
                .and_then(|s| Id::new(s).ok())
                .ok_or_else(|| invalid(at))
        })
        .collect()
}

/// The run mode of the configuration as the projection's mode.
pub fn projection_mode(mode: Mode) -> ProjectionMode {
    match mode {
        Mode::Official => ProjectionMode::Official,
        Mode::Exploratory => ProjectionMode::Exploratory,
    }
}

/// Parse a roster file and check it against `snapshot`. `pin` is the digest the
/// configuration pinned, if any (checked against the roster's own digest).
pub fn load_roster(
    path: &Path,
    snapshot: &CorpusSnapshot,
    pin: Option<&Sha256Digest>,
) -> Result<ProjectionRoster, Failure> {
    let bytes = read_input(path, MAX_ROSTER_BYTES, "projection-roster")?;
    let value = parse_strict(
        &bytes,
        &ParseLimits {
            max_bytes: MAX_ROSTER_BYTES,
            max_depth: 8,
        },
    )
    .map_err(|e| {
        Failure::new(Exit::Invalid, reason::CONFIG_INVALID)
            .with_detail("projection-roster")
            .with_codes([e.code])
    })?;
    let top = closed(
        &value,
        "",
        &["schema", "requiredViews", "views", "controlClasses"],
    )?;
    if top.get("schema").and_then(Value::as_str) != Some(ROSTER_SCHEMA) {
        return Err(invalid("schema"));
    }
    let view_of = |v: &Value, at: &str| -> Result<ProjectionView, Failure> {
        serde_json::from_value::<ProjectionView>(v.clone()).map_err(|_| invalid(at))
    };
    let required = top
        .get("requiredViews")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("requiredViews"))?
        .iter()
        .map(|v| view_of(v, "requiredViews"))
        .collect::<Result<Vec<_>, _>>()?;
    let mut views: Vec<(Id, ProjectionView)> = Vec::new();
    for entry in top
        .get("views")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("views"))?
    {
        let f = closed(entry, "views[]", &["view", "cases"])?;
        let view = view_of(
            f.get("view").ok_or_else(|| invalid("views[].view"))?,
            "views[].view",
        )?;
        for case in case_list(
            f.get("cases").ok_or_else(|| invalid("views[].cases"))?,
            "views[].cases",
        )? {
            views.push((case, view));
        }
    }
    let mut control: Vec<(Id, Id)> = Vec::new();
    if let Some(list) = top.get("controlClasses") {
        for entry in list.as_array().ok_or_else(|| invalid("controlClasses"))? {
            let f = closed(entry, "controlClasses[]", &["class", "cases"])?;
            let class = f
                .get("class")
                .and_then(Value::as_str)
                .and_then(|s| Id::new(s).ok())
                .ok_or_else(|| invalid("controlClasses[].class"))?;
            for case in case_list(
                f.get("cases")
                    .ok_or_else(|| invalid("controlClasses[].cases"))?,
                "controlClasses[].cases",
            )? {
                control.push((case, class.clone()));
            }
        }
    }
    let roster =
        ProjectionRoster::new(&snapshot.semantic, &required, &views, &control).map_err(|_| {
            Failure::new(Exit::Invalid, reason::DOCUMENT_INVALID).with_detail("projection-roster")
        })?;
    if pin.is_some_and(|p| p != roster.digest()) {
        return Err(Failure::provenance("projection-roster-digest"));
    }
    Ok(roster)
}

/// The roster and the mode as the request the assembler takes.
pub fn request(roster: ProjectionRoster, mode: Mode) -> ProjectionRequest {
    ProjectionRequest {
        roster,
        mode: projection_mode(mode),
    }
}
