//! `pii-eval-worker-entry/1`: one input entry is one authored case with its
//! variants and expectations (PROPOSED, engine-owned, opaque to the custodian;
//! Q1).
//!
//! ```json
//! {"schema": "pii-eval-worker-entry/1", "case": { ...the contracts' Case... }}
//! ```
//!
//! Closed: exactly these two keys, and the case in the contracts' own shape
//! (which denies unknown fields). **Naming rule:** the entry's file name is the
//! case's identifier, byte for byte. A case identifier is `[a-z][a-z0-9-]{1,79}`
//! (already lower case); the custodian's entry name is `[a-z0-9][a-z0-9._-]{0,63}`
//! without `..`, so a case whose identifier is longer than 64 bytes cannot be an
//! entry and is refused as `entry-invalid`. Because names are ascending case
//! identifiers, sorting entries by name is the snapshot's canonical case order.
//!
//! Nothing about an entry is validated by trusting its text: it is parsed
//! strictly, its case is validated by the contracts' own validator in a
//! one-case snapshot sealed under the configured header, and the whole
//! assembled snapshot is validated again before any scanner runs.

use pii_eval_contracts::{
    Case, CorpusSnapshot, CorpusSnapshotBody, GenerationRules, ParseLimits, Population,
    parse_strict, seal, validate,
};
use serde_json::{Value, json};

use crate::worker::contract::EntryError;
use crate::worker::job::is_entry_name;

/// `schema` of an entry.
pub const ENTRY_SCHEMA: &str = "pii-eval-worker-entry/1";
/// Largest entry, in bytes (A3).
pub const MAX_ENTRY_BYTES: usize = 16 * 1024 * 1024;
/// Most bytes of all entries together: the contracts' document bound, so the
/// assembled snapshot is a document the engine could also parse.
pub const MAX_TOTAL_ENTRY_BYTES: usize = pii_eval_contracts::limits::MAX_DOCUMENT_BYTES;

/// Encode a case as an entry (the format's only writer; used by tools and tests).
pub fn encode(case: &Case) -> Result<Vec<u8>, EntryError> {
    let value = json!({"schema": ENTRY_SCHEMA, "case": serde_json::to_value(case).map_err(|_| EntryError)?});
    Ok(value.to_string().into_bytes())
}

/// Decode the bytes of the entry named `name`.
pub fn decode(name: &str, bytes: &[u8]) -> Result<Case, EntryError> {
    if !is_entry_name(name) || bytes.len() > MAX_ENTRY_BYTES {
        return Err(EntryError);
    }
    let value = parse_strict(
        bytes,
        &ParseLimits {
            max_bytes: MAX_ENTRY_BYTES,
            max_depth: 32,
        },
    )
    .map_err(|_| EntryError)?;
    let top = value.as_object().ok_or(EntryError)?;
    if top.len() != 2 || top.get("schema").and_then(Value::as_str) != Some(ENTRY_SCHEMA) {
        return Err(EntryError);
    }
    let case: Case = serde_json::from_value(top.get("case").cloned().ok_or(EntryError)?)
        .map_err(|_| EntryError)?;
    if case.case_id.as_str() != name {
        return Err(EntryError);
    }
    Ok(case)
}

/// Validate one case alone, under the configured header, with the contracts'
/// validator (ranges, text digests, derivations, context trios, ...).
pub fn validate_case(
    population: &Population,
    generation: &GenerationRules,
    case: &Case,
) -> Result<(), EntryError> {
    let mut one = CorpusSnapshot::unsealed(CorpusSnapshotBody {
        population: population.clone(),
        generation: generation.clone(),
        cases: vec![case.clone()],
    });
    seal(&mut one).map_err(|_| EntryError)?;
    validate(&one).map_err(|_| EntryError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_entries_are_refused() {
        let secret = "zq-secret-7731";
        for bytes in [
            &b""[..],
            b"null",
            b"{}",
            br#"{"schema":"pii-eval-worker-entry/1"}"#,
            br#"{"schema":"pii-eval-worker-entry/2","case":{}}"#,
            br#"{"schema":"pii-eval-worker-entry/1","case":{},"zq-secret-7731":1}"#,
            br#"{"schema":"pii-eval-worker-entry/1","schema":"pii-eval-worker-entry/1","case":{}}"#,
            br#"{"schema":"pii-eval-worker-entry/1","case":{"caseId":"zq-secret-7731"}}"#,
        ] {
            assert_eq!(decode("zq-secret-7731", bytes), Err(EntryError));
        }
        let _ = secret;
        // The name must be an entry name and equal the case id (covered with a
        // real case in the integration tests).
        assert_eq!(decode("A", b"{}"), Err(EntryError));
    }
}
