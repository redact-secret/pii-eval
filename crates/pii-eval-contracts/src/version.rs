//! Document kinds, schema versions and the envelope check.
//!
//! Schema versioning rules are in ADR 0002. In short: the major version
//! changes for any breaking change; the minor version changes only for
//! additive, optional changes. A reader accepts its own major version with a
//! minor version no newer than its own, and rejects everything else with a
//! stable reason code. A reader never ignores unknown fields.

use std::borrow::Cow;
use std::fmt;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::reason::{ContractError, ReasonCode};

/// Schema major version this crate reads and writes.
pub const SCHEMA_MAJOR: u16 = 1;
/// Highest schema minor version of [`SCHEMA_MAJOR`] this crate reads and writes.
pub const SCHEMA_MINOR: u16 = 0;

/// The five document kinds. The string is the `schema` field value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DocumentKind {
    /// Versioned corpus snapshot: one identified population of cases.
    CorpusSnapshot,
    /// Run manifest (the plan): what will be measured, and how.
    RunManifest,
    /// Observations of one scanner configuration over one population.
    ObservationSet,
    /// Internal run artifact: observations, per-case results, accounting.
    RunArtifact,
    /// Public-synthetic run artifact: the only artifact the public serializer emits.
    PublicSyntheticArtifact,
}

impl DocumentKind {
    /// Every kind.
    pub const ALL: [DocumentKind; 5] = [
        DocumentKind::CorpusSnapshot,
        DocumentKind::RunManifest,
        DocumentKind::ObservationSet,
        DocumentKind::RunArtifact,
        DocumentKind::PublicSyntheticArtifact,
    ];

    /// The `schema` field value.
    pub const fn schema_id(self) -> &'static str {
        match self {
            DocumentKind::CorpusSnapshot => "pii-eval.corpus-snapshot",
            DocumentKind::RunManifest => "pii-eval.run-manifest",
            DocumentKind::ObservationSet => "pii-eval.observation-set",
            DocumentKind::RunArtifact => "pii-eval.run-artifact",
            DocumentKind::PublicSyntheticArtifact => "pii-eval.public-synthetic-artifact",
        }
    }

    /// Parse a `schema` field value.
    pub fn from_schema_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.schema_id() == id)
    }

    /// File stem of the committed JSON Schema for this kind.
    pub const fn schema_file_stem(self) -> &'static str {
        match self {
            DocumentKind::CorpusSnapshot => "corpus-snapshot",
            DocumentKind::RunManifest => "run-manifest",
            DocumentKind::ObservationSet => "observation-set",
            DocumentKind::RunArtifact => "run-artifact",
            DocumentKind::PublicSyntheticArtifact => "public-synthetic-artifact",
        }
    }
}

/// `<major>.<minor>`, each 0 to 9999, serialized as a string such as `"1.0"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchemaVersion {
    /// Breaking-change counter.
    pub major: u16,
    /// Additive-change counter.
    pub minor: u16,
}

impl SchemaVersion {
    /// The version this crate writes.
    pub const CURRENT: SchemaVersion = SchemaVersion {
        major: SCHEMA_MAJOR,
        minor: SCHEMA_MINOR,
    };

    /// Parse `"<major>.<minor>"`: ASCII digits, no sign, no leading zeros.
    pub fn parse(text: &str) -> Option<Self> {
        let (major, minor) = text.split_once('.')?;
        let number = |s: &str| {
            let ok = !s.is_empty()
                && s.len() <= 4
                && s.bytes().all(|b| b.is_ascii_digit())
                && (s == "0" || !s.starts_with('0'));
            if ok { s.parse::<u16>().ok() } else { None }
        };
        Some(Self {
            major: number(major)?,
            minor: number(minor)?,
        })
    }

    /// Whether this crate can read a document that declares `self`.
    pub fn readable(self) -> Result<(), ReasonCode> {
        if self.major != SCHEMA_MAJOR {
            Err(ReasonCode::IncompatibleSchemaMajor)
        } else if self.minor > SCHEMA_MINOR {
            Err(ReasonCode::SchemaMinorTooNew)
        } else {
            Ok(())
        }
    }
}

impl fmt::Display for SchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl Serialize for SchemaVersion {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for SchemaVersion {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        SchemaVersion::parse(&text)
            .ok_or_else(|| de::Error::custom("pii-eval:invalid-identifier:schema-version"))
    }
}

impl JsonSchema for SchemaVersion {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("SchemaVersion")
    }
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "pattern": "^(0|[1-9][0-9]{0,3})\\.(0|[1-9][0-9]{0,3})$",
        })
    }
}

/// Check `schema` and `schemaVersion` on an already strictly parsed document,
/// before any typed parsing, so that unknown or incompatible versions get a
/// specific stable code rather than a generic schema violation.
pub fn check_envelope(
    root: &Value,
    expected: DocumentKind,
) -> Result<SchemaVersion, ContractError> {
    let object = root
        .as_object()
        .ok_or_else(|| ContractError::root(ReasonCode::NotAnObject))?;
    let schema = object
        .get("schema")
        .and_then(Value::as_str)
        .ok_or_else(|| ContractError::root(ReasonCode::MissingSchema))?;
    let kind = DocumentKind::from_schema_id(schema)
        .ok_or_else(|| ContractError::root(ReasonCode::UnknownSchema))?;
    if kind != expected {
        return Err(ContractError::root(ReasonCode::SchemaKindMismatch));
    }
    let version = object
        .get("schemaVersion")
        .and_then(Value::as_str)
        .and_then(SchemaVersion::parse)
        .ok_or_else(|| ContractError::root(ReasonCode::MalformedSchemaVersion))?;
    version.readable().map_err(ContractError::root)?;
    Ok(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_parse_strictly() {
        assert_eq!(
            SchemaVersion::parse("1.0"),
            Some(SchemaVersion { major: 1, minor: 0 })
        );
        for bad in [
            "1", "1.", ".1", "01.0", "1.00", "1.0.0", "-1.0", "1.+0", "a.b", "10000.0", "",
        ] {
            assert_eq!(SchemaVersion::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn readability_rules() {
        let v = |major, minor| SchemaVersion { major, minor };
        assert_eq!(v(1, 0).readable(), Ok(()));
        assert_eq!(v(1, 1).readable(), Err(ReasonCode::SchemaMinorTooNew));
        assert_eq!(v(2, 0).readable(), Err(ReasonCode::IncompatibleSchemaMajor));
        assert_eq!(v(0, 9).readable(), Err(ReasonCode::IncompatibleSchemaMajor));
    }

    #[test]
    fn schema_ids_round_trip() {
        for kind in DocumentKind::ALL {
            assert_eq!(DocumentKind::from_schema_id(kind.schema_id()), Some(kind));
        }
        assert_eq!(DocumentKind::from_schema_id("pii-eval.nope"), None);
    }
}
