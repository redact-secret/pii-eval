//! The consumer of `pii-evidence` snapshots (`pii-evidence-consumer-contract`
//! version 1; ADR 0019, docs/evidence-consumer.md).
//!
//! A snapshot of the evidence repository is the only input this module reads.
//! Everything happens in three separate steps, each failing closed:
//!
//! 1. [`files`] reads a local snapshot directory (no network, no process; the
//!    release archive is fetched and unpacked outside the engine by
//!    `tools/pii-evidence/fetch-snapshot.mjs`);
//! 2. [`verify`] checks the whole snapshot against a pin and against itself
//!    BEFORE anything is mapped or executed: contract name and version, pinned
//!    id and digests, the file list, every file digest, the content digest, the
//!    id derivation, the source-manifest digest, schemas, record counts,
//!    coverage, references, fixture bytes and spans, population, neutrality;
//! 3. [`map`] turns the verified evidence into a pii-eval [`CorpusSnapshot`]
//!    (existing contract, schema 1.4 when it holds range-less occurrences) and
//!    a binding document that records every mapping decision and loss.
//!
//! Nothing here scores, ranks or decides support. Evidence carries no scanner
//! or product-policy field, and neither does the mapped corpus. No input text,
//! matched value or raw scanner output is ever put into an error or a summary.
//!
//! [`CorpusSnapshot`]: pii_eval_contracts::CorpusSnapshot

pub mod cmd;
pub mod files;
pub mod map;
pub mod model;
pub mod pin;
pub mod plan;
pub mod verify;

use crate::status::Exit;

/// The consumer contract this module implements.
pub const CONTRACT_NAME: &str = "pii-evidence-consumer-contract";
/// The only contract version it knows. Any other version is refused.
pub const CONTRACT_VERSION: &str = "1";
/// The only content-digest construction it knows.
pub const DIGEST_SPEC: &str = "files-v1";
/// The only record schema version it knows.
pub const RECORD_SCHEMA_VERSION: &str = "1";
/// Prefix of a snapshot id.
pub const ID_PREFIX: &str = "public-pii-phi";

/// Stable reason codes. A retired code stays reserved. Each one is documented
/// in docs/evidence-consumer.md; a test fails when the two lists differ.
pub mod reason {
    // Integrity and identity (exit 4: what was found is not what was pinned).
    pub const SNAPSHOT_ID_MISMATCH: &str = "snapshot-id-mismatch";
    pub const MANIFEST_DIGEST_MISMATCH: &str = "manifest-digest-mismatch";
    pub const CONTENT_DIGEST_MISMATCH: &str = "content-digest-mismatch";
    pub const SOURCE_MANIFEST_DIGEST_MISMATCH: &str = "source-manifest-digest-mismatch";
    pub const SNAPSHOT_ID_DERIVATION: &str = "snapshot-id-derivation";
    pub const CONTRACT_UNKNOWN: &str = "contract-unknown";
    pub const CONTRACT_VERSION_UNKNOWN: &str = "contract-version-unknown";
    pub const DIGEST_SPEC_UNKNOWN: &str = "digest-spec-unknown";
    pub const FILE_MISSING: &str = "file-missing";
    pub const FILE_UNLISTED: &str = "file-unlisted";
    pub const FILE_DIGEST_MISMATCH: &str = "file-digest-mismatch";
    pub const FILE_LENGTH_MISMATCH: &str = "file-length-mismatch";
    pub const RECORD_COUNT_MISMATCH: &str = "record-count-mismatch";
    pub const POPULATION_NOT_PUBLIC: &str = "population-not-public";
    // Invalid content (exit 3).
    pub const FILE_NOT_REGULAR: &str = "file-not-regular";
    pub const FILE_TOO_LARGE: &str = "file-too-large";
    pub const SNAPSHOT_UNREADABLE: &str = "snapshot-unreadable";
    pub const PIN_INVALID: &str = "pin-invalid";
    pub const MANIFEST_INVALID: &str = "manifest-invalid";
    pub const RECORD_INVALID: &str = "record-invalid";
    pub const RECORD_FIELD_MISSING: &str = "record-field-missing";
    pub const RECORD_FIELD_INVALID: &str = "record-field-invalid";
    pub const RECORD_KIND_UNKNOWN: &str = "record-kind-unknown";
    pub const SCHEMA_VERSION_UNKNOWN: &str = "schema-version-unknown";
    pub const FORBIDDEN_FIELD: &str = "forbidden-field";
    pub const ID_ORDER_INVALID: &str = "id-order-invalid";
    pub const COUNT_MISMATCH: &str = "count-mismatch";
    pub const COVERAGE_MISMATCH: &str = "coverage-mismatch";
    pub const REFERENCE_UNRESOLVED: &str = "reference-unresolved";
    pub const FIXTURE_DIGEST_MISMATCH: &str = "fixture-digest-mismatch";
    pub const FIXTURE_LENGTH_MISMATCH: &str = "fixture-length-mismatch";
    pub const SPAN_INVALID: &str = "span-invalid";
    pub const FIXTURE_EXPECTATION_MISMATCH: &str = "fixture-expectation-mismatch";
    pub const SOURCE_NOT_PUBLIC_SAFE: &str = "source-not-public-safe";
    pub const VALIDATION_NOT_PASSED: &str = "validation-not-passed";
    pub const EXCLUSION_INCONSISTENT: &str = "exclusion-inconsistent";
    pub const TAXONOMY_INVALID: &str = "taxonomy-invalid";
    // Mapping (exit 3).
    pub const KIND_UNMAPPED: &str = "kind-unmapped";
    pub const JURISDICTION_UNMAPPED: &str = "jurisdiction-unmapped";
    pub const MAPPING_INVALID: &str = "mapping-invalid";
    pub const NOTHING_TO_MAP: &str = "nothing-to-map";
    // Planning (exit 3, 4, 6).
    pub const PLAN_INVALID: &str = "plan-invalid";

    /// Every code, for the documentation check.
    pub const ALL: &[&str] = &[
        SNAPSHOT_ID_MISMATCH,
        MANIFEST_DIGEST_MISMATCH,
        CONTENT_DIGEST_MISMATCH,
        SOURCE_MANIFEST_DIGEST_MISMATCH,
        SNAPSHOT_ID_DERIVATION,
        CONTRACT_UNKNOWN,
        CONTRACT_VERSION_UNKNOWN,
        DIGEST_SPEC_UNKNOWN,
        FILE_MISSING,
        FILE_UNLISTED,
        FILE_DIGEST_MISMATCH,
        FILE_LENGTH_MISMATCH,
        RECORD_COUNT_MISMATCH,
        POPULATION_NOT_PUBLIC,
        FILE_NOT_REGULAR,
        FILE_TOO_LARGE,
        SNAPSHOT_UNREADABLE,
        PIN_INVALID,
        MANIFEST_INVALID,
        RECORD_INVALID,
        RECORD_FIELD_MISSING,
        RECORD_FIELD_INVALID,
        RECORD_KIND_UNKNOWN,
        SCHEMA_VERSION_UNKNOWN,
        FORBIDDEN_FIELD,
        ID_ORDER_INVALID,
        COUNT_MISMATCH,
        COVERAGE_MISMATCH,
        REFERENCE_UNRESOLVED,
        FIXTURE_DIGEST_MISMATCH,
        FIXTURE_LENGTH_MISMATCH,
        SPAN_INVALID,
        FIXTURE_EXPECTATION_MISMATCH,
        SOURCE_NOT_PUBLIC_SAFE,
        VALIDATION_NOT_PASSED,
        EXCLUSION_INCONSISTENT,
        TAXONOMY_INVALID,
        KIND_UNMAPPED,
        JURISDICTION_UNMAPPED,
        MAPPING_INVALID,
        NOTHING_TO_MAP,
        PLAN_INVALID,
    ];
}

/// Why a snapshot was refused. The location is a file name or a record id of
/// the evidence repository (public identifiers), or a fixed field name. It is
/// never a value from a record and never input text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceError {
    /// Stable reason code ([`reason`]).
    pub code: &'static str,
    /// Exit status class.
    pub exit: Exit,
    /// File, record id or field name.
    pub at: String,
}

impl EvidenceError {
    /// A refusal because content is malformed or inconsistent with itself.
    pub fn invalid(code: &'static str, at: impl Into<String>) -> Self {
        Self {
            code,
            exit: Exit::Invalid,
            at: at.into(),
        }
    }

    /// A refusal because what was found is not what was pinned or bound.
    pub fn identity(code: &'static str, at: impl Into<String>) -> Self {
        Self {
            code,
            exit: Exit::Provenance,
            at: at.into(),
        }
    }

    /// The one-line diagnostic.
    pub fn human(&self) -> String {
        format!(
            "pii-eval-evidence: {} ({}, exit {}): {}",
            self.code,
            self.exit.name(),
            self.exit.code(),
            self.at
        )
    }
}

impl std::fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.human())
    }
}

impl std::error::Error for EvidenceError {}
