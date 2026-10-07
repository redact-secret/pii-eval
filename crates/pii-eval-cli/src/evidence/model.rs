//! Typed views of the evidence records the consumer reads.
//!
//! Only the fields this consumer relies on are declared. Within contract
//! version 1 an unknown OPTIONAL property is ignored (the contract says so),
//! while a missing or malformed required property is a refusal. Closed enums
//! make an unknown value a refusal too. The neutrality scan
//! ([`crate::evidence::verify`]) separately refuses any scanner, detector,
//! support-state, threshold or score key anywhere in the snapshot.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

/// Authored identity state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Identity {
    /// The occurrence is a valid instance.
    Valid,
    /// The occurrence is an invalid instance.
    Invalid,
    /// The evidence does not decide.
    NotEstablished,
}

impl Identity {
    /// Wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Identity::Valid => "valid",
            Identity::Invalid => "invalid",
            Identity::NotEstablished => "not-established",
        }
    }
}

/// Authored sensitivity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Sensitivity {
    /// Sensitive.
    Sensitive,
    /// Not sensitive.
    NonSensitive,
    /// Depends on context the evidence does not fix.
    ContextDependent,
}

impl Sensitivity {
    /// Wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Sensitivity::Sensitive => "sensitive",
            Sensitivity::NonSensitive => "non-sensitive",
            Sensitivity::ContextDependent => "context-dependent",
        }
    }
}

/// Case role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    /// Positive.
    Positive,
    /// Negative.
    Negative,
    /// Ambiguous.
    Ambiguous,
    /// Twin.
    Twin,
    /// Mutation.
    Mutation,
    /// Collision.
    Collision,
    /// Context.
    Context,
}

impl Role {
    /// Wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Role::Positive => "positive",
            Role::Negative => "negative",
            Role::Ambiguous => "ambiguous",
            Role::Twin => "twin",
            Role::Mutation => "mutation",
            Role::Collision => "collision",
            Role::Context => "context",
        }
    }
}

/// Fixture expectation mode of a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleMode {
    /// The expectation is the case's.
    Copy,
    /// The expectation is the weakest one the rule may assign.
    Derived,
}

/// A half-open UTF-8 byte range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct Span {
    /// Inclusive start.
    pub start: u64,
    /// Exclusive end.
    pub end: u64,
}

/// `case.expectation`.
#[derive(Debug, Clone, Deserialize)]
pub struct CaseExpectation {
    /// Domains (an axis, not a partition).
    pub domains: Vec<String>,
    /// Identity.
    pub identity: Identity,
    /// Sensitivity.
    pub sensitivity: Sensitivity,
    /// Span in `input.text`.
    #[serde(default)]
    pub span: Option<Span>,
}

/// `case.input`.
#[derive(Clone, Deserialize)]
pub struct CaseInput {
    /// The authored text.
    pub text: String,
}

impl std::fmt::Debug for CaseInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CaseInput(<redacted {} bytes>)", self.text.len())
    }
}

/// A relationship between cases.
#[derive(Debug, Clone, Deserialize)]
pub struct Relationship {
    /// The related case id.
    pub case: String,
}

/// `provenance` of a case.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Provenance {
    /// Evidence class.
    pub evidence_class: String,
    /// Source ids.
    #[serde(default)]
    pub sources: Vec<String>,
    /// Claim ids.
    #[serde(default)]
    pub claims: Vec<String>,
}

/// `review` of a record.
#[derive(Debug, Clone, Deserialize)]
pub struct Review {
    /// Review state.
    pub state: String,
    /// Review-event ids.
    #[serde(default)]
    pub events: Vec<String>,
}

/// One authored case.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseRec {
    /// Id.
    pub id: String,
    /// Record kind (`case`).
    pub kind: String,
    /// Record schema version.
    pub schema_version: String,
    /// Role.
    pub role: Role,
    /// Privacy kind id.
    pub privacy_kind: String,
    /// Jurisdiction id.
    pub jurisdiction: String,
    /// Context ids.
    pub contexts: Vec<String>,
    /// Authored expectation.
    pub expectation: CaseExpectation,
    /// Authored input, when the case has text.
    #[serde(default)]
    pub input: Option<CaseInput>,
    /// Related cases.
    #[serde(default)]
    pub relationships: Vec<Relationship>,
    /// Provenance.
    pub provenance: Provenance,
    /// Review.
    pub review: Review,
    /// How the values of the case originate.
    pub value_origin: String,
    /// Population, when stated.
    #[serde(default)]
    pub population: Option<String>,
}

/// `fixture.expectation`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FixtureExpectation {
    /// Identity.
    pub identity: Identity,
    /// Sensitivity.
    pub sensitivity: Sensitivity,
    /// Domains.
    pub domains: Vec<String>,
    /// Whether the outcome is the rule's weakest one rather than the case's.
    pub derived_from_rule: bool,
}

/// `fixture.carrier`.
#[derive(Debug, Clone, Deserialize)]
pub struct Carrier {
    /// Layout.
    pub layout: String,
    /// Variant.
    pub variant: String,
}

/// One fixture projection.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FixtureRec {
    /// Id (`<case id>/<rule id>`).
    pub id: String,
    /// Record kind (`fixture-projection`).
    pub kind: String,
    /// Record schema version.
    pub schema_version: String,
    /// Case id.
    pub case: String,
    /// Rule id.
    pub rule: String,
    /// Rule version.
    pub rule_version: String,
    /// Carrier.
    pub carrier: Carrier,
    /// The exact fixture text.
    pub content: String,
    /// SHA-256 of the UTF-8 bytes of `content`.
    pub sha256: String,
    /// Byte length of `content`.
    pub byte_length: u64,
    /// Spans into `content` (zero or one in version 1).
    pub spans: Vec<Span>,
    /// Population.
    pub population: String,
    /// Expectation.
    pub expectation: FixtureExpectation,
    /// Lineage.
    pub lineage: Provenance,
}

impl std::fmt::Debug for FixtureRec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FixtureRec")
            .field("id", &self.id)
            .field(
                "content",
                &format_args!("<redacted {} bytes>", self.content.len()),
            )
            .finish()
    }
}

/// A fixture rule's expectation block.
#[derive(Debug, Clone, Deserialize)]
pub struct RuleExpectation {
    /// Copy or derived.
    pub mode: RuleMode,
}

/// One fixture rule.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleRec {
    /// Id.
    pub id: String,
    /// Record kind (`fixture-rule`).
    pub kind: String,
    /// Record schema version.
    pub schema_version: String,
    /// Rule version.
    pub rule_version: String,
    /// Expectation mode.
    pub expectation: RuleExpectation,
    /// `carrier`, `twin` or `mutation`.
    pub transformation: String,
    /// Cases that justify the rule.
    #[serde(default)]
    pub justified_by: Vec<String>,
    /// Population, when stated.
    #[serde(default)]
    pub population: Option<String>,
}

/// One skipped (case, rule) pair.
#[derive(Debug, Clone, Deserialize)]
pub struct SkipRec {
    /// Id.
    pub id: String,
    /// Record kind (`fixture-skip`).
    pub kind: String,
    /// Record schema version.
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    /// Case id.
    pub case: String,
    /// Rule id.
    pub rule: String,
    /// Reason.
    pub reason: String,
    /// Population.
    pub population: String,
}

/// The license block of a source.
#[derive(Debug, Clone, Deserialize)]
pub struct License {
    /// `allowed` for a redistributable source.
    pub redistribution: String,
}

/// One source.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceRec {
    /// Id.
    pub id: String,
    /// Record kind (`source`).
    pub kind: String,
    /// Record schema version.
    pub schema_version: String,
    /// License.
    pub license: License,
    /// How values originate.
    pub value_origin: String,
    /// Whether the source naturally contains personal data.
    pub naturally_occurring_personal_data: bool,
}

/// One claim.
#[derive(Debug, Clone, Deserialize)]
pub struct ClaimRec {
    /// Id.
    pub id: String,
    /// Record kind (`claim`).
    pub kind: String,
    /// Record schema version.
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    /// Source id.
    pub source: String,
}

/// One review event (present only when records reference some).
#[derive(Debug, Clone, Deserialize)]
pub struct EventRec {
    /// Id.
    pub id: String,
    /// Record kind (`review-event`).
    pub kind: String,
    /// Record schema version.
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
}

/// One entry of the kind taxonomy.
#[derive(Debug, Clone, Deserialize)]
pub struct KindEntry {
    /// Id (`<name>/<jurisdiction>/<profile>`).
    pub id: String,
    /// Jurisdictions it applies to.
    pub jurisdictions: Vec<String>,
}

/// `taxonomy/privacy-kinds.json`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KindsDoc {
    /// Record kind (`privacy-kinds`).
    pub kind: String,
    /// Schema version.
    pub schema_version: String,
    /// The kinds.
    pub kinds: Vec<KindEntry>,
}

/// An id-only taxonomy entry.
#[derive(Debug, Clone, Deserialize)]
pub struct IdEntry {
    /// Id.
    pub id: String,
}

/// `taxonomy/jurisdictions.json`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JurisdictionsDoc {
    /// Record kind (`jurisdictions`).
    pub kind: String,
    /// Schema version.
    pub schema_version: String,
    /// The entries.
    pub jurisdictions: Vec<IdEntry>,
}

/// `taxonomy/contexts.json`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextsDoc {
    /// Record kind (`contexts`).
    pub kind: String,
    /// Schema version.
    pub schema_version: String,
    /// The entries.
    pub contexts: Vec<IdEntry>,
}

/// One entry of `manifest.files`.
#[derive(Debug, Clone, Deserialize)]
pub struct ManifestFile {
    /// Relative path.
    pub path: String,
    /// Record count (JSON Lines files).
    #[serde(default)]
    pub records: Option<u64>,
    /// Byte length.
    pub bytes: u64,
    /// SHA-256.
    pub sha256: String,
}

/// One recorded validation check.
#[derive(Debug, Clone, Deserialize)]
pub struct Check {
    /// Status.
    pub status: String,
}

/// `manifest.validation`.
#[derive(Debug, Clone, Deserialize)]
pub struct Validation {
    /// Schema gate.
    pub schema: String,
    /// Provenance gate.
    pub provenance: String,
    /// Privacy gate.
    pub privacy: String,
    /// Individual checks.
    #[serde(default)]
    pub checks: Vec<Check>,
}

/// An excluded record id with its reasons (never read further).
#[derive(Debug, Clone, Deserialize)]
pub struct Excluded {
    /// Id.
    pub id: String,
}

/// `manifest.exclusions`.
#[derive(Debug, Clone, Deserialize)]
pub struct Exclusions {
    /// Excluded sources.
    pub sources: Vec<Excluded>,
    /// Excluded claims.
    pub claims: Vec<Excluded>,
    /// Excluded cases.
    pub cases: Vec<Excluded>,
    /// Excluded rules.
    pub rules: Vec<Excluded>,
}

/// The snapshot manifest.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    /// Record kind (`snapshot-manifest`).
    pub kind: String,
    /// Record schema version.
    pub schema_version: String,
    /// Snapshot id.
    pub id: String,
    /// Population.
    pub population: String,
    /// Snapshot date.
    pub snapshot_date: String,
    /// SHA-256 of `sources.jsonl`.
    pub source_manifest_digest: String,
    /// Content digest.
    pub content_digest: String,
    /// Digest construction.
    pub content_digest_spec: String,
    /// Contract name.
    pub consumer_contract: String,
    /// Contract version.
    pub consumer_contract_version: String,
    /// Record counts.
    pub counts: BTreeMap<String, u64>,
    /// Coverage summary (compared after recomputation).
    pub coverage: Value,
    /// Recorded validation.
    pub validation: Validation,
    /// Listed files.
    pub files: Vec<ManifestFile>,
    /// Exclusions.
    pub exclusions: Exclusions,
}
