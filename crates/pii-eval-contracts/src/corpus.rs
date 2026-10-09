//! The corpus snapshot contract: one identified population of authored cases.
//!
//! A snapshot is scanner-neutral input. It carries authored expectations and
//! never absorbs scanner output; `pii-eval` never edits an expectation to match
//! a scanner. One run measures one snapshot (one population). A snapshot of a
//! `protected` population is an internal record: it holds case text and is
//! consumed only inside an authorized custodian run.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::axes::{
    ActionExpectation, ContextClass, ContextObligation, ExpectedType, SensitivityExpectation,
    kebab_enum,
};
use crate::check::{non_empty, sorted_unique, within_limit};
use crate::decimal::ByteRange;
use crate::document::{impl_document, schema_tag};
use crate::ident::{FamilyId, FamilyScope, Id, JurisdictionCode, LanguageTag, Seed, Sha256Digest};
use crate::limits::{
    MAX_CASES, MAX_COMPETING_FAMILIES, MAX_EXPECTATIONS_PER_VARIANT, MAX_TEXT_BYTES,
    MAX_VARIANTS_PER_CASE,
};
use crate::protocol::MethodId;
use crate::reason::{Collector, Meta, Path, ReasonCode};
use crate::version::SchemaVersion;

kebab_enum!(
    /// Who may see the population. Independent of product identity: a
    /// `public-synthetic` population can be run against a candidate.
    Visibility { PublicSynthetic, Protected }
);

kebab_enum!(
    /// How a variant was produced.
    Strategy { Authored, Derived, ReviewRequired }
);

schema_tag!(
    /// `schema` value of a corpus snapshot.
    CorpusSnapshotSchema, "pii-eval.corpus-snapshot"
);

/// Population identity. The snapshot's semantic digest is the content commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Population {
    /// Population identifier, assigned by the corpus author.
    pub population_id: Id,
    /// Population revision, assigned by the corpus author.
    pub population_version: u32,
    /// Visibility class.
    pub visibility: Visibility,
}

/// Deterministic generation rules for derived variants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GenerationRules {
    /// Generator identifier.
    pub generator: Id,
    /// Generator version.
    pub generator_version: u32,
    /// Seed-derivation rule identifier.
    pub seed_derivation: Seed,
}

/// Source lineage of an authored case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Lineage {
    /// Source identifier.
    pub source_id: Id,
    /// Digest of the source material.
    pub source_digest: Sha256Digest,
}

/// Operator that derived a variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperatorRef {
    /// Operator identifier.
    pub id: Id,
    /// Operator version.
    pub version: u32,
}

/// How a variant came to be.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Derivation {
    /// Authored, derived, or review-required.
    pub strategy: Strategy,
    /// The operator, required for derived and review-required variants and
    /// forbidden for authored ones.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<OperatorRef>,
    /// The seed used, when the operator is seeded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<Seed>,
}

/// Validator that established the authored type expectation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ValidatorRef {
    /// Validator identifier.
    pub id: Id,
    /// Validator version.
    pub version: u32,
}

/// Scanner-neutral authored evidence semantics (schema 1.5, ADR 0020).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceSemantics {
    /// Authored domains, independent of detector family and scanner support.
    pub domains: Vec<EvidenceDomain>,
    /// Exact authored context identifiers, sorted and unique. These are evidence
    /// labels, not claims that a scanner observed or understood medical context.
    pub contexts: Vec<String>,
    /// Text-wide negative assertion rather than an unlocated occurrence.
    pub text_negative: bool,
    /// Authored sensitivity retained in artifacts even when the result is unresolved.
    pub authored_sensitivity: SensitivityExpectation,
}

/// Evidence domain. PHI does not imply a scanner capability or product verdict.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceDomain {
    /// Personally identifiable information.
    Pii,
    /// Protected health information in authored evidence context.
    Phi,
}

impl EvidenceSemantics {
    pub(crate) fn validate(&self, path: &Path<'_>, c: &mut Collector) {
        if self.domains.is_empty()
            || self.domains.len() > 2
            || self.domains.windows(2).any(|w| w[0] >= w[1])
            || self.contexts.len() > 64
            || self.contexts.windows(2).any(|w| w[0] >= w[1])
            || self.contexts.iter().any(|id| {
                id.is_empty()
                    || id.len() > 128
                    || !id.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_/".contains(&b)
                    })
            })
        {
            c.push(ReasonCode::ProtocolBindingMismatch, path);
        }
    }
}

/// One authored expectation, with independent type, sensitivity, range and action axes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Expectation {
    /// Optional authored evidence semantics, introduced in schema 1.5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<EvidenceSemantics>,
    /// Identifier unique within the variant.
    pub occurrence_id: Id,
    /// Expected byte range in the variant text. Absent when the authors did
    /// not establish where the occurrence is (schema 1.4, ADR 0018): then the
    /// type identity and sensitivity must be `not-established`, except explicit
    /// schema-1.5 text-negative assertions and context-dependent uncertainty.
    /// Cases must be `schema-only`; no range is invented. An unlocated occurrence
    /// observes `unresolved`; a text-negative assertion observes `not-applicable`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range: Option<ByteRange>,
    /// Expected family. Its scope must agree with the case jurisdiction.
    pub family: FamilyId,
    /// Type axis: is the occurrence a valid or invalid instance of the family.
    pub type_expectation: ExpectedType,
    /// Validator behind the type expectation, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validator: Option<ValidatorRef>,
    /// Sensitivity axis.
    pub sensitivity: SensitivityExpectation,
    /// Context frame of this variant.
    pub context_class: ContextClass,
    /// Whether context is needed for a sensitive classification.
    pub context_obligation: ContextObligation,
    /// Action axis: the action a scanner is expected to report.
    pub action: ActionExpectation,
}

/// One concrete input text with its expectations.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Variant {
    /// Identifier unique across the whole snapshot.
    pub variant_id: Id,
    /// Derivation.
    pub derivation: Derivation,
    /// The exact input text. Coordinates are half-open UTF-8 byte offsets into it.
    pub text: String,
    /// SHA-256 of the UTF-8 bytes of `text`; observations bind to it.
    pub text_digest: Sha256Digest,
    /// Expected occurrences, ascending by occurrence id.
    pub expectations: Vec<Expectation>,
}

impl std::fmt::Debug for Variant {
    /// Never prints the input text: only its length and digest.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Variant")
            .field("variant_id", &self.variant_id)
            .field("derivation", &self.derivation)
            .field(
                "text",
                &format_args!("<redacted {} bytes>", self.text.len()),
            )
            .field("text_digest", &self.text_digest)
            .field("expectations", &self.expectations)
            .finish()
    }
}

/// Declaration for a jurisdiction-collision case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Collision {
    /// The family the case targets.
    pub target_family: FamilyId,
    /// Families that collide with the target, ascending, unique, excluding the target.
    pub competing_families: Vec<FamilyId>,
}

/// One authored case: the sampling unit (together with its method).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Case {
    /// Authored case identifier.
    pub case_id: Id,
    /// Method this case belongs to. Case/method grouping is the sample identity.
    pub method: MethodId,
    /// Source lineage.
    pub lineage: Lineage,
    /// Language of the case text.
    pub language: LanguageTag,
    /// Jurisdiction, or absent for a global case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<JurisdictionCode>,
    /// Collision declaration; required for, and only for, `jurisdiction-collision`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collision: Option<Collision>,
    /// Variants, ascending by variant id.
    pub variants: Vec<Variant>,
}

/// The semantic content of a corpus snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CorpusSnapshotBody {
    /// Population identity.
    pub population: Population,
    /// Generation rules.
    pub generation: GenerationRules,
    /// Cases, ascending by case id.
    pub cases: Vec<Case>,
}

/// A corpus snapshot document. Its `semanticDigest` is the population digest
/// that manifests, observations and artifacts bind to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CorpusSnapshot {
    /// Document kind tag.
    pub schema: CorpusSnapshotSchema,
    /// Schema version.
    pub schema_version: SchemaVersion,
    /// Semantic digest of `semantic`.
    pub semantic_digest: Sha256Digest,
    /// The digested body.
    pub semantic: CorpusSnapshotBody,
}

impl_document!(@impl
    CorpusSnapshot,
    CorpusSnapshotBody,
    crate::version::DocumentKind::CorpusSnapshot,
    {
        fn validate_gates(&self, c: &mut Collector) {
            if self.semantic.authors_evidence_semantics() && self.schema_version < SchemaVersion::V1_5 {
                c.push(ReasonCode::ProtocolBindingMismatch, &Path::ROOT.field("schemaVersion"));
            }
            // An authored `not-established` identity exists from schema 1.3 on
            // (ADR 0017): an older reader must not meet a value it cannot read.
            if self.semantic.authors_not_established_range()
                && self.schema_version < SchemaVersion::V1_4
            {
                c.push(
                    ReasonCode::RangeNotEstablishedGate,
                    &Path::ROOT.field("semantic").field("cases"),
                );
            }
            if self.semantic.authors_not_established_identity()
                && self.schema_version < SchemaVersion::V1_3
            {
                c.push(
                    ReasonCode::IdentityNotEstablishedGate,
                    &Path::ROOT.field("semantic").field("cases"),
                );
            }
        }
    }
);

impl CorpusSnapshot {
    /// Wrap a body in an envelope with the current version and a placeholder
    /// digest; call [`crate::seal`] to compute the real digest. A population
    /// that authors a `not-established` identity is sealed under 1.3 (ADR 0017);
    /// every other population keeps the current version and its bytes.
    pub fn unsealed(semantic: CorpusSnapshotBody) -> Self {
        let schema_version = if semantic.authors_evidence_semantics() {
            SchemaVersion::V1_5
        } else if semantic.authors_not_established_range() {
            SchemaVersion::V1_4
        } else if semantic.authors_not_established_identity() {
            SchemaVersion::V1_3
        } else {
            SchemaVersion::CURRENT
        };
        Self {
            schema: CorpusSnapshotSchema::Only,
            schema_version,
            semantic_digest: Sha256Digest::of_bytes(b""),
            semantic,
        }
    }
}

impl Expectation {
    /// Whether the assertion applies to the entire text, with no invented span.
    pub fn is_text_negative(&self) -> bool {
        self.evidence.as_ref().is_some_and(|e| e.text_negative)
    }

    fn validate(
        &self,
        text: &str,
        jurisdiction: Option<&JurisdictionCode>,
        path: &Path<'_>,
        c: &mut Collector,
    ) {
        if self.sensitivity == SensitivityExpectation::ContextDependent && self.evidence.is_none() {
            c.push(ReasonCode::ProtocolBindingMismatch, &path.field("evidence"));
        }
        if let Some(evidence) = &self.evidence {
            evidence.validate(&path.field("evidence"), c);
            if evidence.authored_sensitivity != self.sensitivity {
                c.push(ReasonCode::OutcomeContradiction, &path.field("evidence"));
            }
            if evidence.text_negative
                && (self.range.is_some()
                    || self.type_expectation == ExpectedType::Valid
                    || self.sensitivity == SensitivityExpectation::Sensitive
                    || (self.type_expectation != ExpectedType::Invalid
                        && self.sensitivity != SensitivityExpectation::NonSensitive))
            {
                c.push(
                    ReasonCode::RangeNotEstablishedInvalid,
                    &path.field("evidence"),
                );
            }
        }
        match &self.range {
            Some(range) => range.check(text, &path.field("range"), c),
            None => {
                // Nothing locates the occurrence, so no judgment about its
                // identity or sensitivity could be anchored to a span.
                if !self.is_text_negative()
                    && (self.type_expectation != ExpectedType::NotEstablished
                        || !matches!(
                            self.sensitivity,
                            SensitivityExpectation::NotEstablished
                                | SensitivityExpectation::ContextDependent
                        ))
                {
                    c.push(ReasonCode::RangeNotEstablishedInvalid, &path.field("range"));
                }
            }
        }
        let scope_ok = match (self.family.scope(), jurisdiction) {
            (FamilyScope::Global, None) => true,
            (FamilyScope::Jurisdiction(a), Some(b)) => a == *b,
            _ => false,
        };
        if !scope_ok {
            c.push(ReasonCode::FamilyScopeMismatch, &path.field("family"));
        }
    }
}

impl Variant {
    fn validate(
        &self,
        jurisdiction: Option<&JurisdictionCode>,
        path: &Path<'_>,
        c: &mut Collector,
    ) {
        let text_path = path.field("text");
        if self.text.len() > MAX_TEXT_BYTES {
            c.push_with(
                ReasonCode::LimitExceeded,
                &text_path,
                Meta::limit(MAX_TEXT_BYTES as u64, self.text.len() as u64),
            );
            return;
        }
        if Sha256Digest::of_bytes(self.text.as_bytes()) != self.text_digest {
            c.push(ReasonCode::TextDigestMismatch, &path.field("textDigest"));
        }
        let derivation = path.field("derivation");
        let has_operator = self.derivation.operator.is_some();
        let operator_ok = match self.derivation.strategy {
            Strategy::Authored => !has_operator && self.derivation.seed.is_none(),
            Strategy::Derived | Strategy::ReviewRequired => has_operator,
        };
        if !operator_ok {
            c.push(ReasonCode::DerivationInvalid, &derivation);
        }
        let expectations = path.field("expectations");
        non_empty(&self.expectations, &expectations, c);
        if let Some(first) = self.expectations.first() {
            if self
                .expectations
                .iter()
                .any(|e| e.context_class != first.context_class)
            {
                c.push(ReasonCode::ContextClassConflict, &expectations);
            }
        }
        if within_limit(
            self.expectations.len(),
            MAX_EXPECTATIONS_PER_VARIANT,
            &expectations,
            c,
        ) {
            sorted_unique(
                &self.expectations,
                |e| e.occurrence_id.clone(),
                &expectations,
                c,
            );
            for (i, e) in self.expectations.iter().enumerate() {
                e.validate(&self.text, jurisdiction, &expectations.index(i), c);
            }
        }
    }

    /// The context class of this variant: that of its first expectation.
    fn context_class(&self) -> Option<ContextClass> {
        self.expectations.first().map(|e| e.context_class)
    }
}

impl Case {
    fn validate(&self, path: &Path<'_>, c: &mut Collector) {
        let variants = path.field("variants");
        non_empty(&self.variants, &variants, c);
        if within_limit(self.variants.len(), MAX_VARIANTS_PER_CASE, &variants, c) {
            sorted_unique(&self.variants, |v| v.variant_id.clone(), &variants, c);
            for (i, v) in self.variants.iter().enumerate() {
                v.validate(self.jurisdiction.as_ref(), &variants.index(i), c);
            }
        }
        // A range-less occurrence (ADR 0018) has no span for a method to
        // frame, mutate, reference or collide on: only `schema-only` cases.
        if self.method != MethodId::SchemaOnly
            && self
                .variants
                .iter()
                .flat_map(|v| &v.expectations)
                .any(|e| e.range.is_none())
        {
            c.push(ReasonCode::RangeNotEstablishedInvalid, &variants);
        }
        // Collision declaration exists exactly for jurisdiction-collision cases.
        let is_collision = self.method == MethodId::JurisdictionCollision;
        match (&self.collision, is_collision) {
            (Some(collision), true) => {
                let p = path.field("collision");
                let competing = p.field("competingFamilies");
                non_empty(&collision.competing_families, &competing, c);
                if within_limit(
                    collision.competing_families.len(),
                    MAX_COMPETING_FAMILIES,
                    &competing,
                    c,
                ) {
                    sorted_unique(&collision.competing_families, |f| f.clone(), &competing, c);
                }
                let target_in_competing = collision
                    .competing_families
                    .contains(&collision.target_family);
                let all_target = self
                    .variants
                    .iter()
                    .flat_map(|v| &v.expectations)
                    .all(|e| e.family == collision.target_family);
                if target_in_competing || !all_target {
                    c.push(ReasonCode::CollisionInvalid, &p);
                }
            }
            (None, false) => {}
            _ => c.push(ReasonCode::CollisionInvalid, &path.field("collision")),
        }
        if self.method == MethodId::ContextDiscrimination {
            let classes: Vec<ContextClass> = self
                .variants
                .iter()
                .filter_map(Variant::context_class)
                .collect();
            // Complete trio (ADR 0008, relaxed from "exactly one per class"):
            // every variant has a class and every class has at least one
            // variant. Real groups hold several frames per class.
            let complete = classes.len() == self.variants.len()
                && [
                    ContextClass::Sensitive,
                    ContextClass::Neutral,
                    ContextClass::NonSensitive,
                ]
                .iter()
                .all(|k| classes.contains(k));
            if !complete {
                c.push(ReasonCode::IncompleteContextTrio, &variants);
            }
        }
    }
}

impl CorpusSnapshotBody {
    /// Whether this population requires the schema 1.5 / protocol 3 path.
    pub fn authors_evidence_semantics(&self) -> bool {
        self.cases
            .iter()
            .flat_map(|c| &c.variants)
            .flat_map(|v| &v.expectations)
            .any(|e| {
                e.evidence.is_some() || e.sensitivity == SensitivityExpectation::ContextDependent
            })
    }

    /// Whether any expectation authors a `not-established` type identity.
    pub fn authors_not_established_identity(&self) -> bool {
        self.cases
            .iter()
            .flat_map(|case| &case.variants)
            .flat_map(|v| &v.expectations)
            .any(|e| e.type_expectation == ExpectedType::NotEstablished)
    }

    /// Whether any expectation authors a `not-established` range, that is,
    /// carries no `range` (schema 1.4, ADR 0018).
    pub fn authors_not_established_range(&self) -> bool {
        self.cases
            .iter()
            .flat_map(|case| &case.variants)
            .flat_map(|v| &v.expectations)
            .any(|e| e.range.is_none())
    }

    pub(crate) fn validate(&self, path: &Path<'_>, c: &mut Collector) {
        let cases = path.field("cases");
        non_empty(&self.cases, &cases, c);
        if !within_limit(self.cases.len(), MAX_CASES, &cases, c) {
            return;
        }
        sorted_unique(&self.cases, |case| case.case_id.clone(), &cases, c);
        let mut variant_ids: BTreeSet<&Id> = BTreeSet::new();
        for (i, case) in self.cases.iter().enumerate() {
            case.validate(&cases.index(i), c);
            for (j, v) in case.variants.iter().enumerate() {
                if !variant_ids.insert(&v.variant_id) {
                    c.push(
                        ReasonCode::DuplicateIdentity,
                        &cases.index(i).field("variants").index(j),
                    );
                }
            }
            if c.is_full() {
                return;
            }
        }
    }

    /// Number of authored cases.
    pub fn case_count(&self) -> u64 {
        self.cases.len() as u64
    }

    /// Number of variants across all cases.
    pub fn variant_count(&self) -> u64 {
        self.cases
            .iter()
            .map(|case| case.variants.len() as u64)
            .sum()
    }

    /// Number of expected occurrences across all variants.
    pub fn occurrence_count(&self) -> u64 {
        self.cases
            .iter()
            .flat_map(|case| &case.variants)
            .map(|v| v.expectations.len() as u64)
            .sum()
    }
}
