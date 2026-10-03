//! Method generation: authored cases in, contract cases with variants and
//! variant provenance out.
//!
//! The generator is pure. It reads no clock, random source, environment or
//! file; every output is a function of the authored cases, the snapshot's
//! generation rules, the validator registry and the limits. Work is bounded:
//! variants per case, per method and in total, cases, text bytes and batch
//! size all have explicit limits (ADR 0007), and generation is an iterator so
//! the whole generated corpus is never required to exist at once.
//!
//! A case the generator cannot honour is *refused with a reason* and counted;
//! it never produces a clean empty result. A limit that would force
//! truncation ends the run with an error instead of dropping cases in an
//! input-order-dependent way.

use std::collections::{BTreeMap, BTreeSet};

use pii_eval_contracts::limits::execution::MAX_BATCH_VARIANTS;
use pii_eval_contracts::limits::{
    MAX_CASES, MAX_COMPETING_FAMILIES, MAX_INPUTS_PER_OBSERVATION_SET, MAX_TEXT_BYTES,
    MAX_VARIANTS_PER_CASE,
};
use pii_eval_contracts::{
    ByteRange, Case, Collision, ContextClass, CorpusSnapshotBody, Derivation, Expectation,
    ExpectedType, FamilyScope, GenerationRules, Id, MethodId, MethodRef, OperatorRef, Population,
    ReasonCode, Seed, SensitivityExpectation, Sha256Digest, Strategy, Variant,
};

use super::ids::{DerivationError, SeedRule, Slot, derive_seed, variant_id};
use super::input::{
    AuthoredCase, BenignClass, CANDIDATE_MARKER, ContextFrame, EvidenceClass, MethodParams,
    ValidatorCheck,
};
use super::operators::{
    CONTEXT_FRAME_ID, CONTEXT_FRAME_VERSION, OperatorError, REVIEW_HOLD_ID, REVIEW_HOLD_VERSION,
    apply_mutation,
};
use super::validators::{
    UnavailableReason, ValidatorObservation, ValidatorRegistry, ValidatorState,
};
use crate::range::{RangeError, validate_range};
use pii_eval_contracts::TypeState;
use pii_eval_contracts::axes::OutcomeRow;

/// The occurrence id of the single expected occurrence of every generated variant.
pub const OCCURRENCE_ID: &str = "occurrence-1";
/// Recorded role of a reference observation: it is evidence about the
/// reference, never replacement ground truth.
pub const REFERENCE_ROLE: &str = "observation-not-truth";

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Explicit generation limits. Every one is checked; none is advisory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenerationLimits {
    /// Most variants one case may derive. At most the contract's 64.
    pub max_variants_per_case: usize,
    /// Most variants one method may derive in a run.
    pub max_variants_per_method: u64,
    /// Most variants in a run.
    pub max_total_variants: u64,
    /// Most authored cases in a run.
    pub max_cases: u64,
    /// Largest variant text, in UTF-8 bytes.
    pub max_text_bytes: usize,
    /// Most variants (plus refusals) in one batch.
    pub batch_variants: usize,
}

impl GenerationLimits {
    /// The contract maxima, with a batch of 1024 variants.
    pub const DEFAULT: GenerationLimits = GenerationLimits {
        max_variants_per_case: MAX_VARIANTS_PER_CASE,
        max_variants_per_method: MAX_INPUTS_PER_OBSERVATION_SET as u64,
        max_total_variants: MAX_INPUTS_PER_OBSERVATION_SET as u64,
        max_cases: MAX_CASES as u64,
        max_text_bytes: MAX_TEXT_BYTES,
        batch_variants: 1024,
    };

    /// Check the limits against each other and the contract maxima.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.max_variants_per_case == 0
            || self.max_variants_per_method == 0
            || self.max_total_variants == 0
            || self.max_cases == 0
            || self.max_text_bytes == 0
            || self.batch_variants == 0
        {
            return Err("limit-zero");
        }
        if self.max_variants_per_case > MAX_VARIANTS_PER_CASE {
            return Err("variants-per-case-above-contract");
        }
        if self.max_text_bytes > MAX_TEXT_BYTES {
            return Err("text-bytes-above-contract");
        }
        if self.max_cases > MAX_CASES as u64 {
            return Err("cases-above-contract");
        }
        if self.max_total_variants > MAX_INPUTS_PER_OBSERVATION_SET as u64
            || self.max_variants_per_method > self.max_total_variants
        {
            return Err("variants-above-contract");
        }
        if self.batch_variants < self.max_variants_per_case
            || self.batch_variants > MAX_BATCH_VARIANTS as usize
        {
            return Err("batch-out-of-range");
        }
        Ok(())
    }
}

impl Default for GenerationLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Which run-level limit ended a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GenerationLimit {
    /// Authored cases.
    Cases,
    /// Variants of one method.
    VariantsPerMethod,
    /// Variants in total.
    TotalVariants,
}

/// Why a whole run ended. Numeric payloads only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenerateError {
    /// A run-level limit would be exceeded; the run is not truncated.
    LimitExceeded {
        /// Which limit.
        limit: GenerationLimit,
        /// Its value.
        max: u64,
    },
    /// The same authored case id was supplied twice.
    DuplicateCase,
    /// A counter would exceed `u64` (unreachable within the explicit limits).
    CounterOverflow,
}

impl std::fmt::Display for GenerateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GenerateError::LimitExceeded { limit, max } => {
                write!(f, "generation limit {limit:?} of {max} exceeded")
            }
            GenerateError::DuplicateCase => f.write_str("duplicate authored case id"),
            GenerateError::CounterOverflow => f.write_str("generation counter overflow"),
        }
    }
}

impl std::error::Error for GenerateError {}

/// Why a generator could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneratorError {
    /// The snapshot's seed-derivation rule is not one this implementation
    /// knows; variants would carry guessed seeds, so none are generated.
    UnsupportedSeedDerivation,
    /// A limit is zero, above the contract maximum or inconsistent.
    InvalidLimits(&'static str),
}

// ---------------------------------------------------------------------------
// Refusals, reviews, provenance
// ---------------------------------------------------------------------------

/// Why one authored case was refused. Payload-free so refusals can be counted
/// and ordered; the case id travels beside it in [`Refusal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefusalReason {
    /// The candidate range is empty, inverted or structurally invalid.
    RangeInvalid,
    /// The candidate range ends past the text.
    RangeOutOfBounds,
    /// The candidate range is not on character boundaries.
    RangeNotOnCharBoundary,
    /// An offset above 2^53 - 1.
    RangeOffsetTooLarge,
    /// A text exceeds the text limit.
    TextTooLarge,
    /// The family's scope disagrees with the case jurisdiction.
    FamilyScopeMismatch,
    /// The case's evidence class belongs to another method or accounting class.
    EvidenceRoleMismatch,
    /// `type-validation` without a validator.
    MissingValidator,
    /// The authored type expectation contradicts the validator's observation.
    /// An authored expectation is never changed to agree with a validator.
    ValidatorExpectationMismatch,
    /// An authored validator expectation (benign or collision) was
    /// contradicted by the observation.
    ValidatorCheckMismatch,
    /// An authored validator expectation could not be observed.
    ValidatorCheckUnavailable,
    /// `pii-benign` with a sensitivity expectation other than non-sensitive.
    NotNonSensitive,
    /// `context-discrimination` with a type or obligation it does not accept.
    ContextCaseInvalid,
    /// The frames are not exactly one per context class.
    ContextFramesNotATrio,
    /// A frame's template does not hold exactly one candidate marker.
    FrameTemplateInvalid,
    /// A frame's class and sensitivity are not paired.
    FrameExpectationMismatch,
    /// Two frames share an id (or derive the same variant id).
    DuplicateFrame,
    /// A case would derive more variants than the per-case limit.
    TooManyVariants,
    /// A slot is not a slug or is too long.
    SlotInvalid,
    /// The collision declaration is empty, contains the target or is too large.
    InvalidCollision,
    /// `reference-differential` without a reference.
    MissingReference,
    /// The mutation operator is unknown.
    OperatorUnknown,
    /// The mutation operator exists at another version.
    OperatorVersionMismatch,
    /// The candidate does not satisfy the operator's precondition.
    OperatorNotApplicable,
    /// A derived identifier failed validation (unreachable for valid inputs).
    DerivationFailed,
}

impl RefusalReason {
    /// Stable reason string.
    pub const fn as_str(self) -> &'static str {
        match self {
            RefusalReason::RangeInvalid => "range-invalid",
            RefusalReason::RangeOutOfBounds => "range-out-of-bounds",
            RefusalReason::RangeNotOnCharBoundary => "range-not-on-char-boundary",
            RefusalReason::RangeOffsetTooLarge => "range-offset-too-large",
            RefusalReason::TextTooLarge => "text-too-large",
            RefusalReason::FamilyScopeMismatch => "family-scope-mismatch",
            RefusalReason::EvidenceRoleMismatch => "evidence-role-mismatch",
            RefusalReason::MissingValidator => "missing-validator",
            RefusalReason::ValidatorExpectationMismatch => "validator-expectation-mismatch",
            RefusalReason::ValidatorCheckMismatch => "validator-check-mismatch",
            RefusalReason::ValidatorCheckUnavailable => "validator-check-unavailable",
            RefusalReason::NotNonSensitive => "not-non-sensitive",
            RefusalReason::ContextCaseInvalid => "context-case-invalid",
            RefusalReason::ContextFramesNotATrio => "context-frames-not-a-trio",
            RefusalReason::FrameTemplateInvalid => "frame-template-invalid",
            RefusalReason::FrameExpectationMismatch => "frame-expectation-mismatch",
            RefusalReason::DuplicateFrame => "duplicate-frame",
            RefusalReason::TooManyVariants => "too-many-variants",
            RefusalReason::SlotInvalid => "slot-invalid",
            RefusalReason::InvalidCollision => "invalid-collision",
            RefusalReason::MissingReference => "missing-reference",
            RefusalReason::OperatorUnknown => "operator-unknown",
            RefusalReason::OperatorVersionMismatch => "operator-version-mismatch",
            RefusalReason::OperatorNotApplicable => "operator-not-applicable",
            RefusalReason::DerivationFailed => "derivation-failed",
        }
    }

    /// The contract reason code this refusal corresponds to, when the contract
    /// has one. Method-level reasons have none: the contracts are frozen and
    /// gain codes only through a reviewed schema revision.
    pub const fn contract_code(self) -> Option<ReasonCode> {
        match self {
            RefusalReason::RangeInvalid => Some(ReasonCode::RangeInvalid),
            RefusalReason::RangeOutOfBounds => Some(ReasonCode::RangeOutOfBounds),
            RefusalReason::RangeNotOnCharBoundary => Some(ReasonCode::RangeNotOnCharBoundary),
            RefusalReason::RangeOffsetTooLarge => Some(ReasonCode::IntegerOutOfRange),
            RefusalReason::TextTooLarge | RefusalReason::TooManyVariants => {
                Some(ReasonCode::LimitExceeded)
            }
            RefusalReason::FamilyScopeMismatch => Some(ReasonCode::FamilyScopeMismatch),
            RefusalReason::ContextFramesNotATrio => Some(ReasonCode::IncompleteContextTrio),
            RefusalReason::InvalidCollision => Some(ReasonCode::CollisionInvalid),
            RefusalReason::DuplicateFrame => Some(ReasonCode::DuplicateIdentity),
            _ => None,
        }
    }
}

impl From<RangeError> for RefusalReason {
    fn from(e: RangeError) -> Self {
        match e {
            RangeError::Empty | RangeError::Inverted => RefusalReason::RangeInvalid,
            RangeError::OffsetTooLarge => RefusalReason::RangeOffsetTooLarge,
            RangeError::OutOfBounds => RefusalReason::RangeOutOfBounds,
            RangeError::NotOnCharBoundary
            | RangeError::InsideSurrogatePair
            | RangeError::InvalidUtf8 => RefusalReason::RangeNotOnCharBoundary,
            RangeError::TextTooLarge => RefusalReason::TextTooLarge,
        }
    }
}

impl From<DerivationError> for RefusalReason {
    fn from(_: DerivationError) -> Self {
        RefusalReason::DerivationFailed
    }
}

/// One refused case: counted, explicit, never silently dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The refused authored case.
    pub case_id: Id,
    /// Its method.
    pub method: MethodId,
    /// Why.
    pub reason: RefusalReason,
}

/// Why a generated variant needs review or has an unmeasured type axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReviewReason {
    /// The validator that establishes the authored type was unavailable
    /// (`type-validation`).
    ValidatorUnavailable(UnavailableReason),
    /// The reference was unavailable (`reference-differential`).
    ReferenceUnavailable(UnavailableReason),
    /// The reference observed a type different from the authored one. The
    /// authored expectation stands; the disagreement is an observation.
    ReferenceDisagrees,
}

impl ReviewReason {
    /// Whether the type-identity axis of this variant cannot be measured.
    /// An unavailable validator or reference removes the type evidence; a
    /// disagreement does not.
    pub const fn unmeasures_type_axis(self) -> bool {
        !matches!(self, ReviewReason::ReferenceDisagrees)
    }

    /// Stable reason string.
    pub const fn as_str(self) -> &'static str {
        match self {
            ReviewReason::ValidatorUnavailable(_) => "validator-unavailable",
            ReviewReason::ReferenceUnavailable(_) => "reference-unavailable",
            ReviewReason::ReferenceDisagrees => "reference-disagrees",
        }
    }
}

/// Apply a variant's review state to an observed outcome row. When the type
/// evidence is unavailable the type axis is `not-measured`, never a pass or a
/// failure; every other axis is untouched. A reference disagreement leaves the
/// row unchanged: it is recorded, not scored.
pub fn apply_review(mut row: OutcomeRow, review: Option<ReviewReason>) -> OutcomeRow {
    if review.is_some_and(ReviewReason::unmeasures_type_axis) {
        row.type_identity = TypeState::NotMeasured;
    }
    row
}

/// A reference observation, recorded next to the unchanged authored
/// expectation. Its role is [`REFERENCE_ROLE`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceObservation {
    /// The observation.
    pub observation: ValidatorObservation,
}

/// Where a variant came from and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariantProvenance {
    /// The variant.
    pub variant_id: Id,
    /// The authored case it derives from.
    pub parent_case_id: Id,
    /// The variant's role inside the case.
    pub slot: Slot,
    /// The generating method and version.
    pub method: MethodRef,
    /// SHA-256 of the authored input text the variant derives from.
    pub parent_text_digest: Sha256Digest,
    /// Operator recorded in the derivation, if any.
    pub operator: Option<OperatorRef>,
    /// Seed recorded in the derivation, if any.
    pub seed: Option<Seed>,
    /// The seed rule that produced `seed`.
    pub seed_rule: SeedRule,
    /// The validator observation behind a `type-validation` variant.
    pub validation: Option<ValidatorObservation>,
    /// The reference observation of a `reference-differential` variant.
    pub reference: Option<ReferenceObservation>,
    /// Review state; see [`apply_review`].
    pub review: Option<ReviewReason>,
    /// Authored evidence class of the parent case. Not part of the snapshot
    /// (schema 1.0 carries no evidence class); kept here so a consumer can
    /// stratify by it.
    pub evidence: Option<EvidenceClass>,
}

/// One generated case: the contract case and the provenance of each variant,
/// in the same order (ascending by variant id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedCase {
    /// The contract case.
    pub case: Case,
    /// Provenance, aligned with `case.variants`.
    pub provenance: Vec<VariantProvenance>,
}

impl GeneratedCase {
    /// Variants of this case.
    pub fn variant_count(&self) -> u64 {
        self.case.variants.len() as u64
    }

    /// Outcome rows one scanner owes for this case: one per expected occurrence.
    pub fn occurrence_count(&self) -> u64 {
        self.case
            .variants
            .iter()
            .map(|v| v.expectations.len() as u64)
            .sum()
    }
}

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

/// Generates variants from authored cases under one set of generation rules.
#[derive(Debug)]
pub struct Generator<'v> {
    rules: GenerationRules,
    seed_rule: SeedRule,
    validators: &'v ValidatorRegistry,
    limits: GenerationLimits,
}

struct Draft {
    slot: Slot,
    text: String,
    expectation: Expectation,
    strategy: Strategy,
    operator: Option<OperatorRef>,
    validation: Option<ValidatorObservation>,
    reference: Option<ReferenceObservation>,
    review: Option<ReviewReason>,
}

fn value_of<'t>(text: &'t str, range: &ByteRange) -> Option<&'t str> {
    let s = usize::try_from(range.start).ok()?;
    let e = usize::try_from(range.end).ok()?;
    text.get(s..e)
}

fn expected_state(t: ExpectedType) -> ValidatorState {
    match t {
        ExpectedType::Valid => ValidatorState::Valid,
        ExpectedType::Invalid => ValidatorState::Invalid,
    }
}

fn slot(value: &str) -> Result<Slot, RefusalReason> {
    Slot::new(value).map_err(|_| RefusalReason::SlotInvalid)
}

fn occurrence_id() -> Result<Id, RefusalReason> {
    Id::new(OCCURRENCE_ID).map_err(|_| RefusalReason::DerivationFailed)
}

impl<'v> Generator<'v> {
    /// Build a generator for a snapshot's generation rules.
    ///
    /// The rules' `seedDerivation` must name a rule this implementation knows
    /// ([`SeedRule`]); otherwise [`GeneratorError::UnsupportedSeedDerivation`].
    pub fn new(
        rules: &GenerationRules,
        validators: &'v ValidatorRegistry,
        limits: GenerationLimits,
    ) -> Result<Self, GeneratorError> {
        let seed_rule = SeedRule::from_id(&rules.seed_derivation)
            .ok_or(GeneratorError::UnsupportedSeedDerivation)?;
        limits.validate().map_err(GeneratorError::InvalidLimits)?;
        Ok(Self {
            rules: rules.clone(),
            seed_rule,
            validators,
            limits,
        })
    }

    /// The generation rules the variants are recorded under.
    pub fn rules(&self) -> &GenerationRules {
        &self.rules
    }

    /// The limits in force.
    pub fn limits(&self) -> &GenerationLimits {
        &self.limits
    }

    /// Generate one case, or refuse it with a reason.
    pub fn generate_case(&self, case: &AuthoredCase) -> Result<GeneratedCase, Refusal> {
        self.generate_inner(case).map_err(|reason| Refusal {
            case_id: case.case_id.clone(),
            method: case.method(),
            reason,
        })
    }

    fn base_expectation(&self, case: &AuthoredCase) -> Result<Expectation, RefusalReason> {
        Ok(Expectation {
            occurrence_id: occurrence_id()?,
            range: case.candidate,
            family: case.family.clone(),
            type_expectation: case.type_expectation,
            validator: case.validator.clone(),
            sensitivity: case.sensitivity,
            context_class: case.context_class,
            context_obligation: case.context_obligation,
            action: case.action,
        })
    }

    fn generate_inner(&self, case: &AuthoredCase) -> Result<GeneratedCase, RefusalReason> {
        if case.text.len() > self.limits.max_text_bytes {
            return Err(RefusalReason::TextTooLarge);
        }
        validate_range(&case.text, &case.candidate)?;
        let scope_ok = match (case.family.scope(), case.jurisdiction.as_ref()) {
            (FamilyScope::Global, None) => true,
            (FamilyScope::Jurisdiction(a), Some(b)) => a == *b,
            _ => false,
        };
        if !scope_ok {
            return Err(RefusalReason::FamilyScopeMismatch);
        }
        if let Some(evidence) = case.evidence {
            if evidence.method() != case.method() {
                return Err(RefusalReason::EvidenceRoleMismatch);
            }
        }
        // Validators and references see the authored candidate only.
        let value = value_of(&case.text, &case.candidate).ok_or(RefusalReason::RangeInvalid)?;

        let mut collision: Option<Collision> = None;
        let drafts = match &case.params {
            MethodParams::SchemaOnly => vec![Draft {
                slot: slot("authored")?,
                text: case.text.clone(),
                expectation: self.base_expectation(case)?,
                strategy: Strategy::Authored,
                operator: None,
                validation: None,
                reference: None,
                review: None,
            }],
            MethodParams::TypeValidation => self.type_validation(case, value)?,
            MethodParams::ContextDiscrimination { frames } => {
                self.context_discrimination(case, value, frames)?
            }
            MethodParams::PiiBenign { class, checks } => {
                self.benign(case, value, *class, checks)?
            }
            MethodParams::JurisdictionCollision { competing, checks } => {
                let declared = self.collision(case, competing)?;
                let drafts = self.collision_drafts(case, value, checks)?;
                collision = Some(declared);
                drafts
            }
            MethodParams::Mutation { operator } => self.mutation(case, operator)?,
            MethodParams::ReferenceDifferential => self.reference(case, value)?,
        };
        self.finish(case, drafts, collision)
    }

    fn type_validation(
        &self,
        case: &AuthoredCase,
        value: &str,
    ) -> Result<Vec<Draft>, RefusalReason> {
        let validator = case
            .validator
            .as_ref()
            .ok_or(RefusalReason::MissingValidator)?;
        let observation = self.validators.observe(validator, value);
        let review = match observation.state {
            ValidatorState::Unavailable => observation
                .unavailable
                .map(ReviewReason::ValidatorUnavailable),
            state if state != expected_state(case.type_expectation) => {
                return Err(RefusalReason::ValidatorExpectationMismatch);
            }
            _ => None,
        };
        Ok(vec![Draft {
            slot: slot("validated")?,
            text: case.text.clone(),
            expectation: self.base_expectation(case)?,
            strategy: if review.is_some() {
                Strategy::ReviewRequired
            } else {
                Strategy::Authored
            },
            operator: None,
            validation: Some(observation),
            reference: None,
            review,
        }])
    }

    fn context_discrimination(
        &self,
        case: &AuthoredCase,
        value: &str,
        frames: &[ContextFrame],
    ) -> Result<Vec<Draft>, RefusalReason> {
        if case.type_expectation != ExpectedType::Valid
            || case.context_obligation
                != pii_eval_contracts::ContextObligation::RequiredForSensitiveClassification
        {
            return Err(RefusalReason::ContextCaseInvalid);
        }
        if frames.len() > self.limits.max_variants_per_case {
            return Err(RefusalReason::TooManyVariants);
        }
        let mut classes: Vec<ContextClass> = frames.iter().map(|f| f.context_class).collect();
        classes.sort();
        if classes
            != [
                ContextClass::Sensitive,
                ContextClass::Neutral,
                ContextClass::NonSensitive,
            ]
        {
            return Err(RefusalReason::ContextFramesNotATrio);
        }
        let mut drafts = Vec::with_capacity(frames.len());
        for frame in frames {
            let paired = matches!(
                (frame.context_class, frame.sensitivity),
                (ContextClass::Sensitive, SensitivityExpectation::Sensitive)
                    | (
                        ContextClass::Neutral,
                        SensitivityExpectation::NotEstablished
                    )
                    | (
                        ContextClass::NonSensitive,
                        SensitivityExpectation::NonSensitive
                    )
            );
            if !paired {
                return Err(RefusalReason::FrameExpectationMismatch);
            }
            let mut parts = frame.template.split(CANDIDATE_MARKER);
            let (Some(prefix), Some(suffix), None) = (parts.next(), parts.next(), parts.next())
            else {
                return Err(RefusalReason::FrameTemplateInvalid);
            };
            let start = prefix.len() as u64;
            let end = start + value.len() as u64;
            let mut expectation = self.base_expectation(case)?;
            expectation.range = ByteRange { start, end };
            expectation.sensitivity = frame.sensitivity;
            expectation.context_class = frame.context_class;
            drafts.push(Draft {
                slot: slot(frame.id.as_str())?,
                text: format!("{prefix}{value}{suffix}"),
                expectation,
                strategy: Strategy::Derived,
                operator: Some(operator_ref(CONTEXT_FRAME_ID, CONTEXT_FRAME_VERSION)?),
                validation: None,
                reference: None,
                review: None,
            });
        }
        Ok(drafts)
    }

    fn benign(
        &self,
        case: &AuthoredCase,
        value: &str,
        class: BenignClass,
        checks: &[ValidatorCheck],
    ) -> Result<Vec<Draft>, RefusalReason> {
        if case.sensitivity != SensitivityExpectation::NonSensitive {
            return Err(RefusalReason::NotNonSensitive);
        }
        if let Some(evidence) = case.evidence {
            if !evidence.accounting_classes().contains(&class) {
                return Err(RefusalReason::EvidenceRoleMismatch);
            }
        }
        self.run_checks(checks, value)?;
        Ok(vec![Draft {
            slot: slot(class.as_str())?,
            text: case.text.clone(),
            expectation: self.base_expectation(case)?,
            strategy: Strategy::Authored,
            operator: None,
            validation: None,
            reference: None,
            review: None,
        }])
    }

    fn collision(
        &self,
        case: &AuthoredCase,
        competing: &[pii_eval_contracts::FamilyId],
    ) -> Result<Collision, RefusalReason> {
        let competing: BTreeSet<_> = competing.iter().cloned().collect();
        if competing.is_empty()
            || competing.contains(&case.family)
            || competing.len() > MAX_COMPETING_FAMILIES
        {
            return Err(RefusalReason::InvalidCollision);
        }
        Ok(Collision {
            target_family: case.family.clone(),
            competing_families: competing.into_iter().collect(),
        })
    }

    fn collision_drafts(
        &self,
        case: &AuthoredCase,
        value: &str,
        checks: &[ValidatorCheck],
    ) -> Result<Vec<Draft>, RefusalReason> {
        self.run_checks(checks, value)?;
        Ok(vec![Draft {
            slot: slot("collision")?,
            text: case.text.clone(),
            expectation: self.base_expectation(case)?,
            strategy: Strategy::Authored,
            operator: None,
            validation: None,
            reference: None,
            review: None,
        }])
    }

    fn run_checks(&self, checks: &[ValidatorCheck], value: &str) -> Result<(), RefusalReason> {
        for check in checks {
            let observed = self.validators.observe(&check.validator, value);
            if observed.state != check.expected {
                return Err(if observed.state == ValidatorState::Unavailable {
                    RefusalReason::ValidatorCheckUnavailable
                } else {
                    RefusalReason::ValidatorCheckMismatch
                });
            }
        }
        Ok(())
    }

    fn mutation(
        &self,
        case: &AuthoredCase,
        operator: &OperatorRef,
    ) -> Result<Vec<Draft>, RefusalReason> {
        let mutated =
            apply_mutation(operator, &case.text, &case.candidate).map_err(|e| match e {
                OperatorError::Unknown => RefusalReason::OperatorUnknown,
                OperatorError::VersionMismatch => RefusalReason::OperatorVersionMismatch,
                OperatorError::NotApplicable => RefusalReason::OperatorNotApplicable,
            })?;
        let mut expectation = self.base_expectation(case)?;
        expectation.range = mutated.candidate;
        expectation.type_expectation = mutated.type_expectation;
        Ok(vec![Draft {
            slot: slot("mutated")?,
            text: mutated.text,
            expectation,
            strategy: Strategy::Derived,
            operator: Some(operator.clone()),
            validation: None,
            reference: None,
            review: None,
        }])
    }

    fn reference(&self, case: &AuthoredCase, value: &str) -> Result<Vec<Draft>, RefusalReason> {
        let reference = case
            .reference
            .as_ref()
            .ok_or(RefusalReason::MissingReference)?;
        let observation = self.validators.observe(reference, value);
        let review = match observation.state {
            ValidatorState::Unavailable => observation
                .unavailable
                .map(ReviewReason::ReferenceUnavailable),
            state if state != expected_state(case.type_expectation) => {
                Some(ReviewReason::ReferenceDisagrees)
            }
            _ => None,
        };
        // The authored expectation is kept whatever the reference observed.
        Ok(vec![Draft {
            slot: slot("reference")?,
            text: case.text.clone(),
            expectation: self.base_expectation(case)?,
            strategy: if matches!(review, Some(ReviewReason::ReferenceUnavailable(_))) {
                Strategy::ReviewRequired
            } else {
                Strategy::Authored
            },
            operator: None,
            validation: None,
            reference: Some(ReferenceObservation { observation }),
            review,
        }])
    }

    fn finish(
        &self,
        case: &AuthoredCase,
        drafts: Vec<Draft>,
        collision: Option<Collision>,
    ) -> Result<GeneratedCase, RefusalReason> {
        if drafts.len() > self.limits.max_variants_per_case {
            return Err(RefusalReason::TooManyVariants);
        }
        let method = MethodRef::frozen(case.method());
        let parent_text_digest = Sha256Digest::of_bytes(case.text.as_bytes());
        let mut rows: Vec<(Variant, VariantProvenance)> = Vec::with_capacity(drafts.len());
        for draft in drafts {
            if draft.text.len() > self.limits.max_text_bytes {
                return Err(RefusalReason::TextTooLarge);
            }
            let id = variant_id(&case.case_id, &draft.slot)?;
            let (operator, seed) = match draft.strategy {
                Strategy::Authored => (None, None),
                Strategy::Derived => (
                    draft.operator.clone(),
                    Some(derive_seed(
                        self.seed_rule,
                        &self.rules.generator,
                        self.rules.generator_version,
                        &case.seed,
                        &case.case_id,
                        &draft.slot,
                    )?),
                ),
                Strategy::ReviewRequired => (
                    Some(operator_ref(REVIEW_HOLD_ID, REVIEW_HOLD_VERSION)?),
                    None,
                ),
            };
            let variant = Variant {
                variant_id: id.clone(),
                derivation: Derivation {
                    strategy: draft.strategy,
                    operator: operator.clone(),
                    seed: seed.clone(),
                },
                text_digest: Sha256Digest::of_bytes(draft.text.as_bytes()),
                text: draft.text,
                expectations: vec![draft.expectation],
            };
            let provenance = VariantProvenance {
                variant_id: id,
                parent_case_id: case.case_id.clone(),
                slot: draft.slot,
                method,
                parent_text_digest: parent_text_digest.clone(),
                operator,
                seed,
                seed_rule: self.seed_rule,
                validation: draft.validation,
                reference: draft.reference,
                review: draft.review,
                evidence: case.evidence,
            };
            rows.push((variant, provenance));
        }
        rows.sort_by(|a, b| a.0.variant_id.cmp(&b.0.variant_id));
        if rows
            .windows(2)
            .any(|w| w[0].0.variant_id == w[1].0.variant_id)
        {
            return Err(RefusalReason::DuplicateFrame);
        }
        let (variants, provenance): (Vec<_>, Vec<_>) = rows.into_iter().unzip();
        Ok(GeneratedCase {
            case: Case {
                case_id: case.case_id.clone(),
                method: case.method(),
                lineage: case.lineage.clone(),
                language: case.language.clone(),
                jurisdiction: case.jurisdiction.clone(),
                collision,
                variants,
            },
            provenance,
        })
    }

    /// A lazy run over `cases`: one item per case, in the order supplied.
    pub fn run<'g, 'c, I>(&'g self, cases: I) -> GenerationRun<'g, 'v, I::IntoIter>
    where
        I: IntoIterator<Item = &'c AuthoredCase>,
    {
        GenerationRun {
            generator: self,
            cases: cases.into_iter(),
            report: GenerationReport::default(),
            seen: BTreeSet::new(),
            failed: false,
        }
    }

    /// Generate every case and return the results in canonical order
    /// (ascending case id), so the output does not depend on input order.
    /// Materializes the whole result; use [`Generator::run`] and
    /// [`GenerationRun::batches`] to stay bounded.
    pub fn generate_all<'c, I>(&self, cases: I) -> Result<GenerationOutput, GenerateError>
    where
        I: IntoIterator<Item = &'c AuthoredCase>,
    {
        let mut run = self.run(cases);
        let mut generated = Vec::new();
        let mut refused = Vec::new();
        for item in run.by_ref() {
            match item? {
                CaseResult::Generated(g) => generated.push(g),
                CaseResult::Refused(r) => refused.push(r),
            }
        }
        generated.sort_by(|a, b| a.case.case_id.cmp(&b.case.case_id));
        refused.sort_by(|a, b| a.case_id.cmp(&b.case_id));
        Ok(GenerationOutput {
            generated,
            refused,
            report: run.report,
        })
    }
}

fn operator_ref(id: &str, version: u32) -> Result<OperatorRef, RefusalReason> {
    Ok(OperatorRef {
        id: Id::new(id).map_err(|_| RefusalReason::DerivationFailed)?,
        version,
    })
}

// ---------------------------------------------------------------------------
// Runs, batches, reports
// ---------------------------------------------------------------------------

/// The outcome of one authored case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaseResult {
    /// Generated.
    Generated(GeneratedCase),
    /// Refused, with a reason.
    Refused(Refusal),
}

/// Per-method counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MethodReport {
    /// Authored cases supplied.
    pub cases_in: u64,
    /// Cases generated.
    pub cases_generated: u64,
    /// Cases refused.
    pub cases_refused: u64,
    /// Variants generated.
    pub variants: u64,
}

/// Counters of one run. Authored cases in always equal generated plus refused;
/// [`GenerationReport::is_conserved`] checks it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GenerationReport {
    /// Authored cases supplied.
    pub cases_in: u64,
    /// Cases generated.
    pub cases_generated: u64,
    /// Variants generated.
    pub variants_generated: u64,
    /// Refusals by reason, ascending.
    pub refused: BTreeMap<RefusalReason, u64>,
    /// Counters by method, ascending by wire id order of the enum.
    pub by_method: BTreeMap<MethodId, MethodReport>,
}

impl GenerationReport {
    /// Cases refused, all reasons.
    pub fn cases_refused(&self) -> u64 {
        self.refused.values().sum()
    }

    /// Denominator conservation: every supplied case was generated or refused,
    /// and the per-method counters add up to the totals.
    pub fn is_conserved(&self) -> bool {
        let methods = self
            .by_method
            .values()
            .fold((0u64, 0u64, 0u64, 0u64), |a, m| {
                (
                    a.0 + m.cases_in,
                    a.1 + m.cases_generated,
                    a.2 + m.cases_refused,
                    a.3 + m.variants,
                )
            });
        self.cases_in == self.cases_generated + self.cases_refused()
            && methods
                == (
                    self.cases_in,
                    self.cases_generated,
                    self.cases_refused(),
                    self.variants_generated,
                )
    }

    fn record(&mut self, method: MethodId, result: &CaseResult) -> Result<(), GenerateError> {
        let add = |counter: &mut u64, by: u64| {
            *counter = counter
                .checked_add(by)
                .ok_or(GenerateError::CounterOverflow)?;
            Ok::<(), GenerateError>(())
        };
        add(&mut self.cases_in, 1)?;
        let m = self.by_method.entry(method).or_default();
        add(&mut m.cases_in, 1)?;
        match result {
            CaseResult::Generated(g) => {
                add(&mut self.cases_generated, 1)?;
                add(&mut self.variants_generated, g.variant_count())?;
                add(&mut m.cases_generated, 1)?;
                add(&mut m.variants, g.variant_count())?;
            }
            CaseResult::Refused(r) => {
                add(self.refused.entry(r.reason).or_default(), 1)?;
                add(&mut m.cases_refused, 1)?;
            }
        }
        Ok(())
    }
}

/// A lazy generation run. After an error the run is finished.
#[derive(Debug)]
pub struct GenerationRun<'g, 'v, I> {
    generator: &'g Generator<'v>,
    cases: I,
    report: GenerationReport,
    seen: BTreeSet<Id>,
    failed: bool,
}

impl<'g, 'v, 'c, I> GenerationRun<'g, 'v, I>
where
    I: Iterator<Item = &'c AuthoredCase>,
{
    /// The counters so far.
    pub fn report(&self) -> &GenerationReport {
        &self.report
    }

    /// Group the results into batches of at most `batch_variants` variants
    /// plus refusals.
    pub fn batches(self) -> Batches<'g, 'v, I> {
        let max_units = self.generator.limits.batch_variants;
        Batches {
            run: self,
            max_units,
            pending: None,
        }
    }

    fn fail(&mut self, e: GenerateError) -> Option<Result<CaseResult, GenerateError>> {
        self.failed = true;
        Some(Err(e))
    }
}

impl<'c, I> Iterator for GenerationRun<'_, '_, I>
where
    I: Iterator<Item = &'c AuthoredCase>,
{
    type Item = Result<CaseResult, GenerateError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        let case = self.cases.next()?;
        let limits = self.generator.limits;
        if self.report.cases_in >= limits.max_cases {
            return self.fail(GenerateError::LimitExceeded {
                limit: GenerationLimit::Cases,
                max: limits.max_cases,
            });
        }
        if !self.seen.insert(case.case_id.clone()) {
            return self.fail(GenerateError::DuplicateCase);
        }
        let result = match self.generator.generate_case(case) {
            Ok(g) => {
                let method_total = self
                    .report
                    .by_method
                    .get(&case.method())
                    .map_or(0, |m| m.variants);
                if method_total.saturating_add(g.variant_count()) > limits.max_variants_per_method {
                    return self.fail(GenerateError::LimitExceeded {
                        limit: GenerationLimit::VariantsPerMethod,
                        max: limits.max_variants_per_method,
                    });
                }
                if self
                    .report
                    .variants_generated
                    .saturating_add(g.variant_count())
                    > limits.max_total_variants
                {
                    return self.fail(GenerateError::LimitExceeded {
                        limit: GenerationLimit::TotalVariants,
                        max: limits.max_total_variants,
                    });
                }
                CaseResult::Generated(g)
            }
            Err(r) => CaseResult::Refused(r),
        };
        if let Err(e) = self.report.record(case.method(), &result) {
            return self.fail(e);
        }
        Some(Ok(result))
    }
}

/// A bounded group of results.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Batch {
    /// Generated cases, in the order the run produced them.
    pub generated: Vec<GeneratedCase>,
    /// Refusals, in the order the run produced them.
    pub refused: Vec<Refusal>,
}

impl Batch {
    /// Variants in the batch.
    pub fn variant_count(&self) -> u64 {
        self.generated
            .iter()
            .map(GeneratedCase::variant_count)
            .sum()
    }

    fn units(&self) -> usize {
        self.generated
            .iter()
            .map(|g| g.case.variants.len())
            .sum::<usize>()
            + self.refused.len()
    }
}

/// Batches of a run. Each batch holds at most `batch_variants` variants plus
/// refusals (at least one case, so progress is guaranteed; a case never
/// exceeds the per-case limit, which is at most the batch size).
#[derive(Debug)]
pub struct Batches<'g, 'v, I> {
    run: GenerationRun<'g, 'v, I>,
    max_units: usize,
    pending: Option<CaseResult>,
}

impl<'g, 'v, 'c, I> Batches<'g, 'v, I>
where
    I: Iterator<Item = &'c AuthoredCase>,
{
    /// The counters of the underlying run.
    pub fn report(&self) -> &GenerationReport {
        self.run.report()
    }

    fn push(batch: &mut Batch, item: CaseResult) {
        match item {
            CaseResult::Generated(g) => batch.generated.push(g),
            CaseResult::Refused(r) => batch.refused.push(r),
        }
    }

    fn weight(item: &CaseResult) -> usize {
        match item {
            CaseResult::Generated(g) => g.case.variants.len(),
            CaseResult::Refused(_) => 1,
        }
    }
}

impl<'c, I> Iterator for Batches<'_, '_, I>
where
    I: Iterator<Item = &'c AuthoredCase>,
{
    type Item = Result<Batch, GenerateError>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut batch = Batch::default();
        if let Some(item) = self.pending.take() {
            Self::push(&mut batch, item);
        }
        loop {
            match self.run.next() {
                None => break,
                Some(Err(e)) => return Some(Err(e)),
                Some(Ok(item)) => {
                    if batch.units() + Self::weight(&item) > self.max_units {
                        self.pending = Some(item);
                        break;
                    }
                    Self::push(&mut batch, item);
                }
            }
        }
        if batch.generated.is_empty() && batch.refused.is_empty() {
            None
        } else {
            Some(Ok(batch))
        }
    }
}

/// The materialized result of [`Generator::generate_all`], in canonical order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationOutput {
    /// Generated cases, ascending by case id.
    pub generated: Vec<GeneratedCase>,
    /// Refusals, ascending by case id.
    pub refused: Vec<Refusal>,
    /// Counters.
    pub report: GenerationReport,
}

// ---------------------------------------------------------------------------
// Assembly
// ---------------------------------------------------------------------------

/// Why generated cases could not be assembled into a snapshot body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssembleError {
    /// Two generated cases share a case id.
    DuplicateCase,
    /// A variant id appears in two cases.
    DuplicateVariant,
}

/// Put generated cases into canonical order (ascending case id). The result
/// does not depend on the order in which workers finished.
pub fn assemble_cases<I>(generated: I) -> Result<Vec<Case>, AssembleError>
where
    I: IntoIterator<Item = GeneratedCase>,
{
    let mut cases: Vec<Case> = generated.into_iter().map(|g| g.case).collect();
    cases.sort_by(|a, b| a.case_id.cmp(&b.case_id));
    if cases.windows(2).any(|w| w[0].case_id == w[1].case_id) {
        return Err(AssembleError::DuplicateCase);
    }
    let mut variants = BTreeSet::new();
    for v in cases.iter().flat_map(|c| &c.variants) {
        if !variants.insert(&v.variant_id) {
            return Err(AssembleError::DuplicateVariant);
        }
    }
    Ok(cases)
}

/// A snapshot body from generated cases, ready to be sealed by the contracts.
/// `population` and `rules` are the author's; `rules` must be the rules the
/// generator was built with so the recorded seeds are reproducible.
pub fn assemble_body<I>(
    population: Population,
    rules: GenerationRules,
    generated: I,
) -> Result<CorpusSnapshotBody, AssembleError>
where
    I: IntoIterator<Item = GeneratedCase>,
{
    Ok(CorpusSnapshotBody {
        population,
        generation: rules,
        cases: assemble_cases(generated)?,
    })
}
