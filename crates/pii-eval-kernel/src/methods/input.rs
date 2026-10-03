//! The authored input of method generation.
//!
//! An [`AuthoredCase`] is what a corpus author writes for one case: one input
//! text, the expected occurrence in it, the authored expectations, and the
//! parameters of the case's method. Methods *derive* contract variants from it
//! ([`crate::methods::Generator`]); nothing here is scanner output and no
//! field is ever edited to match a scanner.

use pii_eval_contracts::{
    ActionExpectation, ByteRange, ContextClass, ContextObligation, ExpectedType, FamilyId, Id,
    JurisdictionCode, LanguageTag, Lineage, MethodId, OperatorRef, Seed, SensitivityExpectation,
    ValidatorRef,
};

use super::validators::ValidatorState;

/// The six authored benign accounting classes of the `pii-v1` profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BenignClass {
    /// Reserved identifier (documentation or authority reserved).
    Reserved,
    /// Documentation display value.
    Documentation,
    /// Official test value.
    TestValue,
    /// Public operational identifier.
    PublicOperational,
    /// Placeholder value.
    Placeholder,
    /// Value whose context marks it as non-sensitive.
    ContextNegative,
}

impl BenignClass {
    /// The oracle's wire string; also the slot of the benign variant.
    pub const fn as_str(self) -> &'static str {
        match self {
            BenignClass::Reserved => "reserved",
            BenignClass::Documentation => "documentation",
            BenignClass::TestValue => "test-value",
            BenignClass::PublicOperational => "public-operational",
            BenignClass::Placeholder => "placeholder",
            BenignClass::ContextNegative => "context-negative",
        }
    }
}

/// The eight authored evidence classes of the oracle's benign/collision
/// corpus. The mapping to accounting classes is deliberately lossy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvidenceClass {
    /// Reserved documentation value.
    ReservedDocumentation,
    /// Official test value.
    OfficialTest,
    /// Public identifier.
    PublicIdentifier,
    /// Ordinary reference account.
    OrdinaryReferenceAccount,
    /// Mechanically invalid near miss (validator and type control).
    NearMiss,
    /// Placeholder.
    Placeholder,
    /// Context-negative value.
    ContextNegative,
    /// Value valid under several families.
    CrossFamilyCollision,
}

impl EvidenceClass {
    /// The oracle's wire string.
    pub const fn as_str(self) -> &'static str {
        match self {
            EvidenceClass::ReservedDocumentation => "reserved-documentation",
            EvidenceClass::OfficialTest => "official-test",
            EvidenceClass::PublicIdentifier => "public-identifier",
            EvidenceClass::OrdinaryReferenceAccount => "ordinary-reference-account",
            EvidenceClass::NearMiss => "near-miss",
            EvidenceClass::Placeholder => "placeholder",
            EvidenceClass::ContextNegative => "context-negative",
            EvidenceClass::CrossFamilyCollision => "cross-family-collision",
        }
    }

    /// The method that counts this evidence class (`PII_EVIDENCE_CLASS_ROLES`).
    pub const fn method(self) -> MethodId {
        match self {
            EvidenceClass::NearMiss => MethodId::TypeValidation,
            EvidenceClass::CrossFamilyCollision => MethodId::JurisdictionCollision,
            _ => MethodId::PiiBenign,
        }
    }

    /// The accounting classes this evidence class may carry
    /// (`PII_EVIDENCE_ACCOUNTING_CLASSES`); empty for classes that are not
    /// benign evidence.
    pub const fn accounting_classes(self) -> &'static [BenignClass] {
        match self {
            EvidenceClass::ReservedDocumentation => {
                &[BenignClass::Reserved, BenignClass::Documentation]
            }
            EvidenceClass::OfficialTest => &[BenignClass::TestValue],
            EvidenceClass::PublicIdentifier | EvidenceClass::OrdinaryReferenceAccount => {
                &[BenignClass::PublicOperational]
            }
            EvidenceClass::Placeholder => &[BenignClass::Placeholder],
            EvidenceClass::ContextNegative => &[BenignClass::ContextNegative],
            EvidenceClass::NearMiss | EvidenceClass::CrossFamilyCollision => &[],
        }
    }
}

/// One context frame: a template around `{{candidate}}` with its authored
/// context class and the sensitivity that frame establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextFrame {
    /// Frame identifier; becomes the variant's slot.
    pub id: Id,
    /// Text with exactly one `{{candidate}}` marker.
    pub template: String,
    /// Authored context class of the frame.
    pub context_class: ContextClass,
    /// Authored sensitivity of the occurrence in this frame. `sensitive` pairs
    /// with the sensitive class, `non-sensitive` with the non-sensitive class
    /// and `not-established` with the neutral class.
    pub sensitivity: SensitivityExpectation,
}

/// The marker a context template replaces with the candidate.
pub const CANDIDATE_MARKER: &str = "{{candidate}}";

/// An authored validator expectation checked against the case's candidate
/// (the oracle's evidence `validator` and collision `party` expectations).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorCheck {
    /// Validator asked.
    pub validator: ValidatorRef,
    /// Authored expected observation.
    pub expected: ValidatorState,
}

/// Method-specific parameters. The variant fixes the case's method, so a case
/// cannot name one method and carry another's parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MethodParams {
    /// `schema-only`: the authored variant, unchanged.
    SchemaOnly,
    /// `type-validation`: the authored variant, checked against the case's
    /// validator.
    TypeValidation,
    /// `context-discrimination`: one derived variant per frame.
    ContextDiscrimination {
        /// The frames; exactly one per context class.
        frames: Vec<ContextFrame>,
    },
    /// `pii-benign`: the authored variant as a benign control.
    PiiBenign {
        /// Benign accounting class; also the variant's slot.
        class: BenignClass,
        /// Authored validator expectations to confirm.
        checks: Vec<ValidatorCheck>,
    },
    /// `jurisdiction-collision`: the authored variant as a collision case.
    JurisdictionCollision {
        /// Competing families (deduplicated and ordered by the generator).
        competing: Vec<FamilyId>,
        /// Authored validator expectations of the target and competitors.
        checks: Vec<ValidatorCheck>,
    },
    /// `mutation`: one variant derived by an operator.
    Mutation {
        /// The operator to apply.
        operator: OperatorRef,
    },
    /// `reference-differential`: the authored variant plus the observation of
    /// the case's independent reference.
    ReferenceDifferential,
}

impl MethodParams {
    /// The method these parameters belong to.
    pub const fn method(&self) -> MethodId {
        match self {
            MethodParams::SchemaOnly => MethodId::SchemaOnly,
            MethodParams::TypeValidation => MethodId::TypeValidation,
            MethodParams::ContextDiscrimination { .. } => MethodId::ContextDiscrimination,
            MethodParams::PiiBenign { .. } => MethodId::PiiBenign,
            MethodParams::JurisdictionCollision { .. } => MethodId::JurisdictionCollision,
            MethodParams::Mutation { .. } => MethodId::Mutation,
            MethodParams::ReferenceDifferential => MethodId::ReferenceDifferential,
        }
    }
}

/// One authored case, before method generation.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthoredCase {
    /// Authored case identifier; unique within one generation run.
    pub case_id: Id,
    /// Source lineage.
    pub lineage: Lineage,
    /// Language of the text.
    pub language: LanguageTag,
    /// Jurisdiction, or `None` for a global case.
    pub jurisdiction: Option<JurisdictionCode>,
    /// Expected family. Its scope must agree with the jurisdiction.
    pub family: FamilyId,
    /// The authored input text.
    pub text: String,
    /// The expected occurrence: half-open UTF-8 byte range into `text`.
    pub candidate: ByteRange,
    /// Authored type expectation.
    pub type_expectation: ExpectedType,
    /// Validator behind the type expectation.
    pub validator: Option<ValidatorRef>,
    /// Authored sensitivity expectation.
    pub sensitivity: SensitivityExpectation,
    /// Authored context class.
    pub context_class: ContextClass,
    /// Whether context is needed for a sensitive classification.
    pub context_obligation: ContextObligation,
    /// Authored action expectation.
    pub action: ActionExpectation,
    /// Independent reference, used by `reference-differential`.
    pub reference: Option<ValidatorRef>,
    /// The authored per-case seed (the oracle's `provenance.seed`). Derived
    /// variant seeds are computed from it by the snapshot's seed rule.
    pub seed: Seed,
    /// Authored evidence class, when the case comes from the benign/collision
    /// evidence corpus.
    pub evidence: Option<EvidenceClass>,
    /// Method parameters; they fix the case's method.
    pub params: MethodParams,
}

impl AuthoredCase {
    /// The case's method.
    pub const fn method(&self) -> MethodId {
        self.params.method()
    }
}

impl std::fmt::Debug for AuthoredCase {
    /// Never prints the input text: only its length.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthoredCase")
            .field("case_id", &self.case_id)
            .field("method", &self.method())
            .field("family", &self.family)
            .field(
                "text",
                &format_args!("<redacted {} bytes>", self.text.len()),
            )
            .field("candidate", &self.candidate)
            .finish_non_exhaustive()
    }
}
