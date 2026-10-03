//! Versioned definitions of the seven methods: what each derives from an
//! authored case, which metric only it feeds, and what its evidence does and
//! does not support.
//!
//! The ids and versions are the frozen `pii-v1` registry's
//! ([`pii_eval_contracts::METHODS`]); a test pins this table to the registry so
//! neither can drift. The generic metrics (`type-miss-rate`,
//! `wrong-family-rate`, `wrong-jurisdiction-rate`, `sensitive-miss-rate`,
//! `non-sensitive-flag-rate`, `range-collateral-rate`, `measurable-share`)
//! pool every method's outcome rows by authored expectation; the three
//! restricted metrics are fed by one method each.

use pii_eval_contracts::{MethodId, MetricId};

/// How the slots (local variant roles) of a method are chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotRule {
    /// One variant in a fixed slot.
    Fixed(&'static str),
    /// One variant per context frame, in the frame's id.
    ContextFrame,
    /// One variant in the benign accounting class's name.
    BenignClass,
}

/// How a method's variants relate to the authored case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivationKind {
    /// The authored variant, unchanged (`authored`); a held-for-review variant
    /// when its validator observation is unavailable.
    Authored,
    /// Derived from context frames (operator `context-frame` v1, seeded).
    ContextFrames,
    /// Derived by a named mutation operator (seeded).
    Operator,
}

/// What a validator contributes to a method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorRole {
    /// The method uses no validator.
    None,
    /// The validator must agree with the authored type expectation; a
    /// disagreement is an authoring defect and the case is refused.
    Confirms,
    /// The validator's authored expectations (evidence corpus) must be
    /// confirmed; a disagreement refuses the case.
    ChecksAuthoredExpectations,
    /// The reference's observation is recorded next to the unchanged authored
    /// expectation. Disagreement is an observation, never a replacement.
    ObservedNotTruth,
}

/// The versioned definition of one method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodSpec {
    /// Method id.
    pub id: MethodId,
    /// Method version (the frozen registry's).
    pub version: u32,
    /// Slot rule.
    pub slots: SlotRule,
    /// Derivation kind.
    pub derivation: DerivationKind,
    /// Exactly this many variants per case, or `None` for "one per frame".
    pub variants_per_case: Option<usize>,
    /// Validator role.
    pub validator: ValidatorRole,
    /// The restricted metric only this method feeds, if any.
    pub restricted_metric: Option<MetricId>,
    /// Whether rows of this method are evidence about scanner behaviour on
    /// real-world input. `schema-only` rows exercise the contract and the
    /// scoring path; they never imply runtime accuracy.
    pub runtime_accuracy_evidence: bool,
}

/// The seven methods, in registry order.
pub const SPECS: [MethodSpec; 7] = [
    MethodSpec {
        id: MethodId::TypeValidation,
        version: 2,
        slots: SlotRule::Fixed("validated"),
        derivation: DerivationKind::Authored,
        variants_per_case: Some(1),
        validator: ValidatorRole::Confirms,
        restricted_metric: None,
        runtime_accuracy_evidence: true,
    },
    MethodSpec {
        id: MethodId::ContextDiscrimination,
        version: 2,
        slots: SlotRule::ContextFrame,
        derivation: DerivationKind::ContextFrames,
        variants_per_case: Some(3),
        validator: ValidatorRole::None,
        restricted_metric: Some(MetricId::ContextDiscriminationRate),
        runtime_accuracy_evidence: true,
    },
    MethodSpec {
        id: MethodId::PiiBenign,
        version: 3,
        slots: SlotRule::BenignClass,
        derivation: DerivationKind::Authored,
        variants_per_case: Some(1),
        validator: ValidatorRole::ChecksAuthoredExpectations,
        restricted_metric: Some(MetricId::BenignSuppressionRate),
        runtime_accuracy_evidence: true,
    },
    MethodSpec {
        id: MethodId::JurisdictionCollision,
        version: 3,
        slots: SlotRule::Fixed("collision"),
        derivation: DerivationKind::Authored,
        variants_per_case: Some(1),
        validator: ValidatorRole::ChecksAuthoredExpectations,
        restricted_metric: Some(MetricId::JurisdictionCollisionRate),
        runtime_accuracy_evidence: true,
    },
    MethodSpec {
        id: MethodId::Mutation,
        version: 1,
        slots: SlotRule::Fixed("mutated"),
        derivation: DerivationKind::Operator,
        variants_per_case: Some(1),
        validator: ValidatorRole::None,
        restricted_metric: None,
        runtime_accuracy_evidence: true,
    },
    MethodSpec {
        id: MethodId::ReferenceDifferential,
        version: 1,
        slots: SlotRule::Fixed("reference"),
        derivation: DerivationKind::Authored,
        variants_per_case: Some(1),
        validator: ValidatorRole::ObservedNotTruth,
        restricted_metric: None,
        runtime_accuracy_evidence: true,
    },
    MethodSpec {
        id: MethodId::SchemaOnly,
        version: 1,
        slots: SlotRule::Fixed("authored"),
        derivation: DerivationKind::Authored,
        variants_per_case: Some(1),
        validator: ValidatorRole::None,
        restricted_metric: None,
        runtime_accuracy_evidence: false,
    },
];

/// The definition of `method`.
pub fn spec(method: MethodId) -> &'static MethodSpec {
    // Exhaustive: no fallback. A test pins each entry to its method id.
    match method {
        MethodId::TypeValidation => &SPECS[0],
        MethodId::ContextDiscrimination => &SPECS[1],
        MethodId::PiiBenign => &SPECS[2],
        MethodId::JurisdictionCollision => &SPECS[3],
        MethodId::Mutation => &SPECS[4],
        MethodId::ReferenceDifferential => &SPECS[5],
        MethodId::SchemaOnly => &SPECS[6],
    }
}

/// The methods whose rows may support a runtime-accuracy statement, ascending
/// by wire id. A consumer that reports accuracy must read the by-method strata
/// of these methods only; `schema-only` is excluded.
pub fn runtime_accuracy_methods() -> Vec<MethodId> {
    let mut v: Vec<MethodId> = SPECS
        .iter()
        .filter(|s| s.runtime_accuracy_evidence)
        .map(|s| s.id)
        .collect();
    v.sort_by_key(|m| m.as_str());
    v
}
