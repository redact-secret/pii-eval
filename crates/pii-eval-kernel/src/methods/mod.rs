//! The seven PII evaluation methods and deterministic variant provenance
//! (P5, issue #6; ADR 0007).
//!
//! `type-validation` (v2), `context-discrimination` (v2), `pii-benign` (v3),
//! `jurisdiction-collision` (v3), `mutation` (v1), `reference-differential`
//! (v1) and `schema-only` (v1) are ported from the pinned oracle's
//! `methods/*.ts`. A method turns an authored case ([`AuthoredCase`]) into
//! contract variants ([`Generator`]) with parent-case provenance, a
//! deterministic variant id and, for derived variants, a deterministic seed
//! ([`ids`]). The outcome rows for those variants come from `matching`, and
//! the ten metrics from `accounting`; this module only decides what each
//! method contributes to them.
//!
//! Boundaries:
//!
//! - Pure: no process, network, clock, random source or file.
//! - Generic validator observations ([`validators`]) are observations. Product
//!   activation gates, thresholds and support status live downstream.
//! - A reference's disagreement with an authored expectation is recorded as an
//!   observation ([`ReviewReason::ReferenceDisagrees`]); it never replaces the
//!   authored expectation.
//! - `schema-only` rows never imply runtime accuracy
//!   ([`MethodSpec::runtime_accuracy_evidence`]).
//! - A case or method that cannot be honoured is refused with a reason
//!   ([`RefusalReason`]) and counted ([`GenerationReport`]); an unavailable
//!   validator is a review state with an unmeasured type axis, never a clean
//!   result ([`apply_review`]).

mod gate;
mod generate;
pub mod ids;
mod input;
pub mod operators;
mod spec;
pub mod validators;
mod views;

/// Identifier of the methods generation rule set.
pub const METHODS_RULE_ID: &str = "pii-v1-methods";
/// Revision of this crate's variant-generation rules (ids, seeds, derivations).
/// Independent of the method versions, which are the frozen registry's.
pub const METHODS_REVISION: u32 = 1;

pub use gate::{ReviewGate, account_gated};
pub use generate::{
    AssembleError, Batch, Batches, CaseResult, GenerateError, GeneratedCase, GenerationLimit,
    GenerationLimits, GenerationOutput, GenerationReport, GenerationRun, Generator, GeneratorError,
    MethodReport, OCCURRENCE_ID, REFERENCE_ROLE, ReferenceObservation, Refusal, RefusalReason,
    ReviewReason, VariantProvenance, apply_review, apply_review_strategy, assemble_body,
    assemble_cases,
};
pub use ids::{
    DerivationError, MAX_SLOT_BYTES, SEED_RULE_LEGACY, SEED_RULE_V1, SeedRule, Slot, SlotError,
    VARIANT_ID_DOMAIN, VARIANT_SEED_DOMAIN, derive_seed, legacy_contract_seed,
    materialize_sha256_pattern, preimage, variant_id,
};
pub use input::{
    AuthoredCase, BenignClass, CANDIDATE_MARKER, ContextFrame, EvidenceClass, MethodParams,
    ValidatorCheck,
};
pub use operators::{Mutation, OperatorError, apply_mutation};
pub use spec::{
    DerivationKind, MethodSpec, SPECS, SlotRule, ValidatorRole, runtime_accuracy_methods, spec,
};
pub use validators::{
    UnavailableReason, ValidatorDef, ValidatorObservation, ValidatorRegistry, ValidatorState,
};
pub use views::{PopulationView, ViewAssignment, ViewComposition, ViewError, ViewRoster};
