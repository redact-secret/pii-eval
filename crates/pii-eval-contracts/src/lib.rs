//! Typed contracts for `pii-eval`: versioned input, observation and artifact
//! documents, the frozen `pii-v1` protocol registry, structural validation,
//! canonical serialization and the semantic digest.
//!
//! Status: schema 1.0 is frozen by P2 (issue #3); see ADR 0002 for the change
//! rules and ADR 0003 for the canonical serialization. The Rust API of this
//! crate is internal. The versioned JSON documents and the committed JSON
//! Schemas under `schemas/` are the consumer contracts.
//!
//! This crate contains types, validation and digests only. It performs no
//! matching, scoring, scanner execution or I/O.

#![forbid(unsafe_code)]

pub mod artifact;
pub mod axes;
pub mod binding;
pub mod canonical;
mod check;
pub mod corpus;
pub mod decimal;
pub mod document;
pub mod ident;
pub mod limits;
pub mod manifest;
pub mod observation;
pub mod protocol;
pub mod reason;
pub mod scanner;
pub mod schema;
pub mod version;

pub use artifact::{
    ArtifactScanner, CaseOutcome, Completeness, FailureCode, MeasurementFailure, MethodCoverage,
    MetricCounts, MetricResult, MetricValue, ObservedSummary, Phase, PhaseTiming, PopulationCounts,
    PublicOutcome, PublicScannerSummary, PublicSyntheticArtifact, PublicSyntheticArtifactBody,
    PublicSyntheticClass, RunArtifact, RunArtifactBody, RunDiagnostics, serialize_internal,
    serialize_public_synthetic,
};
pub use axes::{
    ActionExpectation, ActionKind, ActionOutcome, AxisStatus, ContextClass, ContextObligation,
    ExpectedType, OutputVerification, RangeState, SensitivityExpectation, SensitivityState,
    TypeState, validate_outcome_lattice,
};
pub use binding::{
    validate_artifact_against_manifest, validate_artifact_against_snapshot,
    validate_manifest_against_snapshot, validate_observation_against_manifest,
    validate_observation_against_snapshot,
};
pub use canonical::{
    DIGEST_CONSTRUCTION, ParseLimits, canonical_bytes, canonical_bytes_of, parse_strict,
    semantic_digest,
};
pub use corpus::{
    Case, Collision, CorpusSnapshot, CorpusSnapshotBody, Derivation, Expectation, GenerationRules,
    Lineage, OperatorRef, Population, Strategy, ValidatorRef, Variant, Visibility,
};
pub use decimal::{ByteRange, ScaledDecimal};
pub use document::{
    Document, compute_digest, digest_domain, parse, parse_default, seal, to_pretty_json, validate,
};
pub use ident::{
    ActivationSelector, ConfigKey, FamilyId, FamilyScope, Id, IdentError, JurisdictionCode,
    LanguageTag, ScannerId, Seed, Sha256Digest, TimestampUtc, VersionString, is_jurisdiction,
};
pub use manifest::{
    ExecutionLimits, PopulationBinding, RunClass, RunManifest, RunManifestBody, Scope,
};
pub use observation::{
    Finding, InputObservation, ObservationDiagnostics, ObservationSet, ObservationSetBody,
    ReplayRecord,
};
pub use protocol::{
    ACCOUNTING_VERSION, AccountingId, Applicability, BoundDirection, EffectiveNBasis, METHODS,
    METRICS, Mechanics, MethodDefinition, MethodId, MethodRef, MetricDefinition, MetricId,
    MetricRef, MetricStatus, MetricUnit, PROTOCOL_ID, PROTOCOL_VERSION, ProtocolId,
    ProtocolIdentity, SampleUnit, WithheldReason, registry_json,
};
pub use reason::{Collector, ContractError, Meta, Path, ReasonCode, Violations};
pub use scanner::{
    ActionCapability, AdapterIdentity, CapabilityState, ConfigParameter, ConfigValue,
    EngineIdentity, EngineName, FamilyCapability, JurisdictionCapability, ProductIdentity,
    ScannerCapabilities, ScannerConfiguration, ScannerIdentity, ScannerPlan, ScannerStatus,
};
pub use version::{DocumentKind, SCHEMA_MAJOR, SCHEMA_MINOR, SchemaVersion, check_envelope};

/// Product name used in identity output.
pub const ENGINE_NAME: &str = "pii-eval";

/// Engine implementation version (workspace version, pre-release bootstrap).
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Lifecycle label for output that must not be read as a capability claim.
pub const WORKSPACE_STAGE: &str = "bootstrap";

/// The role a workspace crate plays. One variant per crate in ARCHITECTURE.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Contracts,
    Kernel,
    Adapters,
    Cli,
    Compat,
}

impl Role {
    /// Stable lowercase name of the role.
    pub const fn as_str(self) -> &'static str {
        match self {
            Role::Contracts => "contracts",
            Role::Kernel => "kernel",
            Role::Adapters => "adapters",
            Role::Cli => "cli",
            Role::Compat => "compat",
        }
    }
}

/// Identity of one workspace crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrateIdentity {
    pub role: Role,
    pub package: &'static str,
    pub version: &'static str,
}

impl CrateIdentity {
    pub const fn new(role: Role, package: &'static str, version: &'static str) -> Self {
        Self {
            role,
            package,
            version,
        }
    }
}

/// Identity of this crate.
pub const IDENTITY: CrateIdentity = CrateIdentity::new(
    Role::Contracts,
    env!("CARGO_PKG_NAME"),
    env!("CARGO_PKG_VERSION"),
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_names_its_role() {
        assert_eq!(IDENTITY.role, Role::Contracts);
        assert_eq!(IDENTITY.package, "pii-eval-contracts");
        assert_eq!(IDENTITY.role.as_str(), "contracts");
    }
}
