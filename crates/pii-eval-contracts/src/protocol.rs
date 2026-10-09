//! The frozen `pii-v1` protocol: seven methods, ten metric definitions and the
//! neutral accounting mechanics.
//!
//! Source: the pinned oracle inventory in `docs/migration/ownership-map.md`
//! (oracle commit `4b846967346505baca11e0b98cab1475fbce6773`). Ids, versions,
//! labels and applicability are copied verbatim; they are protocol semantics,
//! not implementation detail. Changing any of them is a protocol revision
//! (ADR 0002), never an incidental edit.
//!
//! Product policy is deliberately absent: no thresholds, no gates, no required
//! method list, no support status. Those stay with the consumer.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::axes::kebab_enum;
use crate::decimal::ScaledDecimal;
use crate::reason::{Collector, Path, ReasonCode};
use crate::version::SchemaVersion;

/// The protocol identifier a manifest and its artifacts bind to.
pub const PROTOCOL_ID: &str = "pii-v1";
/// Protocol revision this engine emits: revision 2, the canonical rules (ADR
/// 0008). A change to any frozen definition below bumps this.
pub const PROTOCOL_VERSION: u32 = 2;
/// The legacy revision (the oracle's first-overlap semantics). Documents of this
/// revision stay readable and structurally valid under schema 1.0; they are not
/// re-measured and not accounting-verified (ADR 0008, section 1).
pub const PROTOCOL_VERSION_LEGACY: u32 = 1;
/// Accounting identity, equal to the legacy `domainAccountingVersion`.
pub const ACCOUNTING_VERSION: &str = "pii-v1";

/// Identifiers of the legacy oracle, kept only so the compatibility layer and
/// parity reports can name what they compare against. They are not part of the
/// canonical model.
pub mod legacy {
    /// `PII_ENGINE_VERSION` at the oracle pin.
    pub const ENGINE_VERSION: &str = "1.0.0";
    /// `evaluationProfile` of the observation-side accounting source.
    pub const OBSERVATION_EVALUATION_PROFILE: &str = "pii-schema-v1";
    /// `domainAccountingVersion` of the observation-side accounting source.
    pub const OBSERVATION_ACCOUNTING_VERSION: &str = "pii-observation-v1";
    /// Oracle repository commit this protocol was inventoried from.
    pub const ORACLE_COMMIT: &str = "4b846967346505baca11e0b98cab1475fbce6773";
}

/// Protocol identifier enum (one variant today, so unknown protocols fail to parse).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
pub enum ProtocolId {
    /// The `pii-v1` protocol.
    #[serde(rename = "pii-v1")]
    PiiV1,
}

/// Accounting identity enum (one variant today).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
pub enum AccountingId {
    /// The `pii-v1` accounting rules.
    #[serde(rename = "pii-v1")]
    PiiV1,
}

kebab_enum!(
    /// A rule that revision 2 binds by identity. Each id is valid in exactly one
    /// slot of [`ProtocolRules`].
    RuleId { PiiV1Canonical, PiiV1CanonicalAccounting, PiiV1WilsonExact }
);

impl RuleId {
    /// The wire string.
    pub const fn as_str(self) -> &'static str {
        match self {
            RuleId::PiiV1Canonical => "pii-v1-canonical",
            RuleId::PiiV1CanonicalAccounting => "pii-v1-canonical-accounting",
            RuleId::PiiV1WilsonExact => "pii-v1-wilson-exact",
        }
    }
}

/// One bound rule: its identity and the revision of the rule text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleRef {
    /// Rule identifier.
    pub id: RuleId,
    /// Rule revision.
    pub revision: u32,
}

/// The rules a revision-2 document states it was produced with (ADR 0008). The
/// kernel's `MATCHING_RULE_ID`, `ACCOUNTING_RULE_ID` and `STATS_RULE_ID` repeat
/// these values and a kernel test pins the equality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolRules {
    /// Matching rule (ADR 0004): `pii-v1-canonical`.
    pub matching: RuleRef,
    /// Accounting rule (ADR 0005, ADR 0008): `pii-v1-canonical-accounting`.
    pub accounting: RuleRef,
    /// Statistics rule (ADR 0005): `pii-v1-wilson-exact`.
    pub statistics: RuleRef,
}

impl ProtocolRules {
    /// The rules of revision 2.
    pub const CANONICAL_V2: ProtocolRules = ProtocolRules {
        matching: RuleRef {
            id: RuleId::PiiV1Canonical,
            revision: 2,
        },
        accounting: RuleRef {
            id: RuleId::PiiV1CanonicalAccounting,
            revision: 2,
        },
        statistics: RuleRef {
            id: RuleId::PiiV1WilsonExact,
            revision: 1,
        },
    };
}

/// Protocol identity bound into every plan and artifact.
///
/// Legacy and canonical revisions are valid: [`ProtocolIdentity::LEGACY_V1`] (revision 1, no
/// `rules`, the oracle's semantics) and [`ProtocolIdentity::CANONICAL_V2`]
/// (revision 2 with its frozen rules), plus [`ProtocolIdentity::CANONICAL_V3`]
/// (schema 1.5 evidence semantics). Anything else
/// is `protocol-binding-mismatch`; a revision-2 document must also declare
/// schema 1.1 or later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolIdentity {
    /// Protocol identifier.
    pub id: ProtocolId,
    /// Protocol revision: 1 (legacy), 2 (canonical) or 3 (evidence semantics).
    pub version: u32,
    /// Accounting family identity.
    pub accounting: AccountingId,
    /// Rule identities; present for canonical revisions 2 and 3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<ProtocolRules>,
}

impl ProtocolIdentity {
    /// Revision 1: the legacy first-overlap semantics. Readable, never emitted.
    pub const LEGACY_V1: ProtocolIdentity = ProtocolIdentity {
        id: ProtocolId::PiiV1,
        version: PROTOCOL_VERSION_LEGACY,
        accounting: AccountingId::PiiV1,
        rules: None,
    };

    /// Revision 2: the canonical rules. What this engine emits.
    pub const CANONICAL_V2: ProtocolIdentity = ProtocolIdentity {
        id: ProtocolId::PiiV1,
        version: PROTOCOL_VERSION,
        accounting: AccountingId::PiiV1,
        rules: Some(ProtocolRules::CANONICAL_V2),
    };

    /// Revision 3 preserves evidence semantics and measures text-level negatives.
    pub const CANONICAL_V3: ProtocolIdentity = ProtocolIdentity {
        id: ProtocolId::PiiV1,
        version: 3,
        accounting: AccountingId::PiiV1,
        rules: Some(ProtocolRules {
            matching: RuleRef {
                id: RuleId::PiiV1Canonical,
                revision: 3,
            },
            accounting: RuleRef {
                id: RuleId::PiiV1CanonicalAccounting,
                revision: 3,
            },
            statistics: ProtocolRules::CANONICAL_V2.statistics,
        }),
    };

    /// Whether this is the legacy revision.
    pub fn is_legacy(&self) -> bool {
        *self == Self::LEGACY_V1
    }

    /// Whether this is the canonical revision.
    pub fn is_canonical(&self) -> bool {
        *self == Self::CANONICAL_V2 || *self == Self::CANONICAL_V3
    }

    /// Record `protocol-binding-mismatch` unless this is exactly one of the
    /// accepted identities.
    pub(crate) fn validate(&self, path: &Path<'_>, c: &mut Collector) {
        if !self.is_legacy() && !self.is_canonical() {
            c.push(ReasonCode::ProtocolBindingMismatch, path);
        }
    }
}

/// Revision gate shared by every document that carries a protocol identity: a
/// revision-2 document must declare schema 1.1 or later, because 1.0 readers
/// know neither its rules nor its per-scanner metrics.
pub(crate) fn check_revision_gate(
    version: SchemaVersion,
    protocol: &ProtocolIdentity,
    c: &mut Collector,
) {
    if (protocol.is_canonical() && version < SchemaVersion::V1_1)
        || (*protocol == ProtocolIdentity::CANONICAL_V3 && version < SchemaVersion::V1_5)
    {
        c.push(
            ReasonCode::ProtocolBindingMismatch,
            &Path::ROOT.field("schemaVersion"),
        );
    }
}

kebab_enum!(
    /// The seven preserved methods.
    MethodId { TypeValidation, ContextDiscrimination, PiiBenign, JurisdictionCollision, Mutation, ReferenceDifferential, SchemaOnly }
);

kebab_enum!(
    /// The ten preserved `pii-v1` metrics.
    MetricId {
        TypeMissRate, WrongFamilyRate, WrongJurisdictionRate, SensitiveMissRate, NonSensitiveFlagRate,
        ContextDiscriminationRate, BenignSuppressionRate, JurisdictionCollisionRate, RangeCollateralRate,
        MeasurableShare
    }
);

impl MethodId {
    /// The wire string; canonical collections sort by this, bytewise.
    pub const fn as_str(self) -> &'static str {
        match self {
            MethodId::TypeValidation => "type-validation",
            MethodId::ContextDiscrimination => "context-discrimination",
            MethodId::PiiBenign => "pii-benign",
            MethodId::JurisdictionCollision => "jurisdiction-collision",
            MethodId::Mutation => "mutation",
            MethodId::ReferenceDifferential => "reference-differential",
            MethodId::SchemaOnly => "schema-only",
        }
    }
}

impl MetricId {
    /// The wire string; canonical collections sort by this, bytewise.
    pub const fn as_str(self) -> &'static str {
        match self {
            MetricId::TypeMissRate => "type-miss-rate",
            MetricId::WrongFamilyRate => "wrong-family-rate",
            MetricId::WrongJurisdictionRate => "wrong-jurisdiction-rate",
            MetricId::SensitiveMissRate => "sensitive-miss-rate",
            MetricId::NonSensitiveFlagRate => "non-sensitive-flag-rate",
            MetricId::ContextDiscriminationRate => "context-discrimination-rate",
            MetricId::BenignSuppressionRate => "benign-suppression-rate",
            MetricId::JurisdictionCollisionRate => "jurisdiction-collision-rate",
            MetricId::RangeCollateralRate => "range-collateral-rate",
            MetricId::MeasurableShare => "measurable-share",
        }
    }
}

kebab_enum!(
    /// Which Wilson interval endpoint a metric reports. Neutral mechanics: it
    /// says which bound is computed, not whether a value is acceptable.
    BoundDirection { Upper, Lower }
);

kebab_enum!(
    /// When a metric is defined for a run.
    Applicability { Required, Jurisdictional, ReportedSpans }
);

kebab_enum!(
    /// The unit that counts as one sample for a metric. Variants derived from
    /// one authored case are never independent samples, and replays are stability
    /// checks, never extra samples.
    SampleUnit { AuthoredCaseMethod, ContextTrio, AxisAssertion }
);

kebab_enum!(
    /// Which count is the effective N of a metric.
    EffectiveNBasis { Measured, Eligible }
);

kebab_enum!(
    /// Unit of a metric value.
    MetricUnit { Proportion }
);

kebab_enum!(
    /// Why a metric value is withheld. `zero-denominator` is the legacy `null`
    /// rate; `insufficient-evidence` is the legacy string of the same name.
    WithheldReason { ZeroDenominator, InsufficientEvidence }
);

kebab_enum!(
    /// Accounting status of a metric.
    MetricStatus { Measured, Partial, Unresolved, NotMeasured, NotApplicable }
);

/// One frozen method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MethodDefinition {
    /// Method identifier.
    pub id: MethodId,
    /// Method version at the oracle pin.
    pub version: u32,
    /// Oracle source path the behavior was inventoried from (reference only).
    pub legacy_source: &'static str,
}

/// The seven methods with their frozen versions.
pub const METHODS: [MethodDefinition; 7] = [
    MethodDefinition {
        id: MethodId::TypeValidation,
        version: 2,
        legacy_source: "benchmarks/evaluation/domains/pii/methods/type-validation.ts",
    },
    MethodDefinition {
        id: MethodId::ContextDiscrimination,
        version: 2,
        legacy_source: "benchmarks/evaluation/domains/pii/methods/context-discrimination.ts",
    },
    MethodDefinition {
        id: MethodId::PiiBenign,
        version: 3,
        legacy_source: "benchmarks/evaluation/domains/pii/methods/benign.ts",
    },
    MethodDefinition {
        id: MethodId::JurisdictionCollision,
        version: 3,
        legacy_source: "benchmarks/evaluation/domains/pii/methods/jurisdiction-collision.ts",
    },
    MethodDefinition {
        id: MethodId::Mutation,
        version: 1,
        legacy_source: "benchmarks/evaluation/domains/pii/methods/mutation.ts",
    },
    MethodDefinition {
        id: MethodId::ReferenceDifferential,
        version: 1,
        legacy_source: "benchmarks/evaluation/domains/pii/methods/reference-differential.ts",
    },
    MethodDefinition {
        id: MethodId::SchemaOnly,
        version: 1,
        legacy_source: "benchmarks/evaluation/domains/pii/methods/schema-only.ts",
    },
];

impl MethodId {
    /// The frozen definition of this method.
    pub fn definition(self) -> &'static MethodDefinition {
        METHODS.iter().find(|m| m.id == self).unwrap_or(&METHODS[0])
    }
}

/// One frozen metric definition. Labels are verbatim from the oracle so that
/// reports and consumers read identical strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricDefinition {
    /// Metric identifier.
    pub id: MetricId,
    /// Metric definition version.
    pub version: u32,
    /// Unit of the metric value.
    pub unit: MetricUnit,
    /// Which Wilson endpoint is reported.
    pub direction: BoundDirection,
    /// When the metric is defined.
    pub applicability: Applicability,
    /// What counts as one sample.
    pub sample_unit: SampleUnit,
    /// Which count is the effective N.
    pub effective_n: EffectiveNBasis,
    /// When set, only rows of this method are eligible.
    pub restricted_to_method: Option<MethodId>,
    /// Population label.
    pub population: &'static str,
    /// Numerator label.
    pub numerator: &'static str,
    /// Denominator label.
    pub denominator: &'static str,
    /// Reasons this metric's value can be withheld.
    pub withheld_reasons: [WithheldReason; 2],
}

const WITHHELD: [WithheldReason; 2] = [
    WithheldReason::ZeroDenominator,
    WithheldReason::InsufficientEvidence,
];

macro_rules! metric {
    ($id:ident, $direction:ident, $applicability:ident, $unit:ident, $basis:ident, $method:expr,
     $population:literal, $numerator:literal, $denominator:literal) => {
        MetricDefinition {
            id: MetricId::$id,
            version: 1,
            unit: MetricUnit::Proportion,
            direction: BoundDirection::$direction,
            applicability: Applicability::$applicability,
            sample_unit: SampleUnit::$unit,
            effective_n: EffectiveNBasis::$basis,
            restricted_to_method: $method,
            population: $population,
            numerator: $numerator,
            denominator: $denominator,
            withheld_reasons: WITHHELD,
        }
    };
}

/// The ten metrics, in the legacy order.
pub const METRICS: [MetricDefinition; 10] = [
    metric!(
        TypeMissRate,
        Upper,
        Required,
        AuthoredCaseMethod,
        Measured,
        None,
        "scanner-source × authored valid-type occurrence",
        "type state is miss",
        "resolved type assertions for authored valid types"
    ),
    metric!(
        WrongFamilyRate,
        Upper,
        Required,
        AuthoredCaseMethod,
        Measured,
        None,
        "scanner-source × authored valid-type occurrence",
        "type state is wrong-family",
        "resolved type assertions for authored valid types"
    ),
    metric!(
        WrongJurisdictionRate,
        Upper,
        Jurisdictional,
        AuthoredCaseMethod,
        Measured,
        None,
        "scanner-source × authored jurisdictional valid-type occurrence",
        "type state is wrong-jurisdiction",
        "resolved jurisdictional type assertions"
    ),
    metric!(
        SensitiveMissRate,
        Upper,
        Required,
        AuthoredCaseMethod,
        Measured,
        None,
        "scanner-source × authored sensitive occurrence",
        "sensitivity state is miss",
        "resolved sensitivity assertions for authored sensitive occurrences"
    ),
    metric!(
        NonSensitiveFlagRate,
        Upper,
        Required,
        AuthoredCaseMethod,
        Measured,
        None,
        "scanner-source × authored non-sensitive occurrence",
        "sensitivity state is false-positive",
        "resolved sensitivity assertions for authored non-sensitive occurrences"
    ),
    metric!(
        ContextDiscriminationRate,
        Lower,
        Required,
        ContextTrio,
        Measured,
        Some(MethodId::ContextDiscrimination),
        "complete scanner-source × authored context trios",
        "both sensitive and non-sensitive endpoints pass",
        "resolved complete context trios"
    ),
    metric!(
        BenignSuppressionRate,
        Lower,
        Required,
        AuthoredCaseMethod,
        Measured,
        Some(MethodId::PiiBenign),
        "scanner-source × distinct authored benign case",
        "non-sensitive assertion passes",
        "resolved authored benign cases"
    ),
    metric!(
        JurisdictionCollisionRate,
        Lower,
        Jurisdictional,
        AuthoredCaseMethod,
        Measured,
        Some(MethodId::JurisdictionCollision),
        "scanner-source × authored jurisdiction collision case",
        "target family and jurisdiction assertion passes",
        "resolved collision type assertions"
    ),
    metric!(
        RangeCollateralRate,
        Upper,
        ReportedSpans,
        AuthoredCaseMethod,
        Measured,
        None,
        "scanner-source × reported span for authored valid type",
        "range is overbroad or partial",
        "exact, overbroad, or partial reported spans"
    ),
    metric!(
        MeasurableShare,
        Lower,
        Required,
        AxisAssertion,
        Eligible,
        None,
        "all scanner-source × authored axis assertions",
        "resolved pass or fail assertions",
        "all eligible authored axes including unresolved axes"
    ),
];

impl MetricId {
    /// The frozen definition of this metric.
    pub fn definition(self) -> &'static MetricDefinition {
        METRICS.iter().find(|m| m.id == self).unwrap_or(&METRICS[0])
    }
}

/// A method selected by a plan, with the version the plan expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MethodRef {
    /// Method identifier.
    pub id: MethodId,
    /// Method version; must equal the frozen version.
    pub version: u32,
}

/// A metric selected by a plan, with the version the plan expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetricRef {
    /// Metric identifier.
    pub id: MetricId,
    /// Metric version; must equal the frozen version.
    pub version: u32,
}

impl MethodRef {
    /// A reference to the frozen version of `id`.
    pub fn frozen(id: MethodId) -> Self {
        Self {
            id,
            version: id.definition().version,
        }
    }
}

impl MetricRef {
    /// A reference to the frozen version of `id`.
    pub fn frozen(id: MetricId) -> Self {
        Self {
            id,
            version: id.definition().version,
        }
    }
}

/// Neutral accounting mechanics. They are part of protocol and configuration
/// identity and are always recorded in the plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Mechanics {
    /// Smallest effective N for which a value is published (at least 1).
    pub min_denominator: u32,
    /// Stability replays per scanner and input (at least 2). Not extra samples.
    pub replays: u32,
    /// Wilson interval z value; positive.
    pub interval_z: ScaledDecimal,
    /// Decimal places of published values, 1 to 12.
    pub interval_precision: u8,
}

impl Mechanics {
    /// The legacy `pii-v1` mechanics: `minDenominator` 4, `replays` 2, z 1.96,
    /// precision 6. Neutral defaults; a plan may choose others.
    pub const PII_V1: Mechanics = Mechanics {
        min_denominator: 4,
        replays: 2,
        interval_z: ScaledDecimal {
            mantissa: 196,
            scale: 2,
        },
        interval_precision: 6,
    };

    /// Record `mechanics-invalid` for out-of-range values.
    pub fn validate(&self, path: &Path<'_>, c: &mut Collector) {
        let z_ok = self.interval_z.is_normalized() && self.interval_z.mantissa > 0;
        if self.min_denominator < 1
            || self.replays < 2
            || self.replays > 1024
            || !z_ok
            || !(1..=12).contains(&self.interval_precision)
        {
            c.push(ReasonCode::MechanicsInvalid, path);
        }
    }
}

/// The frozen registry as JSON, for the committed `schemas/registry/` file and
/// for consumers that want the definitions without linking this crate.
pub fn registry_json() -> serde_json::Value {
    serde_json::json!({
        "protocol": {
            "id": PROTOCOL_ID,
            "version": PROTOCOL_VERSION,
            "accounting": ACCOUNTING_VERSION,
            "readableRevisions": [PROTOCOL_VERSION_LEGACY, PROTOCOL_VERSION],
        },
        "revisions": [
            {
                "version": PROTOCOL_VERSION_LEGACY,
                "state": "legacy",
                "rules": "legacy-first-overlap matching and legacy accounting (pii-eval-compat); a revision-1 document carries no rule identities",
                "minimumSchemaVersion": "1.0",
            },
            {
                "version": PROTOCOL_VERSION,
                "state": "canonical",
                "rules": ProtocolRules::CANONICAL_V2,
                "minimumSchemaVersion": "1.1",
            },
        ],
        "identityRules": {
            "sampleIdentity": "authored case within a method",
            "variantsAreIndependentSamples": false,
            "replaysAreSamples": false,
        },
        "methods": METHODS,
        "metrics": METRICS,
        "defaultMechanics": Mechanics::PII_V1,
        "legacy": {
            "oracleCommit": legacy::ORACLE_COMMIT,
            "engineVersion": legacy::ENGINE_VERSION,
            "observationEvaluationProfile": legacy::OBSERVATION_EVALUATION_PROFILE,
            "observationAccountingVersion": legacy::OBSERVATION_ACCOUNTING_VERSION,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seven_methods_and_ten_metrics_are_unique_and_complete() {
        let mut ids: Vec<_> = METHODS.iter().map(|m| m.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 7);
        let mut ids: Vec<_> = METRICS.iter().map(|m| m.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 10);
    }

    #[test]
    fn frozen_versions_match_the_ownership_map() {
        let versions: Vec<_> = METHODS.iter().map(|m| (m.id, m.version)).collect();
        assert_eq!(
            versions,
            vec![
                (MethodId::TypeValidation, 2),
                (MethodId::ContextDiscrimination, 2),
                (MethodId::PiiBenign, 3),
                (MethodId::JurisdictionCollision, 3),
                (MethodId::Mutation, 1),
                (MethodId::ReferenceDifferential, 1),
                (MethodId::SchemaOnly, 1),
            ]
        );
        assert!(METRICS.iter().all(|m| m.version == 1));
    }

    #[test]
    fn directions_and_applicability_match_the_oracle_profile() {
        use Applicability::*;
        use BoundDirection::*;
        let got: Vec<_> = METRICS
            .iter()
            .map(|m| (m.direction, m.applicability))
            .collect();
        assert_eq!(
            got,
            vec![
                (Upper, Required),
                (Upper, Required),
                (Upper, Jurisdictional),
                (Upper, Required),
                (Upper, Required),
                (Lower, Required),
                (Lower, Required),
                (Lower, Jurisdictional),
                (Upper, ReportedSpans),
                (Lower, Required),
            ]
        );
    }

    #[test]
    fn effective_n_basis_is_eligible_only_for_measurable_share() {
        for m in METRICS {
            assert_eq!(
                m.effective_n == EffectiveNBasis::Eligible,
                m.id == MetricId::MeasurableShare
            );
        }
    }

    #[test]
    fn wire_names_are_the_legacy_ids() {
        let names: Vec<_> = METRICS
            .iter()
            .map(|m| {
                serde_json::to_value(m.id)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(
            names,
            [
                "type-miss-rate",
                "wrong-family-rate",
                "wrong-jurisdiction-rate",
                "sensitive-miss-rate",
                "non-sensitive-flag-rate",
                "context-discrimination-rate",
                "benign-suppression-rate",
                "jurisdiction-collision-rate",
                "range-collateral-rate",
                "measurable-share"
            ]
        );
        let names: Vec<_> = METHODS
            .iter()
            .map(|m| {
                serde_json::to_value(m.id)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(
            names,
            [
                "type-validation",
                "context-discrimination",
                "pii-benign",
                "jurisdiction-collision",
                "mutation",
                "reference-differential",
                "schema-only"
            ]
        );
    }

    #[test]
    fn default_mechanics_validate_and_extremes_do_not() {
        let mut c = Collector::new();
        Mechanics::PII_V1.validate(&Path::ROOT, &mut c);
        assert!(c.is_clean());
        for bad in [
            Mechanics {
                min_denominator: 0,
                ..Mechanics::PII_V1
            },
            Mechanics {
                replays: 1,
                ..Mechanics::PII_V1
            },
            Mechanics {
                interval_precision: 0,
                ..Mechanics::PII_V1
            },
            Mechanics {
                interval_precision: 13,
                ..Mechanics::PII_V1
            },
            Mechanics {
                interval_z: ScaledDecimal::ZERO,
                ..Mechanics::PII_V1
            },
        ] {
            let mut c = Collector::new();
            bad.validate(&Path::ROOT, &mut c);
            assert!(!c.is_clean());
        }
    }
}
