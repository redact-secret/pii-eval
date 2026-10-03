//! Run artifacts: the internal artifact and the public-synthetic artifact.
//!
//! Two different types, on purpose.
//!
//! * [`RunArtifact`] is an internal record. For a protected population it may
//!   carry case identities and per-occurrence outcomes and is never public; its
//!   release is a custodian decision.
//! * [`PublicSyntheticArtifact`] is the only artifact the public serializer
//!   ([`serialize_public_synthetic`]) accepts. Its run class is a one-variant
//!   type that cannot hold `protected`, it has no field for case text, ranges,
//!   findings, observation digests or raw output, and the only way to build one
//!   from a [`RunArtifact`] is [`RunArtifact::to_public_synthetic`], which
//!   refuses protected runs.
//!
//! An artifact can be complete while recording measurement failures:
//! completeness describes coverage, not a product verdict.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::axes::{ActionOutcome, RangeState, SensitivityState, TypeState, kebab_enum};
use crate::check::{non_empty, sorted_unique, within_limit};
use crate::decimal::ScaledDecimal;
use crate::document::{impl_document, schema_tag, to_pretty_json};
use crate::ident::{FamilyId, Id, JurisdictionCode, ScannerId, Sha256Digest, TimestampUtc};
use crate::limits::{MAX_FAILURES, MAX_OUTCOMES, MAX_SAFE_INTEGER, MAX_SCANNERS};
use crate::manifest::{PopulationBinding, RunClass};
use crate::observation::ReplayRecord;
use crate::protocol::{
    EffectiveNBasis, Mechanics, MethodId, MethodRef, MetricRef, MetricStatus, ProtocolIdentity,
    WithheldReason,
};
use crate::reason::{Collector, ContractError, Meta, Path, ReasonCode, Violations};
use crate::scanner::{
    ActionCapability, EngineIdentity, ScannerCapabilities, ScannerIdentity, ScannerStatus,
};
use crate::version::SchemaVersion;

schema_tag!(
    /// `schema` value of an internal run artifact.
    RunArtifactSchema, "pii-eval.run-artifact"
);
schema_tag!(
    /// `schema` value of a public-synthetic artifact.
    PublicSyntheticArtifactSchema, "pii-eval.public-synthetic-artifact"
);
schema_tag!(
    /// The only run class a public-synthetic artifact can carry. A protected
    /// run class has no representation here.
    PublicSyntheticClass, "public-synthetic"
);

kebab_enum!(
    /// Coverage of the outcome matrix. `complete` means every scanner and
    /// expected occurrence has an outcome row (possibly `not-measured`); it
    /// does not mean every scanner worked or that results are acceptable.
    Completeness { Complete, Partial }
);

kebab_enum!(
    /// Sanitized reason a scanner run did not measure.
    FailureCode {
        Unsupported, Unavailable, ExecutionError, Timeout, OutputLimitExceeded, MalformedOutput,
        ReplayDisagreement, Cancelled
    }
);

kebab_enum!(
    /// Phases timed in diagnostics. Timing never reaches the semantic digest.
    Phase { KernelReplay, ScannerStartup, Scan, Materialization, Serialization, Total }
);

/// A recorded measurement failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MeasurementFailure {
    /// Scanner that failed.
    pub scanner_id: ScannerId,
    /// Sanitized reason; never raw scanner output.
    pub code: FailureCode,
    /// Number of inputs affected.
    pub affected_inputs: u64,
}

/// Authored counts, kept apart from metric effective N.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PopulationCounts {
    /// Authored cases.
    pub authored_cases: u64,
    /// Variants (derived variants are not independent samples).
    pub variants: u64,
    /// Expected occurrences.
    pub occurrences: u64,
}

/// Coverage of one method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MethodCoverage {
    /// Method and version.
    pub method: MethodRef,
    /// Authored cases of this method.
    pub cases: u64,
    /// Variants of those cases.
    pub variants: u64,
}

/// Row counts behind a metric. Retained unrounded; rounding happens only in the
/// published value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetricCounts {
    /// Rows eligible for the metric (not `not-applicable`).
    pub eligible: u64,
    /// Rows with a resolved numerator or non-numerator outcome.
    pub measured: u64,
    /// Rows in the numerator.
    pub numerator: u64,
    /// Eligible rows whose axis needs review.
    pub unresolved: u64,
    /// Eligible rows that were not measured.
    pub not_measured: u64,
    /// Rows outside the metric's population.
    pub not_applicable: u64,
    /// All rows considered.
    pub total: u64,
}

/// A metric value, or the reason it is withheld.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum MetricValue {
    /// Published point estimate and pessimistic interval bound.
    Measured {
        /// Point estimate in `[0, 1]`.
        point: ScaledDecimal,
        /// Wilson interval endpoint on the side the metric's direction names, in `[0, 1]`.
        bound: ScaledDecimal,
    },
    /// No value is published.
    Withheld {
        /// Why.
        reason: WithheldReason,
    },
}

/// One metric result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetricResult {
    /// Metric and version.
    pub metric: MetricRef,
    /// Accounting status, derived from the counts.
    pub status: MetricStatus,
    /// Counts.
    pub counts: MetricCounts,
    /// Effective N (distinct from authored and variant counts).
    pub effective_n: u64,
    /// Value or withheld reason.
    pub value: MetricValue,
}

impl MetricCounts {
    fn all(&self) -> [u64; 7] {
        [
            self.eligible,
            self.measured,
            self.numerator,
            self.unresolved,
            self.not_measured,
            self.not_applicable,
            self.total,
        ]
    }

    /// Check the accounting identities with checked arithmetic.
    pub fn is_consistent(&self) -> bool {
        let within = self.all().iter().all(|&n| n <= MAX_SAFE_INTEGER);
        let total = self.eligible.checked_add(self.not_applicable);
        let eligible = self
            .measured
            .checked_add(self.unresolved)
            .and_then(|n| n.checked_add(self.not_measured));
        within
            && total == Some(self.total)
            && eligible == Some(self.eligible)
            && self.numerator <= self.measured
    }

    /// The status the counts imply.
    pub fn derived_status(&self) -> MetricStatus {
        if self.eligible == 0 {
            MetricStatus::NotApplicable
        } else if self.measured == 0 {
            if self.unresolved > 0 {
                MetricStatus::Unresolved
            } else {
                MetricStatus::NotMeasured
            }
        } else if self.unresolved > 0 || self.not_measured > 0 {
            MetricStatus::Partial
        } else {
            MetricStatus::Measured
        }
    }
}

impl MetricResult {
    fn validate(&self, mechanics: &Mechanics, path: &Path<'_>, c: &mut Collector) {
        let definition = self.metric.id.definition();
        if self.metric.version != definition.version {
            c.push(ReasonCode::MetricDefinitionMismatch, &path.field("metric"));
        }
        if !self.counts.is_consistent() || self.status != self.counts.derived_status() {
            c.push(ReasonCode::MetricCountsInconsistent, &path.field("counts"));
            return;
        }
        let expected_n = match definition.effective_n {
            EffectiveNBasis::Measured => self.counts.measured,
            EffectiveNBasis::Eligible => self.counts.eligible,
        };
        if self.effective_n != expected_n {
            c.push(
                ReasonCode::MetricCountsInconsistent,
                &path.field("effectiveN"),
            );
            return;
        }
        let value = path.field("value");
        match self.value {
            MetricValue::Withheld { reason } => {
                let expected = if self.effective_n == 0 {
                    Some(WithheldReason::ZeroDenominator)
                } else if self.effective_n < u64::from(mechanics.min_denominator) {
                    Some(WithheldReason::InsufficientEvidence)
                } else {
                    None
                };
                if expected != Some(reason) {
                    c.push(ReasonCode::MetricValueInconsistent, &value);
                }
            }
            MetricValue::Measured { point, bound } => {
                let published = self.effective_n >= u64::from(mechanics.min_denominator)
                    && self.effective_n > 0;
                point.validate(&value.field("point"), c);
                bound.validate(&value.field("bound"), c);
                let in_range = |d: ScaledDecimal| {
                    d.is_at_most_one() && d.scale <= mechanics.interval_precision
                };
                if !published || !in_range(point) || !in_range(bound) {
                    c.push(ReasonCode::MetricValueInconsistent, &value);
                }
            }
        }
    }
}

/// Summary of what a scanner reported for an occurrence. Contains family and
/// jurisdiction identifiers only, never text or ranges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObservedSummary {
    /// Number of findings the scanner reported for the variant.
    pub finding_count: u64,
    /// Families reported, ascending, unique.
    pub families: Vec<FamilyId>,
    /// Jurisdictions reported, ascending, unique.
    pub jurisdictions: Vec<JurisdictionCode>,
}

/// The outcome axes for one scanner and expected occurrence, without anything
/// scanner-reported beyond the four axes. This is the public shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicOutcome {
    /// Scanner.
    pub scanner_id: ScannerId,
    /// Authored case.
    pub case_id: Id,
    /// Variant.
    pub variant_id: Id,
    /// Expected occurrence.
    pub occurrence_id: Id,
    /// Method of the case.
    pub method: MethodId,
    /// Type-identity axis.
    pub type_identity: TypeState,
    /// Sensitivity-context axis.
    pub sensitivity_context: SensitivityState,
    /// Range axis.
    pub range: RangeState,
    /// Action axis.
    pub action: ActionOutcome,
}

/// An internal outcome row: the four axes plus what the scanner reported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseOutcome {
    /// Scanner.
    pub scanner_id: ScannerId,
    /// Authored case.
    pub case_id: Id,
    /// Variant.
    pub variant_id: Id,
    /// Expected occurrence.
    pub occurrence_id: Id,
    /// Method of the case.
    pub method: MethodId,
    /// Type-identity axis.
    pub type_identity: TypeState,
    /// Sensitivity-context axis.
    pub sensitivity_context: SensitivityState,
    /// Range axis.
    pub range: RangeState,
    /// Action axis.
    pub action: ActionOutcome,
    /// What the scanner reported (internal only).
    pub observed: ObservedSummary,
}

impl CaseOutcome {
    fn public(&self) -> PublicOutcome {
        PublicOutcome {
            scanner_id: self.scanner_id.clone(),
            case_id: self.case_id.clone(),
            variant_id: self.variant_id.clone(),
            occurrence_id: self.occurrence_id.clone(),
            method: self.method,
            type_identity: self.type_identity,
            sensitivity_context: self.sensitivity_context,
            range: self.range,
            action: self.action,
        }
    }
}

/// Scanner record in an internal artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactScanner {
    /// Bound identity.
    pub identity: ScannerIdentity,
    /// Run outcome.
    pub status: ScannerStatus,
    /// Declared capabilities.
    pub capabilities: ScannerCapabilities,
    /// Replay record.
    pub replays: ReplayRecord,
    /// Semantic digest of the observation set this record summarizes.
    pub observation_digest: Sha256Digest,
}

/// Scanner record in a public-synthetic artifact: no observation digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicScannerSummary {
    /// Bound identity.
    pub identity: ScannerIdentity,
    /// Run outcome.
    pub status: ScannerStatus,
    /// Declared capabilities.
    pub capabilities: ScannerCapabilities,
    /// Replay record.
    pub replays: ReplayRecord,
}

/// The semantic content of an internal run artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunArtifactBody {
    /// Engine identity.
    pub engine: EngineIdentity,
    /// Protocol identity.
    pub protocol: ProtocolIdentity,
    /// Run class; `protected` runs produce internal-only artifacts.
    pub run_class: RunClass,
    /// Semantic digest of the manifest this artifact realizes.
    pub manifest_digest: Sha256Digest,
    /// The population measured.
    pub population: PopulationBinding,
    /// Mechanics used.
    pub mechanics: Mechanics,
    /// Authored counts.
    pub population_counts: PopulationCounts,
    /// Scanners, ascending by scanner id.
    pub scanners: Vec<ArtifactScanner>,
    /// Method coverage, ascending by method id.
    pub method_coverage: Vec<MethodCoverage>,
    /// Outcomes, ascending by scanner, case, variant, occurrence.
    pub outcomes: Vec<CaseOutcome>,
    /// Metrics, ascending by metric id.
    pub metrics: Vec<MetricResult>,
    /// Failures, ascending by scanner then code.
    pub failures: Vec<MeasurementFailure>,
    /// Coverage of the outcome matrix.
    pub completeness: Completeness,
}

/// Non-semantic timing of a run. Excluded from the digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunDiagnostics {
    /// Start time.
    pub started_at: TimestampUtc,
    /// End time.
    pub finished_at: TimestampUtc,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
    /// Phase timings, ascending by phase, unique.
    pub phases: Vec<PhaseTiming>,
}

/// Duration of one phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PhaseTiming {
    /// The phase.
    pub phase: Phase,
    /// Duration in milliseconds.
    pub duration_ms: u64,
}

/// An internal run artifact document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunArtifact {
    /// Document kind tag.
    pub schema: RunArtifactSchema,
    /// Schema version.
    pub schema_version: SchemaVersion,
    /// Semantic digest of `semantic`.
    pub semantic_digest: Sha256Digest,
    /// The digested body.
    pub semantic: RunArtifactBody,
    /// Timing diagnostics, outside the digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<RunDiagnostics>,
}

impl_document!(
    RunArtifact,
    RunArtifactBody,
    crate::version::DocumentKind::RunArtifact
);

impl RunArtifact {
    /// Wrap a body in an envelope with the current version and a placeholder digest.
    pub fn unsealed(semantic: RunArtifactBody) -> Self {
        Self {
            schema: RunArtifactSchema::Only,
            schema_version: SchemaVersion::CURRENT,
            semantic_digest: Sha256Digest::of_bytes(b""),
            semantic,
            diagnostics: None,
        }
    }
}

/// The semantic content of a public-synthetic artifact. Aggregates and
/// per-occurrence axis states only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicSyntheticArtifactBody {
    /// Always `public-synthetic`.
    pub run_class: PublicSyntheticClass,
    /// Engine identity.
    pub engine: EngineIdentity,
    /// Protocol identity.
    pub protocol: ProtocolIdentity,
    /// Digest of the internal artifact this was projected from.
    pub source_artifact_digest: Sha256Digest,
    /// Digest of the manifest.
    pub manifest_digest: Sha256Digest,
    /// The population measured.
    pub population: PopulationBinding,
    /// Mechanics used.
    pub mechanics: Mechanics,
    /// Authored counts.
    pub population_counts: PopulationCounts,
    /// Scanners.
    pub scanners: Vec<PublicScannerSummary>,
    /// Method coverage.
    pub method_coverage: Vec<MethodCoverage>,
    /// Per-occurrence axis states.
    pub outcomes: Vec<PublicOutcome>,
    /// Metrics.
    pub metrics: Vec<MetricResult>,
    /// Failures.
    pub failures: Vec<MeasurementFailure>,
    /// Coverage of the outcome matrix.
    pub completeness: Completeness,
}

/// A public-synthetic artifact document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicSyntheticArtifact {
    /// Document kind tag.
    pub schema: PublicSyntheticArtifactSchema,
    /// Schema version.
    pub schema_version: SchemaVersion,
    /// Semantic digest of `semantic`.
    pub semantic_digest: Sha256Digest,
    /// The digested body.
    pub semantic: PublicSyntheticArtifactBody,
}

impl_document!(
    PublicSyntheticArtifact,
    PublicSyntheticArtifactBody,
    crate::version::DocumentKind::PublicSyntheticArtifact
);

impl RunArtifact {
    /// Project into the public-synthetic shape. Fails with
    /// `public-projection-forbidden` for any run class other than
    /// `public-synthetic`. This is the only constructor of a
    /// [`PublicSyntheticArtifact`] from internal data; protected publication is
    /// the custodian's decision and has no code path here.
    pub fn to_public_synthetic(&self) -> Result<PublicSyntheticArtifact, Violations> {
        let body = &self.semantic;
        if body.run_class != RunClass::PublicSynthetic {
            return Err(Violations::single(ContractError::root(
                ReasonCode::PublicProjectionForbidden,
            )));
        }
        let mut public = PublicSyntheticArtifact {
            schema: PublicSyntheticArtifactSchema::Only,
            schema_version: SchemaVersion::CURRENT,
            semantic_digest: Sha256Digest::of_bytes(b""),
            semantic: PublicSyntheticArtifactBody {
                run_class: PublicSyntheticClass::Only,
                engine: body.engine.clone(),
                protocol: body.protocol,
                source_artifact_digest: self.semantic_digest.clone(),
                manifest_digest: body.manifest_digest.clone(),
                population: body.population.clone(),
                mechanics: body.mechanics,
                population_counts: body.population_counts,
                scanners: body
                    .scanners
                    .iter()
                    .map(|s| PublicScannerSummary {
                        identity: s.identity.clone(),
                        status: s.status,
                        capabilities: s.capabilities.clone(),
                        replays: s.replays,
                    })
                    .collect(),
                method_coverage: body.method_coverage.clone(),
                outcomes: body.outcomes.iter().map(CaseOutcome::public).collect(),
                metrics: body.metrics.clone(),
                failures: body.failures.clone(),
                completeness: body.completeness,
            },
        };
        crate::document::seal(&mut public)?;
        Ok(public)
    }
}

/// The public-synthetic serializer. It accepts only a
/// [`PublicSyntheticArtifact`]; an internal [`RunArtifact`] does not type-check.
///
/// ```compile_fail,E0308
/// use pii_eval_contracts::{RunArtifact, serialize_public_synthetic};
/// fn leak(internal: &RunArtifact) {
///     let _ = serialize_public_synthetic(internal);
/// }
/// ```
pub fn serialize_public_synthetic(
    artifact: &PublicSyntheticArtifact,
) -> Result<String, ContractError> {
    to_pretty_json(artifact)
}

/// Serializer for internal artifacts. Output is internal and not publishable
/// without a separate projection policy.
pub fn serialize_internal(artifact: &RunArtifact) -> Result<String, ContractError> {
    to_pretty_json(artifact)
}

/// The parts of an artifact body shared by the internal and public shapes.
struct Shape<'a> {
    scanner_ids: Vec<&'a ScannerId>,
    methods: &'a [MethodCoverage],
    counts: &'a PopulationCounts,
    metrics: &'a [MetricResult],
    mechanics: &'a Mechanics,
    failures: &'a [MeasurementFailure],
    completeness: Completeness,
    outcome_count: usize,
}

fn check_artifact_shape(shape: &Shape<'_>, path: &Path<'_>, c: &mut Collector) {
    let Shape {
        scanner_ids,
        methods,
        counts,
        metrics,
        mechanics,
        failures,
        completeness,
        outcome_count,
    } = shape;
    let scanner_count = scanner_ids.len();
    mechanics.validate(&path.field("mechanics"), c);
    non_empty_scanners(scanner_count, &path.field("scanners"), c);

    let coverage = path.field("methodCoverage");
    non_empty(methods, &coverage, c);
    sorted_unique(methods, |m| m.method.id.as_str(), &coverage, c);
    let (mut cases, mut variants) = (0u64, 0u64);
    for (i, m) in methods.iter().enumerate() {
        if m.method.version != m.method.id.definition().version {
            c.push(ReasonCode::ProtocolBindingMismatch, &coverage.index(i));
        }
        cases = cases.saturating_add(m.cases);
        variants = variants.saturating_add(m.variants);
    }
    let too_large = [counts.authored_cases, counts.variants, counts.occurrences]
        .iter()
        .any(|&n| n > MAX_SAFE_INTEGER);
    if too_large
        || cases != counts.authored_cases
        || variants != counts.variants
        || counts.variants < counts.authored_cases
        || counts.occurrences < counts.variants
    {
        c.push(ReasonCode::CountMismatch, &path.field("populationCounts"));
    }

    let metrics_path = path.field("metrics");
    non_empty(metrics, &metrics_path, c);
    sorted_unique(metrics, |m| m.metric.id.as_str(), &metrics_path, c);
    for (i, m) in metrics.iter().enumerate() {
        m.validate(mechanics, &metrics_path.index(i), c);
    }

    let failures_path = path.field("failures");
    if within_limit(failures.len(), MAX_FAILURES, &failures_path, c) {
        sorted_unique(
            failures,
            |f| (f.scanner_id.as_str(), f.code),
            &failures_path,
            c,
        );
        for (i, f) in failures.iter().enumerate() {
            if !scanner_ids.contains(&&f.scanner_id) {
                c.push(ReasonCode::UnknownScanner, &failures_path.index(i));
            }
        }
    }

    // A complete artifact has one outcome per scanner and expected occurrence.
    let expected_rows = (scanner_count as u64).checked_mul(counts.occurrences);
    let rows_ok = expected_rows == Some(*outcome_count as u64);
    if (*completeness == Completeness::Complete) != rows_ok {
        c.push(
            ReasonCode::ObservationIncomplete,
            &path.field("completeness"),
        );
    }
}

fn non_empty_scanners(count: usize, path: &Path<'_>, c: &mut Collector) {
    if count == 0 {
        c.push(ReasonCode::EmptyCollection, path);
    } else if count > MAX_SCANNERS {
        c.push_with(
            ReasonCode::LimitExceeded,
            path,
            Meta::limit(MAX_SCANNERS as u64, count as u64),
        );
    }
}

fn check_outcome_row(
    status: Option<ScannerStatus>,
    action_capability: Option<ActionCapability>,
    row: (TypeState, SensitivityState, RangeState, ActionOutcome),
    path: &Path<'_>,
    c: &mut Collector,
) {
    let (type_state, sensitivity, range, action) = row;
    let Some(status) = status else {
        c.push(ReasonCode::UnknownScanner, path);
        return;
    };
    if status != ScannerStatus::Complete
        && (type_state != TypeState::NotMeasured
            || sensitivity != SensitivityState::NotMeasured
            || range != RangeState::NotApplicable
            || action != ActionOutcome::NotMeasured)
    {
        c.push(ReasonCode::OutcomeContradiction, path);
    }
    let action_ok = match (action, action_capability) {
        (ActionOutcome::NotMeasured, _) => true,
        (ActionOutcome::NoActionReported | ActionOutcome::Reported { .. }, Some(cap)) => {
            cap != ActionCapability::Unavailable
        }
        (ActionOutcome::OutputVerified { .. }, Some(cap)) => {
            cap == ActionCapability::SanitizedOutput
        }
        (_, None) => false,
    };
    if !action_ok {
        c.push(ReasonCode::OutcomeContradiction, &path.field("action"));
    }
}

impl RunArtifactBody {
    pub(crate) fn validate(&self, path: &Path<'_>, c: &mut Collector) {
        if self.protocol != ProtocolIdentity::CURRENT {
            c.push(ReasonCode::ProtocolBindingMismatch, &path.field("protocol"));
        }
        let scanners = path.field("scanners");
        if within_limit(self.scanners.len(), MAX_SCANNERS, &scanners, c) {
            sorted_unique(
                &self.scanners,
                |s| s.identity.scanner_id.as_str(),
                &scanners,
                c,
            );
            for (i, s) in self.scanners.iter().enumerate() {
                s.identity.validate(&scanners.index(i).field("identity"), c);
                s.capabilities
                    .validate(&scanners.index(i).field("capabilities"), c);
            }
        }
        check_artifact_shape(
            &Shape {
                scanner_ids: self
                    .scanners
                    .iter()
                    .map(|s| &s.identity.scanner_id)
                    .collect(),
                methods: &self.method_coverage,
                counts: &self.population_counts,
                metrics: &self.metrics,
                mechanics: &self.mechanics,
                failures: &self.failures,
                completeness: self.completeness,
                outcome_count: self.outcomes.len(),
            },
            path,
            c,
        );
        let outcomes = path.field("outcomes");
        if !within_limit(self.outcomes.len(), MAX_OUTCOMES, &outcomes, c) {
            return;
        }
        sorted_unique(
            &self.outcomes,
            |o| {
                (
                    o.scanner_id.as_str(),
                    o.case_id.as_str(),
                    o.variant_id.as_str(),
                    o.occurrence_id.as_str(),
                )
            },
            &outcomes,
            c,
        );
        for (i, o) in self.outcomes.iter().enumerate() {
            let scanner = self
                .scanners
                .iter()
                .find(|s| s.identity.scanner_id == o.scanner_id);
            let p = outcomes.index(i);
            check_outcome_row(
                scanner.map(|s| s.status),
                scanner.map(|s| s.capabilities.action),
                (o.type_identity, o.sensitivity_context, o.range, o.action),
                &p,
                c,
            );
            if scanner.is_some_and(|s| s.status != ScannerStatus::Complete)
                && (o.observed.finding_count != 0
                    || !o.observed.families.is_empty()
                    || !o.observed.jurisdictions.is_empty())
            {
                c.push(ReasonCode::OutcomeContradiction, &p.field("observed"));
            }
            sorted_unique(
                &o.observed.families,
                |f| f.as_str(),
                &p.field("observed").field("families"),
                c,
            );
            sorted_unique(
                &o.observed.jurisdictions,
                |j| j.as_str(),
                &p.field("observed").field("jurisdictions"),
                c,
            );
            if c.is_full() {
                return;
            }
        }
    }
}

impl PublicSyntheticArtifactBody {
    pub(crate) fn validate(&self, path: &Path<'_>, c: &mut Collector) {
        if self.protocol != ProtocolIdentity::CURRENT {
            c.push(ReasonCode::ProtocolBindingMismatch, &path.field("protocol"));
        }
        let scanners = path.field("scanners");
        if within_limit(self.scanners.len(), MAX_SCANNERS, &scanners, c) {
            sorted_unique(
                &self.scanners,
                |s| s.identity.scanner_id.as_str(),
                &scanners,
                c,
            );
            for (i, s) in self.scanners.iter().enumerate() {
                s.identity.validate(&scanners.index(i).field("identity"), c);
                s.capabilities
                    .validate(&scanners.index(i).field("capabilities"), c);
            }
        }
        check_artifact_shape(
            &Shape {
                scanner_ids: self
                    .scanners
                    .iter()
                    .map(|s| &s.identity.scanner_id)
                    .collect(),
                methods: &self.method_coverage,
                counts: &self.population_counts,
                metrics: &self.metrics,
                mechanics: &self.mechanics,
                failures: &self.failures,
                completeness: self.completeness,
                outcome_count: self.outcomes.len(),
            },
            path,
            c,
        );
        let outcomes = path.field("outcomes");
        if !within_limit(self.outcomes.len(), MAX_OUTCOMES, &outcomes, c) {
            return;
        }
        sorted_unique(
            &self.outcomes,
            |o| {
                (
                    o.scanner_id.as_str(),
                    o.case_id.as_str(),
                    o.variant_id.as_str(),
                    o.occurrence_id.as_str(),
                )
            },
            &outcomes,
            c,
        );
        for (i, o) in self.outcomes.iter().enumerate() {
            let scanner = self
                .scanners
                .iter()
                .find(|s| s.identity.scanner_id == o.scanner_id);
            check_outcome_row(
                scanner.map(|s| s.status),
                scanner.map(|s| s.capabilities.action),
                (o.type_identity, o.sensitivity_context, o.range, o.action),
                &outcomes.index(i),
                c,
            );
            if c.is_full() {
                return;
            }
        }
    }
}
