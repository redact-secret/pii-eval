//! The run manifest: the plan that fixes what is measured and how.
//!
//! A manifest binds engine and protocol identity, exactly one population by
//! digest, the run class, the scanners with their adapter, product,
//! configuration and activation identities, the neutral accounting mechanics,
//! and explicit execution limits. Replay rejects any changed binding.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::axes::kebab_enum;
use crate::check::{non_empty, sorted_unique, within_limit};
use crate::corpus::{GenerationRules, Visibility};
use crate::document::{impl_document, schema_tag};
use crate::ident::{Id, JurisdictionCode, LanguageTag, Sha256Digest};
use crate::limits::{MAX_SCANNERS, execution};
use crate::protocol::{Mechanics, MethodRef, MetricRef, ProtocolIdentity};
use crate::reason::{Collector, Path, ReasonCode};
use crate::scanner::{EngineIdentity, ScannerPlan};
use crate::version::SchemaVersion;

kebab_enum!(
    /// Class of the run. Must equal the visibility of the population it measures.
    /// A protected run's internal artifact is never public; protected publication
    /// is a custodian decision, not an engine one.
    RunClass { PublicSynthetic, Protected }
);

impl RunClass {
    /// Whether this run class is the one for a population of `visibility`.
    pub fn matches(self, visibility: Visibility) -> bool {
        matches!(
            (self, visibility),
            (RunClass::PublicSynthetic, Visibility::PublicSynthetic)
                | (RunClass::Protected, Visibility::Protected)
        )
    }
}

schema_tag!(
    /// `schema` value of a run manifest.
    RunManifestSchema, "pii-eval.run-manifest"
);

/// The one population a run measures, by identity and digest.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PopulationBinding {
    /// Population identifier.
    pub population_id: Id,
    /// Visibility of the population, copied from the snapshot. A run class
    /// must agree with it.
    pub visibility: Visibility,
    /// Population revision.
    pub population_version: u32,
    /// Semantic digest of the corpus snapshot.
    pub population_digest: Sha256Digest,
}

/// Language and jurisdiction scope of the run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Scope {
    /// Languages in scope, ascending, unique, non-empty.
    pub languages: Vec<LanguageTag>,
    /// Jurisdictions in scope, ascending, unique. Empty means global cases only.
    pub jurisdictions: Vec<JurisdictionCode>,
}

/// Explicit bounds for execution. Every field is required: there are no
/// implicit defaults and no unbounded setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionLimits {
    /// Worker count.
    pub workers: u32,
    /// Concurrent executions per scanner.
    pub per_scanner_parallelism: u32,
    /// Pending tasks queued across workers.
    pub pending_tasks: u32,
    /// Variants per batch.
    pub batch_variants: u32,
    /// Per-scanner timeout in milliseconds.
    pub scanner_timeout_ms: u64,
    /// Captured stdout bound in bytes.
    pub max_stdout_bytes: u64,
    /// Captured stderr bound in bytes.
    pub max_stderr_bytes: u64,
    /// Memory budget in bytes.
    pub max_memory_bytes: u64,
    /// Temporary storage budget in bytes.
    pub max_temporary_bytes: u64,
}

impl ExecutionLimits {
    fn validate(&self, path: &Path<'_>, c: &mut Collector) {
        let in_range = |v: u64, max: u64| (1..=max).contains(&v);
        let ok = in_range(u64::from(self.workers), u64::from(execution::MAX_WORKERS))
            && in_range(
                u64::from(self.per_scanner_parallelism),
                u64::from(self.workers),
            )
            && in_range(
                u64::from(self.pending_tasks),
                u64::from(execution::MAX_PENDING_TASKS),
            )
            && in_range(
                u64::from(self.batch_variants),
                u64::from(execution::MAX_BATCH_VARIANTS),
            )
            && in_range(self.scanner_timeout_ms, execution::MAX_TIMEOUT_MS)
            && in_range(self.max_stdout_bytes, execution::MAX_OUTPUT_BYTES)
            && in_range(self.max_stderr_bytes, execution::MAX_OUTPUT_BYTES)
            && in_range(self.max_memory_bytes, execution::MAX_MEMORY_BYTES)
            && in_range(self.max_temporary_bytes, execution::MAX_TEMPORARY_BYTES);
        if !ok {
            c.push(ReasonCode::LimitsInvalid, path);
        }
    }
}

/// The semantic content of a run manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunManifestBody {
    /// Engine implementation identity.
    pub engine: EngineIdentity,
    /// Protocol identity.
    pub protocol: ProtocolIdentity,
    /// Run class.
    pub run_class: RunClass,
    /// The population measured.
    pub population: PopulationBinding,
    /// Language and jurisdiction scope.
    pub scope: Scope,
    /// Methods run, ascending by id, each at its frozen version.
    pub methods: Vec<MethodRef>,
    /// Metrics computed, ascending by id, each at its frozen version.
    pub metrics: Vec<MetricRef>,
    /// Neutral accounting mechanics (part of protocol and configuration identity).
    pub mechanics: Mechanics,
    /// Generator and seed-derivation rule; must equal the snapshot's.
    pub generation: GenerationRules,
    /// Execution limits.
    pub limits: ExecutionLimits,
    /// Scanners, ascending by scanner id.
    pub scanners: Vec<ScannerPlan>,
}

/// A run manifest document. Its `semanticDigest` is the plan digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunManifest {
    /// Document kind tag.
    pub schema: RunManifestSchema,
    /// Schema version.
    pub schema_version: SchemaVersion,
    /// Semantic digest of `semantic`.
    pub semantic_digest: Sha256Digest,
    /// The digested body.
    pub semantic: RunManifestBody,
}

impl_document!(
    RunManifest,
    RunManifestBody,
    crate::version::DocumentKind::RunManifest
);

impl RunManifest {
    /// Wrap a body in an envelope with the current version and a placeholder digest.
    pub fn unsealed(semantic: RunManifestBody) -> Self {
        Self {
            schema: RunManifestSchema::Only,
            schema_version: SchemaVersion::CURRENT,
            semantic_digest: Sha256Digest::of_bytes(b""),
            semantic,
        }
    }
}

impl RunManifestBody {
    pub(crate) fn validate(&self, path: &Path<'_>, c: &mut Collector) {
        if self.protocol != ProtocolIdentity::CURRENT {
            c.push(ReasonCode::ProtocolBindingMismatch, &path.field("protocol"));
        }
        if !self.run_class.matches(self.population.visibility) {
            c.push(ReasonCode::RunClassMismatch, &path.field("runClass"));
        }
        self.mechanics.validate(&path.field("mechanics"), c);
        self.limits.validate(&path.field("limits"), c);

        let scope = path.field("scope");
        let languages = scope.field("languages");
        non_empty(&self.scope.languages, &languages, c);
        sorted_unique(&self.scope.languages, |l| l.clone(), &languages, c);
        sorted_unique(
            &self.scope.jurisdictions,
            |j| j.clone(),
            &scope.field("jurisdictions"),
            c,
        );

        let methods = path.field("methods");
        non_empty(&self.methods, &methods, c);
        sorted_unique(&self.methods, |m| m.id.as_str(), &methods, c);
        for (i, m) in self.methods.iter().enumerate() {
            if m.version != m.id.definition().version {
                c.push(ReasonCode::ProtocolBindingMismatch, &methods.index(i));
            }
        }
        let metrics = path.field("metrics");
        non_empty(&self.metrics, &metrics, c);
        sorted_unique(&self.metrics, |m| m.id.as_str(), &metrics, c);
        for (i, m) in self.metrics.iter().enumerate() {
            if m.version != m.id.definition().version {
                c.push(ReasonCode::ProtocolBindingMismatch, &metrics.index(i));
            }
        }

        // A metric restricted to a method is meaningless without that method.
        for (i, m) in self.metrics.iter().enumerate() {
            if let Some(required) = m.id.definition().restricted_to_method {
                if !self.methods.iter().any(|r| r.id == required) {
                    c.push(ReasonCode::ProtocolBindingMismatch, &metrics.index(i));
                }
            }
        }

        let scanners = path.field("scanners");
        non_empty(&self.scanners, &scanners, c);
        if within_limit(self.scanners.len(), MAX_SCANNERS, &scanners, c) {
            sorted_unique(
                &self.scanners,
                |s| s.identity.scanner_id.clone(),
                &scanners,
                c,
            );
            for (i, s) in self.scanners.iter().enumerate() {
                s.validate(&scanners.index(i), c);
            }
        }
    }
}
