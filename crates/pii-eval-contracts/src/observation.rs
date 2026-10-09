//! The observation set contract: what one scanner configuration reported over
//! one population.
//!
//! Observations bind the exact input bytes (by digest), the scanner, adapter,
//! configuration and activation identities, the normalization version and the
//! declared capabilities. They contain normalized findings only: no raw
//! scanner output, no matched text. A scanner that did not complete reports
//! its status and no inputs; that is never a scan with no findings.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::axes::{ActionKind, kebab_enum};
use crate::check::{sorted_unique, within_limit};
use crate::decimal::ByteRange;
use crate::document::{impl_document, schema_tag};
use crate::ident::{
    FamilyId, Id, JurisdictionCode, ScannerId, Sha256Digest, TimestampUtc, VersionString,
};
use crate::limits::{MAX_FINDINGS_PER_INPUT, MAX_INPUTS_PER_OBSERVATION_SET};
use crate::protocol::ProtocolIdentity;
use crate::reason::{Collector, Path, ReasonCode};
use crate::scanner::{
    ActionCapability, CapabilityState, EngineIdentity, ScannerCapabilities, ScannerIdentity,
    ScannerStatus,
};
use crate::version::SchemaVersion;

schema_tag!(
    /// `schema` value of an observation set.
    ObservationSetSchema, "pii-eval.observation-set"
);

/// Stability replays of the same input. Replays are a stability check, not
/// extra samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReplayRecord {
    /// Number of replays performed (at least 1).
    pub count: u32,
    /// Whether all replays produced identical normalized findings.
    pub agreed: bool,
}

/// Status, replays and capabilities must agree: a complete scanner needs
/// agreeing replays and range support; an unstable one has disagreeing replays;
/// replay count is 1 to 1024. Shared by observation sets and artifact scanner
/// records so the same rules hold wherever a scanner state is recorded.
pub(crate) fn scanner_state_consistent(
    status: ScannerStatus,
    replays: &ReplayRecord,
    capabilities: &ScannerCapabilities,
) -> bool {
    (1..=1024).contains(&replays.count)
        && match status {
            ScannerStatus::Complete => {
                replays.agreed && capabilities.ranges != CapabilityState::Unsupported
            }
            ScannerStatus::Unstable => !replays.agreed,
            ScannerStatus::Unsupported | ScannerStatus::Unavailable | ScannerStatus::Error => true,
        }
}

/// One normalized finding. Every optional field is absent when the scanner did
/// not report it; absence is not a negative answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Finding {
    /// Reported half-open UTF-8 byte range into the original input.
    pub range: ByteRange,
    /// Reported family (adapter-mapped).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<FamilyId>,
    /// Reported jurisdiction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<JurisdictionCode>,
    /// Reported sensitivity classification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitive: Option<bool>,
    /// Reported action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<ActionKind>,
}

impl Finding {
    /// Canonical sort key: range, family, jurisdiction, sensitivity, then action
    /// by its wire string (absent before present). Enum-valued keys sort by
    /// wire string, never by declaration order (ADR 0003).
    fn sort_key(&self) -> impl Ord + '_ {
        (
            self.range,
            self.family.as_ref(),
            self.jurisdiction.as_ref(),
            self.sensitive,
            self.action.map(ActionKind::as_str),
        )
    }
}

impl PartialOrd for Finding {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Finding {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.sort_key().cmp(&other.sort_key())
    }
}

/// Findings for one input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InputObservation {
    /// The variant scanned.
    pub variant_id: Id,
    /// SHA-256 of the exact input bytes scanned; must equal the snapshot's text digest.
    pub input_digest: Sha256Digest,
    /// SHA-256 of sanitized output, when the scanner provides it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sanitized_output_digest: Option<Sha256Digest>,
    /// Findings in canonical order (ascending; duplicates are kept, not merged).
    pub findings: Vec<Finding>,
}

/// The semantic content of an observation set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObservationSetBody {
    /// Engine that produced the observations.
    pub engine: EngineIdentity,
    /// Protocol identity.
    pub protocol: ProtocolIdentity,
    /// Semantic digest of the corpus snapshot observed.
    pub population_digest: Sha256Digest,
    /// Scanner, adapter, product, configuration and activation identities.
    pub scanner: ScannerIdentity,
    /// Run outcome.
    pub status: ScannerStatus,
    /// Declared capabilities.
    pub capabilities: ScannerCapabilities,
    /// Replay record.
    pub replays: ReplayRecord,
    /// Per-input observations, ascending by variant id. Empty unless `status` is `complete`.
    pub inputs: Vec<InputObservation>,
}

kebab_enum!(
    /// Unit the scanner reported offsets in, before the single translation to
    /// UTF-8 bytes (ADR 0004).
    OffsetUnitName { Utf8Bytes, Utf16CodeUnits, UnicodeCodePoints }
);

/// What actually ran, as observed at startup and verified against the pins
/// (ADR 0006 D5, ADR 0008). It describes the host's runtime, so it lives in the
/// non-semantic diagnostics: it is evidence for reproduction, not part of the
/// digested result. The scanner's own activation identity string is never
/// copied here, only its digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeProvenance {
    /// Runtime name, for example `node`.
    pub runtime_name: ScannerId,
    /// Runtime version without a leading `v`, when it has the `x.y.z` shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_version: Option<VersionString>,
    /// Scanner version the process reported (equal to the pin).
    pub scanner_version: VersionString,
    /// Offset unit the scanner reported.
    pub offset_unit: OffsetUnitName,
    /// Version of the adapter shim protocol (`pii-eval-adapter/<n>`).
    pub adapter_protocol: u32,
    /// Verified digest of the shim file.
    pub shim_digest: Sha256Digest,
    /// Verified digest of the scanner artifact.
    pub artifact_digest: Sha256Digest,
    /// SHA-256 of the scanner's activation identity string.
    pub activation_identity_digest: Sha256Digest,
}

/// Non-semantic timing of an observation run. Excluded from the digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObservationDiagnostics {
    /// Start time.
    pub started_at: TimestampUtc,
    /// End time.
    pub finished_at: TimestampUtc,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
    /// Runtime provenance (protocol revision 2 documents only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<RuntimeProvenance>,
}

/// An observation set document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObservationSet {
    /// Document kind tag.
    pub schema: ObservationSetSchema,
    /// Schema version.
    pub schema_version: SchemaVersion,
    /// Semantic digest of `semantic`.
    pub semantic_digest: Sha256Digest,
    /// The digested body.
    pub semantic: ObservationSetBody,
    /// Timing diagnostics, outside the digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<ObservationDiagnostics>,
}

impl_document!(@impl
    ObservationSet,
    ObservationSetBody,
    crate::version::DocumentKind::ObservationSet,
    {
        fn validate_diagnostics(&self, path: &Path<'_>, c: &mut Collector) {
            if let Some(d) = &self.diagnostics {
                d.validate(path, c);
            }
        }
        fn validate_gates(&self, c: &mut Collector) {
            crate::protocol::check_revision_gate(self.schema_version, &self.semantic.protocol, c);
            // Runtime provenance exists only in revision-2 documents.
            let runtime = self.diagnostics.as_ref().is_some_and(|d| d.runtime.is_some());
            if runtime && !self.semantic.protocol.is_canonical() {
                c.push(
                    ReasonCode::DiagnosticsInvalid,
                    &Path::ROOT.field("diagnostics").field("runtime"),
                );
            }
        }
    }
);

impl ObservationDiagnostics {
    pub(crate) fn validate(&self, path: &Path<'_>, c: &mut Collector) {
        if self.started_at.unix_millis() > self.finished_at.unix_millis() {
            c.push(ReasonCode::DiagnosticsInvalid, path);
        }
    }
}

impl ObservationSet {
    /// Wrap a body in an envelope with the current version and a placeholder digest.
    pub fn unsealed(semantic: ObservationSetBody) -> Self {
        Self {
            schema: ObservationSetSchema::Only,
            schema_version: if semantic.protocol == crate::protocol::ProtocolIdentity::CANONICAL_V3
            {
                SchemaVersion::V1_5
            } else {
                SchemaVersion::CURRENT
            },
            semantic_digest: Sha256Digest::of_bytes(b""),
            semantic,
            diagnostics: None,
        }
    }
}

impl Finding {
    fn check_capabilities(&self, caps: &ScannerCapabilities, path: &Path<'_>, c: &mut Collector) {
        let mut contradiction = false;
        if let Some(family) = &self.family {
            contradiction |= caps.family_state(family) == CapabilityState::Unsupported;
        }
        if let Some(jurisdiction) = &self.jurisdiction {
            contradiction |= caps.jurisdiction_state(jurisdiction) == CapabilityState::Unsupported;
        }
        contradiction |= self.sensitive.is_some()
            && caps.sensitivity_classification == CapabilityState::Unsupported;
        contradiction |= self.action.is_some() && caps.action == ActionCapability::Unavailable;
        if contradiction {
            c.push(ReasonCode::CapabilityContradiction, path);
        }
    }
}

impl ObservationSetBody {
    pub(crate) fn validate(&self, path: &Path<'_>, c: &mut Collector) {
        self.protocol.validate(&path.field("protocol"), c);
        self.scanner.validate(&path.field("scanner"), c);
        self.capabilities.validate(&path.field("capabilities"), c);

        let status = path.field("status");
        let inputs_ok = self.status == ScannerStatus::Complete || self.inputs.is_empty();
        if !scanner_state_consistent(self.status, &self.replays, &self.capabilities) || !inputs_ok {
            c.push(ReasonCode::StatusInconsistent, &status);
        }

        let inputs = path.field("inputs");
        if !within_limit(
            self.inputs.len(),
            MAX_INPUTS_PER_OBSERVATION_SET,
            &inputs,
            c,
        ) {
            return;
        }
        sorted_unique(&self.inputs, |i| i.variant_id.clone(), &inputs, c);
        for (i, input) in self.inputs.iter().enumerate() {
            let p = inputs.index(i);
            let findings = p.field("findings");
            if !within_limit(input.findings.len(), MAX_FINDINGS_PER_INPUT, &findings, c) {
                continue;
            }
            if input.findings.windows(2).any(|pair| pair[0] > pair[1]) {
                c.push(ReasonCode::NonCanonicalOrder, &findings);
            }
            for (j, f) in input.findings.iter().enumerate() {
                let fp = findings.index(j);
                f.range.check_structure(&fp.field("range"), c);
                f.check_capabilities(&self.capabilities, &fp, c);
            }
            if input.sanitized_output_digest.is_some()
                && self.capabilities.action != ActionCapability::SanitizedOutput
            {
                c.push(
                    ReasonCode::CapabilityContradiction,
                    &p.field("sanitizedOutputDigest"),
                );
            }
            if c.is_full() {
                return;
            }
        }
    }
}
