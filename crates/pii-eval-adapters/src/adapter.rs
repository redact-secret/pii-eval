//! The adapter boundary and the process adapter.
//!
//! [`ScannerAdapter`] is what an executor holds: it turns a scanner
//! configuration into a bound [`ScannerPlan`] and starts a [`ScanSession`]
//! after verifying every pin. A session answers one question per call: given
//! this exact text, what did the scanner report? It has no parameter through
//! which an expectation could reach the scanner.
//!
//! Order of checks in [`ScannerAdapter::start`], each before the next:
//!
//! 1. the plan's identity and digests equal what the adapter derives from the
//!    plan's own configuration (wrong configuration or identity pins stop here);
//! 2. the shim and scanner files match their pinned SHA-256 digests;
//! 3. only then is the process spawned, and the `ready` message must repeat
//!    the pinned scanner id and version, offset unit and activation before any
//!    input text is sent.

use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use pii_eval_contracts::limits::MAX_ACTIVATION_SELECTORS;
use pii_eval_contracts::{
    ActionCapability, AdapterIdentity, CapabilityState, ConfigParameter, FamilyCapability,
    FamilyScope, Finding, Id, InputObservation, JurisdictionCapability, JurisdictionCode,
    ProductIdentity, ScannerCapabilities, ScannerConfiguration, ScannerId, ScannerIdentity,
    ScannerPlan, Sha256Digest, VersionString,
};
use pii_eval_kernel::OffsetUnit;

use crate::error::{
    AdapterError, CallPhase, LimitKind, MalformedKind, MissingCapability, PinKind,
    ScannerErrorCode, SpecProblem, StartupStage,
};
use crate::limits::AdapterLimits;
use crate::normalize::normalize_findings;
use crate::pin::{ArtifactPin, PinTarget};
use crate::process::{Received, ShimProcess, SpawnSpec, resolve_executable};
use crate::vocab::ScannerVocabulary;
use crate::wire::{self, ErrorStage, Incoming, PROTOCOL, ShimErrorCode};

/// Environment variables a spec may ask to inherit. Everything else, including
/// `PATH`, `NODE_OPTIONS`, `NODE_PATH`, `LD_*` and `DYLD_*`, is never inherited.
pub const INHERITABLE_ENV: &[&str] = &["LANG", "LC_ALL", "TMPDIR", "TMP", "TEMP", "SystemRoot"];

/// Longest runtime name or version prefix a spec may carry.
const MAX_RUNTIME_TEXT: usize = 64;

/// Sanitized output text, held in memory for the executor's verification step.
/// Its `Debug` hides the text; it is derived from the input and must never be
/// logged or written to an artifact.
#[derive(Clone, PartialEq, Eq)]
pub struct SanitizedOutput(String);

impl SanitizedOutput {
    /// The text. Handle as input-derived data.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SanitizedOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SanitizedOutput(<{} bytes>)", self.0.len())
    }
}

/// What the scanner reported for one input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanOutput {
    /// Normalized findings in canonical order.
    pub findings: Vec<Finding>,
    /// SHA-256 of the exact input bytes scanned.
    pub input_digest: Sha256Digest,
    /// SHA-256 of the sanitized output bytes, when the scanner provides output.
    pub sanitized_output_digest: Option<Sha256Digest>,
    /// The sanitized output itself, when provided. Never serialized by this crate.
    pub sanitized_output: Option<SanitizedOutput>,
    /// Native findings that were not PII observations and were not reported.
    pub skipped_findings: u64,
}

impl ScanOutput {
    /// The contract observation for this input (digests and findings, no text).
    pub fn to_input_observation(&self, variant_id: Id) -> InputObservation {
        InputObservation {
            variant_id,
            input_digest: self.input_digest.clone(),
            sanitized_output_digest: self.sanitized_output_digest.clone(),
            findings: self.findings.clone(),
        }
    }
}

/// Identities observed at runtime, recorded next to the pinned ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeRecord {
    /// Scanner version the process reported (equal to the pin).
    pub scanner_version: String,
    /// Runtime name, for example `node`.
    pub runtime_name: String,
    /// Runtime version, for example `v22.12.0`.
    pub runtime_version: String,
    /// The scanner's own activation identity string.
    pub activation_identity: String,
    /// SHA-256 of the activation identity string.
    pub activation_identity_digest: Sha256Digest,
    /// Unit the scanner reports offsets in (equal to the pin).
    pub offset_unit: OffsetUnit,
    /// Protocol identifier.
    pub protocol: &'static str,
    /// Verified digest of the shim.
    pub shim_digest: Sha256Digest,
    /// Verified digest of the scanner entry file.
    pub artifact_digest: Sha256Digest,
}

/// Counters for one finished session. Diagnostic only; not semantic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionStats {
    /// Scan calls answered.
    pub scans: u64,
    /// Stderr bytes counted and discarded (saturating at the configured cap).
    pub stderr_bytes: u64,
}

/// A failed start with what is known about capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartFailure {
    /// Why the start failed.
    pub error: AdapterError,
    /// Declared capabilities at the point of failure. Everything not known to
    /// be unsupported is `undeclared`, never `supported`.
    pub capabilities: ScannerCapabilities,
}

/// A running scanner bound to one configuration.
pub trait ScanSession: Send {
    /// Identities observed at startup.
    fn runtime(&self) -> &RuntimeRecord;
    /// Capabilities declared by the running scanner.
    fn capabilities(&self) -> &ScannerCapabilities;
    /// Scan one text. Any error other than `InputTooLarge` ends the session:
    /// the process has been killed and later calls return `SessionClosed`.
    fn scan(&mut self, text: &str) -> Result<ScanOutput, AdapterError>;
    /// Stop the scanner and report counters. Idempotent.
    fn finish(&mut self) -> SessionStats;
}

/// A scanner adapter: configuration in, bound plan out, then sessions.
pub trait ScannerAdapter: Send + Sync {
    /// Validate `configuration` and derive the scanner plan (identity plus the
    /// configuration whose digests it binds).
    fn plan(&self, configuration: ScannerConfiguration) -> Result<ScannerPlan, AdapterError>;
    /// Verify every pin and start a session for `plan`.
    fn start(&self, plan: &ScannerPlan) -> Result<Box<dyn ScanSession>, StartFailure>;
}

/// Everything that fixes a process adapter. All of it comes from reviewed
/// code or a pinned plan, never from corpus text or scanner output.
#[derive(Debug, Clone)]
pub struct ProcessAdapterSpec {
    /// Absolute path of the interpreter (for example `node`). Canonicalized at construction.
    pub executable: PathBuf,
    /// The shim script and its digest. Passed as the first argument.
    pub shim: ArtifactPin,
    /// The scanner artifact (a package tree or one file) and its digest. The
    /// digest is the scanner's `artifactDigest`.
    pub scanner_artifact: ArtifactPin,
    /// Absolute path of the file the shim loads, passed as the second
    /// argument. It must be the artifact itself (file pin) or lie inside it
    /// (tree pin), so the loaded code is the verified code.
    pub scanner_entry: PathBuf,
    /// Further files that must match their digests (for example a native addon).
    pub extra_artifacts: Vec<ArtifactPin>,
    /// Scanner identifier.
    pub scanner_id: ScannerId,
    /// Pinned scanner version, which the process must repeat.
    pub scanner_version: VersionString,
    /// Released or candidate. A candidate digest must equal the entry digest.
    pub product: ProductIdentity,
    /// Adapter identity recorded in the scanner identity.
    pub adapter: AdapterIdentity,
    /// Expected runtime name reported by the shim.
    pub runtime_name: String,
    /// Required prefix of the runtime version, when pinned (for example `v22.`).
    pub runtime_version_prefix: Option<String>,
    /// Unit the scanner reports offsets in.
    pub offset_unit: OffsetUnit,
    /// Parent environment variables to pass through; each must be in [`INHERITABLE_ENV`].
    pub inherit_env: Vec<String>,
    /// The only configuration parameters this adapter accepts, ascending by key.
    /// A configuration must equal this list exactly.
    pub allowed_parameters: Vec<ConfigParameter>,
    /// Ask the shim for sanitized output (declares `sanitized-output` action capability).
    pub return_output: bool,
    /// Process limits.
    pub limits: AdapterLimits,
    /// Native-label mapping.
    pub vocabulary: Arc<dyn ScannerVocabulary>,
}

/// An adapter that runs a scanner through a pinned shim process.
#[derive(Debug, Clone)]
pub struct ProcessAdapter {
    spec: ProcessAdapterSpec,
    executable: PathBuf,
}

fn undeclared_capabilities() -> ScannerCapabilities {
    ScannerCapabilities {
        ranges: CapabilityState::Undeclared,
        family_classification: CapabilityState::Undeclared,
        sensitivity_classification: CapabilityState::Undeclared,
        jurisdiction_reporting: CapabilityState::Undeclared,
        action: ActionCapability::Unavailable,
        families: Vec::new(),
        jurisdictions: Vec::new(),
    }
}

impl ProcessAdapter {
    /// Validate a specification. Nothing is executed or hashed here.
    pub fn new(spec: ProcessAdapterSpec) -> Result<Self, AdapterError> {
        spec.limits.validate()?;
        let executable = resolve_executable(&spec.executable)?;
        let bad = |p| AdapterError::InvalidSpec(p);
        let abs = |a: &ArtifactPin| a.path.is_absolute();
        if !abs(&spec.shim)
            || !abs(&spec.scanner_artifact)
            || !spec.scanner_entry.is_absolute()
            || !spec.extra_artifacts.iter().all(abs)
            || spec.shim.path.parent().is_none()
            || spec.shim.target != PinTarget::File
        {
            return Err(bad(SpecProblem::ArtifactPath));
        }
        let no_parent_dirs = !spec
            .scanner_entry
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir));
        let entry_bound = match spec.scanner_artifact.target {
            PinTarget::File => spec.scanner_entry == spec.scanner_artifact.path,
            PinTarget::Tree => {
                spec.scanner_entry.starts_with(&spec.scanner_artifact.path)
                    && spec.scanner_entry != spec.scanner_artifact.path
            }
        };
        if !no_parent_dirs || !entry_bound {
            return Err(bad(SpecProblem::ArtifactPath));
        }
        if spec
            .inherit_env
            .iter()
            .any(|n| !INHERITABLE_ENV.contains(&n.as_str()))
        {
            return Err(bad(SpecProblem::Environment));
        }
        let text_ok = |s: &str| !s.is_empty() && s.len() <= MAX_RUNTIME_TEXT && s.is_ascii();
        if !text_ok(&spec.runtime_name)
            || spec
                .runtime_version_prefix
                .as_deref()
                .is_some_and(|p| !text_ok(p))
        {
            return Err(bad(SpecProblem::Identity));
        }
        if let ProductIdentity::Candidate { candidate_digest } = &spec.product {
            if *candidate_digest != spec.scanner_artifact.sha256 {
                return Err(bad(SpecProblem::Identity));
            }
        }
        if spec
            .allowed_parameters
            .windows(2)
            .any(|w| w[0].key >= w[1].key)
        {
            return Err(bad(SpecProblem::Parameters));
        }
        Ok(Self { spec, executable })
    }

    /// The specification.
    pub fn spec(&self) -> &ProcessAdapterSpec {
        &self.spec
    }

    /// Check a configuration against this adapter's closed parameter set and
    /// selector grammar.
    fn check_configuration(
        &self,
        configuration: &ScannerConfiguration,
    ) -> Result<(), AdapterError> {
        if configuration.parameters != self.spec.allowed_parameters {
            return Err(AdapterError::InvalidSpec(SpecProblem::Parameters));
        }
        let selectors = &configuration.activation;
        let ordered = selectors.windows(2).all(|w| w[0] < w[1]);
        if selectors.len() > MAX_ACTIVATION_SELECTORS
            || !ordered
            || !selectors
                .iter()
                .all(|s| self.spec.vocabulary.valid_selector(s.as_str()))
        {
            return Err(AdapterError::InvalidSpec(SpecProblem::Selector));
        }
        Ok(())
    }

    /// The scanner identity this adapter binds for `configuration`.
    pub fn identity(
        &self,
        configuration: &ScannerConfiguration,
    ) -> Result<ScannerIdentity, AdapterError> {
        self.check_configuration(configuration)?;
        let digest = |r: Result<Sha256Digest, _>| {
            r.map_err(|_| AdapterError::InvalidSpec(SpecProblem::Identity))
        };
        Ok(ScannerIdentity {
            scanner_id: self.spec.scanner_id.clone(),
            scanner_version: Some(self.spec.scanner_version.clone()),
            artifact_digest: Some(self.spec.scanner_artifact.sha256.clone()),
            adapter: self.spec.adapter.clone(),
            product: self.spec.product.clone(),
            configuration_digest: digest(configuration.configuration_digest())?,
            activation_digest: digest(configuration.activation_digest())?,
        })
    }

    fn failure(&self, error: AdapterError, capabilities: ScannerCapabilities) -> StartFailure {
        StartFailure {
            error,
            capabilities,
        }
    }

    /// Capabilities to record when the scanner rejects the selectors: the
    /// jurisdiction is marked unsupported only when exactly one requested
    /// selector names one, since the scanner does not say which it rejected.
    fn rejected_capabilities(&self, configuration: &ScannerConfiguration) -> ScannerCapabilities {
        let mut caps = undeclared_capabilities();
        let requested: Vec<JurisdictionCode> = configuration
            .activation
            .iter()
            .filter_map(|s| self.spec.vocabulary.selector_jurisdiction(s.as_str()))
            .collect();
        if let [only] = requested.as_slice() {
            caps.jurisdictions.push(JurisdictionCapability {
                jurisdiction: only.clone(),
                state: CapabilityState::Unsupported,
            });
        }
        caps
    }

    fn spawn_spec(&self) -> Result<SpawnSpec, AdapterError> {
        let mut env = vec![("PII_EVAL_ADAPTER_PROTOCOL".to_owned(), PROTOCOL.to_owned())];
        for name in &self.spec.inherit_env {
            if let Some(value) = std::env::var_os(name).and_then(|v| v.into_string().ok()) {
                env.push((name.clone(), value));
            }
        }
        let working_dir = self
            .spec
            .shim
            .path
            .parent()
            .map(PathBuf::from)
            .ok_or(AdapterError::InvalidSpec(SpecProblem::ArtifactPath))?;
        Ok(SpawnSpec {
            executable: self.executable.clone(),
            args: vec![
                self.spec.shim.path.clone().into_os_string(),
                self.spec.scanner_entry.clone().into_os_string(),
            ],
            working_dir,
            env,
        })
    }
}

fn startup_error(received: Received) -> AdapterError {
    match received {
        Received::Timeout => AdapterError::Timeout(CallPhase::Startup),
        Received::TooLong => AdapterError::OutputLimit(LimitKind::Line),
        Received::Truncated => AdapterError::MalformedOutput(MalformedKind::Truncated),
        Received::Eof | Received::Line(_) => {
            AdapterError::StartupFailure(StartupStage::ExitedBeforeReady)
        }
    }
}

impl ScannerAdapter for ProcessAdapter {
    fn plan(&self, configuration: ScannerConfiguration) -> Result<ScannerPlan, AdapterError> {
        let identity = self.identity(&configuration)?;
        Ok(ScannerPlan {
            identity,
            configuration,
        })
    }

    fn start(&self, plan: &ScannerPlan) -> Result<Box<dyn ScanSession>, StartFailure> {
        let none = undeclared_capabilities;

        // 1. Identity and digests, derived again from the plan's own configuration.
        let expected = self
            .identity(&plan.configuration)
            .map_err(|e| self.failure(e, none()))?;
        if plan.identity != expected {
            return Err(self.failure(AdapterError::PinMismatch(PinKind::PlanIdentity), none()));
        }

        // 2. File pins, before anything is executed.
        let verify = || -> Result<(), AdapterError> {
            self.spec.shim.verify(PinKind::ShimDigest)?;
            self.spec.scanner_artifact.verify(PinKind::ArtifactDigest)?;
            for extra in &self.spec.extra_artifacts {
                extra.verify(PinKind::ArtifactDigest)?;
            }
            Ok(())
        };
        verify().map_err(|e| self.failure(e, none()))?;

        // 3. Spawn, initialize, and verify the runtime identity before any input.
        let spawn = self.spawn_spec().map_err(|e| self.failure(e, none()))?;
        let limits = self.spec.limits;
        let mut process =
            ShimProcess::spawn(&spawn, limits.max_line_bytes, limits.max_stderr_bytes)
                .map_err(|e| self.failure(e, none()))?;
        let selectors: Vec<String> = plan
            .configuration
            .activation
            .iter()
            .map(|s| s.as_str().to_owned())
            .collect();
        let init = wire::encode_init(
            &selectors,
            &plan.configuration.parameters,
            self.spec.return_output,
            &limits,
        );
        let _ = process.send(init);
        let deadline = Instant::now() + limits.startup_timeout;
        let received = process.receive(deadline);
        let line = match received {
            Received::Line(line) => line,
            other => {
                let error = startup_error(other);
                process.kill();
                return Err(self.failure(error, none()));
            }
        };
        let decoded = wire::decode(&line, self.spec.return_output);
        let ready = match decoded {
            Ok(Incoming::Ready(ready)) => ready,
            Ok(Incoming::Error(e)) if e.stage == ErrorStage::Init => {
                process.kill();
                let (error, caps) = match e.code {
                    ShimErrorCode::UnsupportedSelector => (
                        AdapterError::MissingCapability(MissingCapability::SelectorUnsupported),
                        self.rejected_capabilities(&plan.configuration),
                    ),
                    ShimErrorCode::InvalidSelector => (
                        AdapterError::MissingCapability(MissingCapability::ConfigurationRejected),
                        none(),
                    ),
                    _ => (
                        AdapterError::StartupFailure(StartupStage::ScannerInitialization),
                        none(),
                    ),
                };
                return Err(self.failure(error, caps));
            }
            Ok(_) => {
                process.kill();
                return Err(self.failure(
                    AdapterError::MalformedOutput(MalformedKind::UnexpectedMessage),
                    none(),
                ));
            }
            Err(kind) => {
                process.kill();
                return Err(self.failure(AdapterError::MalformedOutput(kind), none()));
            }
        };

        match self.verify_ready(&ready, &selectors) {
            Ok((record, capabilities)) => Ok(Box::new(ProcessSession {
                process,
                limits,
                unit: self.spec.offset_unit,
                return_output: self.spec.return_output,
                vocabulary: Arc::clone(&self.spec.vocabulary),
                runtime: record,
                capabilities,
                seq: 0,
                closed: false,
            })),
            Err(error) => {
                process.kill();
                Err(self.failure(error, none()))
            }
        }
    }
}

impl ProcessAdapter {
    fn verify_ready(
        &self,
        ready: &wire::Ready,
        requested: &[String],
    ) -> Result<(RuntimeRecord, ScannerCapabilities), AdapterError> {
        let spec = &self.spec;
        if ready.scanner_id != spec.scanner_id.as_str() {
            return Err(AdapterError::PinMismatch(PinKind::ScannerId));
        }
        if ready.scanner_version != spec.scanner_version.as_str() {
            return Err(AdapterError::PinMismatch(PinKind::ScannerVersion));
        }
        let prefix_ok = spec
            .runtime_version_prefix
            .as_deref()
            .is_none_or(|p| ready.runtime_version.starts_with(p));
        if ready.runtime_name != spec.runtime_name || !prefix_ok {
            return Err(AdapterError::PinMismatch(PinKind::Runtime));
        }
        if OffsetUnit::from_wire(&ready.offset_unit) != Some(spec.offset_unit) {
            return Err(AdapterError::PinMismatch(PinKind::OffsetUnit));
        }
        let activation = spec
            .vocabulary
            .parse_activation(&ready.activation)
            .map_err(|_| AdapterError::MalformedOutput(MalformedKind::Activation))?;
        if activation.selectors != requested {
            return Err(AdapterError::PinMismatch(PinKind::Activation));
        }

        let mut capabilities = spec.vocabulary.base_capabilities();
        capabilities.action = if spec.return_output {
            ActionCapability::SanitizedOutput
        } else {
            ActionCapability::ReportedAction
        };
        let families: BTreeSet<_> = activation.families.iter().cloned().collect();
        let jurisdictions: BTreeSet<JurisdictionCode> = families
            .iter()
            .filter_map(|f| match f.scope() {
                FamilyScope::Jurisdiction(code) => Some(code),
                FamilyScope::Global => None,
            })
            .collect();
        capabilities.families = families
            .into_iter()
            .map(|family| FamilyCapability {
                family,
                state: CapabilityState::Supported,
            })
            .collect();
        capabilities.jurisdictions = jurisdictions
            .into_iter()
            .map(|jurisdiction| JurisdictionCapability {
                jurisdiction,
                state: CapabilityState::Supported,
            })
            .collect();

        let record = RuntimeRecord {
            scanner_version: ready.scanner_version.clone(),
            runtime_name: ready.runtime_name.clone(),
            runtime_version: ready.runtime_version.clone(),
            activation_identity_digest: Sha256Digest::of_bytes(ready.activation.as_bytes()),
            activation_identity: ready.activation.clone(),
            offset_unit: spec.offset_unit,
            protocol: PROTOCOL,
            shim_digest: spec.shim.sha256.clone(),
            artifact_digest: spec.scanner_artifact.sha256.clone(),
        };
        Ok((record, capabilities))
    }
}

struct ProcessSession {
    process: ShimProcess,
    limits: AdapterLimits,
    unit: OffsetUnit,
    return_output: bool,
    vocabulary: Arc<dyn ScannerVocabulary>,
    runtime: RuntimeRecord,
    capabilities: ScannerCapabilities,
    seq: u64,
    closed: bool,
}

impl ProcessSession {
    fn fail(&mut self, error: AdapterError) -> AdapterError {
        self.process.kill();
        self.closed = true;
        error
    }
}

impl ScanSession for ProcessSession {
    fn runtime(&self) -> &RuntimeRecord {
        &self.runtime
    }

    fn capabilities(&self) -> &ScannerCapabilities {
        &self.capabilities
    }

    fn scan(&mut self, text: &str) -> Result<ScanOutput, AdapterError> {
        if self.closed {
            return Err(AdapterError::SessionClosed);
        }
        if text.len() > self.limits.max_text_bytes {
            return Err(AdapterError::InputTooLarge);
        }
        let Some(seq) = self.seq.checked_add(1) else {
            return Err(self.fail(AdapterError::SessionClosed));
        };
        self.seq = seq;
        let _ = self.process.send(wire::encode_scan(seq, text));
        let deadline = Instant::now() + self.limits.call_timeout;
        let line = match self.process.receive(deadline) {
            Received::Line(line) => line,
            Received::Timeout => return Err(self.fail(AdapterError::Timeout(CallPhase::Scan))),
            Received::TooLong => {
                return Err(self.fail(AdapterError::OutputLimit(LimitKind::Line)));
            }
            Received::Truncated => {
                return Err(self.fail(AdapterError::MalformedOutput(MalformedKind::Truncated)));
            }
            Received::Eof => {
                let error = if self.process.ended_abnormally() {
                    AdapterError::Crashed
                } else {
                    AdapterError::MalformedOutput(MalformedKind::UnexpectedEof)
                };
                return Err(self.fail(error));
            }
        };
        let result = match wire::decode(&line, self.return_output) {
            Ok(Incoming::Result(r)) => r,
            Ok(Incoming::Error(e)) if e.stage == ErrorStage::Scan && e.seq == Some(seq) => {
                let error = match e.code {
                    ShimErrorCode::FindingLimit => AdapterError::OutputLimit(LimitKind::Findings),
                    ShimErrorCode::InputLimit => {
                        AdapterError::ScannerError(ScannerErrorCode::InputLimit)
                    }
                    ShimErrorCode::ProtocolError => {
                        AdapterError::ScannerError(ScannerErrorCode::ProtocolError)
                    }
                    ShimErrorCode::ScannerError => {
                        AdapterError::ScannerError(ScannerErrorCode::ScanFailed)
                    }
                    _ => AdapterError::MalformedOutput(MalformedKind::UnexpectedMessage),
                };
                return Err(self.fail(error));
            }
            Ok(_) => {
                return Err(self.fail(AdapterError::MalformedOutput(
                    MalformedKind::UnexpectedMessage,
                )));
            }
            Err(kind) => return Err(self.fail(AdapterError::MalformedOutput(kind))),
        };
        if result.seq != seq {
            return Err(self.fail(AdapterError::MalformedOutput(MalformedKind::WrongSequence)));
        }
        let normalized = match normalize_findings(
            text,
            self.unit,
            &result.findings,
            self.vocabulary.as_ref(),
            self.limits.max_findings,
        ) {
            Ok(n) => n,
            Err(error) => return Err(self.fail(error)),
        };
        let sanitized_output_digest = result
            .output
            .as_ref()
            .map(|o| Sha256Digest::of_bytes(o.as_bytes()));
        Ok(ScanOutput {
            findings: normalized.findings,
            input_digest: Sha256Digest::of_bytes(text.as_bytes()),
            sanitized_output_digest,
            sanitized_output: result.output.map(SanitizedOutput),
            skipped_findings: normalized.skipped,
        })
    }

    fn finish(&mut self) -> SessionStats {
        if !self.closed {
            self.closed = true;
            self.process.close(wire::encode_shutdown());
        }
        SessionStats {
            scans: self.seq,
            stderr_bytes: self.process.stderr_bytes(),
        }
    }
}
