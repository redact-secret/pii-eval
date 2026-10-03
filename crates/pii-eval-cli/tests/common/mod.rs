//! Shared helpers for the executor tests. Synthetic only: the scanners are
//! in-process fakes and the inert Node fake of the adapters crate.
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pii_eval_adapters::error::MissingCapability;
use pii_eval_adapters::{
    AbortHandle, AdapterError, AdapterLimits, RuntimeRecord, SanitizedOutput, ScanOutput,
    ScanSession, ScannerAdapter, SessionStats, StartFailure,
};
use pii_eval_contracts::{
    ActionCapability, ActionKind, ActivationSelector, AdapterIdentity, ByteRange, CapabilityState,
    ConfigKey, ConfigParameter, ConfigValue, CorpusSnapshot, EngineIdentity, EngineName,
    ExecutionLimits, FamilyCapability, FamilyId, Finding, JurisdictionCode, LanguageTag, METRICS,
    Mechanics, MethodId, MethodRef, MetricId, MetricRef, PopulationBinding, ProductIdentity,
    ProtocolIdentity, RunClass, RunManifest, RunManifestBody, ScannerCapabilities,
    ScannerConfiguration, ScannerId, ScannerIdentity, ScannerPlan, Scope, Sha256Digest,
    VersionString, parse_default, seal,
};
use pii_eval_kernel::OffsetUnit;

pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/contracts/v1")
}

pub fn snapshot() -> CorpusSnapshot {
    let bytes = std::fs::read(fixtures_dir().join("snapshot.json")).expect("committed snapshot");
    parse_default(&bytes).expect("snapshot parses")
}

pub fn sid(s: &str) -> ScannerId {
    ScannerId::new(s).unwrap()
}

pub fn ver(s: &str) -> VersionString {
    VersionString::new(s).unwrap()
}

pub fn digest_of(s: &str) -> Sha256Digest {
    Sha256Digest::of_bytes(s.as_bytes())
}

pub fn configuration(salt: i64) -> ScannerConfiguration {
    ScannerConfiguration {
        parameters: vec![ConfigParameter {
            key: ConfigKey::new("contextWindow").unwrap(),
            value: ConfigValue::Integer(salt),
        }],
        activation: vec![
            ActivationSelector::new("pii:global").unwrap(),
            ActivationSelector::new("pii:us").unwrap(),
        ],
    }
}

pub fn plan(name: &str, salt: i64) -> ScannerPlan {
    let configuration = configuration(salt);
    ScannerPlan {
        identity: ScannerIdentity {
            scanner_id: sid(name),
            scanner_version: Some(ver("1.0.0")),
            artifact_digest: Some(digest_of(&format!("artifact-{name}"))),
            adapter: AdapterIdentity {
                adapter_id: sid("fake-adapter"),
                adapter_version: ver("0.0.1"),
                normalization_version: 1,
            },
            product: ProductIdentity::Released,
            configuration_digest: configuration.configuration_digest().unwrap(),
            activation_digest: configuration.activation_digest().unwrap(),
        },
        configuration,
    }
}

pub fn limits(workers: u32, per_scanner: u32, batch: u32, pending: u32) -> ExecutionLimits {
    ExecutionLimits {
        workers,
        per_scanner_parallelism: per_scanner,
        pending_tasks: pending,
        batch_variants: batch,
        scanner_timeout_ms: 120_000,
        max_stdout_bytes: 16 << 20,
        max_stderr_bytes: 1 << 20,
        max_memory_bytes: 16 << 30,
        max_temporary_bytes: 4 << 30,
    }
}

pub fn engine() -> EngineIdentity {
    EngineIdentity {
        name: EngineName::PiiEval,
        version: ver(pii_eval_contracts::ENGINE_VERSION),
    }
}

/// A revision-2 manifest over `snapshot` for `plans` (ascending by scanner id).
pub fn manifest(
    snapshot: &CorpusSnapshot,
    plans: Vec<ScannerPlan>,
    limits: ExecutionLimits,
    mechanics: Mechanics,
) -> RunManifest {
    let mut methods: Vec<MethodRef> = [
        MethodId::TypeValidation,
        MethodId::ContextDiscrimination,
        MethodId::JurisdictionCollision,
        MethodId::PiiBenign,
    ]
    .into_iter()
    .map(MethodRef::frozen)
    .collect();
    methods.sort_by_key(|m| m.id.as_str());
    let mut metrics: Vec<MetricRef> = METRICS.iter().map(|m| MetricRef::frozen(m.id)).collect();
    metrics.sort_by_key(|m| m.id.as_str());
    let _ = MetricId::TypeMissRate;
    let mut manifest = RunManifest::unsealed(RunManifestBody {
        engine: engine(),
        protocol: ProtocolIdentity::CANONICAL_V2,
        run_class: RunClass::PublicSynthetic,
        population: PopulationBinding {
            population_id: snapshot.semantic.population.population_id.clone(),
            visibility: snapshot.semantic.population.visibility,
            population_version: snapshot.semantic.population.population_version,
            population_digest: snapshot.semantic_digest.clone(),
        },
        scope: Scope {
            languages: vec![
                LanguageTag::new("en").unwrap(),
                LanguageTag::new("ko").unwrap(),
            ],
            jurisdictions: vec![JurisdictionCode::new("US").unwrap()],
        },
        methods,
        metrics,
        mechanics,
        generation: snapshot.semantic.generation.clone(),
        limits,
        scanners: plans,
    });
    seal(&mut manifest).unwrap();
    manifest
}

pub fn mechanics(replays: u32) -> Mechanics {
    Mechanics {
        replays,
        ..Mechanics::PII_V1
    }
}

// ---------------------------------------------------------------------------
// An in-process fake scanner
// ---------------------------------------------------------------------------

/// How the fake treats sanitized output.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Sanitize {
    /// Replace every finding by `<R>`.
    Clean,
    /// Return the text unchanged.
    Unchanged,
    /// Replace every finding and also this context word.
    AlsoRedact(&'static str),
}

/// Observations shared by every session of one fake adapter.
#[derive(Default)]
pub struct Probe {
    pub current: AtomicUsize,
    pub max_concurrent: AtomicUsize,
    pub sessions_started: AtomicU64,
    pub completed: Mutex<Vec<String>>,
}

#[derive(Clone)]
pub struct FakeAdapter {
    pub plan: ScannerPlan,
    pub capabilities: ScannerCapabilities,
    pub sanitize: Option<Sanitize>,
    /// Sleep before answering a text that starts with the prefix.
    pub delays: Vec<(&'static str, Duration)>,
    /// Sleep before every answer.
    pub delay_all: Duration,
    /// Fail a text containing the needle with the error.
    pub failures: Vec<(&'static str, AdapterError)>,
    /// Sessions with an odd number (counted per adapter) report no findings.
    pub flaky: bool,
    /// Refuse to start with a missing capability.
    pub unsupported: bool,
    /// What every session reports as its end-of-session pin re-check.
    pub pin_check: Option<AdapterError>,
    pub adapter_limits: Option<AdapterLimits>,
    pub probe: Arc<Probe>,
}

pub fn capabilities(output: bool) -> ScannerCapabilities {
    let fam = |s: &str| FamilyCapability {
        family: FamilyId::new(s).unwrap(),
        state: CapabilityState::Supported,
    };
    ScannerCapabilities {
        ranges: CapabilityState::Supported,
        family_classification: CapabilityState::Supported,
        sensitivity_classification: CapabilityState::Supported,
        jurisdiction_reporting: CapabilityState::Supported,
        action: if output {
            ActionCapability::SanitizedOutput
        } else {
            ActionCapability::ReportedAction
        },
        families: vec![
            fam("pii:global:email"),
            fam("pii:global:payment-card"),
            fam("pii:us:ssn"),
        ],
        jurisdictions: vec![pii_eval_contracts::JurisdictionCapability {
            jurisdiction: JurisdictionCode::new("US").unwrap(),
            state: CapabilityState::Supported,
        }],
    }
}

impl FakeAdapter {
    pub fn new(name: &str, salt: i64) -> Self {
        FakeAdapter {
            plan: plan(name, salt),
            capabilities: capabilities(true),
            sanitize: Some(Sanitize::Clean),
            delays: Vec::new(),
            delay_all: Duration::ZERO,
            failures: Vec::new(),
            flaky: false,
            unsupported: false,
            pin_check: None,
            adapter_limits: None,
            probe: Arc::new(Probe::default()),
        }
    }
}

/// Findings of the fake detector: emails (`@`), US SSN shapes and 16-digit card
/// shapes, by UTF-8 byte range, in canonical order.
pub fn detect(text: &str) -> Vec<Finding> {
    let mut tokens: Vec<(usize, &str)> = Vec::new();
    let mut start = None;
    for (i, c) in text.char_indices() {
        match (c.is_whitespace(), start) {
            (false, None) => start = Some(i),
            (true, Some(s)) => {
                tokens.push((s, &text[s..i]));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        tokens.push((s, &text[s..]));
    }
    let finding = |s: usize, e: usize, family: &str, jurisdiction: Option<&str>| Finding {
        range: ByteRange {
            start: s as u64,
            end: e as u64,
        },
        family: Some(FamilyId::new(family).unwrap()),
        jurisdiction: jurisdiction.map(|j| JurisdictionCode::new(j).unwrap()),
        sensitive: Some(true),
        action: Some(ActionKind::Redact),
    };
    let mut out = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let (s, t) = tokens[i];
        let digits4 = |t: &str| t.len() == 4 && t.bytes().all(|b| b.is_ascii_digit());
        if t.contains('@') {
            out.push(finding(s, s + t.len(), "pii:global:email", None));
        } else if t.len() == 11
            && t.bytes().enumerate().all(|(k, b)| {
                if k == 3 || k == 6 {
                    b == b'-'
                } else {
                    b.is_ascii_digit()
                }
            })
        {
            out.push(finding(s, s + t.len(), "pii:us:ssn", Some("US")));
        } else if i + 3 < tokens.len() && (0..4).all(|k| digits4(tokens[i + k].1)) {
            let end = tokens[i + 3].0 + 4;
            out.push(finding(s, end, "pii:global:payment-card", None));
            i += 3;
        }
        i += 1;
    }
    out.sort();
    out
}

fn sanitize(text: &str, findings: &[Finding], mode: Sanitize) -> String {
    let mut out = String::new();
    let mut at = 0usize;
    for f in findings {
        let (s, e) = (f.range.start as usize, f.range.end as usize);
        out.push_str(&text[at..s]);
        out.push_str("<R>");
        at = e;
    }
    out.push_str(&text[at..]);
    match mode {
        Sanitize::AlsoRedact(word) => out.replace(word, "<R>"),
        _ => out,
    }
}

struct FakeSession {
    adapter: FakeAdapter,
    odd: bool,
    runtime: RuntimeRecord,
    scans: u64,
}

impl ScanSession for FakeSession {
    fn runtime(&self) -> &RuntimeRecord {
        &self.runtime
    }

    fn capabilities(&self) -> &ScannerCapabilities {
        &self.adapter.capabilities
    }

    fn scan(&mut self, text: &str) -> Result<ScanOutput, AdapterError> {
        let probe = &self.adapter.probe;
        let now = probe.current.fetch_add(1, Ordering::SeqCst) + 1;
        probe.max_concurrent.fetch_max(now, Ordering::SeqCst);
        let result = (|| {
            let mut delay = self.adapter.delay_all;
            for (prefix, d) in &self.adapter.delays {
                if text.starts_with(prefix) {
                    delay += *d;
                }
            }
            std::thread::sleep(delay);
            for (needle, error) in &self.adapter.failures {
                if text.contains(needle) {
                    return Err(*error);
                }
            }
            self.scans += 1;
            let findings = if self.adapter.flaky && self.odd {
                Vec::new()
            } else {
                detect(text)
            };
            let (digest, output) = match self.adapter.sanitize {
                Some(mode) => {
                    let s = match mode {
                        Sanitize::Unchanged => text.to_owned(),
                        _ => sanitize(text, &findings, mode),
                    };
                    (
                        Some(Sha256Digest::of_bytes(s.as_bytes())),
                        Some(SanitizedOutput::new(s)),
                    )
                }
                None => (None, None),
            };
            probe
                .completed
                .lock()
                .unwrap()
                .push(text.chars().take(24).collect());
            Ok(ScanOutput {
                findings,
                input_digest: Sha256Digest::of_bytes(text.as_bytes()),
                sanitized_output_digest: digest,
                sanitized_output: output,
                skipped_findings: 0,
            })
        })();
        probe.current.fetch_sub(1, Ordering::SeqCst);
        result
    }

    fn finish(&mut self) -> SessionStats {
        SessionStats {
            scans: self.scans,
            stderr_bytes: 0,
            peak_rss_bytes: 0,
            pin_check: self.adapter.pin_check,
        }
    }

    fn abort_handle(&self) -> AbortHandle {
        AbortHandle::inert()
    }
}

impl ScannerAdapter for FakeAdapter {
    fn plan(&self, _configuration: ScannerConfiguration) -> Result<ScannerPlan, AdapterError> {
        Ok(self.plan.clone())
    }

    fn start(&self, plan: &ScannerPlan) -> Result<Box<dyn ScanSession>, StartFailure> {
        if *plan != self.plan {
            return Err(StartFailure {
                error: AdapterError::PinMismatch(pii_eval_adapters::error::PinKind::PlanIdentity),
                capabilities: unknown(),
            });
        }
        if self.unsupported {
            let mut caps = unknown();
            caps.ranges = CapabilityState::Unsupported;
            caps.family_classification = CapabilityState::Unsupported;
            caps.sensitivity_classification = CapabilityState::Unsupported;
            caps.jurisdiction_reporting = CapabilityState::Unsupported;
            return Err(StartFailure {
                error: AdapterError::MissingCapability(MissingCapability::SelectorUnsupported),
                capabilities: caps,
            });
        }
        let n = self.probe.sessions_started.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(FakeSession {
            adapter: self.clone(),
            odd: n % 2 == 1,
            scans: 0,
            runtime: RuntimeRecord {
                scanner_version: "1.0.0".to_owned(),
                runtime_name: "fake-runtime".to_owned(),
                runtime_version: "v1.2.3".to_owned(),
                activation_identity: "fake".to_owned(),
                activation_identity_digest: digest_of("fake"),
                offset_unit: OffsetUnit::Utf8Bytes,
                protocol: "pii-eval-adapter/1",
                shim_digest: digest_of("shim"),
                artifact_digest: digest_of("artifact"),
            },
        }))
    }

    fn limits(&self) -> Option<AdapterLimits> {
        self.adapter_limits
    }
}

fn unknown() -> ScannerCapabilities {
    ScannerCapabilities {
        ranges: CapabilityState::Undeclared,
        family_classification: CapabilityState::Undeclared,
        sensitivity_classification: CapabilityState::Undeclared,
        jurisdiction_reporting: CapabilityState::Undeclared,
        action: ActionCapability::Unavailable,
        families: vec![],
        jurisdictions: vec![],
    }
}

pub fn scratch_dir(label: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "pii-eval-cli-{}-{}-{label}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(label: &str) -> Self {
        TempDir(scratch_dir(label))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
