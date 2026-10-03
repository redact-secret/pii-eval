//! The engine end-to-end check: the REAL run pipeline (executor, assembler,
//! kernel accounting, contract sealing and verification) over the frozen
//! observations of the oracle export, through an in-process adapter that replays
//! them. It closes the loop between the comparator (which calls the kernel
//! directly) and the engine that produces artifacts.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use pii_eval_adapters::error::{MissingCapability, StartupStage};
use pii_eval_adapters::{
    AbortHandle, AdapterError, RuntimeRecord, ScanOutput, ScanSession, ScannerAdapter,
    SessionStats, StartFailure,
};
use pii_eval_cli::exec::{CancelToken, ExecutorConfig, ResourcePolicy};
use pii_eval_cli::run::{RunConfig, RunRequest, run};
use pii_eval_contracts::{
    ActionCapability, CapabilityState, CorpusSnapshot, FamilyCapability, FamilyId, Finding,
    JurisdictionCapability, JurisdictionCode, LanguageTag, METRICS, Mechanics, MethodId, MethodRef,
    MetricId, MetricRef, MetricResult, PopulationBinding, ProtocolIdentity, RunArtifact, RunClass,
    RunManifest, RunManifestBody, ScannerCapabilities, ScannerConfiguration, ScannerPlan, Scope,
    Sha256Digest, seal,
};
use pii_eval_kernel::OffsetUnit;

use super::compare::{MetricView, RateView};
use super::json::*;
use super::model::*;

/// How the frozen scanner behaves.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Behaviour {
    Replay,
    Unsupported,
    Unavailable,
    Error,
    /// The second scan of any text reports nothing (the replays disagree), whatever
    /// session or worker handles it.
    Unstable,
}

#[derive(Clone)]
pub struct FrozenAdapter {
    plan: ScannerPlan,
    behaviour: Behaviour,
    by_text: Arc<BTreeMap<String, Vec<Finding>>>,
    sessions: Arc<AtomicU64>,
    scans_per_text: Arc<Mutex<BTreeMap<String, u64>>>,
}

fn capabilities() -> ScannerCapabilities {
    let fam = |s: &str| FamilyCapability {
        family: FamilyId::new(s).unwrap(),
        state: CapabilityState::Supported,
    };
    ScannerCapabilities {
        ranges: CapabilityState::Supported,
        family_classification: CapabilityState::Supported,
        sensitivity_classification: CapabilityState::Supported,
        jurisdiction_reporting: CapabilityState::Supported,
        action: ActionCapability::ReportedAction,
        families: vec![fam("pii:global:email"), fam("pii:us:ssn")],
        jurisdictions: vec![JurisdictionCapability {
            jurisdiction: JurisdictionCode::new("US").unwrap(),
            state: CapabilityState::Supported,
        }],
    }
}

fn undeclared() -> ScannerCapabilities {
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

struct Session {
    capabilities: ScannerCapabilities,
    by_text: Arc<BTreeMap<String, Vec<Finding>>>,
    behaviour: Behaviour,
    scans_per_text: Arc<Mutex<BTreeMap<String, u64>>>,
    runtime: RuntimeRecord,
    scans: u64,
}

impl ScanSession for Session {
    fn runtime(&self) -> &RuntimeRecord {
        &self.runtime
    }

    fn capabilities(&self) -> &ScannerCapabilities {
        &self.capabilities
    }

    fn scan(&mut self, text: &str) -> Result<ScanOutput, AdapterError> {
        if self.behaviour == Behaviour::Error {
            return Err(AdapterError::Crashed);
        }
        self.scans += 1;
        let nth = {
            let mut map = self.scans_per_text.lock().expect("lock");
            let n = map.entry(text.to_owned()).or_default();
            *n += 1;
            *n
        };
        let mut findings = if self.behaviour == Behaviour::Unstable && nth % 2 == 0 {
            Vec::new()
        } else {
            self.by_text.get(text).cloned().unwrap_or_default()
        };
        findings.sort();
        Ok(ScanOutput {
            findings,
            input_digest: Sha256Digest::of_bytes(text.as_bytes()),
            sanitized_output_digest: None,
            sanitized_output: None,
            skipped_findings: 0,
        })
    }

    fn finish(&mut self) -> SessionStats {
        SessionStats {
            scans: self.scans,
            stderr_bytes: 0,
            peak_rss_bytes: 0,
            pin_check: None,
        }
    }

    fn abort_handle(&self) -> AbortHandle {
        AbortHandle::inert()
    }
}

impl ScannerAdapter for FrozenAdapter {
    fn plan(&self, _configuration: ScannerConfiguration) -> Result<ScannerPlan, AdapterError> {
        Ok(self.plan.clone())
    }

    fn start(&self, plan: &ScannerPlan) -> Result<Box<dyn ScanSession>, StartFailure> {
        if *plan != self.plan {
            return Err(StartFailure {
                error: AdapterError::PinMismatch(pii_eval_adapters::error::PinKind::PlanIdentity),
                capabilities: undeclared(),
            });
        }
        match self.behaviour {
            Behaviour::Unsupported => {
                let mut caps = undeclared();
                caps.ranges = CapabilityState::Unsupported;
                caps.family_classification = CapabilityState::Unsupported;
                caps.sensitivity_classification = CapabilityState::Unsupported;
                caps.jurisdiction_reporting = CapabilityState::Unsupported;
                return Err(StartFailure {
                    error: AdapterError::MissingCapability(MissingCapability::SelectorUnsupported),
                    capabilities: caps,
                });
            }
            Behaviour::Unavailable => {
                return Err(StartFailure {
                    error: AdapterError::StartupFailure(StartupStage::Spawn),
                    capabilities: undeclared(),
                });
            }
            _ => {}
        }
        self.sessions.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(Session {
            capabilities: capabilities(),
            by_text: Arc::clone(&self.by_text),
            behaviour: self.behaviour,
            scans_per_text: Arc::clone(&self.scans_per_text),
            scans: 0,
            runtime: RuntimeRecord {
                scanner_version: "1.0.0".to_owned(),
                runtime_name: "frozen-observation".to_owned(),
                runtime_version: "v1".to_owned(),
                activation_identity: "frozen".to_owned(),
                activation_identity_digest: Sha256Digest::of_bytes(b"frozen"),
                offset_unit: OffsetUnit::Utf8Bytes,
                protocol: "pii-eval-adapter/1",
                shim_digest: Sha256Digest::of_bytes(b"shim"),
                artifact_digest: Sha256Digest::of_bytes(b"artifact"),
            },
        }))
    }
}

/// A revision-2 manifest over `snapshot` for `plans` (ascending by scanner id),
/// planning all seven methods and all ten metrics.
pub fn manifest(snapshot: &CorpusSnapshot, plans: Vec<ScannerPlan>, workers: u32) -> RunManifest {
    let mut methods: Vec<MethodRef> = pii_eval_contracts::METHODS
        .iter()
        .map(|m| MethodRef::frozen(m.id))
        .collect();
    methods.sort_by_key(|m| m.id.as_str());
    let mut metrics: Vec<MetricRef> = METRICS.iter().map(|m| MetricRef::frozen(m.id)).collect();
    metrics.sort_by_key(|m| m.id.as_str());
    let mut manifest = RunManifest::unsealed(RunManifestBody {
        engine: pii_eval_contracts::EngineIdentity {
            name: pii_eval_contracts::EngineName::PiiEval,
            version: pii_eval_contracts::VersionString::new(pii_eval_contracts::ENGINE_VERSION)
                .unwrap(),
        },
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
        mechanics: Mechanics::PII_V1,
        generation: snapshot.semantic.generation.clone(),
        limits: pii_eval_contracts::ExecutionLimits {
            workers,
            per_scanner_parallelism: workers.min(2),
            pending_tasks: 8,
            batch_variants: 2,
            scanner_timeout_ms: 120_000,
            max_stdout_bytes: 16 << 20,
            max_stderr_bytes: 1 << 20,
            max_memory_bytes: 16 << 30,
            max_temporary_bytes: 4 << 30,
        },
        scanners: plans,
    });
    seal(&mut manifest).expect("manifest seals");
    manifest
}

fn plan_of(name: &str, salt: i64) -> ScannerPlan {
    use pii_eval_contracts::{
        ActivationSelector, AdapterIdentity, ConfigKey, ConfigParameter, ConfigValue,
        ProductIdentity, ScannerId, ScannerIdentity, VersionString,
    };
    let configuration = ScannerConfiguration {
        parameters: vec![ConfigParameter {
            key: ConfigKey::new("contextWindow").unwrap(),
            value: ConfigValue::Integer(salt),
        }],
        activation: vec![
            ActivationSelector::new("pii:global").unwrap(),
            ActivationSelector::new("pii:us").unwrap(),
        ],
    };
    ScannerPlan {
        identity: ScannerIdentity {
            scanner_id: ScannerId::new(name).unwrap(),
            scanner_version: Some(VersionString::new("1.0.0").unwrap()),
            artifact_digest: Some(Sha256Digest::of_bytes(
                format!("artifact-{name}").as_bytes(),
            )),
            adapter: AdapterIdentity {
                adapter_id: ScannerId::new("frozen-adapter").unwrap(),
                adapter_version: VersionString::new("0.0.1").unwrap(),
                normalization_version: 1,
            },
            product: ProductIdentity::Released,
            configuration_digest: configuration.configuration_digest().unwrap(),
            activation_digest: configuration.activation_digest().unwrap(),
        },
        configuration,
    }
}

/// The scanners the engine path can run: complete scanners with valid ranges and
/// the four non-complete behaviours. (`parity-midchar` and `parity-badrange`
/// carry ranges that a real adapter's normalization rejects as malformed output
/// before matching; ADR 0011.)
pub fn engine_scanners(ds: &Dataset) -> Vec<(String, Behaviour)> {
    let mut scanners: Vec<(String, Behaviour)> = list(&ds.export, "scanners")
        .iter()
        .filter_map(|s| {
            let id = text(s, "id");
            let behaviour = match (id, text(s, "status")) {
                ("parity-midchar", _) | ("parity-badrange", _) => return None,
                (_, "complete") => Behaviour::Replay,
                (_, "unsupported") => Behaviour::Unsupported,
                (_, "unavailable") => Behaviour::Unavailable,
                (_, "error") => Behaviour::Error,
                (_, "unstable") => Behaviour::Unstable,
                (other, status) => panic!("scanner {other} status {status}"),
            };
            Some((id.to_owned(), behaviour))
        })
        .collect();
    // The manifest lists scanners ascending by id.
    scanners.sort_by(|a, b| a.0.cmp(&b.0));
    scanners
}

pub struct EngineRun {
    pub artifact: RunArtifact,
    /// Per scanner: its ten metrics as views.
    pub metrics: BTreeMap<String, Vec<(MetricId, MetricView)>>,
    pub statuses: BTreeMap<String, String>,
}

pub fn view_of_result(m: &MetricResult) -> MetricView {
    use pii_eval_contracts::{MetricValue, WithheldReason};
    let precision = 6u32;
    let scaled = |d: pii_eval_contracts::ScaledDecimal| {
        d.mantissa * 10u64.pow(precision - u32::from(d.scale))
    };
    MetricView {
        counts: m.counts,
        status: m.status,
        effective_n: m.effective_n,
        rate: match m.value {
            MetricValue::Withheld {
                reason: WithheldReason::ZeroDenominator,
            } => RateView::Null,
            MetricValue::Withheld {
                reason: WithheldReason::InsufficientEvidence,
            } => RateView::Insufficient,
            MetricValue::Measured { point, bound } => RateView::Value {
                point: scaled(point),
                bound: scaled(bound),
                n: m.effective_n,
            },
        },
    }
}

/// The snapshot, the manifest and one frozen adapter per engine scanner.
pub fn prepare(
    ds: &Dataset,
    rc: &RustCorpus,
) -> (CorpusSnapshot, RunManifest, Vec<Arc<dyn ScannerAdapter>>) {
    let snapshot = rc.snapshot();
    let scanners = engine_scanners(ds);
    // Texts must identify variants (the authored texts start with their case id).
    let mut seen = std::collections::BTreeSet::new();
    for v in &rc.variants {
        assert!(
            seen.insert(v.variant.text.clone()),
            "variant texts are unique"
        );
    }
    let mut adapters: Vec<Arc<dyn ScannerAdapter>> = Vec::new();
    let mut plans = Vec::new();
    for (i, (id, behaviour)) in scanners.iter().enumerate() {
        let export = list(&ds.export, "scanners")
            .iter()
            .find(|s| text(s, "id") == id)
            .unwrap();
        let findings = findings_of(export);
        let mut by_text = BTreeMap::new();
        for v in &rc.variants {
            if let Some(f) = findings.get(&v.key()) {
                by_text.insert(v.variant.text.clone(), f.clone());
            }
        }
        let plan = plan_of(id, i as i64 + 1);
        plans.push(plan.clone());
        adapters.push(Arc::new(FrozenAdapter {
            plan,
            behaviour: *behaviour,
            by_text: Arc::new(by_text),
            sessions: Arc::new(AtomicU64::new(0)),
            scans_per_text: Arc::new(Mutex::new(BTreeMap::new())),
        }));
    }
    // The manifest (and so the plan digest) is the same for every host setting; only the host cap varies.
    let manifest = manifest(&snapshot, plans, 4);
    // A refusal here is a defect of the parity data, so say why (reason codes only).
    pii_eval_contracts::validate(&snapshot)
        .unwrap_or_else(|e| panic!("the generated snapshot is invalid: {e:?}"));
    pii_eval_contracts::validate(&manifest)
        .unwrap_or_else(|e| panic!("the manifest is invalid: {e:?}"));
    pii_eval_contracts::validate_manifest_against_snapshot(&manifest, &snapshot)
        .unwrap_or_else(|e| panic!("the manifest does not bind to the snapshot: {e:?}"));
    (snapshot, manifest, adapters)
}

/// Run the engine over the frozen observations with `workers` workers.
pub fn run_engine(ds: &Dataset, rc: &RustCorpus, workers: u32) -> EngineRun {
    let (snapshot, manifest, adapters) = prepare(ds, rc);
    let output = run(
        &RunRequest {
            snapshot: &snapshot,
            manifest: &manifest,
            adapters,
        },
        &RunConfig {
            executor: ExecutorConfig {
                max_workers: workers.max(1) as usize,
                resources: ResourcePolicy::Unenforced,
                ..ExecutorConfig::default()
            },
            diagnostics: false,
            commit_cancelled: false,
        },
        &CancelToken::new(),
    )
    .unwrap_or_else(|e| panic!("the engine run failed: {e}"));
    let artifact = output.assembled.artifact;
    let mut metrics = BTreeMap::new();
    for sm in &artifact.semantic.scanner_metrics {
        let mut views: Vec<(MetricId, MetricView)> = sm
            .metrics
            .iter()
            .map(|m| (m.metric.id, view_of_result(m)))
            .collect();
        views.sort_by_key(|(m, _)| word(m));
        metrics.insert(sm.scanner_id.as_str().to_owned(), views);
    }
    let statuses = artifact
        .semantic
        .scanners
        .iter()
        .map(|s| (s.identity.scanner_id.as_str().to_owned(), word(&s.status)))
        .collect();
    EngineRun {
        artifact,
        metrics,
        statuses,
    }
}

pub fn unused(_: MethodId) {}

/// Run the engine like the CLI's `run` would and write its documents (manifest,
/// observation sets, run artifact, public artifact) and the snapshot to `dir`.
pub fn write_engine_run(
    ds: &Dataset,
    rc: &RustCorpus,
    workers: u32,
    dir: &std::path::Path,
) -> Vec<String> {
    use pii_eval_cli::run::run_and_write;
    use pii_eval_cli::write::{ArtifactWriter, OverwritePolicy};
    let (snapshot, manifest, adapters) = prepare(ds, rc);
    let writer = ArtifactWriter::new(dir, OverwritePolicy::Refuse).with_manifest();
    let (_, written) = run_and_write(
        &RunRequest {
            snapshot: &snapshot,
            manifest: &manifest,
            adapters,
        },
        &RunConfig {
            executor: ExecutorConfig {
                max_workers: workers.max(1) as usize,
                resources: ResourcePolicy::Unenforced,
                ..ExecutorConfig::default()
            },
            diagnostics: false,
            commit_cancelled: false,
        },
        &CancelToken::new(),
        &writer,
    )
    .unwrap_or_else(|e| panic!("the engine run failed: {e}"));
    std::fs::write(
        dir.join("snapshot.json"),
        pii_eval_contracts::to_pretty_json(&snapshot).unwrap(),
    )
    .unwrap();
    let _ = written;
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}
