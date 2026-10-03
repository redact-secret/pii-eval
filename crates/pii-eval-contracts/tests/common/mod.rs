//! Synthetic fixture builders shared by the contract tests.
//!
//! Everything here is synthetic: reserved `.invalid` addresses, a public test
//! card number, and a deliberately invalid-area SSN-shaped string. The metric
//! `bound` values are structural examples; they are not computed Wilson
//! endpoints (accounting arithmetic belongs to a later phase).
#![allow(dead_code)]

use std::path::PathBuf;

use pii_eval_contracts::*;

pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/contracts/v1")
}

pub fn schemas_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schemas")
}

pub fn update_requested(var: &str) -> bool {
    std::env::var(var).is_ok_and(|v| v == "1")
}

pub fn id(s: &str) -> Id {
    Id::new(s).unwrap()
}
pub fn sid(s: &str) -> ScannerId {
    ScannerId::new(s).unwrap()
}
pub fn fam(s: &str) -> FamilyId {
    FamilyId::new(s).unwrap()
}
pub fn ver(s: &str) -> VersionString {
    VersionString::new(s).unwrap()
}
pub fn lang(s: &str) -> LanguageTag {
    LanguageTag::new(s).unwrap()
}
pub fn jur(s: &str) -> JurisdictionCode {
    JurisdictionCode::new(s).unwrap()
}
pub fn digest_of(s: &str) -> Sha256Digest {
    Sha256Digest::of_bytes(s.as_bytes())
}

fn range_of(text: &str, needle: &str) -> ByteRange {
    let start = text.find(needle).expect("needle in text");
    ByteRange {
        start: start as u64,
        end: (start + needle.len()) as u64,
    }
}

#[allow(clippy::too_many_arguments)]
fn variant(
    variant_id: &str,
    derivation: Derivation,
    text: &str,
    needle: &str,
    family: &str,
    type_expectation: ExpectedType,
    sensitivity: SensitivityExpectation,
    context_class: ContextClass,
    validator: Option<ValidatorRef>,
) -> Variant {
    Variant {
        variant_id: id(variant_id),
        derivation,
        text: text.to_owned(),
        text_digest: Sha256Digest::of_bytes(text.as_bytes()),
        expectations: vec![Expectation {
            occurrence_id: id("occurrence-1"),
            range: range_of(text, needle),
            family: fam(family),
            type_expectation,
            validator,
            sensitivity,
            context_class,
            context_obligation: ContextObligation::None,
            action: ActionExpectation::Redact,
        }],
    }
}

fn authored() -> Derivation {
    Derivation {
        strategy: Strategy::Authored,
        operator: None,
        seed: None,
    }
}

fn lineage(name: &str) -> Lineage {
    Lineage {
        source_id: id(name),
        source_digest: digest_of(name),
    }
}

pub fn snapshot_body(visibility: Visibility) -> CorpusSnapshotBody {
    let mod10 = ValidatorRef {
        id: id("synthetic-mod10"),
        version: 1,
    };
    let case_collision = Case {
        case_id: id("collision-us-ssn-demo"),
        method: MethodId::JurisdictionCollision,
        lineage: lineage("synthetic-source-collision"),
        language: lang("en"),
        jurisdiction: Some(jur("US")),
        collision: Some(Collision {
            target_family: fam("pii:us:ssn"),
            competing_families: vec![fam("pii:global:phone")],
        }),
        variants: vec![variant(
            "collision-us-ssn-demo-authored",
            authored(),
            "reference 000-12-3456 synthetic sample",
            "000-12-3456",
            "pii:us:ssn",
            ExpectedType::Valid,
            SensitivityExpectation::Sensitive,
            ContextClass::Sensitive,
            None,
        )],
    };
    // Korean text: every needle sits after multi-byte characters.
    let email = "user@example.invalid";
    let case_context = Case {
        case_id: id("context-email-ko-demo"),
        method: MethodId::ContextDiscrimination,
        lineage: lineage("synthetic-source-context"),
        language: lang("ko"),
        jurisdiction: None,
        collision: None,
        variants: vec![
            variant(
                "context-email-ko-demo-neutral",
                authored(),
                &format!("예시 주소 {email} 참고"),
                email,
                "pii:global:email",
                ExpectedType::Valid,
                SensitivityExpectation::NotEstablished,
                ContextClass::Neutral,
                None,
            ),
            variant(
                "context-email-ko-demo-non-sensitive",
                authored(),
                &format!("문서 샘플 {email} 입니다"),
                email,
                "pii:global:email",
                ExpectedType::Valid,
                SensitivityExpectation::NonSensitive,
                ContextClass::NonSensitive,
                None,
            ),
            variant(
                "context-email-ko-demo-sensitive",
                authored(),
                &format!("연락처: {email} 로 회신 바랍니다"),
                email,
                "pii:global:email",
                ExpectedType::Valid,
                SensitivityExpectation::Sensitive,
                ContextClass::Sensitive,
                None,
            ),
        ],
    };
    let case_type = Case {
        case_id: id("type-card-demo"),
        method: MethodId::TypeValidation,
        lineage: lineage("synthetic-source-type"),
        language: lang("en"),
        jurisdiction: None,
        collision: None,
        variants: vec![
            variant(
                "type-card-demo-authored",
                authored(),
                "card 4111 1111 1111 1111 on file",
                "4111 1111 1111 1111",
                "pii:global:payment-card",
                ExpectedType::Valid,
                SensitivityExpectation::Sensitive,
                ContextClass::Sensitive,
                Some(mod10.clone()),
            ),
            variant(
                "type-card-demo-mutated",
                Derivation {
                    strategy: Strategy::Derived,
                    operator: Some(OperatorRef {
                        id: id("invalidate-final-digit"),
                        version: 1,
                    }),
                    seed: Some(Seed::new("seed-0001").unwrap()),
                },
                "card 4111 1111 1111 1112 on file",
                "4111 1111 1111 1112",
                "pii:global:payment-card",
                ExpectedType::Invalid,
                SensitivityExpectation::NonSensitive,
                ContextClass::NonSensitive,
                Some(mod10),
            ),
        ],
    };
    CorpusSnapshotBody {
        population: Population {
            population_id: id("synthetic-demo-population"),
            population_version: 1,
            visibility,
        },
        generation: GenerationRules {
            generator: id("synthetic-generator"),
            generator_version: 1,
            seed_derivation: Seed::new("seed-v1").unwrap(),
        },
        cases: vec![case_collision, case_context, case_type],
    }
}

pub fn sealed<D: Document>(mut doc: D) -> D {
    seal(&mut doc).unwrap();
    doc
}

pub fn config(extra: i64) -> ScannerConfiguration {
    ScannerConfiguration {
        parameters: vec![
            ConfigParameter {
                key: ConfigKey::new("contextWindow").unwrap(),
                value: ConfigValue::Integer(extra),
            },
            ConfigParameter {
                key: ConfigKey::new("mode").unwrap(),
                value: ConfigValue::Text("default".to_owned()),
            },
            ConfigParameter {
                key: ConfigKey::new("strict").unwrap(),
                value: ConfigValue::Bool(true),
            },
        ],
        activation: vec![
            ActivationSelector::new("pii:global").unwrap(),
            ActivationSelector::new("pii:us").unwrap(),
        ],
    }
}

pub fn scanner_identity(
    name: &str,
    product: ProductIdentity,
    version: Option<&str>,
    configuration: &ScannerConfiguration,
) -> ScannerIdentity {
    ScannerIdentity {
        scanner_id: sid(name),
        scanner_version: version.map(ver),
        artifact_digest: Some(digest_of(&format!("artifact-{name}"))),
        adapter: AdapterIdentity {
            adapter_id: sid("synthetic-adapter"),
            adapter_version: ver("0.1.0"),
            normalization_version: 1,
        },
        product,
        configuration_digest: configuration.configuration_digest().unwrap(),
        activation_digest: configuration.activation_digest().unwrap(),
    }
}

pub fn limits() -> ExecutionLimits {
    ExecutionLimits {
        workers: 4,
        per_scanner_parallelism: 2,
        pending_tasks: 64,
        batch_variants: 128,
        scanner_timeout_ms: 30_000,
        max_stdout_bytes: 1 << 20,
        max_stderr_bytes: 1 << 20,
        max_memory_bytes: 1 << 30,
        max_temporary_bytes: 1 << 28,
    }
}

pub fn engine() -> EngineIdentity {
    EngineIdentity {
        name: EngineName::PiiEval,
        version: ver("0.0.0"),
    }
}

fn run_class_of(visibility: Visibility) -> RunClass {
    match visibility {
        Visibility::PublicSynthetic => RunClass::PublicSynthetic,
        Visibility::Protected => RunClass::Protected,
    }
}

/// The complete synthetic fixture set.
pub struct Fixtures {
    pub snapshot: CorpusSnapshot,
    pub manifest: RunManifest,
    pub obs_alpha: ObservationSet,
    pub obs_beta: ObservationSet,
    pub artifact: RunArtifact,
}

fn alpha_capabilities() -> ScannerCapabilities {
    ScannerCapabilities {
        ranges: CapabilityState::Supported,
        family_classification: CapabilityState::Supported,
        sensitivity_classification: CapabilityState::Supported,
        jurisdiction_reporting: CapabilityState::Undeclared,
        action: ActionCapability::ReportedAction,
        families: vec![
            FamilyCapability {
                family: fam("pii:global:email"),
                state: CapabilityState::Supported,
            },
            FamilyCapability {
                family: fam("pii:global:payment-card"),
                state: CapabilityState::Supported,
            },
            FamilyCapability {
                family: fam("pii:us:ssn"),
                state: CapabilityState::Supported,
            },
        ],
        jurisdictions: vec![],
    }
}

fn beta_capabilities() -> ScannerCapabilities {
    ScannerCapabilities {
        ranges: CapabilityState::Unsupported,
        family_classification: CapabilityState::Unsupported,
        sensitivity_classification: CapabilityState::Unsupported,
        jurisdiction_reporting: CapabilityState::Unsupported,
        action: ActionCapability::Unavailable,
        families: vec![],
        jurisdictions: vec![],
    }
}

fn metric(
    id: MetricId,
    counts: (u64, u64, u64, u64, u64, u64),
    value: MetricValue,
) -> MetricResult {
    let (eligible, measured, numerator, unresolved, not_measured, not_applicable) = counts;
    let c = MetricCounts {
        eligible,
        measured,
        numerator,
        unresolved,
        not_measured,
        not_applicable,
        total: eligible + not_applicable,
    };
    let definition = id.definition();
    MetricResult {
        metric: MetricRef::frozen(id),
        status: c.derived_status(),
        counts: c,
        effective_n: if definition.effective_n == EffectiveNBasis::Eligible {
            eligible
        } else {
            measured
        },
        value,
    }
}

fn measured_value(numerator: u64, n: u64) -> MetricValue {
    let point = ScaledDecimal::new(numerator * 1_000_000 / n, 6).unwrap();
    MetricValue::Measured {
        point,
        bound: ScaledDecimal::new(500_000, 6).unwrap(),
    }
}

pub fn metrics() -> Vec<MetricResult> {
    let mut out: Vec<MetricResult> = METRICS
        .iter()
        .map(|d| {
            let counts = (5, 4, 1, 1, 0, 1);
            match d.id {
                MetricId::WrongJurisdictionRate => metric(
                    d.id,
                    (0, 0, 0, 0, 0, 6),
                    MetricValue::Withheld {
                        reason: WithheldReason::ZeroDenominator,
                    },
                ),
                MetricId::JurisdictionCollisionRate => metric(
                    d.id,
                    (2, 2, 1, 0, 0, 4),
                    MetricValue::Withheld {
                        reason: WithheldReason::InsufficientEvidence,
                    },
                ),
                MetricId::MeasurableShare => metric(d.id, counts, measured_value(1, 5)),
                _ => metric(d.id, counts, measured_value(1, 4)),
            }
        })
        .collect();
    out.sort_by_key(|m| m.metric.id.as_str());
    out
}

fn alpha_observation(snapshot: &CorpusSnapshot) -> Vec<InputObservation> {
    let mut inputs = Vec::new();
    for case in &snapshot.semantic.cases {
        for v in &case.variants {
            let e = &v.expectations[0];
            let mut findings = Vec::new();
            // One scanner miss: the invalid mutated card is not flagged.
            if e.type_expectation == ExpectedType::Valid {
                let mut range = e.range;
                if v.variant_id.as_str() == "type-card-demo-authored" {
                    // Overbroad by one trailing ASCII byte.
                    range.end += 1;
                }
                findings.push(Finding {
                    range,
                    family: Some(e.family.clone()),
                    jurisdiction: None,
                    sensitive: Some(e.sensitivity == SensitivityExpectation::Sensitive),
                    action: Some(ActionKind::Redact),
                });
            }
            inputs.push(InputObservation {
                variant_id: v.variant_id.clone(),
                input_digest: v.text_digest.clone(),
                sanitized_output_digest: None,
                findings,
            });
        }
    }
    inputs.sort_by(|a, b| a.variant_id.cmp(&b.variant_id));
    inputs
}

impl Fixtures {
    pub fn build(visibility: Visibility, alpha_product: ProductIdentity) -> Fixtures {
        let snapshot = sealed(CorpusSnapshot::unsealed(snapshot_body(visibility)));
        let alpha_cfg = config(5);
        let beta_cfg = config(3);
        let alpha_version = match alpha_product {
            ProductIdentity::Released => Some("1.0.0"),
            ProductIdentity::Candidate { .. } => Some("1.1.0-rc.1"),
        };
        let alpha_id = scanner_identity("alpha-scan", alpha_product, alpha_version, &alpha_cfg);
        let beta_id = scanner_identity(
            "beta-scan",
            ProductIdentity::Candidate {
                candidate_digest: digest_of("beta-candidate"),
            },
            None,
            &beta_cfg,
        );
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
        let mut metric_refs: Vec<MetricRef> =
            METRICS.iter().map(|m| MetricRef::frozen(m.id)).collect();
        metric_refs.sort_by_key(|m| m.id.as_str());
        let manifest = sealed(RunManifest::unsealed(RunManifestBody {
            engine: engine(),
            protocol: ProtocolIdentity::CURRENT,
            run_class: run_class_of(visibility),
            population: PopulationBinding {
                population_id: snapshot.semantic.population.population_id.clone(),
                visibility,
                population_version: 1,
                population_digest: snapshot.semantic_digest.clone(),
            },
            scope: Scope {
                languages: vec![lang("en"), lang("ko")],
                jurisdictions: vec![jur("US")],
            },
            methods,
            metrics: metric_refs,
            mechanics: Mechanics::PII_V1,
            generation: snapshot.semantic.generation.clone(),
            limits: limits(),
            scanners: vec![
                ScannerPlan {
                    identity: alpha_id.clone(),
                    configuration: alpha_cfg,
                },
                ScannerPlan {
                    identity: beta_id.clone(),
                    configuration: beta_cfg,
                },
            ],
        }));
        let replays = ReplayRecord {
            count: 2,
            agreed: true,
        };
        let mut alpha_body = ObservationSetBody {
            engine: engine(),
            protocol: ProtocolIdentity::CURRENT,
            population_digest: snapshot.semantic_digest.clone(),
            scanner: alpha_id.clone(),
            status: ScannerStatus::Complete,
            capabilities: alpha_capabilities(),
            replays,
            inputs: vec![],
        };
        alpha_body.inputs = alpha_observation(&snapshot);
        let mut obs_alpha = ObservationSet::unsealed(alpha_body);
        obs_alpha.diagnostics = Some(ObservationDiagnostics {
            started_at: TimestampUtc::new("2026-10-02T09:00:00.000Z").unwrap(),
            finished_at: TimestampUtc::new("2026-10-02T09:00:01.250Z").unwrap(),
            duration_ms: 1250,
        });
        let obs_alpha = sealed(obs_alpha);
        let obs_beta = sealed(ObservationSet::unsealed(ObservationSetBody {
            engine: engine(),
            protocol: ProtocolIdentity::CURRENT,
            population_digest: snapshot.semantic_digest.clone(),
            scanner: beta_id.clone(),
            status: ScannerStatus::Unsupported,
            capabilities: beta_capabilities(),
            replays,
            inputs: vec![],
        }));

        // Outcomes: alpha measured, beta not measured (unsupported).
        let mut outcomes = Vec::new();
        for (scanner, measured) in [("alpha-scan", true), ("beta-scan", false)] {
            for case in &snapshot.semantic.cases {
                for v in &case.variants {
                    let e = &v.expectations[0];
                    let (type_identity, sensitivity_context, range, action) = if !measured {
                        (
                            TypeState::NotMeasured,
                            SensitivityState::NotMeasured,
                            RangeState::NotApplicable,
                            ActionOutcome::NotMeasured,
                        )
                    } else if e.type_expectation == ExpectedType::Invalid {
                        (
                            TypeState::InvalidCorrect,
                            SensitivityState::Correct,
                            RangeState::Miss,
                            ActionOutcome::NoActionReported,
                        )
                    } else {
                        (
                            TypeState::Correct,
                            if e.sensitivity == SensitivityExpectation::NotEstablished {
                                SensitivityState::Unresolved
                            } else {
                                SensitivityState::Correct
                            },
                            if v.variant_id.as_str() == "type-card-demo-authored" {
                                RangeState::Overbroad
                            } else {
                                RangeState::Exact
                            },
                            ActionOutcome::Reported {
                                action: ActionKind::Redact,
                            },
                        )
                    };
                    outcomes.push(CaseOutcome {
                        scanner_id: sid(scanner),
                        case_id: case.case_id.clone(),
                        variant_id: v.variant_id.clone(),
                        occurrence_id: e.occurrence_id.clone(),
                        method: case.method,
                        type_identity,
                        sensitivity_context,
                        range,
                        action,
                        observed: ObservedSummary {
                            finding_count: u64::from(
                                measured && e.type_expectation == ExpectedType::Valid,
                            ),
                            families: if measured && e.type_expectation == ExpectedType::Valid {
                                vec![e.family.clone()]
                            } else {
                                vec![]
                            },
                            jurisdictions: vec![],
                        },
                    });
                }
            }
        }
        let mut coverage = vec![
            MethodCoverage {
                method: MethodRef::frozen(MethodId::ContextDiscrimination),
                cases: 1,
                variants: 3,
            },
            MethodCoverage {
                method: MethodRef::frozen(MethodId::JurisdictionCollision),
                cases: 1,
                variants: 1,
            },
            MethodCoverage {
                method: MethodRef::frozen(MethodId::TypeValidation),
                cases: 1,
                variants: 2,
            },
        ];
        coverage.sort_by_key(|c| c.method.id.as_str());
        let mut artifact = RunArtifact::unsealed(RunArtifactBody {
            engine: engine(),
            protocol: ProtocolIdentity::CURRENT,
            run_class: run_class_of(visibility),
            manifest_digest: manifest.semantic_digest.clone(),
            population: manifest.semantic.population.clone(),
            mechanics: Mechanics::PII_V1,
            population_counts: PopulationCounts {
                authored_cases: 3,
                variants: 6,
                occurrences: 6,
            },
            scanners: vec![
                ArtifactScanner {
                    identity: alpha_id,
                    status: ScannerStatus::Complete,
                    capabilities: alpha_capabilities(),
                    replays,
                    observation_digest: obs_alpha.semantic_digest.clone(),
                },
                ArtifactScanner {
                    identity: beta_id,
                    status: ScannerStatus::Unsupported,
                    capabilities: beta_capabilities(),
                    replays,
                    observation_digest: obs_beta.semantic_digest.clone(),
                },
            ],
            method_coverage: coverage,
            outcomes,
            metrics: metrics(),
            failures: vec![MeasurementFailure {
                scanner_id: sid("beta-scan"),
                code: FailureCode::Unsupported,
                affected_inputs: 6,
            }],
            completeness: Completeness::Complete,
        });
        artifact.diagnostics = Some(RunDiagnostics {
            started_at: TimestampUtc::new("2026-10-02T09:00:00.000Z").unwrap(),
            finished_at: TimestampUtc::new("2026-10-02T09:00:02.000Z").unwrap(),
            duration_ms: 2000,
            phases: vec![
                PhaseTiming {
                    phase: Phase::Scan,
                    duration_ms: 1250,
                },
                PhaseTiming {
                    phase: Phase::Total,
                    duration_ms: 2000,
                },
            ],
        });
        let artifact = sealed(artifact);
        Fixtures {
            snapshot,
            manifest,
            obs_alpha,
            obs_beta,
            artifact,
        }
    }

    pub fn default_public() -> Fixtures {
        Fixtures::build(Visibility::PublicSynthetic, ProductIdentity::Released)
    }
}
