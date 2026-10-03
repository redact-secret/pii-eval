//! Negative golden fixtures and rejection probes.
//!
//! Every probe states the stable reason code it must produce. Probes backed by
//! a document are committed under `fixtures/contracts/negative/` and checked
//! for drift; cross-document probes run in code. A final test requires every
//! reason code to be exercised by some probe (or by a named unit test).
//!
//! Regenerate with
//! `PII_EVAL_UPDATE_FIXTURES=1 cargo test -p pii-eval-contracts --test negative`.

mod common;

use std::collections::BTreeSet;

use common::*;
use pii_eval_contracts::*;

struct Probe {
    name: String,
    expected: ReasonCode,
    outcome: Result<(), Violations>,
    /// Committed document: (kind to parse it as, bytes).
    file: Option<(DocumentKind, Vec<u8>)>,
}

fn parse_kind(kind: DocumentKind, bytes: &[u8]) -> Result<(), Violations> {
    match kind {
        DocumentKind::CorpusSnapshot => parse_default::<CorpusSnapshot>(bytes).map(|_| ()),
        DocumentKind::RunManifest => parse_default::<RunManifest>(bytes).map(|_| ()),
        DocumentKind::ObservationSet => parse_default::<ObservationSet>(bytes).map(|_| ()),
        DocumentKind::RunArtifact => parse_default::<RunArtifact>(bytes).map(|_| ()),
        DocumentKind::PublicSyntheticArtifact => {
            parse_default::<PublicSyntheticArtifact>(bytes).map(|_| ())
        }
    }
}

fn replace_once(text: &str, from: &str, to: &str) -> String {
    assert_eq!(
        text.matches(from).count(),
        1,
        "mutation anchor must be unique"
    );
    text.replacen(from, to, 1)
}

fn doc_probe(kind: DocumentKind, label: &str, expected: ReasonCode, bytes: Vec<u8>) -> Probe {
    Probe {
        name: format!(
            "{}__{}__{label}",
            kind.schema_file_stem(),
            expected.as_str()
        ),
        expected,
        outcome: parse_kind(kind, &bytes),
        file: Some((kind, bytes)),
    }
}

fn typed<D: Document + Clone>(doc: &D, change: impl FnOnce(&mut D)) -> D {
    let mut d = doc.clone();
    change(&mut d);
    seal(&mut d).unwrap();
    d
}

fn probes() -> Vec<Probe> {
    let (k_snap, k_man, k_obs, k_art, k_pub) = (
        DocumentKind::CorpusSnapshot,
        DocumentKind::RunManifest,
        DocumentKind::ObservationSet,
        DocumentKind::RunArtifact,
        DocumentKind::PublicSyntheticArtifact,
    );
    let f = Fixtures::default_public();
    let mut out = Vec::new();

    // ---- Parse-level and envelope probes (raw text mutations). ----
    let snap = to_pretty_json(&f.snapshot).unwrap();
    let man = to_pretty_json(&f.manifest).unwrap();
    let obs_beta = to_pretty_json(&f.obs_beta).unwrap();
    let art = serialize_internal(&f.artifact).unwrap();
    let public = serialize_public_synthetic(&f.artifact.to_public_synthetic().unwrap()).unwrap();
    let schema_line = "\"schema\": \"pii-eval.corpus-snapshot\",";
    let version_line = "\"schemaVersion\": \"1.0\",";

    let mut raw = |kind, label: &str, code, text: String| {
        out.push(doc_probe(kind, label, code, text.into_bytes()))
    };
    raw(
        k_snap,
        "repeated-schema",
        ReasonCode::DuplicateKey,
        replace_once(
            &snap,
            schema_line,
            &format!("{schema_line}\n  {schema_line}"),
        ),
    );
    raw(
        k_snap,
        "null-jurisdiction",
        ReasonCode::NullNotAllowed,
        replace_once(&snap, "\"jurisdiction\": \"US\"", "\"jurisdiction\": null"),
    );
    raw(
        k_obs,
        "null-optional-field",
        ReasonCode::NullNotAllowed,
        replace_once(
            &obs_beta,
            "\"scannerId\": \"beta-scan\"",
            "\"scannerId\": \"beta-scan\",\n      \"scannerVersion\": null",
        ),
    );
    raw(
        k_man,
        "negative-zero",
        ReasonCode::FloatNotAllowed,
        replace_once(&man, "\"workers\": 4", "\"workers\": -0"),
    );
    raw(
        k_man,
        "decimal-point-integer",
        ReasonCode::FloatNotAllowed,
        replace_once(&man, "\"workers\": 4", "\"workers\": 4.0"),
    );
    raw(
        k_man,
        "exponent-integer",
        ReasonCode::FloatNotAllowed,
        replace_once(&man, "\"workers\": 4", "\"workers\": 4e0"),
    );
    raw(
        k_man,
        "beyond-safe-integer",
        ReasonCode::IntegerOutOfRange,
        replace_once(
            &man,
            "\"maxMemoryBytes\": 1073741824",
            "\"maxMemoryBytes\": 9007199254740992",
        ),
    );
    raw(
        k_snap,
        "truncated",
        ReasonCode::MalformedJson,
        snap[..snap.len() / 2].to_owned(),
    );
    raw(
        k_snap,
        "trailing-garbage",
        ReasonCode::MalformedJson,
        format!("{snap}x"),
    );
    raw(
        k_snap,
        "unknown-schema",
        ReasonCode::UnknownSchema,
        replace_once(
            &snap,
            schema_line,
            "\"schema\": \"pii-eval.something-else\",",
        ),
    );
    raw(
        k_snap,
        "missing-schema",
        ReasonCode::MissingSchema,
        replace_once(&snap, &format!("  {schema_line}\n"), ""),
    );
    raw(
        k_man,
        "snapshot-given-as-manifest",
        ReasonCode::SchemaKindMismatch,
        snap.clone(),
    );
    raw(
        k_snap,
        "version-word",
        ReasonCode::MalformedSchemaVersion,
        replace_once(&snap, version_line, "\"schemaVersion\": \"one\","),
    );
    raw(
        k_snap,
        "major-2",
        ReasonCode::IncompatibleSchemaMajor,
        replace_once(&snap, version_line, "\"schemaVersion\": \"2.0\","),
    );
    raw(
        k_snap,
        "major-0",
        ReasonCode::IncompatibleSchemaMajor,
        replace_once(&snap, version_line, "\"schemaVersion\": \"0.9\","),
    );
    raw(
        k_snap,
        "minor-newer-than-reader",
        ReasonCode::SchemaMinorTooNew,
        // 1.1 is readable since P7 (ADR 0008); 1.2 is the first newer minor.
        replace_once(&snap, version_line, "\"schemaVersion\": \"1.2\","),
    );
    raw(
        k_snap,
        "array-root",
        ReasonCode::NotAnObject,
        "[]".to_owned(),
    );
    raw(
        k_snap,
        "unknown-field",
        ReasonCode::SchemaViolation,
        replace_once(
            &snap,
            version_line,
            &format!("{version_line}\n  \"extra\": 1,"),
        ),
    );
    raw(
        k_snap,
        "unknown-enum-value",
        ReasonCode::SchemaViolation,
        replace_once(
            &snap,
            "\"visibility\": \"public-synthetic\"",
            "\"visibility\": \"public\"",
        ),
    );
    raw(
        k_snap,
        "bad-case-id",
        ReasonCode::InvalidIdentifier,
        replace_once(
            &snap,
            "\"caseId\": \"context-email-ko-demo\"",
            "\"caseId\": \"Context Email\"",
        ),
    );
    raw(
        k_snap,
        "too-deep",
        ReasonCode::NestingTooDeep,
        "[".repeat(200),
    );
    // A protected run class cannot even be expressed in a public-synthetic artifact.
    raw(
        k_pub,
        "protected-run-class",
        ReasonCode::SchemaViolation,
        replace_once(
            &public,
            "\"runClass\": \"public-synthetic\"",
            "\"runClass\": \"protected\"",
        ),
    );
    raw(
        k_pub,
        "extra-internal-field",
        ReasonCode::SchemaViolation,
        replace_once(
            &public,
            version_line,
            &format!("{version_line}\n  \"diagnostics\": {{}},"),
        ),
    );
    raw(
        k_art,
        "tampered-digest",
        ReasonCode::SemanticDigestMismatch,
        replace_once(
            &art,
            &format!("\"semanticDigest\": \"{}\"", f.artifact.semantic_digest),
            &format!("\"semanticDigest\": \"{}\"", "0".repeat(64)),
        ),
    );
    raw(
        k_art,
        "tampered-body",
        ReasonCode::SemanticDigestMismatch,
        replace_once(&art, "\"affectedInputs\": 6", "\"affectedInputs\": 7"),
    );

    // Internally tagged enums must reject extra keys (serde ignores them on unit variants).
    let first_replace = |text: &str, from: &str, to: &str| {
        assert!(text.contains(from), "mutation anchor must exist");
        text.replacen(from, to, 1)
    };
    let digest64 = "a".repeat(64);
    raw(
        k_man,
        "released-product-with-candidate-digest",
        ReasonCode::SchemaViolation,
        replace_once(
            &man,
            "\"kind\": \"released\"",
            &format!("\"kind\": \"released\",\n          \"candidateDigest\": \"{digest64}\""),
        ),
    );
    raw(
        k_man,
        "candidate-product-with-unknown-key",
        ReasonCode::SchemaViolation,
        replace_once(
            &man,
            "\"kind\": \"candidate\"",
            "\"kind\": \"candidate\",\n          \"junk\": 1",
        ),
    );
    raw(
        k_art,
        "not-measured-action-with-unknown-key",
        ReasonCode::SchemaViolation,
        first_replace(
            &art,
            "\"state\": \"not-measured\"",
            "\"state\": \"not-measured\",\n        \"junk\": 1",
        ),
    );
    raw(
        k_art,
        "no-action-reported-with-unknown-key",
        ReasonCode::SchemaViolation,
        first_replace(
            &art,
            "\"state\": \"no-action-reported\"",
            "\"state\": \"no-action-reported\",\n        \"junk\": 1",
        ),
    );
    // A hostile key spelled like an internal sentinel must not choose the reason code.
    raw(
        k_snap,
        "unknown-key-spelled-like-a-sentinel",
        ReasonCode::SchemaViolation,
        replace_once(
            &snap,
            version_line,
            &format!(
                "{version_line}\n  \"pii-eval:null\": 1,\n  \"pii-eval:invalid-identifier\": 1,"
            ),
        ),
    );

    // ---- Typed mutations of the corpus snapshot (re-sealed). ----
    let mut snap_probe = |label: &str, code, change: &dyn Fn(&mut CorpusSnapshotBody)| {
        let doc = typed(&f.snapshot, |d| change(&mut d.semantic));
        out.push(doc_probe(
            k_snap,
            label,
            code,
            to_pretty_json(&doc).unwrap().into_bytes(),
        ));
    };
    snap_probe("empty-range", ReasonCode::RangeInvalid, &|b| {
        let r = &mut b.cases[2].variants[0].expectations[0].range;
        r.end = r.start;
    });
    snap_probe("inverted-range", ReasonCode::RangeInvalid, &|b| {
        let r = &mut b.cases[2].variants[0].expectations[0].range;
        std::mem::swap(&mut r.start, &mut r.end);
    });
    snap_probe("end-past-text", ReasonCode::RangeOutOfBounds, &|b| {
        b.cases[2].variants[0].expectations[0].range.end = 10_000;
    });
    snap_probe(
        "inside-korean-character",
        ReasonCode::RangeNotOnCharBoundary,
        &|b| {
            // The Korean prefix is multi-byte: byte 1 is inside the first character.
            let r = &mut b.cases[1].variants[0].expectations[0].range;
            r.start = 1;
        },
    );
    snap_probe(
        "text-changed-digest-kept",
        ReasonCode::TextDigestMismatch,
        &|b| {
            b.cases[2].variants[0].text.push('!');
        },
    );
    snap_probe(
        "variant-id-repeated-across-cases",
        ReasonCode::DuplicateIdentity,
        &|b| {
            b.cases[2].variants[0].variant_id = id("collision-us-ssn-demo-authored");
        },
    );
    snap_probe("case-repeated", ReasonCode::DuplicateIdentity, &|b| {
        let dup = b.cases[0].clone();
        b.cases.insert(1, dup);
    });
    snap_probe("cases-unsorted", ReasonCode::NonCanonicalOrder, &|b| {
        b.cases.swap(0, 2)
    });
    snap_probe(
        "trio-missing-a-frame",
        ReasonCode::IncompleteContextTrio,
        &|b| {
            b.cases[1].variants.pop();
        },
    );
    snap_probe(
        "collision-declaration-missing",
        ReasonCode::CollisionInvalid,
        &|b| {
            b.cases[0].collision = None;
        },
    );
    snap_probe(
        "family-scope-vs-jurisdiction",
        ReasonCode::FamilyScopeMismatch,
        &|b| {
            b.cases[0].jurisdiction = Some(jur("KR"));
        },
    );
    snap_probe(
        "authored-with-operator",
        ReasonCode::DerivationInvalid,
        &|b| {
            b.cases[2].variants[0].derivation.operator = Some(OperatorRef {
                id: id("some-operator"),
                version: 1,
            });
        },
    );
    snap_probe("no-cases", ReasonCode::EmptyCollection, &|b| {
        b.cases.clear()
    });
    snap_probe(
        "variant-expectations-disagree-on-context-class",
        ReasonCode::ContextClassConflict,
        &|b| {
            let mut second = b.cases[2].variants[0].expectations[0].clone();
            second.occurrence_id = id("occurrence-2");
            second.context_class = ContextClass::Neutral;
            b.cases[2].variants[0].expectations.push(second);
        },
    );

    // ---- Typed mutations of the manifest. ----
    let mut man_probe = |label: &str, code, change: &dyn Fn(&mut RunManifestBody)| {
        let doc = typed(&f.manifest, |d| change(&mut d.semantic));
        out.push(doc_probe(
            k_man,
            label,
            code,
            to_pretty_json(&doc).unwrap().into_bytes(),
        ));
    };
    man_probe(
        "method-version-drift",
        ReasonCode::ProtocolBindingMismatch,
        &|b| b.methods[2].version = 1,
    );
    man_probe(
        "protocol-revision-2",
        ReasonCode::ProtocolBindingMismatch,
        &|b| b.protocol.version = 2,
    );
    man_probe("zero-workers", ReasonCode::LimitsInvalid, &|b| {
        b.limits.workers = 0
    });
    man_probe("unbounded-timeout", ReasonCode::LimitsInvalid, &|b| {
        b.limits.scanner_timeout_ms = 10_000_000
    });
    man_probe("zero-min-denominator", ReasonCode::MechanicsInvalid, &|b| {
        b.mechanics.min_denominator = 0
    });
    man_probe(
        "configuration-changed-identity-kept",
        ReasonCode::ConfigurationDigestMismatch,
        &|b| {
            b.scanners[0].configuration.parameters[0].value = ConfigValue::Integer(99);
        },
    );
    man_probe(
        "released-without-version",
        ReasonCode::ProductIdentityInvalid,
        &|b| {
            b.scanners[0].identity.scanner_version = None;
        },
    );
    man_probe("scanners-unsorted", ReasonCode::NonCanonicalOrder, &|b| {
        b.scanners.swap(0, 1)
    });
    man_probe("scanner-repeated", ReasonCode::DuplicateIdentity, &|b| {
        let dup = b.scanners[0].clone();
        b.scanners.insert(1, dup);
    });
    man_probe("no-scanners", ReasonCode::EmptyCollection, &|b| {
        b.scanners.clear()
    });
    man_probe(
        "population-visibility-contradicts-run-class",
        ReasonCode::RunClassMismatch,
        &|b| b.population.visibility = Visibility::Protected,
    );
    man_probe(
        "context-metric-without-its-method",
        ReasonCode::ProtocolBindingMismatch,
        &|b| {
            b.methods
                .retain(|m| m.id != MethodId::ContextDiscrimination)
        },
    );
    man_probe(
        "collision-metric-without-its-method",
        ReasonCode::ProtocolBindingMismatch,
        &|b| {
            b.methods
                .retain(|m| m.id != MethodId::JurisdictionCollision)
        },
    );

    // ---- Typed mutations of observation sets. ----
    let mut obs_probe = |label: &str, code, change: &dyn Fn(&mut ObservationSetBody)| {
        let doc = typed(&f.obs_alpha, |d| change(&mut d.semantic));
        out.push(doc_probe(
            k_obs,
            label,
            code,
            to_pretty_json(&doc).unwrap().into_bytes(),
        ));
    };
    obs_probe(
        "complete-but-replays-disagree",
        ReasonCode::StatusInconsistent,
        &|b| b.replays.agreed = false,
    );
    obs_probe(
        "unsupported-status-with-inputs",
        ReasonCode::StatusInconsistent,
        &|b| {
            b.status = ScannerStatus::Unsupported;
        },
    );
    obs_probe(
        "action-reported-without-capability",
        ReasonCode::CapabilityContradiction,
        &|b| {
            b.capabilities.action = ActionCapability::Unavailable;
        },
    );
    obs_probe(
        "family-reported-for-unsupported-family",
        ReasonCode::CapabilityContradiction,
        &|b| {
            b.capabilities.families[0].state = CapabilityState::Unsupported;
        },
    );
    obs_probe("empty-finding-range", ReasonCode::RangeInvalid, &|b| {
        let r = &mut b.inputs[0].findings[0].range;
        r.end = r.start;
    });
    obs_probe("findings-unsorted", ReasonCode::NonCanonicalOrder, &|b| {
        let first = b.inputs[0].findings[0].clone();
        let mut later = first.clone();
        later.range.start += 1;
        later.range.end += 2;
        b.inputs[0].findings = vec![later, first];
    });
    obs_probe("input-repeated", ReasonCode::DuplicateIdentity, &|b| {
        let dup = b.inputs[0].clone();
        b.inputs.insert(1, dup);
    });
    obs_probe(
        "protocol-revision-2",
        ReasonCode::ProtocolBindingMismatch,
        &|b| b.protocol.version = 2,
    );

    // Findings sort by the wire string of the action: other < preserve < redact.
    obs_probe(
        "findings-sorted-by-enum-order-not-wire-order",
        ReasonCode::NonCanonicalOrder,
        &|b| {
            let redact = b.inputs[0].findings[0].clone();
            let mut preserve = redact.clone();
            preserve.action = Some(ActionKind::Preserve);
            b.inputs[0].findings = vec![redact, preserve];
        },
    );

    // ---- Typed mutations of the internal artifact. ----
    let mut art_probe = |label: &str, code, change: &dyn Fn(&mut RunArtifactBody)| {
        let doc = typed(&f.artifact, |d| change(&mut d.semantic));
        out.push(doc_probe(
            k_art,
            label,
            code,
            serialize_internal(&doc).unwrap().into_bytes(),
        ));
    };
    art_probe(
        "unsupported-scanner-with-measured-axis",
        ReasonCode::OutcomeContradiction,
        &|b| {
            let row = b
                .outcomes
                .iter_mut()
                .find(|o| o.scanner_id.as_str() == "beta-scan")
                .unwrap();
            row.type_identity = TypeState::Correct;
        },
    );
    art_probe(
        "action-verified-without-sanitized-output",
        ReasonCode::OutcomeContradiction,
        &|b| {
            let row = b
                .outcomes
                .iter_mut()
                .find(|o| o.scanner_id.as_str() == "alpha-scan")
                .unwrap();
            row.action = ActionOutcome::OutputVerified {
                verification: OutputVerification::Removed,
            };
        },
    );
    art_probe(
        "counts-do-not-add-up",
        ReasonCode::MetricCountsInconsistent,
        &|b| b.metrics[0].counts.total += 1,
    );
    art_probe(
        "status-contradicts-counts",
        ReasonCode::MetricCountsInconsistent,
        &|b| {
            b.metrics[0].status = MetricStatus::Measured;
        },
    );
    art_probe(
        "effective-n-not-measured-count",
        ReasonCode::MetricCountsInconsistent,
        &|b| b.metrics[0].effective_n += 1,
    );
    art_probe(
        "value-published-below-min-denominator",
        ReasonCode::MetricValueInconsistent,
        &|b| {
            let m = b
                .metrics
                .iter_mut()
                .find(|m| m.metric.id == MetricId::JurisdictionCollisionRate)
                .unwrap();
            m.value = MetricValue::Measured {
                point: ScaledDecimal::new(5, 1).unwrap(),
                bound: ScaledDecimal::new(6, 1).unwrap(),
            };
        },
    );
    art_probe(
        "rate-above-one",
        ReasonCode::MetricValueInconsistent,
        &|b| {
            b.metrics[0].value = MetricValue::Measured {
                point: ScaledDecimal::new(15, 1).unwrap(),
                bound: ScaledDecimal::new(2, 0).unwrap(),
            };
        },
    );
    art_probe("denormalized-decimal", ReasonCode::DecimalInvalid, &|b| {
        b.metrics[0].value = MetricValue::Measured {
            point: ScaledDecimal {
                mantissa: 250,
                scale: 3,
            },
            bound: ScaledDecimal::new(5, 1).unwrap(),
        };
    });
    art_probe(
        "metric-version-drift",
        ReasonCode::MetricDefinitionMismatch,
        &|b| b.metrics[0].metric.version = 2,
    );
    art_probe("authored-count-wrong", ReasonCode::CountMismatch, &|b| {
        b.population_counts.authored_cases = 4
    });
    art_probe(
        "complete-with-missing-row",
        ReasonCode::ObservationIncomplete,
        &|b| {
            b.outcomes.pop();
        },
    );
    art_probe(
        "failure-for-unknown-scanner",
        ReasonCode::UnknownScanner,
        &|b| {
            b.failures.push(MeasurementFailure {
                scanner_id: sid("zeta-scan"),
                code: FailureCode::Timeout,
                affected_inputs: 1,
            });
        },
    );
    art_probe("outcomes-unsorted", ReasonCode::NonCanonicalOrder, &|b| {
        b.outcomes.swap(0, 1)
    });
    art_probe("outcome-repeated", ReasonCode::DuplicateIdentity, &|b| {
        let dup = b.outcomes[0].clone();
        b.outcomes[1] = dup;
    });
    // Capability-aware outcome rules: an unsupported capability is never measured.
    art_probe(
        "sensitivity-measured-though-unsupported",
        ReasonCode::OutcomeContradiction,
        &|b| b.scanners[0].capabilities.sensitivity_classification = CapabilityState::Unsupported,
    );
    art_probe(
        "type-measured-though-family-unsupported",
        ReasonCode::OutcomeContradiction,
        &|b| b.scanners[0].capabilities.family_classification = CapabilityState::Unsupported,
    );
    art_probe(
        "complete-scanner-without-range-support",
        ReasonCode::StatusInconsistent,
        &|b| b.scanners[0].capabilities.ranges = CapabilityState::Unsupported,
    );
    art_probe(
        "complete-scanner-with-disagreeing-replays",
        ReasonCode::StatusInconsistent,
        &|b| b.scanners[0].replays.agreed = false,
    );
    // Failures must agree with scanner status.
    art_probe(
        "complete-scanner-with-timeout-failure",
        ReasonCode::StatusInconsistent,
        &|b| {
            b.failures.insert(
                0,
                MeasurementFailure {
                    scanner_id: sid("alpha-scan"),
                    code: FailureCode::Timeout,
                    affected_inputs: 1,
                },
            )
        },
    );
    art_probe(
        "unsupported-scanner-without-failure",
        ReasonCode::StatusInconsistent,
        &|b| b.failures.clear(),
    );
    art_probe(
        "error-scanner-with-unsupported-failure-code",
        ReasonCode::StatusInconsistent,
        &|b| b.scanners[1].status = ScannerStatus::Error,
    );
    art_probe(
        "population-visibility-contradicts-run-class",
        ReasonCode::RunClassMismatch,
        &|b| b.population.visibility = Visibility::Protected,
    );
    // Diagnostics: bounded, ordered, and not time-travelling.
    let mut diag_probe = |label: &str, code, change: &dyn Fn(&mut RunDiagnostics)| {
        let doc = typed(&f.artifact, |d| {
            change(d.diagnostics.as_mut().expect("fixture has diagnostics"))
        });
        out.push(doc_probe(
            k_art,
            label,
            code,
            serialize_internal(&doc).unwrap().into_bytes(),
        ));
    };
    diag_probe("phases-unsorted", ReasonCode::DiagnosticsInvalid, &|d| {
        d.phases.reverse()
    });
    diag_probe("phase-repeated", ReasonCode::DiagnosticsInvalid, &|d| {
        let dup = d.phases[0];
        d.phases.insert(1, dup);
    });
    diag_probe("too-many-phases", ReasonCode::LimitExceeded, &|d| {
        d.phases = vec![d.phases[0]; 7]
    });
    diag_probe(
        "finished-before-started",
        ReasonCode::DiagnosticsInvalid,
        &|d| std::mem::swap(&mut d.started_at, &mut d.finished_at),
    );
    diag_probe(
        "finished-before-started-by-a-fraction",
        ReasonCode::DiagnosticsInvalid,
        &|d| {
            d.started_at = TimestampUtc::new("2026-10-02T09:00:00.500Z").unwrap();
            d.finished_at = TimestampUtc::new("2026-10-02T09:00:00Z").unwrap();
        },
    );

    // ---- Protocol revision 2 (schema 1.1, ADR 0008). ----
    let c2 = Fixtures::default_canonical();
    let man2 = to_pretty_json(&c2.manifest).unwrap();
    let mut art2_probe = |label: &str, code, change: &dyn Fn(&mut RunArtifact)| {
        let doc = typed(&c2.artifact, |d| change(d));
        out.push(doc_probe(
            k_art,
            label,
            code,
            serialize_internal(&doc).unwrap().into_bytes(),
        ));
    };
    art2_probe(
        "rev2-declared-as-schema-1-0",
        ReasonCode::ProtocolBindingMismatch,
        &|d| d.schema_version = SchemaVersion::V1_0,
    );
    art2_probe(
        "rev2-with-unkeyed-metric-list",
        ReasonCode::ProtocolBindingMismatch,
        &|d| d.semantic.metrics = metrics(),
    );
    art2_probe(
        "rev2-rule-in-the-wrong-slot",
        ReasonCode::ProtocolBindingMismatch,
        &|d| {
            let mut rules = ProtocolRules::CANONICAL_V2;
            rules.matching.id = RuleId::PiiV1WilsonExact;
            d.semantic.protocol.rules = Some(rules);
        },
    );
    art2_probe(
        "rev2-without-rules",
        ReasonCode::ProtocolBindingMismatch,
        &|d| d.semantic.protocol.rules = None,
    );
    art2_probe(
        "rev2-scanner-without-metrics",
        ReasonCode::MetricDefinitionMismatch,
        &|d| {
            d.semantic.scanner_metrics.pop();
        },
    );
    art2_probe(
        "rev2-metrics-for-a-scanner-not-in-the-artifact",
        ReasonCode::UnknownScanner,
        &|d| d.semantic.scanner_metrics[1].scanner_id = sid("zeta-scan"),
    );
    art2_probe(
        "rev2-scanner-metrics-unsorted",
        ReasonCode::NonCanonicalOrder,
        &|d| d.semantic.scanner_metrics.reverse(),
    );
    art2_probe(
        "rev2-scanner-metrics-repeated",
        ReasonCode::DuplicateIdentity,
        &|d| d.semantic.scanner_metrics[1].scanner_id = sid("alpha-scan"),
    );
    art2_probe(
        "rev2-scanner-metrics-counts-do-not-add-up",
        ReasonCode::MetricCountsInconsistent,
        &|d| d.semantic.scanner_metrics[0].metrics[0].counts.total += 1,
    );
    art2_probe(
        "rev2-scanner-metric-list-empty",
        ReasonCode::EmptyCollection,
        &|d| d.semantic.scanner_metrics[0].metrics.clear(),
    );
    // Revision 1 keeps its one unkeyed list and its closed failure codes.
    let mut legacy_probe = |label: &str, code, change: &dyn Fn(&mut RunArtifact)| {
        let doc = typed(&f.artifact, |d| change(d));
        out.push(doc_probe(
            k_art,
            label,
            code,
            serialize_internal(&doc).unwrap().into_bytes(),
        ));
    };
    legacy_probe(
        "rev1-with-scanner-metrics",
        ReasonCode::ProtocolBindingMismatch,
        &|d| {
            d.semantic.scanner_metrics = c2.artifact.semantic.scanner_metrics.clone();
        },
    );
    legacy_probe(
        "rev1-with-a-rev2-failure-code",
        ReasonCode::ProtocolBindingMismatch,
        &|d| {
            d.semantic.scanners[1].status = ScannerStatus::Error;
            d.semantic.failures[0].code = FailureCode::ResourceLimitExceeded;
        },
    );
    legacy_probe(
        "rev1-with-rule-identities",
        ReasonCode::ProtocolBindingMismatch,
        &|d| d.semantic.protocol.rules = Some(ProtocolRules::CANONICAL_V2),
    );
    out.push(doc_probe(
        k_man,
        "rev2-unknown-rule-id",
        ReasonCode::SchemaViolation,
        replace_once(
            &man2,
            "\"id\": \"pii-v1-wilson-exact\"",
            "\"id\": \"pii-v1-wilson-approximate\"",
        )
        .into_bytes(),
    ));
    let mut man2_probe = |label: &str, code, change: &dyn Fn(&mut RunManifest)| {
        let doc = typed(&c2.manifest, |d| change(d));
        out.push(doc_probe(
            k_man,
            label,
            code,
            to_pretty_json(&doc).unwrap().into_bytes(),
        ));
    };
    man2_probe(
        "rev2-declared-as-schema-1-0",
        ReasonCode::ProtocolBindingMismatch,
        &|d| d.schema_version = SchemaVersion::V1_0,
    );
    man2_probe(
        "rev2-rule-revision-drift",
        ReasonCode::ProtocolBindingMismatch,
        &|d| {
            let mut rules = ProtocolRules::CANONICAL_V2;
            rules.accounting.revision = 1;
            d.semantic.protocol.rules = Some(rules);
        },
    );
    let mut obs2_probe = |label: &str, code, change: &dyn Fn(&mut ObservationSet)| {
        let doc = typed(&c2.obs_alpha, |d| change(d));
        out.push(doc_probe(
            k_obs,
            label,
            code,
            to_pretty_json(&doc).unwrap().into_bytes(),
        ));
    };
    obs2_probe(
        "rev2-declared-as-schema-1-0",
        ReasonCode::ProtocolBindingMismatch,
        &|d| d.schema_version = SchemaVersion::V1_0,
    );
    let legacy_with_runtime = typed(&f.obs_alpha, |d| {
        d.diagnostics = c2.obs_alpha.diagnostics.clone();
    });
    out.push(doc_probe(
        k_obs,
        "rev1-with-runtime-provenance",
        ReasonCode::DiagnosticsInvalid,
        to_pretty_json(&legacy_with_runtime).unwrap().into_bytes(),
    ));
    let pub2 = c2.artifact.to_public_synthetic().unwrap();
    let mut pub_unkeyed = pub2.clone();
    pub_unkeyed.semantic.metrics = metrics();
    seal(&mut pub_unkeyed).unwrap();
    out.push(doc_probe(
        k_pub,
        "rev2-with-unkeyed-metric-list",
        ReasonCode::ProtocolBindingMismatch,
        serialize_public_synthetic(&pub_unkeyed)
            .unwrap()
            .into_bytes(),
    ));

    // ---- Cross-document bindings (in code, no committed file). ----
    let mut bind = |name: &str, code: ReasonCode, outcome: Result<(), Violations>| {
        out.push(Probe {
            name: format!("binding__{}__{name}", code.as_str()),
            expected: code,
            outcome,
            file: None,
        });
    };
    let protected = Fixtures::build(Visibility::Protected, ProductIdentity::Released);
    bind(
        "public-manifest-protected-snapshot",
        ReasonCode::RunClassMismatch,
        validate_manifest_against_snapshot(&f.manifest, &protected.snapshot),
    );
    let other_population = typed(&f.snapshot, |d| {
        d.semantic.population.population_version = 2
    });
    bind(
        "population-version-changed",
        ReasonCode::PopulationBindingMismatch,
        validate_manifest_against_snapshot(&f.manifest, &other_population),
    );
    let edited_text = typed(&f.snapshot, |d| {
        let v = &mut d.semantic.cases[2].variants[0];
        v.text = v.text.replace("on file", "on  file");
        v.text_digest = Sha256Digest::of_bytes(v.text.as_bytes());
        v.expectations[0].range.end = v.expectations[0].range.end.min(v.text.len() as u64);
    });
    bind(
        "population-digest-changed-by-text-edit",
        ReasonCode::PopulationBindingMismatch,
        validate_manifest_against_snapshot(&f.manifest, &edited_text),
    );
    bind(
        "observation-of-edited-population",
        ReasonCode::PopulationBindingMismatch,
        validate_observation_against_snapshot(&f.obs_alpha, &edited_text),
    );
    let narrow_scope = typed(&f.manifest, |d| {
        d.semantic.scope.languages.retain(|l| l.as_str() != "ko")
    });
    bind(
        "language-outside-scope",
        ReasonCode::ScopeViolation,
        validate_manifest_against_snapshot(&narrow_scope, &f.snapshot),
    );
    let fewer_methods = typed(&f.manifest, |d| {
        d.semantic
            .methods
            .retain(|m| m.id != MethodId::TypeValidation)
    });
    bind(
        "method-not-planned",
        ReasonCode::ProtocolBindingMismatch,
        validate_manifest_against_snapshot(&fewer_methods, &f.snapshot),
    );

    let other_engine = typed(&f.obs_alpha, |d| d.semantic.engine.version = ver("9.9.9"));
    bind(
        "observation-engine-differs",
        ReasonCode::EngineBindingMismatch,
        validate_observation_against_manifest(&other_engine, &f.manifest),
    );
    let other_pop_obs = typed(&f.obs_alpha, |d| {
        d.semantic.population_digest = digest_of("elsewhere")
    });
    bind(
        "observation-population-differs",
        ReasonCode::PopulationBindingMismatch,
        validate_observation_against_manifest(&other_pop_obs, &f.manifest),
    );
    let unknown = typed(&f.obs_alpha, |d| {
        d.semantic.scanner.scanner_id = sid("gamma-scan")
    });
    bind(
        "observation-scanner-not-in-plan",
        ReasonCode::UnknownScanner,
        validate_observation_against_manifest(&unknown, &f.manifest),
    );
    let other_adapter = typed(&f.obs_alpha, |d| {
        d.semantic.scanner.adapter.adapter_version = ver("0.2.0")
    });
    bind(
        "observation-adapter-version-differs",
        ReasonCode::ConfigurationBindingMismatch,
        validate_observation_against_manifest(&other_adapter, &f.manifest),
    );
    let other_config = typed(&f.obs_alpha, |d| {
        d.semantic.scanner.configuration_digest = digest_of("other-config")
    });
    bind(
        "observation-configuration-differs",
        ReasonCode::ConfigurationBindingMismatch,
        validate_observation_against_manifest(&other_config, &f.manifest),
    );
    let other_activation = typed(&f.obs_alpha, |d| {
        d.semantic.scanner.activation_digest = digest_of("other-activation")
    });
    bind(
        "observation-activation-differs",
        ReasonCode::ConfigurationBindingMismatch,
        validate_observation_against_manifest(&other_activation, &f.manifest),
    );
    let released_to_candidate = typed(&f.obs_alpha, |d| {
        d.semantic.scanner.product = ProductIdentity::Candidate {
            candidate_digest: digest_of("c"),
        };
    });
    bind(
        "observation-product-identity-differs",
        ReasonCode::ConfigurationBindingMismatch,
        validate_observation_against_manifest(&released_to_candidate, &f.manifest),
    );
    let one_replay = typed(&f.obs_alpha, |d| d.semantic.replays.count = 1);
    bind(
        "observation-replay-count-differs",
        ReasonCode::ConfigurationBindingMismatch,
        validate_observation_against_manifest(&one_replay, &f.manifest),
    );

    let changed_input = typed(&f.obs_alpha, |d| {
        d.semantic.inputs[0].input_digest = digest_of("different bytes")
    });
    bind(
        "input-bytes-changed",
        ReasonCode::InputDigestMismatch,
        validate_observation_against_snapshot(&changed_input, &f.snapshot),
    );
    let unknown_variant = typed(&f.obs_alpha, |d| {
        d.semantic.inputs[0].variant_id = id("not-in-snapshot");
        d.semantic
            .inputs
            .sort_by(|a, b| a.variant_id.cmp(&b.variant_id));
    });
    bind(
        "variant-not-in-snapshot",
        ReasonCode::UnknownVariant,
        validate_observation_against_snapshot(&unknown_variant, &f.snapshot),
    );
    let past_end = typed(&f.obs_alpha, |d| {
        d.semantic.inputs[0].findings[0].range.end = 100_000
    });
    bind(
        "finding-past-end-of-text",
        ReasonCode::RangeOutOfBounds,
        validate_observation_against_snapshot(&past_end, &f.snapshot),
    );
    let mid_character = typed(&f.obs_alpha, |d| {
        // inputs sorted by variant id: index 1 is the Korean neutral frame.
        let finding = &mut d.semantic.inputs[1].findings[0];
        finding.range.start = 1;
    });
    bind(
        "finding-inside-korean-character",
        ReasonCode::RangeNotOnCharBoundary,
        validate_observation_against_snapshot(&mid_character, &f.snapshot),
    );
    let missing_input = typed(&f.obs_alpha, |d| {
        d.semantic.inputs.pop();
    });
    bind(
        "complete-observation-misses-a-variant",
        ReasonCode::ObservationIncomplete,
        validate_observation_against_snapshot(&missing_input, &f.snapshot),
    );

    let wrong_manifest = typed(&f.artifact, |d| {
        d.semantic.manifest_digest = digest_of("other manifest")
    });
    bind(
        "artifact-manifest-digest-differs",
        ReasonCode::ConfigurationBindingMismatch,
        validate_artifact_against_manifest(&wrong_manifest, &f.manifest),
    );
    let wrong_config = typed(&f.artifact, |d| {
        d.semantic.scanners[0].identity.configuration_digest = digest_of("x")
    });
    bind(
        "artifact-scanner-configuration-differs",
        ReasonCode::ConfigurationBindingMismatch,
        validate_artifact_against_manifest(&wrong_config, &f.manifest),
    );
    let wrong_class = typed(&f.artifact, |d| d.semantic.run_class = RunClass::Protected);
    bind(
        "artifact-run-class-differs",
        ReasonCode::RunClassMismatch,
        validate_artifact_against_manifest(&wrong_class, &f.manifest),
    );
    let wrong_mechanics = typed(&f.artifact, |d| d.semantic.mechanics.min_denominator = 5);
    bind(
        "artifact-mechanics-differ",
        ReasonCode::ProtocolBindingMismatch,
        validate_artifact_against_manifest(&wrong_mechanics, &f.manifest),
    );
    let wrong_metrics = typed(&f.artifact, |d| {
        d.semantic
            .metrics
            .retain(|m| m.metric.id != MetricId::MeasurableShare);
    });
    bind(
        "artifact-metrics-differ-from-plan",
        ReasonCode::ProtocolBindingMismatch,
        validate_artifact_against_manifest(&wrong_metrics, &f.manifest),
    );
    let c2_missing_metric = typed(&c2.artifact, |d| {
        d.semantic.scanner_metrics[0].metrics.pop();
    });
    bind(
        "rev2-scanner-lacks-a-planned-metric",
        ReasonCode::ProtocolBindingMismatch,
        validate_artifact_against_manifest(&c2_missing_metric, &c2.manifest),
    );
    let invalid_flipped = typed(&f.snapshot, |d| {
        d.semantic.cases[2].variants[0].expectations[0].type_expectation = ExpectedType::Invalid;
    });
    bind(
        "outcome-state-unreachable-for-authored-expectation",
        ReasonCode::OutcomeContradiction,
        validate_artifact_against_snapshot(&f.artifact, &invalid_flipped),
    );
    let wrong_counts = typed(&f.artifact, |d| {
        d.semantic.population_counts.occurrences = 7
    });
    bind(
        "artifact-occurrence-count-differs",
        ReasonCode::CountMismatch,
        validate_artifact_against_snapshot(&wrong_counts, &f.snapshot),
    );

    let other_generator = typed(&f.manifest, |d| d.semantic.generation.generator_version = 2);
    bind(
        "plan-generator-version-differs-from-snapshot",
        ReasonCode::GenerationBindingMismatch,
        validate_manifest_against_snapshot(&other_generator, &f.snapshot),
    );
    let other_seed_rule = typed(&f.manifest, |d| {
        d.semantic.generation.seed_derivation = Seed::new("seed-v2").unwrap()
    });
    bind(
        "plan-seed-derivation-differs-from-snapshot",
        ReasonCode::GenerationBindingMismatch,
        validate_manifest_against_snapshot(&other_seed_rule, &f.snapshot),
    );
    let wrong_visibility = typed(&f.manifest, |d| {
        d.semantic.population.visibility = Visibility::Protected;
        d.semantic.run_class = RunClass::Protected;
    });
    bind(
        "plan-binds-protected-visibility-for-a-public-snapshot",
        ReasonCode::RunClassMismatch,
        validate_manifest_against_snapshot(&wrong_visibility, &f.snapshot),
    );
    bind(
        "plan-population-visibility-differs-from-snapshot",
        ReasonCode::PopulationBindingMismatch,
        validate_manifest_against_snapshot(&wrong_visibility, &f.snapshot),
    );
    let family_unsupported_for_row = typed(&f.snapshot, |d| {
        d.semantic.cases[2].variants[0].expectations[0].family = fam("pii:global:phone")
    });
    let mut unsupported_family = f.artifact.clone();
    unsupported_family.semantic.scanners[0]
        .capabilities
        .families
        .push(FamilyCapability {
            family: fam("pii:global:phone"),
            state: CapabilityState::Unsupported,
        });
    unsupported_family.semantic.scanners[0]
        .capabilities
        .families
        .sort_by(|a, b| a.family.cmp(&b.family));
    bind(
        "expected-family-unsupported-but-type-axis-measured",
        ReasonCode::OutcomeContradiction,
        validate_artifact_against_snapshot(&unsupported_family, &family_unsupported_for_row),
    );

    // ---- Publication boundary. ----
    let mut tampered = f.artifact.clone();
    tampered.semantic.failures[0].affected_inputs = 99;
    bind(
        "tampered-artifact-is-not-projected",
        ReasonCode::SemanticDigestMismatch,
        tampered.to_public_synthetic().map(|_| ()),
    );
    let mut inconsistent = f.artifact.clone();
    inconsistent.semantic.population.visibility = Visibility::Protected;
    seal(&mut inconsistent).unwrap();
    bind(
        "public-run-class-over-protected-population-is-not-projected",
        ReasonCode::RunClassMismatch,
        inconsistent.to_public_synthetic().map(|_| ()),
    );
    bind(
        "protected-run-cannot-be-projected",
        ReasonCode::PublicProjectionForbidden,
        protected.artifact.to_public_synthetic().map(|_| ()),
    );
    out
}

fn negative_dir() -> std::path::PathBuf {
    fixtures_dir().join("negative")
}

#[test]
fn every_probe_is_rejected_with_its_stable_code() {
    let mut failures = Vec::new();
    for p in probes() {
        match &p.outcome {
            Ok(()) => failures.push(format!("{} was accepted", p.name)),
            Err(v) if v.first_code() != Some(p.expected) && !v.contains(p.expected) => {
                failures.push(format!("{}: expected {}, got {v}", p.name, p.expected))
            }
            Err(v) if p.file.is_some() && v.first_code() != Some(p.expected) => failures.push(
                format!("{}: expected first code {}, got {v}", p.name, p.expected),
            ),
            Err(_) => {}
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn committed_negative_fixtures_equal_the_probes() {
    let dir = negative_dir();
    let mut expected: BTreeSet<String> = BTreeSet::new();
    let update = update_requested("PII_EVAL_UPDATE_FIXTURES");
    if update {
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
    }
    for p in probes() {
        let Some((_, bytes)) = &p.file else { continue };
        let name = format!("{}.json", p.name);
        let path = dir.join(&name);
        if update {
            std::fs::write(&path, bytes).unwrap();
        }
        let committed = std::fs::read(&path).unwrap_or_else(|_| {
            panic!("missing negative fixture {name}; run with PII_EVAL_UPDATE_FIXTURES=1")
        });
        assert_eq!(&committed, bytes, "negative fixture {name} drifted");
        expected.insert(name);
    }
    let on_disk: BTreeSet<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(on_disk, expected, "stale or missing negative fixtures");
}

#[test]
fn committed_negative_fixtures_are_rejected_when_read_from_disk() {
    // File name: <kind-stem>__<reason-code>__<label>.json
    for entry in std::fs::read_dir(negative_dir()).unwrap() {
        let path = entry.unwrap().path();
        let stem = path.file_stem().unwrap().to_string_lossy().into_owned();
        let mut parts = stem.splitn(3, "__");
        let (kind_stem, code) = (parts.next().unwrap(), parts.next().unwrap());
        let kind = DocumentKind::ALL
            .into_iter()
            .find(|k| k.schema_file_stem() == kind_stem)
            .unwrap_or_else(|| panic!("unknown kind in {stem}"));
        let err = parse_kind(kind, &std::fs::read(&path).unwrap()).expect_err(&stem);
        assert_eq!(
            err.first_code().map(ReasonCode::as_str),
            Some(code),
            "{stem}"
        );
    }
}

#[test]
fn every_reason_code_is_exercised() {
    let exercised: BTreeSet<ReasonCode> = probes().iter().map(|p| p.expected).collect();
    // Exercised by unit tests next to the code that raises them.
    let by_unit_tests = [
        // canonical::tests::size_and_depth_are_bounded
        ReasonCode::DocumentTooLarge,
        // digest.rs::limits_are_enforced
        ReasonCode::LimitExceeded,
    ];
    for code in ReasonCode::ALL {
        assert!(
            exercised.contains(code) || by_unit_tests.contains(code),
            "reason code {code} has no rejection probe"
        );
    }
}

#[test]
fn reason_codes_are_stable_kebab_case_and_unique() {
    let mut seen = BTreeSet::new();
    for code in ReasonCode::ALL {
        let s = code.as_str();
        assert!(
            s.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'),
            "{s}"
        );
        assert!(
            !s.starts_with('-') && !s.ends_with('-') && !s.contains("--"),
            "{s}"
        );
        assert!(seen.insert(s), "duplicate reason code {s}");
    }
}

#[test]
fn errors_carry_only_bounded_safe_metadata() {
    // Hostile content in identifiers and text must never appear in an error.
    let hostile = "LEAK-CANARY-0xBEEF";
    let f = Fixtures::default_public();
    let mut doc = f.snapshot.clone();
    doc.semantic.cases[2].variants[0].text = format!("{hostile} {hostile}");
    seal(&mut doc).unwrap();
    let err = validate(&doc).unwrap_err();
    let rendered = format!("{err} {err:?}");
    assert!(!rendered.contains(hostile));
    for e in &err.errors {
        assert!(e.path.len() <= pii_eval_contracts::limits::MAX_PATH_BYTES);
        assert!(
            e.path
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'/')
        );
    }
    let bad_id = format!(
        "{{\"schema\":\"pii-eval.corpus-snapshot\",\"schemaVersion\":\"1.0\",\"x\":\"{hostile}\"}}"
    );
    let err = parse_default::<CorpusSnapshot>(bad_id.as_bytes()).unwrap_err();
    assert!(!format!("{err} {err:?}").contains(hostile));
}
