//! Peak memory of parsing a document at the 32 MiB cap (the P2 deferral, ADR 0008
//! section 6). A measurement, not a pass/fail check: it is `#[ignore]`d and run
//! by hand.
//!
//! ```text
//! cargo test -p pii-eval-cli --release --test parse_memory -- --ignored --nocapture
//! ```
//!
//! Method. Each measurement parses one file in a fresh child process (this test
//! binary, re-executed with `--exact parse_child_entry`) wrapped by the system
//! `time` utility, which reports the child's maximum resident set size
//! (`/usr/bin/time -l` on macOS, in bytes; `/usr/bin/time -v` on Linux, in
//! KiB). The process's own baseline (a child that parses nothing) is measured
//! the same way and subtracted. Two documents of just under 32 MiB are used:
//!
//! * `text`: a corpus snapshot of 30 variants of one megabyte of text each
//!   (string-dominated: few nodes, large strings);
//! * `nodes`: an observation set of about 300,000 tiny findings (node-dominated:
//!   the strict value tree allocates per number, key and object, the worst case
//!   for the tree).
//!
//! `parse_default` builds the strict value tree, drops it, then parses the typed
//! document, so the peak is the larger of the two plus the input bytes.

mod common;

use std::path::Path;
use std::process::Command;

use common::*;
use pii_eval_contracts::{
    ActionCapability, ActionExpectation, ActionKind, ByteRange, CapabilityState, Case,
    ContextClass, ContextObligation, CorpusSnapshot, CorpusSnapshotBody, Derivation, Expectation,
    ExpectedType, FamilyCapability, FamilyId, Finding, GenerationRules, Id, InputObservation,
    JurisdictionCode, LanguageTag, Lineage, MethodId, ObservationSet, ObservationSetBody,
    Population, ProtocolIdentity, ReplayRecord, ScannerCapabilities, ScannerStatus,
    SensitivityExpectation, Strategy, Variant, Visibility, parse_default, seal,
};

fn text_snapshot() -> CorpusSnapshot {
    let text = format!("start user@example.invalid {}", "a".repeat(1_000_000 - 28));
    let variants: Vec<Variant> = (0..30)
        .map(|i| Variant {
            variant_id: Id::new(format!("v{i:02}")).unwrap(),
            derivation: Derivation {
                strategy: Strategy::Authored,
                operator: None,
                seed: None,
            },
            text: text.clone(),
            text_digest: pii_eval_contracts::Sha256Digest::of_bytes(text.as_bytes()),
            expectations: vec![Expectation {
                occurrence_id: Id::new("occurrence-1").unwrap(),
                range: ByteRange { start: 6, end: 26 },
                family: FamilyId::new("pii:global:email").unwrap(),
                type_expectation: ExpectedType::Valid,
                validator: None,
                sensitivity: SensitivityExpectation::Sensitive,
                context_class: ContextClass::Sensitive,
                context_obligation: ContextObligation::None,
                action: ActionExpectation::Redact,
            }],
        })
        .collect();
    let mut snapshot = CorpusSnapshot::unsealed(CorpusSnapshotBody {
        population: Population {
            population_id: Id::new("synthetic-memory").unwrap(),
            population_version: 1,
            visibility: Visibility::PublicSynthetic,
        },
        generation: GenerationRules {
            generator: Id::new("synthetic-generator").unwrap(),
            generator_version: 1,
            seed_derivation: pii_eval_contracts::Seed::new("seed-v1").unwrap(),
        },
        cases: vec![Case {
            case_id: Id::new("memory-case").unwrap(),
            method: MethodId::TypeValidation,
            lineage: Lineage {
                source_id: Id::new("synthetic-source").unwrap(),
                source_digest: digest_of("source"),
            },
            language: LanguageTag::new("en").unwrap(),
            jurisdiction: None,
            collision: None,
            variants,
        }],
    });
    seal(&mut snapshot).unwrap();
    snapshot
}

fn node_observation() -> ObservationSet {
    let plan = plan("alpha-scan", 5);
    let finding = |i: u64| Finding {
        range: ByteRange {
            start: i,
            end: i + 1,
        },
        family: Some(FamilyId::new("pii:global:email").unwrap()),
        jurisdiction: None,
        sensitive: Some(true),
        action: Some(ActionKind::Redact),
    };
    let inputs: Vec<InputObservation> = (0..38)
        .map(|n| InputObservation {
            variant_id: Id::new(format!("v{n:02}")).unwrap(),
            input_digest: digest_of(&format!("input-{n}")),
            sanitized_output_digest: None,
            findings: (0..8_000).map(finding).collect(),
        })
        .collect();
    let mut set = ObservationSet::unsealed(ObservationSetBody {
        engine: engine(),
        protocol: ProtocolIdentity::CANONICAL_V2,
        population_digest: digest_of("population"),
        scanner: plan.identity,
        status: ScannerStatus::Complete,
        capabilities: ScannerCapabilities {
            ranges: CapabilityState::Supported,
            family_classification: CapabilityState::Supported,
            sensitivity_classification: CapabilityState::Supported,
            jurisdiction_reporting: CapabilityState::Undeclared,
            action: ActionCapability::ReportedAction,
            families: vec![FamilyCapability {
                family: FamilyId::new("pii:global:email").unwrap(),
                state: CapabilityState::Supported,
            }],
            jurisdictions: Vec::<pii_eval_contracts::JurisdictionCapability>::new(),
        },
        replays: ReplayRecord {
            count: 2,
            agreed: true,
        },
        inputs,
    });
    let _ = JurisdictionCode::new("US");
    seal(&mut set).unwrap();
    set
}

/// Child half: parse the file named by the environment, then exit.
#[test]
fn parse_child_entry() {
    let (Ok(kind), Ok(path)) = (
        std::env::var("PII_EVAL_PARSE_KIND"),
        std::env::var("PII_EVAL_PARSE_FILE"),
    ) else {
        return;
    };
    let bytes = std::fs::read(path).unwrap();
    match kind.as_str() {
        "noop" => {}
        "text" => {
            let doc: CorpusSnapshot = parse_default(&bytes).expect("snapshot parses");
            assert_eq!(doc.semantic.cases[0].variants.len(), 30);
        }
        "nodes" => {
            let doc: ObservationSet = parse_default(&bytes).expect("observation set parses");
            assert_eq!(doc.semantic.inputs.len(), 38);
        }
        other => panic!("unknown kind {other}"),
    }
}

/// Maximum resident set size of a wrapped child, in bytes.
fn max_rss(kind: &str, file: &Path) -> u64 {
    let (flag, kib) = if cfg!(target_os = "macos") {
        ("-l", false)
    } else {
        ("-v", true)
    };
    let out = Command::new("/usr/bin/time")
        .arg(flag)
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "parse_child_entry",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("PII_EVAL_PARSE_KIND", kind)
        .env("PII_EVAL_PARSE_FILE", file)
        .output()
        .expect("/usr/bin/time runs");
    assert!(
        out.status.success(),
        "child failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let line = stderr
        .lines()
        .find(|l| {
            l.contains("maximum resident set size") || l.contains("Maximum resident set size")
        })
        .expect("time reports the maximum resident set size");
    let number: u64 = line
        .split_whitespace()
        .find_map(|w| w.parse().ok())
        .expect("a number on the line");
    if kib { number * 1024 } else { number }
}

#[test]
#[ignore = "a measurement: run by hand (see the module documentation)"]
fn measure_parse_peak_memory_at_the_document_cap() {
    let dir = TempDir::new("parse-memory");
    let text = pii_eval_contracts::to_pretty_json(&text_snapshot()).unwrap();
    let nodes = serde_json::to_string(&node_observation()).unwrap();
    for (name, doc) in [("text", &text), ("nodes", &nodes)] {
        assert!(
            doc.len() < pii_eval_contracts::limits::MAX_DOCUMENT_BYTES,
            "{name} document is within the cap ({} bytes)",
            doc.len()
        );
    }
    let (text_file, nodes_file, noop_file) = (
        dir.0.join("text.json"),
        dir.0.join("nodes.json"),
        dir.0.join("noop"),
    );
    std::fs::write(&text_file, &text).unwrap();
    std::fs::write(&nodes_file, &nodes).unwrap();
    std::fs::write(&noop_file, b"").unwrap();
    let base = (0..3).map(|_| max_rss("noop", &noop_file)).max().unwrap();
    let measure = |kind: &str, file: &Path| (0..3).map(|_| max_rss(kind, file)).max().unwrap();
    let (t, n) = (measure("text", &text_file), measure("nodes", &nodes_file));
    let mib = |b: u64| b as f64 / (1024.0 * 1024.0);
    println!(
        "parse peak memory (host {}, {}, max of 3 runs, baseline subtracted):",
        std::env::consts::OS,
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    );
    println!("  baseline process        {:8.1} MiB", mib(base));
    println!(
        "  text  {:6.2} MiB doc  peak {:8.1} MiB  (+{:.1} MiB, {:.1}x the document)",
        mib(text.len() as u64),
        mib(t),
        mib(t.saturating_sub(base)),
        mib(t.saturating_sub(base)) / mib(text.len() as u64)
    );
    println!(
        "  nodes {:6.2} MiB doc  peak {:8.1} MiB  (+{:.1} MiB, {:.1}x the document)",
        mib(nodes.len() as u64),
        mib(n),
        mib(n.saturating_sub(base)),
        mib(n.saturating_sub(base)) / mib(nodes.len() as u64)
    );
}
