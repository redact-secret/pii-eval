//! The data of the parity suite and the Rust engine's view of the corpus.
//!
//! `fixtures/oracle-parity/input.json` is the frozen synthetic input and
//! `fixtures/oracle-parity/oracle-export.json` is what the pinned oracle's own
//! code produced on it (tools/oracle-parity). The Rust side regenerates the
//! variants from the authored cases with the kernel's methods and compares; it
//! never reads an expected value from the Rust implementation.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use pii_eval_contracts::{
    ActionExpectation, ByteRange, Case, ContextClass, ContextObligation, CorpusSnapshot,
    CorpusSnapshotBody, ExpectedType, FamilyId, Finding, GenerationRules, Id, JurisdictionCode,
    LanguageTag, Lineage, MethodId, OperatorRef, Population, ScannerStatus, Seed,
    SensitivityExpectation, Sha256Digest, Strategy, ValidatorRef, Variant, Visibility, seal,
};
use pii_eval_kernel::methods::{
    AuthoredCase, BenignClass, ContextFrame, GenerationLimits, Generator, MethodParams,
    SEED_RULE_LEGACY, ValidatorDef, ValidatorRegistry, ValidatorState, VariantProvenance,
    assemble_body, legacy_contract_seed,
};
use serde_json::Value;

use super::json::*;

pub fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/oracle-parity")
}

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The committed input and oracle export, parsed, with their exact bytes.
#[derive(Clone)]
pub struct Dataset {
    pub input: Value,
    pub export: Value,
    pub input_bytes: Vec<u8>,
    pub export_bytes: Vec<u8>,
}

impl Dataset {
    pub fn load() -> Dataset {
        let read = |name: &str| {
            std::fs::read(data_dir().join(name)).unwrap_or_else(|_| panic!("missing {name}"))
        };
        let input_bytes = read("input.json");
        let export_bytes = read("oracle-export.json");
        Dataset {
            input: serde_json::from_slice(&input_bytes).expect("input.json is JSON"),
            export: serde_json::from_slice(&export_bytes).expect("oracle-export.json is JSON"),
            input_bytes,
            export_bytes,
        }
    }
}

impl Dataset {
    /// The dataset of the same-pinned-scanner run: the main export with its scanners
    /// replaced by the real scanner's committed export (the cases must be equal, so
    /// both exports describe the same population).
    pub fn load_real() -> Dataset {
        let mut ds = Dataset::load();
        let bytes = std::fs::read(data_dir().join("real-core-export.json"))
            .expect("missing real-core-export.json");
        let real: Value = serde_json::from_slice(&bytes).expect("real export is JSON");
        assert_eq!(
            get(&real, "cases"),
            get(&ds.export, "cases"),
            "the real-scanner export was produced for another population"
        );
        ds.export["scanners"] = get(&real, "scanners").clone();
        ds
    }

    pub fn real_provenance() -> Value {
        let bytes = std::fs::read(data_dir().join("real-core-export.json")).expect("real export");
        let real: Value = serde_json::from_slice(&bytes).expect("real export is JSON");
        get(get(&real, "provenance"), "realScanner").clone()
    }
}

pub fn id(s: &str) -> Id {
    Id::new(s).unwrap_or_else(|_| panic!("not an id: {s:?}"))
}

pub fn status_of(word_: &str) -> ScannerStatus {
    wire(word_)
}

fn validators() -> ValidatorRegistry {
    let mut registry = ValidatorRegistry::builtin();
    // The oracle driver registers the same validator: it answers `unavailable`.
    assert!(registry.register(ValidatorDef {
        id: "unavailable-test",
        version: 1,
        validate: |_| ValidatorState::Unavailable,
    }));
    registry
}

fn vref(v: &Value) -> ValidatorRef {
    ValidatorRef {
        id: id(text(v, "id")),
        version: uint(v, "version") as u32,
    }
}

fn benign_class(word_: &str) -> BenignClass {
    [
        BenignClass::Reserved,
        BenignClass::Documentation,
        BenignClass::TestValue,
        BenignClass::PublicOperational,
        BenignClass::Placeholder,
        BenignClass::ContextNegative,
    ]
    .into_iter()
    .find(|c| c.as_str() == word_)
    .unwrap_or_else(|| panic!("benign class {word_}"))
}

/// One variant as the Rust engine generated it.
pub struct RVariant {
    pub case_id: String,
    pub slot: String,
    pub method: MethodId,
    pub variant: Variant,
    pub provenance: VariantProvenance,
    pub family: FamilyId,
    pub case_jurisdiction: Option<JurisdictionCode>,
    pub language: String,
}

impl RVariant {
    pub fn key(&self) -> (String, String) {
        (self.case_id.clone(), self.slot.clone())
    }
}

/// The Rust engine's corpus: the contract body generated from the authored cases.
pub struct RustCorpus {
    pub body: CorpusSnapshotBody,
    pub variants: Vec<RVariant>,
    pub index: BTreeMap<(String, String), usize>,
    /// Authored cases the Rust methods refused (case id, reason).
    pub refused: Vec<(String, String)>,
}

impl RustCorpus {
    pub fn variant(&self, case: &str, slot: &str) -> Option<&RVariant> {
        self.index
            .get(&(case.to_owned(), slot.to_owned()))
            .map(|i| &self.variants[*i])
    }

    pub fn snapshot(&self) -> CorpusSnapshot {
        let mut snapshot = CorpusSnapshot::unsealed(self.body.clone());
        seal(&mut snapshot).expect("snapshot seals");
        snapshot
    }
}

/// Authored cases of the input, with the context frames read from the oracle's
/// generated variants of the same case (text around the candidate).
pub fn authored_cases(input: &Value, export: &Value) -> Vec<AuthoredCase> {
    list(input, "cases")
        .iter()
        .map(|c| {
            let prefix = text(c, "prefix");
            let value = text(c, "value");
            let full = format!("{prefix}{value}{}", text(c, "suffix"));
            let method = text(c, "method");
            let params = match method {
                "schema-only" => MethodParams::SchemaOnly,
                "type-validation" => MethodParams::TypeValidation,
                "context-discrimination" => {
                    let exported = list(export, "cases")
                        .iter()
                        .find(|e| text(e, "id") == text(c, "id"))
                        .expect("exported context case");
                    MethodParams::ContextDiscrimination {
                        frames: list(exported, "variants")
                            .iter()
                            .map(|v| {
                                let t = text(v, "text");
                                let (s, e) = (
                                    uint(get(v, "candidate"), "start") as usize,
                                    uint(get(v, "candidate"), "end") as usize,
                                );
                                let expectation = get(v, "expectation");
                                ContextFrame {
                                    id: id(text(v, "slot")),
                                    template: format!("{}{{{{candidate}}}}{}", &t[..s], &t[e..]),
                                    context_class: wire(text(expectation, "contextClass")),
                                    sensitivity: wire(text(expectation, "sensitivity")),
                                }
                            })
                            .collect(),
                    }
                }
                "pii-benign" => MethodParams::PiiBenign {
                    class: benign_class(text(c, "accountingClass")),
                    checks: Vec::new(),
                },
                "jurisdiction-collision" => MethodParams::JurisdictionCollision {
                    competing: list(c, "competing")
                        .iter()
                        .map(|f| FamilyId::new(f.as_str().unwrap()).unwrap())
                        .collect(),
                    checks: Vec::new(),
                },
                "mutation" => MethodParams::Mutation {
                    operator: OperatorRef {
                        id: id(text(c, "operator")),
                        version: 1,
                    },
                },
                "reference-differential" => MethodParams::ReferenceDifferential,
                other => panic!("method {other}"),
            };
            AuthoredCase {
                case_id: id(text(c, "id")),
                lineage: Lineage {
                    source_id: id("synthetic-source"),
                    source_digest: Sha256Digest::of_bytes(b"synthetic"),
                },
                language: LanguageTag::new(text(c, "language")).unwrap(),
                jurisdiction: opt_text(c, "jurisdiction")
                    .map(|j| JurisdictionCode::new(j).unwrap()),
                family: FamilyId::new(text(c, "family")).unwrap(),
                text: full,
                candidate: ByteRange {
                    start: prefix.len() as u64,
                    end: (prefix.len() + value.len()) as u64,
                },
                type_expectation: wire::<ExpectedType>(text(c, "type")),
                validator: get(c, "validator").as_str().map(|v| ValidatorRef {
                    id: id(v),
                    version: 1,
                }),
                sensitivity: wire::<SensitivityExpectation>(text(c, "sensitivity")),
                context_class: wire::<ContextClass>(text(c, "contextClass")),
                context_obligation: wire::<ContextObligation>(text(c, "obligation")),
                action: ActionExpectation::NotSpecified,
                reference: get(c, "reference")
                    .is_object()
                    .then(|| vref(get(c, "reference"))),
                seed: legacy_contract_seed(text(c, "seed")).unwrap(),
                evidence: None,
                params,
            }
        })
        .collect()
}

/// Generate the Rust corpus (legacy seed rule, so seeds are the oracle's up to
/// ADR 0007 D7).
pub fn rust_corpus(input: &Value, export: &Value) -> RustCorpus {
    let rules = GenerationRules {
        generator: id("parity-generator"),
        generator_version: 1,
        seed_derivation: Seed::new(SEED_RULE_LEGACY).unwrap(),
    };
    let validators = validators();
    let generator = Generator::new(&rules, &validators, GenerationLimits::DEFAULT)
        .expect("generator for the legacy seed rule");
    let authored = authored_cases(input, export);
    let output = generator.generate_all(authored.iter()).expect("generation");
    let refused = output
        .refused
        .iter()
        .map(|r| (r.case_id.as_str().to_owned(), r.reason.as_str().to_owned()))
        .collect();
    let mut variants = Vec::new();
    let mut by_case: BTreeMap<String, (&Case, &[VariantProvenance])> = BTreeMap::new();
    for g in &output.generated {
        by_case.insert(g.case.case_id.as_str().to_owned(), (&g.case, &g.provenance));
    }
    for (case_id, (case, provenance)) in &by_case {
        for (variant, prov) in case.variants.iter().zip(provenance.iter()) {
            assert_eq!(variant.variant_id, prov.variant_id);
            variants.push(RVariant {
                case_id: case_id.clone(),
                slot: prov.slot.as_str().to_owned(),
                method: case.method,
                variant: variant.clone(),
                provenance: prov.clone(),
                family: variant.expectations[0].family.clone(),
                case_jurisdiction: case.jurisdiction.clone(),
                language: case.language.as_str().to_owned(),
            });
        }
    }
    variants.sort_by_key(RVariant::key);
    let index = variants
        .iter()
        .enumerate()
        .map(|(i, v)| (v.key(), i))
        .collect();
    let population = Population {
        population_id: id(text(get(input, "population"), "id")),
        population_version: uint(get(input, "population"), "version") as u32,
        visibility: wire::<Visibility>(text(get(input, "population"), "visibility")),
    };
    let body = assemble_body(population, rules, output.generated.clone()).expect("assemble");
    RustCorpus {
        body,
        variants,
        index,
        refused,
    }
}

/// The findings a scanner returned for each variant, in emission order.
pub fn findings_of(scanner: &Value) -> BTreeMap<(String, String), Vec<Finding>> {
    list(scanner, "returned")
        .iter()
        .map(|r| {
            let findings = list(r, "findings")
                .iter()
                .map(|f| Finding {
                    range: ByteRange {
                        start: uint(f, "start"),
                        end: uint(f, "end"),
                    },
                    family: opt_text(f, "family").map(|x| FamilyId::new(x).unwrap()),
                    jurisdiction: opt_text(f, "jurisdiction")
                        .map(|x| JurisdictionCode::new(x).unwrap()),
                    sensitive: get(f, "sensitive").as_bool(),
                    action: None,
                })
                .collect();
            (
                (text(r, "case").to_owned(), text(r, "slot").to_owned()),
                findings,
            )
        })
        .collect()
}

/// The oracle's exported outcome of one variant under one scanner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleOutcome {
    pub type_state: pii_eval_contracts::TypeState,
    pub sensitivity_state: pii_eval_contracts::SensitivityState,
    pub range: pii_eval_contracts::RangeState,
    pub finding_count: u64,
    pub families: Vec<String>,
    pub jurisdictions: Vec<String>,
}

pub fn oracle_outcomes(scanner: &Value) -> BTreeMap<(String, String), OracleOutcome> {
    list(scanner, "outcomes")
        .iter()
        .map(|o| {
            let strings = |v: &Value| {
                v.as_array()
                    .map(|a| {
                        a.iter()
                            .map(|s| s.as_str().unwrap_or("").to_owned())
                            .collect()
                    })
                    .unwrap_or_default()
            };
            let observed = get(o, "observed");
            (
                (text(o, "case").to_owned(), text(o, "slot").to_owned()),
                OracleOutcome {
                    type_state: wire(text(get(o, "type"), "state")),
                    sensitivity_state: wire(text(get(o, "sensitivity"), "state")),
                    range: wire(text(o, "range")),
                    finding_count: uint(observed, "findingCount"),
                    families: strings(get(observed, "families")),
                    jurisdictions: strings(get(observed, "jurisdictions")),
                },
            )
        })
        .collect()
}

pub fn strategy_word(s: Strategy) -> String {
    word(&s)
}
