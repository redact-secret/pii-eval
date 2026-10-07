//! Mapping verified evidence into pii-eval's existing corpus contract.
//!
//! Rule `pii-evidence-to-corpus` revision 1 (ADR 0019). The unit of
//! measurement is the evidence FIXTURE (exact bytes), grouped under the
//! evidence CASE that explains it. Nothing here invents an expectation, copies
//! a scanner field or adds a threshold: a value is mapped when the evidence
//! states it in a form pii-eval can represent, weakened to the weakest
//! pii-eval state (`not-established`, observed `unresolved` and so
//! `review-required`) when it cannot be anchored, and every weakening is
//! recorded per variant in the binding document. Protocol semantics, the
//! outcome lattice and the schema are used as they are; where they would need
//! to change, the loss is documented and nothing is changed.
//!
//! Decisions (each is a row of docs/evidence-consumer.md):
//!
//! * identity `valid`/`invalid`/`not-established` map one to one onto
//!   `ExpectedType`;
//! * sensitivity `sensitive`/`non-sensitive` map one to one;
//!   `context-dependent` maps to `not-established` (a recorded flattening);
//! * a fixture span is a located occurrence; a fixture with NO span (every
//!   `derivedFromRule` fixture and every case the evidence leaves unlocated)
//!   becomes a range-less occurrence (ADR 0018), which pii-eval only accepts
//!   with identity and sensitivity `not-established` in a `schema-only` case,
//!   so an authored `invalid`/`non-sensitive` without a span is weakened and
//!   recorded;
//! * located and range-less fixtures of one evidence case are separate
//!   pii-eval cases, so an unlocated variant can never turn the located
//!   variants' accounting into `unresolved`;
//! * the method is `pii-benign` for a located occurrence authored
//!   non-sensitive, `type-validation` for other located occurrences and
//!   `schema-only` for range-less ones; no evidence case is a context trio or
//!   declares competing families, so those methods are not used;
//! * the family comes from a fixed kind table onto pii-eval's neutral family
//!   vocabulary; an unknown kind is refused;
//! * context ids, the phi domain, claims and rationale have no pii-eval field:
//!   they stay in the binding (identity only, no text), not in the corpus;
//! * the action expectation is `not-specified` and the context frame is
//!   `neutral`/`none`: the evidence states neither.

use std::collections::BTreeMap;

use pii_eval_contracts::{
    ActionExpectation, ByteRange, Case, ContextClass, ContextObligation, CorpusSnapshot,
    CorpusSnapshotBody, Derivation, Expectation, ExpectedType, FamilyId, FamilyScope,
    GenerationRules, Id, JurisdictionCode, LanguageTag, Lineage, MethodId, OperatorRef, Population,
    Seed, SensitivityExpectation, Sha256Digest, Strategy, Variant, Visibility, canonical_bytes,
    seal, semantic_digest, to_pretty_json, validate,
};
use serde_json::{Map, Value, json};

use super::model::{CaseRec, FixtureRec, Identity, Sensitivity};
use super::pin::SnapshotPin;
use super::verify::Verified;
use super::{CONTRACT_NAME, CONTRACT_VERSION, EvidenceError, reason};

/// Identity of this mapping rule.
pub const MAPPING_RULE_ID: &str = "pii-evidence-to-corpus";
/// Revision of this mapping rule. A change to any decision below is a new
/// revision and so a new population version.
pub const MAPPING_REVISION: u32 = 1;
/// Population revision this mapping produces.
pub const POPULATION_VERSION: u32 = 1;
/// `schema` of the binding document.
pub const BINDING_SCHEMA: &str = "pii-eval-evidence-binding/1";
/// Digest domain of the binding document.
pub const BINDING_DIGEST_DOMAIN: &str = "pii-eval.evidence-binding/1";
/// Language tag of every mapped case: the evidence states no language and its
/// multibyte variants mix scripts, so the BCP 47 "undetermined" subtag is the
/// honest value.
pub const LANGUAGE: &str = "und";
/// Generator identity recorded in the corpus generation rules.
pub const GENERATOR: &str = "pii-evidence-snapshot-consumer";

/// The closed vocabulary of per-variant losses.
pub mod loss {
    /// An authored `valid`/`invalid` identity became `not-established`
    /// because the evidence states no span.
    pub const IDENTITY_WEAKENED_NO_SPAN: &str = "identity-weakened-no-span";
    /// An authored `sensitive`/`non-sensitive` became `not-established`
    /// because the evidence states no span.
    pub const SENSITIVITY_WEAKENED_NO_SPAN: &str = "sensitivity-weakened-no-span";
    /// `context-dependent` was mapped to `not-established`.
    pub const SENSITIVITY_CONTEXT_FLATTENED: &str = "sensitivity-context-dependent-flattened";
    /// The case names contexts; pii-eval has no field for them.
    pub const CONTEXTS_NOT_CARRIED: &str = "contexts-not-carried";
    /// The case is in the `phi` domain; pii-eval's families are PII-only.
    pub const PHI_DOMAIN_NOT_CARRIED: &str = "phi-domain-not-carried";
    /// Every code, for the documentation check.
    pub const ALL: &[&str] = &[
        IDENTITY_WEAKENED_NO_SPAN,
        SENSITIVITY_WEAKENED_NO_SPAN,
        SENSITIVITY_CONTEXT_FLATTENED,
        CONTEXTS_NOT_CARRIED,
        PHI_DOMAIN_NOT_CARRIED,
    ];
}

/// Evidence kind to pii-eval family. Fixed and versioned with the rule.
const FAMILIES: &[(&str, &str)] = &[
    ("email/global/basic", "pii:global:email"),
    ("phone/global/basic", "pii:global:phone"),
    ("payment-card/global/basic", "pii:global:payment-card"),
    ("iban/global/basic", "pii:global:iban"),
    ("us-ssn/us/structured", "pii:us:ssn"),
    (
        "medical-record-number/us/labeled-field",
        "pii:us:medical-record-number",
    ),
    (
        "health-plan-member-id/us/member-field",
        "pii:us:health-plan-member-id",
    ),
    (
        "health-claim-identifier/us/claim-field",
        "pii:us:health-claim-identifier",
    ),
    (
        "prescription-order-identifier/us/order-field",
        "pii:us:prescription-order-identifier",
    ),
];

/// The result of a mapping.
#[derive(Debug)]
pub struct Mapped {
    /// The sealed corpus snapshot.
    pub snapshot: CorpusSnapshot,
    /// The binding document, with its digest.
    pub binding: Value,
}

fn invalid(code: &'static str, at: impl Into<String>) -> EvidenceError {
    EvidenceError::invalid(code, at)
}

/// `prefix-` followed by 24 hex digits of the domain-separated, length-prefixed
/// SHA-256 of the evidence id (the preimage convention of ADR 0007).
fn derived_id(prefix: &str, tag: &str, evidence_id: &str) -> Result<Id, EvidenceError> {
    let mut preimage = Vec::new();
    for field in ["pii-eval.evidence-id/1", tag, evidence_id] {
        preimage.extend_from_slice(&(field.len() as u32).to_be_bytes());
        preimage.extend_from_slice(field.as_bytes());
    }
    let digest = Sha256Digest::of_bytes(&preimage);
    Id::new(format!("{prefix}-{}", &digest.as_str()[..24]))
        .map_err(|_| invalid(reason::MAPPING_INVALID, evidence_id))
}

fn family_for(case: &CaseRec) -> Result<FamilyId, EvidenceError> {
    let (_, name) = FAMILIES
        .iter()
        .find(|(kind, _)| *kind == case.privacy_kind)
        .ok_or_else(|| invalid(reason::KIND_UNMAPPED, case.id.as_str()))?;
    FamilyId::new(*name).map_err(|_| invalid(reason::MAPPING_INVALID, case.id.as_str()))
}

fn jurisdiction_for(case: &CaseRec) -> Result<Option<JurisdictionCode>, EvidenceError> {
    match case.jurisdiction.as_str() {
        "global" => Ok(None),
        "us" => JurisdictionCode::new("US")
            .map(Some)
            .map_err(|_| invalid(reason::MAPPING_INVALID, case.id.as_str())),
        _ => Err(invalid(reason::JURISDICTION_UNMAPPED, case.id.as_str())),
    }
}

fn type_of(identity: Identity) -> ExpectedType {
    match identity {
        Identity::Valid => ExpectedType::Valid,
        Identity::Invalid => ExpectedType::Invalid,
        Identity::NotEstablished => ExpectedType::NotEstablished,
    }
}

fn sensitivity_of(s: Sensitivity) -> SensitivityExpectation {
    match s {
        Sensitivity::Sensitive => SensitivityExpectation::Sensitive,
        Sensitivity::NonSensitive => SensitivityExpectation::NonSensitive,
        Sensitivity::ContextDependent => SensitivityExpectation::NotEstablished,
    }
}

fn major(version: &str) -> Option<u32> {
    version.split('.').next()?.parse().ok()
}

struct Row {
    value: Value,
}

/// Map a verified snapshot. Pure; never reads a file.
pub fn map(verified: &Verified, pin: &SnapshotPin) -> Result<Mapped, EvidenceError> {
    let case_by_id: BTreeMap<&str, &CaseRec> =
        verified.cases.iter().map(|c| (c.id.as_str(), c)).collect();
    let rule_by_id: BTreeMap<&str, &super::model::RuleRec> =
        verified.rules.iter().map(|r| (r.id.as_str(), r)).collect();

    // Group fixtures under (evidence case, located?).
    let mut groups: BTreeMap<(&str, bool), Vec<&FixtureRec>> = BTreeMap::new();
    for f in &verified.fixtures {
        groups
            .entry((f.case.as_str(), f.spans.len() == 1))
            .or_default()
            .push(f);
    }

    let mut cases: Vec<Case> = Vec::new();
    let mut rows: Vec<Row> = Vec::new();
    let mut losses: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut by_method: BTreeMap<&'static str, (u64, u64)> = BTreeMap::new();
    let mut by_family: BTreeMap<String, (u64, u64)> = BTreeMap::new();

    for ((case_id, located), fixtures) in &groups {
        let case = case_by_id[case_id];
        let family = family_for(case)?;
        let jurisdiction = jurisdiction_for(case)?;
        match (family.scope(), &jurisdiction) {
            (FamilyScope::Global, None) => {}
            (FamilyScope::Jurisdiction(a), Some(b)) if a == *b => {}
            _ => return Err(invalid(reason::JURISDICTION_UNMAPPED, case.id.as_str())),
        }
        let method = if !located {
            MethodId::SchemaOnly
        } else if fixtures
            .iter()
            .all(|f| f.expectation.sensitivity == Sensitivity::NonSensitive)
        {
            MethodId::PiiBenign
        } else {
            MethodId::TypeValidation
        };
        let (tag, prefix) = if *located {
            ("case-located", "ec")
        } else {
            ("case-unlocated", "eu")
        };
        let mut variants: Vec<Variant> = Vec::new();
        for f in fixtures {
            let e = &f.expectation;
            let mut row_losses: Vec<&'static str> = Vec::new();
            let (type_expectation, sensitivity) = if *located {
                (type_of(e.identity), sensitivity_of(e.sensitivity))
            } else {
                if e.identity != Identity::NotEstablished {
                    row_losses.push(loss::IDENTITY_WEAKENED_NO_SPAN);
                }
                if !matches!(e.sensitivity, Sensitivity::ContextDependent) {
                    row_losses.push(loss::SENSITIVITY_WEAKENED_NO_SPAN);
                }
                (
                    ExpectedType::NotEstablished,
                    SensitivityExpectation::NotEstablished,
                )
            };
            if e.sensitivity == Sensitivity::ContextDependent && *located {
                row_losses.push(loss::SENSITIVITY_CONTEXT_FLATTENED);
            }
            if !case.contexts.is_empty() {
                row_losses.push(loss::CONTEXTS_NOT_CARRIED);
            }
            if e.domains.iter().any(|d| d == "phi") {
                row_losses.push(loss::PHI_DOMAIN_NOT_CARRIED);
            }
            let range = f.spans.first().map(|s| ByteRange {
                start: s.start,
                end: s.end,
            });
            let derivation = if e.derived_from_rule {
                let rule = rule_by_id[f.rule.as_str()];
                let operator = Id::new(f.rule.replace('/', "-"))
                    .map_err(|_| invalid(reason::MAPPING_INVALID, f.id.as_str()))?;
                let version = major(&rule.rule_version)
                    .ok_or_else(|| invalid(reason::MAPPING_INVALID, f.id.as_str()))?;
                Derivation {
                    strategy: Strategy::Derived,
                    operator: Some(OperatorRef {
                        id: operator,
                        version,
                    }),
                    seed: None,
                }
            } else {
                Derivation {
                    strategy: Strategy::Authored,
                    operator: None,
                    seed: None,
                }
            };
            let variant_id = derived_id("ev", "fixture", &f.id)?;
            variants.push(Variant {
                variant_id: variant_id.clone(),
                derivation,
                text: f.content.clone(),
                text_digest: Sha256Digest::of_bytes(f.content.as_bytes()),
                expectations: vec![Expectation {
                    occurrence_id: Id::new("occurrence-1")
                        .map_err(|_| invalid(reason::MAPPING_INVALID, f.id.as_str()))?,
                    range,
                    family: family.clone(),
                    type_expectation,
                    validator: None,
                    sensitivity,
                    context_class: ContextClass::Neutral,
                    context_obligation: ContextObligation::None,
                    action: ActionExpectation::NotSpecified,
                }],
            });
            for l in &row_losses {
                *losses.entry(l).or_default() += 1;
            }
            let entry = by_method.entry(method.as_str()).or_default();
            entry.1 += 1;
            let fam = by_family.entry(family.as_str().to_owned()).or_default();
            fam.1 += 1;
            let mut row = Map::new();
            row.insert("variantId".into(), json!(variant_id.as_str()));
            row.insert("evidenceCase".into(), json!(case.id));
            row.insert("evidenceFixture".into(), json!(f.id));
            row.insert(
                "evidenceClass".into(),
                json!(case.provenance.evidence_class),
            );
            row.insert("role".into(), json!(case.role.as_str()));
            row.insert(
                "rule".into(),
                json!({
                    "id": f.rule,
                    "version": f.rule_version,
                    "carrier": {"layout": f.carrier.layout, "variant": f.carrier.variant},
                    "derivedFromRule": e.derived_from_rule,
                }),
            );
            row.insert(
                "authored".into(),
                json!({
                    "identity": e.identity.as_str(),
                    "sensitivity": e.sensitivity.as_str(),
                    "spanEstablished": *located,
                }),
            );
            row.insert(
                "mapped".into(),
                json!({
                    "family": family.as_str(),
                    "method": method.as_str(),
                    "rangeEstablished": *located,
                    "sensitivity": match sensitivity {
                        SensitivityExpectation::Sensitive => "sensitive",
                        SensitivityExpectation::NonSensitive => "non-sensitive",
                        SensitivityExpectation::NotEstablished => "not-established",
                    },
                    "typeExpectation": match type_expectation {
                        ExpectedType::Valid => "valid",
                        ExpectedType::Invalid => "invalid",
                        ExpectedType::NotEstablished => "not-established",
                    },
                }),
            );
            row.insert("domains".into(), json!(e.domains));
            row.insert("contexts".into(), json!(case.contexts));
            row.insert("losses".into(), json!(row_losses));
            rows.push(Row {
                value: Value::Object(row),
            });
        }
        variants.sort_by(|a, b| a.variant_id.cmp(&b.variant_id));
        let case_digest = verified
            .case_line_sha256
            .get(*case_id)
            .ok_or_else(|| invalid(reason::MAPPING_INVALID, *case_id))?;
        let by_m = by_method.entry(method.as_str()).or_default();
        by_m.0 += 1;
        let by_f = by_family.entry(family.as_str().to_owned()).or_default();
        by_f.0 += 1;
        cases.push(Case {
            case_id: derived_id(prefix, tag, case_id)?,
            method,
            lineage: Lineage {
                source_id: derived_id("es", "case", case_id)?,
                source_digest: Sha256Digest::new(case_digest.clone())
                    .map_err(|_| invalid(reason::MAPPING_INVALID, *case_id))?,
            },
            language: LanguageTag::new(LANGUAGE)
                .map_err(|_| invalid(reason::MAPPING_INVALID, *case_id))?,
            jurisdiction,
            collision: None,
            variants,
        });
    }
    if cases.is_empty() {
        return Err(invalid(reason::NOTHING_TO_MAP, "fixtures"));
    }
    cases.sort_by(|a, b| a.case_id.cmp(&b.case_id));
    rows.sort_by(|a, b| {
        a.value["variantId"]
            .as_str()
            .cmp(&b.value["variantId"].as_str())
    });

    let population_id = Id::new(format!(
        "pii-evidence-{}",
        verified.manifest.id.replace('/', "-")
    ))
    .map_err(|_| invalid(reason::MAPPING_INVALID, "population"))?;
    let body = CorpusSnapshotBody {
        population: Population {
            population_id: population_id.clone(),
            population_version: POPULATION_VERSION,
            visibility: Visibility::PublicSynthetic,
        },
        generation: GenerationRules {
            generator: Id::new(GENERATOR)
                .map_err(|_| invalid(reason::MAPPING_INVALID, "generation"))?,
            generator_version: MAPPING_REVISION,
            seed_derivation: Seed::new("none")
                .map_err(|_| invalid(reason::MAPPING_INVALID, "generation"))?,
        },
        cases,
    };
    let mut snapshot = CorpusSnapshot::unsealed(body);
    seal(&mut snapshot).map_err(|_| invalid(reason::MAPPING_INVALID, "snapshot"))?;
    validate(&snapshot).map_err(|_| invalid(reason::MAPPING_INVALID, "snapshot"))?;

    // The binding: what was consumed, what was produced, every decision.
    let located = snapshot
        .semantic
        .cases
        .iter()
        .flat_map(|c| &c.variants)
        .flat_map(|v| &v.expectations)
        .filter(|e| e.range.is_some())
        .count() as u64;
    let occurrences = snapshot.semantic.occurrence_count();
    let carried_cases: std::collections::BTreeSet<&str> = groups.keys().map(|(c, _)| *c).collect();
    let uncarried_cases: Vec<&str> = verified
        .cases
        .iter()
        .map(|c| c.id.as_str())
        .filter(|c| !carried_cases.contains(c))
        .collect();
    let mut doc = Map::new();
    doc.insert("schema".into(), json!(BINDING_SCHEMA));
    doc.insert(
        "mappingRule".into(),
        json!({"id": MAPPING_RULE_ID, "revision": MAPPING_REVISION}),
    );
    doc.insert(
        "evidence".into(),
        json!({
            "contract": {"name": CONTRACT_NAME, "version": CONTRACT_VERSION},
            "snapshotId": verified.manifest.id,
            "snapshotDate": verified.manifest.snapshot_date,
            "contentDigest": verified.manifest.content_digest,
            "manifestSha256": verified.manifest_sha256,
            "sourceManifestDigest": verified.manifest.source_manifest_digest,
            "release": {
                "repository": pin.release.repository,
                "tag": pin.release.tag,
                "commit": pin.release.commit,
            },
            "population": "public",
        }),
    );
    doc.insert(
        "population".into(),
        json!({
            "id": population_id.as_str(),
            "version": POPULATION_VERSION,
            "visibility": "public-synthetic",
            "schemaVersion": snapshot.schema_version.to_string(),
            "semanticDigest": snapshot.semantic_digest.as_str(),
        }),
    );
    doc.insert(
        "counts".into(),
        json!({
            "evidenceCases": verified.cases.len(),
            "evidenceCasesCarried": carried_cases.len(),
            "evidenceCasesWithoutFixtures": uncarried_cases.len(),
            "evidenceFixtures": verified.fixtures.len(),
            "evidenceSkipped": verified.skipped.len(),
            "corpusCases": snapshot.semantic.case_count(),
            "corpusVariants": snapshot.semantic.variant_count(),
            "occurrences": occurrences,
            "locatedOccurrences": located,
            "rangeLessOccurrences": occurrences - located,
        }),
    );
    doc.insert("byMethod".into(), counts_of(&by_method));
    doc.insert("byFamily".into(), counts_of(&by_family));
    doc.insert("losses".into(), json!(losses));
    doc.insert(
        "notCarried".into(),
        json!({
            "casesWithoutFixtures": uncarried_cases,
            "skipped": verified
                .skipped
                .iter()
                .map(|s| json!({"id": s.id, "reason": s.reason}))
                .collect::<Vec<_>>(),
        }),
    );
    doc.insert(
        "rows".into(),
        Value::Array(rows.into_iter().map(|r| r.value).collect()),
    );
    let canonical = canonical_bytes(&Value::Object(doc.clone()))
        .map_err(|_| invalid(reason::MAPPING_INVALID, "binding"))?;
    let digest = semantic_digest(BINDING_DIGEST_DOMAIN, &canonical);
    let mut sealed = Map::new();
    sealed.insert("schema".into(), json!(BINDING_SCHEMA));
    sealed.insert("semanticDigest".into(), json!(digest.as_str()));
    sealed.insert("semantic".into(), Value::Object(doc));
    Ok(Mapped {
        snapshot,
        binding: Value::Object(sealed),
    })
}

fn counts_of<K: AsRef<str>>(m: &BTreeMap<K, (u64, u64)>) -> Value {
    Value::Object(
        m.iter()
            .map(|(k, (cases, variants))| {
                (
                    k.as_ref().to_owned(),
                    json!({"cases": cases, "variants": variants}),
                )
            })
            .collect(),
    )
}

/// The corpus snapshot as pretty JSON (the bytes `pii-eval run` reads).
pub fn snapshot_json(mapped: &Mapped) -> Result<String, EvidenceError> {
    to_pretty_json(&mapped.snapshot).map_err(|_| invalid(reason::MAPPING_INVALID, "snapshot"))
}

/// The binding as pretty JSON with a trailing newline.
pub fn binding_json(mapped: &Mapped) -> Result<String, EvidenceError> {
    serde_json::to_string_pretty(&mapped.binding)
        .map(|s| s + "\n")
        .map_err(|_| invalid(reason::MAPPING_INVALID, "binding"))
}
