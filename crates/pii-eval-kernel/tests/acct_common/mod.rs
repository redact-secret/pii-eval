//! Builders for the accounting tests. Not part of the kernel. Synthetic only.
#![allow(dead_code)]

use pii_eval_contracts::{
    ActionExpectation, ActionOutcome, ByteRange, Case, CaseOutcome, Collision, ContextClass,
    ContextObligation, CorpusSnapshotBody, Derivation, Expectation, ExpectedType, FamilyId,
    GenerationRules, Id, JurisdictionCode, LanguageTag, Lineage, MethodId, ObservedSummary,
    Population, RangeState, ScannerId, Seed, SensitivityExpectation, SensitivityState,
    Sha256Digest, Strategy, TypeState, Variant, Visibility,
};

pub const TEXT: &str = "aaaa bbbb";

pub struct Occ {
    pub id: &'static str,
    pub ty: ExpectedType,
    pub sens: SensitivityExpectation,
}

pub struct Var {
    pub id: String,
    pub ctx: ContextClass,
    pub occs: Vec<Occ>,
}

pub struct CaseSpec {
    pub id: String,
    pub method: MethodId,
    pub language: &'static str,
    pub jurisdiction: Option<&'static str>,
    pub variants: Vec<Var>,
}

pub fn id(s: &str) -> Id {
    Id::new(s).unwrap()
}

pub fn sid(s: &str) -> ScannerId {
    ScannerId::new(s).unwrap()
}

pub fn occ(id: &'static str, ty: ExpectedType, sens: SensitivityExpectation) -> Occ {
    Occ { id, ty, sens }
}

pub fn var(id: &str, ctx: ContextClass, occs: Vec<Occ>) -> Var {
    Var {
        id: id.to_owned(),
        ctx,
        occs,
    }
}

pub fn case(
    id: &str,
    method: MethodId,
    language: &'static str,
    jurisdiction: Option<&'static str>,
    variants: Vec<Var>,
) -> CaseSpec {
    CaseSpec {
        id: id.to_owned(),
        method,
        language,
        jurisdiction,
        variants,
    }
}

fn family(jurisdiction: Option<&str>) -> FamilyId {
    match jurisdiction {
        Some("US") => FamilyId::new("pii:us:ssn").unwrap(),
        Some(other) => FamilyId::new(format!("pii:{}:id", other.to_lowercase())).unwrap(),
        None => FamilyId::new("pii:global:email").unwrap(),
    }
}

/// A contract-valid snapshot body from compact specs. Cases, variants and
/// occurrences are sorted into canonical order.
pub fn snapshot_body(mut cases: Vec<CaseSpec>) -> CorpusSnapshotBody {
    cases.sort_by(|a, b| a.id.cmp(&b.id));
    let cases = cases
        .into_iter()
        .map(|mut spec| {
            spec.variants.sort_by(|a, b| a.id.cmp(&b.id));
            let fam = family(spec.jurisdiction);
            let variants = spec
                .variants
                .into_iter()
                .map(|mut v| {
                    v.occs.sort_by(|a, b| a.id.cmp(b.id));
                    let expectations = v
                        .occs
                        .iter()
                        .enumerate()
                        .map(|(i, o)| Expectation {
                            occurrence_id: id(o.id),
                            range: ByteRange {
                                start: (i as u64) * 5,
                                end: (i as u64) * 5 + 4,
                            },
                            family: fam.clone(),
                            type_expectation: o.ty,
                            validator: None,
                            sensitivity: o.sens,
                            context_class: v.ctx,
                            context_obligation: ContextObligation::None,
                            action: ActionExpectation::NotSpecified,
                        })
                        .collect();
                    Variant {
                        variant_id: id(&v.id),
                        derivation: Derivation {
                            strategy: Strategy::Authored,
                            operator: None,
                            seed: None,
                        },
                        text: TEXT.to_owned(),
                        text_digest: Sha256Digest::of_bytes(TEXT.as_bytes()),
                        expectations,
                    }
                })
                .collect();
            let collision = (spec.method == MethodId::JurisdictionCollision).then(|| Collision {
                target_family: fam.clone(),
                competing_families: vec![FamilyId::new("pii:global:phone").unwrap()],
            });
            Case {
                case_id: id(&spec.id),
                method: spec.method,
                lineage: Lineage {
                    source_id: id("synthetic-source"),
                    source_digest: Sha256Digest::of_bytes(b"synthetic"),
                },
                language: LanguageTag::new(spec.language).unwrap(),
                jurisdiction: spec.jurisdiction.map(|j| JurisdictionCode::new(j).unwrap()),
                collision,
                variants,
            }
        })
        .collect();
    CorpusSnapshotBody {
        population: Population {
            population_id: id("synthetic-population"),
            population_version: 1,
            visibility: Visibility::PublicSynthetic,
        },
        generation: GenerationRules {
            generator: id("synthetic-generator"),
            generator_version: 1,
            seed_derivation: Seed::new("seed-v1").unwrap(),
        },
        cases,
    }
}

/// `(case, variant, occurrence, type, sensitivity, range)`.
pub type RowSpec = (
    &'static str,
    &'static str,
    &'static str,
    TypeState,
    SensitivityState,
    RangeState,
);

pub fn outcome(
    scanner: &str,
    body: &CorpusSnapshotBody,
    spec: &(
        String,
        String,
        String,
        TypeState,
        SensitivityState,
        RangeState,
    ),
) -> CaseOutcome {
    let method = body
        .cases
        .iter()
        .find(|c| c.case_id.as_str() == spec.0)
        .map(|c| c.method)
        .expect("case exists");
    CaseOutcome {
        scanner_id: sid(scanner),
        case_id: id(&spec.0),
        variant_id: id(&spec.1),
        occurrence_id: id(&spec.2),
        method,
        type_identity: spec.3,
        sensitivity_context: spec.4,
        range: spec.5,
        action: ActionOutcome::NotMeasured,
        observed: ObservedSummary {
            finding_count: 0,
            families: Vec::new(),
            jurisdictions: Vec::new(),
        },
    }
}

pub fn outcomes_of(
    scanner: &str,
    body: &CorpusSnapshotBody,
    specs: &[RowSpec],
) -> Vec<CaseOutcome> {
    specs
        .iter()
        .map(|s| {
            outcome(
                scanner,
                body,
                &(
                    s.0.to_owned(),
                    s.1.to_owned(),
                    s.2.to_owned(),
                    s.3,
                    s.4,
                    s.5,
                ),
            )
        })
        .collect()
}

/// SplitMix64, as in the kernel's other property tests.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            items.swap(i, self.below(i + 1));
        }
    }
}

/// Counts of strata that partition the cases add up to the overall counts,
/// and every accounting identity holds, for every metric and stratum.
pub fn assert_conserved(acc: &pii_eval_kernel::Accounting) {
    for s in &acc.scanners {
        let mut strata = vec![&s.overall];
        strata.extend(s.by_language.iter().map(|(_, x)| x));
        strata.extend(s.by_jurisdiction.iter().map(|(_, x)| x));
        strata.extend(s.by_method.iter().map(|(_, x)| x));
        for x in strata {
            for m in &x.metrics {
                let c = m.counts;
                assert!(c.is_consistent(), "{:?}", m.metric);
                assert_eq!(m.status, c.derived_status());
                assert_eq!(m.to_result().counts, c);
            }
        }
        type Sum = (u64, u64, u64, u64, u64, u64, u64);
        let sums = |group: Vec<&pii_eval_kernel::StratumAccounting>| -> Vec<Sum> {
            (0..10)
                .map(|i| {
                    group.iter().fold((0, 0, 0, 0, 0, 0, 0), |a: Sum, x| {
                        let c = x.metrics[i].counts;
                        (
                            a.0 + c.eligible,
                            a.1 + c.measured,
                            a.2 + c.numerator,
                            a.3 + c.unresolved,
                            a.4 + c.not_measured,
                            a.5 + c.not_applicable,
                            a.6 + c.total,
                        )
                    })
                })
                .collect()
        };
        let overall = sums(vec![&s.overall]);
        assert_eq!(
            overall,
            sums(s.by_language.iter().map(|(_, x)| x).collect())
        );
        assert_eq!(
            overall,
            sums(s.by_jurisdiction.iter().map(|(_, x)| x).collect())
        );
        assert_eq!(overall, sums(s.by_method.iter().map(|(_, x)| x).collect()));
        let cases = |group: Vec<&pii_eval_kernel::StratumAccounting>| -> u64 {
            group.iter().map(|x| x.authored.authored_cases).sum()
        };
        assert_eq!(cases(vec![&s.overall]), acc.authored.authored_cases);
        assert_eq!(
            cases(s.by_language.iter().map(|(_, x)| x).collect()),
            acc.authored.authored_cases
        );
    }
}
