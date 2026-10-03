//! Builders for the method tests. Not part of the kernel. Synthetic only.
#![allow(dead_code)]

use pii_eval_contracts::{
    ActionExpectation, ByteRange, ContextClass, ContextObligation, ExpectedType, FamilyId,
    GenerationRules, Id, JurisdictionCode, LanguageTag, Lineage, OperatorRef, Population, Seed,
    SensitivityExpectation, Sha256Digest, ValidatorRef, Visibility,
};
use pii_eval_kernel::methods::{
    AuthoredCase, BenignClass, ContextFrame, MethodParams, ValidatorCheck, ValidatorState,
};

pub fn id(s: &str) -> Id {
    Id::new(s).unwrap()
}

pub fn vref(id_: &str, version: u32) -> ValidatorRef {
    ValidatorRef {
        id: id(id_),
        version,
    }
}

pub fn rules(seed_rule: &str) -> GenerationRules {
    GenerationRules {
        generator: id("synthetic-generator"),
        generator_version: 1,
        seed_derivation: Seed::new(seed_rule).unwrap(),
    }
}

pub fn population() -> Population {
    Population {
        population_id: id("synthetic-population"),
        population_version: 1,
        visibility: Visibility::PublicSynthetic,
    }
}

/// A global email case around `value`, with neutral defaults. Adjust with
/// [`with`].
pub fn authored(case_id: &str, params: MethodParams, prefix: &str, value: &str) -> AuthoredCase {
    authored_in(case_id, params, prefix, value, "")
}

pub fn authored_in(
    case_id: &str,
    params: MethodParams,
    prefix: &str,
    value: &str,
    suffix: &str,
) -> AuthoredCase {
    AuthoredCase {
        case_id: id(case_id),
        lineage: Lineage {
            source_id: id("synthetic-source"),
            source_digest: Sha256Digest::of_bytes(b"synthetic"),
        },
        language: LanguageTag::new("en").unwrap(),
        jurisdiction: None,
        family: FamilyId::new("pii:global:email").unwrap(),
        text: format!("{prefix}{value}{suffix}"),
        candidate: ByteRange {
            start: prefix.len() as u64,
            end: (prefix.len() + value.len()) as u64,
        },
        type_expectation: ExpectedType::Valid,
        validator: None,
        sensitivity: SensitivityExpectation::NotEstablished,
        context_class: ContextClass::Neutral,
        context_obligation: ContextObligation::None,
        action: ActionExpectation::NotSpecified,
        reference: None,
        seed: Seed::new(format!("seed-{case_id}")).unwrap(),
        evidence: None,
        params,
    }
}

pub fn with(mut c: AuthoredCase, f: impl FnOnce(&mut AuthoredCase)) -> AuthoredCase {
    f(&mut c);
    c
}

pub fn us_ssn(c: &mut AuthoredCase) {
    c.family = FamilyId::new("pii:us:ssn").unwrap();
    c.jurisdiction = Some(JurisdictionCode::new("US").unwrap());
}

pub fn frame(
    id_: &str,
    template: &str,
    class: ContextClass,
    sensitivity: SensitivityExpectation,
) -> ContextFrame {
    ContextFrame {
        id: id(id_),
        template: template.to_owned(),
        context_class: class,
        sensitivity,
    }
}

pub fn trio() -> Vec<ContextFrame> {
    vec![
        frame(
            "frame-sensitive",
            "email: {{candidate}}",
            ContextClass::Sensitive,
            SensitivityExpectation::Sensitive,
        ),
        frame(
            "frame-neutral",
            "value = {{candidate}}",
            ContextClass::Neutral,
            SensitivityExpectation::NotEstablished,
        ),
        frame(
            "frame-negative",
            "example {{candidate}}",
            ContextClass::NonSensitive,
            SensitivityExpectation::NonSensitive,
        ),
    ]
}

pub fn context_case(case_id: &str, prefix: &str) -> AuthoredCase {
    with(
        authored(
            case_id,
            MethodParams::ContextDiscrimination { frames: trio() },
            prefix,
            "subject@example.invalid",
        ),
        |c| c.context_obligation = ContextObligation::RequiredForSensitiveClassification,
    )
}

pub fn mod10_case(case_id: &str, value: &str, expected: ExpectedType) -> AuthoredCase {
    with(
        authored(case_id, MethodParams::TypeValidation, "ref=", value),
        |c| {
            c.family = FamilyId::new("pii:global:synthetic-reference").unwrap();
            c.validator = Some(vref("synthetic-mod10", 1));
            c.type_expectation = expected;
        },
    )
}

pub fn benign_case(case_id: &str) -> AuthoredCase {
    with(
        authored(
            case_id,
            MethodParams::PiiBenign {
                class: BenignClass::Placeholder,
                checks: vec![],
            },
            "ref=",
            "SYNTHETIC-0000",
        ),
        |c| {
            c.family = FamilyId::new("pii:global:synthetic-reference").unwrap();
            c.sensitivity = SensitivityExpectation::NonSensitive;
            c.context_class = ContextClass::NonSensitive;
        },
    )
}

pub fn collision_case(case_id: &str) -> AuthoredCase {
    with(
        authored(
            case_id,
            MethodParams::JurisdictionCollision {
                competing: vec![
                    FamilyId::new("pii:kr:national-id").unwrap(),
                    FamilyId::new("pii:global:synthetic-reference").unwrap(),
                ],
                checks: vec![ValidatorCheck {
                    validator: vref("us-ssn-allocation", 1),
                    expected: ValidatorState::Valid,
                }],
            },
            "ssn=",
            "111111111",
        ),
        |c| {
            us_ssn(c);
            c.validator = Some(vref("us-ssn-allocation", 1));
            c.sensitivity = SensitivityExpectation::Sensitive;
            c.context_class = ContextClass::Sensitive;
        },
    )
}

pub fn mutation_case(case_id: &str, prefix: &str, value: &str) -> AuthoredCase {
    with(
        authored(
            case_id,
            MethodParams::Mutation {
                operator: OperatorRef {
                    id: id("invalidate-final-digit"),
                    version: 1,
                },
            },
            prefix,
            value,
        ),
        |c| c.family = FamilyId::new("pii:global:synthetic-reference").unwrap(),
    )
}

pub fn reference_case(case_id: &str, value: &str, reference: ValidatorRef) -> AuthoredCase {
    with(
        authored(case_id, MethodParams::ReferenceDifferential, "ref=", value),
        |c| {
            c.family = FamilyId::new("pii:global:synthetic-reference").unwrap();
            c.reference = Some(reference);
        },
    )
}

pub fn schema_case(case_id: &str) -> AuthoredCase {
    with(
        authored(
            case_id,
            MethodParams::SchemaOnly,
            "contact=",
            "person@example.invalid",
        ),
        |c| {
            c.sensitivity = SensitivityExpectation::NonSensitive;
            c.context_class = ContextClass::NonSensitive;
        },
    )
}

/// One case of every method, valid, ids ascending is not required.
pub fn one_of_each() -> Vec<AuthoredCase> {
    vec![
        schema_case("case-schema"),
        mod10_case("case-typeval", "SYNTHETIC-1236", ExpectedType::Valid),
        context_case("case-context", "value="),
        benign_case("case-benign"),
        collision_case("case-collision"),
        mutation_case("case-mutation", "ref=", "SYNTHETIC-1236"),
        reference_case(
            "case-reference",
            "SYNTHETIC-1236",
            vref("synthetic-mod10", 1),
        ),
    ]
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
