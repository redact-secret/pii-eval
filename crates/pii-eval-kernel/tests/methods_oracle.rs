//! Compatibility of method generation with the pinned oracle.
//!
//! `vectors/oracle_methods.rs` was produced by running the oracle's OWN method
//! code (redact-secret/redact-secret-benchmarks @
//! 4b846967346505baca11e0b98cab1475fbce6773, via
//! `vectors/oracle_methods_driver.mjs`) on synthetic authored cases. Every
//! expected value is therefore what the oracle did, not what this kernel does.
//!
//! The comparison is field by field. Where the Rust kernel differs from the
//! oracle the difference must be one of the classified differences D1 to D7
//! recorded in ADR 0007; an unclassified difference fails the test, and the
//! census test fails if a classified difference stops occurring.

mod meth_common;

use std::collections::BTreeSet;

use meth_common::*;
use pii_eval_contracts::{
    ContextClass, ContextObligation, ExpectedType, FamilyId, JurisdictionCode, LanguageTag,
    MethodId, MethodRef, OperatorRef, SensitivityExpectation, Strategy,
};
use pii_eval_kernel::methods::{
    AuthoredCase, BenignClass, ContextFrame, EvidenceClass, GenerationLimits, Generator,
    MethodParams, RefusalReason, ReviewReason, SEED_RULE_LEGACY, UnavailableReason, ValidatorCheck,
    ValidatorRegistry, ValidatorState,
};

include!("vectors/oracle_methods.rs");

fn etype(s: &str) -> ExpectedType {
    match s {
        "valid" => ExpectedType::Valid,
        "invalid" => ExpectedType::Invalid,
        other => panic!("type {other}"),
    }
}

fn sens(s: &str) -> SensitivityExpectation {
    match s {
        "sensitive" => SensitivityExpectation::Sensitive,
        "non-sensitive" => SensitivityExpectation::NonSensitive,
        "not-established" => SensitivityExpectation::NotEstablished,
        other => panic!("sensitivity {other}"),
    }
}

fn class(s: &str) -> ContextClass {
    match s {
        "sensitive" => ContextClass::Sensitive,
        "neutral" => ContextClass::Neutral,
        "non-sensitive" => ContextClass::NonSensitive,
        other => panic!("class {other}"),
    }
}

fn obligation(s: &str) -> ContextObligation {
    match s {
        "none" => ContextObligation::None,
        "reinforcing" => ContextObligation::Reinforcing,
        "required-for-sensitive-classification" => {
            ContextObligation::RequiredForSensitiveClassification
        }
        other => panic!("obligation {other}"),
    }
}

fn state(s: &str) -> ValidatorState {
    match s {
        "valid" => ValidatorState::Valid,
        "invalid" => ValidatorState::Invalid,
        "unavailable" => ValidatorState::Unavailable,
        other => panic!("state {other}"),
    }
}

fn benign_class(s: &str) -> BenignClass {
    [
        BenignClass::Reserved,
        BenignClass::Documentation,
        BenignClass::TestValue,
        BenignClass::PublicOperational,
        BenignClass::Placeholder,
        BenignClass::ContextNegative,
    ]
    .into_iter()
    .find(|c| c.as_str() == s)
    .unwrap_or_else(|| panic!("benign class {s}"))
}

fn evidence_class(s: &str) -> EvidenceClass {
    [
        EvidenceClass::ReservedDocumentation,
        EvidenceClass::OfficialTest,
        EvidenceClass::PublicIdentifier,
        EvidenceClass::OrdinaryReferenceAccount,
        EvidenceClass::NearMiss,
        EvidenceClass::Placeholder,
        EvidenceClass::ContextNegative,
        EvidenceClass::CrossFamilyCollision,
    ]
    .into_iter()
    .find(|c| c.as_str() == s)
    .unwrap_or_else(|| panic!("evidence class {s}"))
}

/// D7: the oracle's seeds are free-form (`group/1`); the contract's seed alphabet is
/// `[A-Za-z0-9._-]`. Corpus conversion maps `/` to `.`; the seed is a label, so this
/// has no semantic effect.
fn contract_seed(oracle_seed: &str) -> String {
    oracle_seed.replace('/', ".")
}

fn build(o: &OracleCase) -> AuthoredCase {
    let checks: Vec<ValidatorCheck> = o
        .checks
        .iter()
        .map(|(v, ver, exp)| ValidatorCheck {
            validator: vref(v, *ver),
            expected: state(exp),
        })
        .collect();
    let params = match o.method {
        "schema-only" => MethodParams::SchemaOnly,
        "type-validation" => MethodParams::TypeValidation,
        "context-discrimination" => MethodParams::ContextDiscrimination {
            frames: o
                .frames
                .iter()
                .map(|(i, t, c, s)| ContextFrame {
                    id: id(i),
                    template: (*t).to_owned(),
                    context_class: class(c),
                    sensitivity: sens(s),
                })
                .collect(),
        },
        "pii-benign" => MethodParams::PiiBenign {
            class: benign_class(o.accounting_class.expect("benign class")),
            checks,
        },
        "jurisdiction-collision" => MethodParams::JurisdictionCollision {
            competing: o
                .competing
                .iter()
                .map(|f| FamilyId::new(*f).unwrap())
                .collect(),
            checks,
        },
        "mutation" => MethodParams::Mutation {
            operator: OperatorRef {
                id: id(o.operator.expect("operator")),
                version: 1,
            },
        },
        "reference-differential" => MethodParams::ReferenceDifferential,
        other => panic!("method {other}"),
    };
    let mut c = authored(&o.name.replace('/', "-"), params, "", "");
    c.language = LanguageTag::new(o.language).unwrap();
    c.family = FamilyId::new(o.family).unwrap();
    c.jurisdiction = o.jurisdiction.map(|j| JurisdictionCode::new(j).unwrap());
    c.text = o.text.to_owned();
    c.candidate = pii_eval_contracts::ByteRange {
        start: o.start,
        end: o.end,
    };
    c.type_expectation = etype(o.type_expectation);
    c.validator = o.validator.map(|(v, ver)| vref(v, ver));
    c.sensitivity = sens(o.sensitivity);
    c.context_class = class(o.context_class);
    c.context_obligation = obligation(o.context_obligation);
    c.reference = o.reference.map(|(v, ver)| vref(v, ver));
    c.seed = pii_eval_contracts::Seed::new(contract_seed(o.seed)).unwrap();
    c.evidence = o.evidence_class.map(evidence_class);
    c
}

/// The registry the oracle driver used: the two validators plus one that
/// always answers `unavailable`.
fn registry() -> ValidatorRegistry {
    let mut r = ValidatorRegistry::builtin();
    assert!(r.register(pii_eval_kernel::methods::ValidatorDef {
        id: "unavailable-test",
        version: 1,
        validate: |_| ValidatorState::Unavailable,
    }));
    r
}

#[test]
fn the_validators_reproduce_the_oracle_on_every_vector() {
    let reg = ValidatorRegistry::builtin();
    assert!(ORACLE_VALIDATOR_VECTORS.len() >= 30);
    for (validator, input, expected) in ORACLE_VALIDATOR_VECTORS {
        let got = reg.observe(&vref(validator, 1), input);
        assert_eq!(
            got.state.as_str(),
            *expected,
            "{validator} on {} bytes",
            input.len()
        );
        assert!(got.unavailable.is_none());
    }
}

/// Differences found, by code.
#[derive(Default)]
struct Census(BTreeSet<&'static str>);

impl Census {
    fn note(&mut self, code: &'static str) {
        self.0.insert(code);
    }
}

fn compare_variants(
    o: &OracleCase,
    variants: &[OracleVariant],
    competing: &[&str],
    census: &mut Census,
) {
    let reg = registry();
    let g = Generator::new(&rules(SEED_RULE_LEGACY), &reg, GenerationLimits::DEFAULT).unwrap();
    let case = build(o);
    let result = g.generate_case(&case);

    // D2: the oracle accepts any number of frames; the contract requires one per class.
    if o.method == "context-discrimination" && variants.len() != 3 {
        assert_eq!(variants.len(), 8, "{}", o.name);
        assert_eq!(
            result.unwrap_err().reason,
            RefusalReason::ContextFramesNotATrio
        );
        census.note("D2");
        return;
    }
    // D6: the oracle slices bytes and decodes lossily; the kernel validates character boundaries.
    if o.name == "schema-only/mid-character-range" {
        assert_eq!(
            result.unwrap_err().reason,
            RefusalReason::RangeNotOnCharBoundary
        );
        census.note("D6");
        return;
    }
    let generated = result.unwrap_or_else(|r| panic!("{}: refused {}", o.name, r.reason.as_str()));
    assert_eq!(generated.case.variants.len(), variants.len(), "{}", o.name);
    assert_eq!(generated.case.method.as_str(), o.method, "case method");
    for ov in variants {
        let i = generated
            .provenance
            .iter()
            .position(|p| p.slot.as_str() == ov.slot)
            .unwrap_or_else(|| panic!("{}: slot {} missing", o.name, ov.slot));
        let (v, p) = (&generated.case.variants[i], &generated.provenance[i]);
        let e = &v.expectations[0];

        // Identical to the oracle.
        assert_eq!(v.text, ov.text, "{}: text", o.name);
        assert_eq!(
            (e.range.start, e.range.end),
            (ov.start, ov.end),
            "{}: range",
            o.name
        );
        assert_eq!(e.type_expectation, etype(ov.type_expectation), "{}", o.name);
        assert_eq!(e.sensitivity, sens(ov.sensitivity), "{}", o.name);
        assert_eq!(e.context_class, class(ov.context_class), "{}", o.name);
        assert_eq!(p.parent_case_id, case.case_id);
        assert_eq!(
            p.method,
            MethodRef::frozen(case.method()),
            "{}: method version",
            o.name
        );
        assert_eq!(p.method.version, ov.method_version, "{}", o.name);
        // The oracle's `invalidate` effect is the authored type changing.
        assert_eq!(
            ov.type_effect == "invalidate",
            e.type_expectation != case.type_expectation,
            "{}: type effect",
            o.name
        );
        // Strategy: authored/derived agree; review-required agrees.
        let expected_strategy = match ov.strategy {
            "authored" => Strategy::Authored,
            "derived" => Strategy::Derived,
            "review-required" => Strategy::ReviewRequired,
            other => panic!("strategy {other}"),
        };
        assert_eq!(v.derivation.strategy, expected_strategy, "{}", o.name);
        // The oracle's gating of the type axis and reference disposition.
        let unmeasured = p.review.is_some_and(ReviewReason::unmeasures_type_axis);
        assert_eq!(
            ov.outcome_type_state == "not-measured",
            unmeasured,
            "{}: type-axis gating",
            o.name
        );
        if let Some(disposition) = ov.disposition {
            assert_eq!(
                disposition == "review-required",
                p.review.is_some(),
                "{}: reference disposition",
                o.name
            );
        }
        assert_eq!(v.expectations.len(), 1);

        // D1: the oracle's local id is the slot; the kernel's id binds slot and case.
        census.note("D1");
        match expected_strategy {
            Strategy::Derived => {
                // Operator and (legacy rule) seed are the oracle's.
                let op = v.derivation.operator.as_ref().unwrap();
                assert_eq!((op.id.as_str(), op.version), ov.operator, "{}", o.name);
                assert_eq!(
                    v.derivation.seed.as_ref().unwrap().as_str(),
                    contract_seed(ov.seed),
                    "{}: legacy seed",
                    o.name
                );
                census.note("D7");
                // D5: under `pii-seed-v1` the seed is derived, not copied.
                census.note("D5");
            }
            Strategy::Authored => {
                // D4: the oracle records operator `authored` and the case seed; the contract
                // forbids both on an authored variant.
                assert_eq!(ov.operator, ("authored", 1));
                assert!(v.derivation.operator.is_none() && v.derivation.seed.is_none());
                census.note("D4");
            }
            Strategy::ReviewRequired => {
                assert_eq!(ov.operator, ("authored", 1));
                let op = v.derivation.operator.as_ref().unwrap();
                assert_eq!((op.id.as_str(), op.version), ("review-hold", 1));
                census.note("D4");
            }
        }
    }
    if o.method == "jurisdiction-collision" {
        let got: Vec<&str> = generated
            .case
            .collision
            .as_ref()
            .unwrap()
            .competing_families
            .iter()
            .map(|f| f.as_str())
            .collect();
        assert_eq!(got, competing, "{}: competing families", o.name);
    }
}

fn compare_error(o: &OracleCase, message: &str, census: &mut Census) {
    let reg = registry();
    let g = Generator::new(&rules(SEED_RULE_LEGACY), &reg, GenerationLimits::DEFAULT).unwrap();
    let result = g.generate_case(&build(o));
    let refused = |reason: RefusalReason| {
        assert_eq!(
            result.as_ref().unwrap_err().reason,
            reason,
            "{}: {message}",
            o.name
        );
    };
    let reviewed = |review: ReviewReason| {
        let generated = result.as_ref().unwrap_or_else(|r| {
            panic!(
                "{}: refused {} for oracle error {message}",
                o.name,
                r.reason.as_str()
            )
        });
        assert_eq!(generated.provenance[0].review, Some(review), "{}", o.name);
    };
    match message {
        "PII validator expectation mismatch" => {
            refused(RefusalReason::ValidatorExpectationMismatch)
        }
        "Invalid PII benign control" => refused(RefusalReason::NotNonSensitive),
        "PII evidence validator expectation mismatch" => {
            refused(RefusalReason::ValidatorCheckMismatch)
        }
        "Invalid PII jurisdiction collision" => refused(RefusalReason::InvalidCollision),
        "PII mutation needs a final digit" => refused(RefusalReason::OperatorNotApplicable),
        "Unknown PII operator: no-such-operator" => refused(RefusalReason::OperatorUnknown),
        // D3: the oracle throws and aborts the run; the kernel holds the variant for review
        // with an explicit reason and an unmeasured type axis.
        "Unknown PII validator: no-such-validator" if o.method == "type-validation" => {
            reviewed(ReviewReason::ValidatorUnavailable(
                UnavailableReason::UnknownValidator,
            ));
            census.note("D3");
        }
        "Unknown PII validator: no-such-validator" => {
            reviewed(ReviewReason::ReferenceUnavailable(
                UnavailableReason::UnknownValidator,
            ));
            census.note("D3");
        }
        "PII reference version mismatch" => {
            reviewed(ReviewReason::ReferenceUnavailable(
                UnavailableReason::VersionMismatch,
            ));
            census.note("D3");
        }
        other => panic!("{}: unclassified oracle error {other:?}", o.name),
    }
}

#[test]
fn every_oracle_case_is_reproduced_or_has_a_classified_difference() {
    let mut census = Census::default();
    let mut errors = 0;
    let mut methods = BTreeSet::new();
    for o in ORACLE_CASES {
        methods.insert(o.method);
        match &o.expect {
            Expect::Variants {
                variants,
                competing_sorted,
            } => compare_variants(o, variants, competing_sorted, &mut census),
            Expect::Error(message) => {
                errors += 1;
                compare_error(o, message, &mut census);
            }
        }
    }
    // Every method has at least one oracle case, and error paths are exercised.
    assert_eq!(methods.len(), 7);
    assert!(errors >= 8);
    // Each documented difference actually occurs: the list in ADR 0007 is neither stale nor padded.
    let documented: BTreeSet<&str> = ["D1", "D2", "D3", "D4", "D5", "D6", "D7"]
        .into_iter()
        .collect();
    assert_eq!(census.0, documented);
}

#[test]
fn oracle_cases_cover_the_documented_method_behaviours() {
    let names: BTreeSet<&str> = ORACLE_CASES.iter().map(|o| o.name).collect();
    for required in [
        "schema-only/email-probe",
        "type-validation/mod10-valid",
        "type-validation/unavailable",
        "context-discrimination/ko-trio",
        "pii-benign/reserved-ssn",
        "jurisdiction-collision/ssn-collision",
        "mutation/wrap9",
        "mutation/ko-prefix-ssn",
        "reference-differential/disagree",
        "reference-differential/unavailable",
    ] {
        assert!(names.contains(required), "{required}");
    }
    assert_eq!(MethodId::Mutation.as_str(), "mutation");
}
