//! Method generation: one positive and several negative fixtures per method,
//! contract validity, and the exact variants, ranges and identifiers.
//!
//! Hand-calculated expectations. Byte layouts are in the comments. Variant ids
//! and seeds below were computed by an independent Python script
//! (`vectors/ids_reference.py`), not by the code under test.

mod meth_common;

use meth_common::*;
use pii_eval_contracts::axes::OutcomeRow;
use pii_eval_contracts::{
    ActionOutcome, ByteRange, ContextClass, ContextObligation, CorpusSnapshot, Derivation,
    ExpectedType, FamilyId, METHODS, METRICS, MethodId, RangeState, SensitivityExpectation,
    SensitivityState, Strategy, TypeState, seal, validate,
};
use pii_eval_kernel::methods::{
    AuthoredCase, BenignClass, CaseResult, EvidenceClass, GeneratedCase, GenerationLimits,
    GenerationOutput, Generator, GeneratorError, MethodParams, RefusalReason, ReviewReason,
    SEED_RULE_LEGACY, SEED_RULE_V1, SPECS, UnavailableReason, ValidatorCheck, ValidatorDef,
    ValidatorRegistry, ValidatorState, VariantProvenance, apply_review, assemble_body, spec,
};

const V1: &str = SEED_RULE_V1;

fn builtin() -> ValidatorRegistry {
    ValidatorRegistry::builtin()
}

fn generate(case: &AuthoredCase) -> Result<GeneratedCase, RefusalReason> {
    let reg = builtin();
    let g = Generator::new(&rules(V1), &reg, GenerationLimits::DEFAULT).unwrap();
    g.generate_case(case).map_err(|r| r.reason)
}

fn ok(case: &AuthoredCase) -> GeneratedCase {
    generate(case).unwrap_or_else(|r| panic!("refused: {}", r.as_str()))
}

fn by_slot<'a>(
    g: &'a GeneratedCase,
    slot: &str,
) -> (&'a pii_eval_contracts::Variant, &'a VariantProvenance) {
    let i = g
        .provenance
        .iter()
        .position(|p| p.slot.as_str() == slot)
        .unwrap_or_else(|| panic!("no slot {slot}"));
    (&g.case.variants[i], &g.provenance[i])
}

fn refused(case: &AuthoredCase) -> RefusalReason {
    generate(case).expect_err("must be refused")
}

// ---------------------------------------------------------------------------
// The definitions
// ---------------------------------------------------------------------------

#[test]
fn the_method_table_is_pinned_to_the_frozen_registry() {
    assert_eq!(SPECS.len(), METHODS.len());
    for (s, m) in SPECS.iter().zip(METHODS.iter()) {
        assert_eq!((s.id, s.version), (m.id, m.version));
        assert_eq!(spec(m.id).id, m.id);
        assert_eq!(spec(m.id), s);
    }
    // The restricted metrics and their methods agree with the metric registry.
    for metric in METRICS {
        let owners: Vec<MethodId> = SPECS
            .iter()
            .filter(|s| s.restricted_metric == Some(metric.id))
            .map(|s| s.id)
            .collect();
        match metric.restricted_to_method {
            Some(method) => assert_eq!(owners, vec![method], "{:?}", metric.id),
            None => assert!(owners.is_empty(), "{:?}", metric.id),
        }
    }
}

#[test]
fn schema_only_never_supports_a_runtime_accuracy_statement() {
    assert!(!spec(MethodId::SchemaOnly).runtime_accuracy_evidence);
    let methods = pii_eval_kernel::methods::runtime_accuracy_methods();
    assert_eq!(methods.len(), 6);
    assert!(!methods.contains(&MethodId::SchemaOnly));
    let wire: Vec<&str> = methods.iter().map(|m| m.as_str()).collect();
    let mut sorted = wire.clone();
    sorted.sort();
    assert_eq!(wire, sorted);
}

// ---------------------------------------------------------------------------
// schema-only
// ---------------------------------------------------------------------------

#[test]
fn schema_only_derives_the_authored_variant_unchanged() {
    // "contact=person@example.invalid": 8 bytes of prefix, 22 of candidate.
    let c = schema_case("case-schema");
    let g = ok(&c);
    assert_eq!(g.case.method, MethodId::SchemaOnly);
    assert_eq!(g.case.variants.len(), 1);
    let (v, p) = by_slot(&g, "authored");
    // Independently computed: authored + sha256(preimage(["pii-eval.variant-id/1","case-schema","authored"])).
    assert_eq!(v.variant_id.as_str(), "authored-812448d38d24f8fd81172836");
    assert_eq!(v.text, c.text);
    assert_eq!(v.expectations.len(), 1);
    let e = &v.expectations[0];
    assert_eq!(e.range, ByteRange { start: 8, end: 30 });
    assert_eq!(e.type_expectation, ExpectedType::Valid);
    assert_eq!(e.sensitivity, SensitivityExpectation::NonSensitive);
    assert_eq!(
        v.derivation,
        Derivation {
            strategy: Strategy::Authored,
            operator: None,
            seed: None
        }
    );
    assert_eq!(p.parent_case_id.as_str(), "case-schema");
    assert_eq!(p.method.version, 1);
    assert!(p.review.is_none() && p.validation.is_none() && p.reference.is_none());
}

#[test]
fn schema_only_refuses_bad_ranges_and_scopes() {
    let base = schema_case("case-schema");
    let r = |f: &dyn Fn(&mut AuthoredCase)| refused(&with(base.clone(), |c| f(c)));
    assert_eq!(
        r(&|c| c.candidate = ByteRange { start: 8, end: 8 }),
        RefusalReason::RangeInvalid
    );
    assert_eq!(
        r(&|c| c.candidate = ByteRange { start: 9, end: 8 }),
        RefusalReason::RangeInvalid
    );
    assert_eq!(
        r(&|c| c.candidate = ByteRange { start: 8, end: 31 }),
        RefusalReason::RangeOutOfBounds
    );
    // "연락처=x": 연 is bytes 0..3; a range starting at byte 1 is mid-character.
    assert_eq!(
        refused(&with(base.clone(), |c| {
            c.text = "연락처=x".to_owned();
            c.candidate = ByteRange { start: 1, end: 10 };
        })),
        RefusalReason::RangeNotOnCharBoundary
    );
    assert_eq!(
        r(&|c| c.jurisdiction = Some(pii_eval_contracts::JurisdictionCode::new("US").unwrap())),
        RefusalReason::FamilyScopeMismatch
    );
    assert_eq!(
        r(&|c| c.family = FamilyId::new("pii:us:ssn").unwrap()),
        RefusalReason::FamilyScopeMismatch
    );
}

#[test]
fn text_limits_refuse_instead_of_truncating() {
    let reg = builtin();
    let limits = GenerationLimits {
        max_text_bytes: 20,
        ..GenerationLimits::DEFAULT
    };
    let g = Generator::new(&rules(V1), &reg, limits).unwrap();
    let c = schema_case("case-schema"); // 30 bytes
    assert_eq!(
        g.generate_case(&c).unwrap_err().reason,
        RefusalReason::TextTooLarge
    );
}

// ---------------------------------------------------------------------------
// type-validation
// ---------------------------------------------------------------------------

#[test]
fn type_validation_confirms_the_authored_type_with_the_validator() {
    // SYNTHETIC-1236: 1+2+3 = 6, last digit 6: valid. SYNTHETIC-1237: invalid.
    let valid = ok(&mod10_case(
        "case-typeval",
        "SYNTHETIC-1236",
        ExpectedType::Valid,
    ));
    let (v, p) = by_slot(&valid, "validated");
    assert_eq!(v.variant_id.as_str(), "validated-cb0f1e62b4acf0efed904dd2");
    assert_eq!(v.derivation.strategy, Strategy::Authored);
    assert_eq!(p.method.version, 2);
    let o = p.validation.as_ref().unwrap();
    assert_eq!((o.state, o.unavailable), (ValidatorState::Valid, None));
    assert!(p.review.is_none());
    assert_eq!(
        v.expectations[0].validator.as_ref().unwrap().id.as_str(),
        "synthetic-mod10"
    );

    let invalid = ok(&mod10_case(
        "case-typeval",
        "SYNTHETIC-1237",
        ExpectedType::Invalid,
    ));
    let (v, p) = by_slot(&invalid, "validated");
    assert_eq!(v.expectations[0].type_expectation, ExpectedType::Invalid);
    assert_eq!(
        p.validation.as_ref().unwrap().state,
        ValidatorState::Invalid
    );
}

#[test]
fn type_validation_never_edits_an_authored_expectation_to_match_a_validator() {
    // The validator says invalid; the author said valid: an authoring defect.
    let c = mod10_case("case-typeval", "SYNTHETIC-1237", ExpectedType::Valid);
    assert_eq!(refused(&c), RefusalReason::ValidatorExpectationMismatch);
    let c = mod10_case("case-typeval", "SYNTHETIC-1236", ExpectedType::Invalid);
    assert_eq!(refused(&c), RefusalReason::ValidatorExpectationMismatch);
    let c = with(
        mod10_case("case-typeval", "SYNTHETIC-1236", ExpectedType::Valid),
        |c| c.validator = None,
    );
    assert_eq!(refused(&c), RefusalReason::MissingValidator);
}

#[test]
fn an_unavailable_validator_is_a_review_state_with_an_unmeasured_type_axis() {
    let reasons = [
        (
            vref("no-such-validator", 1),
            UnavailableReason::UnknownValidator,
        ),
        (
            vref("synthetic-mod10", 2),
            UnavailableReason::VersionMismatch,
        ),
    ];
    for (validator, reason) in reasons {
        let c = with(
            mod10_case("case-typeval", "SYNTHETIC-1236", ExpectedType::Valid),
            |c| c.validator = Some(validator.clone()),
        );
        let g = ok(&c);
        let (v, p) = by_slot(&g, "validated");
        assert_eq!(v.derivation.strategy, Strategy::ReviewRequired);
        let op = v.derivation.operator.as_ref().unwrap();
        assert_eq!((op.id.as_str(), op.version), ("review-hold", 1));
        assert!(v.derivation.seed.is_none());
        assert_eq!(p.review, Some(ReviewReason::ValidatorUnavailable(reason)));
        let o = p.validation.as_ref().unwrap();
        assert_eq!(o.state, ValidatorState::Unavailable);
        assert_eq!(o.unavailable, Some(reason));
        // The authored expectation is untouched.
        assert_eq!(v.expectations[0].type_expectation, ExpectedType::Valid);

        // A scanner that found the value correctly still cannot make the type
        // axis a pass: it is not-measured; the other axes are untouched.
        let row = OutcomeRow {
            type_identity: TypeState::Correct,
            sensitivity_context: SensitivityState::Unresolved,
            range: RangeState::Exact,
            action: ActionOutcome::NotMeasured,
        };
        let gated = apply_review(row, p.review);
        assert_eq!(gated.type_identity, TypeState::NotMeasured);
        assert_eq!(gated.sensitivity_context, SensitivityState::Unresolved);
        assert_eq!(gated.range, RangeState::Exact);
    }
}

#[test]
fn an_empty_registry_and_a_declining_validator_are_also_unavailable() {
    let c = mod10_case("case-typeval", "SYNTHETIC-1236", ExpectedType::Valid);
    let empty = ValidatorRegistry::empty();
    let g = Generator::new(&rules(V1), &empty, GenerationLimits::DEFAULT).unwrap();
    let out = g.generate_case(&c).unwrap();
    assert_eq!(
        out.provenance[0].review,
        Some(ReviewReason::ValidatorUnavailable(
            UnavailableReason::UnknownValidator
        ))
    );

    let mut reg = builtin();
    assert!(reg.register(ValidatorDef {
        id: "declining",
        version: 1,
        validate: |_| ValidatorState::Unavailable,
    }));
    assert!(!reg.register(ValidatorDef {
        id: "declining",
        version: 9,
        validate: |_| ValidatorState::Valid,
    }));
    let g = Generator::new(&rules(V1), &reg, GenerationLimits::DEFAULT).unwrap();
    let c = with(c, |c| c.validator = Some(vref("declining", 1)));
    let out = g.generate_case(&c).unwrap();
    assert_eq!(
        out.provenance[0].review,
        Some(ReviewReason::ValidatorUnavailable(
            UnavailableReason::ValidatorDeclined
        ))
    );
}

#[test]
fn type_validation_runs_the_us_ssn_validator_on_a_jurisdictional_case() {
    let c = with(
        authored(
            "case-ssn",
            MethodParams::TypeValidation,
            "ssn=",
            "666123456",
        ),
        |c| {
            us_ssn(c);
            c.validator = Some(vref("us-ssn-allocation", 1));
            c.type_expectation = ExpectedType::Invalid;
        },
    );
    let g = ok(&c);
    assert_eq!(g.case.jurisdiction.as_ref().unwrap().as_str(), "US");
    assert_eq!(
        g.provenance[0].validation.as_ref().unwrap().state,
        ValidatorState::Invalid
    );
}

// ---------------------------------------------------------------------------
// context-discrimination
// ---------------------------------------------------------------------------

#[test]
fn context_discrimination_derives_one_variant_per_frame() {
    // value = "subject@example.invalid" (7+1+7+1+7 = 23 bytes).
    //   "email: " (7)  + value -> [7, 30)
    //   "value = " (8) + value -> [8, 31)
    //   "example " (8) + value -> [8, 31)
    let g = ok(&context_case("case-context", "value="));
    assert_eq!(g.case.variants.len(), 3);
    assert!(
        g.case
            .variants
            .windows(2)
            .all(|w| w[0].variant_id < w[1].variant_id)
    );
    let expect = [
        (
            "frame-sensitive",
            "email: subject@example.invalid",
            7,
            ContextClass::Sensitive,
            SensitivityExpectation::Sensitive,
            "frame-sensitive-42393028a5745321b097d782",
        ),
        (
            "frame-neutral",
            "value = subject@example.invalid",
            8,
            ContextClass::Neutral,
            SensitivityExpectation::NotEstablished,
            "frame-neutral-c711b6aa30cd6e2063453db2",
        ),
        (
            "frame-negative",
            "example subject@example.invalid",
            8,
            ContextClass::NonSensitive,
            SensitivityExpectation::NonSensitive,
            "frame-negative-f5b1912b5d0882a06ee3dbcb",
        ),
    ];
    for (slot, text, start, class, sens, id) in expect {
        let (v, p) = by_slot(&g, slot);
        assert_eq!(v.variant_id.as_str(), id);
        assert_eq!(v.text, text);
        let e = &v.expectations[0];
        assert_eq!(
            e.range,
            ByteRange {
                start,
                end: start + 23
            }
        );
        assert_eq!(
            &v.text[start as usize..(start + 23) as usize],
            "subject@example.invalid"
        );
        assert_eq!((e.context_class, e.sensitivity), (class, sens));
        assert_eq!(e.type_expectation, ExpectedType::Valid);
        assert_eq!(
            e.context_obligation,
            ContextObligation::RequiredForSensitiveClassification
        );
        assert_eq!(v.derivation.strategy, Strategy::Derived);
        let op = v.derivation.operator.as_ref().unwrap();
        assert_eq!((op.id.as_str(), op.version), ("context-frame", 1));
        assert!(v.derivation.seed.is_some());
        assert_eq!(p.method.version, 2);
    }
    // pii-seed-v1: sha256(preimage(["pii-eval.variant-seed/1","synthetic-generator","1",
    //   "seed-case-context","case-context","frame-sensitive"])), computed in Python.
    let (v, _) = by_slot(&g, "frame-sensitive");
    assert_eq!(
        v.derivation.seed.as_ref().unwrap().as_str(),
        "99c8b0aa8fff45d2490b95052fc37e1053e387c510e63c8578df8a062ca0fb3f"
    );
}

#[test]
fn context_frames_keep_korean_byte_offsets() {
    // "이메일: " = 이메일 (9 bytes) + ":" + " " = 11 bytes, so the candidate is [11, 34).
    let mut c = context_case("case-context", "값=");
    c.language = pii_eval_contracts::LanguageTag::new("ko").unwrap();
    if let MethodParams::ContextDiscrimination { frames } = &mut c.params {
        frames[0].template = "이메일: {{candidate}}".to_owned();
    }
    let g = ok(&c);
    let (v, _) = by_slot(&g, "frame-sensitive");
    assert_eq!(v.expectations[0].range, ByteRange { start: 11, end: 34 });
    assert_eq!(v.text.len(), 34);
    assert!(v.text.is_char_boundary(11));
}

#[test]
fn context_discrimination_refuses_incomplete_or_malformed_trios() {
    let base = context_case("case-context", "value=");
    let frames = |f: &dyn Fn(&mut Vec<pii_eval_kernel::methods::ContextFrame>)| {
        with(base.clone(), |c| {
            if let MethodParams::ContextDiscrimination { frames } = &mut c.params {
                f(frames);
            }
        })
    };
    assert_eq!(
        refused(&frames(&|f| {
            f.pop();
        })),
        RefusalReason::ContextFramesNotATrio
    );
    assert_eq!(
        refused(&frames(&|f| f[2].context_class = ContextClass::Neutral)),
        RefusalReason::ContextFramesNotATrio
    );
    // More than three frames is a complete trio (ADR 0008 R5: at least one frame per class; the
    // oracle's real groups hold 8 and 11 frames). A group that lost a class stays refused (above).
    let four = ok(&frames(&|f| {
        let mut extra = f[0].clone();
        extra.id = id("frame-sensitive-two");
        extra.template = "also: {{candidate}}".to_owned();
        f.push(extra);
    }));
    assert_eq!(four.case.variants.len(), 4);
    assert_eq!(
        refused(&frames(&|f| f[0].template = "no marker".to_owned())),
        RefusalReason::FrameTemplateInvalid
    );
    assert_eq!(
        refused(&frames(
            &|f| f[0].template = "{{candidate}} and {{candidate}}".to_owned()
        )),
        RefusalReason::FrameTemplateInvalid
    );
    assert_eq!(
        refused(&frames(
            &|f| f[0].sensitivity = SensitivityExpectation::NonSensitive
        )),
        RefusalReason::FrameExpectationMismatch
    );
    assert_eq!(
        refused(&frames(&|f| f[1].id = id(&"x".repeat(60)))),
        RefusalReason::SlotInvalid
    );
    assert_eq!(
        refused(&with(base.clone(), |c| c.type_expectation = ExpectedType::Invalid)),
        RefusalReason::ContextCaseInvalid
    );
    assert_eq!(
        refused(&with(base.clone(), |c| c.context_obligation =
            ContextObligation::None)),
        RefusalReason::ContextCaseInvalid
    );
}

#[test]
fn context_discrimination_refuses_a_case_over_the_per_case_variant_limit() {
    let reg = builtin();
    let limits = GenerationLimits {
        max_variants_per_case: 2,
        batch_variants: 2,
        ..GenerationLimits::DEFAULT
    };
    let g = Generator::new(&rules(V1), &reg, limits).unwrap();
    let r = g
        .generate_case(&context_case("case-context", "value="))
        .unwrap_err();
    assert_eq!(r.reason, RefusalReason::TooManyVariants);
}

// ---------------------------------------------------------------------------
// pii-benign
// ---------------------------------------------------------------------------

#[test]
fn pii_benign_derives_the_authored_control_in_its_accounting_class_slot() {
    let g = ok(&benign_case("case-benign"));
    let (v, p) = by_slot(&g, "placeholder");
    assert_eq!(
        v.variant_id.as_str(),
        "placeholder-1dbe0073278a6cc5bea90379"
    );
    assert_eq!(v.derivation.strategy, Strategy::Authored);
    assert_eq!(
        v.expectations[0].sensitivity,
        SensitivityExpectation::NonSensitive
    );
    assert_eq!(p.method.version, 3);

    // A reserved SSN control: the authored validator expectation (invalid) is confirmed.
    let c = with(benign_case("case-benign-ssn"), |c| {
        us_ssn(c);
        c.text = "ssn=000000000".to_owned();
        c.candidate = ByteRange { start: 4, end: 13 };
        c.type_expectation = ExpectedType::Invalid;
        c.evidence = Some(EvidenceClass::ReservedDocumentation);
        c.params = MethodParams::PiiBenign {
            class: BenignClass::Reserved,
            checks: vec![ValidatorCheck {
                validator: vref("us-ssn-allocation", 1),
                expected: ValidatorState::Invalid,
            }],
        };
    });
    let g = ok(&c);
    assert_eq!(g.provenance[0].slot.as_str(), "reserved");
    // The authored evidence class travels with the provenance (schema 1.0 does not carry it).
    assert_eq!(
        g.provenance[0].evidence,
        Some(EvidenceClass::ReservedDocumentation)
    );
}

#[test]
fn pii_benign_refuses_what_is_not_a_benign_control() {
    let sensitive = with(benign_case("case-benign"), |c| {
        c.sensitivity = SensitivityExpectation::Sensitive
    });
    assert_eq!(refused(&sensitive), RefusalReason::NotNonSensitive);
    let not_established = with(benign_case("case-benign"), |c| {
        c.sensitivity = SensitivityExpectation::NotEstablished
    });
    assert_eq!(refused(&not_established), RefusalReason::NotNonSensitive);

    // Evidence class and accounting class must agree (placeholder evidence cannot be `test-value`).
    let wrong_class = with(benign_case("case-benign"), |c| {
        c.evidence = Some(EvidenceClass::OfficialTest)
    });
    assert_eq!(refused(&wrong_class), RefusalReason::EvidenceRoleMismatch);
    // Near misses and collisions are other methods' evidence.
    for e in [EvidenceClass::NearMiss, EvidenceClass::CrossFamilyCollision] {
        let c = with(benign_case("case-benign"), |c| c.evidence = Some(e));
        assert_eq!(refused(&c), RefusalReason::EvidenceRoleMismatch);
    }

    let mismatch = with(benign_case("case-benign"), |c| {
        c.params = MethodParams::PiiBenign {
            class: BenignClass::Placeholder,
            checks: vec![ValidatorCheck {
                validator: vref("synthetic-mod10", 1),
                expected: ValidatorState::Invalid, // SYNTHETIC-0000 is valid
            }],
        };
    });
    assert_eq!(refused(&mismatch), RefusalReason::ValidatorCheckMismatch);

    let unavailable = with(benign_case("case-benign"), |c| {
        c.params = MethodParams::PiiBenign {
            class: BenignClass::Placeholder,
            checks: vec![ValidatorCheck {
                validator: vref("no-such-validator", 1),
                expected: ValidatorState::Valid,
            }],
        };
    });
    assert_eq!(
        refused(&unavailable),
        RefusalReason::ValidatorCheckUnavailable
    );

    // An authored expectation of `unavailable` is confirmed by an unavailable observation.
    let confirmed = with(benign_case("case-benign"), |c| {
        c.params = MethodParams::PiiBenign {
            class: BenignClass::Placeholder,
            checks: vec![ValidatorCheck {
                validator: vref("no-such-validator", 1),
                expected: ValidatorState::Unavailable,
            }],
        };
    });
    ok(&confirmed);
}

// ---------------------------------------------------------------------------
// jurisdiction-collision
// ---------------------------------------------------------------------------

#[test]
fn jurisdiction_collision_declares_ordered_unique_competitors() {
    let g = ok(&collision_case("case-collision"));
    let collision = g.case.collision.as_ref().unwrap();
    assert_eq!(collision.target_family.as_str(), "pii:us:ssn");
    let competing: Vec<&str> = collision
        .competing_families
        .iter()
        .map(|f| f.as_str())
        .collect();
    assert_eq!(
        competing,
        ["pii:global:synthetic-reference", "pii:kr:national-id"]
    );
    let (v, p) = by_slot(&g, "collision");
    assert_eq!(v.variant_id.as_str(), "collision-05d24dd0c649f64a136ffc8b");
    assert_eq!(v.expectations[0].family, collision.target_family);
    assert_eq!(p.method.version, 3);

    // Duplicates in the authored list collapse; the order is canonical.
    let dup = with(collision_case("case-collision"), |c| {
        c.params = MethodParams::JurisdictionCollision {
            competing: vec![
                FamilyId::new("pii:kr:national-id").unwrap(),
                FamilyId::new("pii:kr:national-id").unwrap(),
            ],
            checks: vec![],
        };
    });
    assert_eq!(ok(&dup).case.collision.unwrap().competing_families.len(), 1);
}

#[test]
fn jurisdiction_collision_refuses_invalid_declarations() {
    let with_competing = |competing: Vec<FamilyId>| {
        with(collision_case("case-collision"), |c| {
            c.params = MethodParams::JurisdictionCollision {
                competing,
                checks: vec![],
            }
        })
    };
    assert_eq!(
        refused(&with_competing(vec![])),
        RefusalReason::InvalidCollision
    );
    assert_eq!(
        refused(&with_competing(vec![FamilyId::new("pii:us:ssn").unwrap()])),
        RefusalReason::InvalidCollision
    );
    let many: Vec<FamilyId> = (0..33)
        .map(|i| FamilyId::new(format!("pii:global:family-{i}")).unwrap())
        .collect();
    assert_eq!(
        refused(&with_competing(many)),
        RefusalReason::InvalidCollision
    );

    let wrong_evidence = with(collision_case("case-collision"), |c| {
        c.evidence = Some(EvidenceClass::ReservedDocumentation)
    });
    assert_eq!(
        refused(&wrong_evidence),
        RefusalReason::EvidenceRoleMismatch
    );
    // Cross-family evidence must check the target and every competitor (3 parties here).
    let evidenced = |checks: usize| {
        with(collision_case("case-collision"), |c| {
            c.evidence = Some(EvidenceClass::CrossFamilyCollision);
            if let MethodParams::JurisdictionCollision { checks: ch, .. } = &mut c.params {
                let one = ch[0].clone();
                *ch = vec![one; checks];
            }
        })
    };
    assert_eq!(refused(&evidenced(0)), RefusalReason::MissingEvidenceChecks);
    assert_eq!(refused(&evidenced(2)), RefusalReason::MissingEvidenceChecks);
    ok(&evidenced(3));

    // The target validator expectation is contradicted by the observation.
    let mismatch = with(collision_case("case-collision"), |c| {
        c.params = MethodParams::JurisdictionCollision {
            competing: vec![FamilyId::new("pii:kr:national-id").unwrap()],
            checks: vec![ValidatorCheck {
                validator: vref("us-ssn-allocation", 1),
                expected: ValidatorState::Invalid,
            }],
        };
    });
    assert_eq!(refused(&mismatch), RefusalReason::ValidatorCheckMismatch);
}

// ---------------------------------------------------------------------------
// mutation
// ---------------------------------------------------------------------------

#[test]
fn mutation_invalidates_the_final_digit_and_derives_a_seeded_variant() {
    // SYNTHETIC-1236 -> SYNTHETIC-1237; "ref=" is 4 bytes, the candidate is 14: [4, 18).
    let g = ok(&mutation_case("case-mutation", "ref=", "SYNTHETIC-1236"));
    let (v, p) = by_slot(&g, "mutated");
    assert_eq!(v.variant_id.as_str(), "mutated-26d2db97da61c3ac7875063e");
    assert_eq!(v.text, "ref=SYNTHETIC-1237");
    let e = &v.expectations[0];
    assert_eq!(e.range, ByteRange { start: 4, end: 18 });
    assert_eq!(e.type_expectation, ExpectedType::Invalid);
    assert_eq!(e.sensitivity, SensitivityExpectation::NotEstablished);
    assert_eq!(v.derivation.strategy, Strategy::Derived);
    let op = v.derivation.operator.as_ref().unwrap();
    assert_eq!((op.id.as_str(), op.version), ("invalidate-final-digit", 1));
    assert_eq!(
        v.derivation.seed.as_ref().unwrap().as_str(),
        "271e1a8829bff2ffbc986ae6ab72565c283c0ea44347b86076dd6d5da8c6990a"
    );
    assert_eq!(p.method.version, 1);
    assert_eq!(p.seed, v.derivation.seed);
}

#[test]
fn mutation_wraps_nine_and_keeps_multibyte_offsets() {
    // 9 -> 0 (mod 10).
    let g = ok(&mutation_case("case-mutation", "ref=", "SYNTHETIC-1239"));
    assert_eq!(g.case.variants[0].text, "ref=SYNTHETIC-1230");
    // "번호=" = 6 + 1 bytes; the 9-digit candidate is [7, 16); 111111119 -> 111111110.
    let c = with(
        mutation_case("case-mutation", "번호=", "111111119"),
        |c| c.family = FamilyId::new("pii:global:email").unwrap(),
    );
    let g = ok(&c);
    let v = &g.case.variants[0];
    assert_eq!(v.text, "번호=111111110");
    assert_eq!(v.expectations[0].range, ByteRange { start: 7, end: 16 });
    // An already-invalid authored type stays invalid.
    let c = with(
        mutation_case("case-mutation", "ref=", "SYNTHETIC-1237"),
        |c| c.type_expectation = ExpectedType::Invalid,
    );
    assert_eq!(
        ok(&c).case.variants[0].expectations[0].type_expectation,
        ExpectedType::Invalid
    );
}

#[test]
fn mutation_refuses_what_it_cannot_apply() {
    let no_digit = mutation_case("case-mutation", "contact=", "person@example.invalid");
    assert_eq!(refused(&no_digit), RefusalReason::OperatorNotApplicable);
    let unknown = with(
        mutation_case("case-mutation", "ref=", "SYNTHETIC-1236"),
        |c| {
            c.params = MethodParams::Mutation {
                operator: pii_eval_contracts::OperatorRef {
                    id: id("no-such-operator"),
                    version: 1,
                },
            }
        },
    );
    assert_eq!(refused(&unknown), RefusalReason::OperatorUnknown);
    let version = with(
        mutation_case("case-mutation", "ref=", "SYNTHETIC-1236"),
        |c| {
            c.params = MethodParams::Mutation {
                operator: pii_eval_contracts::OperatorRef {
                    id: id("invalidate-final-digit"),
                    version: 2,
                },
            }
        },
    );
    assert_eq!(refused(&version), RefusalReason::OperatorVersionMismatch);
}

// ---------------------------------------------------------------------------
// reference-differential
// ---------------------------------------------------------------------------

#[test]
fn a_reference_that_agrees_is_recorded_and_changes_nothing() {
    let g = ok(&reference_case(
        "case-reference",
        "SYNTHETIC-1236",
        vref("synthetic-mod10", 1),
    ));
    let (v, p) = by_slot(&g, "reference");
    assert_eq!(v.variant_id.as_str(), "reference-b38abee8ece5c7dbc45bfc0c");
    assert_eq!(v.derivation.strategy, Strategy::Authored);
    assert!(p.review.is_none());
    let o = &p.reference.as_ref().unwrap().observation;
    assert_eq!(o.state, ValidatorState::Valid);
    assert_eq!(
        pii_eval_kernel::methods::REFERENCE_ROLE,
        "observation-not-truth"
    );
}

#[test]
fn reference_disagreement_is_an_observation_never_replacement_truth() {
    // The author says valid; the reference observes invalid.
    let c = reference_case(
        "case-reference",
        "SYNTHETIC-1237",
        vref("synthetic-mod10", 1),
    );
    let g = ok(&c);
    let (v, p) = by_slot(&g, "reference");
    assert_eq!(p.review, Some(ReviewReason::ReferenceDisagrees));
    assert_eq!(
        p.reference.as_ref().unwrap().observation.state,
        ValidatorState::Invalid
    );
    // The authored expectation stands.
    assert_eq!(v.expectations[0].type_expectation, ExpectedType::Valid);
    assert_eq!(v.derivation.strategy, Strategy::Authored);
    // A disagreement does not unmeasure the type axis: it is recorded, not scored.
    assert!(!ReviewReason::ReferenceDisagrees.unmeasures_type_axis());
    let row = OutcomeRow {
        type_identity: TypeState::Correct,
        sensitivity_context: SensitivityState::Unresolved,
        range: RangeState::Exact,
        action: ActionOutcome::NotMeasured,
    };
    assert_eq!(apply_review(row, p.review), row);

    // And the same holds when the author said invalid and the reference valid.
    let c = with(
        reference_case(
            "case-reference",
            "SYNTHETIC-1236",
            vref("synthetic-mod10", 1),
        ),
        |c| c.type_expectation = ExpectedType::Invalid,
    );
    let g = ok(&c);
    assert_eq!(
        g.provenance[0].review,
        Some(ReviewReason::ReferenceDisagrees)
    );
    assert_eq!(
        g.case.variants[0].expectations[0].type_expectation,
        ExpectedType::Invalid
    );
}

#[test]
fn an_unavailable_reference_holds_the_variant_for_review() {
    for (reference, reason) in [
        (
            vref("no-such-validator", 1),
            UnavailableReason::UnknownValidator,
        ),
        (
            vref("synthetic-mod10", 2),
            UnavailableReason::VersionMismatch,
        ),
    ] {
        let g = ok(&reference_case(
            "case-reference",
            "SYNTHETIC-1236",
            reference,
        ));
        let (v, p) = by_slot(&g, "reference");
        assert_eq!(v.derivation.strategy, Strategy::ReviewRequired);
        assert_eq!(p.review, Some(ReviewReason::ReferenceUnavailable(reason)));
        assert!(p.review.unwrap().unmeasures_type_axis());
        assert_eq!(v.expectations[0].type_expectation, ExpectedType::Valid);
    }
    let missing = with(
        reference_case(
            "case-reference",
            "SYNTHETIC-1236",
            vref("synthetic-mod10", 1),
        ),
        |c| c.reference = None,
    );
    assert_eq!(refused(&missing), RefusalReason::MissingReference);
}

// ---------------------------------------------------------------------------
// Seed rules and snapshot validity
// ---------------------------------------------------------------------------

#[test]
fn the_legacy_seed_rule_keeps_the_case_seed_and_pii_seed_v1_derives_one() {
    let reg = builtin();
    let case = mutation_case("case-mutation", "ref=", "SYNTHETIC-1236");
    let legacy = Generator::new(&rules(SEED_RULE_LEGACY), &reg, GenerationLimits::DEFAULT).unwrap();
    let g = legacy.generate_case(&case).unwrap();
    assert_eq!(
        g.case.variants[0].derivation.seed.as_ref().unwrap(),
        &case.seed
    );
    let v1 = Generator::new(&rules(V1), &reg, GenerationLimits::DEFAULT).unwrap();
    let g1 = v1.generate_case(&case).unwrap();
    assert_ne!(
        g1.case.variants[0].derivation.seed.as_ref().unwrap(),
        &case.seed
    );
}

#[test]
fn an_unknown_seed_rule_or_bad_limits_build_no_generator() {
    let reg = builtin();
    assert_eq!(
        Generator::new(&rules("made-up-rule"), &reg, GenerationLimits::DEFAULT).unwrap_err(),
        GeneratorError::UnsupportedSeedDerivation
    );
    for bad in [
        GenerationLimits {
            max_variants_per_case: 0,
            ..GenerationLimits::DEFAULT
        },
        GenerationLimits {
            max_variants_per_case: 65,
            ..GenerationLimits::DEFAULT
        },
        GenerationLimits {
            max_text_bytes: 2 * 1024 * 1024,
            ..GenerationLimits::DEFAULT
        },
        GenerationLimits {
            max_variants_per_method: 5_000_000,
            max_total_variants: 5_000_000,
            ..GenerationLimits::DEFAULT
        },
        GenerationLimits {
            max_variants_per_method: 10,
            max_total_variants: 5,
            ..GenerationLimits::DEFAULT
        },
        GenerationLimits {
            batch_variants: 1,
            ..GenerationLimits::DEFAULT
        },
        GenerationLimits {
            batch_variants: 100_000,
            ..GenerationLimits::DEFAULT
        },
    ] {
        assert!(
            matches!(
                Generator::new(&rules(V1), &reg, bad),
                Err(GeneratorError::InvalidLimits(_))
            ),
            "{bad:?}"
        );
    }
    assert!(GenerationLimits::DEFAULT.validate().is_ok());
}

fn sealed(out: GenerationOutput, seed_rule: &str) -> CorpusSnapshot {
    let body = assemble_body(population(), rules(seed_rule), out.generated).unwrap();
    let mut doc = CorpusSnapshot::unsealed(body);
    seal(&mut doc).unwrap();
    doc
}

#[test]
fn generated_cases_form_a_valid_contract_snapshot() {
    for rule in [V1, SEED_RULE_LEGACY] {
        let reg = builtin();
        let g = Generator::new(&rules(rule), &reg, GenerationLimits::DEFAULT).unwrap();
        let cases = one_of_each();
        let out = g.generate_all(&cases).unwrap();
        assert!(out.refused.is_empty());
        let doc = sealed(out, rule);
        validate(&doc).unwrap_or_else(|v| panic!("{v:?}"));
        assert_eq!(doc.semantic.case_count(), 7);
        assert_eq!(doc.semantic.variant_count(), 9);
        assert_eq!(doc.semantic.occurrence_count(), 9);
    }
}

#[test]
fn review_variants_and_derived_variants_satisfy_the_contract_derivation_rules() {
    // review-required needs an operator; derived needs operator and (here) a seed; authored neither.
    let reg = builtin();
    let g = Generator::new(&rules(V1), &reg, GenerationLimits::DEFAULT).unwrap();
    let mut cases = one_of_each();
    cases.push(with(
        mod10_case(
            "case-typeval-unavailable",
            "SYNTHETIC-1236",
            ExpectedType::Valid,
        ),
        |c| c.validator = Some(vref("no-such-validator", 1)),
    ));
    cases.push(reference_case(
        "case-reference-unavailable",
        "SYNTHETIC-1236",
        vref("no-such-validator", 1),
    ));
    let out = g.generate_all(&cases).unwrap();
    let doc = sealed(out, V1);
    validate(&doc).unwrap_or_else(|v| panic!("{v:?}"));
    let strategies: Vec<Strategy> = doc
        .semantic
        .cases
        .iter()
        .flat_map(|c| &c.variants)
        .map(|v| v.derivation.strategy)
        .collect();
    assert_eq!(
        strategies
            .iter()
            .filter(|s| **s == Strategy::ReviewRequired)
            .count(),
        2
    );
}

#[test]
fn debug_output_never_prints_text() {
    let c = schema_case("case-schema");
    assert!(!format!("{c:?}").contains("person@example"));
    let r = generate(&with(c.clone(), |c| {
        c.candidate = ByteRange { start: 3, end: 3 }
    }))
    .unwrap_err();
    assert!(!format!("{r:?}").contains("person@example"));
    let g = ok(&c);
    assert!(!format!("{g:?}").contains("person@example"));
    let m = pii_eval_kernel::methods::apply_mutation(
        &pii_eval_contracts::OperatorRef {
            id: id("invalidate-final-digit"),
            version: 1,
        },
        "ref=SYNTHETIC-1236",
        &ByteRange { start: 4, end: 18 },
    )
    .unwrap();
    assert!(!format!("{m:?}").contains("SYNTHETIC"));
}

#[test]
fn case_results_are_explicit_in_a_run() {
    let reg = builtin();
    let g = Generator::new(&rules(V1), &reg, GenerationLimits::DEFAULT).unwrap();
    let bad = with(schema_case("case-bad"), |c| {
        c.candidate = ByteRange { start: 0, end: 0 }
    });
    let cases = [schema_case("case-good"), bad];
    let results: Vec<CaseResult> = g.run(&cases).map(|r| r.unwrap()).collect();
    assert!(matches!(results[0], CaseResult::Generated(_)));
    match &results[1] {
        CaseResult::Refused(r) => assert_eq!(r.reason, RefusalReason::RangeInvalid),
        CaseResult::Generated(_) => panic!("a bad range must not produce a clean result"),
    }
}
