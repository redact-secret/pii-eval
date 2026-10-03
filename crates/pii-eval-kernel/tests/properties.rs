//! Property tests with a fixed-seed generator (no third-party test dependency;
//! see docs/dependency-policy.md). Every run explores the same inputs, so a
//! failure reproduces from the printed iteration number alone.

mod common;

use common::*;
use pii_eval_contracts::{
    ActionCapability, ActionKind, CapabilityState, Expectation, ExpectedType, FamilyId, Finding,
    JurisdictionCode, ScannerCapabilities, ScannerStatus, SensitivityExpectation,
};
use pii_eval_kernel::{
    OffsetUnit, RangeError, ScannerView, VariantInput, assess_variant, byte_to_unit_offset,
    translate_offset, translate_range, unit_length, validate_range, validate_range_bytes,
};

/// SplitMix64: tiny, deterministic, good enough for input generation.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }

    fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            items.swap(i, self.below(i + 1));
        }
    }
}

/// ASCII, CRLF, 2-, 3- and 4-byte scalars, a precomposed accent and a
/// combining mark.
const ALPHABET: [&str; 10] = [
    "a",
    "k",
    "\r",
    "\n",
    "\u{E9}",
    "\u{301}",
    "\u{D55C}",
    "\u{AE00}",
    "\u{1F600}",
    "\u{10348}",
];

fn random_text(rng: &mut Rng, max_chars: usize) -> String {
    (0..rng.below(max_chars + 1))
        .map(|_| *rng.pick(&ALPHABET))
        .collect()
}

fn boundaries(text: &str) -> Vec<u64> {
    (0..=text.len())
        .filter(|&b| text.is_char_boundary(b))
        .map(|b| b as u64)
        .collect()
}

#[test]
fn offsets_round_trip_through_every_unit() {
    let mut rng = Rng(1);
    for iteration in 0..400 {
        let text = random_text(&mut rng, 20);
        let bounds = boundaries(&text);
        for unit in OffsetUnit::ALL {
            let total = unit_length(&text, unit).unwrap();
            // Every boundary maps to a unit offset and back to itself.
            let mut previous = None;
            for &b in &bounds {
                let u = byte_to_unit_offset(&text, unit, b).unwrap();
                assert!(u <= total, "iteration {iteration}");
                assert_eq!(
                    translate_offset(&text, unit, u),
                    Ok(b),
                    "iteration {iteration}"
                );
                // Strictly increasing: distinct boundaries have distinct offsets.
                assert!(previous.is_none_or(|p| p < u), "iteration {iteration}");
                previous = Some(u);
            }
            // Every non-boundary byte is rejected, as bytes and as an inverse.
            for b in 0..=text.len() as u64 {
                if !bounds.contains(&b) {
                    assert_eq!(
                        translate_offset(&text, OffsetUnit::Utf8Bytes, b),
                        Err(RangeError::NotOnCharBoundary)
                    );
                    assert_eq!(
                        byte_to_unit_offset(&text, unit, b),
                        Err(RangeError::NotOnCharBoundary)
                    );
                }
            }
            // A unit offset either lands on a boundary that maps back, or is
            // rejected as inside a character or past the end; exactly
            // `bounds.len()` offsets in `0..=total` succeed.
            let mut accepted = 0;
            for u in 0..=total + 2 {
                match translate_offset(&text, unit, u) {
                    Ok(b) => {
                        accepted += 1;
                        assert_eq!(byte_to_unit_offset(&text, unit, b), Ok(u));
                    }
                    Err(RangeError::InsideSurrogatePair) => {
                        assert_eq!(unit, OffsetUnit::Utf16CodeUnits);
                        assert!(u < total);
                    }
                    Err(RangeError::OutOfBounds) => assert!(u > total),
                    Err(RangeError::NotOnCharBoundary) => {
                        assert_eq!(unit, OffsetUnit::Utf8Bytes);
                    }
                    Err(other) => panic!("unexpected {other:?}"),
                }
            }
            assert_eq!(accepted, bounds.len(), "iteration {iteration} {unit:?}");
        }
    }
}

#[test]
fn translated_ranges_equal_the_same_range_in_every_unit() {
    let mut rng = Rng(2);
    for iteration in 0..400 {
        let text = random_text(&mut rng, 16);
        let bounds = boundaries(&text);
        if bounds.len() < 2 {
            continue;
        }
        let i = rng.below(bounds.len() - 1);
        let j = i + 1 + rng.below(bounds.len() - i - 1);
        let (bs, be) = (bounds[i], bounds[j]);
        for unit in OffsetUnit::ALL {
            let us = byte_to_unit_offset(&text, unit, bs).unwrap();
            let ue = byte_to_unit_offset(&text, unit, be).unwrap();
            let r = translate_range(&text, unit, us, ue).unwrap();
            assert_eq!((r.start, r.end), (bs, be), "iteration {iteration} {unit:?}");
            assert_eq!(validate_range(&text, &r), Ok(()));
        }
        // In bytes, translation is exactly validation.
        for s in 0..=text.len() as u64 + 1 {
            for e in 0..=text.len() as u64 + 1 {
                let translated = translate_range(&text, OffsetUnit::Utf8Bytes, s, e);
                let validated =
                    validate_range(&text, &pii_eval_contracts::ByteRange { start: s, end: e });
                assert_eq!(
                    translated.map(|_| ()),
                    validated,
                    "iteration {iteration} [{s},{e})"
                );
            }
        }
    }
}

#[test]
fn validation_never_panics_on_arbitrary_bytes_and_offsets() {
    let mut rng = Rng(3);
    let edge = [
        0,
        1,
        2,
        3,
        4,
        63,
        64,
        65,
        (1 << 53) - 1,
        1 << 53,
        u64::MAX - 1,
        u64::MAX,
    ];
    for _ in 0..3000 {
        let len = rng.below(48);
        let bytes: Vec<u8> = (0..len)
            .map(|_| match rng.below(4) {
                0 => 0x80 + (rng.next() % 0x40) as u8, // continuation bytes
                1 => 0xC0 + (rng.next() % 0x40) as u8, // lead / invalid bytes
                _ => (rng.next() % 0x80) as u8,
            })
            .collect();
        let offset = |rng: &mut Rng| {
            if rng.below(3) == 0 {
                *rng.pick(&edge)
            } else {
                rng.next() % 70
            }
        };
        let (start, end) = (offset(&mut rng), offset(&mut rng));
        let range = pii_eval_contracts::ByteRange { start, end };
        let result = validate_range_bytes(&bytes, &range);
        match std::str::from_utf8(&bytes) {
            Err(_) => assert_eq!(result, Err(RangeError::InvalidUtf8)),
            Ok(text) => {
                assert_eq!(result, validate_range(text, &range));
                for unit in OffsetUnit::ALL {
                    // Must return, not panic; a success must be a valid range.
                    if let Ok(r) = translate_range(text, unit, start, end) {
                        assert_eq!(validate_range(text, &r), Ok(()));
                    }
                    let _ = translate_offset(text, unit, start);
                    let _ = byte_to_unit_offset(text, unit, end);
                }
                // The whole assessment path also refuses instead of panicking.
                let e = [valid("occ-a", start, end, "pii:global:email")];
                let f = [Finding {
                    range,
                    ..found(0, 1, "pii:global:email")
                }];
                let _ = assess_variant(
                    &VariantInput {
                        text,
                        case_jurisdiction: None,
                        expectations: &e,
                    },
                    &ScannerView {
                        status: ScannerStatus::Complete,
                        capabilities: &supported(),
                        findings: &f,
                    },
                );
            }
        }
    }
}

const FAMILIES: [&str; 3] = ["pii:global:email", "pii:global:phone", "pii:kr:phone"];
const JURISDICTIONS: [&str; 2] = ["KR", "US"];

fn random_caps(rng: &mut Rng) -> ScannerCapabilities {
    let state = |rng: &mut Rng| {
        *rng.pick(&[
            CapabilityState::Supported,
            CapabilityState::Supported,
            CapabilityState::Undeclared,
            CapabilityState::Unsupported,
        ])
    };
    ScannerCapabilities {
        ranges: CapabilityState::Supported,
        family_classification: state(rng),
        sensitivity_classification: state(rng),
        jurisdiction_reporting: state(rng),
        action: *rng.pick(&[
            ActionCapability::Unavailable,
            ActionCapability::ReportedAction,
            ActionCapability::SanitizedOutput,
        ]),
        families: vec![],
        jurisdictions: vec![],
    }
}

fn random_range(rng: &mut Rng, bounds: &[u64]) -> (u64, u64) {
    let i = rng.below(bounds.len() - 1);
    let j = i + 1 + rng.below(bounds.len() - i - 1);
    (bounds[i], bounds[j])
}

fn random_finding(rng: &mut Rng, bounds: &[u64]) -> Finding {
    let (s, e) = random_range(rng, bounds);
    let family = rng.pick(&FAMILIES);
    let mut f = found(s, e, family);
    if rng.below(4) == 0 {
        f.family = None;
    }
    if rng.below(2) == 0 {
        f.jurisdiction = Some(JurisdictionCode::new(*rng.pick(&JURISDICTIONS)).unwrap());
    }
    f.sensitive = *rng.pick(&[Some(true), Some(false), None]);
    f.action = *rng.pick(&[
        None,
        Some(ActionKind::Redact),
        Some(ActionKind::Preserve),
        Some(ActionKind::Other),
    ]);
    f
}

fn random_expectations(rng: &mut Rng, bounds: &[u64]) -> Vec<Expectation> {
    (0..1 + rng.below(4))
        .map(|k| {
            let (s, e) = random_range(rng, bounds);
            exp(
                &format!("occ-{k:02}"),
                s,
                e,
                FAMILIES[rng.below(FAMILIES.len())],
                *rng.pick(&[ExpectedType::Valid, ExpectedType::Invalid]),
                *rng.pick(&[
                    SensitivityExpectation::Sensitive,
                    SensitivityExpectation::NonSensitive,
                    SensitivityExpectation::NotEstablished,
                ]),
            )
        })
        .collect()
}

#[test]
fn assessment_is_invariant_under_permutation_and_repetition() {
    let mut rng = Rng(4);
    let mut multi_candidate = 0;
    for iteration in 0..3000 {
        let text = loop {
            let t = random_text(&mut rng, 14);
            if boundaries(&t).len() >= 3 {
                break t;
            }
        };
        let bounds = boundaries(&text);
        let caps = random_caps(&mut rng);
        let jurisdiction = [None, Some("KR")][rng.below(2)];
        let expectations = random_expectations(&mut rng, &bounds);
        let mut findings: Vec<Finding> = (0..rng.below(9))
            .map(|_| random_finding(&mut rng, &bounds))
            .collect();
        // Force duplicates some of the time.
        if !findings.is_empty() && rng.below(2) == 0 {
            let copy = findings[rng.below(findings.len())].clone();
            findings.push(copy);
        }
        let jur = jurisdiction.map(|j| JurisdictionCode::new(j).unwrap());
        let run = |expectations: &[Expectation], findings: &[Finding]| {
            assess_variant(
                &VariantInput {
                    text: &text,
                    case_jurisdiction: jur.as_ref(),
                    expectations,
                },
                &ScannerView {
                    status: ScannerStatus::Complete,
                    capabilities: &caps,
                    findings,
                },
            )
        };
        let baseline = run(&expectations, &findings).expect("generated ranges are valid");
        if baseline
            .occurrences
            .iter()
            .any(|o| o.observed.finding_count > 1)
        {
            multi_candidate += 1;
        }
        // Repetition: the same input gives the same result.
        assert_eq!(
            run(&expectations, &findings).as_ref(),
            Ok(&baseline),
            "iteration {iteration}"
        );
        for _ in 0..4 {
            let mut e = expectations.clone();
            let mut f = findings.clone();
            rng.shuffle(&mut e);
            rng.shuffle(&mut f);
            assert_eq!(run(&e, &f).as_ref(), Ok(&baseline), "iteration {iteration}");
        }
        // Every expectation appears exactly once, in ascending id order.
        let ids: Vec<_> = baseline
            .occurrences
            .iter()
            .map(|o| o.occurrence_id.as_str().to_owned())
            .collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
        assert_eq!(ids.len(), expectations.len());
        // One reported row per finding: nothing is merged or dropped.
        assert_eq!(baseline.reported.len(), findings.len());
    }
    // The generator really exercises multi-finding overlap.
    assert!(
        multi_candidate > 300,
        "only {multi_candidate} multi-candidate runs"
    );
}

#[test]
fn family_identity_does_not_leak_into_unrelated_axes() {
    // Changing only the reported family of the primary finding never changes
    // the range or action axes (axes are independent observations).
    let mut rng = Rng(5);
    let caps = supported();
    for iteration in 0..500 {
        let text = loop {
            let t = random_text(&mut rng, 12);
            if boundaries(&t).len() >= 3 {
                break t;
            }
        };
        let bounds = boundaries(&text);
        let expectations = random_expectations(&mut rng, &bounds);
        let finding = random_finding(&mut rng, &bounds);
        let mut other = finding.clone();
        other.family = Some(FamilyId::new("pii:global:email").unwrap());
        let jur = None;
        let run = |f: &Finding| {
            assess_variant(
                &VariantInput {
                    text: &text,
                    case_jurisdiction: jur,
                    expectations: &expectations,
                },
                &ScannerView {
                    status: ScannerStatus::Complete,
                    capabilities: &caps,
                    findings: std::slice::from_ref(f),
                },
            )
            .unwrap()
        };
        let (a, b) = (run(&finding), run(&other));
        for (x, y) in a.occurrences.iter().zip(&b.occurrences) {
            assert_eq!(x.row.range, y.row.range, "iteration {iteration}");
            assert_eq!(x.row.action, y.row.action, "iteration {iteration}");
            assert_eq!(
                x.row.sensitivity_context, y.row.sensitivity_context,
                "iteration {iteration}"
            );
        }
    }
}
