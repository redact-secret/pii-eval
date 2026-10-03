//! Variant ids, seeds and the `sha256-pattern` generator against vectors computed
//! independently by `vectors/ids_reference.py` (Python `hashlib`; run once, output
//! committed as `vectors/ids_vectors.rs`; CI does not run Python). The script is
//! written from the specification in ADR 0007 and shares no code with the kernel.

use pii_eval_contracts::{Id, Seed};
use pii_eval_kernel::methods::{
    MAX_SLOT_BYTES, SEED_RULE_LEGACY, SEED_RULE_V1, SeedRule, Slot, derive_seed,
    materialize_sha256_pattern, preimage, variant_id,
};

include!("vectors/ids_vectors.rs");

fn hex(bytes: &[u8]) -> String {
    use pii_eval_contracts::Sha256Digest;
    Sha256Digest::of_bytes(bytes).as_str().to_owned()
}

#[test]
fn preimages_match_the_independent_vectors() {
    for (fields, digest) in PREIMAGE_VECTORS {
        assert_eq!(hex(&preimage(fields)), *digest, "{fields:?}");
    }
}

#[test]
fn field_boundaries_are_unambiguous() {
    assert_ne!(preimage(&["ab", "c"]), preimage(&["a", "bc"]));
    assert_ne!(preimage(&["abc"]), preimage(&["abc", ""]));
    // 4-byte big-endian length, then the bytes.
    assert_eq!(preimage(&["ab"]), [0, 0, 0, 2, b'a', b'b']);
}

#[test]
fn variant_ids_match_the_independent_vectors() {
    for (case, slot, expected) in VARIANT_ID_VECTORS {
        let id = variant_id(&Id::new(*case).unwrap(), &Slot::new(slot).unwrap()).unwrap();
        assert_eq!(id.as_str(), *expected, "{case}/{slot}");
        assert!(id.as_str().len() <= 80);
    }
}

#[test]
fn hyphenated_case_and_slot_pairs_do_not_collide() {
    // "aa-b" + "c-d" and "aa" + "b-c-d" concatenate to the same "aa-b-c-d".
    let a = variant_id(&Id::new("aa-b").unwrap(), &Slot::new("c-d").unwrap()).unwrap();
    let b = variant_id(&Id::new("aa").unwrap(), &Slot::new("b-c-d").unwrap()).unwrap();
    assert_ne!(a, b);
}

#[test]
fn the_longest_case_and_slot_still_give_a_valid_identifier() {
    let id = variant_id(
        &Id::new("c".repeat(80)).unwrap(),
        &Slot::new(&"s".repeat(MAX_SLOT_BYTES)).unwrap(),
    )
    .unwrap();
    assert_eq!(id.as_str().len(), MAX_SLOT_BYTES + 1 + 24);
    assert!(Slot::new(&"s".repeat(MAX_SLOT_BYTES + 1)).is_err());
    for bad in ["", "A", "x", "a_b", "9a", "a b"] {
        assert!(Slot::new(bad).is_err(), "{bad}");
    }
}

#[test]
fn pii_seed_v1_matches_the_independent_vectors() {
    for (generator, version, case_seed, case, slot, expected) in SEED_VECTORS {
        let seed = derive_seed(
            SeedRule::PiiSeedV1,
            &Id::new(*generator).unwrap(),
            *version,
            &Seed::new(*case_seed).unwrap(),
            &Id::new(*case).unwrap(),
            &Slot::new(slot).unwrap(),
        )
        .unwrap();
        assert_eq!(seed.as_str(), *expected, "{case}/{slot}");
        assert_eq!(seed.as_str().len(), 64);
    }
}

#[test]
fn every_input_of_the_seed_changes_it() {
    let mut seen = std::collections::BTreeSet::new();
    for (generator, version, case_seed, case, slot, _) in SEED_VECTORS {
        seen.insert(
            derive_seed(
                SeedRule::PiiSeedV1,
                &Id::new(*generator).unwrap(),
                *version,
                &Seed::new(*case_seed).unwrap(),
                &Id::new(*case).unwrap(),
                &Slot::new(slot).unwrap(),
            )
            .unwrap(),
        );
    }
    assert_eq!(seen.len(), SEED_VECTORS.len());
}

#[test]
fn the_legacy_rule_returns_the_case_seed_unchanged() {
    let s = Seed::new("group-id.1").unwrap();
    let out = derive_seed(
        SeedRule::LegacyCaseSeed,
        &Id::new("any-generator").unwrap(),
        7,
        &s,
        &Id::new("some-case").unwrap(),
        &Slot::new("any-slot").unwrap(),
    )
    .unwrap();
    assert_eq!(out, s);
}

#[test]
fn rule_ids_round_trip_and_unknown_ids_are_not_guessed() {
    for rule in [SeedRule::PiiSeedV1, SeedRule::LegacyCaseSeed] {
        assert_eq!(
            SeedRule::from_id(&Seed::new(rule.id()).unwrap()),
            Some(rule)
        );
    }
    assert_eq!(SEED_RULE_V1, "pii-seed-v1");
    assert_eq!(SEED_RULE_LEGACY, "legacy-case-seed");
    assert_eq!(SeedRule::from_id(&Seed::new("seed-v1").unwrap()), None);
}

#[test]
fn sha256_pattern_matches_the_independent_vectors_and_the_oracle_function() {
    // The same five vectors were also produced by a verbatim copy of the oracle's
    // `materializePiiEvidenceCandidate` (JavaScript, Node crypto); both agree with Python.
    for (seed, pattern, expected) in PATTERN_VECTORS {
        assert_eq!(
            materialize_sha256_pattern(seed, pattern),
            *expected,
            "{seed}/{pattern}"
        );
    }
}

#[test]
fn sha256_pattern_is_deterministic_and_keeps_non_placeholder_characters() {
    let a = materialize_sha256_pattern("seed", "ref-DDDD-AA");
    assert_eq!(a, materialize_sha256_pattern("seed", "ref-DDDD-AA"));
    assert!(a.starts_with("ref-") && a.as_bytes()[8] == b'-');
    assert!(a[4..8].bytes().all(|b| b.is_ascii_digit()));
    assert!(a[9..].bytes().all(|b| b.is_ascii_uppercase()));
    assert_ne!(a, materialize_sha256_pattern("other", "ref-DDDD-AA"));
}
