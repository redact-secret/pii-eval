//! The pii-evidence snapshot consumer (ADR 0019): the released snapshot loads,
//! and every wrong, incompatible, tampered, incomplete or non-public snapshot
//! fails closed BEFORE anything is mapped. Negative tests forge a snapshot with
//! consistent digests (so the intended defect is the only one) unless the test
//! is about the digests themselves. Public synthetic reserved values only.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use pii_eval_cli::evidence::files::{SnapshotFiles, read_dir};
use pii_eval_cli::evidence::map::{loss, map, snapshot_json};
use pii_eval_cli::evidence::pin::SnapshotPin;
use pii_eval_cli::evidence::verify::verify;
use pii_eval_cli::evidence::{EvidenceError, reason};
use pii_eval_cli::status::Exit;
use pii_eval_contracts::{MethodId, Sha256Digest, Strategy};
use serde_json::{Value, json};

const SNAPSHOT_ID: &str = "public-pii-phi/2026-10-07/9d4e8e036bbb";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn vendored() -> PathBuf {
    root()
        .join("fixtures/pii-evidence/snapshots")
        .join(SNAPSHOT_ID)
}

fn pin_path() -> PathBuf {
    root().join("fixtures/pii-evidence/pin.json")
}

fn pin() -> SnapshotPin {
    SnapshotPin::parse(&std::fs::read(pin_path()).unwrap()).unwrap()
}

fn files() -> SnapshotFiles {
    read_dir(&vendored()).expect("vendored snapshot is readable")
}

fn sha(bytes: &[u8]) -> String {
    Sha256Digest::of_bytes(bytes).as_str().to_owned()
}

/// A mutable copy of a snapshot that can be re-sealed consistently.
struct Forge {
    files: BTreeMap<String, Vec<u8>>,
}

impl Forge {
    fn new() -> Self {
        Self {
            files: files().into_map(),
        }
    }

    fn lines(&self, path: &str) -> Vec<Value> {
        std::str::from_utf8(&self.files[path])
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn set_lines(&mut self, path: &str, lines: &[Value]) {
        let mut text = String::new();
        for l in lines {
            text.push_str(&canonical(l));
            text.push('\n');
        }
        self.files.insert(path.to_owned(), text.into_bytes());
    }

    /// Edit the first record that `pick` selects.
    fn edit_first(&mut self, path: &str, pick: impl Fn(&Value) -> bool, f: impl Fn(&mut Value)) {
        let mut lines = self.lines(path);
        let line = lines.iter_mut().find(|l| pick(l)).expect("a record");
        f(line);
        self.set_lines(path, &lines);
    }

    fn manifest(&self) -> Value {
        serde_json::from_slice(&self.files["manifest.json"]).unwrap()
    }

    fn set_manifest(&mut self, m: &Value) {
        self.files.insert(
            "manifest.json".into(),
            (serde_json::to_string_pretty(m).unwrap() + "\n").into_bytes(),
        );
    }

    /// Re-derive the file list, the digests and the id so that only the
    /// semantic defect a test introduced remains.
    fn reseal(&mut self) -> &mut Self {
        let mut m = self.manifest();
        let mut listed = Vec::new();
        for (path, bytes) in &self.files {
            if path == "manifest.json" {
                continue;
            }
            let mut e = json!({"path": path, "bytes": bytes.len(), "sha256": sha(bytes)});
            if path.ends_with(".jsonl") {
                e["records"] = json!(
                    bytes
                        .split(|b| *b == b'\n')
                        .filter(|l| !l.is_empty())
                        .count()
                );
            }
            listed.push(e);
        }
        m["files"] = Value::Array(listed);
        let mut lines = String::new();
        for (path, bytes) in &self.files {
            if path != "manifest.json" {
                lines.push_str(&format!("{} {path}\n", sha(bytes)));
            }
        }
        let digest = sha(lines.as_bytes());
        m["contentDigest"] = json!(digest);
        m["id"] = json!(format!(
            "public-pii-phi/{}/{}",
            m["snapshotDate"].as_str().unwrap(),
            &digest[..12]
        ));
        m["sourceManifestDigest"] = json!(sha(&self.files["sources.jsonl"]));
        self.set_manifest(&m);
        self
    }

    /// The pin that matches the current bytes.
    fn pin(&self) -> SnapshotPin {
        let mut p = pin();
        let m = self.manifest();
        p.id = m["id"].as_str().unwrap().to_owned();
        p.manifest_sha256 = sha(&self.files["manifest.json"]);
        p.content_digest = m["contentDigest"].as_str().unwrap().to_owned();
        p.source_manifest_digest = m["sourceManifestDigest"].as_str().unwrap().to_owned();
        p
    }

    fn check(&self) -> Result<(), EvidenceError> {
        verify(&SnapshotFiles::from_map(self.files.clone()), &self.pin()).map(|_| ())
    }

    fn expect(&self, code: &str) {
        let err = self.check().expect_err("must be refused");
        assert_eq!(err.code, code, "{err}");
    }
}

/// Canonical JSON (sorted keys, compact), as the producer writes JSON Lines.
fn canonical(v: &Value) -> String {
    serde_json::to_string(v).unwrap()
}

// ---------------------------------------------------------------------------
// Positive: the released snapshot loads and maps
// ---------------------------------------------------------------------------

#[test]
fn the_released_snapshot_verifies_against_its_pin() {
    let v = verify(&files(), &pin()).expect("verifies");
    assert_eq!(v.manifest.id, SNAPSHOT_ID);
    assert_eq!(v.cases.len(), 49);
    assert_eq!(v.fixtures.len(), 139);
    assert_eq!(v.skipped.len(), 8);
    assert_eq!(
        v.manifest_sha256,
        "a9e24b6dc73bc876f9fce341c7305421b054ae399df83d198513bede03555ca9"
    );
}

#[test]
fn the_forge_helper_is_an_identity_when_nothing_changes() {
    // A forged snapshot with no defect must verify, so a failure below is the defect's.
    Forge::new()
        .reseal()
        .check()
        .expect("consistent reseal verifies");
}

#[test]
fn mapping_is_deterministic_and_pins_the_population_digest() {
    let v = verify(&files(), &pin()).unwrap();
    let a = map(&v, &pin()).expect("maps");
    let b = map(&v, &pin()).expect("maps");
    assert_eq!(snapshot_json(&a).unwrap(), snapshot_json(&b).unwrap());
    assert_eq!(a.binding, b.binding);
    // Golden values: a change to the mapping rule changes them and must bump the revision.
    assert_eq!(
        a.snapshot.semantic_digest.as_str(),
        "612a8cf629c24c8e92be474a8129a592c7f1f75cbe4e2e2afcc60383cc6347d8"
    );
    assert_eq!(
        a.binding["semanticDigest"],
        "f481baee5aa3d812f7858902c5024618e09e0a2868993d31dc10525c53ddf9fb"
    );
    assert_eq!(a.snapshot.schema_version.to_string(), "1.4");
}

#[test]
fn every_fixture_is_carried_once_and_nothing_is_invented() {
    let v = verify(&files(), &pin()).unwrap();
    let m = map(&v, &pin()).unwrap();
    let s = &m.snapshot.semantic;
    assert_eq!(s.variant_count(), 139);
    assert_eq!(s.occurrence_count(), 139);
    assert_eq!(s.case_count(), 55);
    let counts = &m.binding["semantic"]["counts"];
    assert_eq!(counts["locatedOccurrences"], 98);
    assert_eq!(counts["rangeLessOccurrences"], 41);
    assert_eq!(counts["evidenceCasesWithoutFixtures"], 2);
    // Every variant text is a fixture, byte for byte.
    let fixtures: BTreeMap<&str, &str> = v
        .fixtures
        .iter()
        .map(|f| (f.content.as_str(), f.id.as_str()))
        .collect();
    for case in &s.cases {
        for variant in &case.variants {
            assert!(fixtures.contains_key(variant.text.as_str()));
        }
    }
    // The three methods used are the ones the decisions name; no collision or
    // trio method is invented.
    let methods: std::collections::BTreeSet<MethodId> = s.cases.iter().map(|c| c.method).collect();
    assert_eq!(
        methods,
        [
            MethodId::PiiBenign,
            MethodId::SchemaOnly,
            MethodId::TypeValidation
        ]
        .into()
    );
    assert!(s.cases.iter().all(|c| c.collision.is_none()));
}

#[test]
fn range_less_variants_are_never_stronger_than_not_established() {
    use pii_eval_contracts::{ActionExpectation, ExpectedType, SensitivityExpectation};
    let v = verify(&files(), &pin()).unwrap();
    let m = map(&v, &pin()).unwrap();
    let mut rangeless = 0;
    for case in &m.snapshot.semantic.cases {
        for variant in &case.variants {
            for e in &variant.expectations {
                assert_eq!(e.action, ActionExpectation::NotSpecified);
                if e.range.is_none() {
                    rangeless += 1;
                    assert_eq!(case.method, MethodId::SchemaOnly);
                    assert_eq!(e.type_expectation, ExpectedType::NotEstablished);
                    assert_eq!(e.sensitivity, SensitivityExpectation::NotEstablished);
                }
            }
        }
    }
    assert_eq!(rangeless, 41);
}

#[test]
fn rule_derived_fixtures_keep_their_derivation_and_no_span() {
    let v = verify(&files(), &pin()).unwrap();
    let m = map(&v, &pin()).unwrap();
    let derived: Vec<_> = m
        .snapshot
        .semantic
        .cases
        .iter()
        .flat_map(|c| &c.variants)
        .filter(|v| v.derivation.strategy == Strategy::Derived)
        .collect();
    assert_eq!(derived.len(), 16);
    for variant in derived {
        let op = variant.derivation.operator.as_ref().expect("operator");
        assert!(op.id.as_str().starts_with("mutation-"), "{:?}", op.id);
        assert!(variant.expectations.iter().all(|e| e.range.is_none()));
    }
}

#[test]
fn spans_are_the_fixture_byte_ranges_on_character_boundaries() {
    let v = verify(&files(), &pin()).unwrap();
    let m = map(&v, &pin()).unwrap();
    let mut multibyte = 0;
    for case in &m.snapshot.semantic.cases {
        for variant in &case.variants {
            for e in &variant.expectations {
                if let Some(r) = e.range {
                    let (s, t) = (r.start as usize, r.end as usize);
                    assert!(variant.text.is_char_boundary(s) && variant.text.is_char_boundary(t));
                    if variant.text.len() != variant.text.chars().count() {
                        multibyte += 1;
                    }
                }
            }
        }
    }
    assert!(
        multibyte > 0,
        "the snapshot has multibyte fixtures with spans"
    );
}

#[test]
fn the_binding_records_losses_and_never_carries_text() {
    let v = verify(&files(), &pin()).unwrap();
    let m = map(&v, &pin()).unwrap();
    let text = serde_json::to_string(&m.binding).unwrap();
    for f in &v.fixtures {
        if f.content.len() >= 12 {
            assert!(!text.contains(f.content.trim_end()), "fixture text leaked");
        }
    }
    let losses = m.binding["semantic"]["losses"].as_object().unwrap();
    for code in losses.keys() {
        assert!(loss::ALL.contains(&code.as_str()), "{code}");
    }
    assert_eq!(losses[loss::PHI_DOMAIN_NOT_CARRIED], 37);
    // The corpus carries no scanner, detector, support or threshold field.
    for banned in ["scanner", "detector", "support", "threshold", "score"] {
        let lower = serde_json::to_string(&snapshot_json(&m).unwrap())
            .unwrap()
            .to_ascii_lowercase();
        assert!(!lower.contains(&format!("\\\"{banned}")), "{banned}");
    }
}

// ---------------------------------------------------------------------------
// Fail closed: identity
// ---------------------------------------------------------------------------

#[test]
fn a_wrong_snapshot_id_is_refused() {
    let mut p = pin();
    p.id = "public-pii-phi/2026-10-07/000000000000".into();
    let err = verify(&files(), &p).unwrap_err();
    assert_eq!(err.code, reason::SNAPSHOT_ID_MISMATCH);
    assert_eq!(err.exit, Exit::Provenance);
}

#[test]
fn a_wrong_manifest_digest_pin_is_refused() {
    let mut p = pin();
    p.manifest_sha256 = "0".repeat(64);
    assert_eq!(
        verify(&files(), &p).unwrap_err().code,
        reason::MANIFEST_DIGEST_MISMATCH
    );
}

#[test]
fn a_wrong_content_digest_pin_is_refused() {
    let mut p = pin();
    p.content_digest = "1".repeat(64);
    assert_eq!(
        verify(&files(), &p).unwrap_err().code,
        reason::CONTENT_DIGEST_MISMATCH
    );
}

#[test]
fn a_wrong_source_manifest_digest_pin_is_refused() {
    let mut p = pin();
    p.source_manifest_digest = "2".repeat(64);
    assert_eq!(
        verify(&files(), &p).unwrap_err().code,
        reason::SOURCE_MANIFEST_DIGEST_MISMATCH
    );
}

#[test]
fn a_manifest_whose_content_digest_is_not_the_files_digest_is_refused() {
    let mut f = Forge::new();
    let mut m = f.manifest();
    m["contentDigest"] = json!("3".repeat(64));
    f.set_manifest(&m);
    f.expect(reason::CONTENT_DIGEST_MISMATCH);
}

#[test]
fn an_id_not_derived_from_the_date_and_digest_is_refused() {
    let mut f = Forge::new();
    f.reseal();
    let mut m = f.manifest();
    m["snapshotDate"] = json!("2026-10-08");
    f.set_manifest(&m);
    f.expect(reason::SNAPSHOT_ID_DERIVATION);
}

#[test]
fn a_tampered_fixture_byte_is_refused_by_the_file_digest() {
    let mut bytes = files().into_map();
    let fixtures = bytes.get_mut("fixtures.jsonl").unwrap();
    let at = fixtures
        .iter()
        .position(|b| *b == b'@')
        .expect("an at sign");
    fixtures[at] = b'#';
    let err = verify(&SnapshotFiles::from_map(bytes), &pin()).unwrap_err();
    assert_eq!(err.code, reason::FILE_DIGEST_MISMATCH);
    assert_eq!(err.at, "fixtures.jsonl");
}

#[test]
fn a_tampered_fixture_resealed_with_every_digest_is_still_refused_by_its_own_digest() {
    let mut f = Forge::new();
    f.edit_first(
        "fixtures.jsonl",
        |l| l["content"].as_str().is_some_and(|c| c.contains('@')),
        |l| {
            let c = l["content"].as_str().unwrap().replacen('@', "#", 1);
            l["content"] = json!(c);
        },
    );
    f.reseal();
    f.expect(reason::FIXTURE_DIGEST_MISMATCH);
}

#[test]
fn a_changed_file_length_is_refused() {
    let mut bytes = files().into_map();
    bytes.get_mut("claims.jsonl").unwrap().push(b'\n');
    let err = verify(&SnapshotFiles::from_map(bytes), &pin()).unwrap_err();
    assert_eq!(err.code, reason::FILE_LENGTH_MISMATCH);
}

#[test]
fn a_missing_file_is_refused() {
    for name in [
        "skipped.jsonl",
        "cases.jsonl",
        "taxonomy/contexts.json",
        "manifest.json",
    ] {
        let mut bytes = files().into_map();
        bytes.remove(name);
        let err = verify(&SnapshotFiles::from_map(bytes), &pin()).unwrap_err();
        assert_eq!(err.code, reason::FILE_MISSING, "{name}");
        assert_eq!(err.at, name);
    }
}

#[test]
fn a_listed_file_that_is_absent_is_refused_even_when_not_required() {
    let mut f = Forge::new();
    f.files.insert("review-events.jsonl".into(), b"".to_vec());
    f.reseal();
    f.files.remove("review-events.jsonl");
    f.expect(reason::FILE_MISSING);
}

#[test]
fn an_unlisted_extra_file_is_refused() {
    let mut bytes = files().into_map();
    bytes.insert("notes.txt".into(), b"x".to_vec());
    let err = verify(&SnapshotFiles::from_map(bytes), &pin()).unwrap_err();
    assert_eq!(err.code, reason::FILE_UNLISTED);
    assert_eq!(err.at, "notes.txt");
}

#[test]
fn a_changed_record_count_is_refused() {
    let mut f = Forge::new();
    f.reseal();
    let mut m = f.manifest();
    m["files"][0]["records"] = json!(1);
    f.set_manifest(&m);
    // Digests of the manifest changed: pin from the forged bytes.
    f.expect(reason::RECORD_COUNT_MISMATCH);
}

// ---------------------------------------------------------------------------
// Fail closed: contract and schema
// ---------------------------------------------------------------------------

#[test]
fn an_unknown_contract_version_is_refused() {
    for version in ["2", "0", "1.1", ""] {
        let mut f = Forge::new();
        let mut m = f.manifest();
        m["consumerContractVersion"] = json!(version);
        f.set_manifest(&m);
        f.reseal();
        let mut m = f.manifest();
        m["consumerContractVersion"] = json!(version);
        f.set_manifest(&m);
        f.expect(reason::CONTRACT_VERSION_UNKNOWN);
    }
}

#[test]
fn an_unknown_contract_or_digest_spec_is_refused() {
    let mut f = Forge::new();
    f.reseal();
    let mut m = f.manifest();
    m["consumerContract"] = json!("another-contract");
    f.set_manifest(&m);
    f.expect(reason::CONTRACT_UNKNOWN);

    let mut f = Forge::new();
    f.reseal();
    let mut m = f.manifest();
    m["contentDigestSpec"] = json!("files-v2");
    f.set_manifest(&m);
    f.expect(reason::DIGEST_SPEC_UNKNOWN);

    let mut f = Forge::new();
    f.reseal();
    let mut m = f.manifest();
    m.as_object_mut().unwrap().remove("consumerContract");
    f.set_manifest(&m);
    f.expect(reason::CONTRACT_UNKNOWN);
}

#[test]
fn an_unknown_schema_version_or_record_kind_is_refused() {
    let mut f = Forge::new();
    f.edit_first("cases.jsonl", |_| true, |l| l["schemaVersion"] = json!("2"));
    f.reseal();
    f.expect(reason::SCHEMA_VERSION_UNKNOWN);

    let mut f = Forge::new();
    f.edit_first(
        "fixtures.jsonl",
        |_| true,
        |l| l["kind"] = json!("fixture-projection-v2"),
    );
    f.reseal();
    f.expect(reason::RECORD_KIND_UNKNOWN);

    let mut f = Forge::new();
    f.edit_first(
        "cases.jsonl",
        |_| true,
        |l| {
            l.as_object_mut().unwrap().remove("schemaVersion");
        },
    );
    f.reseal();
    f.expect(reason::SCHEMA_VERSION_UNKNOWN);
}

#[test]
fn a_missing_required_field_is_refused() {
    let mut f = Forge::new();
    f.edit_first(
        "cases.jsonl",
        |_| true,
        |l| {
            l.as_object_mut().unwrap().remove("expectation");
        },
    );
    f.reseal();
    f.expect(reason::RECORD_FIELD_MISSING);

    let mut f = Forge::new();
    f.edit_first(
        "fixtures.jsonl",
        |_| true,
        |l| {
            l.as_object_mut().unwrap().remove("sha256");
        },
    );
    f.reseal();
    f.expect(reason::RECORD_FIELD_MISSING);

    let mut f = Forge::new();
    f.edit_first(
        "cases.jsonl",
        |_| true,
        |l| {
            l["expectation"].as_object_mut().unwrap().remove("identity");
        },
    );
    f.reseal();
    f.expect(reason::RECORD_FIELD_MISSING);
}

#[test]
fn an_unknown_enum_value_is_refused_not_ignored() {
    let mut f = Forge::new();
    f.edit_first(
        "cases.jsonl",
        |_| true,
        |l| {
            l["expectation"]["identity"] = json!("probably-valid");
        },
    );
    f.reseal();
    f.expect(reason::RECORD_FIELD_INVALID);
}

#[test]
fn unknown_optional_properties_are_ignored_within_version_one() {
    let mut f = Forge::new();
    f.edit_first(
        "cases.jsonl",
        |_| true,
        |l| l["futureNote"] = json!("additive"),
    );
    f.reseal();
    f.check()
        .expect("an additive optional property is accepted");
}

#[test]
fn malformed_json_a_duplicate_key_or_a_float_is_refused() {
    let mut f = Forge::new();
    let mut bytes = f.files["claims.jsonl"].clone();
    bytes.splice(0..1, b"{\"kind\":\"claim\",".iter().copied());
    f.files.insert("claims.jsonl".into(), bytes);
    f.reseal();
    f.expect(reason::RECORD_INVALID);

    let mut f = Forge::new();
    let text = String::from_utf8(f.files["claims.jsonl"].clone()).unwrap();
    let dup = text.replacen("{\"", "{\"id\":\"x\",\"id\":\"y\",\"", 1);
    f.files.insert("claims.jsonl".into(), dup.into_bytes());
    f.reseal();
    f.expect(reason::RECORD_INVALID);

    let mut f = Forge::new();
    let text = String::from_utf8(f.files["fixtures.jsonl"].clone()).unwrap();
    f.files.insert(
        "fixtures.jsonl".into(),
        text.replacen("\"byteLength\":", "\"byteLength\":1.5,\"x\":", 1)
            .into_bytes(),
    );
    f.reseal();
    f.expect(reason::RECORD_INVALID);
}

#[test]
fn unsorted_or_duplicate_ids_are_refused() {
    let mut f = Forge::new();
    let mut lines = f.lines("claims.jsonl");
    lines.swap(0, 1);
    f.set_lines("claims.jsonl", &lines);
    f.reseal();
    f.expect(reason::ID_ORDER_INVALID);

    let mut f = Forge::new();
    let mut lines = f.lines("claims.jsonl");
    lines.insert(1, lines[0].clone());
    f.set_lines("claims.jsonl", &lines);
    f.reseal();
    f.expect(reason::ID_ORDER_INVALID);
}

// ---------------------------------------------------------------------------
// Fail closed: population and neutrality
// ---------------------------------------------------------------------------

#[test]
fn a_protected_or_non_public_population_is_refused() {
    for value in ["protected", "private", "mixed", ""] {
        let mut f = Forge::new();
        f.edit_first(
            "fixtures.jsonl",
            |_| true,
            |l| l["population"] = json!(value),
        );
        f.reseal();
        f.expect(reason::POPULATION_NOT_PUBLIC);
    }
    let mut f = Forge::new();
    f.edit_first(
        "cases.jsonl",
        |_| true,
        |l| l["population"] = json!("protected"),
    );
    f.reseal();
    f.expect(reason::POPULATION_NOT_PUBLIC);

    let mut f = Forge::new();
    f.edit_first(
        "fixture-rules.jsonl",
        |_| true,
        |l| l["population"] = json!("protected"),
    );
    f.reseal();
    f.expect(reason::POPULATION_NOT_PUBLIC);

    let mut f = Forge::new();
    f.reseal();
    let mut m = f.manifest();
    m["population"] = json!("protected");
    f.set_manifest(&m);
    f.expect(reason::POPULATION_NOT_PUBLIC);

    // A missing population on a fixture is not "public by default".
    let mut f = Forge::new();
    f.edit_first(
        "fixtures.jsonl",
        |_| true,
        |l| {
            l.as_object_mut().unwrap().remove("population");
        },
    );
    f.reseal();
    f.expect(reason::RECORD_FIELD_MISSING);
}

#[test]
fn any_scanner_detector_support_threshold_or_score_field_is_refused() {
    for key in [
        "supportState",
        "detectorId",
        "scannerBehavior",
        "threshold",
        "score",
        "benchmarkRank",
        "qualification",
        "expectedCurrent",
        "SUPPORT_STATE",
    ] {
        for file in [
            "cases.jsonl",
            "fixtures.jsonl",
            "claims.jsonl",
            "sources.jsonl",
            "fixture-rules.jsonl",
            "skipped.jsonl",
        ] {
            let mut f = Forge::new();
            f.edit_first(file, |_| true, |l| l[key] = json!("anything"));
            f.reseal();
            f.expect(reason::FORBIDDEN_FIELD);
        }
        // Nested, inside an object and inside an array of objects.
        let mut f = Forge::new();
        f.edit_first(
            "cases.jsonl",
            |_| true,
            |l| {
                l["expectation"][key] = json!(1);
            },
        );
        f.reseal();
        f.expect(reason::FORBIDDEN_FIELD);
        let mut f = Forge::new();
        f.edit_first(
            "cases.jsonl",
            |l| l["relationships"].as_array().is_some_and(|r| !r.is_empty()),
            |l| {
                l["relationships"][0][key] = json!(1);
            },
        );
        f.reseal();
        f.expect(reason::FORBIDDEN_FIELD);
    }
    let mut f = Forge::new();
    f.reseal();
    let mut m = f.manifest();
    m["supportState"] = json!("stable");
    f.set_manifest(&m);
    f.expect(reason::FORBIDDEN_FIELD);
}

#[test]
fn a_non_public_safe_source_is_refused() {
    for edit in [
        |l: &mut Value| l["license"]["redistribution"] = json!("unknown"),
        |l: &mut Value| l["valueOrigin"] = json!("real"),
        |l: &mut Value| l["naturallyOccurringPersonalData"] = json!(true),
    ] {
        let mut f = Forge::new();
        f.edit_first("sources.jsonl", |_| true, edit);
        f.reseal();
        f.expect(reason::SOURCE_NOT_PUBLIC_SAFE);
    }
    let mut f = Forge::new();
    f.edit_first(
        "cases.jsonl",
        |_| true,
        |l| l["valueOrigin"] = json!("real"),
    );
    f.reseal();
    f.expect(reason::SOURCE_NOT_PUBLIC_SAFE);
}

// ---------------------------------------------------------------------------
// Fail closed: counts, coverage, references, bytes and spans
// ---------------------------------------------------------------------------

#[test]
fn counts_and_coverage_must_equal_the_recomputed_values() {
    let mut f = Forge::new();
    f.reseal();
    let mut m = f.manifest();
    m["counts"]["cases"] = json!(48);
    f.set_manifest(&m);
    f.expect(reason::COUNT_MISMATCH);

    let mut f = Forge::new();
    f.reseal();
    let mut m = f.manifest();
    m["counts"].as_object_mut().unwrap().remove("fixtures");
    f.set_manifest(&m);
    f.expect(reason::COUNT_MISMATCH);

    let mut f = Forge::new();
    f.reseal();
    let mut m = f.manifest();
    m["coverage"]["identityStates"]["valid"] = json!(99);
    f.set_manifest(&m);
    f.expect(reason::COVERAGE_MISMATCH);
}

#[test]
fn a_dangling_reference_is_refused() {
    let mut f = Forge::new();
    f.edit_first(
        "cases.jsonl",
        |_| true,
        |l| {
            l["provenance"]["sources"] = json!(["no/such-source"]);
        },
    );
    f.reseal();
    f.expect(reason::REFERENCE_UNRESOLVED);

    let mut f = Forge::new();
    f.edit_first(
        "claims.jsonl",
        |_| true,
        |l| l["source"] = json!("no/such-source"),
    );
    f.reseal();
    f.expect(reason::REFERENCE_UNRESOLVED);

    let mut f = Forge::new();
    f.edit_first(
        "fixtures.jsonl",
        |_| true,
        |l| l["rule"] = json!("no/such-rule"),
    );
    f.reseal();
    f.expect(reason::REFERENCE_UNRESOLVED);

    let mut f = Forge::new();
    f.edit_first(
        "skipped.jsonl",
        |_| true,
        |l| l["case"] = json!("no/such-case"),
    );
    f.reseal();
    f.expect(reason::REFERENCE_UNRESOLVED);
}

#[test]
fn a_span_off_a_character_boundary_or_out_of_range_is_refused() {
    let mut f = Forge::new();
    f.edit_first(
        "fixtures.jsonl",
        |l| {
            l["content"].as_str().is_some_and(|c| !c.is_ascii())
                && l["spans"].as_array().is_some_and(|s| !s.is_empty())
        },
        |l| {
            // Move the start into the middle of the first multibyte character.
            let c = l["content"].as_str().unwrap();
            let first = c.char_indices().find(|(_, ch)| !ch.is_ascii()).unwrap().0;
            l["spans"][0]["start"] = json!(first + 1);
        },
    );
    f.reseal();
    f.expect(reason::SPAN_INVALID);

    let mut f = Forge::new();
    f.edit_first(
        "fixtures.jsonl",
        |l| l["spans"].as_array().is_some_and(|s| !s.is_empty()),
        |l| l["spans"][0]["end"] = json!(10_000),
    );
    f.reseal();
    f.expect(reason::SPAN_INVALID);

    let mut f = Forge::new();
    f.edit_first(
        "fixtures.jsonl",
        |l| l["spans"].as_array().is_some_and(|s| !s.is_empty()),
        |l| {
            let s = l["spans"][0]["start"].clone();
            l["spans"][0]["end"] = s;
        },
    );
    f.reseal();
    f.expect(reason::SPAN_INVALID);
}

#[test]
fn a_fixture_whose_expectation_differs_from_its_case_is_refused() {
    let mut f = Forge::new();
    f.edit_first(
        "fixtures.jsonl",
        |l| l["expectation"]["identity"] == "valid",
        |l| l["expectation"]["identity"] = json!("invalid"),
    );
    f.reseal();
    f.expect(reason::FIXTURE_EXPECTATION_MISMATCH);

    // A derived fixture may assert nothing stronger than the rule's weakest outcome.
    let mut f = Forge::new();
    f.edit_first(
        "fixtures.jsonl",
        |l| l["expectation"]["derivedFromRule"] == true,
        |l| l["expectation"]["identity"] = json!("valid"),
    );
    f.reseal();
    f.expect(reason::FIXTURE_EXPECTATION_MISMATCH);

    // A copied span must carry the authored value bytes.
    let mut f = Forge::new();
    f.edit_first(
        "fixtures.jsonl",
        |l| {
            l["spans"].as_array().is_some_and(|s| !s.is_empty())
                && l["content"]
                    .as_str()
                    .is_some_and(|c| c.is_ascii() && c.len() > 12)
        },
        |l| {
            let s = l["spans"][0]["start"].as_u64().unwrap();
            l["spans"][0]["start"] = json!(s + 1);
        },
    );
    f.reseal();
    f.expect(reason::FIXTURE_EXPECTATION_MISMATCH);
}

#[test]
fn recorded_validation_must_have_passed_and_exclusions_must_be_consistent() {
    let mut f = Forge::new();
    f.reseal();
    let mut m = f.manifest();
    m["validation"]["privacy"] = json!("failed");
    f.set_manifest(&m);
    f.expect(reason::VALIDATION_NOT_PASSED);

    let mut f = Forge::new();
    f.reseal();
    let mut m = f.manifest();
    m["validation"]["checks"][0]["status"] = json!("failed");
    f.set_manifest(&m);
    f.expect(reason::VALIDATION_NOT_PASSED);

    let mut f = Forge::new();
    let id = f.lines("cases.jsonl")[0]["id"].clone();
    f.reseal();
    let mut m = f.manifest();
    m["exclusions"]["cases"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id": id, "reasons": ["x"]}));
    m["counts"]["excludedCases"] = json!(m["exclusions"]["cases"].as_array().unwrap().len());
    f.set_manifest(&m);
    f.expect(reason::EXCLUSION_INCONSISTENT);
}

// ---------------------------------------------------------------------------
// Fail closed: the directory, and nothing is mapped when verification fails
// ---------------------------------------------------------------------------

static N: AtomicU64 = AtomicU64::new(0);

struct Tmp(PathBuf);
impl Tmp {
    fn new(label: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "pii-eval-evidence-{}-{}-{label}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let target = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_tree(&e.path(), &target);
        } else {
            std::fs::copy(e.path(), target).unwrap();
        }
    }
}

#[cfg(unix)]
#[test]
fn a_symlink_in_the_snapshot_directory_is_refused() {
    let tmp = Tmp::new("symlink");
    let dir = tmp.0.join("snap");
    copy_tree(&vendored(), &dir);
    std::fs::remove_file(dir.join("skipped.jsonl")).unwrap();
    std::os::unix::fs::symlink(vendored().join("skipped.jsonl"), dir.join("skipped.jsonl"))
        .unwrap();
    let err = read_dir(&dir).unwrap_err();
    assert_eq!(err.code, reason::FILE_NOT_REGULAR);
}

#[test]
fn a_directory_that_is_not_a_directory_or_is_missing_is_refused() {
    let tmp = Tmp::new("notdir");
    assert_eq!(
        read_dir(&tmp.0.join("absent")).unwrap_err().code,
        reason::SNAPSHOT_UNREADABLE
    );
    std::fs::write(tmp.0.join("file"), b"x").unwrap();
    assert_eq!(
        read_dir(&tmp.0.join("file")).unwrap_err().code,
        reason::FILE_NOT_REGULAR
    );
}

#[test]
fn an_unmapped_kind_or_jurisdiction_is_refused_at_mapping_not_guessed() {
    let mut v = verify(&files(), &pin()).unwrap();
    v.cases[0].privacy_kind = "national-id/unresolved/placeholder".into();
    assert_eq!(map(&v, &pin()).unwrap_err().code, reason::KIND_UNMAPPED);
    let mut v = verify(&files(), &pin()).unwrap();
    v.cases[0].jurisdiction = "unresolved".into();
    assert_eq!(
        map(&v, &pin()).unwrap_err().code,
        reason::JURISDICTION_UNMAPPED
    );
}

#[test]
fn expanded_families_have_faithful_identity_and_a_distinct_mapping_revision() {
    for (kind, jurisdiction, family, iso) in [
        (
            "date-of-birth/global/labeled-field",
            "global",
            "pii:global:date-of-birth",
            None,
        ),
        (
            "date-of-birth/global/labeled-field",
            "us",
            "pii:us:date-of-birth",
            Some("US"),
        ),
        (
            "date-of-birth/global/labeled-field",
            "uk",
            "pii:gb:date-of-birth",
            Some("GB"),
        ),
        (
            "uk-nino/uk/structured",
            "uk",
            "pii:gb:national-insurance-number",
            Some("GB"),
        ),
    ] {
        let mut v = verify(&files(), &pin()).unwrap();
        v.cases[0].privacy_kind = kind.into();
        v.cases[0].jurisdiction = jurisdiction.into();
        let a = map(&v, &pin()).unwrap();
        let b = map(&v, &pin()).unwrap();
        assert_eq!(snapshot_json(&a).unwrap(), snapshot_json(&b).unwrap());
        assert_eq!(a.binding, b.binding);
        assert_eq!(a.binding["semantic"]["mappingRule"]["revision"], 2);
        assert_eq!(a.snapshot.semantic.population.population_version, 2);
        assert_eq!(a.snapshot.semantic.generation.generator_version, 2);
        // Inspect the generated corpus directly: family and jurisdiction must
        // agree, never coerced onto an existing unrelated privacy family.
        assert!(a.snapshot.semantic.cases.iter().any(|c| {
            c.variants.iter().any(|variant| {
                variant
                    .expectations
                    .iter()
                    .any(|e| e.family.as_str() == family)
            }) && c.jurisdiction.as_ref().map(|j| j.as_str()) == iso
        }));
    }
    let legacy = map(&verify(&files(), &pin()).unwrap(), &pin()).unwrap();
    assert_eq!(legacy.binding["semantic"]["mappingRule"]["revision"], 1);
    assert_eq!(legacy.snapshot.semantic.population.population_version, 1);
}

#[test]
fn expanded_kind_with_wrong_jurisdiction_is_refused() {
    let mut v = verify(&files(), &pin()).unwrap();
    v.cases[0].privacy_kind = "uk-nino/uk/structured".into();
    v.cases[0].jurisdiction = "us".into();
    assert_eq!(
        map(&v, &pin()).unwrap_err().code,
        reason::JURISDICTION_UNMAPPED
    );
}

#[test]
fn errors_name_files_and_ids_never_text() {
    let mut f = Forge::new();
    f.edit_first(
        "fixtures.jsonl",
        |l| l["content"].as_str().is_some_and(|c| c.contains('@')),
        |l| {
            let c = l["content"].as_str().unwrap().replacen('@', "#", 1);
            l["content"] = json!(c);
        },
    );
    f.reseal();
    let err = f.check().unwrap_err();
    let line = err.human();
    for fixture in verify(&files(), &pin()).unwrap().fixtures {
        assert!(!line.contains(fixture.content.trim_end()));
    }
    assert!(!line.contains('@'));
}

// ---------------------------------------------------------------------------
// The binary: exit codes, and no output on refusal
// ---------------------------------------------------------------------------

fn evidence_bin() -> &'static str {
    env!("CARGO_BIN_EXE_pii-eval-evidence")
}

fn run(args: &[&str]) -> std::process::Output {
    std::process::Command::new(evidence_bin())
        .args(args)
        .output()
        .unwrap()
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn the_binary_verifies_imports_and_refuses_with_distinct_exit_codes() {
    let dir = vendored();
    let pin = pin_path();
    let ok = run(&["verify", "--snapshot-dir", s(&dir), "--pin", s(&pin)]);
    assert_eq!(ok.status.code(), Some(0));
    let summary: Value = serde_json::from_slice(&ok.stdout).unwrap();
    assert_eq!(summary["state"], "accepted");
    assert_eq!(summary["semantic"]["snapshotId"], SNAPSHOT_ID);

    let tmp = Tmp::new("bin");
    // A wrong pin: exit 4, nothing written.
    let mut bad = std::fs::read_to_string(&pin).unwrap();
    bad = bad.replace("9d4e8e036bbb\"", "ffffffffffff\"");
    let bad_pin = tmp.0.join("bad-pin.json");
    std::fs::write(&bad_pin, bad).unwrap();
    let out = tmp.0.join("out");
    let refused = run(&[
        "import",
        "--snapshot-dir",
        s(&dir),
        "--pin",
        s(&bad_pin),
        "--out",
        s(&out),
    ]);
    assert_eq!(
        refused.status.code(),
        Some(4),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(!out.exists(), "nothing is written on refusal");
    assert_eq!(String::from_utf8_lossy(&refused.stdout).lines().count(), 1);
    let summary: Value = serde_json::from_slice(&refused.stdout).unwrap();
    assert_eq!(summary["state"], "refused");

    // An unusable pin: exit 3. Usage errors: exit 2.
    std::fs::write(&bad_pin, "{}").unwrap();
    assert_eq!(
        run(&["verify", "--snapshot-dir", s(&dir), "--pin", s(&bad_pin)])
            .status
            .code(),
        Some(3)
    );
    assert_eq!(
        run(&["verify", "--snapshot-dir", s(&dir)]).status.code(),
        Some(2)
    );
    assert_eq!(run(&["verify", "--bogus", "x"]).status.code(), Some(2));
    assert_eq!(run(&[]).status.code(), Some(2));
    assert_eq!(run(&["frobnicate"]).status.code(), Some(2));

    // Import writes exactly the two documents, and refuses a non-empty output.
    let imported = run(&[
        "import",
        "--snapshot-dir",
        s(&dir),
        "--pin",
        s(&pin),
        "--out",
        s(&out),
    ]);
    assert_eq!(imported.status.code(), Some(0));
    let mut names: Vec<_> = std::fs::read_dir(&out)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, ["binding.json", "snapshot.json"]);
    let again = run(&[
        "import",
        "--snapshot-dir",
        s(&dir),
        "--pin",
        s(&pin),
        "--out",
        s(&out),
    ]);
    assert_ne!(again.status.code(), Some(0));
}

#[test]
fn the_binary_refuses_a_tampered_directory_and_writes_nothing() {
    let tmp = Tmp::new("tamper");
    let dir = tmp.0.join("snap");
    copy_tree(&vendored(), &dir);
    let target = dir.join("fixtures.jsonl");
    let mut bytes = std::fs::read(&target).unwrap();
    let at = bytes.iter().position(|b| *b == b'@').unwrap();
    bytes[at] = b'#';
    std::fs::write(&target, bytes).unwrap();
    let out = tmp.0.join("out");
    let r = run(&[
        "import",
        "--snapshot-dir",
        s(&dir),
        "--pin",
        s(&pin_path()),
        "--out",
        s(&out),
    ]);
    assert_eq!(r.status.code(), Some(4));
    assert!(!out.exists());
    let summary: Value = serde_json::from_slice(&r.stdout).unwrap();
    assert_eq!(summary["error"]["reason"], reason::FILE_DIGEST_MISMATCH);
    assert_eq!(summary["error"]["at"], "fixtures.jsonl");
}

#[test]
fn every_reason_code_is_documented() {
    let doc = std::fs::read_to_string(root().join("docs/evidence-consumer.md")).unwrap();
    for code in reason::ALL {
        assert!(
            doc.contains(&format!("`{code}`")),
            "{code} is not documented"
        );
    }
    for code in loss::ALL {
        assert!(
            doc.contains(&format!("`{code}`")),
            "{code} is not documented"
        );
    }
}
