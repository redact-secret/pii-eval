//! Verification of a snapshot BEFORE it is mapped or executed.
//!
//! The order is deliberate and fail-closed: contract name and version first (an
//! unknown version is never read further), then identity against the pin, then
//! population, the file list and every digest, then the content digest, the id
//! derivation and the source-manifest digest, then strict parsing of every
//! record, then counts, coverage, references, fixture bytes and spans, source
//! safety and recorded validation. The first failure is returned; nothing past
//! it is looked at. The checks are the contract's section 4, plus the
//! neutrality and population rules of section 2.

use std::collections::{BTreeMap, BTreeSet};

use pii_eval_contracts::Sha256Digest;
use serde::de::{self, DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

use super::files::SnapshotFiles;
use super::model::{
    CaseRec, ClaimRec, ContextsDoc, EventRec, FixtureRec, JurisdictionsDoc, KindsDoc, Manifest,
    RuleMode, RuleRec, SkipRec, SourceRec,
};
use super::pin::SnapshotPin;
use super::{
    CONTRACT_NAME, CONTRACT_VERSION, DIGEST_SPEC, EvidenceError, ID_PREFIX, RECORD_SCHEMA_VERSION,
    reason,
};

const MANIFEST: &str = "manifest.json";
const SOURCES: &str = "sources.jsonl";
const CLAIMS: &str = "claims.jsonl";
const CASES: &str = "cases.jsonl";
const FIXTURES: &str = "fixtures.jsonl";
const SKIPPED: &str = "skipped.jsonl";
const RULES: &str = "fixture-rules.jsonl";
const EVENTS: &str = "review-events.jsonl";
const KINDS: &str = "taxonomy/privacy-kinds.json";
const JURISDICTIONS: &str = "taxonomy/jurisdictions.json";
const CONTEXTS: &str = "taxonomy/contexts.json";

const REQUIRED: [&str; 9] = [
    SOURCES,
    CLAIMS,
    CASES,
    FIXTURES,
    SKIPPED,
    RULES,
    KINDS,
    JURISDICTIONS,
    CONTEXTS,
];

/// Key fragments that may never appear in a record (contract section 2: no
/// record carries a detector id, support state, threshold, score or current
/// scanner behavior). Compared case-insensitively against every object key at
/// every depth.
const BANNED_KEY_FRAGMENTS: [&str; 9] = [
    "scanner",
    "detector",
    "support",
    "threshold",
    "blocker",
    "score",
    "benchmark",
    "qualif",
    "expectedcurrent",
];

/// A verified snapshot: typed records, in file order, plus what the mapping
/// needs to cite them exactly.
#[derive(Debug)]
pub struct Verified {
    /// The manifest.
    pub manifest: Manifest,
    /// SHA-256 of `manifest.json`.
    pub manifest_sha256: String,
    /// Cases, ascending by id.
    pub cases: Vec<CaseRec>,
    /// SHA-256 of each case's record line (its exact bytes without the LF), by case id.
    pub case_line_sha256: BTreeMap<String, String>,
    /// Fixtures, ascending by id.
    pub fixtures: Vec<FixtureRec>,
    /// Rules, ascending by id.
    pub rules: Vec<RuleRec>,
    /// Skipped pairs, ascending by id.
    pub skipped: Vec<SkipRec>,
    /// The kind taxonomy.
    pub kinds: KindsDoc,
}

fn sha(bytes: &[u8]) -> String {
    Sha256Digest::of_bytes(bytes).as_str().to_owned()
}

/// Whether any object key at any depth names scanner or policy state.
pub fn forbidden_key(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(k, v)| {
            let lower = k.to_ascii_lowercase();
            BANNED_KEY_FRAGMENTS.iter().any(|f| lower.contains(f)) || forbidden_key(v)
        }),
        Value::Array(items) => items.iter().any(forbidden_key),
        _ => false,
    }
}

fn classify(e: &serde_json::Error, at: &str) -> EvidenceError {
    // Only the message PREFIX is read, never echoed: serde writes
    // "missing field `name`" for an absent required property.
    if e.to_string().starts_with("missing field") {
        EvidenceError::invalid(reason::RECORD_FIELD_MISSING, at)
    } else {
        EvidenceError::invalid(reason::RECORD_FIELD_INVALID, at)
    }
}

fn typed<T: DeserializeOwned>(value: Value, at: &str) -> Result<T, EvidenceError> {
    serde_json::from_value(value).map_err(|e| classify(&e, at))
}

fn str_of<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

/// The envelope every record carries: `kind` and `schemaVersion`, and a public
/// population where one is stated.
fn envelope(value: &Value, kind: &str, at: &str) -> Result<(), EvidenceError> {
    if str_of(value, "kind") != Some(kind) {
        return Err(EvidenceError::invalid(reason::RECORD_KIND_UNKNOWN, at));
    }
    if str_of(value, "schemaVersion") != Some(RECORD_SCHEMA_VERSION) {
        return Err(EvidenceError::invalid(reason::SCHEMA_VERSION_UNKNOWN, at));
    }
    if let Some(p) = value.get("population") {
        if p.as_str() != Some("public") {
            return Err(EvidenceError::identity(reason::POPULATION_NOT_PUBLIC, at));
        }
    }
    if forbidden_key(value) {
        return Err(EvidenceError::invalid(reason::FORBIDDEN_FIELD, at));
    }
    Ok(())
}

/// Deepest nesting accepted in an evidence document.
const MAX_DEPTH: usize = 32;
/// Largest integer magnitude accepted (2^53 - 1: exact in every JSON reader).
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// A strict JSON reader for evidence files: no duplicate object key, no float,
/// no integer beyond 2^53 - 1, bounded depth. Unlike the contracts' own strict
/// parser it accepts `null`, which the evidence taxonomy uses (the contract
/// does not forbid it).
struct Strict {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for Strict {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Strict {
    type Value = Value;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("strict JSON")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        if v > MAX_SAFE_INTEGER {
            return Err(E::custom("integer"));
        }
        Ok(Value::from(v))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        if v.unsigned_abs() > MAX_SAFE_INTEGER {
            return Err(E::custom("integer"));
        }
        Ok(Value::from(v))
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Value, E> {
        Err(E::custom("float"))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        if self.depth >= MAX_DEPTH {
            return Err(de::Error::custom("depth"));
        }
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(Strict {
            depth: self.depth + 1,
        })? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        if self.depth >= MAX_DEPTH {
            return Err(de::Error::custom("depth"));
        }
        let mut object = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            let value = map.next_value_seed(Strict {
                depth: self.depth + 1,
            })?;
            if object.insert(key, value).is_some() {
                return Err(de::Error::custom("duplicate"));
            }
        }
        Ok(Value::Object(object))
    }
}

fn parse_doc(path: &str, bytes: &[u8]) -> Result<Value, EvidenceError> {
    let bad = || EvidenceError::invalid(reason::RECORD_INVALID, path);
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let value = Strict { depth: 0 }
        .deserialize(&mut de)
        .map_err(|_| bad())?;
    de.end().map_err(|_| bad())?;
    Ok(value)
}

/// Parse one JSON Lines file into typed records with the SHA-256 of each line.
fn parse_jsonl<T: DeserializeOwned>(
    path: &str,
    bytes: &[u8],
    kind: &str,
    id_of: impl Fn(&T) -> &str,
) -> Result<Vec<(T, String)>, EvidenceError> {
    let bad = |at: String| EvidenceError::invalid(reason::RECORD_INVALID, at);
    let text = std::str::from_utf8(bytes).map_err(|_| bad(path.to_owned()))?;
    if text.contains('\r') || (!text.is_empty() && !text.ends_with('\n')) {
        return Err(bad(path.to_owned()));
    }
    let mut out: Vec<(T, String)> = Vec::new();
    for (n, line) in text.split_terminator('\n').enumerate() {
        let at = format!("{path}:{}", n + 1);
        if line.is_empty() {
            return Err(bad(at));
        }
        let value = parse_doc(&at, line.as_bytes())?;
        envelope(&value, kind, &at)?;
        let record: T = typed(value, &at)?;
        if let Some((prev, _)) = out.last() {
            if id_of(prev) >= id_of(&record) {
                return Err(EvidenceError::invalid(reason::ID_ORDER_INVALID, at));
            }
        }
        out.push((record, sha(line.as_bytes())));
    }
    Ok(out)
}

fn taxonomy<T: DeserializeOwned>(
    files: &SnapshotFiles,
    path: &str,
    kind: &str,
) -> Result<T, EvidenceError> {
    let bytes = files
        .get(path)
        .ok_or_else(|| EvidenceError::identity(reason::FILE_MISSING, path))?;
    let value = parse_doc(path, bytes)?;
    if str_of(&value, "kind") != Some(kind) {
        return Err(EvidenceError::invalid(reason::RECORD_KIND_UNKNOWN, path));
    }
    if str_of(&value, "schemaVersion") != Some(RECORD_SCHEMA_VERSION) {
        return Err(EvidenceError::invalid(reason::SCHEMA_VERSION_UNKNOWN, path));
    }
    if forbidden_key(&value) {
        return Err(EvidenceError::invalid(reason::FORBIDDEN_FIELD, path));
    }
    typed(value, path)
}

fn is_safe_path(p: &str) -> bool {
    !p.is_empty()
        && !p.starts_with('/')
        && !p.contains('\\')
        && p.split('/').all(|s| !s.is_empty() && s != "." && s != "..")
}

fn content_digest(files: &SnapshotFiles) -> String {
    let mut lines = String::new();
    for (path, bytes) in files.iter() {
        if path != MANIFEST {
            lines.push_str(&sha(bytes));
            lines.push(' ');
            lines.push_str(path);
            lines.push('\n');
        }
    }
    sha(lines.as_bytes())
}

fn valid_date(d: &str) -> bool {
    let b = d.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b.iter()
            .enumerate()
            .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
        && (1..=12).contains(&d[5..7].parse::<u32>().unwrap_or(0))
        && (1..=31).contains(&d[8..10].parse::<u32>().unwrap_or(0))
}

/// Verify `files` against `pin` and against themselves. See the module docs.
pub fn verify(files: &SnapshotFiles, pin: &SnapshotPin) -> Result<Verified, EvidenceError> {
    // 1. The manifest, and the contract it claims, before anything else.
    let manifest_bytes = files
        .get(MANIFEST)
        .ok_or_else(|| EvidenceError::identity(reason::FILE_MISSING, MANIFEST))?;
    let raw = parse_doc(MANIFEST, manifest_bytes)
        .map_err(|e| EvidenceError::invalid(reason::MANIFEST_INVALID, e.at))?;
    if str_of(&raw, "consumerContract") != Some(CONTRACT_NAME) {
        return Err(EvidenceError::identity(reason::CONTRACT_UNKNOWN, MANIFEST));
    }
    if str_of(&raw, "consumerContractVersion") != Some(CONTRACT_VERSION) {
        return Err(EvidenceError::identity(
            reason::CONTRACT_VERSION_UNKNOWN,
            MANIFEST,
        ));
    }
    if str_of(&raw, "contentDigestSpec") != Some(DIGEST_SPEC) {
        return Err(EvidenceError::identity(
            reason::DIGEST_SPEC_UNKNOWN,
            MANIFEST,
        ));
    }
    envelope(&raw, "snapshot-manifest", MANIFEST)?;
    let manifest: Manifest = typed(raw, MANIFEST)?;

    // 2. Identity against the pin: wrong or incompatible identity stops here.
    if manifest.id != pin.id {
        return Err(EvidenceError::identity(reason::SNAPSHOT_ID_MISMATCH, "id"));
    }
    let manifest_sha256 = sha(manifest_bytes);
    if manifest_sha256 != pin.manifest_sha256 {
        return Err(EvidenceError::identity(
            reason::MANIFEST_DIGEST_MISMATCH,
            MANIFEST,
        ));
    }
    if manifest.content_digest != pin.content_digest {
        return Err(EvidenceError::identity(
            reason::CONTENT_DIGEST_MISMATCH,
            "contentDigest",
        ));
    }
    if manifest.source_manifest_digest != pin.source_manifest_digest {
        return Err(EvidenceError::identity(
            reason::SOURCE_MANIFEST_DIGEST_MISMATCH,
            "sourceManifestDigest",
        ));
    }

    // 3. Population.
    if manifest.population != "public" {
        return Err(EvidenceError::identity(
            reason::POPULATION_NOT_PUBLIC,
            "population",
        ));
    }

    // 4. The file list: exactly the listed set, every length and digest.
    for required in REQUIRED {
        if files.get(required).is_none() {
            return Err(EvidenceError::identity(reason::FILE_MISSING, required));
        }
    }
    let mut listed: BTreeMap<&str, &super::model::ManifestFile> = BTreeMap::new();
    for f in &manifest.files {
        if !is_safe_path(&f.path) || f.path == MANIFEST || listed.insert(&f.path, f).is_some() {
            return Err(EvidenceError::invalid(reason::MANIFEST_INVALID, "files"));
        }
    }
    for path in files.paths().filter(|p| *p != MANIFEST) {
        if !listed.contains_key(path) {
            return Err(EvidenceError::identity(reason::FILE_UNLISTED, path));
        }
    }
    for (path, entry) in &listed {
        let bytes = files
            .get(path)
            .ok_or_else(|| EvidenceError::identity(reason::FILE_MISSING, *path))?;
        if bytes.len() as u64 != entry.bytes {
            return Err(EvidenceError::identity(reason::FILE_LENGTH_MISMATCH, *path));
        }
        if sha(bytes) != entry.sha256 {
            return Err(EvidenceError::identity(reason::FILE_DIGEST_MISMATCH, *path));
        }
        if let Some(records) = entry.records {
            let lines = bytes
                .split(|b| *b == b'\n')
                .filter(|l| !l.is_empty())
                .count() as u64;
            if lines != records {
                return Err(EvidenceError::identity(
                    reason::RECORD_COUNT_MISMATCH,
                    *path,
                ));
            }
        }
    }

    // 5. Content digest, id derivation, source-manifest digest.
    let digest = content_digest(files);
    if digest != manifest.content_digest {
        return Err(EvidenceError::identity(
            reason::CONTENT_DIGEST_MISMATCH,
            "contentDigest",
        ));
    }
    if !valid_date(&manifest.snapshot_date)
        || manifest.id != format!("{ID_PREFIX}/{}/{}", manifest.snapshot_date, &digest[..12])
    {
        return Err(EvidenceError::identity(
            reason::SNAPSHOT_ID_DERIVATION,
            "id",
        ));
    }
    let sources_bytes = files.get(SOURCES).unwrap_or_default();
    if sha(sources_bytes) != manifest.source_manifest_digest {
        return Err(EvidenceError::identity(
            reason::SOURCE_MANIFEST_DIGEST_MISMATCH,
            SOURCES,
        ));
    }

    // 6. Strict parse of every record. Neutrality, population, kind and
    // schema version are checked per record before the typed read.
    let get = |p: &str| files.get(p).unwrap_or_default();
    let sources = parse_jsonl::<SourceRec>(SOURCES, get(SOURCES), "source", |r| &r.id)?;
    let claims = parse_jsonl::<ClaimRec>(CLAIMS, get(CLAIMS), "claim", |r| &r.id)?;
    let cases = parse_jsonl::<CaseRec>(CASES, get(CASES), "case", |r| &r.id)?;
    let fixtures =
        parse_jsonl::<FixtureRec>(FIXTURES, get(FIXTURES), "fixture-projection", |r| &r.id)?;
    let skipped = parse_jsonl::<SkipRec>(SKIPPED, get(SKIPPED), "fixture-skip", |r| &r.id)?;
    let rules = parse_jsonl::<RuleRec>(RULES, get(RULES), "fixture-rule", |r| &r.id)?;
    let events = match files.get(EVENTS) {
        Some(bytes) => parse_jsonl::<EventRec>(EVENTS, bytes, "review-event", |r| &r.id)?,
        None => Vec::new(),
    };
    let kinds: KindsDoc = taxonomy(files, KINDS, "privacy-kinds")?;
    let jurisdictions: JurisdictionsDoc = taxonomy(files, JURISDICTIONS, "jurisdictions")?;
    let contexts: ContextsDoc = taxonomy(files, CONTEXTS, "contexts")?;
    for fixture in fixtures.iter().map(|(f, _)| f) {
        if fixture.population != "public" {
            return Err(EvidenceError::identity(
                reason::POPULATION_NOT_PUBLIC,
                fixture.id.as_str(),
            ));
        }
    }
    for skip in skipped.iter().map(|(s, _)| s) {
        if skip.population != "public" {
            return Err(EvidenceError::identity(
                reason::POPULATION_NOT_PUBLIC,
                skip.id.as_str(),
            ));
        }
    }

    let case_line_sha256: BTreeMap<String, String> = cases
        .iter()
        .map(|(c, line)| (c.id.clone(), line.clone()))
        .collect();
    let cases: Vec<CaseRec> = cases.into_iter().map(|(c, _)| c).collect();
    let fixtures: Vec<FixtureRec> = fixtures.into_iter().map(|(f, _)| f).collect();
    let rules: Vec<RuleRec> = rules.into_iter().map(|(r, _)| r).collect();
    let skipped: Vec<SkipRec> = skipped.into_iter().map(|(s, _)| s).collect();
    let sources: Vec<SourceRec> = sources.into_iter().map(|(s, _)| s).collect();
    let claims: Vec<ClaimRec> = claims.into_iter().map(|(c, _)| c).collect();
    let events: Vec<EventRec> = events.into_iter().map(|(e, _)| e).collect();

    // 7. Counts, exclusions, coverage.
    let counted = [
        ("cases", cases.len()),
        ("fixtures", fixtures.len()),
        ("sources", sources.len()),
        ("claims", claims.len()),
        ("skipped", skipped.len()),
        ("rules", rules.len()),
        ("reviewEvents", events.len()),
        ("excludedCases", manifest.exclusions.cases.len()),
        ("excludedSources", manifest.exclusions.sources.len()),
        ("excludedClaims", manifest.exclusions.claims.len()),
    ];
    for (key, n) in counted {
        if manifest.counts.get(key).copied() != Some(n as u64) {
            return Err(EvidenceError::invalid(reason::COUNT_MISMATCH, key));
        }
    }
    let present: BTreeSet<&str> = sources
        .iter()
        .map(|s| s.id.as_str())
        .chain(claims.iter().map(|c| c.id.as_str()))
        .chain(cases.iter().map(|c| c.id.as_str()))
        .chain(rules.iter().map(|r| r.id.as_str()))
        .collect();
    let excluded = manifest
        .exclusions
        .sources
        .iter()
        .chain(&manifest.exclusions.claims)
        .chain(&manifest.exclusions.cases)
        .chain(&manifest.exclusions.rules);
    for e in excluded {
        if present.contains(e.id.as_str()) {
            return Err(EvidenceError::invalid(
                reason::EXCLUSION_INCONSISTENT,
                e.id.as_str(),
            ));
        }
    }
    let kind_ids: Vec<&str> = kinds.kinds.iter().map(|k| k.id.as_str()).collect();
    let mut expected_coverage = coverage_of(&cases, &fixtures, &kind_ids);
    let mut recorded_coverage = manifest.coverage.clone();
    if let Some(m) = recorded_coverage.as_object_mut() {
        // `languages` is an optional additive summary this consumer does not recompute.
        m.remove("languages");
    }
    if let Some(m) = expected_coverage.as_object_mut() {
        m.remove("languages");
    }
    if recorded_coverage != expected_coverage {
        return Err(EvidenceError::invalid(
            reason::COVERAGE_MISMATCH,
            "coverage",
        ));
    }

    // 8. Recorded validation and source safety.
    let v = &manifest.validation;
    if [&v.schema, &v.provenance, &v.privacy]
        .iter()
        .any(|s| s.as_str() != "passed")
        || v.checks.iter().any(|c| c.status != "passed")
    {
        return Err(EvidenceError::invalid(
            reason::VALIDATION_NOT_PASSED,
            "validation",
        ));
    }
    let safe_origin = |o: &str| matches!(o, "reserved" | "synthetic" | "public-test");
    for s in &sources {
        if s.license.redistribution != "allowed"
            || !safe_origin(&s.value_origin)
            || s.naturally_occurring_personal_data
        {
            return Err(EvidenceError::invalid(
                reason::SOURCE_NOT_PUBLIC_SAFE,
                s.id.as_str(),
            ));
        }
    }

    // 9. References.
    let kind_set = ids(kind_ids.clone());
    let jur_set = ids(jurisdictions
        .jurisdictions
        .iter()
        .map(|j| j.id.as_str())
        .collect());
    let ctx_set = ids(contexts.contexts.iter().map(|c| c.id.as_str()).collect());
    let source_set = ids(sources.iter().map(|s| s.id.as_str()).collect());
    let claim_set = ids(claims.iter().map(|c| c.id.as_str()).collect());
    let case_set = ids(cases.iter().map(|c| c.id.as_str()).collect());
    let event_set = ids(events.iter().map(|e| e.id.as_str()).collect());
    let unresolved = |at: &str| EvidenceError::invalid(reason::REFERENCE_UNRESOLVED, at);
    for claim in &claims {
        if !source_set.contains(claim.source.as_str()) {
            return Err(unresolved(&claim.id));
        }
    }
    for case in &cases {
        if !safe_origin(&case.value_origin) {
            return Err(EvidenceError::invalid(
                reason::SOURCE_NOT_PUBLIC_SAFE,
                case.id.as_str(),
            ));
        }
        let ok = kind_set.contains(case.privacy_kind.as_str())
            && jur_set.contains(case.jurisdiction.as_str())
            && case.contexts.iter().all(|c| ctx_set.contains(c.as_str()))
            && case
                .provenance
                .sources
                .iter()
                .all(|s| source_set.contains(s.as_str()))
            && case
                .provenance
                .claims
                .iter()
                .all(|c| claim_set.contains(c.as_str()))
            && case
                .relationships
                .iter()
                .all(|r| case_set.contains(r.case.as_str()))
            && case
                .review
                .events
                .iter()
                .all(|e| event_set.contains(e.as_str()));
        if !ok {
            return Err(unresolved(&case.id));
        }
        if let Some(span) = case.expectation.span {
            let text = case
                .input
                .as_ref()
                .ok_or_else(|| EvidenceError::invalid(reason::SPAN_INVALID, case.id.as_str()))?;
            if !span_ok(&text.text, span.start, span.end) {
                return Err(EvidenceError::invalid(
                    reason::SPAN_INVALID,
                    case.id.as_str(),
                ));
            }
        }
    }
    let rule_by_id: BTreeMap<&str, &RuleRec> = rules.iter().map(|r| (r.id.as_str(), r)).collect();
    let case_by_id: BTreeMap<&str, &CaseRec> = cases.iter().map(|c| (c.id.as_str(), c)).collect();
    for rule in &rules {
        if rule
            .justified_by
            .iter()
            .any(|c| !case_set.contains(c.as_str()))
        {
            return Err(unresolved(&rule.id));
        }
    }
    let mut pairs: BTreeSet<(&str, &str)> = BTreeSet::new();
    for skip in &skipped {
        if !case_set.contains(skip.case.as_str())
            || !rule_by_id.contains_key(skip.rule.as_str())
            || skip.id != format!("{}/{}", skip.case, skip.rule)
            || !pairs.insert((skip.case.as_str(), skip.rule.as_str()))
        {
            return Err(unresolved(&skip.id));
        }
    }

    // 10. Fixtures: identity, bytes, spans, expectation against case and rule.
    for f in &fixtures {
        let (Some(case), Some(rule)) = (
            case_by_id.get(f.case.as_str()),
            rule_by_id.get(f.rule.as_str()),
        ) else {
            return Err(unresolved(&f.id));
        };
        if f.id != format!("{}/{}", f.case, f.rule)
            || !pairs.insert((f.case.as_str(), f.rule.as_str()))
            || f.rule_version != rule.rule_version
            || f.lineage
                .sources
                .iter()
                .any(|s| !source_set.contains(s.as_str()))
            || f.lineage
                .claims
                .iter()
                .any(|c| !claim_set.contains(c.as_str()))
            || f.lineage.evidence_class != case.provenance.evidence_class
            || f.lineage.sources != case.provenance.sources
            || f.lineage.claims != case.provenance.claims
        {
            return Err(unresolved(&f.id));
        }
        let bytes = f.content.as_bytes();
        if bytes.len() as u64 != f.byte_length {
            return Err(EvidenceError::invalid(
                reason::FIXTURE_LENGTH_MISMATCH,
                f.id.as_str(),
            ));
        }
        if sha(bytes) != f.sha256 {
            return Err(EvidenceError::invalid(
                reason::FIXTURE_DIGEST_MISMATCH,
                f.id.as_str(),
            ));
        }
        if f.spans.len() > 1 || f.spans.iter().any(|s| !span_ok(&f.content, s.start, s.end)) {
            return Err(EvidenceError::invalid(reason::SPAN_INVALID, f.id.as_str()));
        }
        let mismatch =
            || EvidenceError::invalid(reason::FIXTURE_EXPECTATION_MISMATCH, f.id.as_str());
        let e = &f.expectation;
        if e.domains != case.expectation.domains {
            return Err(mismatch());
        }
        match rule.expectation.mode {
            RuleMode::Copy => {
                if e.derived_from_rule
                    || e.identity != case.expectation.identity
                    || e.sensitivity != case.expectation.sensitivity
                {
                    return Err(mismatch());
                }
                let want = case.expectation.span.and_then(|s| {
                    case.input
                        .as_ref()
                        .map(|t| t.text.as_bytes()[s.start as usize..s.end as usize].to_vec())
                });
                match (f.spans.first(), want) {
                    (None, None) => {}
                    (Some(s), Some(value)) => {
                        if f.content.as_bytes()[s.start as usize..s.end as usize] != value[..] {
                            return Err(mismatch());
                        }
                    }
                    _ => return Err(mismatch()),
                }
            }
            RuleMode::Derived => {
                if !e.derived_from_rule
                    || e.identity != super::model::Identity::NotEstablished
                    || e.sensitivity != super::model::Sensitivity::ContextDependent
                    || !f.spans.is_empty()
                {
                    return Err(mismatch());
                }
            }
        }
    }

    Ok(Verified {
        manifest,
        manifest_sha256,
        cases,
        case_line_sha256,
        fixtures,
        rules,
        skipped,
        kinds,
    })
}

/// A non-empty `[start, end)` inside `text` on character boundaries.
fn ids(it: Vec<&str>) -> BTreeSet<&str> {
    it.into_iter().collect()
}

fn span_ok(text: &str, start: u64, end: u64) -> bool {
    let (Ok(start), Ok(end)) = (usize::try_from(start), usize::try_from(end)) else {
        return false;
    };
    start < end && end <= text.len() && text.is_char_boundary(start) && text.is_char_boundary(end)
}

fn tally<'a>(items: impl Iterator<Item = &'a str>) -> Value {
    let mut m: BTreeMap<&str, u64> = BTreeMap::new();
    for i in items {
        *m.entry(i).or_default() += 1;
    }
    Value::Object(
        m.into_iter()
            .map(|(k, v)| (k.to_owned(), Value::from(v)))
            .collect(),
    )
}

fn sorted_unique<'a>(items: impl Iterator<Item = &'a str>) -> Value {
    let set: BTreeSet<&str> = items.collect();
    Value::Array(set.into_iter().map(Value::from).collect())
}

/// The coverage summary, recomputed exactly as the producer defines it.
fn coverage_of(cases: &[CaseRec], fixtures: &[FixtureRec], kind_ids: &[&str]) -> Value {
    let mut per_kind: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
    for c in cases {
        per_kind.entry(&c.privacy_kind).or_default().0 += 1;
    }
    let kind_of: BTreeMap<&str, &str> = cases
        .iter()
        .map(|c| (c.id.as_str(), c.privacy_kind.as_str()))
        .collect();
    for f in fixtures {
        if let Some(kind) = kind_of.get(f.case.as_str()) {
            per_kind.entry(kind).or_default().1 += 1;
        }
    }
    let with_cases: BTreeSet<&str> = cases.iter().map(|c| c.privacy_kind.as_str()).collect();
    let mut m = Map::new();
    m.insert(
        "kinds".into(),
        sorted_unique(cases.iter().map(|c| c.privacy_kind.as_str())),
    );
    m.insert(
        "jurisdictions".into(),
        sorted_unique(cases.iter().map(|c| c.jurisdiction.as_str())),
    );
    m.insert(
        "contexts".into(),
        sorted_unique(
            cases
                .iter()
                .flat_map(|c| c.contexts.iter().map(String::as_str)),
        ),
    );
    m.insert(
        "domains".into(),
        sorted_unique(
            cases
                .iter()
                .flat_map(|c| c.expectation.domains.iter().map(String::as_str)),
        ),
    );
    m.insert(
        "perKind".into(),
        Value::Object(
            per_kind
                .into_iter()
                .map(|(k, (c, f))| (k.to_owned(), serde_json::json!({"cases": c, "fixtures": f})))
                .collect(),
        ),
    );
    m.insert("roles".into(), tally(cases.iter().map(|c| c.role.as_str())));
    m.insert(
        "identityStates".into(),
        tally(cases.iter().map(|c| c.expectation.identity.as_str())),
    );
    m.insert(
        "evidenceClasses".into(),
        tally(cases.iter().map(|c| c.provenance.evidence_class.as_str())),
    );
    m.insert(
        "kindsWithoutCases".into(),
        sorted_unique(kind_ids.iter().copied().filter(|k| !with_cases.contains(k))),
    );
    Value::Object(m)
}
