//! The comparator: oracle export versus the Rust engine, layer by layer, with
//! every difference attributed to a classified id or reported as unexplained.
//!
//! Layers (ADR 0012):
//!
//! * `variant`: the oracle's generated variants against the kernel's methods;
//! * `outcome-compat`: oracle outcomes against the legacy compatibility mode
//!   (`pii-eval-compat`); the compatibility protocol promises equality;
//! * `outcome`: legacy against the canonical matcher, same findings; every
//!   difference needs a counterfactual that removes it (see [`attribute`]);
//! * `accounting-compat`: the oracle's metrics against the legacy accounting
//!   port (`pii-eval-compat::legacy_accounting`); equality is promised;
//! * `accounting-rule`: the oracle's metrics against the kernel's accounting on
//!   the SAME legacy rows, attributed by switching one oracle quirk at a time;
//! * `accounting-canonical`: the full canonical path (canonical rows, kernel
//!   accounting) against the oracle, attributed as the telescoping of the two
//!   steps above;
//! * `statistics-compat` / `statistics`: the Wilson arithmetic over a grid;
//! * `population`: case and row counts.
//!
//! A difference with no explanation is [`Class::Unexplained`]; the suite requires
//! none. The comparator is a pure function of the dataset, so the negative tests
//! can corrupt a copy of the export and require the corruption to be found.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use pii_eval_compat::legacy_accounting::{
    LegacyMechanics, LegacyMetric, LegacyRate, LegacyRow, Quirks, account_rows, proportion,
};
use pii_eval_contracts::{
    ActionExpectation, ActionOutcome, BoundDirection, ByteRange, Case, CaseOutcome, Collision,
    ContextClass, ContextObligation, CorpusSnapshotBody, Derivation, Expectation, ExpectedType,
    FamilyId, Finding, JurisdictionCode, LanguageTag, Lineage, Mechanics, MethodId, MetricCounts,
    MetricId, MetricStatus, MetricValue, ObservedSummary, Population, RangeState, ScaledDecimal,
    ScannerId, ScannerStatus, SensitivityExpectation, SensitivityState, Sha256Digest, Strategy,
    TypeState, Variant, Visibility, WithheldReason,
};
use pii_eval_kernel::{
    AuthoredIndex, MetricAccount, ScannerInput, VariantAssessment, account_outcomes,
    published_value, round_ratio, wilson_mantissa,
};
use serde_json::Value;

use super::json::*;
use super::model::*;
use super::rows::*;

// ---------------------------------------------------------------------------
// Classes and explanation ids
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    IntendedRevision,
    OldBug,
    NewBug,
    Compatibility,
    Unresolved,
    Unexplained,
}

impl Class {
    pub const fn as_str(self) -> &'static str {
        match self {
            Class::IntendedRevision => "intended-versioned-revision",
            Class::OldBug => "old-bug",
            Class::NewBug => "new-bug",
            Class::Compatibility => "compatibility",
            Class::Unresolved => "unresolved",
            Class::Unexplained => "unexplained",
        }
    }
}

/// Every id a difference can be attributed to: (qualified id, class, what it is).
/// The qualified id is `<adr>/<row>` (ADR 0004 D1-D11, ADR 0005 A2-A9 and S1,
/// ADR 0007 D1-D9, ADR 0008 R1-R7). The classes are decided in ADR 0012.
pub const EXPLANATIONS: &[(&str, Class, &str)] = &[
    (
        "0004/D1",
        Class::OldBug,
        "the first overlapping finding decides every axis, so the oracle result depends on scanner emission order; the canonical matcher selects by closeness and identity (fix delivered by protocol revision 2)",
    ),
    (
        "0004/D3",
        Class::IntendedRevision,
        "a selected finding with no sensitivity value is not-measured; legacy reads it as not flagged",
    ),
    (
        "0004/D6",
        Class::IntendedRevision,
        "a range that is not valid on the text (empty, out of bounds, inside a character) is refused; legacy and the oracle match or reject it by their own rules",
    ),
    (
        "0005/A2",
        Class::OldBug,
        "the oracle takes eligibility for the valid-type metrics from the first variant of a case (after a locale-dependent sort) and judges every variant; the canonical rule judges the valid-type occurrences",
    ),
    (
        "0005/A3",
        Class::IntendedRevision,
        "a benign case with several variants throws in the oracle; the canonical rule counts one sample",
    ),
    (
        "0008/R3",
        Class::IntendedRevision,
        "benign and collision cases count when ALL rows pass (oracle: any row; ADR 0005 A8)",
    ),
    (
        "0005/S1",
        Class::IntendedRevision,
        "the oracle rounds binary64 with toFixed; the canonical rule rounds the exact rational half up; they differ only at ties and near-ties",
    ),
    (
        "0007/D1",
        Class::Compatibility,
        "variant ids are snapshot-unique digests of case and slot; the slot (the oracle's variant id) is compared equal",
    ),
    (
        "0007/D4",
        Class::Compatibility,
        "an authored variant records no operator and no seed in the contract; a held variant records the review-hold operator",
    ),
];

pub fn class_of(id: &str) -> Class {
    EXPLANATIONS
        .iter()
        .find(|(i, _, _)| *i == id)
        .map_or(Class::Unexplained, |(_, c, _)| *c)
}

/// One difference between the oracle and a Rust path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Difference {
    pub layer: &'static str,
    pub scanner: String,
    pub subject: String,
    pub aspect: String,
    pub oracle: String,
    pub rust: String,
    /// Explanation ids; empty means unexplained.
    pub ids: Vec<&'static str>,
}

impl Difference {
    pub fn class(&self) -> Class {
        // The class of a difference is that of its explanations; with several the
        // order of precedence is the order of the enum (intended before old bug).
        self.ids
            .iter()
            .map(|i| class_of(i))
            .min()
            .unwrap_or(Class::Unexplained)
    }
}

/// What was compared and found.
#[derive(Debug, Default, Clone)]
pub struct Comparison {
    pub differences: Vec<Difference>,
    /// How many items each layer compared (non-vacuity evidence).
    pub compared: BTreeMap<&'static str, u64>,
    /// Per scanner: (oracle status, variants, rows equal in compat, rows differing canonically).
    pub scanners: Vec<ScannerSummary>,
    pub vectors: Vec<VectorSummary>,
    /// Canonical metrics per complete scanner, for the engine end-to-end check.
    pub canonical: BTreeMap<String, Vec<(MetricId, MetricView)>>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ScannerSummary {
    pub id: String,
    pub status: String,
    pub variants: u64,
    pub canonical_refused: u64,
    pub canonical_accounted: bool,
}

#[derive(Debug, Clone)]
pub struct VectorSummary {
    pub id: String,
    pub oracle_throws: bool,
    pub metrics_differing: u64,
}

impl Comparison {
    fn bump(&mut self, layer: &'static str, n: u64) {
        *self.compared.entry(layer).or_default() += n;
    }

    fn diff(
        &mut self,
        layer: &'static str,
        scanner: &str,
        subject: &str,
        aspect: &str,
        oracle: impl ToString,
        rust: impl ToString,
        ids: Vec<&'static str>,
    ) {
        self.differences.push(Difference {
            layer,
            scanner: scanner.to_owned(),
            subject: subject.to_owned(),
            aspect: aspect.to_owned(),
            oracle: oracle.to_string(),
            rust: rust.to_string(),
            ids,
        });
    }

    pub fn unexplained(&self) -> Vec<&Difference> {
        self.differences
            .iter()
            .filter(|d| d.class() == Class::Unexplained)
            .collect()
    }

    /// Differences of the compatibility layers, which promise equality.
    pub fn compat_differences(&self) -> Vec<&Difference> {
        self.differences
            .iter()
            .filter(|d| d.layer.ends_with("-compat"))
            .collect()
    }

    pub fn ids_exercised(&self) -> BTreeMap<&'static str, u64> {
        let mut out = BTreeMap::new();
        for d in &self.differences {
            for id in &d.ids {
                *out.entry(*id).or_default() += 1;
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Metric views
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateView {
    Null,
    Insufficient,
    Value { point: u64, bound: u64, n: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricView {
    pub counts: MetricCounts,
    pub status: MetricStatus,
    pub effective_n: u64,
    pub rate: RateView,
}

impl MetricView {
    pub fn describe(&self) -> String {
        let c = &self.counts;
        let rate = match self.rate {
            RateView::Null => "null".to_owned(),
            RateView::Insufficient => "insufficient-evidence".to_owned(),
            RateView::Value { point, bound, n } => format!("point={point} bound={bound} n={n}"),
        };
        format!(
            "status={} eligible={} measured={} numerator={} unresolved={} notMeasured={} notApplicable={} total={} effectiveN={} {rate}",
            word(&self.status),
            c.eligible,
            c.measured,
            c.numerator,
            c.unresolved,
            c.not_measured,
            c.not_applicable,
            c.total,
            self.effective_n
        )
    }

    fn count_fields(&self) -> (MetricCounts, MetricStatus, u64) {
        (self.counts, self.status, self.effective_n)
    }
}

fn mantissa_of(decimal: &str, precision: u32) -> Option<u64> {
    let (whole, frac) = decimal.split_once('.').unwrap_or((decimal, ""));
    if frac.len() as u32 != precision || whole.len() != 1 {
        return None;
    }
    format!("{whole}{frac}").parse().ok()
}

pub fn view_of_oracle(metric: &Value, precision: u32) -> Option<MetricView> {
    let c = get(metric, "counts");
    let rate = get(metric, "rate");
    let rate = match text(rate, "kind") {
        "null" => RateView::Null,
        "insufficient-evidence" => RateView::Insufficient,
        "value" => RateView::Value {
            point: mantissa_of(text(rate, "point"), precision)?,
            bound: mantissa_of(text(rate, "bound"), precision)?,
            n: uint(rate, "n"),
        },
        _ => return None,
    };
    Some(MetricView {
        counts: MetricCounts {
            eligible: uint(c, "eligible"),
            measured: uint(c, "measured"),
            numerator: uint(c, "numerator"),
            unresolved: uint(c, "unresolved"),
            not_measured: uint(c, "notMeasured"),
            not_applicable: uint(c, "notApplicable"),
            total: uint(c, "total"),
        },
        status: wire(text(metric, "status")),
        effective_n: uint(metric, "effectiveN"),
        rate,
    })
}

pub fn view_of_port(m: &LegacyMetric) -> MetricView {
    MetricView {
        counts: m.counts,
        status: m.status,
        effective_n: m.effective_n,
        rate: match m.rate {
            LegacyRate::Null => RateView::Null,
            LegacyRate::InsufficientEvidence => RateView::Insufficient,
            LegacyRate::Value {
                point, bound, n, ..
            } => RateView::Value { point, bound, n },
        },
    }
}

fn scaled_to(d: ScaledDecimal, precision: u32) -> u64 {
    d.mantissa * 10u64.pow(precision - u32::from(d.scale))
}

pub fn view_of_kernel(m: &MetricAccount, precision: u32) -> MetricView {
    MetricView {
        counts: m.counts,
        status: m.status,
        effective_n: m.effective_n,
        rate: match m.value {
            MetricValue::Withheld {
                reason: WithheldReason::ZeroDenominator,
            } => RateView::Null,
            MetricValue::Withheld {
                reason: WithheldReason::InsufficientEvidence,
            } => RateView::Insufficient,
            MetricValue::Measured { point, bound } => RateView::Value {
                point: scaled_to(point, precision),
                bound: scaled_to(bound, precision),
                n: m.effective_n,
            },
        },
    }
}

// ---------------------------------------------------------------------------
// The S1 rule: binary64 `toFixed` against exact half-up rounding
// ---------------------------------------------------------------------------

fn decimal_of(s: &str) -> ScaledDecimal {
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    ScaledDecimal::new(format!("{whole}{frac}").parse().unwrap(), frac.len() as u8).unwrap()
}

/// True when the exact value of `field` lies within 2e-12 of a rounding boundary
/// at `precision` places, where binary64 may legitimately round the other way.
fn near_boundary(
    field: Field,
    numerator: u64,
    n: u64,
    direction: BoundDirection,
    z: ScaledDecimal,
    precision: u32,
) -> bool {
    if precision >= 12 {
        return false;
    }
    let m12 = match field {
        Field::Point => round_ratio(numerator, n, 12).ok(),
        Field::Bound => wilson_mantissa(numerator, n, direction, z, 12).ok(),
    };
    let Some(m12) = m12 else { return false };
    let unit = 10u64.pow(12 - precision);
    let boundary = unit / 2;
    let r = m12 % unit;
    r.abs_diff(boundary) <= 2
}

#[derive(Clone, Copy)]
enum Field {
    Point,
    Bound,
}

/// Whether two rates are equal, differ only by the S1 rule, or differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateRelation {
    Equal,
    S1,
    Different,
}

pub fn rate_relation(
    kernel: RateView,
    port: RateView,
    numerator: u64,
    direction: BoundDirection,
    z: ScaledDecimal,
    precision: u32,
) -> RateRelation {
    if kernel == port {
        return RateRelation::Equal;
    }
    match (kernel, port) {
        (
            RateView::Value {
                point: kp,
                bound: kb,
                n,
            },
            RateView::Value {
                point: pp,
                bound: pb,
                n: pn,
            },
        ) if n == pn => {
            let ok = |k: u64, p: u64, field: Field| {
                k == p
                    || (k.abs_diff(p) == 1
                        && near_boundary(field, numerator, n, direction, z, precision))
            };
            if ok(kp, pp, Field::Point) && ok(kb, pb, Field::Bound) {
                RateRelation::S1
            } else {
                RateRelation::Different
            }
        }
        _ => RateRelation::Different,
    }
}

// ---------------------------------------------------------------------------
// Layer: variants
// ---------------------------------------------------------------------------

/// The ADR 0007 section 3 variant id, recomputed here from the specification
/// (length-prefixed preimage of domain, case id and slot; first 24 hex digits of
/// SHA-256), not by the code under test.
fn expected_variant_id(case: &str, slot: &str) -> String {
    let mut preimage = Vec::new();
    for field in ["pii-eval.variant-id/1", case, slot] {
        preimage.extend((field.len() as u32).to_be_bytes());
        preimage.extend(field.as_bytes());
    }
    format!(
        "{slot}-{}",
        &Sha256Digest::of_bytes(&preimage).as_str()[..24]
    )
}

fn check_variants(ds: &Dataset, rc: &RustCorpus, cmp: &mut Comparison) {
    for (case, reason) in &rc.refused {
        cmp.diff(
            "variant",
            "-",
            case,
            "generation",
            "generated",
            format!("refused: {reason}"),
            vec![],
        );
    }
    let mut seen = BTreeSet::new();
    for case in list(&ds.export, "cases") {
        let case_id = text(case, "id");
        for v in list(case, "variants") {
            let slot = text(v, "slot");
            seen.insert((case_id.to_owned(), slot.to_owned()));
            let subject = format!("{case_id}/{slot}");
            let Some(r) = rc.variant(case_id, slot) else {
                cmp.diff(
                    "variant",
                    "-",
                    &subject,
                    "variant",
                    "generated",
                    "absent",
                    vec![],
                );
                continue;
            };
            cmp.bump("variant", 1);
            let e = &r.variant.expectations[0];
            let exp = get(v, "expectation");
            let mut check = |aspect: &str, oracle: String, rust: String| {
                if oracle != rust {
                    cmp.diff("variant", "-", &subject, aspect, oracle, rust, vec![]);
                }
            };
            check("text", text(v, "text").to_owned(), r.variant.text.clone());
            check(
                "candidate",
                format!(
                    "{}..{}",
                    uint(get(v, "candidate"), "start"),
                    uint(get(v, "candidate"), "end")
                ),
                format!("{}..{}", e.range.unwrap().start, e.range.unwrap().end),
            );
            check(
                "strategy",
                text(v, "strategy").to_owned(),
                strategy_word(r.variant.derivation.strategy),
            );
            check("method", text(case, "method").to_owned(), word(&r.method));
            check(
                "method-version",
                uint(case, "methodVersion").to_string(),
                r.provenance.method.version.to_string(),
            );
            check(
                "family",
                text(case, "family").to_owned(),
                e.family.as_str().to_owned(),
            );
            let scope = r
                .case_jurisdiction
                .as_ref()
                .map_or("global".to_owned(), |j| {
                    format!("jurisdiction:{}", j.as_str())
                });
            check("scope", text(case, "scope").to_owned(), scope);
            check(
                "language",
                text(exp, "language").to_owned(),
                r.language.clone(),
            );
            check(
                "type",
                text(exp, "type").to_owned(),
                word(&e.type_expectation),
            );
            check(
                "sensitivity",
                text(exp, "sensitivity").to_owned(),
                word(&e.sensitivity),
            );
            check(
                "context-class",
                text(exp, "contextClass").to_owned(),
                word(&e.context_class),
            );
            check(
                "context-obligation",
                text(exp, "contextObligation").to_owned(),
                word(&e.context_obligation),
            );
            // Operators: derived variants carry the operator in both; the oracle
            // records `authored` on authored variants, the contract none (0007/D4).
            let rust_operator = r
                .variant
                .derivation
                .operator
                .as_ref()
                .map(|o| o.id.as_str().to_owned());
            match (text(v, "operator"), rust_operator) {
                ("authored", None) => cmp.diff(
                    "variant",
                    "-",
                    &subject,
                    "operator",
                    "authored",
                    "none",
                    vec!["0007/D4"],
                ),
                ("authored", Some(op)) if op == "review-hold" => cmp.diff(
                    "variant",
                    "-",
                    &subject,
                    "operator",
                    "authored",
                    "review-hold",
                    vec!["0007/D4"],
                ),
                (oracle, Some(rust)) if oracle == rust => {
                    // The operator version is compared too (seeds are not: 0007/D5, D7).
                    let version = r.variant.derivation.operator.as_ref().map(|o| o.version);
                    if version != Some(uint(v, "operatorVersion") as u32) {
                        cmp.diff(
                            "variant",
                            "-",
                            &subject,
                            "operator-version",
                            uint(v, "operatorVersion"),
                            format!("{version:?}"),
                            vec![],
                        );
                    }
                }
                (oracle, rust) => cmp.diff(
                    "variant",
                    "-",
                    &subject,
                    "operator",
                    oracle,
                    format!("{rust:?}"),
                    vec![],
                ),
            }
            // The id format is a systematic, classified difference (0007/D1): the
            // oracle's id is the slot, the contract's is `slot-<digest>`.
            let id = r.variant.variant_id.as_str();
            if id == slot {
                cmp.diff("variant", "-", &subject, "variant-id", slot, id, vec![]);
            } else if id == expected_variant_id(case_id, slot) {
                cmp.diff(
                    "variant",
                    "-",
                    &subject,
                    "variant-id",
                    slot,
                    "slot-digest",
                    vec!["0007/D1"],
                );
            } else {
                cmp.diff("variant", "-", &subject, "variant-id", slot, id, vec![]);
            }
        }
    }
    for v in &rc.variants {
        if !seen.contains(&v.key()) {
            cmp.diff(
                "variant",
                "-",
                &format!("{}/{}", v.case_id, v.slot),
                "variant",
                "absent",
                "generated",
                vec![],
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Layer: outcomes
// ---------------------------------------------------------------------------

/// An independent check of the canonical primary choice (ADR 0004 section 3.2,
/// written from the specification with its own arithmetic): among the findings
/// that overlap the expected range, the primary must have the smallest
/// (geometry rank, tightness, identity evidence). A primary-selection defect
/// therefore cannot hide behind the D1 counterfactual below.
pub fn independent_primary_ok(v: &RVariant, emission: &[Finding], primary: &Finding) -> bool {
    let e = &v.variant.expectations[0];
    let (es, ee) = (e.range.unwrap().start, e.range.unwrap().end);
    let key = |f: &Finding| -> Option<(u8, u64, u8)> {
        let (fs, fe) = (f.range.start, f.range.end);
        if !(fs < ee && es < fe) {
            return None;
        }
        let (rank, tight) = if fs == es && fe == ee {
            (0, 0)
        } else if fs <= es && fe >= ee {
            (1, (fe - fs) - (ee - es))
        } else {
            (2, (ee - es) - (ee.min(fe) - es.max(fs)))
        };
        let identity = match &f.family {
            None => 2,
            Some(family) if *family == e.family => match (&v.case_jurisdiction, &f.jurisdiction) {
                (Some(a), Some(b)) if a != b => 1,
                (Some(_), None) => 1,
                _ => 0,
            },
            Some(_) => 1,
        };
        Some((rank, tight, identity))
    };
    let Some(chosen) = key(primary) else {
        return false;
    };
    emission.iter().filter_map(key).all(|k| chosen <= k)
}

/// Attribute a legacy/canonical row difference by counterfactuals.
///
/// 1. Reorder the findings so that the canonical primary comes first and
///    interpret again with the legacy rule. If that changes the legacy row, the
///    legacy selection by position mattered: `0004/D1`.
/// 2. If the reordered legacy row now equals the canonical row, that is all.
/// 3. Otherwise the only remaining cause the canonical rule can add under full
///    declared capability is `0004/D3` (the primary reports no sensitivity):
///    the canonical sensitivity is not-measured and every other field is equal.
///
/// Anything else is `Err`: an unexplained difference.
pub fn attribute(
    v: &RVariant,
    status: ScannerStatus,
    emission: &[Finding],
    assessment: &VariantAssessment,
    legacy: &Row3,
    canonical: &Row3,
) -> Result<Vec<&'static str>, ()> {
    let mut ids = Vec::new();
    let primary = assessment.occurrences[0]
        .primary
        .map(|i| &assessment.findings[i]);
    let mut legacy_prime = legacy.clone();
    if let Some(p) = primary {
        if !independent_primary_ok(v, emission, p) {
            return Err(());
        }
        if let Some(at) = emission.iter().position(|f| f == p) {
            let mut reordered: Vec<Finding> = vec![emission[at].clone()];
            reordered.extend(
                emission
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i != at)
                    .map(|(_, f)| f.clone()),
            );
            legacy_prime = legacy_row(v, status, &reordered);
            if legacy_prime != *legacy {
                ids.push("0004/D1");
            }
        }
    }
    if legacy_prime == *canonical {
        return Ok(ids);
    }
    let sensitivity_only = legacy_prime.type_state == canonical.type_state
        && legacy_prime.range == canonical.range
        && legacy_prime.finding_count == canonical.finding_count
        && legacy_prime.families == canonical.families
        && legacy_prime.jurisdictions == canonical.jurisdictions;
    if sensitivity_only
        && canonical.sensitivity_state == SensitivityState::NotMeasured
        && primary.is_some_and(|p| p.sensitive.is_none())
    {
        ids.push("0004/D3");
        return Ok(ids);
    }
    Err(())
}

fn row_text(r: &Row3) -> String {
    format!(
        "type={} sensitivity={} range={} findings={} families={:?} jurisdictions={:?}",
        word(&r.type_state),
        word(&r.sensitivity_state),
        word(&r.range),
        r.finding_count,
        r.families,
        r.jurisdictions
    )
}

/// Per scanner: the three row sets, for the accounting layers.
struct ScannerRows {
    id: String,
    status: ScannerStatus,
    /// Legacy rows per variant key (always available).
    legacy: BTreeMap<(String, String), Row3>,
    /// Canonical rows per variant key; `None` when the canonical matcher refused.
    canonical: Option<BTreeMap<(String, String), Row3>>,
    /// Union of the explanation ids of the rows that differ between the two paths.
    row_ids: BTreeSet<&'static str>,
    rows_differing: u64,
}

fn check_outcomes(ds: &Dataset, rc: &RustCorpus, cmp: &mut Comparison) -> Vec<ScannerRows> {
    let caps = super::capabilities();
    let mut out = Vec::new();
    for s in list(&ds.export, "scanners") {
        let id = text(s, "id").to_owned();
        let oracle_status = status_of(text(s, "status"));
        let findings = findings_of(s);
        let oracle = oracle_outcomes(s);
        let mut legacy_rows = BTreeMap::new();
        let mut canonical_rows = BTreeMap::new();
        let mut refused = 0u64;
        let mut row_ids: BTreeSet<&'static str> = BTreeSet::new();
        let mut differing = 0u64;
        for v in &rc.variants {
            let key = v.key();
            let subject = format!("{}/{}", v.case_id, v.slot);
            let emission: Vec<Finding> = if oracle_status == ScannerStatus::Complete {
                findings.get(&key).cloned().unwrap_or_default()
            } else {
                Vec::new()
            };
            // Compatibility: the legacy rule against the oracle's own outcome.
            let legacy = legacy_row(v, oracle_status, &emission);
            legacy_rows.insert(key.clone(), legacy.clone());
            cmp.bump("outcome-compat", 1);
            if let Some(o) = oracle.get(&key) {
                let oracle_row = Row3 {
                    type_state: o.type_state,
                    sensitivity_state: o.sensitivity_state,
                    range: o.range,
                    finding_count: o.finding_count,
                    families: o.families.clone(),
                    jurisdictions: o.jurisdictions.clone(),
                };
                for (aspect, a, b) in [
                    (
                        "type",
                        word(&oracle_row.type_state),
                        word(&legacy.type_state),
                    ),
                    (
                        "sensitivity",
                        word(&oracle_row.sensitivity_state),
                        word(&legacy.sensitivity_state),
                    ),
                    ("range", word(&oracle_row.range), word(&legacy.range)),
                    (
                        "observed.count",
                        oracle_row.finding_count.to_string(),
                        legacy.finding_count.to_string(),
                    ),
                    (
                        "observed.families",
                        format!("{:?}", oracle_row.families),
                        format!("{:?}", legacy.families),
                    ),
                    (
                        "observed.jurisdictions",
                        format!("{:?}", oracle_row.jurisdictions),
                        format!("{:?}", legacy.jurisdictions),
                    ),
                ] {
                    if a != b {
                        cmp.diff("outcome-compat", &id, &subject, aspect, a, b, vec![]);
                    }
                }
            } else {
                cmp.diff(
                    "outcome-compat",
                    &id,
                    &subject,
                    "row",
                    "absent",
                    "present",
                    vec![],
                );
            }

            // Canonical rule over the same findings.
            cmp.bump("outcome", 1);
            // The scanner status the canonical engine records: what the oracle observed.
            match canonical_assessment(v, oracle_status, &caps, &emission) {
                Ok(assessment) => {
                    let canonical = canonical_row(v, &assessment);
                    if canonical != legacy {
                        match attribute(
                            v,
                            oracle_status,
                            &emission,
                            &assessment,
                            &legacy,
                            &canonical,
                        ) {
                            Ok(ids) => {
                                differing += 1;
                                row_ids.extend(ids.iter().copied());
                                for (aspect, a, b) in [
                                    (
                                        "type",
                                        word(&legacy.type_state),
                                        word(&canonical.type_state),
                                    ),
                                    (
                                        "sensitivity",
                                        word(&legacy.sensitivity_state),
                                        word(&canonical.sensitivity_state),
                                    ),
                                    ("range", word(&legacy.range), word(&canonical.range)),
                                ] {
                                    if a != b {
                                        cmp.diff(
                                            "outcome",
                                            &id,
                                            &subject,
                                            aspect,
                                            a,
                                            b,
                                            ids.clone(),
                                        );
                                    }
                                }
                                if legacy.finding_count != canonical.finding_count
                                    || legacy.families != canonical.families
                                    || legacy.jurisdictions != canonical.jurisdictions
                                {
                                    cmp.diff(
                                        "outcome",
                                        &id,
                                        &subject,
                                        "observed",
                                        row_text(&legacy),
                                        row_text(&canonical),
                                        vec![],
                                    );
                                }
                            }
                            Err(()) => {
                                differing += 1;
                                cmp.diff(
                                    "outcome",
                                    &id,
                                    &subject,
                                    "row",
                                    row_text(&legacy),
                                    row_text(&canonical),
                                    vec![],
                                );
                            }
                        }
                    }
                    canonical_rows.insert(key, canonical);
                }
                Err(error) => {
                    refused += 1;
                    differing += 1;
                    // D6: the canonical matcher refuses a range that is not valid on the
                    // text; the oracle and the legacy mode accepted it.
                    let is_range = matches!(error, pii_eval_kernel::AssessError::Range { .. });
                    cmp.diff(
                        "outcome",
                        &id,
                        &subject,
                        "range-validation",
                        "accepted",
                        "refused",
                        if is_range { vec!["0004/D6"] } else { vec![] },
                    );
                    if is_range {
                        row_ids.insert("0004/D6");
                    }
                }
            }
        }
        for key in oracle.keys() {
            if !rc.index.contains_key(key) {
                cmp.diff(
                    "outcome-compat",
                    &id,
                    &format!("{}/{}", key.0, key.1),
                    "row",
                    "present",
                    "absent",
                    vec![],
                );
            }
        }
        // A scanner the oracle failed although it was declared complete: its findings
        // must be refused by the canonical matcher too (the oracle validates findings
        // at the runtime boundary; the canonical rule at the matcher). Same outcome:
        // nothing measured.
        let declared = text(s, "declaredStatus");
        if declared == "complete" && oracle_status != ScannerStatus::Complete {
            cmp.bump("outcome", 1);
            let returned = findings_of(s);
            let refuses = rc.variants.iter().any(|v| {
                let f = returned.get(&v.key()).cloned().unwrap_or_default();
                matches!(
                    canonical_assessment(v, ScannerStatus::Complete, &caps, &f),
                    Err(pii_eval_kernel::AssessError::Range { .. })
                )
            });
            cmp.diff(
                "outcome",
                &id,
                "(scanner)",
                "scanner-status",
                format!(
                    "{} (finding rejected at the runtime boundary)",
                    word(&oracle_status)
                ),
                if refuses {
                    "complete (finding refused by the matcher)"
                } else {
                    "complete"
                },
                if refuses { vec!["0004/D6"] } else { vec![] },
            );
            if refuses {
                row_ids.insert("0004/D6");
            }
        }
        let canonical_ok = canonical_rows.len() == legacy_rows.len() && refused == 0;
        cmp.scanners.push(ScannerSummary {
            id: id.clone(),
            status: word(&oracle_status),
            variants: legacy_rows.len() as u64,
            canonical_refused: refused,
            canonical_accounted: canonical_ok,
        });
        out.push(ScannerRows {
            id,
            status: oracle_status,
            legacy: legacy_rows,
            canonical: canonical_ok.then_some(canonical_rows),
            row_ids,
            rows_differing: differing,
        });
    }
    out
}

// ---------------------------------------------------------------------------
// Layer: accounting
// ---------------------------------------------------------------------------

const PRECISION: u32 = 6;

fn legacy_rows_for(rc: &RustCorpus, rows: &BTreeMap<(String, String), Row3>) -> Vec<LegacyRow> {
    rc.variants
        .iter()
        .filter_map(|v| {
            let r = rows.get(&v.key())?;
            let e = &v.variant.expectations[0];
            Some(LegacyRow {
                case_id: v.case_id.clone(),
                method: v.method,
                variant: v.slot.clone(),
                jurisdictional: v.case_jurisdiction.is_some(),
                expected_type: e.type_expectation,
                sensitivity: e.sensitivity,
                context_class: e.context_class,
                type_state: r.type_state,
                sensitivity_state: r.sensitivity_state,
                range: r.range,
            })
        })
        .collect()
}

fn kernel_rows(
    scanner: &ScannerId,
    body: &CorpusSnapshotBody,
    rows: impl Iterator<
        Item = (
            String,
            String,
            String,
            TypeState,
            SensitivityState,
            RangeState,
            MethodId,
        ),
    >,
) -> Vec<CaseOutcome> {
    let _ = body;
    rows.map(|(case, variant, occurrence, t, s, r, method)| CaseOutcome {
        evidence: None,
        scanner_id: scanner.clone(),
        case_id: id(&case),
        variant_id: id(&variant),
        occurrence_id: id(&occurrence),
        method,
        type_identity: t,
        sensitivity_context: s,
        range: r,
        action: ActionOutcome::NotMeasured,
        observed: ObservedSummary {
            finding_count: 0,
            families: Vec::new(),
            jurisdictions: Vec::new(),
        },
    })
    .collect()
}

fn kernel_metrics(
    body: &CorpusSnapshotBody,
    scanner: &str,
    status: ScannerStatus,
    rows: &[CaseOutcome],
) -> Result<BTreeMap<MetricId, MetricView>, String> {
    let index = AuthoredIndex::new(body).map_err(|e| format!("{e:?}"))?;
    let sid = ScannerId::new(scanner).map_err(|e| format!("{e:?}"))?;
    let accounting = account_outcomes(
        &index,
        &[ScannerInput { id: &sid, status }],
        rows,
        &Mechanics::PII_V1,
    )
    .map_err(|e| format!("{e:?}"))?;
    Ok(accounting.scanners[0]
        .overall
        .metrics
        .iter()
        .map(|m| (m.metric, view_of_kernel(m, PRECISION)))
        .collect())
}

fn mask_ids(mask: u8) -> Vec<&'static str> {
    let mut ids = Vec::new();
    if mask & 1 != 0 {
        ids.push("0005/A2");
    }
    if mask & 2 != 0 {
        ids.push("0005/A3");
    }
    if mask & 4 != 0 {
        ids.push("0008/R3");
    }
    ids
}

fn masks() -> Vec<u8> {
    let mut m: Vec<u8> = (0..8).collect();
    m.sort_by_key(|x| (x.count_ones(), *x));
    m
}

type PortResult =
    Result<Vec<(MetricId, LegacyMetric)>, pii_eval_compat::legacy_accounting::LegacyAccountError>;

fn port_all(rows: &[LegacyRow]) -> Vec<PortResult> {
    masks()
        .into_iter()
        .map(|mask| {
            account_rows(
                rows,
                &LegacyMechanics::PII_V1,
                Quirks::ORACLE.with_canonical(mask & 1 != 0, mask & 2 != 0, mask & 4 != 0),
            )
        })
        .collect()
}

fn port_metric(results: &[PortResult], mask_pos: usize, metric: MetricId) -> Option<MetricView> {
    results[mask_pos]
        .as_ref()
        .ok()
        .and_then(|v| v.iter().find(|(i, _)| *i == metric))
        .map(|(_, m)| view_of_port(m))
}

/// Explain `kernel` against the oracle metric. Returns the ids, or `None`.
fn explain_metric(
    results: &[PortResult],
    metric: MetricId,
    kernel: &MetricView,
    oracle_throws: bool,
) -> Option<Vec<&'static str>> {
    let z = Mechanics::PII_V1.interval_z;
    let direction = pii_eval_contracts::METRICS
        .iter()
        .find(|d| d.id == metric)
        .map(|d| d.direction)?;
    for (pos, mask) in masks().into_iter().enumerate() {
        if oracle_throws && mask & 2 == 0 {
            continue;
        }
        let Some(port) = port_metric(results, pos, metric) else {
            continue;
        };
        if port.count_fields() != kernel.count_fields() {
            continue;
        }
        match rate_relation(
            kernel.rate,
            port.rate,
            kernel.counts.numerator,
            direction,
            z,
            PRECISION,
        ) {
            RateRelation::Equal => return Some(mask_ids(mask)),
            RateRelation::S1 => {
                let mut ids = mask_ids(mask);
                ids.push("0005/S1");
                return Some(ids);
            }
            RateRelation::Different => {}
        }
    }
    None
}

/// Compare one accounting (a scanner's rows or a vector) against the oracle.
/// `kernel_legacy` is the kernel's accounting over the legacy rows.
#[allow(clippy::too_many_arguments)]
fn compare_accounting(
    cmp: &mut Comparison,
    scanner: &str,
    subject: &str,
    oracle_accounting: &Value,
    legacy_rows: &[LegacyRow],
    kernel_legacy: &BTreeMap<MetricId, MetricView>,
    kernel_canonical: Option<&BTreeMap<MetricId, MetricView>>,
    row_ids: &BTreeSet<&'static str>,
    population: Option<(u64, u64)>,
) -> BTreeMap<MetricId, Vec<&'static str>> {
    let results = port_all(legacy_rows);
    let oracle_throws = oracle_accounting.is_null();
    let oracle_message = text(oracle_accounting, "throws");
    let _ = oracle_message;
    // Population: case and row counts.
    if let Some((cases, rows)) = population {
        cmp.bump("population", 2);
        if uint(oracle_accounting, "sourceCaseCount") != cases {
            cmp.diff(
                "population",
                scanner,
                subject,
                "sourceCaseCount",
                uint(oracle_accounting, "sourceCaseCount"),
                cases,
                vec![],
            );
        }
        if uint(oracle_accounting, "rowCount") != rows {
            cmp.diff(
                "population",
                scanner,
                subject,
                "rowCount",
                uint(oracle_accounting, "rowCount"),
                rows,
                vec![],
            );
        }
    }
    let mut rule_ids: BTreeMap<MetricId, Vec<&'static str>> = BTreeMap::new();
    for def in &pii_eval_contracts::METRICS {
        let m = def.id;
        let name = word(&m);
        let oracle = get(get(oracle_accounting, "metrics"), &name);
        let oracle_view = if oracle.is_null() {
            None
        } else {
            view_of_oracle(oracle, PRECISION)
        };
        let kernel_l = &kernel_legacy[&m];
        // Compatibility: the legacy port with the oracle's quirks equals the oracle.
        cmp.bump("accounting-compat", 1);
        match (&oracle_view, port_metric(&results, 0, m)) {
            (Some(o), Some(p)) if *o == p => {}
            (Some(o), Some(p)) => cmp.diff(
                "accounting-compat",
                scanner,
                subject,
                &name,
                o.describe(),
                p.describe(),
                vec![],
            ),
            (None, None) => {}
            (Some(o), None) => cmp.diff(
                "accounting-compat",
                scanner,
                subject,
                &name,
                o.describe(),
                "throws",
                vec![],
            ),
            (None, Some(p)) => cmp.diff(
                "accounting-compat",
                scanner,
                subject,
                &name,
                "throws",
                p.describe(),
                vec![],
            ),
        }
        // The kernel's accounting over the same rows.
        cmp.bump("accounting-rule", 1);
        let differs = match &oracle_view {
            Some(o) => o != kernel_l,
            None => true,
        };
        let mut metric_ids: Vec<&'static str> = Vec::new();
        if differs {
            if let Some(ids) = explain_metric(&results, m, kernel_l, oracle_throws) {
                metric_ids = ids;
            }
            let explained = !metric_ids.is_empty();
            cmp.diff(
                "accounting-rule",
                scanner,
                subject,
                &name,
                oracle_view
                    .as_ref()
                    .map_or("throws".to_owned(), MetricView::describe),
                kernel_l.describe(),
                if explained {
                    metric_ids.clone()
                } else {
                    vec![]
                },
            );
        }
        rule_ids.insert(m, metric_ids.clone());
        if let Some(kc) = kernel_canonical {
            cmp.bump("accounting-canonical", 1);
            let k = &kc[&m];
            let equal_to_oracle = oracle_view.as_ref().is_some_and(|o| o == k);
            if !equal_to_oracle {
                // Telescoping: oracle -> kernel(legacy rows) is the accounting rule,
                // kernel(legacy rows) -> kernel(canonical rows) is the matching rule.
                let rule_step = differs;
                let row_step = k != kernel_l;
                let mut ids: Vec<&'static str> = Vec::new();
                if rule_step {
                    ids.extend(metric_ids.iter().copied());
                }
                if row_step {
                    ids.extend(row_ids.iter().copied());
                }
                let explained =
                    (!rule_step || !metric_ids.is_empty()) && (!row_step || !row_ids.is_empty());
                ids.sort_unstable();
                ids.dedup();
                cmp.diff(
                    "accounting-canonical",
                    scanner,
                    subject,
                    &name,
                    oracle_view
                        .as_ref()
                        .map_or("throws".to_owned(), MetricView::describe),
                    k.describe(),
                    if explained { ids } else { vec![] },
                );
            }
        }
    }
    rule_ids
}

fn check_scanner_accounting(
    ds: &Dataset,
    rc: &RustCorpus,
    scanner_rows: &[ScannerRows],
    cmp: &mut Comparison,
) {
    let body = &rc.body;
    for sr in scanner_rows {
        let export = list(&ds.export, "scanners")
            .iter()
            .find(|s| text(s, "id") == sr.id)
            .expect("scanner");
        let oracle_accounting = get(export, "accounting");
        let legacy = legacy_rows_for(rc, &sr.legacy);
        let to_rows = |rows: &BTreeMap<(String, String), Row3>| -> Vec<CaseOutcome> {
            kernel_rows(
                &ScannerId::new(&sr.id).unwrap(),
                body,
                rc.variants.iter().filter_map(|v| {
                    let r = rows.get(&v.key())?;
                    Some((
                        v.case_id.clone(),
                        v.variant.variant_id.as_str().to_owned(),
                        v.variant.expectations[0].occurrence_id.as_str().to_owned(),
                        r.type_state,
                        r.sensitivity_state,
                        r.range,
                        v.method,
                    ))
                }),
            )
        };
        let kernel_legacy = kernel_metrics(body, &sr.id, sr.status, &to_rows(&sr.legacy))
            .unwrap_or_else(|e| panic!("kernel accounting of the legacy rows of {}: {e}", sr.id));
        let kernel_canonical = sr.canonical.as_ref().map(|rows| {
            kernel_metrics(body, &sr.id, sr.status, &to_rows(rows)).unwrap_or_else(|e| {
                panic!("kernel accounting of the canonical rows of {}: {e}", sr.id)
            })
        });
        if let Some(kc) = &kernel_canonical {
            let mut views: Vec<(MetricId, MetricView)> =
                kc.iter().map(|(m, v)| (*m, v.clone())).collect();
            views.sort_by_key(|(m, _)| word(m));
            cmp.canonical.insert(sr.id.clone(), views);
        }
        let cases = body.cases.len() as u64;
        let rows = sr.legacy.len() as u64;
        compare_accounting(
            cmp,
            &sr.id,
            "(scanner)",
            oracle_accounting,
            &legacy,
            &kernel_legacy,
            kernel_canonical.as_ref(),
            &sr.row_ids,
            Some((cases, rows)),
        );
    }
}

// ---------------------------------------------------------------------------
// Layer: hand-built accounting vectors
// ---------------------------------------------------------------------------

fn vector_parts(
    v: &Value,
) -> (
    CorpusSnapshotBody,
    Vec<LegacyRow>,
    Vec<(
        String,
        String,
        String,
        TypeState,
        SensitivityState,
        RangeState,
        MethodId,
    )>,
) {
    const TEXT: &str = "aaaa bbbb";
    let mut cases = Vec::new();
    let mut legacy = Vec::new();
    let mut rows = Vec::new();
    let mut specs: Vec<&Value> = list(v, "cases").iter().collect();
    specs.sort_by_key(|c| text(c, "id"));
    for c in specs {
        let global = text(c, "scope") == "global";
        let family = FamilyId::new(if global {
            "pii:global:email"
        } else {
            "pii:us:ssn"
        })
        .unwrap();
        let jurisdiction = (!global).then(|| JurisdictionCode::new("US").unwrap());
        let method: MethodId = wire(text(c, "method"));
        let mut variants = Vec::new();
        let mut vs: Vec<&Value> = list(c, "variants").iter().collect();
        vs.sort_by_key(|r| text(r, "slot"));
        for r in vs {
            let ty: ExpectedType = wire(text(r, "type"));
            let sens: SensitivityExpectation = wire(text(r, "sensitivity"));
            let ctx: ContextClass = wire(text(r, "contextClass"));
            let (ts, ss, rg): (TypeState, SensitivityState, RangeState) = (
                wire(text(r, "typeState")),
                wire(text(r, "sensitivityState")),
                wire(text(r, "range")),
            );
            variants.push(Variant {
                variant_id: id(text(r, "slot")),
                derivation: Derivation {
                    strategy: Strategy::Authored,
                    operator: None,
                    seed: None,
                },
                text: TEXT.to_owned(),
                text_digest: Sha256Digest::of_bytes(TEXT.as_bytes()),
                expectations: vec![Expectation {
                    evidence: None,
                    occurrence_id: id("o1"),
                    range: Some(ByteRange { start: 0, end: 4 }),
                    family: family.clone(),
                    type_expectation: ty,
                    validator: None,
                    sensitivity: sens,
                    context_class: ctx,
                    context_obligation: ContextObligation::None,
                    action: ActionExpectation::NotSpecified,
                }],
            });
            // Variant ids must be snapshot-unique: prefix the case id.
            let last = variants.last_mut().unwrap();
            last.variant_id = id(&format!("{}-{}", text(c, "id"), text(r, "slot")));
            legacy.push(LegacyRow {
                case_id: text(c, "id").to_owned(),
                method,
                variant: text(r, "slot").to_owned(),
                jurisdictional: !global,
                expected_type: ty,
                sensitivity: sens,
                context_class: ctx,
                type_state: ts,
                sensitivity_state: ss,
                range: rg,
            });
            rows.push((
                text(c, "id").to_owned(),
                format!("{}-{}", text(c, "id"), text(r, "slot")),
                "o1".to_owned(),
                ts,
                ss,
                rg,
                method,
            ));
        }
        let collision = (method == MethodId::JurisdictionCollision).then(|| Collision {
            target_family: family.clone(),
            competing_families: vec![FamilyId::new("pii:global:phone").unwrap()],
        });
        cases.push(Case {
            case_id: id(text(c, "id")),
            method,
            lineage: Lineage {
                source_id: id("synthetic-source"),
                source_digest: Sha256Digest::of_bytes(b"synthetic"),
            },
            language: LanguageTag::new("en").unwrap(),
            jurisdiction,
            collision,
            variants,
        });
    }
    let body = CorpusSnapshotBody {
        population: Population {
            population_id: id("synthetic-vector"),
            population_version: 1,
            visibility: Visibility::PublicSynthetic,
        },
        generation: pii_eval_contracts::GenerationRules {
            generator: id("synthetic-generator"),
            generator_version: 1,
            seed_derivation: pii_eval_contracts::Seed::new("seed-v1").unwrap(),
        },
        cases,
    };
    (body, legacy, rows)
}

fn check_vectors(ds: &Dataset, cmp: &mut Comparison) {
    for v in list(&ds.input, "accountingVectors") {
        let vid = text(v, "id");
        let exported = list(&ds.export, "accountingVectors")
            .iter()
            .find(|e| text(e, "id") == vid);
        let Some(exported) = exported else {
            cmp.diff(
                "accounting-compat",
                "-",
                vid,
                "vector",
                "present",
                "absent",
                vec![],
            );
            continue;
        };
        let (body, legacy, rows) = vector_parts(v);
        let kernel = kernel_metrics(
            &body,
            "vector-scanner",
            ScannerStatus::Complete,
            &kernel_rows(
                &ScannerId::new("vector-scanner").unwrap(),
                &body,
                rows.into_iter(),
            ),
        )
        .unwrap_or_else(|e| panic!("kernel accounting of vector {vid}: {e}"));
        let throws = exported.get("throws").is_some();
        let before = cmp.differences.len();
        let oracle_accounting = if throws {
            Value::Null
        } else {
            get(exported, "accounting").clone()
        };
        compare_accounting(
            cmp,
            "vector-scanner",
            vid,
            &oracle_accounting,
            &legacy,
            &kernel,
            None,
            &BTreeSet::new(),
            None,
        );
        // The oracle's refusal must be reproduced by the port, with its own message.
        if throws {
            cmp.bump("accounting-compat", 1);
            if text(exported, "throws") != "PII benign controls must be distinct authored cases" {
                cmp.diff(
                    "accounting-compat",
                    "-",
                    vid,
                    "throws",
                    text(exported, "throws"),
                    "PII benign controls must be distinct authored cases",
                    vec![],
                );
            }
        }
        let differing = cmp.differences[before..]
            .iter()
            .filter(|d| d.layer == "accounting-rule")
            .count() as u64;
        cmp.vectors.push(VectorSummary {
            id: vid.to_owned(),
            oracle_throws: throws,
            metrics_differing: differing,
        });
    }
}

// ---------------------------------------------------------------------------
// Layer: statistics
// ---------------------------------------------------------------------------

fn check_statistics(ds: &Dataset, cmp: &mut Comparison) {
    let stats = get(&ds.export, "statistics");
    for entry in list(stats, "grid").iter().chain(list(stats, "singles")) {
        let k = uint(entry, "numerator");
        let n = uint(entry, "denominator");
        let precision = uint(entry, "intervalPrecision") as u32;
        let direction: BoundDirection = wire(text(entry, "direction"));
        let z_text = text(entry, "intervalZ");
        let subject = format!("{k}/{n} {} z={z_text} p={precision}", word(&direction));
        let Some(oracle) = view_of_rate(get(entry, "rate"), n, precision) else {
            cmp.diff(
                "statistics-compat",
                "-",
                &subject,
                "rate",
                "unparseable",
                "-",
                vec![],
            );
            continue;
        };
        // The compatibility port, with the oracle's arithmetic.
        let mech = LegacyMechanics {
            min_denominator: 4,
            interval_z: z_text.parse::<f64>().unwrap(),
            interval_precision: precision,
        };
        cmp.bump("statistics-compat", 1);
        let port = match proportion(k, n, direction, &mech) {
            LegacyRate::Null => RateView::Null,
            LegacyRate::InsufficientEvidence => RateView::Insufficient,
            LegacyRate::Value {
                point, bound, n, ..
            } => RateView::Value { point, bound, n },
        };
        if port != oracle {
            cmp.diff(
                "statistics-compat",
                "-",
                &subject,
                "rate",
                format!("{oracle:?}"),
                format!("{port:?}"),
                vec![],
            );
        }
        // The canonical statistics.
        cmp.bump("statistics", 1);
        let z = decimal_of(z_text);
        let kernel_mech = Mechanics {
            min_denominator: 4,
            replays: 2,
            interval_z: z,
            interval_precision: precision as u8,
        };
        let kernel = match published_value(k, n, direction, &kernel_mech) {
            Ok(MetricValue::Withheld {
                reason: WithheldReason::ZeroDenominator,
            }) => RateView::Null,
            Ok(MetricValue::Withheld {
                reason: WithheldReason::InsufficientEvidence,
            }) => RateView::Insufficient,
            Ok(MetricValue::Measured { point, bound }) => RateView::Value {
                point: scaled_to(point, precision),
                bound: scaled_to(bound, precision),
                n,
            },
            Err(e) => {
                cmp.diff(
                    "statistics",
                    "-",
                    &subject,
                    "rate",
                    format!("{oracle:?}"),
                    format!("{e:?}"),
                    vec![],
                );
                continue;
            }
        };
        match rate_relation(kernel, oracle, k, direction, z, precision) {
            RateRelation::Equal => {}
            RateRelation::S1 => cmp.diff(
                "statistics",
                "-",
                &subject,
                "rate",
                format!("{oracle:?}"),
                format!("{kernel:?}"),
                vec!["0005/S1"],
            ),
            RateRelation::Different => cmp.diff(
                "statistics",
                "-",
                &subject,
                "rate",
                format!("{oracle:?}"),
                format!("{kernel:?}"),
                vec![],
            ),
        }
    }
}

fn view_of_rate(rate: &Value, n: u64, precision: u32) -> Option<RateView> {
    Some(match text(rate, "kind") {
        "null" => RateView::Null,
        "insufficient-evidence" => RateView::Insufficient,
        "value" => RateView::Value {
            point: mantissa_of(text(rate, "point"), precision)?,
            bound: mantissa_of(text(rate, "bound"), precision)?,
            n: if uint(rate, "n") == u64::MAX {
                n
            } else {
                uint(rate, "n")
            },
        },
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Run every layer. A pure function of `ds`.
pub fn compare(ds: &Dataset) -> Comparison {
    let mut cmp = Comparison::default();
    let rc = rust_corpus(&ds.input, &ds.export);
    check_variants(ds, &rc, &mut cmp);
    let scanner_rows = check_outcomes(ds, &rc, &mut cmp);
    check_scanner_accounting(ds, &rc, &scanner_rows, &mut cmp);
    check_vectors(ds, &mut cmp);
    check_statistics(ds, &mut cmp);
    cmp.differences.sort_by(|a, b| {
        (a.layer, &a.scanner, &a.subject, &a.aspect)
            .cmp(&(b.layer, &b.scanner, &b.subject, &b.aspect))
    });
    cmp
}
