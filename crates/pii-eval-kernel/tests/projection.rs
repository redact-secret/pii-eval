//! The product projection (schema 1.2, ADR 0016) against hand-calculated cells.
//!
//! Population: 24 type-validation cases, all one valid sensitive occurrence.
//! `email` cases e01..e12 (global, no jurisdiction) and `ssn` cases s01..s12
//! (jurisdiction US). Language: odd case numbers `en`, even `ko`. View of the
//! roster: numbers 01..08 are `oracle-plan`, 09..12 `qualification-plan`.
//! Scanner `alpha-scan` misses e02, e05, e11, s03, s11, s12 (type and
//! sensitivity miss); every other row is a pass. Expected counts below were
//! derived by hand from that table before the code ran.

mod acct_common;

use acct_common::*;
use pii_eval_contracts::{
    ActionOutcome, CaseOutcome, ContextClass::Neutral, CorpusSnapshotBody, ExpectedType, Id,
    Mechanics, MethodId::TypeValidation, MetricId, MetricValue, PopulationCounts, ProductIdentity,
    ProjectionMode, ProjectionView, PublicPopulationBinding, PublicSyntheticClass, RangeState,
    ScannerId, ScannerIdentity, ScannerStatus, SensitivityExpectation as Sx,
    SensitivityState as Ss, Sha256Digest, TypeState as Ts,
};
use pii_eval_kernel::{
    OutcomeRef, ProjectionError, ProjectionInput, ProjectionRoster, build_projection, case_family,
};

const MISSES: [&str; 6] = ["e02", "e05", "e11", "s03", "s11", "s12"];

fn name(prefix: char, n: usize) -> String {
    format!("{prefix}{n:02}")
}

fn population() -> CorpusSnapshotBody {
    let mut cases = Vec::new();
    for (prefix, jurisdiction) in [('e', None), ('s', Some("US"))] {
        for n in 1..=12 {
            let id = name(prefix, n);
            cases.push(case(
                &id,
                TypeValidation,
                if n % 2 == 1 { "en" } else { "ko" },
                jurisdiction,
                vec![var(
                    &format!("{id}-a"),
                    Neutral,
                    vec![occ("o1", ExpectedType::Valid, Sx::Sensitive)],
                )],
            ));
        }
    }
    snapshot_body(cases)
}

fn rows(scanner: &str, body: &CorpusSnapshotBody, status: ScannerStatus) -> Vec<CaseOutcome> {
    body.cases
        .iter()
        .map(|c| {
            let id = c.case_id.as_str();
            let (ty, sens, range) = if status != ScannerStatus::Complete {
                (Ts::NotMeasured, Ss::NotMeasured, RangeState::NotApplicable)
            } else if MISSES.contains(&id) {
                (Ts::Miss, Ss::Miss, RangeState::Miss)
            } else {
                (Ts::Correct, Ss::Correct, RangeState::Exact)
            };
            CaseOutcome {
                scanner_id: sid(scanner),
                case_id: c.case_id.clone(),
                variant_id: c.variants[0].variant_id.clone(),
                occurrence_id: id_of("o1"),
                method: c.method,
                type_identity: ty,
                sensitivity_context: sens,
                range,
                action: ActionOutcome::NotMeasured,
                observed: pii_eval_contracts::ObservedSummary {
                    finding_count: 0,
                    families: vec![],
                    jurisdictions: vec![],
                },
            }
        })
        .collect()
}

fn id_of(s: &str) -> Id {
    Id::new(s).unwrap()
}

fn digest(s: &str) -> Sha256Digest {
    Sha256Digest::of_bytes(s.as_bytes())
}

fn identity(scanner: &str) -> ScannerIdentity {
    ScannerIdentity {
        scanner_id: ScannerId::new(scanner).unwrap(),
        scanner_version: Some(pii_eval_contracts::VersionString::new("1.0.0").unwrap()),
        artifact_digest: None,
        adapter: pii_eval_contracts::AdapterIdentity {
            adapter_id: ScannerId::new("synthetic-adapter").unwrap(),
            adapter_version: pii_eval_contracts::VersionString::new("1.0.0").unwrap(),
            normalization_version: 1,
        },
        product: ProductIdentity::Released,
        configuration_digest: digest(&format!("configuration-{scanner}")),
        activation_digest: digest(&format!("activation-{scanner}")),
    }
}

fn binding(body: &CorpusSnapshotBody) -> PublicPopulationBinding {
    PublicPopulationBinding {
        population_id: body.population.population_id.clone(),
        visibility: PublicSyntheticClass::Only,
        population_version: body.population.population_version,
        population_digest: digest("synthetic-population"),
    }
}

fn roster(body: &CorpusSnapshotBody) -> ProjectionRoster {
    let views: Vec<(Id, ProjectionView)> = body
        .cases
        .iter()
        .map(|c| {
            let n: usize = c.case_id.as_str()[1..].parse().unwrap();
            (
                c.case_id.clone(),
                if n <= 8 {
                    ProjectionView::OraclePlan
                } else {
                    ProjectionView::QualificationPlan
                },
            )
        })
        .collect();
    ProjectionRoster::new(
        body,
        &[
            ProjectionView::QualificationPlan,
            ProjectionView::OraclePlan,
        ],
        &views,
        &[],
    )
    .unwrap()
}

fn build(
    body: &CorpusSnapshotBody,
    roster: &ProjectionRoster,
    scanners: &[(&str, ScannerStatus)],
    reverse: bool,
) -> pii_eval_contracts::ProductProjection {
    let identities: Vec<ScannerIdentity> = scanners.iter().map(|(n, _)| identity(n)).collect();
    let pairs: Vec<(&ScannerIdentity, ScannerStatus)> = identities
        .iter()
        .zip(scanners)
        .map(|(i, (_, s))| (i, *s))
        .collect();
    let mut all: Vec<CaseOutcome> = scanners
        .iter()
        .flat_map(|(n, s)| rows(n, body, *s))
        .collect();
    if reverse {
        all.reverse();
    }
    let refs: Vec<OutcomeRef<'_>> = all.iter().map(OutcomeRef::from).collect();
    let population = binding(body);
    build_projection(
        &ProjectionInput {
            snapshot: body,
            population: &population,
            scanners: &pairs,
            rows: &refs,
            mechanics: &Mechanics::PII_V1,
            mode: ProjectionMode::Official,
        },
        roster,
    )
    .unwrap()
}

fn metric(
    row: &pii_eval_contracts::ProjectionRow,
    id: MetricId,
) -> &pii_eval_contracts::MetricResult {
    row.metrics.iter().find(|m| m.metric.id == id).unwrap()
}

#[test]
fn cells_have_hand_calculated_counts_and_their_own_denominators() {
    let body = population();
    let block = build(
        &body,
        &roster(&body),
        &[("alpha-scan", ScannerStatus::Complete)],
        false,
    );
    assert_eq!(block.rows.len(), 4);
    let keys: Vec<(&str, &str)> = block
        .rows
        .iter()
        .map(|r| (r.view.as_str(), r.family.as_str()))
        .collect();
    assert_eq!(
        keys,
        [
            ("oracle-plan", "pii:global:email"),
            ("oracle-plan", "pii:us:ssn"),
            ("qualification-plan", "pii:global:email"),
            ("qualification-plan", "pii:us:ssn"),
        ]
    );
    // (cases, type-miss numerator): oracle/email e01..e08 misses e02 e05;
    // oracle/ssn s01..s08 miss s03; qualification/email e09..e12 miss e11;
    // qualification/ssn s09..s12 miss s11 s12.
    let expected = [(8, 2), (8, 1), (4, 1), (4, 2)];
    for (row, (cases, misses)) in block.rows.iter().zip(expected) {
        assert_eq!(row.counts.authored_cases, cases);
        assert_eq!(row.counts.variants, cases);
        assert_eq!(row.counts.occurrences, cases);
        let m = metric(row, MetricId::TypeMissRate);
        assert_eq!(m.counts.eligible, cases);
        assert_eq!(m.counts.measured, cases);
        assert_eq!(m.counts.numerator, misses);
        assert_eq!(
            m.counts.total, cases,
            "a cell's denominator is its own cases"
        );
        assert_eq!(m.effective_n, cases);
        assert!(matches!(m.value, MetricValue::Measured { .. }));
        assert_eq!(row.metrics.len(), 10);
        assert_eq!(row.method_coverage.len(), 1);
        assert_eq!(row.method_coverage[0].cases, cases);
    }
    // The cells partition the population and are never added to each other.
    let total: u64 = block.rows.iter().map(|r| r.counts.authored_cases).sum();
    assert_eq!(total, 24);
    let miss_total: u64 = block
        .rows
        .iter()
        .map(|r| metric(r, MetricId::TypeMissRate).counts.numerator)
        .sum();
    assert_eq!(miss_total, MISSES.len() as u64);
}

#[test]
fn language_strata_partition_each_cell() {
    let body = population();
    let block = build(
        &body,
        &roster(&body),
        &[("alpha-scan", ScannerStatus::Complete)],
        false,
    );
    let oracle_email = &block.rows[0];
    // e01..e08: en = 01 03 05 07 (miss e05), ko = 02 04 06 08 (miss e02).
    let langs: Vec<(&str, u64, u64)> = oracle_email
        .by_language
        .iter()
        .map(|l| {
            (
                l.language.as_str(),
                l.counts.authored_cases,
                metric_of(&l.metrics, MetricId::TypeMissRate)
                    .counts
                    .numerator,
            )
        })
        .collect();
    assert_eq!(langs, [("en", 4, 1), ("ko", 4, 1)]);
    for row in &block.rows {
        let sum: u64 = row
            .by_language
            .iter()
            .map(|l| l.counts.authored_cases)
            .sum();
        assert_eq!(sum, row.counts.authored_cases);
    }
}

fn metric_of(
    metrics: &[pii_eval_contracts::MetricResult],
    id: MetricId,
) -> &pii_eval_contracts::MetricResult {
    metrics.iter().find(|m| m.metric.id == id).unwrap()
}

#[test]
fn control_class_strata_cover_only_the_assigned_cases() {
    let body = population();
    let views: Vec<(Id, ProjectionView)> = body
        .cases
        .iter()
        .map(|c| (c.case_id.clone(), ProjectionView::DiagnosticBalanced))
        .collect();
    // Two classes inside the email cell: e01..e04 `reserved`, e05..e08 `placeholder`;
    // e09 is `reserved` too; the rest carry no class.
    let class = |names: &[&str], class: &str| -> Vec<(Id, Id)> {
        names.iter().map(|n| (id_of(n), id_of(class))).collect()
    };
    let mut control = class(&["e01", "e02", "e03", "e04", "e09"], "reserved");
    control.extend(class(&["e05", "e06", "e07", "e08"], "placeholder"));
    let roster = ProjectionRoster::new(
        &body,
        &[ProjectionView::DiagnosticBalanced],
        &views,
        &control,
    )
    .unwrap();
    let block = build(
        &body,
        &roster,
        &[("alpha-scan", ScannerStatus::Complete)],
        false,
    );
    let email = block
        .rows
        .iter()
        .find(|r| r.family.as_str() == "pii:global:email")
        .unwrap();
    let strata: Vec<(&str, u64, u64)> = email
        .by_control_class
        .iter()
        .map(|k| {
            (
                k.control_class.as_str(),
                k.counts.authored_cases,
                metric_of(&k.metrics, MetricId::TypeMissRate)
                    .counts
                    .numerator,
            )
        })
        .collect();
    // placeholder e05..e08 (miss e05); reserved e01..e04 and e09 (miss e02).
    assert_eq!(strata, [("placeholder", 4, 1), ("reserved", 5, 1)]);
    let ssn = block
        .rows
        .iter()
        .find(|r| r.family.as_str() == "pii:us:ssn")
        .unwrap();
    assert!(ssn.by_control_class.is_empty());
    // Control classes change the roster digest, hence the artifact.
    let plain =
        ProjectionRoster::new(&body, &[ProjectionView::DiagnosticBalanced], &views, &[]).unwrap();
    assert_ne!(plain.digest(), roster.digest());
}

#[test]
fn the_projection_is_deterministic_across_row_order_and_scanner_order() {
    let body = population();
    let roster = roster(&body);
    let scanners = [
        ("alpha-scan", ScannerStatus::Complete),
        ("beta-scan", ScannerStatus::Complete),
    ];
    let a = build(&body, &roster, &scanners, false);
    let b = build(&body, &roster, &scanners, true);
    let c = build(&body, &roster, &[scanners[1], scanners[0]], true);
    assert_eq!(a, b);
    assert_eq!(a, c);
    assert_eq!(a.rows.len(), 8);
    // Ascending by (scanner, view, family).
    let keys: Vec<_> = a
        .rows
        .iter()
        .map(|r| {
            (
                r.binding.scanner_id.as_str(),
                r.view.as_str(),
                r.family.as_str(),
            )
        })
        .collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted);
}

#[test]
fn a_scanner_that_did_not_complete_is_unmeasured_in_every_cell_never_a_pass() {
    let body = population();
    let block = build(
        &body,
        &roster(&body),
        &[
            ("alpha-scan", ScannerStatus::Complete),
            ("beta-scan", ScannerStatus::Unavailable),
        ],
        false,
    );
    for row in block
        .rows
        .iter()
        .filter(|r| r.binding.scanner_id.as_str() == "beta-scan")
    {
        let m = metric(row, MetricId::TypeMissRate);
        assert_eq!(m.counts.measured, 0);
        assert_eq!(m.counts.numerator, 0);
        assert_eq!(m.counts.not_measured, row.counts.authored_cases);
        assert!(matches!(m.value, MetricValue::Withheld { .. }));
        // The counts are the cell's own, not the scanner's absence of rows.
        assert!(row.counts.authored_cases > 0);
    }
}

#[test]
fn rosters_are_checked_against_the_snapshot() {
    let body = population();
    let all = |view| -> Vec<(Id, ProjectionView)> {
        body.cases
            .iter()
            .map(|c| (c.case_id.clone(), view))
            .collect()
    };
    let oracle = ProjectionView::OraclePlan;
    let qual = ProjectionView::QualificationPlan;
    let new =
        |required: &[ProjectionView], views: &[(Id, ProjectionView)], control: &[(Id, Id)]| {
            ProjectionRoster::new(&body, required, views, control)
        };
    assert_eq!(
        new(&[], &all(oracle), &[]).unwrap_err(),
        ProjectionError::NoRequiredViews
    );
    assert_eq!(
        new(&[oracle, oracle], &all(oracle), &[]).unwrap_err(),
        ProjectionError::DuplicateRequiredView
    );
    // A case with no view.
    let mut missing = all(oracle);
    missing.pop();
    assert_eq!(
        new(&[oracle], &missing, &[]).unwrap_err(),
        ProjectionError::UnassignedCase
    );
    // A case in two views.
    let mut twice = all(oracle);
    twice.push((body.cases[0].case_id.clone(), oracle));
    assert_eq!(
        new(&[oracle], &twice, &[]).unwrap_err(),
        ProjectionError::DuplicateAssignment
    );
    // An unknown case.
    let mut unknown = all(oracle);
    unknown.push((id_of("zz99"), oracle));
    assert_eq!(
        new(&[oracle], &unknown, &[]).unwrap_err(),
        ProjectionError::UnknownCase
    );
    // A view that is used but not required, and a required view with no case.
    assert_eq!(
        new(&[qual], &all(oracle), &[]).unwrap_err(),
        ProjectionError::ViewNotRequired
    );
    assert_eq!(
        new(&[oracle, qual], &all(oracle), &[]).unwrap_err(),
        ProjectionError::EmptyRequiredView
    );
    // Control classes: unknown case, repeated case.
    let ok = all(oracle);
    assert_eq!(
        new(&[oracle], &ok, &[(id_of("zz99"), id_of("reserved"))]).unwrap_err(),
        ProjectionError::UnknownControlCase
    );
    let c0 = body.cases[0].case_id.clone();
    assert_eq!(
        new(
            &[oracle],
            &ok,
            &[(c0.clone(), id_of("reserved")), (c0, id_of("placeholder"))]
        )
        .unwrap_err(),
        ProjectionError::DuplicateControlAssignment
    );
}

#[test]
fn a_roster_has_one_digest_whatever_order_its_file_lists_things_in() {
    let body = population();
    let views: Vec<(Id, ProjectionView)> = body
        .cases
        .iter()
        .map(|c| (c.case_id.clone(), ProjectionView::OraclePlan))
        .collect();
    let mut reversed = views.clone();
    reversed.reverse();
    let a = ProjectionRoster::new(&body, &[ProjectionView::OraclePlan], &views, &[]).unwrap();
    let b = ProjectionRoster::new(&body, &[ProjectionView::OraclePlan], &reversed, &[]).unwrap();
    assert_eq!(a.digest(), b.digest());
}

#[test]
fn a_case_spanning_families_without_a_target_has_no_family_cell() {
    let mut body = population();
    // Give e01 a second occurrence of another family.
    let case = &mut body.cases[0];
    let mut extra = case.variants[0].expectations[0].clone();
    extra.occurrence_id = id_of("o2");
    extra.family = pii_eval_contracts::FamilyId::new("pii:global:phone").unwrap();
    case.variants[0].expectations.push(extra);
    assert_eq!(
        case_family(&body.cases[0]).unwrap_err(),
        ProjectionError::AmbiguousFamily
    );
    // Everything else still has its family.
    assert_eq!(
        case_family(&body.cases[1]).unwrap().as_str(),
        "pii:global:email"
    );
    let counts: PopulationCounts = AuthoredIndexCounts::of(&body);
    assert_eq!(counts.authored_cases, 24);
}

struct AuthoredIndexCounts;
impl AuthoredIndexCounts {
    fn of(body: &CorpusSnapshotBody) -> PopulationCounts {
        pii_eval_kernel::AuthoredIndex::new(body).unwrap().counts()
    }
}
