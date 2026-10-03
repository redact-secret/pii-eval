//! Property tests for accounting with a fixed-seed generator.
//!
//! * Differential: a deliberately naive reference (group the rows into vectors,
//!   then apply the oracle's `groupBucket`/`metricBuckets` lambdas literally,
//!   one metric at a time, rescanning every group) must agree with the indexed
//!   single-pass implementation on counts, for random snapshots, scanner
//!   statuses and outcome rows. The reference shares no code with the kernel.
//! * Determinism: row order, scanner order and repetition cannot change the
//!   result.
//! * Conservation: strata add up to the whole and every identity holds.
//!
//! A failure reproduces from the printed iteration number.

mod acct_common;

use acct_common::*;
use pii_eval_contracts::{
    ContextClass, CorpusSnapshotBody, ExpectedType, Mechanics, MethodId, MetricCounts, MetricId,
    RangeState, ScannerStatus, SensitivityExpectation, SensitivityState, TypeState,
};
use pii_eval_kernel::{AuthoredIndex, OutcomeRef, ScannerInput, account};

#[derive(Clone, Copy, PartialEq, Eq)]
enum B {
    Num,
    Other,
    Unres,
    Nm,
    Na,
}

#[derive(Clone, Copy)]
struct R {
    valid: bool,
    sens: SensitivityExpectation,
    ctx: ContextClass,
    t: TypeState,
    s: SensitivityState,
    r: RangeState,
}

struct G {
    method: MethodId,
    jurisdictional: bool,
    rows: Vec<R>,
}

// The oracle's status derivation and group bucket, written out directly.
fn tstatus(t: TypeState) -> &'static str {
    match t {
        TypeState::NotMeasured => "nm",
        TypeState::Correct | TypeState::InvalidCorrect => "pass",
        _ => "fail",
    }
}

fn sstatus(s: SensitivityState) -> &'static str {
    match s {
        SensitivityState::NotMeasured => "nm",
        SensitivityState::Unresolved => "review",
        SensitivityState::Correct => "pass",
        _ => "fail",
    }
}

fn bucket(statuses: &[&str], event: &[bool]) -> B {
    if statuses.contains(&"review") {
        B::Unres
    } else if statuses.contains(&"nm") {
        B::Nm
    } else if event.iter().any(|e| *e) {
        B::Num
    } else {
        B::Other
    }
}

fn reference(g: &G, metric: MetricId) -> Vec<B> {
    let rows = &g.rows;
    let valid: Vec<&R> = rows.iter().filter(|r| r.valid).collect();
    let type_metric = |event: &dyn Fn(&R) -> bool| -> B {
        if valid.is_empty() {
            B::Na
        } else {
            bucket(
                &valid.iter().map(|r| tstatus(r.t)).collect::<Vec<_>>(),
                &valid.iter().map(|r| event(r)).collect::<Vec<_>>(),
            )
        }
    };
    let sens_metric = |want: SensitivityExpectation, event: &dyn Fn(&R) -> bool| -> B {
        let eligible: Vec<&R> = rows.iter().filter(|r| r.sens == want).collect();
        if eligible.is_empty() {
            B::Na
        } else {
            bucket(
                &eligible.iter().map(|r| sstatus(r.s)).collect::<Vec<_>>(),
                &eligible.iter().map(|r| event(r)).collect::<Vec<_>>(),
            )
        }
    };
    let all_s: Vec<&str> = rows.iter().map(|r| sstatus(r.s)).collect();
    let all_t: Vec<&str> = rows.iter().map(|r| tstatus(r.t)).collect();
    vec![match metric {
        MetricId::TypeMissRate => type_metric(&|r| r.t == TypeState::Miss),
        MetricId::WrongFamilyRate => type_metric(&|r| r.t == TypeState::WrongFamily),
        MetricId::WrongJurisdictionRate => {
            if g.jurisdictional {
                type_metric(&|r| r.t == TypeState::WrongJurisdiction)
            } else {
                B::Na
            }
        }
        MetricId::SensitiveMissRate => sens_metric(SensitivityExpectation::Sensitive, &|r| {
            r.s == SensitivityState::Miss
        }),
        MetricId::NonSensitiveFlagRate => sens_metric(SensitivityExpectation::NonSensitive, &|r| {
            r.s == SensitivityState::FalsePositive
        }),
        MetricId::ContextDiscriminationRate => {
            if g.method != MethodId::ContextDiscrimination {
                return vec![];
            }
            let endpoints: Vec<&R> = rows
                .iter()
                .filter(|r| r.ctx != ContextClass::Neutral)
                .collect();
            let st: Vec<&str> = endpoints.iter().map(|r| sstatus(r.s)).collect();
            if st.contains(&"review") {
                B::Unres
            } else if st.contains(&"nm") {
                B::Nm
            } else if st.iter().all(|s| *s == "pass") {
                B::Num
            } else {
                B::Other
            }
        }
        MetricId::BenignSuppressionRate => {
            if g.method != MethodId::PiiBenign {
                B::Na
            } else {
                bucket(
                    &all_s,
                    &rows
                        .iter()
                        .map(|r| sstatus(r.s) == "pass")
                        .collect::<Vec<_>>(),
                )
            }
        }
        MetricId::JurisdictionCollisionRate => {
            if g.method != MethodId::JurisdictionCollision {
                B::Na
            } else {
                bucket(
                    &all_t,
                    &rows
                        .iter()
                        .map(|r| tstatus(r.t) == "pass")
                        .collect::<Vec<_>>(),
                )
            }
        }
        MetricId::RangeCollateralRate => {
            if valid.is_empty() || valid.iter().all(|r| r.r == RangeState::Miss) {
                B::Na
            } else if valid.iter().any(|r| r.r == RangeState::NotApplicable) {
                B::Nm
            } else if valid
                .iter()
                .any(|r| matches!(r.r, RangeState::Overbroad | RangeState::Partial))
            {
                B::Num
            } else {
                B::Other
            }
        }
        MetricId::MeasurableShare => {
            let type_axis = bucket(&all_t, &[true]);
            let sens_axis = if rows
                .iter()
                .any(|r| r.sens == SensitivityExpectation::NotEstablished)
            {
                B::Unres
            } else {
                bucket(&all_s, &[true])
            };
            return vec![type_axis, sens_axis];
        }
    }]
}

fn tally(buckets: &[B]) -> MetricCounts {
    let n = |b: B| buckets.iter().filter(|x| **x == b).count() as u64;
    let (num, other, unres, nm, na) = (n(B::Num), n(B::Other), n(B::Unres), n(B::Nm), n(B::Na));
    MetricCounts {
        eligible: num + other + unres + nm,
        measured: num + other,
        numerator: num,
        unresolved: unres,
        not_measured: nm,
        not_applicable: na,
        total: buckets.len() as u64,
    }
}

struct World {
    body: CorpusSnapshotBody,
    /// Per case: method, jurisdictional, and per occurrence (variant, occurrence, valid, sens, ctx).
    occurrences: Vec<(
        String,
        String,
        String,
        ExpectedType,
        SensitivityExpectation,
        ContextClass,
    )>,
}

fn pick<'a, T>(rng: &mut Rng, items: &'a [T]) -> &'a T {
    &items[rng.below(items.len())]
}

fn generate(rng: &mut Rng) -> World {
    let methods = [
        MethodId::TypeValidation,
        MethodId::ContextDiscrimination,
        MethodId::PiiBenign,
        MethodId::JurisdictionCollision,
        MethodId::Mutation,
        MethodId::ReferenceDifferential,
        MethodId::SchemaOnly,
    ];
    let types = [ExpectedType::Valid, ExpectedType::Invalid];
    let senses = [
        SensitivityExpectation::Sensitive,
        SensitivityExpectation::NonSensitive,
        SensitivityExpectation::NotEstablished,
    ];
    let mut specs = Vec::new();
    let case_count = 1 + rng.below(12);
    for c in 0..case_count {
        let method = *pick(rng, &methods);
        let language = *pick(rng, &["en", "ko", "ja"]);
        let jurisdiction = *pick(rng, &[None, Some("US"), Some("KR")]);
        let cid = format!("case-{c:02}");
        let variants = if method == MethodId::ContextDiscrimination {
            [
                ("sen", ContextClass::Sensitive),
                ("neu", ContextClass::Neutral),
                ("non", ContextClass::NonSensitive),
            ]
            .iter()
            .map(|(suffix, ctx)| {
                let occs = (0..1 + rng.below(2))
                    .map(|i| occ(["o1", "o2"][i], *pick(rng, &types), *pick(rng, &senses)))
                    .collect();
                var(&format!("{cid}-{suffix}"), *ctx, occs)
            })
            .collect()
        } else {
            (0..1 + rng.below(3))
                .map(|v| {
                    let occs = (0..1 + rng.below(2))
                        .map(|i| occ(["o1", "o2"][i], *pick(rng, &types), *pick(rng, &senses)))
                        .collect();
                    var(&format!("{cid}-v{v}"), ContextClass::Neutral, occs)
                })
                .collect()
        };
        specs.push(case(&cid, method, language, jurisdiction, variants));
    }
    let body = snapshot_body(specs);
    let mut occurrences = Vec::new();
    for c in &body.cases {
        for v in &c.variants {
            for e in &v.expectations {
                occurrences.push((
                    c.case_id.as_str().to_owned(),
                    v.variant_id.as_str().to_owned(),
                    e.occurrence_id.as_str().to_owned(),
                    e.type_expectation,
                    e.sensitivity,
                    e.context_class,
                ));
            }
        }
    }
    World { body, occurrences }
}

/// Random outcome rows for one scanner: reachable states for a complete
/// scanner, all-unmeasured rows otherwise.
fn rows_for(
    rng: &mut Rng,
    world: &World,
    scanner: &str,
    status: ScannerStatus,
) -> Vec<pii_eval_contracts::CaseOutcome> {
    let ranges = [
        RangeState::Exact,
        RangeState::Overbroad,
        RangeState::Partial,
        RangeState::Miss,
        RangeState::NotApplicable,
    ];
    world
        .occurrences
        .iter()
        .map(|(c, v, o, ty, sens, _)| {
            let (t, s, r) = if status == ScannerStatus::Complete {
                let ts = TypeState::reachable(*ty);
                let ss = SensitivityState::reachable(*sens);
                (
                    ts[rng.below(ts.len())],
                    ss[rng.below(ss.len())],
                    ranges[rng.below(ranges.len())],
                )
            } else {
                (
                    TypeState::NotMeasured,
                    SensitivityState::NotMeasured,
                    RangeState::NotApplicable,
                )
            };
            outcome(
                scanner,
                &world.body,
                &(c.clone(), v.clone(), o.clone(), t, s, r),
            )
        })
        .collect()
}

fn reference_counts(
    world: &World,
    rows: &[pii_eval_contracts::CaseOutcome],
) -> Vec<(MetricId, MetricCounts)> {
    let mut groups: Vec<G> = world
        .body
        .cases
        .iter()
        .map(|c| G {
            method: c.method,
            jurisdictional: c.jurisdiction.is_some(),
            rows: Vec::new(),
        })
        .collect();
    for row in rows {
        let ci = world
            .body
            .cases
            .iter()
            .position(|c| c.case_id == row.case_id)
            .unwrap();
        let (_, _, _, ty, sens, ctx) = world
            .occurrences
            .iter()
            .find(|o| o.1 == row.variant_id.as_str() && o.2 == row.occurrence_id.as_str())
            .unwrap();
        groups[ci].rows.push(R {
            valid: *ty == ExpectedType::Valid,
            sens: *sens,
            ctx: *ctx,
            t: row.type_identity,
            s: row.sensitivity_context,
            r: row.range,
        });
    }
    pii_eval_contracts::METRICS
        .iter()
        .map(|m| {
            let buckets: Vec<B> = groups.iter().flat_map(|g| reference(g, m.id)).collect();
            (m.id, tally(&buckets))
        })
        .collect()
}

#[test]
fn indexed_accounting_agrees_with_the_naive_reference() {
    let mut rng = Rng(0xACC0_0001);
    for iteration in 0..400 {
        let world = generate(&mut rng);
        let status = if rng.below(4) == 0 {
            *pick(
                &mut rng,
                &[
                    ScannerStatus::Unsupported,
                    ScannerStatus::Unavailable,
                    ScannerStatus::Unstable,
                    ScannerStatus::Error,
                ],
            )
        } else {
            ScannerStatus::Complete
        };
        let rows = rows_for(&mut rng, &world, "scan-one", status);
        let index = AuthoredIndex::new(&world.body).expect("generated snapshot is accountable");
        let id = sid("scan-one");
        let acc = account(
            &index,
            &[ScannerInput { id: &id, status }],
            rows.iter().map(OutcomeRef::from),
            &Mechanics::PII_V1,
        )
        .unwrap_or_else(|e| panic!("iteration {iteration}: {e}"));
        for (metric, expected) in reference_counts(&world, &rows) {
            let got = acc.scanners[0].overall.metric(metric).unwrap();
            assert_eq!(got.counts, expected, "iteration {iteration} {metric:?}");
        }
        assert_conserved(&acc);
        assert_eq!(acc.resources.rows_visited, world.occurrences.len() as u64);
        assert_eq!(acc.resources.group_visits, world.body.cases.len() as u64);
    }
}

#[test]
fn row_order_scanner_order_and_repetition_cannot_change_the_result() {
    let mut rng = Rng(0xACC0_0002);
    for iteration in 0..120 {
        let world = generate(&mut rng);
        let index = AuthoredIndex::new(&world.body).unwrap();
        let (a, b, c) = (sid("alpha-scan"), sid("beta-scan"), sid("gamma-scan"));
        let statuses = [
            (&a, ScannerStatus::Complete, "alpha-scan"),
            (&b, ScannerStatus::Unstable, "beta-scan"),
            (&c, ScannerStatus::Complete, "gamma-scan"),
        ];
        let mut rows = Vec::new();
        for (_, status, name) in &statuses {
            rows.extend(rows_for(&mut rng, &world, name, *status));
        }
        let inputs: Vec<ScannerInput<'_>> = statuses
            .iter()
            .map(|(id, status, _)| ScannerInput {
                id,
                status: *status,
            })
            .collect();
        let baseline = account(
            &index,
            &inputs,
            rows.iter().map(OutcomeRef::from),
            &Mechanics::PII_V1,
        )
        .unwrap();
        // Scanners come out in id order whatever order they were given.
        let names: Vec<&str> = baseline
            .scanners
            .iter()
            .map(|s| s.scanner_id.as_str())
            .collect();
        assert_eq!(names, ["alpha-scan", "beta-scan", "gamma-scan"]);
        assert_conserved(&baseline);
        for _ in 0..4 {
            let mut shuffled = rows.clone();
            rng.shuffle(&mut shuffled);
            let mut reordered = inputs.clone();
            rng.shuffle(&mut reordered);
            let again = account(
                &index,
                &reordered,
                shuffled.iter().map(OutcomeRef::from),
                &Mechanics::PII_V1,
            )
            .unwrap();
            assert_eq!(again, baseline, "iteration {iteration}");
        }
        // Scanners are never pooled: each scanner's accounting equals a run on its own rows.
        for (id, status, name) in &statuses {
            let own: Vec<_> = rows
                .iter()
                .filter(|r| r.scanner_id.as_str() == *name)
                .collect();
            let alone = account(
                &index,
                &[ScannerInput {
                    id,
                    status: *status,
                }],
                own.iter().map(|r| OutcomeRef::from(*r)),
                &Mechanics::PII_V1,
            )
            .unwrap();
            let in_run = baseline
                .scanners
                .iter()
                .find(|s| s.scanner_id.as_str() == *name)
                .unwrap();
            assert_eq!(&alone.scanners[0], in_run, "iteration {iteration} {name}");
        }
    }
}

#[test]
fn an_unstable_scanner_never_contributes_a_measured_sample() {
    let mut rng = Rng(0xACC0_0003);
    for _ in 0..50 {
        let world = generate(&mut rng);
        let index = AuthoredIndex::new(&world.body).unwrap();
        let id = sid("beta-scan");
        let rows = rows_for(&mut rng, &world, "beta-scan", ScannerStatus::Unstable);
        let acc = account(
            &index,
            &[ScannerInput {
                id: &id,
                status: ScannerStatus::Unstable,
            }],
            rows.iter().map(OutcomeRef::from),
            &Mechanics::PII_V1,
        )
        .unwrap();
        for m in &acc.scanners[0].overall.metrics {
            assert_eq!(m.counts.measured, 0, "{:?}", m.metric);
            assert_eq!(m.counts.numerator, 0, "{:?}", m.metric);
        }
    }
}
