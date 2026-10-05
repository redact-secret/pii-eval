//! The product-projection block of the public-synthetic artifact (schema 1.2,
//! ADR 0016).
//!
//! The block restates ONE population artifact's measurement per
//! (scanner, view, family) cell, so a downstream qualification policy can read
//! "this family under this view" without reading outcome rows. It is a
//! measurement view, never a verdict: no threshold, support status or ranking
//! exists here, and nothing in it is product policy.
//!
//! Boundaries kept by construction and checked by [`ProductProjection::validate`]:
//!
//! * **One population.** Every row carries the artifact's own population and
//!   scanner binding; a row that differs from the artifact is
//!   `projection-binding-mismatch`.
//! * **No pooling.** Cells partition the population per scanner: the cases,
//!   variants and occurrences of a scanner's rows add up to the artifact's
//!   authored counts, never more (`projection-pooled-denominator`), and every
//!   metric's `total` fits inside the row's own cases. A row never borrows
//!   another row's denominator, and no combined view exists.
//! * **Closed vocabulary.** The view and the mode are closed enums; an unknown
//!   value is a `schema-violation`. Which views a run needs comes from the
//!   caller's roster, recorded as `requiredViews`.
//! * **Provenance, not text.** Rows carry identifiers, digests and integers
//!   only. The block lives inside `semantic`, so the semantic digest covers it.
//!
//! The values themselves (recomputation from the authored population) are the
//! kernel's to verify (`pii_eval_kernel::projection`); this module proves the
//! structure and the bindings, which need no scoring rule.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::artifact::{MethodCoverage, MetricResult, PopulationCounts, PublicPopulationBinding};
use crate::axes::kebab_enum;
use crate::check::{non_empty, sorted_unique, within_limit};
use crate::ident::{FamilyId, Id, LanguageTag, ScannerId, Sha256Digest};
use crate::limits::{MAX_PROJECTION_ROWS, MAX_PROJECTION_STRATA, MAX_SAFE_INTEGER, MAX_SCANNERS};
use crate::protocol::{METRICS, Mechanics, SampleUnit};
use crate::reason::{Collector, Path, ReasonCode};
use crate::scanner::{ProductIdentity, ScannerIdentity, ScannerStatus};

kebab_enum!(
    /// A population view of the product projection. The four ids are the closed
    /// vocabulary of the benchmarks request (redact-secret-benchmarks#664). A
    /// run's caller supplies which of them it requires and which cases belong
    /// to which (the roster); the engine holds no view policy.
    ProjectionView { OraclePlan, QualificationPlan, DiagnosticBalanced, BenignHeavyStress }
);

impl ProjectionView {
    /// Every view, in wire order.
    pub const ALL: [ProjectionView; 4] = [
        ProjectionView::BenignHeavyStress,
        ProjectionView::DiagnosticBalanced,
        ProjectionView::OraclePlan,
        ProjectionView::QualificationPlan,
    ];

    /// The wire string; collections sort by it, bytewise.
    pub const fn as_str(self) -> &'static str {
        match self {
            ProjectionView::OraclePlan => "oracle-plan",
            ProjectionView::QualificationPlan => "qualification-plan",
            ProjectionView::DiagnosticBalanced => "diagnostic-balanced",
            ProjectionView::BenignHeavyStress => "benign-heavy-stress",
        }
    }
}

kebab_enum!(
    /// The mode of the run the rows come from (the run configuration's mode).
    /// `official` runs pin every identity and enforce resource limits;
    /// `exploratory` runs may not. The mode travels with every row so an
    /// exploratory number is never read as an official one.
    ProjectionMode { Official, Exploratory }
);

impl ProjectionMode {
    /// The wire string.
    pub const fn as_str(self) -> &'static str {
        match self {
            ProjectionMode::Official => "official",
            ProjectionMode::Exploratory => "exploratory",
        }
    }
}

/// The identities a row must share with the artifact that holds it. Copying
/// them into the row makes a row that was lifted out of its artifact, or edited
/// to point at another scanner configuration or population, detectable on its
/// own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectionBinding {
    /// The scanner the row measures.
    pub scanner_id: ScannerId,
    /// Digest of the scanner configuration parameters.
    pub configuration_digest: Sha256Digest,
    /// Digest of the activation selectors.
    pub activation_digest: Sha256Digest,
    /// Released, or the candidate and its digest.
    pub product: ProductIdentity,
    /// The population the row belongs to.
    pub population: PublicPopulationBinding,
}

/// One language stratum of a row: the row's cases in that language, accounted
/// on their own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LanguageStratum {
    /// Case language.
    pub language: LanguageTag,
    /// Authored counts of the stratum.
    pub counts: PopulationCounts,
    /// The ten metrics over the stratum's cases.
    pub metrics: Vec<MetricResult>,
}

/// One control-class stratum of a row. The class is an opaque label the
/// caller's roster assigns to authored cases; the corpus carries no control
/// class (ADR 0005, A7). Strata cover the assigned cases only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ControlClassStratum {
    /// Opaque control-class label from the roster.
    pub control_class: Id,
    /// Authored counts of the stratum.
    pub counts: PopulationCounts,
    /// The ten metrics over the stratum's cases.
    pub metrics: Vec<MetricResult>,
}

/// One cell of the projection: a scanner, a view and a family, with their own
/// counts and ten metric results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectionRow {
    /// Family of the cases in this cell, as the corpus names it.
    pub family: FamilyId,
    /// The view the cases belong to.
    pub view: ProjectionView,
    /// Mode of the run.
    pub mode: ProjectionMode,
    /// Scanner, configuration, activation, product and population binding.
    pub binding: ProjectionBinding,
    /// Authored cases, variants and occurrences of this cell. Never effective N.
    pub counts: PopulationCounts,
    /// Method coverage of the cell, ascending by method id.
    pub method_coverage: Vec<MethodCoverage>,
    /// The ten metrics over the cell's cases, ascending by metric id. Counts,
    /// effective N and the value or withheld reason are the metric's own.
    pub metrics: Vec<MetricResult>,
    /// Language strata, ascending by language, partitioning the cell.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub by_language: Vec<LanguageStratum>,
    /// Control-class strata, ascending by class; only when the roster assigns
    /// classes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub by_control_class: Vec<ControlClassStratum>,
}

/// The closed, optional product-projection block (schema 1.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductProjection {
    /// Digest of the caller's roster (view and control-class assignments), so a
    /// different roster is a different artifact.
    pub roster_digest: Sha256Digest,
    /// The views the caller required, ascending, unique. Every one has rows.
    pub required_views: Vec<ProjectionView>,
    /// Rows, ascending by (scanner id, view, family); each key appears once.
    pub rows: Vec<ProjectionRow>,
}

/// What the artifact that holds the block says, for the structural checks.
pub(crate) struct ProjectionContext<'a> {
    pub scanners: &'a [(&'a ScannerIdentity, ScannerStatus)],
    pub population: &'a PublicPopulationBinding,
    pub counts: &'a PopulationCounts,
    pub methods: &'a [MethodCoverage],
    pub mechanics: &'a Mechanics,
}

fn counts_sane(counts: &PopulationCounts) -> bool {
    [counts.authored_cases, counts.variants, counts.occurrences]
        .iter()
        .all(|&n| n <= MAX_SAFE_INTEGER)
        && counts.variants >= counts.authored_cases
        && counts.occurrences >= counts.variants
}

/// The ten metrics, each once, ascending; every result valid on its own and no
/// denominator larger than the cases it may count.
fn check_ten_metrics(
    metrics: &[MetricResult],
    cases: u64,
    mechanics: &Mechanics,
    path: &Path<'_>,
    c: &mut Collector,
) {
    if metrics.len() != METRICS.len() {
        c.push(ReasonCode::MetricDefinitionMismatch, path);
    }
    sorted_unique(metrics, |m| m.metric.id.as_str(), path, c);
    let all_present = METRICS
        .iter()
        .all(|d| metrics.iter().any(|m| m.metric.id == d.id));
    if !all_present {
        c.push(ReasonCode::MetricDefinitionMismatch, path);
    }
    for (i, m) in metrics.iter().enumerate() {
        let p = path.index(i);
        m.validate(mechanics, &p, c);
        // A sample is a case (a trio, for context discrimination); the
        // axis-assertion metric counts at most two assertions per case. A
        // `total` beyond that counts cases this row does not hold: a pooled
        // denominator.
        let per_case: u64 = match m.metric.id.definition().sample_unit {
            SampleUnit::AuthoredCaseMethod | SampleUnit::ContextTrio => 1,
            SampleUnit::AxisAssertion => 2,
        };
        if m.counts.total > cases.saturating_mul(per_case) {
            c.push(ReasonCode::ProjectionPooledDenominator, &p.field("counts"));
        }
    }
}

fn add(sum: &mut u64, n: u64) {
    *sum = sum.saturating_add(n);
}

impl ProductProjection {
    pub(crate) fn validate(&self, ctx: &ProjectionContext<'_>, path: &Path<'_>, c: &mut Collector) {
        let views_path = path.field("requiredViews");
        non_empty(&self.required_views, &views_path, c);
        sorted_unique(&self.required_views, |v| v.as_str(), &views_path, c);
        let rows_path = path.field("rows");
        if !within_limit(self.rows.len(), MAX_PROJECTION_ROWS, &rows_path, c) {
            return;
        }
        sorted_unique(
            &self.rows,
            |r| {
                (
                    r.binding.scanner_id.as_str(),
                    r.view.as_str(),
                    r.family.as_str(),
                )
            },
            &rows_path,
            c,
        );
        // The run has one mode: official and exploratory rows are never mixed
        // in one artifact.
        if let Some(first) = self.rows.first() {
            if self.rows.iter().any(|r| r.mode != first.mode) {
                c.push(ReasonCode::ProjectionInvalid, &rows_path);
            }
        }
        for (i, row) in self.rows.iter().enumerate() {
            self.check_row(row, ctx, &rows_path.index(i), c);
            if c.is_full() {
                return;
            }
        }
        self.check_views_and_sums(ctx, path, c);
    }

    fn check_row(
        &self,
        row: &ProjectionRow,
        ctx: &ProjectionContext<'_>,
        path: &Path<'_>,
        c: &mut Collector,
    ) {
        if !self.required_views.contains(&row.view) {
            c.push(ReasonCode::ProjectionInvalid, &path.field("view"));
        }
        // Binding: the row names a scanner of this artifact and carries exactly
        // its configuration, activation and product, and this artifact's population.
        let binding = path.field("binding");
        let scanner = ctx
            .scanners
            .iter()
            .find(|(id, _)| id.scanner_id == row.binding.scanner_id);
        let bound = scanner.is_some_and(|(id, _)| {
            id.configuration_digest == row.binding.configuration_digest
                && id.activation_digest == row.binding.activation_digest
                && id.product == row.binding.product
        });
        if !bound || row.binding.population != *ctx.population {
            c.push(ReasonCode::ProjectionBindingMismatch, &binding);
        }

        // Counts.
        let counts_path = path.field("counts");
        if !counts_sane(&row.counts) || row.counts.authored_cases == 0 {
            c.push(ReasonCode::CountMismatch, &counts_path);
            return;
        }
        if row.counts.authored_cases > ctx.counts.authored_cases
            || row.counts.variants > ctx.counts.variants
            || row.counts.occurrences > ctx.counts.occurrences
        {
            c.push(ReasonCode::ProjectionPooledDenominator, &counts_path);
        }
        let coverage = path.field("methodCoverage");
        non_empty(&row.method_coverage, &coverage, c);
        sorted_unique(&row.method_coverage, |m| m.method.id.as_str(), &coverage, c);
        let (mut cases, mut variants) = (0u64, 0u64);
        for (i, m) in row.method_coverage.iter().enumerate() {
            let pop = ctx.methods.iter().find(|p| p.method == m.method);
            if pop.is_none_or(|p| m.cases > p.cases || m.variants > p.variants) {
                c.push(ReasonCode::ProjectionPooledDenominator, &coverage.index(i));
            }
            add(&mut cases, m.cases);
            add(&mut variants, m.variants);
        }
        if cases != row.counts.authored_cases || variants != row.counts.variants {
            c.push(ReasonCode::CountMismatch, &coverage);
        }

        check_ten_metrics(
            &row.metrics,
            row.counts.authored_cases,
            ctx.mechanics,
            &path.field("metrics"),
            c,
        );

        // Language strata partition the cell.
        let langs = path.field("byLanguage");
        if within_limit(row.by_language.len(), MAX_PROJECTION_STRATA, &langs, c) {
            sorted_unique(&row.by_language, |l| l.language.as_str(), &langs, c);
            let mut sum = PopulationCounts {
                authored_cases: 0,
                variants: 0,
                occurrences: 0,
            };
            for (i, l) in row.by_language.iter().enumerate() {
                let p = langs.index(i);
                if !counts_sane(&l.counts) || l.counts.authored_cases == 0 {
                    c.push(ReasonCode::CountMismatch, &p.field("counts"));
                    continue;
                }
                add(&mut sum.authored_cases, l.counts.authored_cases);
                add(&mut sum.variants, l.counts.variants);
                add(&mut sum.occurrences, l.counts.occurrences);
                check_ten_metrics(
                    &l.metrics,
                    l.counts.authored_cases,
                    ctx.mechanics,
                    &p.field("metrics"),
                    c,
                );
            }
            if !row.by_language.is_empty() && sum != row.counts {
                let code = if sum.authored_cases > row.counts.authored_cases {
                    ReasonCode::ProjectionPooledDenominator
                } else {
                    ReasonCode::CountMismatch
                };
                c.push(code, &langs);
            }
        }

        // Control-class strata cover the assigned cases: never more than the cell.
        let classes = path.field("byControlClass");
        if within_limit(
            row.by_control_class.len(),
            MAX_PROJECTION_STRATA,
            &classes,
            c,
        ) {
            sorted_unique(
                &row.by_control_class,
                |k| k.control_class.as_str(),
                &classes,
                c,
            );
            let mut sum = (0u64, 0u64, 0u64);
            for (i, k) in row.by_control_class.iter().enumerate() {
                let p = classes.index(i);
                if !counts_sane(&k.counts) || k.counts.authored_cases == 0 {
                    c.push(ReasonCode::CountMismatch, &p.field("counts"));
                    continue;
                }
                add(&mut sum.0, k.counts.authored_cases);
                add(&mut sum.1, k.counts.variants);
                add(&mut sum.2, k.counts.occurrences);
                check_ten_metrics(
                    &k.metrics,
                    k.counts.authored_cases,
                    ctx.mechanics,
                    &p.field("metrics"),
                    c,
                );
            }
            if sum.0 > row.counts.authored_cases
                || sum.1 > row.counts.variants
                || sum.2 > row.counts.occurrences
            {
                c.push(ReasonCode::ProjectionPooledDenominator, &classes);
            }
        }
    }

    /// Every required view has rows for every scanner, and each scanner's rows
    /// add up to the artifact's authored counts, exactly.
    fn check_views_and_sums(
        &self,
        ctx: &ProjectionContext<'_>,
        path: &Path<'_>,
        c: &mut Collector,
    ) {
        if ctx.scanners.len() > MAX_SCANNERS {
            return;
        }
        for (identity, _) in ctx.scanners {
            let own: Vec<&ProjectionRow> = self
                .rows
                .iter()
                .filter(|r| r.binding.scanner_id == identity.scanner_id)
                .collect();
            for view in &self.required_views {
                if !own.iter().any(|r| r.view == *view) {
                    c.push(ReasonCode::ProjectionViewMissing, &path.field("rows"));
                }
            }
            let mut sum = PopulationCounts {
                authored_cases: 0,
                variants: 0,
                occurrences: 0,
            };
            for r in &own {
                add(&mut sum.authored_cases, r.counts.authored_cases);
                add(&mut sum.variants, r.counts.variants);
                add(&mut sum.occurrences, r.counts.occurrences);
            }
            if sum != *ctx.counts {
                let code = if sum.authored_cases > ctx.counts.authored_cases
                    || sum.variants > ctx.counts.variants
                    || sum.occurrences > ctx.counts.occurrences
                {
                    ReasonCode::ProjectionPooledDenominator
                } else {
                    ReasonCode::CountMismatch
                };
                c.push(code, &path.field("rows"));
            }
        }
    }
}
