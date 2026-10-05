//! The product projection (schema 1.2, ADR 0016): the optional per
//! (scanner, view, family) block of the public artifact, built and recomputed
//! from the authored population, the outcome rows and a caller-supplied roster.
//!
//! This module only arranges what accounting already measures. Each cell is the
//! authored cases of one family inside one view, accounted ON THEIR OWN with the
//! same `account` the whole population uses, so a cell's denominators are its own
//! cases and no value is derived from another cell. Language strata come from the
//! accounting's own language stratum; control-class strata account the cell's
//! cases that the roster assigned a class. Nothing here decides support, sets a
//! threshold or ranks: the view ids are a closed vocabulary, which cases belong
//! to which view and which views are required is the caller's roster, and the
//! family is the corpus's own identifier.
//!
//! A case's family is its collision declaration's target family, or the one
//! family all its expected occurrences share. A case whose occurrences span
//! several families and that declares no target has no honest family cell:
//! the projection is refused ([`ProjectionError::AmbiguousFamily`]) rather than
//! attributing it to one of them.
//!
//! Pure: no process, network, clock or file access.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use pii_eval_contracts::limits::MAX_PROJECTION_ROWS;
use pii_eval_contracts::{
    Case, Collector, ControlClassStratum, CorpusSnapshot, CorpusSnapshotBody, FamilyId, Id,
    LanguageStratum, Mechanics, MethodCoverage, MethodId, MethodRef, Path, PopulationCounts,
    ProductProjection, ProjectionBinding, ProjectionMode, ProjectionRow, ProjectionView,
    PublicPopulationBinding, PublicSyntheticArtifact, ReasonCode, ScannerIdentity, ScannerStatus,
    Sha256Digest,
};

use crate::accounting::{
    AccountError, Accounting, AuthoredIndex, OutcomeRef, ScannerInput, StratumAccounting, account,
};
use crate::verify::{VerifyFailure, verify_public_artifact_accounting};

const ROSTER_DOMAIN: &str = "pii-eval.projection-roster/1";

/// Why a roster or a projection was refused. Numeric and enumerated payloads
/// only, never identifiers taken from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionError {
    /// No view is required.
    NoRequiredViews,
    /// A view is required twice.
    DuplicateRequiredView,
    /// A case is assigned to a view twice.
    DuplicateAssignment,
    /// An assignment names a case the snapshot does not contain.
    UnknownCase,
    /// A snapshot case has no view: every case belongs to exactly one view.
    UnassignedCase,
    /// A case is assigned to a view the roster did not list as required.
    ViewNotRequired,
    /// A required view has no case: it would have no rows.
    EmptyRequiredView,
    /// A case has a control class twice.
    DuplicateControlAssignment,
    /// A control-class assignment names a case the snapshot does not contain.
    UnknownControlCase,
    /// A case's occurrences span several families and it declares no target.
    AmbiguousFamily,
    /// More cells than the contract allows.
    TooManyRows,
    /// Accounting could not run.
    Accounting(AccountError),
}

impl fmt::Display for ProjectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            ProjectionError::NoRequiredViews => "no required view",
            ProjectionError::DuplicateRequiredView => "a view is required twice",
            ProjectionError::DuplicateAssignment => "a case is assigned to a view twice",
            ProjectionError::UnknownCase => "a view assignment names an unknown case",
            ProjectionError::UnassignedCase => "a case has no view",
            ProjectionError::ViewNotRequired => "a case is assigned to a view that is not required",
            ProjectionError::EmptyRequiredView => "a required view has no case",
            ProjectionError::DuplicateControlAssignment => "a case has two control classes",
            ProjectionError::UnknownControlCase => "a control class names an unknown case",
            ProjectionError::AmbiguousFamily => "a case spans several families and has no target",
            ProjectionError::TooManyRows => "too many projection rows",
            ProjectionError::Accounting(e) => return write!(f, "accounting: {e}"),
        };
        f.write_str(text)
    }
}

impl std::error::Error for ProjectionError {}

impl From<AccountError> for ProjectionError {
    fn from(e: AccountError) -> Self {
        ProjectionError::Accounting(e)
    }
}

/// The caller's roster: which views a run requires, the view of every authored
/// case, and optionally a control class for some cases. External input: the
/// engine holds no roster of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionRoster {
    required: Vec<ProjectionView>,
    views: BTreeMap<Id, ProjectionView>,
    control: BTreeMap<Id, Id>,
    digest: Sha256Digest,
}

impl ProjectionRoster {
    /// Check a roster against the snapshot it will be applied to. Every case is
    /// in exactly one view; every assigned view is required; every required view
    /// has at least one case; a control class names an existing case once.
    pub fn new(
        body: &CorpusSnapshotBody,
        required: &[ProjectionView],
        views: &[(Id, ProjectionView)],
        control_classes: &[(Id, Id)],
    ) -> Result<Self, ProjectionError> {
        if required.is_empty() {
            return Err(ProjectionError::NoRequiredViews);
        }
        let mut required_sorted: Vec<ProjectionView> = required.to_vec();
        required_sorted.sort_by_key(|v| v.as_str());
        if required_sorted.windows(2).any(|w| w[0] == w[1]) {
            return Err(ProjectionError::DuplicateRequiredView);
        }
        let known: BTreeSet<&Id> = body.cases.iter().map(|c| &c.case_id).collect();
        let mut map = BTreeMap::new();
        for (case, view) in views {
            if !known.contains(case) {
                return Err(ProjectionError::UnknownCase);
            }
            if !required_sorted.contains(view) {
                return Err(ProjectionError::ViewNotRequired);
            }
            if map.insert(case.clone(), *view).is_some() {
                return Err(ProjectionError::DuplicateAssignment);
            }
        }
        if map.len() != known.len() {
            return Err(ProjectionError::UnassignedCase);
        }
        if required_sorted
            .iter()
            .any(|v| !map.values().any(|assigned| assigned == v))
        {
            return Err(ProjectionError::EmptyRequiredView);
        }
        // Every case must have a family cell, and the cells must fit a block:
        // refused here, before any scanner runs.
        let mut cells: BTreeSet<(&'static str, FamilyId)> = BTreeSet::new();
        for case in &body.cases {
            let view = map
                .get(&case.case_id)
                .copied()
                .unwrap_or(required_sorted[0]);
            cells.insert((view.as_str(), case_family(case)?));
        }
        if cells.len() > MAX_PROJECTION_ROWS {
            return Err(ProjectionError::TooManyRows);
        }
        let mut control = BTreeMap::new();
        for (case, class) in control_classes {
            if !known.contains(case) {
                return Err(ProjectionError::UnknownControlCase);
            }
            if control.insert(case.clone(), class.clone()).is_some() {
                return Err(ProjectionError::DuplicateControlAssignment);
            }
        }
        // A digest over the sorted content, so one roster has one digest
        // whatever order its file lists things in.
        let mut preimage = String::from(ROSTER_DOMAIN);
        preimage.push('\n');
        for v in &required_sorted {
            preimage.push_str(&format!("required\t{}\n", v.as_str()));
        }
        for (case, view) in &map {
            preimage.push_str(&format!("view\t{}\t{}\n", case.as_str(), view.as_str()));
        }
        for (case, class) in &control {
            preimage.push_str(&format!("control\t{}\t{}\n", case.as_str(), class.as_str()));
        }
        Ok(Self {
            required: required_sorted,
            views: map,
            control,
            digest: Sha256Digest::of_bytes(preimage.as_bytes()),
        })
    }

    /// The required views, ascending by wire string.
    pub fn required_views(&self) -> &[ProjectionView] {
        &self.required
    }

    /// Digest of the roster's content.
    pub fn digest(&self) -> &Sha256Digest {
        &self.digest
    }

    /// The view of `case`.
    pub fn view_of(&self, case: &Id) -> Option<ProjectionView> {
        self.views.get(case).copied()
    }

    /// The control class of `case`, when the roster assigned one.
    pub fn control_class_of(&self, case: &Id) -> Option<&Id> {
        self.control.get(case)
    }
}

/// The family of a case: its collision target, or the one family its
/// occurrences share.
pub fn case_family(case: &Case) -> Result<FamilyId, ProjectionError> {
    if let Some(collision) = &case.collision {
        return Ok(collision.target_family.clone());
    }
    let mut families = case
        .variants
        .iter()
        .flat_map(|v| &v.expectations)
        .map(|e| &e.family);
    let first = families.next().ok_or(ProjectionError::AmbiguousFamily)?;
    if families.any(|f| f != first) {
        return Err(ProjectionError::AmbiguousFamily);
    }
    Ok(first.clone())
}

/// What a projection is built from.
pub struct ProjectionInput<'a> {
    /// The authored population.
    pub snapshot: &'a CorpusSnapshotBody,
    /// The artifact's population binding, copied into every row.
    pub population: &'a PublicPopulationBinding,
    /// The artifact's scanners.
    pub scanners: &'a [(&'a ScannerIdentity, ScannerStatus)],
    /// Every scanner's outcome rows over the whole population.
    pub rows: &'a [OutcomeRef<'a>],
    /// The artifact's mechanics.
    pub mechanics: &'a Mechanics,
    /// The run's mode.
    pub mode: ProjectionMode,
}

fn restrict(body: &CorpusSnapshotBody, cases: &[&Case]) -> CorpusSnapshotBody {
    CorpusSnapshotBody {
        population: body.population.clone(),
        generation: body.generation.clone(),
        cases: cases.iter().map(|c| (*c).clone()).collect(),
    }
}

fn coverage_of(cases: &[&Case]) -> Vec<MethodCoverage> {
    let mut by_method: BTreeMap<&'static str, (MethodId, u64, u64)> = BTreeMap::new();
    for case in cases {
        let e = by_method
            .entry(case.method.as_str())
            .or_insert((case.method, 0, 0));
        e.1 += 1;
        e.2 += case.variants.len() as u64;
    }
    by_method
        .into_values()
        .map(|(id, cases, variants)| MethodCoverage {
            method: MethodRef::frozen(id),
            cases,
            variants,
        })
        .collect()
}

/// Account `cases` alone: every scanner, rows restricted to those cases.
fn account_cell(
    input: &ProjectionInput<'_>,
    cases: &[&Case],
    rows_by_case: &BTreeMap<&str, Vec<OutcomeRef<'_>>>,
) -> Result<Accounting, ProjectionError> {
    let body = restrict(input.snapshot, cases);
    let index = AuthoredIndex::new(&body)?;
    let scanners: Vec<ScannerInput<'_>> = input
        .scanners
        .iter()
        .map(|(id, status)| ScannerInput {
            id: &id.scanner_id,
            status: *status,
        })
        .collect();
    let rows = cases
        .iter()
        .flat_map(|c| rows_by_case.get(c.case_id.as_str()).into_iter().flatten())
        .copied();
    Ok(account(&index, &scanners, rows, input.mechanics)?)
}

fn stratum_counts(s: &StratumAccounting) -> PopulationCounts {
    s.authored
}

/// Build the product projection of one population artifact.
pub fn build_projection(
    input: &ProjectionInput<'_>,
    roster: &ProjectionRoster,
) -> Result<ProductProjection, ProjectionError> {
    // Cells: (view, family) -> cases, in snapshot order.
    let mut cells: BTreeMap<(&'static str, FamilyId), (ProjectionView, Vec<&Case>)> =
        BTreeMap::new();
    for case in &input.snapshot.cases {
        let view = roster
            .view_of(&case.case_id)
            .ok_or(ProjectionError::UnassignedCase)?;
        let family = case_family(case)?;
        cells
            .entry((view.as_str(), family))
            .or_insert_with(|| (view, Vec::new()))
            .1
            .push(case);
    }
    if cells.len().saturating_mul(input.scanners.len()) > MAX_PROJECTION_ROWS {
        return Err(ProjectionError::TooManyRows);
    }
    let mut rows_by_case: BTreeMap<&str, Vec<OutcomeRef<'_>>> = BTreeMap::new();
    for r in input.rows {
        rows_by_case.entry(r.case_id).or_default().push(*r);
    }

    let mut out: Vec<ProjectionRow> = Vec::new();
    for ((_, family), (view, cases)) in &cells {
        let accounting = account_cell(input, cases, &rows_by_case)?;
        let coverage = coverage_of(cases);
        // Control-class strata: the cell's cases that carry a class.
        let mut by_class: BTreeMap<&Id, Vec<&Case>> = BTreeMap::new();
        for case in cases {
            if let Some(class) = roster.control_class_of(&case.case_id) {
                by_class.entry(class).or_default().push(case);
            }
        }
        let mut class_accounts: Vec<(&Id, Accounting)> = Vec::new();
        for (class, class_cases) in by_class {
            class_accounts.push((class, account_cell(input, &class_cases, &rows_by_case)?));
        }
        for scanner in &accounting.scanners {
            let (identity, _) = input
                .scanners
                .iter()
                .find(|(id, _)| id.scanner_id == scanner.scanner_id)
                .ok_or(ProjectionError::Accounting(AccountError::UnknownScanner(0)))?;
            let by_control_class = class_accounts
                .iter()
                .filter_map(|(class, acc)| {
                    acc.scanners
                        .iter()
                        .find(|s| s.scanner_id == scanner.scanner_id)
                        .map(|s| ControlClassStratum {
                            control_class: (*class).clone(),
                            counts: stratum_counts(&s.overall),
                            metrics: s.overall.results(),
                        })
                })
                .collect();
            out.push(ProjectionRow {
                family: family.clone(),
                view: *view,
                mode: input.mode,
                binding: ProjectionBinding {
                    scanner_id: identity.scanner_id.clone(),
                    configuration_digest: identity.configuration_digest.clone(),
                    activation_digest: identity.activation_digest.clone(),
                    product: identity.product.clone(),
                    population: input.population.clone(),
                },
                counts: stratum_counts(&scanner.overall),
                method_coverage: coverage.clone(),
                metrics: scanner.overall.results(),
                by_language: scanner
                    .by_language
                    .iter()
                    .map(|(language, s)| LanguageStratum {
                        language: language.clone(),
                        counts: stratum_counts(s),
                        metrics: s.results(),
                    })
                    .collect(),
                by_control_class,
            });
        }
    }
    out.sort_by(|a, b| {
        (
            a.binding.scanner_id.as_str(),
            a.view.as_str(),
            a.family.as_str(),
        )
            .cmp(&(
                b.binding.scanner_id.as_str(),
                b.view.as_str(),
                b.family.as_str(),
            ))
    });
    Ok(ProductProjection {
        roster_digest: roster.digest().clone(),
        required_views: roster.required_views().to_vec(),
        rows: out,
    })
}

/// Verify the product projection of a public artifact against the authored
/// snapshot and the roster the run was given: the artifact's own accounting
/// first (`verify_public_artifact_accounting`), then the block recomputed from
/// the artifact's outcome rows and compared with what it carries.
///
/// An artifact without a block verifies the 1.1 way and is then refused if the
/// caller supplied a roster (it was supposed to carry one). A recomputed cell
/// that differs is reported with the stable codes of the contract:
/// `projection-binding-mismatch`, `projection-pooled-denominator` when a row
/// counts more than its own cases, `count-mismatch`, `metric-value-inconsistent`.
pub fn verify_public_projection(
    artifact: &PublicSyntheticArtifact,
    snapshot: &CorpusSnapshot,
    roster: &ProjectionRoster,
) -> Result<(), VerifyFailure> {
    verify_public_artifact_accounting(artifact, snapshot)?;
    let body = &artifact.semantic;
    let semantic = Path::ROOT.field("semantic");
    let root = semantic.field("productProjection");
    let mut c = Collector::new();
    let Some(actual) = &body.product_projection else {
        c.push(ReasonCode::ProjectionInvalid, &root);
        return c.finish().map_err(VerifyFailure::Mismatch);
    };
    let Some(first) = actual.rows.first() else {
        c.push(ReasonCode::ProjectionViewMissing, &root.field("rows"));
        return c.finish().map_err(VerifyFailure::Mismatch);
    };
    let scanners: Vec<(&ScannerIdentity, ScannerStatus)> = body
        .scanners
        .iter()
        .map(|s| (&s.identity, s.status))
        .collect();
    let rows: Vec<OutcomeRef<'_>> = body.outcomes.iter().map(OutcomeRef::from).collect();
    let expected = build_projection(
        &ProjectionInput {
            snapshot: &snapshot.semantic,
            population: &body.population,
            scanners: &scanners,
            rows: &rows,
            mechanics: &body.mechanics,
            mode: first.mode,
        },
        roster,
    )
    .map_err(|e| match e {
        ProjectionError::Accounting(a) => VerifyFailure::Accounting(a),
        _ => {
            let mut c = Collector::new();
            c.push(ReasonCode::ProjectionInvalid, &root);
            VerifyFailure::Mismatch(c.finish().unwrap_err())
        }
    })?;
    if actual.roster_digest != expected.roster_digest
        || actual.required_views != expected.required_views
    {
        c.push(ReasonCode::ProjectionInvalid, &root);
    }
    compare_rows(actual, &expected, &root.field("rows"), &mut c);
    c.finish().map_err(VerifyFailure::Mismatch)
}

type RowKey<'a> = (&'a str, &'a str, &'a str);

fn key(r: &ProjectionRow) -> RowKey<'_> {
    (
        r.binding.scanner_id.as_str(),
        r.view.as_str(),
        r.family.as_str(),
    )
}

fn compare_rows(
    actual: &ProductProjection,
    expected: &ProductProjection,
    list: &Path<'_>,
    c: &mut Collector,
) {
    // A relabeled or merged row shows up twice: its own counts differ from the
    // recomputed cell, and the cell it absorbed is missing.
    for (i, row) in actual.rows.iter().enumerate() {
        let p = list.index(i);
        match expected.rows.iter().find(|e| key(e) == key(row)) {
            None => c.push(ReasonCode::CountMismatch, &p),
            Some(want) => compare_row(row, want, &p, c),
        }
    }
    for want in &expected.rows {
        if !actual.rows.iter().any(|r| key(r) == key(want)) {
            c.push(ReasonCode::CountMismatch, list);
        }
    }
}

fn counts_exceed(a: &PopulationCounts, b: &PopulationCounts) -> bool {
    a.authored_cases > b.authored_cases || a.variants > b.variants || a.occurrences > b.occurrences
}

fn compare_metrics(
    a: &[pii_eval_contracts::MetricResult],
    b: &[pii_eval_contracts::MetricResult],
    path: &Path<'_>,
    c: &mut Collector,
) {
    if a.len() != b.len() {
        c.push(ReasonCode::MetricDefinitionMismatch, path);
        return;
    }
    for (i, (x, y)) in a.iter().zip(b).enumerate() {
        let p = path.index(i);
        if x.metric != y.metric {
            c.push(ReasonCode::MetricDefinitionMismatch, &p);
        } else if x.counts != y.counts {
            c.push(ReasonCode::CountMismatch, &p.field("counts"));
        } else if x != y {
            c.push(ReasonCode::MetricValueInconsistent, &p);
        }
    }
}

fn compare_row(a: &ProjectionRow, want: &ProjectionRow, path: &Path<'_>, c: &mut Collector) {
    if a.binding != want.binding {
        c.push(
            ReasonCode::ProjectionBindingMismatch,
            &path.field("binding"),
        );
    }
    if a.counts != want.counts {
        let code = if counts_exceed(&a.counts, &want.counts) {
            ReasonCode::ProjectionPooledDenominator
        } else {
            ReasonCode::CountMismatch
        };
        c.push(code, &path.field("counts"));
    }
    if a.method_coverage != want.method_coverage {
        c.push(ReasonCode::CountMismatch, &path.field("methodCoverage"));
    }
    compare_metrics(&a.metrics, &want.metrics, &path.field("metrics"), c);
    if a.by_language.len() != want.by_language.len()
        || a.by_language
            .iter()
            .zip(&want.by_language)
            .any(|(x, y)| x.language != y.language || x.counts != y.counts)
    {
        c.push(ReasonCode::CountMismatch, &path.field("byLanguage"));
    } else {
        for (i, (x, y)) in a.by_language.iter().zip(&want.by_language).enumerate() {
            compare_metrics(
                &x.metrics,
                &y.metrics,
                &path.field("byLanguage").index(i).field("metrics"),
                c,
            );
        }
    }
    if a.by_control_class.len() != want.by_control_class.len()
        || a.by_control_class
            .iter()
            .zip(&want.by_control_class)
            .any(|(x, y)| x.control_class != y.control_class || x.counts != y.counts)
    {
        c.push(ReasonCode::CountMismatch, &path.field("byControlClass"));
    } else {
        for (i, (x, y)) in a
            .by_control_class
            .iter()
            .zip(&want.by_control_class)
            .enumerate()
        {
            compare_metrics(
                &x.metrics,
                &y.metrics,
                &path.field("byControlClass").index(i).field("metrics"),
                c,
            );
        }
    }
    if a.mode != want.mode {
        c.push(ReasonCode::ProjectionInvalid, &path.field("mode"));
    }
}
