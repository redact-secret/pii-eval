//! The two population views of the oracle: `diagnostic-balanced` and
//! `benign-heavy-stress`.
//!
//! A view is an authored *membership* of cases: which authored cases belong to
//! the development-only diagnostic population and which to the evaluation-only
//! benign-dominant stress population. The kernel preserves the two views
//! separately. It never merges them, never weights them and never publishes a
//! combined score; declared base-rate mass, thresholds and verdicts are product
//! policy and stay downstream (oracle `docs/specs/pii-populations.md`).
//!
//! A view is applied by restricting the snapshot body to the view's cases and
//! accounting that restriction on its own (`AuthoredIndex::new` and `account`).

use std::collections::{BTreeMap, BTreeSet};

use pii_eval_contracts::{CorpusSnapshotBody, Id, SensitivityExpectation};

/// A population view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PopulationView {
    /// Development-only tuning population; present evidence classes get equal
    /// mass downstream.
    DiagnosticBalanced,
    /// Evaluation-only population in which non-sensitive occurrences outnumber
    /// sensitive ones.
    BenignHeavyStress,
}

impl PopulationView {
    /// Both views, in wire order.
    pub const ALL: [PopulationView; 2] = [
        PopulationView::DiagnosticBalanced,
        PopulationView::BenignHeavyStress,
    ];

    /// The oracle's wire string.
    pub const fn as_str(self) -> &'static str {
        match self {
            PopulationView::DiagnosticBalanced => "diagnostic-balanced",
            PopulationView::BenignHeavyStress => "benign-heavy-stress",
        }
    }
}

/// One authored view assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewAssignment {
    /// Authored case.
    pub case_id: Id,
    /// Its view.
    pub view: PopulationView,
}

/// Why a roster was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewError {
    /// A case is assigned to a view twice.
    DuplicateAssignment,
    /// An assignment names a case the snapshot does not contain.
    UnknownCase,
    /// A snapshot case has no assignment: every case belongs to exactly one view.
    UnassignedCase,
}

/// A complete, exclusive assignment of a snapshot's cases to the two views.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewRoster {
    map: BTreeMap<Id, PopulationView>,
}

impl ViewRoster {
    /// Check that `assignments` put every case of `body` in exactly one view.
    pub fn new(
        body: &CorpusSnapshotBody,
        assignments: &[ViewAssignment],
    ) -> Result<Self, ViewError> {
        let known: BTreeSet<&Id> = body.cases.iter().map(|c| &c.case_id).collect();
        let mut map = BTreeMap::new();
        for a in assignments {
            if !known.contains(&a.case_id) {
                return Err(ViewError::UnknownCase);
            }
            if map.insert(a.case_id.clone(), a.view).is_some() {
                return Err(ViewError::DuplicateAssignment);
            }
        }
        if map.len() != known.len() {
            return Err(ViewError::UnassignedCase);
        }
        Ok(Self { map })
    }

    /// The view of `case`.
    pub fn view_of(&self, case: &Id) -> Option<PopulationView> {
        self.map.get(case).copied()
    }

    /// The snapshot body restricted to the cases of `view`, in the original
    /// order. The population identity is unchanged; the restriction is a view
    /// of the same population, accounted on its own and never added to the
    /// other view.
    pub fn restrict(&self, body: &CorpusSnapshotBody, view: PopulationView) -> CorpusSnapshotBody {
        CorpusSnapshotBody {
            population: body.population.clone(),
            generation: body.generation.clone(),
            cases: body
                .cases
                .iter()
                .filter(|c| self.view_of(&c.case_id) == Some(view))
                .cloned()
                .collect(),
        }
    }

    /// Authored composition of `view`.
    pub fn composition(&self, body: &CorpusSnapshotBody, view: PopulationView) -> ViewComposition {
        let mut out = ViewComposition::default();
        for case in body
            .cases
            .iter()
            .filter(|c| self.view_of(&c.case_id) == Some(view))
        {
            out.cases += 1;
            for variant in &case.variants {
                out.variants += 1;
                for e in &variant.expectations {
                    out.occurrences += 1;
                    match e.sensitivity {
                        SensitivityExpectation::Sensitive => out.sensitive += 1,
                        SensitivityExpectation::NonSensitive => out.non_sensitive += 1,
                        SensitivityExpectation::NotEstablished
                        | SensitivityExpectation::ContextDependent => out.not_established += 1,
                    }
                }
            }
        }
        out
    }
}

/// Authored counts of one view. Observations about the corpus, not a verdict.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ViewComposition {
    /// Authored cases.
    pub cases: u64,
    /// Variants.
    pub variants: u64,
    /// Expected occurrences.
    pub occurrences: u64,
    /// Occurrences authored sensitive.
    pub sensitive: u64,
    /// Occurrences authored non-sensitive.
    pub non_sensitive: u64,
    /// Occurrences whose sensitivity is not established.
    pub not_established: u64,
}

impl ViewComposition {
    /// Whether authored non-sensitive occurrences strictly outnumber sensitive
    /// ones. The stress view is defined as benign-dominant; whether a given
    /// roster must satisfy that is validated by the consumer that owns the
    /// view's policy.
    pub fn benign_dominant(&self) -> bool {
        self.non_sensitive > self.sensitive
    }
}
