//! The review gate, derivable from a sealed snapshot alone.
//!
//! `account` and the matcher judge rows; they do not read a variant's
//! `derivation.strategy`. A variant held for review (`review-required`: its
//! validator or reference was unavailable) must still have an unmeasured type
//! axis, or a replay of a stored snapshot would score a clean pass.
//!
//! **Who must call it.** Whoever turns matcher output into outcome rows (the
//! run and replay paths, P8) must pass every row through [`ReviewGate::apply`]
//! before accounting, or call [`account_gated`], which does so. The gate is
//! built from the snapshot body alone ([`ReviewGate::from_body`]), so a
//! generation run and a later replay of the sealed snapshot gate identically.
//! `account` itself is unchanged and stays strategy-agnostic.

use std::collections::BTreeSet;

use pii_eval_contracts::axes::OutcomeRow;
use pii_eval_contracts::{CorpusSnapshotBody, Mechanics, Strategy};

use super::apply_review_strategy;
use crate::{AccountError, Accounting, AuthoredIndex, OutcomeRef, ScannerInput, account};

/// The variants of a snapshot that are held for review.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReviewGate {
    held: BTreeSet<String>,
}

impl ReviewGate {
    /// Collect the `review-required` variants of `body`.
    pub fn from_body(body: &CorpusSnapshotBody) -> Self {
        Self {
            held: body
                .cases
                .iter()
                .flat_map(|c| &c.variants)
                .filter(|v| v.derivation.strategy == Strategy::ReviewRequired)
                .map(|v| v.variant_id.as_str().to_owned())
                .collect(),
        }
    }

    /// Whether `variant_id` is held for review.
    pub fn is_held(&self, variant_id: &str) -> bool {
        self.held.contains(variant_id)
    }

    /// Number of held variants.
    pub fn held_count(&self) -> usize {
        self.held.len()
    }

    /// Gate one row of `variant_id`.
    pub fn apply(&self, variant_id: &str, row: OutcomeRow) -> OutcomeRow {
        if self.is_held(variant_id) {
            apply_review_strategy(row, Strategy::ReviewRequired)
        } else {
            row
        }
    }
}

/// `account` with every row gated by the snapshot's review states. Equivalent
/// to mapping the rows through [`ReviewGate::apply`] and calling `account`.
pub fn account_gated<'r, I>(
    body: &CorpusSnapshotBody,
    authored: &AuthoredIndex<'_>,
    scanners: &[ScannerInput<'_>],
    rows: I,
    mechanics: &Mechanics,
) -> Result<Accounting, AccountError>
where
    I: IntoIterator<Item = OutcomeRef<'r>>,
{
    let gate = ReviewGate::from_body(body);
    account(
        authored,
        scanners,
        rows.into_iter().map(|mut r| {
            r.row = gate.apply(r.variant_id, r.row);
            r
        }),
        mechanics,
    )
}
