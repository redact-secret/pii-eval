//! `private-custodian.aggregates/1` (Decided shape: A11), built from the kernel's
//! accounting. Delivery and labels are adapters (Q2, Q3: Proposed).
//!
//! Cells: the overall stratum times each metric the label adapter publishes
//! (the proposal is all ten `pii-v1` metrics; which metrics a stratum may
//! carry is the disclosure policy's, Q3, so an adapter returning `None` for a
//! metric leaves it out). A cell's
//! `numerator` and `denominator` are the metric's `counts.numerator` and
//! `counts.measured` from the run artifact's `scannerMetrics`, the output of the
//! kernel's accounting that the writer verified before the artifact was
//! committed. This module computes nothing: it copies two integers per metric.
//!
//! Known tension (docs/worker-job.md): the unit of `measurable-share` is the axis
//! assertion, two per case on the synthetic population, so its denominator can
//! exceed a roster counted in entries (one entry is one case). The launcher
//! refuses such a document; it never lowers a denominator.
//!
//! Refusals, never clamps: a denominator above the roster's `observed` is
//! `aggregates-roster-violation` (the custodian would reject the document as
//! inconsistent); more than 256 cells or more than 64 KiB is
//! `aggregates-too-large`; a label outside the custodian's label pattern is
//! `aggregate-label-invalid`.

use std::collections::BTreeSet;

use pii_eval_contracts::MetricResult;
use serde_json::{Value, json};

use crate::status::Failure;
use crate::worker::contract::AggregateLabelsAdapter;
use crate::worker::job::{DOMAIN, Roster, is_label, protocol_value};
use crate::worker::reason;

/// `schema` of the aggregates document.
pub const AGGREGATES_SCHEMA: &str = "private-custodian.aggregates/1";
/// Most cells (A11).
pub const MAX_CELLS: usize = 256;
/// Largest document (A11).
pub const MAX_AGGREGATES_BYTES: usize = 64 * 1024;

/// Build the document for a roster and the metric results of the scanner.
pub fn build(
    roster: &Roster,
    metrics: &[MetricResult],
    labels: &dyn AggregateLabelsAdapter,
) -> Result<Vec<u8>, Failure> {
    let stratum = labels.overall_stratum();
    if !is_label(stratum) {
        return Err(reason::output(reason::AGGREGATE_LABEL_INVALID, "stratum"));
    }
    if metrics.len() > MAX_CELLS {
        return Err(reason::output(reason::AGGREGATES_TOO_LARGE, "cells"));
    }
    let mut seen = BTreeSet::new();
    let mut cells: Vec<Value> = Vec::with_capacity(metrics.len());
    for m in metrics {
        // `None`: the policy does not publish this metric.
        let Some(label) = labels.metric(m.metric.id.as_str()) else {
            continue;
        };
        if !is_label(&label) {
            return Err(reason::output(reason::AGGREGATE_LABEL_INVALID, "metric"));
        }
        let (numerator, denominator) = (m.counts.numerator, m.counts.measured);
        if numerator > denominator || denominator > roster.observed {
            return Err(reason::output(reason::AGGREGATES_ROSTER_VIOLATION, ""));
        }
        if !seen.insert(label.clone()) {
            return Err(reason::output(reason::AGGREGATE_LABEL_INVALID, "metric"));
        }
        cells.push(json!({
            "stratum": stratum,
            "metric": label,
            "numerator": numerator,
            "denominator": denominator,
        }));
    }
    if cells.is_empty() {
        return Err(reason::output(reason::AGGREGATE_LABEL_INVALID, "no-cells"));
    }
    let bytes = json!({
        "schema": AGGREGATES_SCHEMA,
        "domain": DOMAIN,
        "protocol": protocol_value(),
        "roster": roster.to_value(),
        "cells": cells,
    })
    .to_string()
    .into_bytes();
    if bytes.len() > MAX_AGGREGATES_BYTES {
        return Err(reason::output(reason::AGGREGATES_TOO_LARGE, "bytes"));
    }
    Ok(bytes)
}
