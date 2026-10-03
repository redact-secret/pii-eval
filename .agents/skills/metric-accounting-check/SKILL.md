---
name: metric-accounting-check
description: Verify pii-eval's ten metric contracts, checked integer counters, effective-N accounting, and Wilson interval arithmetic against independent vectors. Use when scoring, accounting, grouping, or rounding changes. Test-adding only.
---

# Metric accounting check

Read `ARCHITECTURE.md` (Methods and accounting). Accounting is protocol
semantics: do not change eligibility, grouping, intervals, or withheld
states without an explicit protocol/accounting revision. If the kernel does
not exist yet, say which checks could not run.

## Check

For each of the ten metrics (type-miss-rate, wrong-family-rate,
wrong-jurisdiction-rate, sensitive-miss-rate, non-sensitive-flag-rate,
context-discrimination-rate, benign-suppression-rate,
jurisdiction-collision-rate, range-collateral-rate, measurable-share),
confirm the contract declares unit, eligibility, numerator, denominator,
direction, grouping, interval, and withheld states, and that a hand-built
case reproduces the numerator and denominator.

Cross-check the seven methods (type-validation, context-discrimination,
pii-benign, jurisdiction-collision, mutation, reference-differential,
schema-only) for coverage: which metrics each feeds, and what happens when
a method has no eligible cases.

Counters and counts:

- authored-case count, variant count, and metric effective N are recorded
  separately; derived variants are not independent observations;
- replays are stability checks and never increase N;
- context trios stay complete: an incomplete trio is withheld or counted
  per the declared rule, never partially scored;
- counters are checked integers; test overflow and large counts; unrounded
  sufficient counts are retained and rounding happens only at the defined
  artifact boundary;
- `not-measured` and missing family/jurisdiction capability never count as
  success.

Wilson interval vectors, computed independently of the implementation, must
include zero samples, zero failures, all failures, incomplete strata, and
very large counts, with decimal-rounding behavior frozen. Interval
interpretation is limited by sampling assumptions and synthetic corpus
design; do not add confidence claims beyond that.

Report each metric as `verified`, `mismatch`, or `not assessable`, with the
vector and file/line. Do not add thresholds or stable/provisional decisions:
those are downstream.
