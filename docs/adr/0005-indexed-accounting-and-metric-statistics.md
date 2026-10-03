# ADR 0005: Indexed accounting and versioned metric statistics

- Status: accepted for P4 (issue #5); subject to review.
- Date: 2026-10-02
- Related: [ADR 0001](0001-rust-first-and-oracle-pin.md),
  [ADR 0002](0002-freeze-pii-contracts-v1.md),
  [ADR 0003](0003-canonical-serialization-and-semantic-digest.md),
  [ADR 0004](0004-order-invariant-pii-matching.md),
  [ownership map](../migration/ownership-map.md), epic #1. Implementation:
  `crates/pii-eval-kernel/src/{accounting,stats,verify,bigint}.rs`. Oracle:
  `benchmarks/evaluation/domains/pii/accounting.ts` and
  `benchmarks/accounting/shared/primitives.ts` at
  `4b846967346505baca11e0b98cab1475fbce6773`.

## Context

The contracts (ADR 0002) freeze the ten metric definitions, the mechanics
(`minDenominator`, `intervalZ`, `intervalPrecision`) and the artifact shape, and
deliberately carry no arithmetic. ADR 0002 deferred two things to P4: metric
values against counts, and counts against outcome rows. ADR 0004 left open who
bumps the protocol revision and which count `ObservedSummary.finding_count` is.
The oracle computes accounting in one TypeScript function over a flat row list
and rounds binary64 values with `toFixed`. This ADR fixes the accounting rule,
the statistics, the verifier, and the two open items, and classifies every
difference from the oracle.

## 1. Identities

| Item | Identifier | Revision | State |
| --- | --- | --- | --- |
| Accounting rule | `pii-v1-canonical-accounting` (`ACCOUNTING_RULE_ID`) | proposed protocol revision 2 (`ACCOUNTING_PROTOCOL_REVISION`) | implemented in the kernel; not bindable in a document yet (section 9) |
| Statistics rule (point, Wilson endpoint, rounding) | `pii-v1-wilson-exact` (`STATS_RULE_ID`) | 1 (`STATS_REVISION`) | implemented |
| Matching rule | `pii-v1-canonical` | proposed protocol revision 2 | ADR 0004 |
| Legacy accounting | oracle `pii-v1` / `pii-observation-v1` | protocol revision 1 | reproduced only as classified expectations in `pii-eval-compat` tests |

The accounting and statistics rules are part of protocol identity: a change to a
bucket rule, eligibility, grouping, interval, rounding or failure
interpretation is a protocol revision with a difference report, never a
refactor (ADR 0002).

## 2. Sample model

- **Group.** A *group* is one scanner's rows for one authored case (a case has
  exactly one method, so this is the oracle's `runId/scanner/caseId/method`
  group). All variants and all expected occurrences of the case are rows of the
  one group.
- **Sample.** Each metric counts *samples* (the registry's `sampleUnit`): one
  group (`authored-case-method`), one complete context trio
  (`context-trio`, `context-discrimination-rate`), or one axis assertion
  (`axis-assertion`, `measurable-share`: two per group, one on the type axis and
  one on the sensitivity axis). `MetricCounts` therefore counts samples, not
  outcome rows; the contract documentation now says so.
- **Variants and replays.** Variants of a case are rows inside one sample; they
  never add samples. A replay is a stability check, not a row: accounting takes
  exactly one result per scanner and occurrence, a second row for the same
  occurrence is `DuplicateRow` (or exceeds the bounded matrix), and an unstable
  scanner (replays disagreed) has every row unmeasured, so it contributes no
  measured sample.
- **Separate counts.** The kernel returns authored cases, variants and
  occurrences (`Accounting::authored`, per stratum `StratumAccounting::authored`),
  the eligible cases, variants and occurrences behind each metric
  (`SampleBasis`), and the effective N (`MetricAccount::effective_n`) as separate
  fields. `SampleBasis::correlated_variants` is true when an eligible case has
  more than one variant, and `shared_case_axes` is true for `measurable-share`.
- **Effective N** follows the registry: measured samples for nine metrics,
  eligible samples for `measurable-share`.

## 3. Metric semantics

A group's outcome per metric is a bucket: numerator, other (measured, not in the
numerator), unresolved, not-measured, or not-applicable. A bucket is chosen from
the group's rows in the oracle's order (`groupBucket`): any review-required row
gives *unresolved*, else any not-measured row gives *not-measured*, else the
event gives *numerator*, else *other*. Counts follow the oracle exactly:
`eligible` is every bucket but not-applicable, `measured` is numerator plus
other, `total` is eligible plus not-applicable. `MetricStatus` is the contract's
`derived_status` of the counts (not-applicable, unresolved, not-measured,
partial, measured).

| Metric | Group population (else not-applicable) | Rows judged | Event (numerator) |
| --- | --- | --- | --- |
| `type-miss-rate` | the group has a valid-type occurrence | valid-type occurrences, type axis | type `miss` |
| `wrong-family-rate` | same | same | type `wrong-family` |
| `wrong-jurisdiction-rate` | valid-type occurrence and the case has a jurisdiction | valid-type occurrences, type axis | type `wrong-jurisdiction` |
| `sensitive-miss-rate` | an authored-sensitive occurrence | authored-sensitive occurrences, sensitivity axis | sensitivity `miss` |
| `non-sensitive-flag-rate` | an authored-non-sensitive occurrence | authored-non-sensitive occurrences | sensitivity `false-positive` |
| `context-discrimination-rate` | method `context-discrimination` (other cases are outside the population and not counted); the trio must be complete | the non-neutral frames (endpoints), sensitivity axis | every endpoint passes |
| `benign-suppression-rate` | method `pii-benign` | all rows, sensitivity axis | any sensitivity `pass` |
| `jurisdiction-collision-rate` | method `jurisdiction-collision` | all rows, type axis | any type `pass` |
| `range-collateral-rate` | a valid-type occurrence whose range is not `miss` | valid-type occurrences, range axis | `overbroad` or `partial`; a `not-applicable` range makes the group not-measured |
| `measurable-share` | every group (two assertions each) | type axis; sensitivity axis (unresolved if any occurrence is authored `not-established`) | resolved (pass or fail) |

Review-required cannot occur on the type axis (`TypeState::status` never yields
it), which the flag code relies on and a test pins. A trio is complete when the
snapshot holds exactly one sensitive, one neutral and one non-sensitive frame
(contract rule `incomplete-context-trio`); an incomplete trio found by the kernel
is `SnapshotDefect::IncompleteContextTrio`, an error, never partial scoring.
A variant whose expectations disagree on the context class (rejected by the
contracts as `context-class-conflict`) is `SnapshotDefect::ContextClassConflict`.
`not-measured` rows (missing family or jurisdiction capability, a scanner that
did not complete) are never successes: they land in the not-measured bucket.
Range-collateral accounting is group-level, as in the oracle and the registry
(`sampleUnit: authored-case-method`); the per-finding reported spans of ADR 0004
section 3.4 are not an input to `pii-v1` accounting (a span-level collateral
rate would be a new metric version).

## 4. Statuses and failures

The contract's `MetricStatus` separates *unresolved* (authored `not-established`
or review-required, not a failure), *not-measured* (eligible but no measured
sample) and *not-applicable* (no eligible sample). A withheld value separates
`zero-denominator` (the oracle's `null`) from `insufficient-evidence`
(`effectiveN < minDenominator`). *Unstable* and *execution failure* are scanner
states, not metric states: `ScannerAccounting::status` carries the scanner
status, and `MetricAccount::not_measured_cause` is `ScannerUnstable`,
`ExecutionFailure`, `ScannerUnsupported`, `ScannerUnavailable` or (a complete
scanner that did not report the axis) `AxisNotReported`. An unstable scanner is
therefore visible as unstable even though its metrics read not-measured.

## 5. Statistics: exact integer arithmetic

Contracts forbid floats, so published point and bound are `ScaledDecimal`s. The
kernel uses **no floating point**. Alternatives considered:

- *binary64 with the oracle's formula.* IEEE-754 `+ - * /` and `sqrt` are
  correctly rounded, so the Wilson value would be reproducible across IEEE
  hosts. But decimal rounding of a binary64 value (`toFixed`) is not the
  rounding of the real number: exact ties such as 3/20 at one place are stored
  on one side or the other, so the result depends on the binary representation,
  and expected values cannot be hand-checked as decimals.
- *Exact arithmetic (chosen).* With `p = k/n`, `z = zm/10^zs`, the endpoint
  `(2k + z^2 +- z*sqrt(z^2 + 4k(n-k)/n)) / (2(n + z^2))` is an exact rational
  plus one square root. It is evaluated by scaling to integers
  (`bound = (A n +- sqrt(Q n)) / (D n)` with `A = 2k Z^2 + zm^2`,
  `D = 2(n Z^2 + zm^2)`, `Q = zm^2 (zm^2 n + 4k(n-k) Z^2)`, `Z = 10^zs`) and
  rounded half up to `precision` places by integer square root and integer
  division in a private 512-bit unsigned integer (`bigint.rs`). Every operation
  is checked; the largest intermediate for any in-contract input (counts up to
  2^53 - 1, `z` up to a 2^53 - 1 mantissa at scale 12, 12 places) is below
  10^129 against a capacity near 10^154, so `StatsError::Overflow` is
  unreachable in contract and typed if it is reached.

**Rounding.** Point and bound are rounded **once**, half up, from the exact
value to `mechanics.interval_precision` places (1 to 12) and then normalized
(`ScaledDecimal::new`). The bound is clamped to `[0, 1]` as the oracle does
(mathematically it never leaves it). The unrounded sufficient counts
(`numerator`, `effective_n`, `z`, precision) are retained in the result, so a
consumer can recompute under another declared precision.

**States.** `effective_n == 0` withholds as `zero-denominator`;
`0 < effective_n < min_denominator` withholds as `insufficient-evidence`;
`numerator > effective_n` is `StatsError::InvalidCounts`, never clamped. Which
endpoint is reported follows the registry direction (`upper` or `lower`).

**Independent vectors.** `crates/pii-eval-kernel/tests/vectors/wilson_reference.py`
evaluates the textbook formula in Python `decimal` at 120 digits (correctly
rounded `sqrt`), rounded once half up. It shares no code or algebra with the
kernel. 38 vectors cover zero samples (`n = 1`, the zero-denominator path is
tested separately), zero failures, all failures, tiny strata, ties, other `z`
and precisions, 10^9, 10^12 and 2^53 - 1 counts; the table is committed as
`tests/vectors/wilson_vectors.rs` (the script is not run in CI). The same
vectors were also run through the oracle's own `proportion()` under Node 22.16:
all 31 comparable vectors agree except the exact tie 3/20 at one place
(difference S1 below).

**Interpretation.** The interval treats each effective-N sample as an
independent trial. Authored cases are not a random draw from real-world data,
the corpus is synthetic, and variants and the two axes of one case are
correlated. `INTERVAL_INTERPRETATION` states this and `SampleBasis` carries the
facts a reader needs (cases, variants, occurrences, `correlated_variants`,
`shared_case_axes`). No confidence claim beyond sampling arithmetic conditional
on the corpus design is made; thresholds and stable/provisional decisions stay
downstream.

## 6. Strata and aggregation

Accounting is always per scanner: scanners are never pooled, and the population
is never merged with another (the manifest binds one population digest). For
each scanner the kernel returns the overall population and strata by case
language, by case jurisdiction (global first) and by method. "View" is read as
the population's visibility class (public-synthetic or protected), which is a
property of the whole run and is recorded by the artifact's population binding,
not a stratum. Strata partition the cases, so the counts of the strata of one
dimension add up to the overall counts for every metric (a conservation property
tested on random populations); each stratum has its own effective N and
interval, and no interval is derived from another. Strata are bounded at 1024
values per dimension (`MAX_STRATA_PER_DIMENSION`).

## 7. Indexed, bounded execution

`AuthoredIndex::new` interns the snapshot once into dense case and occurrence
tables, an ordered variant map and sorted language and jurisdiction lists.
`account` then makes **one pass over the rows**: each row is located by scanner
(binary search), variant (ordered map) and occurrence (binary search), checked,
marked in a duplicate bitset, and OR-folded into one 32-bit flag word of its
(scanner, case) group. One pass over the groups derives all ten metrics from the
flag word and adds the group to four tallies (overall, language, jurisdiction,
method). No metric rescans the rows; flags are OR-accumulated so row order,
scanner order and scheduling cannot change the result (tested by shuffles and a
differential test against a naive per-metric reference).

| Limit | Value | Source |
| --- | --- | --- |
| cases | 1,000,000 | contracts `MAX_CASES` |
| scanner-by-occurrence rows | 16,000,000 | contracts `MAX_OUTCOMES` |
| scanners | 32 | contracts `MAX_SCANNERS` |
| languages, jurisdictions | 1024 each | `MAX_STRATA_PER_DIMENSION` |

State is 4 bytes per group, 1 bit per (scanner, occurrence), 8 bytes per
scanner, and 640 bytes per metric tally set per stratum and scanner: at most
about 108 MB at the limits (asserted in `tests/accounting_complexity.rs`).
Counters are checked `u64` increments (`CounterOverflow`). Untrusted rows cannot
panic: every defect is a typed `AccountError` with numeric payload (unknown
scanner or occurrence, case or method mismatch, duplicate row, unreachable
state or a measured axis from a scanner that did not complete, missing rows,
limits, invalid mechanics, snapshot defects). A **missing row is an error**
(`MissingRows`), not an implicit not-measured: a scanner that did not run must
report explicit not-measured rows, which keeps measurement gaps visible. A
partial artifact therefore cannot be accounted until P7 records the gap as
rows.

Complexity method (`tests/accounting_complexity.rs`): the pass reports
`rows_visited`, `group_visits` and `state_bytes` (an element-count model of its
own allocations, not RSS). On 1000, 2000 and 4000 cases with 1 and 3 scanners,
rows read equal scanners x occurrences, groups visited equal scanners x cases,
and doubling the population doubles both and grows state by the group and row
terms only. No wall-clock or speed claim is made.

## 8. The deferred P2 verification

**Decision: the verifier lives in the kernel** (`verify` module:
`verify_metric_result`, `verify_run_artifact_accounting`,
`verify_public_artifact_accounting`), not in the contracts crate.

- It needs the Wilson arithmetic and the accounting rule, which are protocol
  semantics that ADR 0002 kept out of the contracts, and the contracts crate has
  no dependency on the kernel. Adding them there would also have meant
  a schema, fixture and digest change for what is a recomputation, not a shape.
- It checks, with the contracts' reason codes and no new code
  (`metric-definition-mismatch`, `metric-counts-inconsistent`, `count-mismatch`,
  `metric-value-inconsistent`): frozen metric version; count identities and
  derived status; effective-N basis; that the artifact lists exactly the
  registry's ten metrics, each once (an omitted metric cannot hide a bad one;
  `metric-definition-mismatch`; manifests that plan fewer metrics are not
  verifiable until P7 passes the plan in); the published point and bound recomputed
  from `numerator` and `effective_n` (equality of integer mantissa and scale, so
  an off-by-one digit is caught; tested to pass `pii_eval_contracts::validate`
  and fail the verifier); and every counted field against the accounting of the
  outcome rows and the snapshot (after `validate_artifact_against_snapshot`).
- **Cost of the choice**: `pii_eval_contracts::validate` alone does not prove
  metric values or counts. Every consumer that accepts an artifact must also call
  the verifier: P7 after writing an artifact, and P8 `validate` and `replay`.
- **Limit of schema 1.0**: an artifact holds one `metrics` list, with no scanner
  key, so with several scanners the metrics belong to no scanner. The verifier
  returns `VerifyFailure::MetricScopeAmbiguous` for such an artifact instead of
  inventing a pooled reading (pooling scanners would repeat the same occurrences
  as if independent). The committed P2 fixture has two scanners and
  placeholder metrics; a test shows both facts. Per-scanner metrics are a
  requirement of the revision in section 9.

## 9. Protocol revision ownership: P7

The canonical rules (matching, ADR 0004; accounting and statistics, this ADR;
the P5 method changes, if any) form protocol revision 2. **P7 owns the bump**,
because the bump is observable only when something writes a document, P7 is the
first emitter, and one revision covering matching, accounting and methods
regenerates schemas, fixtures and digests once while P5 and P6 still work
against revision-1 fixtures. P4 therefore changes no bound meaning: contracts
still bind `pii-v1` revision 1, the committed schemas change only in
description text (section 10), and no digest changes.

Until that change merges, no phase may emit an artifact with the canonical
rules, and `verify_*` implements revision 2 accounting without checking the
artifact's revision (checking would reject every revision-1 document, including
the fixture). **P7 must, in one change:**

1. Bump `PROTOCOL_VERSION` to 2 (or accept a declared set), keeping revision-1
   documents readable under their own digest domain, and decide whether a
   revision-1 artifact can be verified (it cannot with these rules: the legacy
   accounting differs, section 11) or is only readable.
2. Make `verify_*` require `protocol.version == ACCOUNTING_PROTOCOL_REVISION`.
3. Add the rule identities (`MATCHING_RULE_ID`, `ACCOUNTING_RULE_ID`,
   `STATS_RULE_ID` with revisions) to the registry JSON and protocol identity so
   an artifact states which rules produced it.
4. Key metrics by scanner (and strata where published) so a multi-scanner
   artifact has attributable metrics, and add the per-metric `SampleBasis`
   counts (eligible cases, variants, occurrences) next to effective N.
5. Regenerate schemas, registry, fixtures and digests (the update commands in
   CONVENTIONS.md), replace the placeholder metrics of the P2 fixture by the
   accounting of its rows, add negative fixtures per ADR 0002, and write the
   migration note and difference report (section 11 is the accounting part).
6. Keep legacy revision-1 meaning untouched: legacy first-overlap and legacy
   accounting stay a named compatibility mode in `pii-eval-compat`.

## 10. `ObservedSummary.finding_count`: per occurrence

The field counts the findings that overlap **the occurrence** (its candidates,
duplicates counted), and `families` and `jurisdictions` are those of the same
findings. This is what the matcher (ADR 0004 section 3.4) and the legacy rule
produce and what the oracle's `observed.findingCount` counted for its single
candidate per variant. The old contract text, "findings the scanner reported for
the variant", was wrong for variants with several occurrences or findings that
overlap none. A per-variant count would need a new optional field (an additive
minor change, ADR 0002); none is added because nothing consumes it. Only the
documentation changed: the committed schemas were regenerated (description text
only; no field, type, reason code or digest changed) and the `MetricCounts`
fields now say "samples" instead of "rows".

## 11. Compatibility with the oracle

Executable evidence: `crates/pii-eval-compat/tests/accounting_oracle.rs`.
Expected counts for its fixtures were derived by hand from `accounting.ts`
(`buildAccounting`, `metricBuckets`, `groupBucket`); rate values come from
running the oracle's own `proportion()` (Node 22.16, type stripping) on the same
counts. Equal: group buckets and the five count fields, effective N and its
basis, statuses, `null` / `insufficient-evidence` as the two withheld reasons,
and point and bound at default precision.

| Id | Difference | Class |
| --- | --- | --- |
| S1 | The oracle rounds binary64 with `toFixed`; the canonical rule rounds the exact rational half up. They differ only at exact ties stored on the other side in binary64 (3/20 and 7/20 at one place: oracle 0.1 and 0.3, canonical 0.2 and 0.4). Wilson endpoints are irrational and agree in every comparison made (31 vectors, up to 12 places). | Intentional (exactness, decimal hand-checkability) |
| A2 | Valid-type metrics: the oracle takes eligibility from the first row of the group after a `localeCompare` sort of variant ids (host locale dependent) and judges all variants; the canonical rule makes a case eligible when it has a valid-type occurrence and judges those occurrences. Differs for groups mixing valid and invalid types (a valid-type miss behind an invalid first variant is not-applicable in the oracle; a not-measured invalid variant turns a valid group not-measured in the oracle). Uniform groups agree. Applies to `type-miss-rate`, `wrong-family-rate`, `wrong-jurisdiction-rate`, `range-collateral-rate`. | Intentional (order and locale independence; registry population is "valid-type occurrence") |
| A3 | A benign case with several variants: the oracle throws (`PII benign controls must be distinct authored cases`); the canonical rule keeps one sample. | Intentional (variants are never independent samples; no hidden denominator row) |
| A4 | Several scanners: the oracle throws (`Mixed PII scanner population`); the canonical rule accounts per scanner. | Addition |
| A5 | Context groups: the oracle validates frames against its `piiContextEvidence` roster; the canonical rule relies on snapshot trio completeness and errors on an incomplete trio. Which frames a trio should hold is corpus-author truth. | Contract shape |
| A6 | Bad rows: the oracle validates outcome shape and reasons (`validatePiiOutcome`); the kernel rejects unreachable states and measured axes of non-complete scanners as `OutcomeContradiction`; capability rules stay with `validate_artifact_against_snapshot`. | Equivalent intent, different mechanism |
| A7 | Not carried: `benignByControlClass`, `evidenceByClass`, `contextByLanguage` and `contextRoster` projections, and the `evidence` block (authority, validator, reference counts). Language strata exist for all metrics, which supersedes `contextByLanguage`. | Not carried into schema 1.0 (ADR 0002); P5 and P9 decide |
| A8 | `benign-suppression-rate` and `jurisdiction-collision-rate` count a case as numerator when **any** row passes (oracle `group.some`), while the context metric requires **all** endpoints to pass. Failing example: a benign case with variant A `correct` and variant B `false-positive` counts as suppressed; a collision case with one `correct` and one `wrong-jurisdiction` variant counts as passed. Kept as is (the oracle rule) in revision-2 accounting and pinned by `accounting_oracle.rs::a8_*`. | Known limitation inherited from the oracle. Recommendation: the canonical protocol revision (P7) decides any -> all explicitly, with a difference report; changing it is a protocol revision, not a refactor |
| A9 | `wrong-jurisdiction-rate` population: kernel `case.jurisdiction.is_some()`, oracle `scope.startsWith('jurisdiction:')`. Equivalent: the oracle ties scope to the family scope (`validateRow`) and the contracts tie `case.jurisdiction` to it (`family-scope-mismatch`); tested in `accounting_oracle.rs`. | Equal |

Same-observation replay parity against the TypeScript oracle remains P9.

## 12. Public API for downstream phases

`pii_eval_kernel`: `AuthoredIndex::new`, `account`, `account_outcomes`,
`OutcomeRef`, `ScannerInput`, `Accounting`, `ScannerAccounting`,
`StratumAccounting`, `MetricAccount` (`to_result`), `SampleBasis`,
`UnmeasuredCause`, `ResourceUse`, `AccountError`, `SnapshotDefect`, `Limit`;
`published_value`, `round_ratio`, `wilson_mantissa`, `StatsError`;
`verify_metric_result`, `verify_run_artifact_accounting`,
`verify_public_artifact_accounting`, `VerifyFailure`; constants
`ACCOUNTING_RULE_ID`, `ACCOUNTING_PROTOCOL_REVISION`, `STATS_RULE_ID`,
`STATS_REVISION`, `MAX_STRATA_PER_DIMENSION`, `INTERVAL_INTERPRETATION`. The
crates stay internal: consumers integrate through artifacts and the CLI.

## Consequences

- P5 (methods) produces cases and variants; accounting groups them and does not
  change when methods are added.
- P6 adapters keep producing observations; accounting never reads findings.
- P7 owns the revision bump and the per-scanner metric shape (section 9) and must
  call the verifier; P8 `validate` and `replay` must too.
- P9 parity compares counts and rates with the table in section 11.
- P10 can measure wall time and RSS; this ADR makes no speed claim.
- A scanner with missing rows is not accountable (section 7), which is a
  deliberate fail-closed choice reversible only by a revision.
