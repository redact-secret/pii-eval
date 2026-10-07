# ADR 0017: The authored not-established type identity and schema 1.3

- Status: accepted (issue #32; coordinates redact-secret-benchmarks #664/#665/#666); subject to review.
- Date: 2026-10-06
- Related: [ADR 0002](0002-freeze-pii-contracts-v1.md) (change rules),
  [ADR 0005](0005-indexed-accounting-and-metric-statistics.md) (accounting),
  [ADR 0008](0008-protocol-revision-2-and-schema-1-1.md),
  [ADR 0016](0016-product-projection-and-schema-1-2.md),
  [docs/migration/benchmarks-handoff-32.md](../migration/benchmarks-handoff-32.md).
  Implementation: `crates/pii-eval-contracts/src/{axes,corpus,artifact,version,reason}.rs`,
  `crates/pii-eval-kernel/src/{matching,accounting}.rs`,
  `crates/pii-eval-kernel/src/methods/generate.rs`.

## Context

Schema 1.2 states an authored type identity as `valid` or `invalid` only. The benchmarks'
four-population dual run carried 1,032 of 1,188 case memberships; 156 have an authored
identity of `not-established` and were left to the benchmarks' own scorer, so the
migration is `accepted-representable-cases`, not complete. The sensitivity axis already
had the pattern: the authored `not-established` sensitivity is observed as `unresolved`
(review-required), never as a pass or a fail. The type axis had none.

## Decisions

### 1. The authored value and its only observation

`ExpectedType` gains `not-established`; `TypeState` gains `unresolved`
(status `review-required`). The reachable observations of an authored
`not-established` identity are exactly `unresolved` and `not-measured`; `unresolved`
is unreachable from `valid` and `invalid`. A scanner's finding, family or silence
never turns the identity into a pass or a fail: no ground truth is fabricated, and the
authored value is never rewritten to match a scanner (repository rule). The matching
rule returns `unresolved` for such an occurrence unless the scanner did not complete or
the family or jurisdiction capability is unsupported (then `not-measured`, as for
every other identity).

### 2. Independent axes

Type identity, sensitivity context and range stay independent. An occurrence authored
`not-established` keeps its authored sensitivity (so its sensitive-miss or
non-sensitive-flag outcome is judged as before) and its range is assessed against the
authored candidate range. No axis is inferred from another.

### 3. Eligibility of every metric (hand-checked in tests)

| Metric | Effect of an authored `not-established` identity |
| --- | --- |
| `type-miss-rate`, `wrong-family-rate`, `wrong-jurisdiction-rate`, `range-collateral-rate` | The occurrence is outside the population (valid-type occurrences only): no numerator, denominator, effective N or interval changes. The sample counts as not-applicable, as an invalid-type occurrence already does. |
| `sensitive-miss-rate`, `non-sensitive-flag-rate`, `context-discrimination-rate`, `benign-suppression-rate` | Unchanged: they judge the sensitivity axis (or the context trio's sensitivity endpoints), which is independent of this identity. |
| `jurisdiction-collision-rate` | A case with an `unresolved` type row is `unresolved` (precedence: review-required, then not-measured, then the event), not a pass and not a fail; it adds to `unresolved`, not to effective N. |
| `measurable-share` | The type axis of that case is `unresolved` (a second axis per case, as the sensitivity axis already is), so it is not counted as measurable. |

Wilson arithmetic, rounding, withheld reasons and thresholds are unchanged; no
threshold, support status or product verdict enters the engine. The accounting and
matching protocol revision numbers stay 2: for every population that does not author the
value the results are byte-identical, and the value is an additive extension
whose use is gated by the schema version (below).

### 4. Method generation never invents an identity

A validator or reference observation of a `not-established` case is recorded as evidence
but neither confirms nor contradicts it (no `validator-expectation-mismatch`, no
`reference-disagrees` review). A mutation of a `not-established` case stays
`not-established`: the operator invalidates a valid value, and nothing says the source
was valid. The compatibility interpreter (protocol revision 1, the oracle's contract is
closed over valid/invalid) maps the value to `unresolved` and does not shape the canonical
model.

### 5. Schema 1.3, additive and gated

`SCHEMA_MINOR` becomes 3 (`SchemaVersion::V1_3`); `SchemaVersion::CURRENT` stays 1.1.
A corpus snapshot is sealed under 1.3 only when it authors the value; a run or public
artifact only when an outcome is `unresolved` on the type axis. A snapshot that authors
the value, or an artifact with such an outcome, under an older schema is refused with
the new reason code `identity-not-established-gate`. Every valid 1.0, 1.1 and 1.2
document keeps its bytes and digest (the committed fixtures and goldens are unchanged;
the five JSON Schemas and the reason catalog change by the `$id`, the new enum values and
the new reason code, as the drift test regenerates them). 1.3 is a superset of 1.2: the
product projection is valid under it. The `$id` of every schema moves to 1.3.

### 6. Consumer handoff

[docs/migration/benchmarks-handoff-32.md](../migration/benchmarks-handoff-32.md) states the
exact authoring, pins and re-run steps. Upstream completion does not close the benchmarks
acceptance; the benchmarks re-run all four populations and decide their own scorer and
thresholds.

## Amendment (ADR 0018)

Section 6 and the benchmarks handoff said the 156 memberships were carried by 1.3. They
were not: the benchmarks author them with no candidate range either, which 1.3 still
required. [ADR 0018](0018-not-established-range-and-schema-1-4.md) adds the authored
not-established range (schema 1.4). The identity decisions here are unchanged.

## Consequences

- A reader older than 1.3 refuses a 1.3 document by `schema-minor-too-new`; it cannot
  misread an uncertain identity as valid or invalid.
- `unresolved` is a `review-required` status: it is never a failure and never a success.
- The worker-entry format carries the value unchanged (it is the contracts' `Case`).
