# ADR 0018: The authored not-established range and schema 1.4

- Status: accepted (issue #32; coordinates redact-secret-benchmarks #664/#665/#666/#795/#796); subject to review.
- Date: 2026-10-06
- Related: [ADR 0002](0002-freeze-pii-contracts-v1.md) (change rules),
  [ADR 0005](0005-indexed-accounting-and-metric-statistics.md) (accounting),
  [ADR 0017](0017-not-established-type-identity-and-schema-1-3.md) (the identity),
  [docs/migration/benchmarks-handoff-32.md](../migration/benchmarks-handoff-32.md),
  [docs/migration/populations-32/handoff.json](../migration/populations-32/handoff.json).
  Implementation: `crates/pii-eval-contracts/src/{axes,corpus,artifact,binding,version,reason}.rs`,
  `crates/pii-eval-kernel/src/{matching,accounting}.rs`, `crates/pii-eval-cli/src/assemble.rs`.

## Context

ADR 0017 made an authored `not-established` type identity representable (schema 1.3) and
its handoff said the 156 of 1,188 benchmark population memberships were therefore
carried. Inventorying the memberships against the benchmarks plans (the same
`b11-population-v2` tables the schema 1.2 dual run read) showed that was not so. All 156
(110 distinct cases) are authored with **no candidate range at all**: the plan states
neither an identity, nor a sensitivity, nor where the occurrence is (98 cases such as a
version-prefixed address that may or may not contain one; 12 cases whose generated
structure has a built span but whose authors set no candidate). The 1.3 contract still
requires an `Expectation.range`, so none of them could be stated. Dropping them,
inventing a range, or coercing them to valid/invalid would silently change the authored
population, and treating their absence as success would hide them. The range axis needs
the same explicit uncertain state the identity axis got.

Distinct states, kept distinct: authored uncertainty (this ADR and ADR 0017); malformed
input (`range-invalid`, `range-out-of-bounds`, refused at validation); scanner failure
(`failed`, every axis `not-measured`); unsupported capability (`not-measured`); an
unmeasured observation (`not-measured`).

## Decisions

### 1. The authored value and its only observation

`Expectation.range` becomes optional. An absent `range` is the authored
**not-established range**: the authors did not establish where the occurrence is. The
wire form omits the key (a `null` is refused: the strict parser has no such field value).
`RangeState` gains `unresolved`, the only observation of such an occurrence. It is
unreachable for an occurrence with a range, and a located occurrence is never
`unresolved`; both directions are checked by the outcome lattice
(`AuthoredAxes.range_established`).

### 2. Axes, and why the absent range constrains the others

The four axes stay separate fields and separate observations. Validation adds one rule
about what may be authored together (`range-not-established-invalid`): an expectation
without a range must author type identity `not-established` and sensitivity
`not-established`, and its case must be `schema-only`. Reason: an identity or a sensitivity
judgment is a judgment about a located value; with nothing located a scanner finding cannot
be attributed to the occurrence, so any pass or fail on those axes would be fabricated. The
mutation, frame, collision and reference methods all need a span to operate on. Nothing is
inferred across axes: a range-less occurrence observes `unresolved` on identity and
sensitivity because they are authored `not-established` (ADR 0017 and the existing
sensitivity rule), not because the range is absent; a missing capability still yields
`not-measured` on those two axes.

The observed row of a range-less occurrence with a complete scanner is
`(type unresolved, sensitivity unresolved, range unresolved, action not-measured)`.
The action axis has no located occurrence to judge, so it is `not-measured`, never
`no-action-reported`. A scanner that did not complete or cannot report ranges measured
nothing: the row is entirely `not-measured` / `not-applicable`, as for every occurrence.

### 3. Findings in a range-less variant

The matching rule selects no primary and no candidate for such an occurrence, whatever the
scanner reported: findings in the text are not read as evidence about it, and are still
accounted for, one per finding, as spans that match no occurrence (`reported[].matched =
null`). The engine does not decide whether they are right or wrong; the sensitivity of
those findings is the benchmarks' scorer decision (#795).

### 4. Eligibility of every metric (hand-checked in tests)

Because the identity is `not-established` (ADR 0017 table) and the sensitivity is
`not-established` (existing rule), a range-less occurrence is outside every numerator,
denominator, effective N and interval of `type-miss-rate`, `wrong-family-rate`,
`wrong-jurisdiction-rate`, `range-collateral-rate`, `sensitive-miss-rate` and
`non-sensitive-flag-rate`, and adds to `unresolved` in `measurable-share` on both axes
(two samples per case, none measured). `jurisdiction-collision-rate` and
`context-discrimination-rate` need other methods and never meet it (schema-only only).
Wilson arithmetic, rounding, withheld reasons, thresholds and protocol revision numbers are
unchanged (matching and accounting stay revision 2): a population that does not author the
value has byte-identical results. The only metric whose numbers change on the benchmark
populations is `measurable-share` (its denominator now includes the 156 uncertain samples
as `unresolved`); whether and how a product scorer reads it is the benchmarks' decision.

### 5. Schema 1.4, additive and gated

`SCHEMA_MINOR` becomes 4 (`SchemaVersion::V1_4`); `SchemaVersion::CURRENT` stays 1.1. A
corpus snapshot is sealed under 1.4 only when an expectation has no range; a run or public
artifact only when an outcome's range is `unresolved`. A snapshot that authors the value, or
an artifact with such an outcome, under an older schema is refused with the new reason code
`range-not-established-gate`. 1.4 is a superset of 1.3, 1.2 and 1.1: the identity value and
the product projection stay valid under it. Every valid 1.0 to 1.3 document keeps its bytes
and digest (the committed fixtures are unchanged); the five JSON Schemas and the reason
catalog change by the `$id`, the optional `range`, the new enum value and two reason codes,
as the drift test regenerates them. A reader older than 1.4 refuses a 1.4 document with
`schema-minor-too-new`; it cannot misread an unlocated occurrence.

### 6. What does not change

Method generation (`pii-eval-kernel` `generate`) works on authored cases that always have a
candidate; it never produces a range-less expectation. The compatibility interpreter (protocol
revision 1) is closed over located valid/invalid occurrences and never receives one.
Adapters see only the ranges that exist (`VariantTask.ranges`). The worker-entry format
carries the value unchanged.

### 7. Consumer handoff

[docs/migration/populations-32/handoff.json](../migration/populations-32/handoff.json) states
the four populations with all 1,188 memberships carried, the 156 inventory, digests and pins;
[docs/migration/benchmarks-handoff-32.md](../migration/benchmarks-handoff-32.md) states the
upgrade requirements. Upstream completion does not close the benchmarks acceptance; the
benchmarks re-run the populations with the pinned engine on linux, decide the scorer and
denominators, and own every threshold.

## Consequences

- No membership of the four benchmark populations is dropped, narrowed or coerced; the 156
  are observed `unresolved` on three axes and `not-measured` on action.
- `unresolved` is never a failure and never a success on any axis.
- Located occurrences' numerators and denominators are identical to the schema 1.2 dual run
  (verified on all four populations: `type-miss-rate` 43/79, 15/191, 143/356, 179/247).
- A producer of schema 1.4 snapshots must keep range-less occurrences schema-only; the
  validator enforces it.
