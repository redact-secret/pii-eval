# ADR 0016: The product projection and schema 1.2

- Status: accepted (benchmarks request redact-secret-benchmarks#664); subject to review.
- Date: 2026-10-05
- Related: [ADR 0002](0002-freeze-pii-contracts-v1.md) (change rules),
  [ADR 0003](0003-canonical-serialization-and-semantic-digest.md),
  [ADR 0005](0005-indexed-accounting-and-metric-statistics.md) (strata, A7),
  [ADR 0007](0007-method-generation-and-variant-provenance.md) (population views),
  [ADR 0008](0008-protocol-revision-2-and-schema-1-1.md) (schema 1.1, section 9),
  [docs/migration/benchmarks-handoff-664.md](../migration/benchmarks-handoff-664.md),
  [docs/cli.md](../cli.md). Implementation:
  `crates/pii-eval-contracts/src/projection.rs`,
  `crates/pii-eval-kernel/src/projection.rs`,
  `crates/pii-eval-cli/src/{projection,assemble}.rs`.

## Context

redact-secret-benchmarks#664 asked for an additive schema 1.2 with a closed,
optional product-projection block: rows carrying `family`, `view`
(`oracle-plan`, `qualification-plan`, `diagnostic-balanced`,
`benign-heavy-stress`), case and variant counts, method coverage, all ten metric
results with integer counts, effective N and interval or withheld reason, and
`mode` (`official` or `exploratory`). Each row must stay inside one population
artifact and its semantic digest, and the consumer must reject duplicate
family/view rows, absent required views, pooled denominators, unknown modes, and a
row whose scanner, configuration, activation, candidate or population binding
differs from the artifact. Language and control-class breakdowns were asked for
too. ADR 0008 section 9 had deferred views as "optional fields that can arrive
additively in a later minor (1.2) ... when a consumer is in hand"; this is that
consumer. The repository boundary does not move: pii-eval measures and records. No
threshold, support status, ranking or view policy enters the engine.

What already existed and is reused: the accounting's per-language stratum
(`ScannerAccounting::by_language`), whose counts partition the cases; the kernel's
view model (`ViewRoster`: an external, complete, exclusive assignment of authored
cases to views, ADR 0007 section 6); the `ProductIdentity`, configuration and
activation digests of `ScannerIdentity`; the protocol's `mode` vocabulary
(`official` / `exploratory`) of the run configuration. What did not exist: a
control class (ADR 0005 A7: `benignByControlClass` was never carried; the benign
classes are authoring input of the methods, not a corpus field) and any case
family (a case carries expectations, each with a family).

## Decisions

### 1. Additive, in place, opt-in

Schema 1.2 adds exactly one optional member, `semantic.productProjection`, to the
**public-synthetic artifact**. Every valid 1.1 document is still valid and keeps its
bytes and digest (ADR 0002). The naming convention of this repository is one schema
file per document kind and major version, superseded in place by the superset
(`schemas/public-synthetic-artifact.v1.schema.json`, ADR 0008 section 2); the minor
lives in `schemaVersion` and in the `$id` (`urn:pii-eval:schema:<kind>:1.2`). 1.2 follows
that convention: **no second schema file**. The five schema files and the
reason-code catalog change only by the `$id` (all five) and by the new member and
its types (the public artifact); the drift test regenerates them.

`SCHEMA_MINOR` (the highest minor a reader accepts) becomes 2. What a writer emits
by default does not: `SchemaVersion::CURRENT` stays **1.1**, because every consumer
of an artifact without a projection must see the same bytes. A document is sealed
under 1.2 only when it carries the block (`RunArtifact::to_public_synthetic_with_projection`
with `Some`). The digest domain includes the declared version (ADR 0003), so a 1.2
document's digest is under `.../1.2`. Gate (`projection-invalid`): the block needs
schema 1.2 or later and protocol revision 2. The internal run artifact, observation
sets, manifest and snapshot are not changed in any way (a test asserts the bytes of
all of them are identical with and without a roster).

### 2. The block

```text
productProjection
  rosterDigest      sha256 of the caller's roster content (sorted, order-independent)
  requiredViews[]   ascending, unique, a subset of the four view ids; every one has rows
  rows[]            ascending by (binding.scannerId, view, family); each key once
    family          the corpus family id, as the corpus names it
    view            oracle-plan | qualification-plan | diagnostic-balanced | benign-heavy-stress
    mode            official | exploratory
    binding         scannerId, configurationDigest, activationDigest, product (released |
                    candidate + digest), population (id, version, digest, visibility)
    counts          authoredCases, variants, occurrences     (never effective N)
    methodCoverage[] method {id, version}, cases, variants
    metrics[10]     the ten metric results: counts (eligible, measured, numerator,
                    unresolved, notMeasured, notApplicable, total), effectiveN, status,
                    value = measured {point, bound} | withheld {reason}
    byLanguage[]    optional; language, counts, metrics[10]; partitions the cell
    byControlClass[] optional; controlClass, counts, metrics[10]; covers the assigned cases
```

The block, the rows and the strata are closed (`deny_unknown_fields`); a field
outside them, an unknown view or an unknown mode is `schema-violation`. A JSON
example of the exact shape is in
[benchmarks-handoff-664.md](../migration/benchmarks-handoff-664.md#7-schema-12-the-product-projection)
and a real artifact is committed at
`fixtures/contracts/v1/rev2/public-synthetic-artifact.projection.json`.

**The key is (scanner, view, family), not (view, family).** One population
artifact can hold several scanners (ADR 0008 section 3: scanners are never pooled,
metrics are keyed by scanner), so a row without the scanner in its key would
either pool scanners or be ambiguous. The request's "duplicate family/view rows"
is the duplicate of that key's other two parts within a scanner.

**`mode` is the run's mode, on every row.** The run configuration already has a
`mode` (`exploratory`, `official`) that decides whether every identity is pinned and
resource limits are enforced; the projection copies it rather than inventing a
second notion. There is no separate `--projection-mode` on `run` (it would be a
second source of the same fact); `replay` has no run configuration and states it
(`--projection-mode`). **Rows of one artifact have one mode**
(`projection-invalid` otherwise): an exploratory number is never read next to an
official one inside one digest. The mode is part of the digest, so an exploratory
and an official run of the same data are two artifacts.

### 3. Views come from an external roster; the vocabulary is closed

The four view ids are the closed vocabulary the request names; they are wire
identifiers, not policy. The engine does not know what an `oracle-plan` contains,
which views a product qualifies against, or whether a stress view is benign-dominant
(ADR 0007 section 6: that stays with the consumer). The caller supplies a **roster**
(`pii-eval-projection-roster/1`, docs/cli.md): the required views, the view of every
authored case and optionally a control class for some cases. It generalizes the
kernel's `ViewRoster` (complete, exclusive assignment) to the four ids;
`ViewRoster`/`PopulationView` are unchanged. `ProjectionRoster::new` refuses a roster
that leaves a case without a view, names a case twice or an unknown case, uses a view
it did not list as required, lists a required view with no case, or leaves a case
without an honest family cell. The roster digest is recorded in the block, so a
different roster is a different artifact.

A population is measured **as one population**: the oracle-plan and
qualification-plan "populations" of the request are separate runs with separate
snapshots (one population per run, the repository's rule); the views inside one
artifact are the diagnostic and stress memberships of ADR 0007 or any other
caller-declared split. The block never merges views and never reports a combined row.

### 4. Case family

A case's family is its collision declaration's target, else the one family all its
expected occurrences share. A case whose occurrences span several families and that
declares no target has no honest cell: attributing it to one of them would hide the
others. The roster is refused (`AmbiguousFamily`) before any scanner starts; the
corpus author splits the case. (The alternative, a first-family rule, was rejected as
arbitrary attribution in a measurement repository.)

### 5. How a row is computed: no pooling by construction

Each cell is accounted **on its own**: the snapshot body is restricted to the
cell's cases, `AuthoredIndex` is built over it and the same `account` that scores
the whole population scores the cell with the scanner's rows for those cases. The
cell's denominators are therefore its own cases; no value is derived from another
cell. Language strata are the accounting's own `by_language` of that cell
(a partition of it). Control-class strata account the cell's cases that the roster
assigned a class (a roster-supplied opaque `Id` label such as `test-value`; the
authored benign classes of ADR 0007 fit but are not required). The strata count only
assigned cases, so they need not partition the cell. A scanner that did not complete
is unmeasured in every cell (the accounting's own rule), never a pass.

### 6. Where each rejection is enforced

Structure and bindings (contracts, `validate` and every parse):

| Request | Reason code | Rule |
| --- | --- | --- |
| duplicate family/view rows | `duplicate-identity` (existing) | rows strictly ascending by (scanner, view, family) |
| absent required views | `projection-view-missing` (new) | every scanner has a row for every `requiredViews` entry |
| pooled denominators | `projection-pooled-denominator` (new) | a row or stratum that counts more than the population or its parent; a metric `total` above its row's cases (twice the cases for the axis-assertion metric); a scanner's rows adding up to more than the artifact's authored counts. Fewer is `count-mismatch` |
| unknown modes (and views) | `schema-violation` (existing) | closed enums; uniform mode is `projection-invalid` |
| binding differs | `projection-binding-mismatch` (new) | scanner, configuration digest, activation digest, product (candidate digest) and population must equal the artifact's own |
| block under 1.1, or revision 1 | `projection-invalid` (new) | the gate |

Values (kernel, `verify_public_projection`, `validate --snapshot --projection-roster`):
the block is recomputed from the artifact's outcome rows, the snapshot and the
roster and compared with the carried one. This catches what structure cannot: two
cells merged into one row that still sums to the population, or a self-consistent
count set that is not the measurement. Without a roster `validate` reports
`productProjection: "structural"`; with one, `"recomputed"`. The writer cannot
recompute (it has no roster after assembly); the builder validates the block it
makes and the run and replay paths build it from the roster they were given.

The reference consumer (`examples/consumer/consume.mjs`, which reads the published
JSON only and imports no pii-eval code) implements the same six rejections for the
public block with its own codes (`projection-row-duplicate`,
`projection-view-missing`, `projection-pooled-denominator`,
`projection-mode-unknown`, `projection-view-unknown`, `projection-binding-mismatch`,
...), and accepts pins for 1.1 or 1.2 (a pin names exactly one: no silent upgrade).
Its tests are the "consumer tests" of the request.

### 7. CLI

`run --projection-roster FILE` (or config `projection.roster`), `replay
--projection-roster FILE --projection-mode official|exploratory`, `validate
--projection-roster FILE`. An official run must pin the roster
(`projection.roster.rosterDigest`). A protected run cannot carry a projection (the
public artifact is the only carrier). A roster problem is refused before any scanner
starts, with existing reason codes (`config-invalid`, `document-invalid` naming
`projection-roster`; a wrong pin is `provenance-mismatch`): no CLI reason code and no
exit status was added. The summary of `run` and `replay` gains `productProjection`
(roster digest, mode, required views, row count) only when a block exists.

### 8. Limits

At most 2048 rows and 64 strata per row (`MAX_PROJECTION_ROWS`,
`MAX_PROJECTION_STRATA`), so a block fits the 32 MiB parse cap (ADR 0008 section 6).
Memory for a projection is one restricted copy of a cell at a time plus the outcome
rows indexed by case.

## Consequences

- 1.1 consumers see no change unless a roster is supplied; 1.1 readers reject a 1.2
  document with `schema-minor-too-new` (the usual minor rule). The negative fixture for
  "minor newer than reader" moved from 1.2 to 1.3.
- Four reason codes were added to the catalog (`projection-invalid`,
  `projection-view-missing`, `projection-binding-mismatch`,
  `projection-pooled-denominator`); none was renamed or reused.
- `AGENTS.md`'s rule holds: nothing here asserts product output. Qualification,
  thresholds and "which view gates which family" stay with benchmarks.

## Not done, and why

- The sanitized-output verdicts that let `replay` work without the original artifact
  (ADR 0010) are a different 1.2 candidate. They are not added: no consumer asked,
  and mixing them would make this change two concerns. They remain an additive item.
- Population `view` / `evidence class` / `benign class` as **corpus** fields (ADR 0008
  section 9) are still not added: the roster carries them from outside, which needs no
  corpus change and keeps every existing snapshot digest.
- Per-metric `SampleBasis` counts (ADR 0008 section 3) are still kernel-side.
- Recomputing a block needs the roster; the public artifact carries only its digest.
  Embedding the case-to-view assignment would publish every case id's view for no
  consumer need and would multiply the artifact's size.
