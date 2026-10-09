# Consumer example

A reference consumer of pii-eval **public** artifacts, in plain Node (22) with the
standard library only. It imports nothing from this repository's code: it reads
the published JSON documents ([schemas/](../../schemas/), the digest construction
of [ADR 0003](../../docs/adr/0003-canonical-serialization-and-semantic-digest.md))
and a pin file the caller writes. It is the reference for what a consumer such as
redact-secret-benchmarks must verify; it is not that consumer, and it does not
verify custodian envelopes or revocation feeds
([docs/custodian-boundary.md](../../docs/custodian-boundary.md)).

It verifies and composes. It makes **no** stable or provisional decision, applies
no threshold, ranks nothing, and never pools populations.

```sh
node examples/consumer/consume.mjs --pins examples/consumer/fixtures/pins.json \
  examples/consumer/fixtures/population-a-v2.public-synthetic-artifact.json \
  examples/consumer/fixtures/population-b-v1.public-synthetic-artifact.json
node --test examples/consumer/test/consume.test.mjs      # CI runs exactly this
```

stdout is one JSON line, `pii-eval-consumer-report/1`, with keys in ascending
order. Exit 0: every supplied artifact was accepted and every pinned population is
satisfied. Exit 1: an artifact was rejected or a pinned population has no accepted
artifact. Exit 2: usage error or unusable pins.

## Pins (`pii-eval-consumer-pins/1`)

The consumer's own format, recorded by the caller from a run it qualified. Every
field is compared exactly; there is no tolerance and no "latest".

| Field | Meaning |
| --- | --- |
| `engine`, `protocol` | The exact engine and protocol identity objects of the artifact |
| `artifactSchema` | `{id, version}`; only the public synthetic artifact, schema `1.1` or `1.2` (the artifact's version must equal the pin's) |
| `requireComplete` | Reject an artifact whose measurement is incomplete (a failed scanner stays failed; it is never read as a clean result) |
| `populations[]` | One entry per separately identified population |
| `populations[].population` | `populationId`, `populationVersion`, `populationDigest`, `visibility` |
| `populations[].runClass` | `public-synthetic` |
| `populations[].artifactDigest`, `.manifestDigest` | The head: the exact artifact and manifest semantic digests |
| `populations[].retiredArtifactDigests`, `.retiredManifestDigests` | Superseded digests: an artifact carrying one is reported as `superseded` rather than merely unknown |
| `populations[].projection` | Optional, schema `1.2` only: `{requiredViews[], mode?, rosterDigest?}`. The artifact must carry the product projection, cover these views, have exactly this mode and this roster |
| `populations[].scanners[]` | The exact scanner identity (product, candidate/artifact digest, configuration digest, activation digest, adapter, version) |

## What is checked, in this order

1. The document parses strictly (no duplicate key, no `null`, integers only, bounded depth and size).
2. It is not the internal run artifact and not a legacy schema 1.0 document, and its schema and version equal the pin.
3. Its stated `semanticDigest` equals the digest recomputed from its body.
4. It claims a pinned population (by population id); then the artifact digest equals the pinned head, the engine, protocol and run class, population version, digest and visibility, and the manifest digest equal the pins.
5. Every pinned scanner is present with exactly the pinned identity and nothing else is present; a scanner is `complete`; the measurement is `complete` with no failure.
6. Every pinned scanner has all ten metrics with sane counts.
7. The product projection (schema 1.2), when the artifact carries one or the pin
   requires one (next section).

## Product projection (schema 1.2)

An artifact under schema `1.2` may carry `semantic.productProjection`
([ADR 0016](../../docs/adr/0016-product-projection-and-schema-1-2.md)): rows per
(scanner, view, family) for **this one population**, each with its counts, ten
metrics, `mode` (`official` or `exploratory`) and the scanner, configuration,
activation, candidate and population binding it was measured under. The consumer
checks the block and keeps every row apart; it never merges rows, never adds a
combined row and decides nothing. It rejects: duplicate (scanner, view, family)
rows (`projection-row-duplicate`); a required view with no row for a scanner, in the
artifact's own `requiredViews` or in the pin (`projection-view-missing`); rows that
count more cases than their own or than the population holds, or metric totals larger
than the row's cases (`projection-pooled-denominator`), and cells that do not add up
(`projection-counts-mismatch`); a mode or view outside the closed vocabulary
(`projection-mode-unknown`, `projection-view-unknown`), mixed modes or a mode other
than the pinned one (`projection-mode-mismatch`); a row whose scanner, configuration,
activation, product (candidate) or population differs from the artifact
(`projection-binding-mismatch`); another roster than the pinned one
(`projection-roster-mismatch`); a block, row or stratum that is not the closed shape
(`projection-malformed`); and an artifact without the block when the pin requires it
(`projection-missing`). The engine recomputes the values from the snapshot and the roster
(`pii-eval validate --snapshot ... --projection-roster ...`); this consumer reads the
published block only.

A population with no accepted artifact is reported `missing`; it is never filled
from another. Composition lists each accepted population with its own identity,
counts and metrics. No total, average or combined denominator exists anywhere in the
report (`pooling: "none"`, `decision: "none"`).

## Reason codes

`artifact-digest-not-pinned`, `artifact-superseded`, `digest-mismatch`,
`document-malformed`, `document-too-large`, `document-unreadable`, `engine-mismatch`,
`incomplete-measurement`, `internal-artifact-not-consumable`, `legacy-schema-version`,
`manifest-mismatch`, `manifest-superseded`, `metrics-malformed`, `metrics-missing`,
`population-digest-mismatch`, `population-not-pinned`, `population-version-mismatch`,
`population-visibility-mismatch`, `projection-binding-mismatch`,
`projection-counts-mismatch`, `projection-malformed`, `projection-missing`,
`projection-mode-mismatch`, `projection-mode-unknown`,
`projection-pooled-denominator`, `projection-roster-mismatch`,
`projection-row-duplicate`, `projection-view-missing`, `projection-view-unknown`,
`protocol-mismatch`, `run-class-mismatch`,
`scanner-activation-mismatch`, `scanner-adapter-mismatch`,
`scanner-artifact-mismatch`, `scanner-configuration-mismatch`,
`scanner-missing`, `scanner-not-pinned`, `scanner-product-mismatch`,
`scanner-version-mismatch`, `schema-unsupported`, `schema-version-unsupported`,
`unexpected-top-level-field`.

`document-too-large` and `document-unreadable` come from reading the file (over 32
MiB, missing, not a regular file); `document-malformed` with field `invalid-utf8` or
`invalid-unicode` is invalid UTF-8 or a lone surrogate escape. A public artifact has
exactly four members (`schema`, `schemaVersion`, `semantic`, `semanticDigest`); any
other member is rejected because only `semantic` is covered by the digest.

Pins are validated strictly and an unusable pin file is exit 2: the artifact schema
version must be `1.1` or `1.2`, the run class `public-synthetic`, every digest 64 hex
characters, every scanner field present, and a digest cannot be both the head and
retired.

A test (`consumer_handoff_docs.rs`) fails when this list and the program differ.

## Fixtures

`fixtures/` was produced by the real engine through the built binary
(`crates/pii-eval-cli/tests/consumer_fixtures.rs`, synthetic data, the inert fake
scanner package): population A version 1 (superseded), A version 2 (the head), a
second population B, A version 2 measured with another candidate build, A version 2's
internal run artifact (never consumable), and the pins; and A version 2 measured with
the product projection (schema 1.2) with its pins (`pins.projection.json`) and the
roster it was built from (`projection-roster.json`). Regenerate after an
intentional change with
`PII_EVAL_UPDATE_FIXTURES=1 cargo test -p pii-eval-cli --test consumer_fixtures`.
The artifacts say `candidate` because the fake package is not the released one; a
candidate result is never accepted as `released` (a test pins this).

## Limits

The consumer reads the public projection only, so it cannot recompute metrics from
rows; the engine's `validate --snapshot` does that for whoever holds the snapshot.
A pin proves the artifact is the one you pinned, not that the expected results are
right, and a digest identifies content, not authorship.

Schema 1.5 / protocol 3 evidence artifacts are accepted only with explicit new
caller pins. Authored PHI/context metadata is covered by the semantic digest;
the consumer does not turn it into product support policy. Old pins reject the
new population/schema. See ADR 0020 for migration and rollback.
