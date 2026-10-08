# pii-evidence snapshot consumer

Status: implemented (decisions and alternatives: [ADR 0019](adr/0019-pii-evidence-snapshot-consumer.md);
hand-off: [migration/pii-evidence-handoff.md](migration/pii-evidence-handoff.md)). Producer contract:
[`pii-evidence-consumer-contract`](https://github.com/redact-secret/pii-evidence/blob/main/docs/methodology/consumer-contract.md)
version 1. The Rust API is internal; the contract is the pin, the two commands below and the documents they read and
write.

`pii-eval` consumes a released public snapshot of `redact-secret/pii-evidence`, verifies all of it **before anything is
mapped or executed**, maps it into the existing corpus contract, and measures a scanner over it with the unchanged
protocol. The evidence repository owns the authored evidence; this repository owns scanner-neutral measurement; neither
owns Redact Secret qualification.

## What belongs to whom

| Concern | Owner | Here |
| --- | --- | --- |
| Authored cases, sources, claims, fixture bytes, spans, identity and sensitivity expectations, provenance, snapshot release and digests | `pii-evidence` | Read-only input, pinned by id and digests; never edited, never repaired |
| Verification of the snapshot, the mapping onto corpus semantics, execution, replay, accounting, the measurement artifact | `pii-eval` | `pii-eval-evidence` and `pii-eval`; the mapping decisions and their losses are below |
| Thresholds, support states, scanner rankings, release approval, stable/provisional decisions, publication, what a rate means for Redact Secret | downstream benchmark qualification (`redact-secret-benchmarks`) | Not here. The measurement states counts and withheld states and nothing more |
| Protected populations, custody, budgets, authorization | `private-custodian` | Not needed and not used: the path is public-synthetic end to end |

## Pin

`fixtures/pii-evidence/pin.json` (`pii-eval-evidence-pin/1`, closed fields) pins one snapshot: id, manifest SHA-256,
content digest, source-manifest digest, the contract name, version and digest construction, and the release (tag, full
commit, archive digests). There is no floating reference. The pinned snapshot is
`public-pii-phi/2026-10-07/9d4e8e036bbb` (content digest `9d4e8e036bbb180f...b321ba2`, manifest SHA-256
`a9e24b6dc73bc876...e3555ca9`, tag `snapshot-public-pii-phi-2026-10-07-9d4e8e036bbb`, commit
`c436ae013011b9c8b1126f589d1b14d99a84baf5`).

The snapshot is **vendored** at `fixtures/pii-evidence/snapshots/<id>/` (276 KiB; reserved, synthetic and documented
test values only; the evidence repository is MIT licensed and every source it carries is `redistribution: allowed`).
`tools/pii-evidence/test/fetch.test.mjs` shows the vendored files are byte-identical to the released archive by
rebuilding the producer's deterministic tar and comparing it with the pinned `tarSha256`.

## Commands

The engine never touches the network. Fetching is a separate Node tool; the consumer is a separate binary so the
five-command contract of `pii-eval` ([cli.md](cli.md)) is unchanged.

```text
node tools/pii-evidence/fetch-snapshot.mjs --pin fixtures/pii-evidence/pin.json --out <new-dir>
pii-eval-evidence verify --snapshot-dir DIR --pin FILE
pii-eval-evidence import --snapshot-dir DIR --pin FILE --out DIR        # snapshot.json + binding.json
pii-eval-evidence plan   --config FILE [--node PATH] [--replays N]       # writes the run manifest
```

* `fetch-snapshot.mjs` (needs `gh`): the tag must resolve, through an annotated tag object, to the pinned commit; the
  `.tar.gz` and the tar inside it must have the pinned SHA-256; only regular files below the one top directory with safe
  relative names are extracted, into a new empty directory. It prints `fetched-unverified`: it does not judge the
  snapshot.
* `verify` reads the directory (regular files only, no symlink, bounded count and size) and runs the whole verification.
* `import` verifies, maps and writes `snapshot.json` (a sealed schema 1.4 `CorpusSnapshot`) and `binding.json`. On any
  refusal **nothing is written**. The output directory must be new or empty.
* `plan` builds the sealed run manifest from the mapped corpus and the scanner plan the configured adapter derives.

stdout is one JSON line (`pii-eval-evidence-summary/1`), stderr one fixed-vocabulary line. Exit codes reuse the frozen
table of `pii-eval`: 0 accepted, 2 usage, 3 invalid content, 4 identity or integrity mismatch. A refusal names a file, a
record id of the evidence repository or a fixed field name, never a value and never input text.

## Verification order

The first failure is reported and nothing after it is read. Every step is a hard refusal.

1. `manifest.json` exists; `consumerContract` is `pii-evidence-consumer-contract`, `consumerContractVersion` is `1`,
   `contentDigestSpec` is `files-v1`, `schemaVersion` is `1`, `kind` is `snapshot-manifest`. An unknown version is never
   read further.
2. Identity against the pin: id, manifest SHA-256, content digest, source-manifest digest.
3. Population is `public`.
4. The file list: all required files are present; every file except the manifest is listed, no listed file is missing;
   each byte length, SHA-256 and JSON Lines record count equals the manifest's.
5. The content digest (`files-v1`) is recomputed and equals the manifest's; the id is `public-pii-phi/<snapshotDate>/<first
   12 hex digits>`; the source-manifest digest equals the SHA-256 of `sources.jsonl`.
6. Every record parses strictly (no duplicate key, no float, integers within 2^53 - 1, bounded depth, LF lines, ids
   strictly ascending); `kind` and `schemaVersion` are known; a stated `population` is `public`; no object key anywhere
   contains `scanner`, `detector`, `support`, `threshold`, `blocker`, `score`, `benchmark`, `qualif` or `expectedcurrent`
   (the producer's own neutrality rule); required fields exist and enums are closed. An unknown optional property is
   ignored, as the contract says.
7. Counts and exclusions agree with the files; the coverage summary equals the coverage recomputed from the cases,
   fixtures and taxonomy; recorded validation all `passed`.
8. Every source is `redistribution: allowed`, of reserved, synthetic or public-test origin, with no naturally occurring
   personal data; so is every case's value origin.
9. References resolve (case to kind, jurisdiction, contexts, sources, claims, related cases, review events; claim to source;
   fixture and skip to case and rule); each fixture's `sha256` and `byteLength` match its `content`; every span is a
   non-empty `[start, end)` inside it on character boundaries; a copied fixture equals its case (identity, sensitivity,
   domains, the bytes at the span) and a `derivedFromRule` fixture asserts exactly `not-established` /
   `context-dependent` and has no span.

### Reason codes

| Code | Exit | Meaning |
| --- | --- | --- |
| `snapshot-id-mismatch` | 4 | The manifest id is not the pinned id |
| `manifest-digest-mismatch` | 4 | `manifest.json` is not the pinned bytes |
| `content-digest-mismatch` | 4 | The pinned or recorded content digest differs from the digest of the files |
| `source-manifest-digest-mismatch` | 4 | The pinned or recorded source-manifest digest differs from `sources.jsonl` |
| `snapshot-id-derivation` | 4 | The id is not derived from the snapshot date and the content digest |
| `contract-unknown` | 4 | The manifest names another consumer contract, or none |
| `contract-version-unknown` | 4 | Contract version other than `1` |
| `digest-spec-unknown` | 4 | Digest construction other than `files-v1` |
| `file-missing` | 4 | A required or listed file is absent |
| `file-unlisted` | 4 | A file the manifest does not list is present |
| `file-digest-mismatch` | 4 | A file's SHA-256 differs from the manifest (a tampered byte) |
| `file-length-mismatch` | 4 | A file's length differs from the manifest |
| `record-count-mismatch` | 4 | A JSON Lines file holds another number of records than listed |
| `population-not-public` | 4 | The manifest or a record names a protected, private, mixed or empty population |
| `file-not-regular` | 3 | A symlink, device, directory where a file is expected, or an unusable name |
| `file-too-large` | 3 | More files, a larger file or a larger total than the bounds |
| `snapshot-unreadable` | 3 | The directory or a file cannot be read |
| `pin-invalid` | 3 | The pin is malformed, has unknown fields or names another contract |
| `manifest-invalid` | 3 | The manifest is not valid JSON or lists files unsafely |
| `record-invalid` | 3 | A record is not strict JSON, is not LF-terminated, or a line is empty |
| `record-field-missing` | 3 | A required field is absent |
| `record-field-invalid` | 3 | A field has the wrong type or an unknown enum value |
| `record-kind-unknown` | 3 | The record `kind` is not the one its file holds |
| `schema-version-unknown` | 3 | The record `schemaVersion` is not `1` |
| `forbidden-field` | 3 | A scanner, detector, support-state, threshold or score key exists |
| `id-order-invalid` | 3 | Ids are not strictly ascending (unsorted or duplicate) |
| `count-mismatch` | 3 | A manifest count differs from the files or the exclusion lists |
| `coverage-mismatch` | 3 | The coverage summary differs from the recomputed coverage |
| `reference-unresolved` | 3 | A reference does not resolve inside the snapshot |
| `fixture-digest-mismatch` | 3 | A fixture's `sha256` differs from its `content` |
| `fixture-length-mismatch` | 3 | A fixture's `byteLength` differs from its `content` |
| `span-invalid` | 3 | A span is empty, out of range or off a character boundary |
| `fixture-expectation-mismatch` | 3 | A fixture asserts more than, or something other than, its case or rule |
| `source-not-public-safe` | 3 | A source or case value origin is not redistributable synthetic or reserved material |
| `validation-not-passed` | 3 | A recorded validation gate did not pass |
| `exclusion-inconsistent` | 3 | An excluded record is present, or an exclusion count is wrong |
| `taxonomy-invalid` | 3 | Reserved for a taxonomy file that cannot be read as the vocabulary it claims |
| `kind-unmapped` | 3 | An evidence kind has no family in the mapping table (for example `national-id`) |
| `jurisdiction-unmapped` | 3 | A jurisdiction is neither `global`, `us` nor `uk`, or disagrees with the family scope |
| `mapping-invalid` | 3 | The mapped corpus does not validate, or the output cannot be written |
| `nothing-to-map` | 3 | The snapshot holds no fixture |
| `plan-invalid` | 3, 4 | The run manifest cannot be built or does not bind to the corpus |

## Expanded mapping revision 2

The consumer additionally maps `date-of-birth/global/labeled-field` to
`pii:global:date-of-birth` for global occurrences, `pii:us:date-of-birth`
for US occurrences and `pii:gb:date-of-birth` for UK occurrences, preserving
the authored jurisdiction. It maps `uk-nino/uk/structured` to
`pii:gb:national-insurance-number`. Evidence jurisdiction `uk` becomes ISO 3166-1
`GB`; it is not mapped to an unrelated existing family. A population carrying
one of these families uses mapping revision 2, generation version 2 and
population version 2. The artifact schema and measurement protocol do not change.
Unknown kinds and jurisdictions still fail closed, and family scope must agree
with the jurisdiction.

Legacy-only populations use revision 1 and retain their exact corpus and binding
bytes, including the committed first-snapshot golden digests and replay. This is
an additive vocabulary mapping, not a change to authored truth, sensitivity,
range handling, scoring, or product qualification. Existing context/PHI and
span-less mapping losses still apply to the candidate.

## Mapping (rule `pii-evidence-to-corpus`, revision 1)

The unit measured is the evidence **fixture** (exact bytes), grouped under the evidence **case** that explains it. The
mapping uses the existing `CorpusSnapshot` contract and the outcome lattice as they are. No protocol change was made or
is needed to run; the losses below are what an unchanged protocol cannot say.

| Evidence | pii-eval | Decision and loss |
| --- | --- | --- |
| Fixture `content` | `Variant.text`, byte for byte; `textDigest` = fixture `sha256` | Exact. Spans are the fixture's half-open UTF-8 byte ranges (verified on character boundaries) |
| Case id, fixture id | Opaque ids `ec-`, `eu-`, `es-`, `ev-` plus 24 hex digits of a domain-separated SHA-256 (`Id` forbids `/`) | The readable ids live in the binding, which maps every variant id to its fixture and case |
| Case line | `Lineage.sourceDigest` = SHA-256 of the exact case line in `cases.jsonl` | The corpus traces to the authored case record |
| `identity` valid / invalid / not-established | `ExpectedType` valid / invalid / not-established | One to one for located occurrences |
| `sensitivity` sensitive / non-sensitive | `SensitivityExpectation` sensitive / non-sensitive | One to one for located occurrences |
| `sensitivity` context-dependent | `not-established` | A flattening: pii-eval has no "depends on context" value. Observed `unresolved`, `review-required`; recorded as `sensitivity-context-dependent-flattened` |
| Fixture with one span | A located occurrence, `range` = the span | Case method `type-validation`, or `pii-benign` when the occurrence is authored non-sensitive |
| Fixture with no span (every `derivedFromRule` fixture, and cases the evidence leaves unlocated) | A range-less occurrence ([ADR 0018](adr/0018-not-established-range-and-schema-1-4.md)), `schema-only` | pii-eval accepts a range-less occurrence only with identity and sensitivity `not-established`. An authored `valid`/`invalid` or `sensitive`/`non-sensitive` without a span is therefore weakened to `not-established` and recorded as `identity-weakened-no-span` / `sensitivity-weakened-no-span`. The weaker value never asserts more than the evidence; what is lost is the authored "invalid, non-sensitive" claim about text that has no located value |
| Located and range-less fixtures of one case | Separate pii-eval cases (`ec-` and `eu-`) | An unlocated variant cannot turn the located variants' accounting `unresolved`. Both cite the same authored case |
| `derivedFromRule` | `Strategy::Derived` with operator = rule id (`/` becomes `-`) and version = rule major version; no seed | The projector's minor and patch version are in the binding, not the corpus. Copied carrier fixtures are `Authored` (the evidence states a carrier is representational only) |
| Rule outcomes `not-established` | observed `unresolved` (review-required), never pass or fail | As ADR 0017 and ADR 0018 specify. A scanner's finding or silence never settles it |
| Kind | `FamilyId` from a fixed table: `email` and `phone` and `payment-card` and `iban` `pii:global:*`; `us-ssn` `pii:us:ssn`; the four `us` health kinds `pii:us:<kind name>` | The names match pii-eval's existing family vocabulary. An unknown kind (`national-id`) is refused, not guessed |
| `jurisdiction` | `global` is no jurisdiction, `us` is `US` | Another jurisdiction is refused |
| `contexts[]`, `domains[]` (`phi`) | Not carried in the corpus; recorded per variant in the binding | pii-eval has no context-id or PHI field and its families are PII-only. `contexts-not-carried`, `phi-domain-not-carried` |
| Case with no `input.text` | Not carried | Two `us-ssn` cases are structural only (no fixture exists); listed in the binding |
| Skipped (case, rule) pairs | Not carried | Eight skips, each with the producer's reason; listed in the binding |
| Language | `und` | The evidence states none and mixes scripts |
| Context frame, obligation, action | `neutral`, `none`, `not-specified` | The evidence states none of them; none is invented |
| Role (positive, negative, collision, ...) | Not a pii-eval concept; recorded in the binding | No evidence case is a context trio or declares competing jurisdictions, so `context-discrimination` and `jurisdiction-collision` are not used |
| Evidence class, review state, ambiguity, rationale, claims | Not carried; evidence class and role are in the binding | Project-maintained evidence is not independent validation, and the binding keeps the evidence class next to each variant |

The mapped population is `pii-evidence-public-pii-phi-2026-10-07-9d4e8e036bbb` version 1, run class
`public-synthetic`, schema 1.4, semantic digest `612a8cf629c24c8e...6347d8`. It holds 55 cases (22 located, 33
range-less), 139 variants and 139 occurrences (98 located, 41 range-less). Losses over its 139 variants:
`contexts-not-carried` 37, `phi-domain-not-carried` 37, `sensitivity-context-dependent-flattened` 11,
`identity-weakened-no-span` 17, `sensitivity-weakened-no-span` 19.

### Loss codes

| Code | Meaning |
| --- | --- |
| `identity-weakened-no-span` | An authored `valid`/`invalid` identity became `not-established` because no span is stated |
| `sensitivity-weakened-no-span` | An authored `sensitive`/`non-sensitive` became `not-established` because no span is stated |
| `sensitivity-context-dependent-flattened` | `context-dependent` was mapped to `not-established` |
| `contexts-not-carried` | The case names contexts; the corpus has no field for them |
| `phi-domain-not-carried` | The case is in the `phi` domain; pii-eval families are PII-only |

### Excluded kinds

The snapshot carries no `payment-card`, `iban` or `national-id` case: the producer's provenance gate excluded them
(`coverage.kindsWithoutCases`). The table maps `payment-card` and `iban` so a later snapshot needs no rule change;
`national-id` stays unmapped until the evidence names a jurisdiction.

## Measurement

The run is a public-synthetic, official-mode, `released` run of the one real adapter this repository ships,
`@redact-secret/core` 0.1.0-beta.12, installed hermetically from the public npm registry (`npm ci --ignore-scripts` from
the committed lockfile; npm checks the recorded sha512 integrity). The repository ships no other real scanner; the inert
fake package is a test double. Selecting it is not a statement about the product: the adapter is the engine's input,
and the evidence is public. Everything below is in
[`docs/measurements/pii-evidence-public-pii-phi-2026-10-07-9d4e8e036bbb/`](measurements/pii-evidence-public-pii-phi-2026-10-07-9d4e8e036bbb/):

| File | Role |
| --- | --- |
| `provenance.json` | The record: every identity, what is execution and what is replay, the digests, what the measurement is not |
| `manifest.json` | The sealed run plan (`pii-eval.run-manifest`, protocol `pii-v1` revision 2) |
| `observation-redact-secret-core.json` | The normalized observations of the live scanner: what a replay consumes |
| `run-artifact.json` | The internal artifact (needed to replay a scanner that returns sanitized output) |
| `public-synthetic-artifact.json` | The versioned measurement artifact (`pii-eval.public-synthetic-artifact`, schema 1.4) |
| `run-config.json` | The official run configuration, as `reproduce.mjs` writes it, paths relative to its scratch directory |

Identities: engine `pii-eval` 0.0.0, protocol `pii-v1` revision 2, population digest `612a8cf6...`, manifest digest
`a2ee0b5b...`, scanner `redact-secret-core` 0.1.0-beta.12, product `released`, package tree
`726421636189573b...036d03` (the released digest), adapter `redact-secret-core-node` 1.0.0 normalization 1, shim
`21664407345b099d...`, configuration digest `d213ca5d...`, activation `pii:global`, `pii:us` (digest `68785ee0...`),
Node v22.16.0. The platform addon (`@redact-secret/node-darwin-arm64`) and the WebAssembly package are pinned by tree
digest in the run configuration and recorded in `provenance.json` (they are platform specific and not part of the
scanner identity the manifest binds).

**Execution** is `pii-eval run`: a live scanner process, two passes per input that agreed. **Replay** is
`pii-eval replay`: the artifacts re-derived from the observation set alone, `scannersLaunched` 0. They are recorded as
different kinds of provenance. Replay reproduced the semantic result: `parity: identical`, the same run and public
artifact digests (`2d06741e...`, `d54f96f9...`) and byte-identical files. What a replay carries over from the original
rather than recomputes is the output verdicts (the scanner returned sanitized output); the rest is recomputed. Three fresh
executions on one host produced equal digests.

Result (descriptive; denominators and withheld states as the artifact records them): 139 variants, complete, no
failure. All 98 located occurrences observed range `miss`: the pinned scanner reported no finding on any located
occurrence. Across 20 type cases `type-miss-rate` is 20/20, `sensitive-miss-rate` 18/18, `wrong-family-rate` 0/20,
`wrong-jurisdiction-rate` 0/8; `non-sensitive-flag-rate` (0/1) and `benign-suppression-rate` (1/1: the one benign case was not flagged) are withheld for
insufficient evidence (below the minimum denominator of 4); `measurable-share` is 39 of 110 (partial: 71 samples are
`unresolved` by construction, the 41 range-less occurrences and the not-established sensitivities); the collision,
context-discrimination and range-collateral rates are not applicable. This describes what this one scanner build did on
this reserved-value corpus, whose values are mostly unlabeled and use reserved example domains and fictional numbers by
design; the artifact does not say why it reported nothing, and this document does not guess. It is not accuracy
evidence for real data and not a product verdict.

## Reproduce

Needs Node 22, `npm` with registry access, and the release binaries. CI does not run the live step; it replays the
committed observations (`crates/pii-eval-cli/tests/evidence_measurement.rs`, no scanner, no network).

```sh
cargo build --release --locked -p pii-eval-cli
node tools/pii-evidence/reproduce.mjs [--scratch DIR] [--snapshot-dir DIR]   # verify, import, plan, run, replay, compare
node tools/pii-evidence/fetch-snapshot.mjs --pin fixtures/pii-evidence/pin.json --out DIR   # optional: use a fetched copy
cargo test -p pii-eval-cli --locked --test evidence_consumer --test evidence_measurement
```

`reproduce.mjs` prints one JSON line and exits 0 only when every digest equals `provenance.json` and the replay equals
the execution. On another platform the platform addon differs; the report says `matchesRecordedAddon: false` and any
semantic difference is then a finding to investigate, not a failure to hide.

## Limits

* The consumer verifies the snapshot's structure, identity, digests, references and safety rules; it does not
  re-run the producer's provenance lint or its safe-data scan. It trusts the pinned digests for authorship, which prove
  which release was read, not that its expectations are right.
* One population, one scanner, one platform, one host. No claim extends past them.
* Every evidence case is project-maintained and `unreviewed`; the measurement inherits that.
