# ADR 0002: Freeze the PII input, observation and artifact contracts (schema 1.0)

- Status: accepted for P2 (issue #3); subject to review.
- Date: 2026-10-02
- Related: [ADR 0001](0001-rust-first-and-oracle-pin.md),
  [ADR 0003](0003-canonical-serialization-and-semantic-digest.md),
  [ownership map](../migration/ownership-map.md), epic #1.

## Context

P3 to P12 build on a shared vocabulary. This ADR records what P2 froze, the
rules for changing it, how a population is consumed, and the decisions on the
ownership-map rows marked `mixed-split` that bear on contracts.

## What is frozen

Five documents share one envelope (`schema`, `schemaVersion`, `semanticDigest`,
`semantic`, optional `diagnostics`). Only `semantic` is digested.

| Document | Rust type | Schema file | Purpose |
| --- | --- | --- | --- |
| Corpus snapshot | `CorpusSnapshot` | `schemas/corpus-snapshot.v1.schema.json` | one identified population: cases, variants, authored expectations |
| Run manifest | `RunManifest` | `schemas/run-manifest.v1.schema.json` | the plan: engine, protocol, population digest, scanners, mechanics, limits |
| Observation set | `ObservationSet` | `schemas/observation-set.v1.schema.json` | one scanner configuration over one population |
| Run artifact | `RunArtifact` | `schemas/run-artifact.v1.schema.json` | internal result: outcomes, metrics, failures |
| Public-synthetic artifact | `PublicSyntheticArtifact` | `schemas/public-synthetic-artifact.v1.schema.json` | the only artifact the public serializer emits |

Also frozen: the `pii-v1` registry (seven methods and ten metrics, with ids,
versions, units, direction, applicability, sample unit, effective-N basis,
labels and withheld reasons) in `schemas/registry/pii-v1.registry.json`, and the
reason-code catalog in `schemas/reason-codes.v1.json`.

Design points:

1. **Independent axes.** Type identity, sensitivity context, range and action are
   separate fields in expectations and outcomes. Statuses are derived from
   states (`TypeState::status`), never stored beside them, so a contradictory
   pair is unrepresentable. Reachable states depend on the authored expectation.
2. **Missing capability is explicit.** `CapabilityState` is `supported`,
   `unsupported` or `undeclared`; an unlisted family or jurisdiction is never
   `supported`. A scanner that did not complete reports a status and no inputs,
   and every axis is `not-measured` / `not-applicable`. Action evidence is
   `unavailable`, `reported-action` or `sanitized-output`; removal is asserted
   only by `output-verified`.
3. **Independent identity bindings.** Engine, protocol, population (by digest),
   scanner, adapter and normalization version, product identity, configuration
   digest and activation digest are separate fields. Run class
   (`public-synthetic` or `protected`, equal to the population's visibility) and
   product identity (`released` or `candidate`) are independent; all four
   combinations are valid and distinct. A public-synthetic candidate run is
   candidate evidence.
4. **Population consumption.** One run binds exactly one population digest. A
   population from the public `credential-evidence`-style release or a
   product-owned corpus is consumed as a separately identified snapshot
   (`populationId`, `populationVersion`, digest). The engine never merges
   snapshots; consumers compose artifacts and keep each population's identity
   and denominator. Binding mismatches fail with `population-binding-mismatch`
   or `run-class-mismatch`.
5. **Public boundary by types.** `PublicSyntheticArtifact` has a run class type
   with one variant, no field for text, ranges, findings, observation digests or
   diagnostics, and a single constructor, `RunArtifact::to_public_synthetic`,
   that refuses protected runs. `serialize_public_synthetic` accepts only that
   type (a `compile_fail` doctest and tests in
   `crates/pii-eval-contracts/tests/public_projection.rs` check it). Protected
   publication is a custodian decision and has no code path here.
6. **Validation is layered**: strict parse, envelope check, typed parse,
   structural validation plus digest verification (`parse`/`validate`), then
   cross-document bindings (`validate_*_against_*`). Range validity (non-empty,
   ordered), bounds, and UTF-8 boundary validity are three separate checks with
   three reason codes. Errors carry a code, a structural path and numeric
   metadata only.
7. **No floats.** Rates and the interval z value are `ScaledDecimal`.
   Counters are `u64` bounded to 2^53 - 1 with checked identities.

## Change rules

- **Schema version** is `<major>.<minor>`. Reader rule: same major, minor no
  newer than the reader's; otherwise `incompatible-schema-major` or
  `schema-minor-too-new`. Readers never ignore unknown fields (all objects are
  closed), so a newer-minor document is rejected by an older reader rather than
  misread.
- **Optional (minor) changes**: adding an optional field (absent means
  unchanged meaning), adding an enum value that old documents cannot contain,
  adding a reason code, raising a documented limit, adding a document-level
  optional section. The old schema file stays; the new minor is published as
  `schemas/<name>.v<major>.schema.json` with a new `$id` minor, and the minor
  constant is bumped. The digest domain includes the full declared version
  (ADR 0003), so a document is sealed under the version it declares: old
  documents stay valid under their own version, and a document moved to a new
  minor is re-sealed, which changes its digest. Absent optional fields are
  omitted from canonical form.
- **Breaking (major) changes**: removing or renaming a field, reason code or
  enum value; making a field required; changing a type, unit, encoding or
  meaning; lowering a limit; changing canonical serialization or the digest
  preimage; changing any frozen method or metric definition, label, direction,
  version or mechanics default. These need a new major, a protocol revision
  where semantics change, a difference report, and a migration note.
- **Protocol (`pii-v1`) revision** is separate from schema version and from
  engine version: changes to matching precedence, eligibility, grouping,
  intervals, failure interpretation or action semantics bump `PROTOCOL_VERSION`
  and are never made inside a refactor.
- Golden fixtures and committed schemas change only through the documented
  update commands, with the changed fields explained in the commit.

## Decisions on `mixed-split` rows that bear on contracts

| Row | Decision |
| --- | --- |
| `domains/pii/profile.ts` | Metric ids, labels, units, sample unit and applicability are frozen in the registry. `direction` is retained as the Wilson endpoint a metric reports (a mechanical property). Thresholds are not in any contract. |
| `qualification/pii-v1.json` | `minDenominator`, `replays`, `intervalZ`, `intervalPrecision` are neutral `Mechanics`, recorded in every plan and artifact. The `0.5` thresholds, `gates` (required methods, minimum benign counts, protected/independent-evidence flags) stay in benchmarks. |
| `qualification.ts`, `schemas/pii-qualification-profile-v1.json` | Verdicts and thresholds stay in benchmarks; artifacts carry no pass/fail verdict or support status. |
| `populations.ts`, `schemas/pii-population-contract-v1.json` | Population identity and visibility are neutral (`Population`). Product population definitions and pin binding stay in benchmarks. |
| `schemas/pii-population-report-v1.json`, `pii-population-comparison-v1.json` | Composition across populations is consumer policy; artifacts carry identity and denominators so a consumer can compose them. |
| `holdout.ts`, `holdout-corpus.ts` | Protected bytes are never part of this repository. A protected population is the same `CorpusSnapshot` type with `visibility: protected`, consumed only inside a custodian-authorized run; its artifact is internal. |
| `identity-oracle.ts` | The neutral part (expected type and sensitivity per occurrence) is the expectation model. Product identity-format binding stays product-side. |
| `scanners/candidate.mjs` | Candidate identity is `ProductIdentity::Candidate { candidateDigest }`; activation selectors are `ScannerConfiguration.activation`. The mapping of product finding types to families is adapter-side (P6). |
| `scanners/families.mjs`, `score-pii-port-suffix.mjs`, `validator-qualification.ts`, `observe-pii-populations.mjs` | Not contract-bearing. Left to P3, P9, P6 and P7 as the map states. |

Not carried into schema 1.0 (added later as optional fields if needed): authority
records and evidence counters of the legacy accounting report, benign control
classes, validator observation shape, multi-population comparison.

## Consequences

- Downstream phases depend on documents and schemas, not on Rust types.
- Matching, accounting arithmetic (Wilson endpoints and rounding), methods,
  adapters and execution are not implemented here; the contracts only check
  structural consistency (for example count identities and that a published
  value respects `minDenominator`).
- Schema validation of documents with an independent JSON Schema validator is
  not part of CI; the drift test proves generated equals committed, and Rust
  validation is the enforcement point.

## Review amendments (PR #15)

Independent review found defects; the fixes are part of the 1.0 freeze.

- **Closed tagged enums.** serde ignores extra keys on the unit variants of an
  internally tagged enum, so `ProductIdentity` and `ActionOutcome` deserialize
  and generate their schema through closed wire types (`ProductIdentityWire`,
  `ActionOutcomeWire`, empty struct variants under `deny_unknown_fields`). The
  audit covered every internally tagged enum (`MetricValue` was already closed);
  `hardening.rs` asserts each rejects an extra key, and the schema test
  requires every object schema to be closed.
- **Capability-aware outcomes.** An axis whose capability is `unsupported`
  (ranges, family, jurisdiction, sensitivity; action `unavailable`) must be
  `not-measured` / `not-applicable`, also when the expected family or
  jurisdiction itself is unsupported (`check_capability_rules`,
  `validate_outcome_lattice`). Artifact scanner records follow the same status
  rules as observation sets (complete needs agreeing replays and range support).
- **Failures follow status.** Every scanner that did not complete has a failure
  record whose code is allowed for its status; a complete scanner has none.
- **Wire-string ordering.** Every enum-valued sort key (finding action, failure
  code, phase) sorts by wire string, as ADR 0003 states.
- **Generation and visibility are bound.** A manifest carries the snapshot's
  `generation` (generator, version, seed derivation) and the population's
  `visibility`; both are compared with the snapshot, and run class must match
  visibility. `to_public_synthetic` first validates the artifact (including its
  digest) and refuses unless both run class and population visibility are
  public-synthetic; the public artifact's population binding has a one-value
  visibility type.
- **Plans** must include the method a restricted metric depends on.
- **Diagnostics** are validated: at most one entry per phase, ascending by wire
  string, `startedAt` not after `finishedAt` (compared as instants).
- **Context class** must be the same across all expectations of a variant
  (`context-class-conflict`).
- **Reason-code integrity.** Parse errors are classified from this crate's own
  state, never from serde message text, so a key named like an internal
  sentinel cannot choose a reason code.
- **Redacting `Debug`** for case, variant and seed identifiers and for variant
  text; a test asserts no text, seed or identifier appears in debug output.
- **Digest domain** includes the full schema version (see ADR 0003).
- **Dependency guard** inspects normal and build edges for all targets.

### Deferred (explicit)

- Point and bound against counts, and metric counts against outcome rows:
  deferred to P4 (accounting arithmetic and Wilson endpoints).
- Parse memory: a document is read twice, the strict value tree and then the
  typed document. The tree is dropped before the typed parse, so the peak is the
  larger of the two plus the input, and the document cap was lowered from
  128 MiB to 32 MiB. The peak is not measured on this host (the sandbox refused
  the timing wrapper); streaming parse and resource limits are deferred to P7,
  which must measure peak RSS with its execution limits.
