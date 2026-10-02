# Architecture

## Design status

This is the initial design baseline. Requirements below describe intended behavior and must be demonstrated by implementation evidence. Engine implementation, measurement protocol, artifact schema, accounting, methods, and adapters have separate version identities.

## Ownership and dependencies

The engine consumes a versioned corpus snapshot and scanner configuration, produces measurements, and leaves qualification to consumers. It must not depend on Redact Secret internals, a benchmark checkout, a site, or custodian storage credentials.

Protected operation uses the same measurement kernel inside a custodian-controlled environment. An engine invocation is not an authorization decision. The custodian supplies authorized inputs and decides which aggregate can leave that environment.

Do not make `pii-eval` depend on credential family semantics. Reuse a shared crate only after its neutral contract and both consumers are proven; pin any extracted dependency. A common framework is not a migration prerequisite.

## Planned workspace

| Crate | Responsibility |
| --- | --- |
| `pii-eval-contracts` | Typed inputs/outputs, version constants, JSON Schema |
| `pii-eval-kernel` | Methods, outcome interpretation, range relationships, accounting |
| `pii-eval-adapters` | Process adapters, scanner identity, observation normalization |
| `pii-eval-cli` | Configuration, resource limits, run/replay/validate/compare orchestration |
| `pii-eval-compat` | Isolated, removable legacy projection and parity support |

The kernel has no process spawning, network, publication, or product support policy. Adapters never score expected outcomes. Compatibility code may reproduce legacy quirks without redefining the canonical model.

## Contracts and identities

Proposed contracts are `CorpusSnapshot`, `RunPlan`, `ObservationSet`, and `RunArtifact`; names and fields are frozen through contract tests before implementation.

- A snapshot binds population identity, authored cases, source lineage, expected ranges, context groups, language/jurisdiction, and deterministic generation rules.
- A plan binds engine/protocol, snapshot, scanner binaries/packages, adapters, enable sets, activation/configuration, seed derivation, replay count, and execution limits.
- Observations bind the exact input bytes, scanner/configuration identity, normalization version, and observed findings/actions/output capabilities. Replay rejects changed inputs or settings.
- A run artifact binds observations, per-case results, method coverage, accounting, failures, and provenance. An artifact can be complete while recording measurement failures; completeness is not a product verdict.

Use separate population visibility (`public-synthetic` or `protected`) and product identity (`released` or `candidate`). A public synthetic candidate run is still candidate evidence. Publication requires an additional explicit projection policy.

## PII semantics

Type identity and sensitivity context remain independent outcome axes. Preserve `pass`, `fail`, `review-required`, and `not-measured`; derive status from a valid state rather than allowing contradictory authored pairs. Missing family/jurisdiction capability must not become success.

Migration range states are `exact`, `overbroad`, `partial`, `miss`, and `not-applicable`. Use validated half-open UTF-8 byte ranges against original input. Reject invalid offsets and ambiguous normalization; adapters translate runtime indices once.

The legacy interpreter selects the first overlapping finding. Before canonical semantics are frozen, explicitly decide ordering, duplicate handling, multiple overlaps, label mappings, and outcome precedence. Reproduce legacy selection only in a declared compatibility mode if needed. A revised selection rule requires a separately versioned protocol and difference report, not a silent Rust refactor.

Action evidence has declared capability: reported action, available sanitized output, or unavailable. Never infer actual removal from a finding flag. Output validation must use synthetic data and account for collateral changes.

## Methods and accounting

Preserve seven methods: type-validation, context-discrimination, pii-benign, jurisdiction-collision, mutation, reference-differential, and schema-only.

Preserve ten metric contracts: type-miss-rate, wrong-family-rate, wrong-jurisdiction-rate, sensitive-miss-rate, non-sensitive-flag-rate, context-discrimination-rate, benign-suppression-rate, jurisdiction-collision-rate, range-collateral-rate, and measurable-share.

Each metric declares its unit, eligibility, numerator, denominator, direction, grouping, interval, and withheld states. Retain authored-case/method grouping and complete context trios. Replays are stability checks, not extra samples; derived variants are not automatically independent observations. Record authored counts, variant counts, and metric effective N separately.

Use checked integer counters. Retain unrounded sufficient counts; validate finite arithmetic and round only at the defined artifact boundary. Freeze Wilson endpoint and decimal-rounding behavior against independent vectors, including zero samples, zero failures, all failures, incomplete strata, and large counts. Interval interpretation is limited by sampling assumptions and synthetic corpus design.

Support thresholds and stable/provisional decisions remain downstream. Neutral mechanics can be configurable but are always part of protocol/configuration identity.

## Execution and performance

Normalize identifiers into indexed tables; group rows once. Index findings by file and use a range-search algorithm justified by measured density. Process variants in bounded batches rather than retaining the entire generated corpus and raw scanner output.

Bound workers, per-scanner parallelism, pending tasks, memory, timeout, and stdout/stderr. Long-lived Node/Python workers may amortize startup; isolate workers by scanner/configuration/activation realm and verify reset/replay behavior. Default to fresh processes where isolation is uncertain. Enforce process-tree cleanup through the supported platform runner.

Separate kernel replay cost, scanner startup/scan cost, materialization, serialization, and total wall time. Record peak RSS and allocation measurements with their collection method. Performance comparisons pin inputs, toolchain, build profile, host, scanner versions, and settings; report uncertainty and regressions. No speed target is justified without a baseline.

Parallelism must preserve canonical semantic ordering. Timestamps and host timing diagnostics are non-semantic; scheduler order must not change the semantic digest. Nondeterministic scanner output is recorded as instability, not sorted away when differences are meaningful.

## Protected integration

`private-custodian` verifies the plan and candidate, reserves budget, enforces isolation, invokes a pinned engine, validates private output, and authorizes an allowlisted aggregate. The public engine repository stores neither protected input nor custody ledger. Signatures attest execution identity; they do not prove true expectations or independent review.

## Validation and cutover

Acceptance requires independent hand-checkable conformance, property tests, same-observation TypeScript/Rust parity, real-scanner dual runs, worker/input-order tests, failure-path tests, and bounded stress runs. Attribute every difference. Do not fix a legacy semantic bug merely to achieve or abandon parity without a versioned decision.

Benchmarks retains its oracle until explicit release qualification, rollback rehearsal, and caller-based retirement requirements are met. Compatibility is removed only after its last consumer is gone.
