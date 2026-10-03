# Architecture

## Design status

This is the initial design baseline plus a bootstrap workspace. Requirements below describe intended behavior and must be demonstrated by implementation evidence. Implemented today: the six-crate workspace skeleton, CI, the dependency-isolation guard, the frozen contracts (P2), and byte-range rules, offset translation, canonical matching and the legacy compatibility mode (P3), indexed metric accounting with exact statistics and a metric verifier (P4), and the seven methods with deterministic variant provenance ([ADR 0007](docs/adr/0007-method-generation-and-variant-provenance.md), P5). The scanner adapter boundary (P6, [ADR 0006](docs/adr/0006-scanner-adapter-boundary.md)) is implemented for one process adapter and `@redact-secret/core`; protocol revision 2, schema 1.1 and the bounded executor, replay scheduling, tree cleanup and validated atomic writer are implemented as a library (P7, [ADR 0008](docs/adr/0008-protocol-revision-2-and-schema-1-1.md), [ADR 0009](docs/adr/0009-bounded-execution-and-artifact-writing.md)); the standalone CLI (`run`, `replay`, `validate`, `compare`, P8, [docs/cli.md](docs/cli.md), [ADR 0010](docs/adr/0010-standalone-cli-workflows.md)) drives them; the internal GitHub App's service core (`pii-eval-app`, P11, [ADR 0011](docs/adr/0011-internal-github-app.md)) is implemented without its transport. Everything else is proposed. Engine implementation, measurement protocol, artifact schema, accounting, methods, and adapters have separate version identities.

## Ownership and dependencies

The engine consumes a versioned corpus snapshot and scanner configuration, produces measurements, and leaves qualification to consumers. It must not depend on Redact Secret internals, a benchmark checkout, a site, or custodian storage credentials.

Protected operation uses the same measurement kernel inside a custodian-controlled environment. An engine invocation is not an authorization decision. The custodian supplies authorized inputs and decides which aggregate can leave that environment.

Do not make `pii-eval` depend on credential family semantics. Reuse a shared crate only after its neutral contract and both consumers are proven; pin any extracted dependency. A common framework is not a migration prerequisite.

## Workspace

The crates exist as identity-only placeholders. They are internal: names, APIs, and layout are not consumer contracts and may change without notice; consumers depend on versioned artifacts and the CLI. Dependency rules and the verified MSRV are in [docs/dependency-policy.md](docs/dependency-policy.md).

| Crate | Responsibility |
| --- | --- |
| `pii-eval-contracts` | Typed inputs/outputs, version constants, JSON Schema |
| `pii-eval-kernel` | Methods, outcome interpretation, range relationships, accounting |
| `pii-eval-adapters` | Process adapters, scanner identity, observation normalization |
| `pii-eval-cli` | Configuration, resource limits, run/replay/validate/compare orchestration |
| `pii-eval-compat` | Isolated, removable legacy projection and parity support |
| `pii-eval-app` | GitHub-independent core of the internal App: webhook authentication, allowlist authorization, bounded job queue and workers, sanitized Checks ([ADR 0011](docs/adr/0011-internal-github-app.md)). Nothing depends on it; the CLI works without it |

The kernel has no process spawning, network, publication, or product support policy; `crates/pii-eval-cli/tests/dependency_policy.rs` enforces the dependency side (implemented). `pii-eval-compat` is reachable only from CLI tests and can be deleted without touching other crates. Adapters never score expected outcomes. Compatibility code may reproduce legacy quirks without redefining the canonical model.

## Delivery surfaces and boundaries

| Surface | State | Boundary |
| --- | --- | --- |
| CLI | Implemented (`run`, `replay`, `validate`, `compare`; [docs/cli.md](docs/cli.md)) | Local public/synthetic runs work without GitHub or custodian. Resource limits are explicit. A protected run needs a valid custodian job context, which the CLI validates and which grants no access. |
| Internal GitHub App | Service core implemented as the `pii-eval-app` library (P11, [ADR 0011](docs/adr/0011-internal-github-app.md), [docs/github-app.md](docs/github-app.md)); the HTTP/GitHub transport is not built and nothing is registered, installed or deployed | Thin adapter: accepts an evaluation request, invokes the pinned CLI/engine, and posts sanitized status. It holds no corpus, makes no measurement or support decision, and is not an authorization authority. |
| private-custodian | Separate repository | Verifies plan/candidate, reserves budget, enforces isolation, invokes the pinned engine, validates private output, authorizes the allowlisted aggregate. |
| redact-secret-benchmarks | Separate repository | Retains product policy, populations, thresholds, support status, publication, and the pinned TypeScript oracle (commit recorded in [ADR 0001](docs/adr/0001-rust-first-and-oracle-pin.md)). |

Public review records (what a maintainer or reviewer may see and discuss) and private audit records (custody ledger, protected inputs, budget state) are distinct data classes with separate storage. The engine produces neither authorization decisions nor ledger entries. No Rust crate depends on `credential-eval`, the benchmarks checkout, or custodian code; no shared crate is created until a neutral contract is proven by both consumers. The file-level split of legacy code is in the [migration ownership map](docs/migration/ownership-map.md).

## Contracts and identities

Contracts are frozen at schema 1.0 (P2, [ADR 0002](docs/adr/0002-freeze-pii-contracts-v1.md)): `CorpusSnapshot`, `RunManifest` (the plan, formerly `RunPlan`), `ObservationSet`, `RunArtifact` (internal) and `PublicSyntheticArtifact`. Canonical serialization and the semantic digest are specified in [ADR 0003](docs/adr/0003-canonical-serialization-and-semantic-digest.md). JSON Schemas are committed under `schemas/` and guarded by a drift test. The bullets below describe the intended binding; the types implement them.

- A snapshot binds population identity, authored cases, source lineage, expected ranges, context groups, language/jurisdiction, and deterministic generation rules.
- A plan binds engine/protocol, snapshot, scanner binaries/packages, adapters, enable sets, activation/configuration, seed derivation, replay count, and execution limits.
- Observations bind the exact input bytes, scanner/configuration identity, normalization version, and observed findings/actions/output capabilities. Replay rejects changed inputs or settings.
- A run artifact binds observations, per-case results, method coverage, accounting, failures, and provenance. An artifact can be complete while recording measurement failures; completeness is not a product verdict.

Use separate population visibility (`public-synthetic` or `protected`) and product identity (`released` or `candidate`). A public synthetic candidate run is still candidate evidence. Publication requires an additional explicit projection policy.

## PII semantics

Type identity and sensitivity context remain independent outcome axes. Preserve `pass`, `fail`, `review-required`, and `not-measured`; derive status from a valid state rather than allowing contradictory authored pairs. Missing family/jurisdiction capability must not become success.

Migration range states are `exact`, `overbroad`, `partial`, `miss`, and `not-applicable`. Use validated half-open UTF-8 byte ranges against original input. Reject invalid offsets and ambiguous normalization; adapters translate runtime indices once.

The legacy interpreter selects the first overlapping finding. P3 decided ordering, duplicate handling, multiple overlaps, label mappings, and outcome precedence in [ADR 0004](docs/adr/0004-order-invariant-pii-matching.md): the legacy rule is reproduced unchanged as `legacy-first-overlap` in `pii-eval-compat`, and the order-invariant `pii-v1-canonical` rule (proposed protocol revision 2, not yet representable in a contract document) lives in the kernel with a classified difference list. Implemented: range validation and the single adapter offset translation (`utf8-bytes`, `utf16-code-units`, `unicode-code-points`), canonical matching with the four independent axes, and the legacy mode. Methods, adapters and execution remain proposed. A further selection change requires a separately versioned protocol and difference report, not a silent Rust refactor.

Action evidence has declared capability: reported action, available sanitized output, or unavailable. Never infer actual removal from a finding flag. Output validation must use synthetic data and account for collateral changes.

## Methods and accounting

Preserve seven methods: type-validation, context-discrimination, pii-benign, jurisdiction-collision, mutation, reference-differential, and schema-only.

Preserve ten metric contracts: type-miss-rate, wrong-family-rate, wrong-jurisdiction-rate, sensitive-miss-rate, non-sensitive-flag-rate, context-discrimination-rate, benign-suppression-rate, jurisdiction-collision-rate, range-collateral-rate, and measurable-share.

Each metric declares its unit, eligibility, numerator, denominator, direction, grouping, interval, and withheld states. Retain authored-case/method grouping and complete context trios. Replays are stability checks, not extra samples; derived variants are not automatically independent observations. Record authored counts, variant counts, and metric effective N separately.

Use checked integer counters. Retain unrounded sufficient counts; validate finite arithmetic and round only at the defined artifact boundary. Freeze Wilson endpoint and decimal-rounding behavior against independent vectors, including zero samples, zero failures, all failures, incomplete strata, and large counts. Interval interpretation is limited by sampling assumptions and synthetic corpus design.

P4 implemented this in the kernel ([ADR 0005](docs/adr/0005-indexed-accounting-and-metric-statistics.md)): one pass over the outcome rows into per-(scanner, case) flag words, all ten metrics derived per group, scanner, language, jurisdiction and method strata kept separate, exact integer Wilson arithmetic rounded once half up (no floating point), and a verifier that recomputes metric values and counts from the rows. The accounting and statistics rules are proposed protocol revision 2 and are bound with the matching rule by P7; schema 1.0 still holds one metric list per artifact, so metrics of a multi-scanner artifact are not verifiable until that revision.

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

P9 ([ADR 0011](docs/adr/0011-oracle-parity-and-migration-evidence.md)) delivered the parity evidence for steps 2 to 5 of the migration acceptance on a frozen synthetic population: same-observation parity against the pinned oracle's own code (compatibility protocol with zero differences; every canonical difference classified, none unexplained), canonical invariance to input order, worker count and repeats, the engine end to end, and an opt-in same-pinned-scanner check. It is evidence for benchmarks' acceptance ([handoff](docs/migration/benchmarks-handoff-664.md)), not a cutover: protected populations, release qualification, rollback rehearsal and oracle retirement stay with their owners.
