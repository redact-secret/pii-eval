# pii-eval

A Rust-based, scanner-neutral engine for reproducible PII measurement.

`pii-eval` evaluates what a scanner identifies, how it interprets sensitive context, and what ranges and actions it reports against versioned authored expectations. It produces inspectable measurement artifacts for downstream consumers.

## Status

**Bootstrap.** This repository starts privately and may be published after its contracts, migration evidence, and security boundaries are ready. The Rust workspace, CI, the contracts, the kernel, the adapters, the bounded executor and the standalone CLI exist, and migration parity evidence against the pinned oracle exists (opt-in real-scanner check, one platform); the GitHub App core exists without transport, installation or deployment; a measured performance baseline against the pinned oracle exists (one shared development host, synthetic workloads); protected execution does not. The architecture and commands described here are targets unless the table below says implemented. No throughput, accuracy, or production-readiness claim is established by these documents.

| Item | State |
| --- | --- |
| Cargo workspace (six crates), pinned toolchain 1.98.1, MSRV 1.85, committed lockfile | Implemented (identity-only placeholders) |
| CI: fmt, Clippy `-D warnings`, locked tests, MSRV test, dependency-policy guard | Implemented |
| CLI: `run`, `replay`, `validate`, `compare` with a versioned configuration, pinned identities, frozen exit codes and a one-line JSON summary ([CLI contract](docs/cli.md), [ADR 0010](docs/adr/0010-standalone-cli-workflows.md)) | Implemented (Linux and macOS execution; Windows refused; offline clean-checkout example in `examples/quickstart/`; no published binary) |
| Legacy ownership map and oracle pin ([ownership map](docs/migration/ownership-map.md), [ADR 0001](docs/adr/0001-rust-first-and-oracle-pin.md)) | Implemented (inventory, no code moved) |
| Versioned contracts (schema 1.0): snapshot, manifest, observation set, internal and public-synthetic artifacts, frozen `pii-v1` registry, canonical digest, committed JSON Schemas ([ADR 0002](docs/adr/0002-freeze-pii-contracts-v1.md), [ADR 0003](docs/adr/0003-canonical-serialization-and-semantic-digest.md)) | Implemented (types, validation, digest, schemas; no measurement) |
| UTF-8 byte-range rules, adapter offset translation, order-invariant `pii-v1-canonical` matching and outcome axes, and the `legacy-first-overlap` compatibility mode ([ADR 0004](docs/adr/0004-order-invariant-pii-matching.md)) | Implemented (library functions with conformance and property tests; the canonical rule is a proposed protocol revision 2 not yet bindable in a contract document) |
| Scanner adapters: bounded pinned process adapter, `pii-eval-adapter/1` shim protocol, `@redact-secret/core` 0.1.0-beta.12 adapter with activation provenance and observed actions ([ADR 0006](docs/adr/0006-scanner-adapter-boundary.md)) | Implemented (synthetic fake-shim tests; real-scanner test opt-in; no worker pool, no live-scanner parity) |
| Indexed accounting of the ten metrics, exact Wilson statistics and the metric verifier ([ADR 0005](docs/adr/0005-indexed-accounting-and-metric-statistics.md)) | Implemented (kernel library with hand-calculated, independent-vector, differential and oracle-compatibility tests; the accounting rule is proposed protocol revision 2, bound by P7 together with the matching rule) |
| The seven methods with deterministic variant ids, seeds and provenance, the validators `synthetic-mod10` / `us-ssn-allocation` and the `invalidate-final-digit` operator, explicit unavailable-validator states and the two population views ([ADR 0007](docs/adr/0007-method-generation-and-variant-provenance.md)) | Implemented (kernel library with independent-vector and oracle-compatibility tests; adapters, execution and artifact writing are separate phases) |
| Protocol revision 2 (canonical rules, schema 1.1, per-scanner metrics, A8 any-to-all, sanitized-output verification, parse-memory measurement) ([ADR 0008](docs/adr/0008-protocol-revision-2-and-schema-1-1.md)) | Implemented (legacy revision 1 stays readable and unchanged; not re-measured) |
| Optional product projection and schema 1.2 (per scanner, view and family rows of one population artifact, caller-supplied roster; [ADR 0016](docs/adr/0016-product-projection-and-schema-1-2.md)) | Implemented (additive; without a roster the output is schema 1.1, byte for byte) |
| Authored not-established identity (schema 1.3, [ADR 0017](docs/adr/0017-not-established-type-identity-and-schema-1-3.md)) and range (schema 1.4, [ADR 0018](docs/adr/0018-not-established-range-and-schema-1-4.md)): the 156 uncertain benchmark memberships are observed `unresolved`, never dropped or coerced; [handoff](docs/migration/benchmarks-handoff-32.md) | Implemented (additive and opt-in; every document that does not author the values keeps its bytes) |
| Migration parity evidence: the Rust engine against the pinned oracle's own output on frozen synthetic input (compatibility protocol with zero differences, every canonical difference classified, zero unexplained), same-pinned-scanner check, handoff for benchmarks ([ADR 0012](docs/adr/0012-oracle-parity-and-migration-evidence.md), [report](docs/migration/oracle-parity-report.md), [handoff](docs/migration/benchmarks-handoff-664.md)) | Implemented (committed oracle export compared in CI; regenerating it and the live real-scanner check are manual; no protected corpus; no cutover decision) |
| Bounded deterministic execution and artifact writing: worker pool, per-scanner parallelism, deadlines, process-group tree cleanup, sampled memory and scratch limits, fresh process per pass, replay and instability recording, validated atomic writer ([ADR 0009](docs/adr/0009-bounded-execution-and-artifact-writing.md)) | Implemented as a library (`pii-eval-cli`), driven by the CLI; Linux and macOS; Windows tree cleanup not implemented; process control is not a sandbox |
| Internal GitHub App: `pii-eval-app` service core (webhook HMAC, replay protection, allowlist authorization, bounded queue and workers, stale-head handling, sanitized Checks) behind transport traits ([docs/github-app.md](docs/github-app.md), [ADR 0011](docs/adr/0011-internal-github-app.md)) | Core implemented and tested against fakes; **no HTTP server or GitHub client, nothing registered, installed or deployed**; the CLI does not depend on it |
| Performance measurement: frozen synthetic workloads, kernel replay, scanner startup and full pipeline measured separately against the pinned TypeScript oracle, scaling shapes, memory ceilings, budgets from measured baselines, one bounded optimization ([docs/performance.md](docs/performance.md), [ADR 0013](docs/adr/0013-performance-measurement-budgets-and-optimizations.md)) | Implemented (manual suites; raw results committed; CI runs the harness at tiny sizes with deterministic guards; no throughput promise; one macOS arm64 development host) |
| Protected execution via private-custodian | Proposed (owned by that repository). The CLI validates a custodian job context and refuses a protected run without one; the context grants no access ([CLI contract](docs/cli.md)). The custodian's worker protocol is implemented on its side; the engine speaks it in `pii-eval worker-job` ([docs/worker-job.md](docs/worker-job.md), [ADR 0015](docs/adr/0015-worker-job-launcher-and-contract-adapters.md)), **the five contract slots (stage layout, bundle and entry formats, embedded aggregates, nine labels) are decided by the custodian's ADR 0135 and installed as `Decided` adapters in the production build** ([what is decided](docs/custodian-contract-status.md)); tested with synthetic data, not deployed, and the production host, real-scanner sizing and the operational disclosure policy remain open. The boundary and its open questions are in [docs/custodian-boundary.md](docs/custodian-boundary.md) ([ADR 0014](docs/adr/0014-custodian-boundary-and-consumer-contract.md)) |
| Consumer handoff: dependency-free reference consumer with exact pins (`examples/consumer/`), synthetic custodian round trip (a stub, not the custodian), public-release hygiene checks, handoff for benchmarks #665 and #666 with rollback and compat inventory ([handoff](docs/migration/consumer-handoff-665-666.md)) | Implemented (synthetic data; no cutover, no release tag, no published binary) |
| Internal engine artifact: CI builds the release binary once per run and publishes it as a GitHub Actions artifact (linux-x86_64, 30-day retention on main, `build-info.json` + `SHA256SUMS`); `evaluate.yml` runs a public/synthetic evaluation with a prebuilt artifact and can be dispatched from other workflows ([docs/ci-artifacts.md](docs/ci-artifacts.md)) | Implemented in CI. Internal only: not a release, no signature or attestation, no macOS/Windows build |
| Custodian contract status (what private-custodian decides and what it does not, with evidence) and a real-Linux measurement of Node and the engine under the custodian's `RLIMIT_AS` ([contract status](docs/custodian-contract-status.md), [isolation measurement](docs/custodian-isolation-node.md)) | Implemented as documentation and an `isolation` CI job (a replica of the custodian's launcher, synthetic data). Finding: an unmodified Node runtime needs a little over 772 MiB of address space (fails at 768 MiB, starts at 800 MiB), so the custodian's 512 MiB test profile cannot start it; reported to the custodian as [private-custodian#37](https://github.com/redact-secret/private-custodian/issues/37) |

## What the engine measures

| Dimension | Question |
| --- | --- |
| Type identity | Did the scanner identify the expected family and jurisdiction? |
| Sensitivity context | Did it distinguish authored sensitive, non-sensitive, and unresolved context? |
| Range | What relationship does the reported byte range have to the expected occurrence? |
| Action observation | What action was reported, and, where output is available, what actually remained? |

Detection, sensitivity classification, a reported `redact` action, and verified sanitized output are separate observations. An adapter that exposes only some of them must declare that limitation.

The migration preserves the current seven PII methods and ten metric definitions. It does not adopt credential scoring merely because both engines use Rust. The existing TypeScript implementation in [redact-secret-benchmarks](https://github.com/redact-secret/redact-secret-benchmarks) is the migration oracle; independent conformance tests also verify the oracle's assumptions.

## Responsibilities

- Versioned corpus, case, variant, finding, observation, and artifact contracts.
- Bounded scanner execution and validated observation replay.
- PII outcome semantics, range assessment, and mechanical accounting.
- Reproducible semantic digests, explicit failure states, and migration compatibility.
- Measured kernel performance and representative end-to-end stress evaluation.

The engine does not own canonical truth, product thresholds, support status, release approval, corpus custody, or permission to publish protected results.

## Ecosystem boundary

| Component | Owns |
| --- | --- |
| Corpus author | Reviewed expectations, provenance, generation rules, and population identity |
| `pii-eval` | Scanner-neutral execution and measurement |
| [private-custodian](https://github.com/redact-secret/private-custodian) | Protected execution authorization, custody, budgets, and release of approved projections |
| Internal GitHub App (core implemented, not deployed) | A thin request and sanitized-status adapter over the CLI/artifacts; not a measurement, custody, or authorization authority |
| [redact-secret-benchmarks](https://github.com/redact-secret/redact-secret-benchmarks) | Redact Secret qualification policy and public presentation; retains the pinned TypeScript oracle until its recorded exit |
| [credential-eval](https://github.com/redact-secret/credential-eval) | Credential measurement with its own protocol |

One run measures one identified population. Consumers may compose several artifacts through explicit policy, retaining each population's identity and denominator.

## Planned implementation

A Rust workspace (present, see [dependency policy](docs/dependency-policy.md)) separates contracts, kernel, adapters, CLI, and temporary compatibility tooling. The crates are internal; consumers integrate through versioned artifacts and the CLI, not through Rust APIs. Node/Python shims support scanners in those runtimes; scoring is implemented in Rust. Public synthetic runs can execute locally. Protected runs execute only within a separately authorized custodian environment.

The CLI has four commands, `run`, `replay`, `validate` and `compare`; their syntax, configuration, exit codes and stdout and stderr contract are [docs/cli.md](docs/cli.md). Build with `cargo build --release --locked`; the quickstart there runs offline on synthetic data with an inert fake scanner package. No command is promised beyond that document.

## Migration acceptance

1. Freeze input, observation, accounting, and compatibility contracts.
2. Measure the TypeScript baseline and build independent conformance cases.
3. Implement the Rust kernel and adapters.
4. Prove same-observation replay parity, then live-scanner parity (evidence: [ADR 0012](docs/adr/0012-oracle-parity-and-migration-evidence.md)).
5. Explain every difference and measure performance with correctness checks enabled.
6. Switch benchmark consumers with explicit rollback and retirement criteria.

## Reading and contribution

Read [ARCHITECTURE.md](ARCHITECTURE.md), the [migration ownership map](docs/migration/ownership-map.md), [CONVENTIONS.md](CONVENTIONS.md), [SECURITY.md](SECURITY.md), and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Contributions must use synthetic/public-test material and preserve scanner-neutral expectations. Scanner agreement does not establish ground truth.

## Publication and licensing

Public code is separate from permission to publish any corpus or artifact. Repository access changes do not authorize release of protected data. The code in this repository is licensed under the MIT License (see [LICENSE](LICENSE), Copyright (c) 2026 Omiologic). That license covers this repository's source and documentation only: it does not grant permission to publish any corpus, protected data or measurement artifact, and it makes no promise about redistribution rights for third-party scanners or their packages, which keep their own licenses.
