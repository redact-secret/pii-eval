# pii-eval

A Rust-based, scanner-neutral engine for reproducible PII measurement.

`pii-eval` evaluates what a scanner identifies, how it interprets sensitive context, and what ranges and actions it reports against versioned authored expectations. It produces inspectable measurement artifacts for downstream consumers.

## Status

**Bootstrap — measurement not yet implemented.** This repository starts privately and may be published after its contracts, migration evidence, and security boundaries are ready. A Rust workspace, CI, and the migration ownership map exist; contracts, kernel, adapters, and CLI workflows do not. The architecture and commands described here are targets unless the table below says implemented. No throughput, accuracy, or production-readiness claim is established by these documents.

| Item | State |
| --- | --- |
| Cargo workspace (five crates), pinned toolchain 1.98.1, MSRV 1.85, committed lockfile | Implemented (identity-only placeholders) |
| CI: fmt, Clippy `-D warnings`, locked tests, MSRV test, dependency-policy guard | Implemented |
| CLI | Implemented: `--version` only; every other input is a usage error |
| Legacy ownership map and oracle pin ([ownership map](docs/migration/ownership-map.md), [ADR 0001](docs/adr/0001-rust-first-and-oracle-pin.md)) | Implemented (inventory, no code moved) |
| Versioned contracts (schema 1.0): snapshot, manifest, observation set, internal and public-synthetic artifacts, frozen `pii-v1` registry, canonical digest, committed JSON Schemas ([ADR 0002](docs/adr/0002-freeze-pii-contracts-v1.md), [ADR 0003](docs/adr/0003-canonical-serialization-and-semantic-digest.md)) | Implemented (types, validation, digest, schemas; no measurement) |
| UTF-8 byte-range rules, adapter offset translation, order-invariant `pii-v1-canonical` matching and outcome axes, and the `legacy-first-overlap` compatibility mode ([ADR 0004](docs/adr/0004-order-invariant-pii-matching.md)) | Implemented (library functions with conformance and property tests; the canonical rule is a proposed protocol revision 2 not yet bindable in a contract document) |
| Scanner adapters: bounded pinned process adapter, `pii-eval-adapter/1` shim protocol, `@redact-secret/core` 0.1.0-beta.12 adapter with activation provenance and observed actions ([ADR 0006](docs/adr/0006-scanner-adapter-boundary.md)) | Implemented (synthetic fake-shim tests; real-scanner test opt-in; no worker pool, no live-scanner parity) |
| Indexed accounting of the ten metrics, exact Wilson statistics and the metric verifier ([ADR 0005](docs/adr/0005-indexed-accounting-and-metric-statistics.md)) | Implemented (kernel library with hand-calculated, independent-vector, differential and oracle-compatibility tests; the accounting rule is proposed protocol revision 2, bound by P7 together with the matching rule) |
| Methods | Proposed |
| `run`, `replay`, `validate`, `compare` | Proposed |
| Internal GitHub App | Proposed |
| Protected execution via private-custodian | Proposed (owned by that repository) |

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
| Internal GitHub App (proposed) | A thin request and sanitized-status adapter over the CLI/artifacts; not a measurement, custody, or authorization authority |
| [redact-secret-benchmarks](https://github.com/redact-secret/redact-secret-benchmarks) | Redact Secret qualification policy and public presentation; retains the pinned TypeScript oracle until its recorded exit |
| [credential-eval](https://github.com/redact-secret/credential-eval) | Credential measurement with its own protocol |

One run measures one identified population. Consumers may compose several artifacts through explicit policy, retaining each population's identity and denominator.

## Planned implementation

A Rust workspace (present, see [dependency policy](docs/dependency-policy.md)) separates contracts, kernel, adapters, CLI, and temporary compatibility tooling. The crates are internal; consumers integrate through versioned artifacts and the CLI, not through Rust APIs. Node/Python shims support scanners in those runtimes; scoring is implemented in Rust. Public synthetic runs can execute locally. Protected runs execute only within a separately authorized custodian environment.

The only implemented CLI behavior is `pii-eval --version`. No other CLI command is promised until implemented and tested. The intended capabilities are `run`, `replay`, `validate`, and `compare`; their final syntax is established by the CLI contract.

## Migration acceptance

1. Freeze input, observation, accounting, and compatibility contracts.
2. Measure the TypeScript baseline and build independent conformance cases.
3. Implement the Rust kernel and adapters.
4. Prove same-observation replay parity, then live-scanner parity.
5. Explain every difference and measure performance with correctness checks enabled.
6. Switch benchmark consumers with explicit rollback and retirement criteria.

## Reading and contribution

Read [ARCHITECTURE.md](ARCHITECTURE.md), the [migration ownership map](docs/migration/ownership-map.md), [CONVENTIONS.md](CONVENTIONS.md), [SECURITY.md](SECURITY.md), and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Contributions must use synthetic/public-test material and preserve scanner-neutral expectations. Scanner agreement does not establish ground truth.

## Publication and licensing

Public code is separate from permission to publish any corpus or artifact. Repository access changes do not authorize release of protected data. The maintainer must select and add a `LICENSE` before public distribution; these documents do not grant a license or promise third-party scanner redistribution rights.
