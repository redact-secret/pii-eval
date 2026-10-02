# pii-eval

A Rust-based, scanner-neutral engine for reproducible PII measurement.

`pii-eval` evaluates what a scanner identifies, how it interprets sensitive context, and what ranges and actions it reports against versioned authored expectations. It produces inspectable measurement artifacts for downstream consumers.

## Status

**Design baseline — implementation not yet shipped.** This repository starts privately and may be published after its contracts, migration evidence, and security boundaries are ready. The architecture and commands described here are targets, not claims of completed functionality. No throughput, accuracy, or production-readiness claim is established by these documents.

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
| [redact-secret-benchmarks](https://github.com/redact-secret/redact-secret-benchmarks) | Redact Secret qualification policy and public presentation |
| [credential-eval](https://github.com/redact-secret/credential-eval) | Credential measurement with its own protocol |

One run measures one identified population. Consumers may compose several artifacts through explicit policy, retaining each population's identity and denominator.

## Planned implementation

A Rust workspace separates contracts, kernel, adapters, CLI, and temporary compatibility tooling. Node/Python shims support scanners in those runtimes; scoring is implemented in Rust. Public synthetic runs can execute locally. Protected runs execute only within a separately authorized custodian environment.

No CLI command is promised until implemented and tested. The intended capabilities are `run`, `replay`, `validate`, and `compare`; their final syntax is established by the CLI contract.

## Migration acceptance

1. Freeze input, observation, accounting, and compatibility contracts.
2. Measure the TypeScript baseline and build independent conformance cases.
3. Implement the Rust kernel and adapters.
4. Prove same-observation replay parity, then live-scanner parity.
5. Explain every difference and measure performance with correctness checks enabled.
6. Switch benchmark consumers with explicit rollback and retirement criteria.

## Reading and contribution

Read [ARCHITECTURE.md](ARCHITECTURE.md), [CONVENTIONS.md](CONVENTIONS.md), [SECURITY.md](SECURITY.md), and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Contributions must use synthetic/public-test material and preserve scanner-neutral expectations. Scanner agreement does not establish ground truth.

## Publication and licensing

Public code is separate from permission to publish any corpus or artifact. Repository access changes do not authorize release of protected data. The maintainer must select and add a `LICENSE` before public distribution; these documents do not grant a license or promise third-party scanner redistribution rights.
