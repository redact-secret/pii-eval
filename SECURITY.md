# Security policy

## Status and supported versions

The repository currently contains a design baseline and a bootstrap workspace (no measurement code), not a released security product. No supported production version is declared. Releases must publish their supported-version policy and known limitations before adoption.

## Reporting

Do not open a public issue containing sensitive data, exploit payloads tied to protected execution, private logs, or credentials. While private, contact a repository maintainer through an existing private channel. Once available, use GitHub's private vulnerability reporting. Maintainers must configure and document a verified private reporting channel before making the repository public. No response-time promise is established yet.

Provide affected revision, impact, prerequisites, and a minimal synthetic reproduction. Never send real personal data or active/revoked credentials as a test case.

## Threat model

Inputs, generated variants, scanner output, adapter packages, and run configuration are untrusted. A malicious scanner can read its supplied inputs, emit sensitive bytes in errors, consume resources, spawn children, or attempt network access. A scanner shim is executable code, not a harmless parser.

Protected execution also faces leakage through case identities, rare strata, raw hashes, timing, repeated queries, and overly detailed failures. These risks require custodian controls beyond engine implementation.

## Required controls

- Validate contracts, offset bounds, path containment, counts, output sizes, and supported versions before scoring.
- Reject absolute/traversal paths, unexpected symlinks, archive escapes, and mismatched replay identities.
- Use fixed executable paths and structured arguments; never evaluate shell text from a corpus or scanner response.
- Pin scanner/adapter identities and verify digests. Installation/build steps use reviewed dependency and network policies.
- Bound process fan-out, memory, time, buffered output, and temporary storage; cancel descendants as supported by the runner.
- Separate scanner errors from successful scans with no findings. Use sanitized reason codes; raw stdout/stderr never appears in public artifacts.
- Use restricted scratch permissions and deterministic cleanup. Persistent artifacts require an explicit output classification and owner.

Rust memory safety does not provide OS isolation. The runner must enforce network, filesystem, process, and credential boundaries. A `network=off` manifest field is not enforcement evidence by itself.

## Delivery-surface boundaries

State as of bootstrap: only the CI and dependency controls in the next list are implemented; the rest is proposed.

- Implemented: CI uses `permissions: contents: read`, no secrets, no benchmark or scanner checkout, third-party actions pinned by full commit SHA, and `--locked` builds. A test guards `pii-eval-contracts` and `pii-eval-kernel` against unreviewed, process, and network dependencies. First-party crates forbid `unsafe`. These are repository hygiene controls, not an assurance that the future engine is secure.
- Proposed: a thin internal GitHub App must hold only the minimum repository permissions for requests and Checks, hold no corpus, protected input, custody state, or measurement logic, accept only validated request fields, and post sanitized reason codes and aggregates that the custodian or public policy allows. App credentials are not available to the scanner execution environment.
- Proposed: protected runs execute only inside a custodian-controlled environment; the engine's output is internal until the custodian projects it. The App never reads the private audit ledger.
- Public review records and private audit records are separate classes; neither is a substitute for the other, and a GitHub status is not an authorization decision.

## Data policy

Ordinary development, fixtures, tests, examples, and public CI use safe synthetic/public-test data only. Public synthetic values must never be used in production systems. Real customer data, production logs, and real credentials are prohibited in this repository.

Protected synthetic inputs may be measured only through an authorized custodian run. Future use of real personal data is out of scope and requires a separate reviewed data-governance design before ingestion.

Internal output is not automatically public. Public projection must be allowlisted and validated independently; protected projections exclude input text, seeds, raw findings/ranges, individual case IDs, value hashes, raw errors, and private paths. Population commitments intended for public use must come from the custodian's opaque release identity policy rather than unsalted low-entropy value hashes.

## Integrity and release

Bind candidate bytes, scanner configuration, corpus, adapter, and engine to every run. Verify candidate identity before and after execution where the execution boundary allows mutation. A signature proves provenance under its trust model, not correctness or independence.

Publish no accuracy/speed/security claim without pinned evidence and stated limitations. Before public release, configure private reporting, choose a license, scan repository history/assets/logs, review third-party redistribution, and demonstrate publication guards. Keep synthetic measurement and candidate/internal results correctly labeled.
