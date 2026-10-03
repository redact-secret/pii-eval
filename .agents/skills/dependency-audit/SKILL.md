---
name: dependency-audit
description: Audit pii-eval's Rust workspace and Node/Python scanner-shim dependency graph for known vulnerabilities, provenance problems, and risky runtime capabilities. Use for dependency or supply-chain audits. Report-only unless fixes are requested.
---

# Dependency audit

Read `README.md`, `ARCHITECTURE.md`, `CONVENTIONS.md`, and the current
manifests/lockfiles. The repository is a design baseline; do not assume Cargo,
npm, or Python files exist. If none exist, report that and stop.

## Procedure

1. Inventory every manifest, lockfile, toolchain/MSRV pin, vendored component,
   and scanner-shim dependency, grouped by the planned crates
   (`pii-eval-contracts`, `-kernel`, `-adapters`, `-cli`, `-compat`) and by the
   Node/Python shim runtimes.
2. Use the ecosystem-native locked-graph audit tools that are installed (for
   example `cargo audit`/`cargo deny`, `npm audit --package-lock-only`,
   `pip-audit` against a lock, or OSV-Scanner). Use locked resolution only.
   Record tool versions and advisory-database timestamps.
3. Separate engine/runtime dependencies from development tooling, from the
   TypeScript migration oracle, and from external scanners invoked through
   adapters.
4. Check the architecture's dependency rules: `pii-eval-contracts` and
   `pii-eval-kernel` must not pull in process-spawning, network, or
   publication crates; nothing may depend on Redact Secret internals, a
   benchmark checkout, a site, or custodian storage credentials; any shared
   crate extracted with `credential-eval` must be pinned. Report violations.
5. Confirm the first-party `unsafe` policy: first-party crates forbid unsafe
   code; list dependencies that introduce build scripts, proc macros, or
   native code, since those execute at build time.
6. For each advisory, confirm reachability and whether the vulnerable
   capability is used in corpus/observation parsing, JSON/schema handling,
   UTF-8 or Unicode processing, process execution, or artifact serialization.
7. Report exact package, locked version, advisory, reachability, severity, and
   the smallest compatible remediation. Check that a proposed upgrade does not
   change canonical serialization, number encoding, or interval arithmetic
   dependencies that the protocol/accounting versions freeze.

Do not run or install arbitrary scanner packages merely to audit them. A
scanner's own vulnerabilities are not automatically vulnerabilities of the
evaluator; explain the trust boundary and invocation exposure. Never download
real personal data or credentials as part of an audit.
