---
name: release-regression-check
description: Compare a pinned pii-eval candidate with a pinned baseline (a prior revision or the TypeScript oracle) on the same corpus snapshot and scanner identities, producing a deterministic sanitized regression and parity report. Use for evaluator release regression or migration parity checks.
---

# Release regression check

Require an immutable baseline, an immutable candidate, and one corpus
snapshot. The baseline is either a prior `pii-eval` revision or the
TypeScript migration oracle in `redact-secret-benchmarks`. If scanner
binaries, adapter versions, protocol/accounting/method versions, or
configuration differ, report the comparison as confounded and stop unless the
user explicitly requests that experiment.

The repository is a design baseline. Run only the build, test, and CLI
commands that exist in the manifests; if none exist, say which checks could
not run instead of inventing them.

## Procedure

1. Record every pinned identity: engine, protocol, accounting, methods,
   artifact schema, snapshot and population (visibility and
   released/candidate), scanner, adapter, configuration, toolchain, host.
2. Follow the migration order: first same-observation replay parity (identical
   `ObservationSet`, no scanner involved), then live-scanner parity. A
   live-scanner difference is not interpretable until replay parity holds.
3. Execute both sides with identical inputs and bounded settings. Compare
   per-case outcomes on each axis (type identity, sensitivity context, range
   state, action observation), failure and `not-measured` states, the seven
   methods' coverage, the ten metrics (with numerator, denominator, effective
   N, and interval endpoints), and artifact schema.
4. Verify determinism: repeat the candidate run, vary worker count and input
   order, and confirm the semantic digest is unchanged. Timestamps and host
   timing are non-semantic. Nondeterministic scanner output is reported as
   instability, not sorted away.
5. Classify every difference as semantic regression, intended protocol change,
   legacy quirk reproduced in compat mode, serialization-only change,
   performance change, or unexplained. Attribute every difference; do not fix
   or excuse a legacy bug merely to reach parity. Re-run each semantic
   difference to exclude nondeterminism.
6. Measure performance separately: kernel replay, scanner startup/scan,
   materialization, serialization, total wall time, peak RSS (with the
   collection method). Keep validation enabled and corpus sampling unchanged.

The report must include all pinned identities, completeness and failure
status, changed case IDs without input text or matched values (omit case IDs
for protected populations), reconciliation totals, performance conditions, and
artifact locations. This skill supplies measurement evidence; it does not
approve a release, set thresholds, or assign support status.
