---
name: oracle-parity-check
description: Check same-observation replay parity between the pii-eval Rust kernel and the TypeScript oracle in redact-secret-benchmarks, and attribute every difference. Use during the migration, before any consumer cutover. Report-only.
---

# Oracle parity check

The TypeScript engine in `redact-secret-benchmarks` is the migration oracle.
Read `README.md` (Migration acceptance) and `ARCHITECTURE.md` (Validation and
cutover). The oracle is a reference, not a dependency; do not import its
internals into the Rust crates.

## Procedure

1. Pin both sides: oracle revision, `pii-eval` engine/protocol/accounting
   versions, corpus snapshot, and the seven method and ten metric
   definitions. If any differ in an unexplained way, report the comparison as
   confounded and stop.
2. Same-observation replay first: feed one frozen `ObservationSet` to both
   engines with no scanner involved. Live-scanner parity is not meaningful
   until this passes.
3. Compare per-case outcomes on each axis (type identity, sensitivity
   context, range state, action observation), per-method coverage, metric
   numerators/denominators/effective N, interval endpoints, and withheld
   states.
4. Attribute every difference to one of: oracle quirk reproduced in
   `pii-eval-compat`, oracle bug, `pii-eval` bug, independent-conformance
   disagreement with the oracle, input/serialization artifact, or
   unexplained. The legacy first-overlapping-finding rule is the main known
   source; it is reproduced only in a declared compatibility mode.
5. Run independent hand-checkable conformance cases against both; where they
   disagree with the oracle, record that the oracle's assumption is wrong
   rather than adjusting the expectation.

Do not fix a legacy semantic bug merely to achieve or abandon parity; that
needs a versioned protocol decision with a difference report. Do not change
expected results to match either engine. The output is a difference table
with pinned identities and sanitized case references, not a cutover
decision. Rollback and retirement criteria belong to the cutover plan.
