---
name: determinism-check
description: Verify that pii-eval's semantic digest and aggregates are invariant to worker count, scheduling, input order, repeated runs, and host, and that instability is recorded rather than hidden. Use when parallelism, serialization, or digesting changes. Test-adding only.
---

# Determinism check

Read `ARCHITECTURE.md` (Execution and performance) and `CONVENTIONS.md`
(Serialization and errors). Parallel scheduling may not change semantic
output ordering or aggregates. If no runner or digest exists yet, say which
checks could not run.

## Check

- Run the same plan repeatedly and with different worker counts,
  per-scanner parallelism, batch sizes, and input orderings. The semantic
  digest, per-case results, and aggregates must be identical.
- Timestamps and host timing diagnostics are non-semantic and must be
  excluded from the digest; confirm they cannot leak in.
- Canonical serialization: documented key order and number encoding; no
  hashing of map iteration order or locale-dependent sort; defined behavior
  for absent versus null, non-finite floats, negative zero, and large
  integers.
- Nondeterministic scanner output is recorded as instability in the artifact.
  It must not be sorted or deduplicated away when the differences are
  meaningful, and it must not make the run silently "complete".
- Replay rejects changed inputs, settings, or identities; a replay count
  greater than one is a stability check, not extra samples.
- Failure paths (timeout, cancellation, scanner error) yield stable reason
  codes with bounded safe metadata and the same digest across schedules.

Use the smallest synthetic corpus that exercises the property, with a
fake or inert scanner that can emit controlled out-of-order and unstable
output. Report each property as `holds`, `violated` (with the minimal
reproduction and file/line), or `not assessable`.
