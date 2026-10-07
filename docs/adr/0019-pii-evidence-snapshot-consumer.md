# ADR 0019: Consuming pii-evidence snapshots

- Status: accepted (redact-secret/pii-evidence#9, part of pii-evidence#1; coordinates #34); subject to review.
- Date: 2026-10-07
- Related: [ADR 0002](0002-freeze-pii-contracts-v1.md) (change rules),
  [ADR 0003](0003-canonical-serialization-and-semantic-digest.md),
  [ADR 0007](0007-method-generation-and-variant-provenance.md) (id preimage convention),
  [ADR 0009](0009-bounded-execution-and-artifact-writing.md), [ADR 0010](0010-standalone-cli-workflows.md),
  [ADR 0017](0017-not-established-type-identity-and-schema-1-3.md),
  [ADR 0018](0018-not-established-range-and-schema-1-4.md),
  [docs/evidence-consumer.md](../evidence-consumer.md),
  [hand-off](../migration/pii-evidence-handoff.md). Implementation:
  `crates/pii-eval-cli/src/evidence/`, `crates/pii-eval-cli/src/evidence_main.rs`,
  `tools/pii-evidence/`.

## Context

`pii-evidence` publishes immutable, public snapshots of authored PII/PHI evidence under
`pii-evidence-consumer-contract` version 1: a directory of JSON files bound by a manifest with per-file digests, a
content digest, an id derived from both, counts and coverage. It owns the evidence and no scanner or policy field. This
repository measures scanners against corpus snapshots (`CorpusSnapshot`, one identified population per run) and owns no
canonical truth. The first end to end loop is `snapshot -> pii-eval -> reproducible measurement artifact`, with no
protected infrastructure.

Nothing in the repository read an evidence snapshot. The corpus contract differs from the evidence model in four ways
that matter: identifiers (`Id` forbids `/`), the sensitivity vocabulary (`context-dependent` against
`not-established`), occurrences (a pii-eval occurrence has a method and, until schema 1.4, a range; an evidence fixture
may have no span), and fields with no counterpart (contexts, the `phi` domain, roles, claims).

## Decisions

### 1. A loader that verifies everything before it maps anything

`evidence::verify` takes the bytes of a snapshot directory and a pin and refuses on the first failure, in the order of
[the verification list](../evidence-consumer.md#verification-order). The contract name and version are read first and an
unknown one is never read further. Identity is compared with the pin before any content check, so a wrong snapshot is
refused as a wrong snapshot. The strict reader (duplicate keys, floats, integer range, depth) is a small own reader because the
contracts' parser refuses `null` and the evidence taxonomy contains one; it is local to the evidence module, so no
contract document's strictness changes. Reading the directory is separate and bounded (`evidence::files`).
Neutrality (no scanner, detector, support, threshold or score key) is enforced with the producer's own key rule, and the
population rule refuses anything not `public` and any fixture without a population.

Considered: calling the producer's `verify-dir` (Node) from the engine. Rejected: the engine must not spawn processes
and a consumer is required to need only the snapshot files and the contract.

### 2. A separate binary, not a sixth command

`pii-eval-evidence` (`verify`, `import`, `plan`) is a second binary of `pii-eval-cli`. docs/cli.md says the five
commands are the only ones and that is a contract scripts and the custodian depend on; a population import is an
authoring step before `run`, not a measurement command. No dependency was added (`Cargo.lock` is unchanged), the kernel
and contracts are untouched, and the pure parts take bytes, so tests need no filesystem. Fetching the release is a Node
tool (`tools/pii-evidence/fetch-snapshot.mjs`, `gh`), outside the engine like the other tooling.

### 3. The unit of measurement is the fixture; the mapping is a versioned rule

The pii-eval variant is the evidence fixture, byte for byte; the pii-eval case is the evidence case, split into a
located and a range-less case so unlocated variants never make located accounting `unresolved`. The rule
`pii-evidence-to-corpus` revision 1 and every decision and loss are in the table of
[docs/evidence-consumer.md](../evidence-consumer.md#mapping-rule-pii-evidence-to-corpus-revision-1). Principles, in order:

1. Never assert more than the evidence asserts. A value pii-eval cannot anchor is weakened to `not-established`
   (observed `unresolved`, `review-required`), never invented and never dropped.
2. Every weakening is recorded per variant (`binding.json`), with the authored value next to the mapped one, so the
   loss is countable and the binding is a digest-bound document.
3. Use pii-eval's existing states. No scanner field, threshold, support state or detector id enters the corpus (the
   corpus contract has none), no expectation is edited to match a scanner, and the protocol, the outcome lattice and the
   schema are unchanged.
4. Ids derive from the evidence ids with a domain-separated, length-prefixed SHA-256 (the ADR 0007 convention), so the
   corpus does not depend on a lossy slug.

### 4. Public, released, pinned, with execution and replay recorded apart

The measurement uses the one real adapter the repository ships and runs it in official mode with every pin, as
`released`, with the platform addon and the WebAssembly package pinned by tree digest in the run configuration. The
record (`provenance.json`) separates the execution (a live process; the observation set) from the replay (artifacts
re-derived from the observation set, no scanner launched). CI replays the committed observation set and validates the
committed artifacts against the corpus the importer re-derives; the live execution stays manual because it needs the
public registry.

## Protocol and contract follow-ups (not made here)

None is needed to run. These are what the decisions above give up, stated so an owner can decide:

1. **A variant-level negative expectation.** An evidence case may say "this text has an invalid, non-sensitive value"
   without a span. pii-eval can carry that only as `not-established`. A text-level expectation (no located occurrence,
   findings are false positives) would need a protocol revision with a difference report (ADR 0002). It would make 17
   `identity-weakened-no-span` and 19 `sensitivity-weakened-no-span` variants exact.
2. **A `context-dependent` sensitivity value** distinct from `not-established` (11 flattened variants).
3. **Contexts and a domain axis** (`phi`) in the corpus, and a PHI-capable family vocabulary (37 variants each).
4. **Binding extra artifacts** (the platform addon, the WebAssembly package) into the scanner identity of the manifest,
   instead of only the run configuration.
5. **Replay of a sanitized-output scanner without the original artifact** (already deferred in ADR 0010).

## Consequences

- A wrong, incompatible, tampered, incomplete or non-public snapshot is refused with a stable reason code and
  nothing is written; the first refusal is the only output.
- The released snapshot maps to a schema 1.4 corpus of 55 cases and 139 variants, deterministically (a test pins
  the population and binding digests, so a change to the rule is visible and must bump the revision).
- Downstream consumers read the public artifact and the pin; they keep this population's denominator separate from
  any other population (the artifact is one population).
- The measurement says nothing about Redact Secret qualification, thresholds or support, and nothing about protected
  evaluation.
