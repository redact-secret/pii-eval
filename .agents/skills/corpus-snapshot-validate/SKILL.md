---
name: corpus-snapshot-validate
description: Validate a pii-eval CorpusSnapshot, RunPlan, or ObservationSet against the contract and data policy before any run. Use before executing or replaying a plan, and before accepting a new fixture. Read-only on the inputs.
---

# Corpus snapshot validate

Validate inputs before running anything long: validation costs far less than
a run, and `AGENTS.md` requires it first. Read `ARCHITECTURE.md` (Contracts
and identities), `CONVENTIONS.md`, and `SECURITY.md` (Data policy).

## Snapshot

- Population identity, visibility (`public-synthetic` or `protected`), and
  product identity (`released` or `candidate`) are present and independent.
- Every case has source lineage, expected ranges, context groups,
  language/jurisdiction, and generation rules with seeds and generator
  versions. Case/method grouping is explicit; context trios are complete.
- Expected ranges are valid half-open UTF-8 byte ranges on character
  boundaries within the case bytes.
- Deduplication follows an authored, versioned rule; no hidden extra rows.
- Outcome pairs are valid states of the lattice (`pass`, `fail`,
  `review-required`, `not-measured`); contradictory authored pairs are
  rejected.
- Content is synthetic or documented public-test material. Flag anything
  that could be real personal data or a real credential without opening it
  further or quoting it. A protected snapshot is not read here at all
  outside an authorized custodian run.

## Plan and observations

- The plan binds engine/protocol, snapshot, scanner binaries/packages,
  adapters, enable sets, configuration, seed derivation, replay count, and
  execution limits, with digests verified before use.
- Observations bind the exact input bytes, scanner/configuration identity,
  normalization version, and declared output capability (reported action,
  sanitized output, or unavailable). A changed input or setting fails.
- Paths are contained: no absolute or traversal paths, unexpected symlinks,
  or archive escapes. All counts, sizes, and limits are bounded.

Report violations by stable reason code and location only, never quoting
case text. Do not edit expectations to fit a scanner's output, and do not
authorize or start a protected run.
