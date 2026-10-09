# ADR 0020: PHI/context semantics, schema 1.5 and protocol revision 3

- Status: accepted for issue #37, subject to PR review.
- Date: 2026-10-09
- Related: ADR 0019 (lossy evidence consumer), ADR 0018 (unlocated occurrences),
  ADR 0008 (protocol 2), ADR 0005 (accounting).

## Decision

Schema 1.5 adds optional `evidence` to each corpus expectation and each internal
and public-synthetic outcome. It contains sorted unique `domains` (`pii`, `phi`),
exact authored `contexts` identifiers, `authoredSensitivity` and `textNegative`.
Domains remain independent of family identity, scanner capabilities, outcome and
product policy. PHI is an evidence axis, never a new detector family or verdict.
The public-synthetic projection copies this metadata; protected projection stays
forbidden. Binding checks reject altered or missing metadata.

Contexts are a justified projection of the producer's taxonomy: exact context
identifiers and their authored domain effects survive, and the bounded signal
(such as a patient-labeled field) stays in the unchanged input bytes. Taxonomy
claims, research status, prose and open questions remain in the immutable pinned
source, linked by the evidence binding. The evaluator does not invent medical
triggers or reinterpret a research-needed context as an established capability.
Identifiers are ASCII lowercase/digits plus `-_/`, 1..128 bytes, at most 64 per
expectation. Domains are nonempty, unique, sorted, at most two. No free-form
medical prose is copied into outcome metadata.

`context-dependent` is a distinct authored sensitivity. Its observation is
`unresolved` (`review-required`), or `not-measured` without sensitivity capability.
A binary scanner sensitivity flag cannot establish the missing contextual truth.
Its authored value survives the artifact through `authoredSensitivity`; it is
excluded from binary sensitive/non-sensitive denominators and remains unresolved
in measurable-share, like authored uncertainty. It requires evidence metadata.

Protocol `pii-v1` revision 3 binds matching and accounting revision 3 and the
unchanged Wilson statistics revision 1. Plans, observations and artifacts using
it require schema 1.5. A snapshot with these semantics cannot bind a protocol-2
plan. No old document is rewritten on read. Schemas 1.0..1.4 and protocols 1/2
remain readable; documents without the new values retain their version, digest
and bytes. `SchemaVersion::CURRENT` stays 1.1 for those constructors.

## Text-level negative measurement

`textNegative: true` explicitly makes an expectation text-wide, without a range.
It must assert invalid identity and/or non-sensitive context; valid identity,
sensitive context and any range are forbidden. A range-less positive assertion
still cannot be scored by inventing an occurrence. Cases remain `schema-only`;
no context trio, mutation frame, validator or competing jurisdiction is invented.

Findings with the expected family and, for jurisdiction-scoped assertions, the
expected jurisdiction are candidates. Unrelated families/jurisdictions are not.
Any candidate rejects an invalid identity. Any sensitive candidate rejects a
non-sensitive assertion, independent of order; a missing sensitivity flag cannot
prove absence. Missing family/jurisdiction labels leave absence unmeasured. No
finding proves identity rejection only with declared family and jurisdiction
support; no finding proves non-sensitive suppression only with declared
sensitivity support. Unsupported ranges retain the existing all-unmeasured
scanner behavior. Range is `not-applicable`, action is `not-measured`; no primary
located finding, span match or sanitized-output verification is invented.
Observed summaries count target candidates without including matched values.

The existing ten metrics and authored-case grouping remain. Text-negative rows
can contribute to non-sensitive-flag-rate and measurable-share through the
existing schema-only accounting rules; they do not add located range samples,
valid type samples, benign-method cases, or context trios. Replays do not add N.

## Mapping and migration

The default evidence import retains mapping revision 1 (or revision 2 for the
expanded kind vocabulary) byte for byte. Explicit `--mapping-revision 3` selects
population version 3, schema 1.5 and metadata-preserving mapping; `plan` selects
protocol 3 from that snapshot. This does not activate the proposed evidence v2
snapshot or change the downstream active denominator.

On pinned `public-pii-phi/2026-10-07/9d4e8e036bbb`, all five recorded losses become
zero: contexts 37, PHI 37, located context-dependent flattening 11, unlocated
identity weakening 17, unlocated sensitivity weakening 19. All 139 fixtures and
139 expectations remain. There are 33 authored context-dependent expectations
(including the previously unlocated ones) and 19 text-negative expectations.
This is representability evidence, not a scanner support or accuracy claim.

The deterministic mapping report is `docs/migration/phi-context-mapping-delta-37.json`.
The same-observation report is `docs/migration/phi-context-outcome-delta-37.json`:
it uses the committed, pinned released scanner observations, launches no scanner,
explicitly rebinds the plan to the named new population/protocol, and classifies
every changed outcome and metric: 19 changed rows, 120 unchanged, zero unexplained. Old measurements remain unchanged. This is a
protocol migration replay, not a fresh product measurement or an ordinary replay
under the old plan.

## Validation and consumer migration

Independent vectors cover target/unrelated findings, multiple candidates,
missing labels/capabilities, context-dependent uncertainty and invalid authorship.
Fresh fake-scanner executions of the entire pinned corpus agree for workers
1/2/4 and repeats, and observation replay reproduces internal/public bytes.
The fake scanner is conformance tooling, not product evidence. Contract binding
checks detect metadata tampering. Existing goldens and oracle replay demonstrate
unchanged old semantics. The reference Node consumer accepts schema 1.5 only
with exact caller-supplied new pins, and refuses it under old schema pins. Other
consumers must opt into schema 1.5, protocol 3 and population version 3 together;
retain their old pins for rollback. No support threshold enters the evaluator.
