# ADR 0001: Rust-first engine and pinned TypeScript oracle

- Status: accepted for the bootstrap phase (P1, issue #2); subject to review.
- Date: 2026-10-02
- Related: epic #1; benchmarks issues #661 to #666; file-level inventory in
  [ownership-map.md](../migration/ownership-map.md).

## Context

PII measurement exists today as a TypeScript evaluator inside
`redact-secret-benchmarks`, interleaved with Redact Secret qualification
policy and with substrate code shared with the credential domain. The epic
requires a scanner-neutral, bounded, deterministic engine with a standalone CLI.
The benchmarks issues #661 to #666 already say "Rust-first engine required" and
"pinned TypeScript remains a compatibility oracle" and forbid an intermediate
TypeScript engine.

## Decision

1. **Rust-first.** The measurement engine is implemented directly in Rust in
   this repository. No TypeScript extraction step, no shared TypeScript
   package, no transpilation of oracle code. Node and Python appear only as
   scanner shims for scanners that run in those runtimes.
2. **The TypeScript evaluator is a pinned behavioral oracle**, not a source of
   truth and not a dependency. Pin:
   `redact-secret/redact-secret-benchmarks` commit
   `4b846967346505baca11e0b98cab1475fbce6773` (develop head on 2026-10-02).
   - Oracle trees are read only from that exact commit (detached worktree or
     archive). An unpinned checkout is never used for parity work.
   - No Rust crate imports, vendors or links oracle code. Rust tests may consume
     oracle-produced synthetic observations once their contract is frozen (P2)
     and reviewed (P9).
   - Moving the pin requires a new ADR that records the new commit and the
     behavioral differences found, so that parity differences stay attributable.
3. **Legacy semantics are a named compatibility protocol.** Behavior needed for
   parity (for example first-overlap selection) is reproduced only in
   `pii-eval-compat` or a declared compatibility mode, and a canonical change
   requires a separately versioned protocol revision and difference report
   (ARCHITECTURE.md). The seven methods and ten `pii-v1` metrics are preserved
   by name; their inventory is in the ownership map.
4. **Ownership split.** `pii-eval` owns neutral measurement. Benchmarks keeps
   thresholds, support status, accepted tradeoffs, activation acceptance,
   product populations and publication. `private-custodian` keeps protected
   authorization, budgets, isolation and disclosure. Shared-substrate code is
   not moved wholesale; a minimal neutral behavior is re-implemented and
   conformance-tested.
5. **No shared crate with `credential-eval`** for now. A common crate is
   considered only after a neutral contract exists and both consumers have
   proven it, and then it is pinned.
6. **Crates are internal.** The five workspace crates are not consumer
   contracts; consumers integrate through versioned artifacts and the CLI.

## Mapping to benchmarks issues

Benchmarks issues remain open on their side as inventory, handoff, acceptance
or consumer deliverables (their own text says so). The `pii-eval` issues named
below carry the engine work. The mapping follows the "Rust-first implementation
ownership" sections recorded on those issues on 2026-10-02.

| Benchmarks issue | Purpose | pii-eval implementation owner | Notes |
| --- | --- | --- | --- |
| #661 Define PII evaluation ownership and freeze migration contracts | Inventory, ADR, file-level ownership map, contract freeze | #2 (P1) inventory/ADR/map; #3 (P2) contracts | #661 acceptance also asks that existing fixtures validate against the frozen contracts (P2) and that a target repository/access/pinning handoff be defined (this ADR plus P12). |
| #662 Extract product-neutral PII execution, methods and accounting | Generic execution, methods, normalization, ten metrics | #4 (P3 matching/range/axes), #5 (P4 accounting/metrics), #6 (P5 seven methods), #8 (P7 bounded execution/artifacts), #9 (P8 CLI) | `qualification.ts` and `profile.ts` stay split: neutral calculation here, verdicts in benchmarks. Substrate is handled as a seam, not moved. |
| #663 Define PII scanner adapters, activation provenance and validator observations | Adapters, activation/config identity, validator observations | #7 (P6) | Product activation acceptance and candidate binding stay in benchmarks. |
| #664 Prove PII dual-run parity on frozen synthetic populations | Old vs new engine on identical inputs, zero unexplained differences | #10 (P9) | Needs #662/#663 equivalents (P3 to P8) first. |
| #665 Consume pii-eval artifacts for product qualification and publication | Benchmarks reads validated artifacts instead of evaluator internals | #13 (P12), plus private-custodian #12 | Consumer work in benchmarks; this repository provides the handoff and artifact contract. |
| #666 Switch PII authority and retire legacy execution after rollback validation | Authority switch, rollback rehearsal, legacy retirement | #10 (P9) evidence, #13 (P12) handoff, private-custodian #12 | Retirement is gated by benchmarks' recorded oracle exit; this repository never deletes oracle code. |

`pii-eval` P10 (#11, performance) and P11 (#12, internal GitHub App) have no
direct benchmarks counterpart. The numbering differs between the two
repositories (benchmarks P1 to P6 versus pii-eval P1 to P12); issue numbers, not
P-labels, are the stable key.

## Consequences

- Behavior preserved from the oracle is verified by same-observation replay and
  by independent hand-checkable vectors, not by reading oracle source.
- Until P9 completes, no consumer may treat Rust output as authoritative and no
  parity, accuracy, speed or security claim is made by this repository.
- The oracle remains operational in benchmarks until its caller-based exit is
  met; pii-eval does not coordinate its deletion.
- Re-implementation cost is accepted in exchange for a clean neutral boundary
  and no circular repository dependency.

## Alternatives considered

- **Extract the TypeScript engine into a package first, then port.** Rejected:
  adds an intermediate engine and a second migration, contradicting #662.
- **Keep the engine inside benchmarks.** Rejected: leaves product policy and
  measurement coupled and blocks the standalone CLI and protected execution
  model.
- **Share a Rust framework with `credential-eval` now.** Rejected: contracts
  differ (credential scoring versus two PII axes) and no neutral contract is
  proven; premature coupling.
- **Track the oracle's moving branch.** Rejected: differences would not be
  attributable.

## Open items

- The target repository access and pin handoff is partly addressed here (pin,
  read-only access, no imports); the consumer-facing handoff is P12.
- The mixed-split files in the ownership map need explicit decisions in P2.

## Update (P9)

Parity work reads the oracle only at the pin, through `gh api` by commit, and
verifies it (commit id, blob ids against the pinned tree, tree digest) before use;
see [ADR 0012](0012-oracle-parity-and-migration-evidence.md) and
`tools/oracle-parity/`. The pin did not move.
