# Handoff to benchmarks #665 and #666 (artifact consumer and cutover)

Status: written for P12 (pii-eval issue #13). It is a document, not a comment on
any other repository: pii-eval posts nowhere else. The maintainer or the
orchestrator may link it from
[redact-secret-benchmarks#665](https://github.com/redact-secret/redact-secret-benchmarks/issues/665),
[#666](https://github.com/redact-secret/redact-secret-benchmarks/issues/666) and
[private-custodian#12](https://github.com/redact-secret/private-custodian/issues/12).

pii-eval owns measurement and its evidence. It does not decide that the oracle may
be retired, set thresholds, assign support status, authorize protected runs or
publish protected results. Everything below is evidence and instructions for
benchmarks' own acceptance; benchmarks keeps product policy, populations, the cutover
decision, the rollback rehearsal and retirement. Companion documents:
[custodian boundary](../custodian-boundary.md),
[ADR 0014](../adr/0014-custodian-boundary-and-consumer-contract.md),
[parity handoff for #664](benchmarks-handoff-664.md) (toolchain, lockfile,
scanner and oracle identity tables, guarded by a test),
[parity report](oracle-parity-report.md), [CLI contract](../cli.md).

## 1. Identities to pin

| Item | Value |
| --- | --- |
| Engine | `pii-eval` version `0.0.0` (bootstrap). There is **no release tag and no public binary**; CI publishes an internal, unsigned engine artifact per run with `build-info.json` (docs/ci-artifacts.md). The candidate is the commit that contains this file: record `git rev-parse HEAD` of the checkout, the SHA-256 of `Cargo.lock` and of the binary you built (`cargo build --release --locked`, then `shasum -a 256 target/release/pii-eval`) next to every result |
| Protocol | `pii-v1` revision 2 (canonical); rules `pii-v1-canonical` (matching), `pii-v1-canonical-accounting`, `pii-v1-wilson-exact`; revision 1 is the legacy compatibility protocol, readable and not verifiable |
| Public artifact | schema `pii-eval.public-synthetic-artifact` `1.1`, or `1.2` when it carries the optional product projection ([benchmarks-handoff-664.md section 7](benchmarks-handoff-664.md#7-schema-12-the-product-projection), [ADR 0016](../adr/0016-product-projection-and-schema-1-2.md)); the only artifact a consumer reads |
| Internal artifact | schema `pii-eval.run-artifact` `1.1`; never consumed outside the party that ran it |
| Other documents | `pii-eval.corpus-snapshot`, `pii-eval.run-manifest`, `pii-eval.observation-set`, all `1.1`; committed JSON Schemas under `schemas/` with a drift test |
| Digest | `pii-eval-semantic-digest/1` over the canonical `semantic` body with the domain `schemaId/major.minor` (ADR 0003); bare lowercase hex SHA-256 |
| CLI output | `pii-eval-summary/1` (one JSON line on stdout), frozen exit codes 0 to 11 |
| Job context | `pii-eval-job-context/1` (custodian-supplied, grants nothing) |
| Consumer pins | `pii-eval-consumer-pins/1` and report `pii-eval-consumer-report/1`, the example's own formats ([examples/consumer/README.md](../../examples/consumer/README.md)); not engine contracts |
| Scanner, adapter, oracle pin | See the identity tables of [benchmarks-handoff-664.md](benchmarks-handoff-664.md); they are the ones a test keeps current |

A population is identified by `populationId`, `populationVersion` and
`populationDigest` (the snapshot's semantic digest) and one run measures exactly one
population. A candidate run says `candidate`; a result is `released` only when the
scanner package is the released tree (`product.kind`). Public-synthetic and protected
evidence are separate classes and denominators.

## 2. What benchmarks consumes and how (#665)

1. **Pin**: record, from a run you qualified, the artifact digest, manifest digest,
   population identity and the scanner identity (candidate or artifact digest,
   configuration digest, activation digest, adapter, version), plus engine and
   protocol identity. `examples/consumer/fixtures/pins.json` is a worked example.
2. **Verify, do not import**: `examples/consumer/consume.mjs` is a dependency-free
   reference (standard library only; it imports no pii-eval code and a test enforces
   that). It recomputes the digest, matches every pinned binding exactly, refuses
   wrong, stale (superseded) and mismatched artifacts with explicit reason codes,
   never reads the internal artifact or a legacy schema 1.0 document, composes
   populations side by side without pooling, and decides nothing. Re-implement its
   steps in benchmarks' own client; do not take it as a dependency.
3. **Recompute when you hold the snapshot**: `pii-eval validate ARTIFACT --snapshot S
   [--manifest M]` runs the accounting verifier over the rows (exit 0, `verification:
   verified`). The consumer example reads only the public projection and cannot.
4. **Protected evidence** is not an engine artifact at all. It arrives as a
   custodian-signed projection envelope plus the signed revocation feed, verified by
   the steps in private-custodian's `docs/benchmarks-integration.md` (section 2).
   That verification, the freshness and the revocation are benchmarks' and the
   custodian's; the engine contributes nothing to them. Never read a private ledger
   from benchmarks CI (the custodian's contract and the #665 text).

### #665 acceptance text mapped (read 2026-10-03)

| #665 | State | Evidence or gap |
| --- | --- | --- |
| Replace benchmark-side generic PII execution with artifact consumption; do not import evaluator internals | Mechanism provided | The consumer example and its enforcement test; the benchmarks client is benchmarks' deliverable (**not done here**) |
| Update `scripts/publish-pii-support.ts`, publication inputs and `web/services/domains.ts` | **Open (benchmarks)** | Not in this repository |
| Preserve ten metric definitions and values with denominator, interval and mode, method coverage, population comparison identities | Mostly carried | Per scanner: ten metrics with integer counts, effective N, point and Wilson bound or the withheld reason, method coverage, population counts, identities. **Not carried by schema 1.x:** the oracle's per-family and per-view projections (`benignByControlClass`, `evidenceByClass`, `contextByLanguage`, `contextRoster`, the evidence block; ADR 0005 A7, [664 handoff](benchmarks-handoff-664.md) section 5), the diagnostic-balanced and benign-heavy-stress views (an external roster in the kernel, not in artifacts), and the run **mode** (`official` or `exploratory` appears in the CLI summary, not in the artifact). An additive schema 1.2 is the route if benchmarks needs them (ADR 0008 section 9) |
| Refuse mismatched or stale artifacts; missing evidence stays not-measured | Provided | Consumer example: `missing` populations, `superseded`, `incomplete-measurement`; the engine records `not-measured`, never a pass |
| Released and candidate paths correctly bound; no candidate mislabeled released | Provided for artifacts | `product.kind` in the scanner identity, pinned; test `a candidate result is never accepted as released` |
| Sanitized publication contracts and immutable artifact commit marker preserved | Provided | The public artifact has no text, seed, raw output or finding; `run-artifact.json` is written last and a directory without it is incomplete; the writer never overwrites by default (docs/cli.md) |
| Protected consumption verifies signatures, bindings, revocation, freshness | **Not an engine matter** | Custodian bridge; see section 2, item 4 |
| Current support policy reproduced | **Open (benchmarks)** | Support policy is not in this repository |

## 3. Migration report

The parity evidence of P9 is the migration report: [oracle-parity-report.md](oracle-parity-report.md),
`fixtures/oracle-parity/report.json`, and the summary and open items in
[benchmarks-handoff-664.md](benchmarks-handoff-664.md). In short: on one frozen
synthetic population the compatibility protocol reproduces the pinned oracle's own
output with zero differences (540 outcome rows, 181 metric comparisons, 660
statistics vectors); every canonical-revision difference is classified and none is
unexplained; canonical results are invariant to input order, worker count and
repeats; one pinned real scanner version was checked on one platform (opt-in). This
is evidence for benchmarks' acceptance, not a cutover. Not covered, and stated there:
the product-owned plans (oracle-plan, qualification-plan, diagnostic-balanced,
benign-heavy-stress populations), protected populations, release qualification.

## 4. Rollback

pii-eval produces additive, immutable documents and never modifies the oracle or
the benchmarks repository, so rolling back is a benchmarks action and removes nothing
here.

Steps marked **(engine side)** can be done and checked from this repository;
steps marked **(benchmarks-owned, unverified)** are described only as what must
happen. No setting, script or workflow name of benchmarks is asserted here, and none
of the benchmarks-owned steps was run or checked by pii-eval.

1. **(engine side) Stop consuming revision-2 artifacts.** Remove the pii-eval pin file
   from the consumer and delete or ignore the pii-eval output directories
   (`manifest.json`, `observation-*.json`, `run-artifact.json`,
   `public-synthetic-artifact.json`); nothing else in this repository references them,
   and `pii-eval` itself is not installed anywhere (it exists only as internal CI artifacts, docs/ci-artifacts.md). To
   quarantine one artifact instead of all, add its digest to the pin's
   `retiredArtifactDigests` (and its manifest digest to `retiredManifestDigests`): the
   example consumer then reports `artifact-superseded` rather than "unknown"; verify
   with `node examples/consumer/consume.mjs --pins PINS ARTIFACT` (exit 1, reason
   listed). A defect is fixed by a new protocol or schema revision and a new digest,
   never by editing a published artifact.
2. **(engine side) The oracle plan is unchanged.** The oracle is the commit
   `4b846967346505baca11e0b98cab1475fbce6773` of redact-secret-benchmarks; nothing in
   this repository modifies or deletes it (ADR 0001). To re-establish what that plan
   produces without pii-eval, check out that commit in a benchmarks checkout and use
   its own commands; which commands and settings are benchmarks' to name. The
   compatibility protocol evidence for the same inputs is
   `fixtures/oracle-parity/` (`cargo test -p pii-eval-cli --locked --test oracle_parity`).
3. **(benchmarks-owned, unverified) Authority switch.** Whatever records which engine
   is authoritative for PII is returned to the oracle path and the change recorded
   (the #666 text asks to "record the active PII source" and to rehearse rollback).
   Which file or setting that is, is not known here.
4. **(benchmarks-owned, unverified) CI.** Measurement that was moved to artifact
   consumption is moved back, or the consumer step is disabled, in whatever workflow
   benchmarks used. pii-eval can contribute only the scanner-free checks
   (`pii-eval validate ARTIFACT --snapshot SNAPSHOT`, the consumer pin check).
5. **(custodian-owned, unverified here) Protected populations.** Rollback follows the
   custodian's rules: a population moves whole to one authority, rollback preserves
   every receipt and never resets a budget (private-custodian ADR 0092,
   `docs/legacy-migration.md`), and no protected data is rerun.
6. **(benchmarks-owned) Rehearsal: not performed.** The rollback rehearsal is a #666
   acceptance item; its commands and resulting pin file are benchmarks' evidence.

## 5. Compatibility inventory and retirement gate

Compatibility code is isolated and removable. This is what exists and what must stay
until retirement. **The decision to retire belongs to benchmarks** (recorded oracle
exit, caller inventory, rehearsed rollback, #666); pii-eval changes nothing here.

| Item | Paths | Used by | Must stay until | Removal |
| --- | --- | --- | --- | --- |
| Compat crate: `legacy-first-overlap` matching, `legacy_accounting` (binary64), `legacy_any_row_passes` | `crates/pii-eval-compat/` | The oracle-parity suite and the kernel/compat difference tests (dev-dependency of the CLI crate and the smoke test only) | The oracle exit: while benchmarks may still need to reproduce or re-run the compatibility protocol against the oracle | Delete the crate, its workspace member and dependency lines in `Cargo.toml`, the dev-dependency in `crates/pii-eval-cli/Cargo.toml`, the compat references in the files of the reference list below, and the tests below |
| Oracle parity evidence | `fixtures/oracle-parity/`, `tools/oracle-parity/`, `crates/pii-eval-cli/tests/oracle_parity*.rs`, `crates/pii-eval-cli/tests/parity/`, `crates/pii-eval-cli/tests/real_scanner.rs`, the CI steps named "Oracle parity" | Benchmarks' parity acceptance (#664) and any re-run | Parity acceptance and the oracle exit | Delete with the compat crate; the committed export is the only reproducible record, so archive it first |
| Legacy revision-1 readability (not in the compat crate) | `ProtocolIdentity::LEGACY_V1` and the revision-1 paths of `pii-eval-contracts`, kernel verifier `UnsupportedRevision`, CLI exit 11 `valid-legacy-not-verifiable`, `compare` refusal `legacy-protocol-revision` | Anyone holding stored revision-1 documents | Until no revision-1 document is consumed. This is a **schema-major decision separate from the compat crate** | Not removable by deleting compat; needs its own ADR and a major version |
| Oracle seed compatibility (not in the compat crate) | `legacy_contract_seed` in `pii-eval-kernel` (methods) | Variant provenance for oracle-derived populations | Until oracle-derived populations are re-authored or retired | Kernel change with a difference report |
| Pinned oracle identity | ADR 0001, `tools/oracle-parity/oracle-files.json` | The parity tooling | The oracle exit | Document the exit in a new ADR |

**Reference list for removing the compat crate** (generated on 2026-10-03 with
`grep -rIl "pii-eval-compat\|pii_eval_compat" . --exclude-dir=target --exclude-dir=.git --exclude-dir=graft`
and `grep -rIln "legacy-first-overlap\|legacy_accounting\|legacy-accounting" crates schemas docs/adr README.md ARCHITECTURE.md`;
**re-run both before removing anything**, the list is not guarded by a test). Code and
configuration to edit:

- `Cargo.toml` (workspace member and dependency lines, 8 and 23), `Cargo.lock` (regenerate, never hand-edit), `crates/pii-eval-cli/Cargo.toml` (dev-dependency, 30)
- `crates/pii-eval-cli/tests/dependency_policy.rs` (crate name lists at about 120, 251 and the guard `only_the_cli_test_graph_reaches_compat` at about 417)
- `crates/pii-eval-cli/tests/oracle_parity_docs.rs`, `tests/smoke.rs`, `tests/parity/{report,compare,rows}.rs` (users of the crate; delete or rewrite with the parity suite)
- `.github/workflows/ci.yml` (line about 50, `cargo test -p pii-eval-kernel -p pii-eval-compat`, and the "Oracle parity" steps)
- doc comments that name the crate or the legacy rules: `crates/pii-eval-contracts/src/protocol.rs`, `crates/pii-eval-kernel/src/{lib,matching,stats}.rs`, and the registry text `schemas/registry/pii-v1.registry.json` (a schema-registry text change: regenerate and re-run the drift test, and check whether it changes a digest)
- the crate itself: `crates/pii-eval-compat/` (`src`, `tests`, `Cargo.toml`)

Documents to update in the same change: `README.md`, `ARCHITECTURE.md`, `CONVENTIONS.md`, `AGENTS.md`, `docs/dependency-policy.md`,
`docs/migration/{ownership-map,benchmarks-handoff-664,oracle-parity-report,consumer-handoff-665-666}.md`, ADRs 0001, 0004, 0005, 0008, 0012
(ADRs are history: add a superseding note rather than rewriting them), `.agents/skills/oracle-parity-check/SKILL.md`, and the generated
`fixtures/oracle-parity/report.json`. After removal, `cargo test --workspace --locked` and the two greps must show no remaining reference
outside archived ADRs.

**Retirement gate (downstream exit criteria, owned by benchmarks).** Compat is
removed only when all of these are recorded by benchmarks: the bounded oracle period
has ended and the exit is recorded (#666); the caller inventory shows no remaining
consumer of the compatibility protocol or of revision-1 documents; parity is accepted
(#664) and the evidence archived; the rollback was rehearsed; specialized and shared
consumers have been checked; and the authority switch names a pinned pii-eval
commit and digests. A credential authority setting does not authorize PII retirement
(#666). pii-eval then deletes the items above in one change and updates this table
and the README. Until then they stay, and no compatibility behavior is promoted into
the canonical model.

## 6. What remains with whom

| Owner | Open |
| --- | --- |
| benchmarks (#665) | The artifact client, `publish-pii-support.ts` and `domains.ts` changes, support policy reproduction, the product-owned populations as snapshots (one population per run), per-family/view and mode needs (route: schema 1.2), custodian bridge verification |
| benchmarks (#666) | Oracle period and exit, rollback rehearsal, authority switch record (tag or commit, digests, populations, policy revision), moving repetitive measurement out of PR builds, retirement under section 5 |
| private-custodian | The engine launcher contract (worker-job to run to `worker-result/1`), the aggregates delivery and strata labels, the roster unit, candidate identity for a package tree, an isolation self-check that includes Node, receipt assembly ([custodian boundary](../custodian-boundary.md), section 6) |
| pii-eval (follow-up) | `pii-eval worker --job` launcher once the open questions are answered; schema 1.2 if benchmarks needs the missing projections; a release tag, a signed or attested binary and a longer retention when a release process exists |
