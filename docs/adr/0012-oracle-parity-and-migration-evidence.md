# ADR 0012: Oracle parity, replay parity and real-scanner dual-run evidence

- Status: accepted for P9 (issue #10); subject to review.
- Date: 2026-10-03
- Related: [ADR 0001](0001-rust-first-and-oracle-pin.md),
  [ADR 0004](0004-order-invariant-pii-matching.md),
  [ADR 0005](0005-indexed-accounting-and-metric-statistics.md),
  [ADR 0006](0006-scanner-adapter-boundary.md),
  [ADR 0007](0007-method-generation-and-variant-provenance.md),
  [ADR 0008](0008-protocol-revision-2-and-schema-1-1.md),
  [ADR 0009](0009-bounded-execution-and-artifact-writing.md),
  [ADR 0010](0010-standalone-cli-workflows.md), epic #1.
  Report: [oracle-parity-report.md](../migration/oracle-parity-report.md).
  Handoff: [benchmarks-handoff-664.md](../migration/benchmarks-handoff-664.md).
  Tooling: `tools/oracle-parity/`. Suites:
  `crates/pii-eval-cli/tests/{oracle_parity,oracle_parity_cli,oracle_parity_docs,real_scanner}.rs`
  with the support code in `tests/parity/`.

## Context

The migration acceptance order (README) is: independent conformance first,
identical-observation replay parity second, same-pinned-scanner end-to-end parity
third, every difference attributed. P3 to P8 produced independent vectors and
hand-derived oracle expectations; none of them ran the oracle's code, and none
compared the engine as a whole. This ADR records how P9 does it, the
classification rules, one defect the comparison found, and what it does not
establish. It changes no contract, schema or protocol.

## Decisions

### P1. The oracle is fetched at the pin, verified, and never imported

`tools/oracle-parity/fetch-oracle.mjs` reads the files listed in
`oracle-files.json` from `redact-secret/redact-secret-benchmarks` with `gh api`
(commit `4b846967346505baca11e0b98cab1475fbce6773`), into a scratch directory.
It checks, in order, that the API reports the pinned commit, that every file's
git blob id equals the one the pinned commit's own tree lists (so transport
cannot change a byte), and that the sha256 over the sorted `path NUL blob-id`
lines equals the recorded tree digest. The local benchmarks checkout and any
unpinned revision are never read. No oracle source is copied into this repository
and no Rust crate imports it. The tree digest is recorded twice on purpose
(`oracle-files.json` and a constant in `oracle_parity.rs`), so a changed file list
or pin cannot pass by editing one place.

### P2. The oracle's own code runs, unmodified, under Node 22 type stripping

`export-oracle.mjs` runs the oracle's seven methods, operators, validators,
`executePiiEvaluation` (generation, scanner runtime with two replays and the five
scanner states, `interpretPiiOutcome`), `piiAccountingRowsFromEvaluation`,
`accountPiiRows` (the ten metrics) and `proportion` (the Wilson interval).
Node's module hooks (`hooks.mjs`) adapt only loading: `ajv` is a stub that
accepts every document, `.json` imports without an attribute load as JSON, and
the benign/collision evidence loader (`benign-collision-evidence.ts`) is a stub
without entries. No package is installed. Consequences, stated rather than hidden:
the oracle's JSON-schema checks do not run (its semantic checks do), and the
oracle's evidence-entry checks (ADR 0007 D8, D9) are not exercised.

### P3. One frozen synthetic input; the oracle export is committed

`fixtures/oracle-parity/input.json` (built by `make-input.mjs`) holds 37
authored synthetic cases covering the seven methods (the oracle's real English
and Korean context groups of 8 and 11 frames included), ten scanner recipes
(complete scanners with exact, missing, wider, narrower, wrong-family,
wrong-jurisdiction, family-less, sensitivity-less and multi-finding behavior in
several orders, plus unsupported, error, unavailable, unstable and a
rejected-range scanner), eight hand-built accounting vectors (including the
oracle's refusal of a benign case with several variants) and a statistics grid.
Values are synthetic or documented public-test shapes (`SYNTHETIC-dddd`, a
`.invalid` mailbox, SSN-shaped numbers, the standard's IBAN example). Case and
variant ids use `[a-z0-9-]` so the oracle's `localeCompare` agrees with a
byte-wise comparison, and every text starts with its case id so a frozen
observation can be keyed by text. The input is authored, never edited to match
an engine.

The export (`oracle-export.json`) holds only integers and strings: the
variants the oracle generated, each scanner's frozen findings **in emission order**
(the identical observation fed to both engines), the oracle's per-variant outcomes
and ten metrics (counts, effective N, status, and the interval as the
`toFixed` string), the vectors and 660 statistics vectors. Its provenance records
the oracle commit and tree digest, the Node and ICU versions, the adaptations, and
the sha256 of the input and of every script. `regenerate.sh` runs the oracle twice
and requires byte-identical output, then compares with the committed files (or
replaces them with `--update`). CI cannot reach the oracle repository: it runs the
comparison from the committed export and a test checks that the oracle pin, the
tree digest, the script digests and the input digest are unchanged.

### P4. Order of validation

1. **Independent conformance first** (already in place, extended). Hand-calculated
   and independent-implementation vectors: ADR 0004 `conformance.rs` and
   properties, ADR 0005 `stats.rs` with the Python `decimal` vectors and
   `accounting.rs`, ADR 0007 `methods_ids.rs`. P9 adds the legacy accounting port
   with its own unit checks (`to_fixed_mantissa` against known JavaScript results,
   the A3 and A8 switches), and the statistics grid below is an independent
   cross-check of the Wilson arithmetic against the oracle's binary64 code.
2. **Identical-observation parity.** The frozen observations go to the oracle
   (above) and to the Rust engine, through the legacy compatibility mode where the
   legacy protocol is promised and through canonical revision 2 otherwise.
3. **Same-pinned-scanner end-to-end parity** (P8 below).

### P5. What is compared, and how a difference is attributed

Nine layers (the report's table): `variant` (generated variants), `outcome-compat`
(oracle outcome against `legacy-first-overlap`), `outcome` (legacy against the
canonical matcher over the same findings), `accounting-compat` (oracle metrics
against the new `legacy_accounting` port), `accounting-rule` (oracle against the
kernel accounting over the **same** legacy rows), `accounting-canonical` (the
full canonical path), `statistics-compat`, `statistics`, `population`. Compared:
both axes, range states, observed summaries, case and variant identity, the seven
methods, the ten metrics with every count, effective N, status, point, bound and
withheld state, scanner failure states, case and row counts.

* **Compatibility layers promise equality** and the suite requires zero
  differences: the oracle, `legacy-first-overlap` and `legacy_accounting` agree on
  every outcome, metric and statistic, including `Number.toFixed` ties.
* **A difference of the canonical revision must be attributed by a
  counterfactual**, not asserted:
  * matching: reorder the findings so the canonical primary comes first and
    interpret again with the legacy rule. If that changes the legacy row, the
    legacy position rule mattered (`0004/D1`); if the reordered legacy row then
    equals the canonical row, that is all. Otherwise the only remaining cause
    under declared full capability is `0004/D3` (the primary reports no
    sensitivity, canonical says not-measured). Anything else is unexplained;
  * accounting: the port has three switches (A2 first-row eligibility, A3 distinct
    benign controls, A8 any-row pass). A metric difference is explained by the
    smallest set of switches that makes the port equal to the kernel on counts,
    status and effective N; if only the published interval differs it must be
    `0005/S1` (a one-unit difference at a point or bound whose exact value lies
    within 2e-12 of a rounding boundary; there binary64 may round the other way);
  * the full canonical path is the telescoping of those two steps, so its
    attribution is the union of the two;
  * a range the canonical matcher refuses (`0004/D6`) must actually fail
    `validate_range`; the oracle's runtime rejects an empty range as a scanner
    error, and the matcher must refuse the same finding.
* The D1 counterfactual only shows consistency with the canonical primary, so a
  second, independent check runs first on every attributed row: from ADR 0004
  section 3.2 and with its own arithmetic (`independent_primary_ok`), the primary
  must have the smallest (geometry rank, tightness, identity evidence) among the
  overlapping findings. A primary-selection defect therefore cannot hide as
  D1/old bug; a test forges wrong primaries and requires each to be refused.
  Variant ids are verified by recomputing the ADR 0007 digest, and operator ids
  and versions are compared; seeds (`0007/D5`, `D7`) are not compared here.
* The comparator is a pure function of the dataset. Negative tests corrupt a copy
  of the export (a count, a range state, an axis state, an observed count, an
  interval, a withheld state, a status, a variant id, a case family, a text, a
  strategy, an outcome filed under another variant, population counts, a frozen
  finding, a missing vector, a changed oracle refusal) and a tampered canonical
  row, and require each to be reported, so the comparison cannot pass vacuously.
  Compared-item counts are asserted equal to what the data holds.

### P6. Classes

Every difference carries one or more ids of the form `<ADR>/<row>` and each id has
one class. `unexplained` means no id applies and fails the suite.

| Class | Meaning | Ids |
| --- | --- | --- |
| intended versioned revision | A decided protocol change, recorded in an ADR with the reason; reproduced by the oracle's semantics only in the compatibility mode | `0004/D3` (no sensitivity value is not-measured), `0004/D6` (invalid ranges are refused), `0005/A3` (a benign case counts one sample), `0005/S1` (exact rational rounding), `0008/R3` (A8: all rows must pass) |
| old bug | Oracle behavior that no document defends and that depends on something incidental (emission order, locale); the canonical revision fixes it | `0004/D1` (first overlapping finding in emission order), `0005/A2` (eligibility from the first variant after a locale sort, all variants judged) |
| compatibility | A representation difference with no semantic effect | `0007/D1` (variant id `slot-digest`), `0007/D4` (authored variants carry no operator or seed) |
| new bug | A defect of the Rust engine found by the comparison | `N1` below (fixed in this change); none remain |
| unresolved | Observed, not decided | none |

`old bug` and `intended versioned revision` are both delivered by protocol
revision 2; the split records whether the oracle behavior was a decision (A8, D3)
or an accident (D1, A2). A8 is `0008/R3` because ADR 0008 owns the decision. A
future difference needs a new row with ADR text before it can be attributed.

Census at this commit (the report is authoritative): 0 unexplained, 0 new bug, 0
unresolved; 85 intended versioned revision, 32 old bug, 85 compatibility
difference instances, in nine layers over 54 variants, 10 scanners, 8 vectors and
660 statistics vectors (the numbers are instances of aspects, so a row that
differs on two axes counts twice). Every canonical-revision metric of the
scanners that report full capability and sensitivity (`parity-baseline`,
`parity-unsupported`, `parity-error`, `parity-unavailable`, `parity-unstable`,
`parity-badrange` and the real scanner) equals the oracle's exactly.

### P7. Finding N1: the method generator was stricter than the contract

The comparison could not generate the oracle's real context groups: the kernel's
`context-discrimination` generator refused any frame set that was not exactly one
frame per class (`context-frames-not-a-trio`, ADR 0007 D2) although ADR 0008 R5
had already relaxed the contract rule and the accounting index to at least one
frame per class and ADR 0007 section 11 recorded the item as resolved.
Classification: **new bug** (an inconsistency introduced by the P7 revision, not
an oracle behavior). Fix in this change: the generator accepts at least one frame
per class (`generate.rs`), with tests (`methods.rs`: four frames in three classes
are generated and a group missing a class is still refused; `methods_oracle.rs`:
the 8-frame group is compared like any other and ADR 0007 D2 leaves the census).
No contract, schema, digest or protocol value changed.

### P8. Real scanner (same-pinned-scanner, opt-in)

`tools/oracle-parity/real-scanner/run.sh` installs `@redact-secret/core`
0.1.0-beta.12 hermetically: `make-lock.mjs` writes a lockfile that holds only the
`@redact-secret/*` entries of the **oracle's verified lockfile** (version, resolved
URL, sha512 integrity copied verbatim) and `npm ci --ignore-scripts --no-audit
--no-fund` refuses any tarball that differs; nothing else is installed and no
install script runs. The oracle's own adapter (`scanners/candidate.mjs`
`loadCandidate`, with the wrapper of `scripts/observe-pii-populations.mjs`:
PII-family findings only) then observes the frozen population through the oracle
pipeline. The synthetic observation and the oracle's outcomes and metrics are
committed (`real-core-export.json`, with the package versions, integrities, the
lockfile digest and the platform) and are compared **in CI** by the same
comparator and engine pipeline as the synthetic scanners
(`real_scanner.rs`, test 1).

The live check (`real_scanner.rs`, test 2, `#[ignore]`d so CI reports it as ignored, never as passed; run with `-- --ignored`; it fails without `PII_EVAL_REDACT_SECRET_CORE_DIR`)
runs the Rust adapter, the Node shim and the engine over the same installed
package and requires every variant's observed findings to equal the oracle
adapter's, then the engine's metrics to equal the canonical accounting. It
passed at this commit on one host (macOS 26.5, arm64, Node v22.16.0, package
platform `darwin-arm64`, 54 variants, ten findings over the SSN, IBAN and mutation
cases; the pinned package tree digest matched). It is not part of CI: it needs the
public registry and a platform addon, and it was observed on one platform only.
On this corpus the scanner reported findings for the SSN-shaped values and the
IBAN only: the reserved-domain mailboxes and the `SYNTHETIC-dddd` references
produced none, so most email and reference cases are misses. That documents what
the pinned scanner did on a synthetic corpus; it is not a statement about the
product.

### P9. Invariance

Where the canonical protocol promises invariance it is tested on this corpus:
shuffling case order, scanner order, row order and every finding list leaves every
canonical metric unchanged; the engine's artifact has the same semantic digest at
one and four workers (the manifest, and so the plan digest, is the same: the host
only lowers the cap) and across repeats; the report is identical across two runs;
the comparison is identical across runs. The legacy mode is not invariant to
finding order (D1): the suite shows at least five variants whose legacy row changes
when the findings are reversed and none whose canonical row changes. The
compatibility protocol promises equality with the oracle on the emission order the
oracle saw, not order invariance.

### P10. The engine end to end

The comparator calls the kernel directly. `engine.rs` runs the real pipeline
(executor with fresh sessions per replay pass, assembler, kernel accounting,
contract sealing) over the same frozen observations through an in-process adapter
that replays them, for the eight scanners whose findings are valid ranges, and
requires: the artifact verifies against the snapshot and its accounting; its
population binding equals the snapshot's id, version, visibility and digest; every
scanner's status is the oracle's; every scanner's ten metrics equal the
comparator's canonical accounting bit for bit. `parity-midchar` and
`parity-badrange` carry ranges that a real adapter's normalization rejects as
malformed output before matching, so they are compared at the matcher only (D6).
`oracle_parity_cli.rs` then drives the built binary over the same population: the
documents written at one and four workers are byte-identical, `pii-eval validate`
verifies the run artifact, the manifest, the snapshot and the public artifact, and
`pii-eval replay` from the observation sets (and the original, because four
scanners did not complete) re-derives every document byte for byte, with exit 5
and `incomplete` as the CLI contract requires for a run whose scanners failed.

## What this does not establish

- Not a cutover decision. Rollback rehearsal, release qualification and the
  retirement of the oracle belong to benchmarks (README, ARCHITECTURE).
- No protected corpus was run and none may be: protected parity is through
  approved receipts under the custodian contract (private-custodian), which is
  out of scope here.
- Same-observation parity is over a synthetic population of 54 variants and 10
  scanner behaviors, not over the oracle's frozen evidence (`evidence/901/428/*`,
  not opened); that selection needs its own review.
- `0004/D2` (stored observation sets carry findings in canonical order, so legacy
  over a stored set can pick another first finding than the oracle did) is not
  exercised: the legacy mode was fed the emission order. Replaying stored sets for a
  legacy comparison needs the emission order carried (open item).
- Capability-aware differences (`0004/D4`, `D5`, `D11`) need a scanner that declares
  less; they stay covered by `crates/pii-eval-compat/tests/differences.rs`.
- The oracle's evidence, benign-class, evidence-class and context-language
  projections (`0005/A7`), the evidence-entry checks (`0007/D8`, `D9`) and the
  oracle's JSON-schema validation are not compared (stubbed or not carried).
- The oracle's `localeCompare` is reproduced only for the id alphabet used;
  the real-scanner run covers one pinned version on one platform.
- `Number.toFixed`, binary64 `sqrt` and division are reproduced in Rust floating
  point inside the removable compat crate. They agree with the oracle on all 660
  statistics vectors and every metric, which is evidence for the platforms and
  toolchains tested, not a proof for every host.

## Consequences

- New: `tools/oracle-parity/` (fetch, export, regenerate, real-scanner),
  `fixtures/oracle-parity/`, `crates/pii-eval-compat/src/legacy_accounting.rs`,
  `crates/pii-eval-cli/tests/{oracle_parity,real_scanner}.rs` with `tests/parity/`,
  the generated report, the handoff document. No dependency, contract, schema or
  digest changed; the Rust workspace gained no crate.
- Changed: `crates/pii-eval-kernel/src/methods/generate.rs` (N1) and its tests;
  ADR 0007 D2.
- CI runs the parity suite from the committed export and the syntax of the
  tooling; it never contacts the oracle repository or the npm registry.
- The compatibility crate remains removable: the CLI keeps it as a dev-dependency
  only, the parity suite is the heaviest user, and deleting it deletes the suite.

## Reproduction

```sh
# CI-equivalent, offline after the build:
cargo test -p pii-eval-cli --locked --test oracle_parity --test oracle_parity_cli --test oracle_parity_docs --test real_scanner
# Manual, needs gh access to the oracle repository and Node >= 22.6:
tools/oracle-parity/regenerate.sh "$SCRATCH"                 # verify the committed export
tools/oracle-parity/regenerate.sh "$SCRATCH" --update        # after a reviewed change
PII_EVAL_UPDATE_FIXTURES=1 cargo test -p pii-eval-cli --test oracle_parity   # refresh the report
# Manual, needs the public npm registry:
tools/oracle-parity/real-scanner/run.sh "$SCRATCH"           # prints the live-check command
```
