# Handoff to benchmarks #664: parity evidence, identities and mismatch handling

Status: written for P9 (pii-eval issue #10). It is a document, not a comment on
the benchmarks repository: pii-eval does not post there. The maintainer or the
orchestrator may link it from
[redact-secret-benchmarks#664](https://github.com/redact-secret/redact-secret-benchmarks/issues/664).

pii-eval owns measurement and its evidence. It does not decide that the oracle
may be retired, set thresholds, assign support status or authorize protected
runs. Everything below is evidence for benchmarks' own acceptance of parity;
benchmarks keeps the cutover, rollback and retirement decisions
([README](../../README.md), Migration acceptance; [ARCHITECTURE](../../ARCHITECTURE.md),
Validation and cutover).

Method, classification rules and limits: [ADR 0012](../adr/0012-oracle-parity-and-migration-evidence.md).
Generated results: [oracle-parity-report.md](oracle-parity-report.md) and
`fixtures/oracle-parity/report.json`.

## 1. Exact identities

A test (`oracle_parity_docs.rs`, `the_handoff_names_the_current_identities`) fails when
a value below no longer matches the repository, so this table cannot go stale
silently.

### Oracle (the baseline)

| Item | Value |
| --- | --- |
| Repository | `redact-secret/redact-secret-benchmarks` |
| Commit | `4b846967346505baca11e0b98cab1475fbce6773` |
| Oracle files read (40, listed in `tools/oracle-parity/oracle-files.json`), tree digest | `6f35613cc5a6a827f19609d8c3d22a56362c0f7f526553f17cc1bc4e9ec8a83b` |
| Oracle engine and profile | `PII_ENGINE_VERSION` `1.0.0`, profile `pii-v1` version 1 |
| Runtime of the export | Node `v22.16.0`, ICU `77.1` |

### Frozen artifacts (committed under `fixtures/oracle-parity/`)

| File | SHA-256 | What |
| --- | --- | --- |
| `input.json` | `f4ed904849e028c415490d852d0e655b8fc0b2331264b758c1922d641fd44333` | The frozen synthetic input (37 cases, 10 scanner recipes, 8 accounting vectors, statistics grid); population `parity-synthetic` v1, `public-synthetic` |
| `oracle-export.json` | `338a3f466a4c9157a557c2084b83a466d5dea39893f2a79dc54c117301036082` | What the oracle's own code produced on it: variants, frozen observations in emission order, outcomes, ten metrics, vectors, 660 statistics vectors |
| `real-core-export.json` | `9ae7e1a2647d816819e8935d656f0056ed70acd46a6e124b2e2cf875791aeb5f` | The real pinned scanner's synthetic observation and the oracle's outcomes and metrics over it |

### Protocol identities

| Item | Compatibility protocol | Canonical protocol |
| --- | --- | --- |
| Protocol | `pii-v1` revision 1 (legacy, readable, not verifiable by the engine) | `pii-v1` revision 2, schema 1.1 |
| Matching | `legacy-first-overlap` (`pii-eval-compat`) | `pii-v1-canonical` revision 2 |
| Accounting | `legacy-accounting` (`pii-eval-compat`, binary64 `toFixed`) | `pii-v1-canonical-accounting` revision 2 |
| Statistics | the oracle's `proportion` | `pii-v1-wilson-exact` revision 1 |
| Mechanics | `minDenominator` 4, `replays` 2, `intervalZ` 1.96, `intervalPrecision` 6 | the same values, recorded in the manifest |
| Methods | `type-validation` v2, `context-discrimination` v2, `pii-benign` v3, `jurisdiction-collision` v3, `mutation` v1, `reference-differential` v1, `schema-only` v1 | the same |
| Metrics | the ten `pii-v1` metrics | the same |

### Candidate (pii-eval)

| Item | Value |
| --- | --- |
| Engine | `pii-eval` version `0.0.0` (workspace version, bootstrap); the candidate is the pii-eval commit that contains this file. Record it as `git rev-parse HEAD` of the checkout (or the squash commit that merged P9) next to every result, and the digest of `Cargo.lock` and the binary |
| Toolchain | Rust `1.98.1` (`rust-toolchain.toml`, SHA-256 `887f9be066a15585a2c583578e84b0fcb541126d81546276bad3d2ff00d61167`), edition 2024, MSRV `1.85` (`workspace.package.rust-version`) |
| Dependency lock | `Cargo.lock` SHA-256 `e646a917c7dc8a5d5f5744bbfc56456661ebeb5505ac18788b7d5262f29a956a` (build with `--locked`) |
| CLI | `pii-eval run|replay|validate|compare` ([docs/cli.md](../cli.md)) |
| Scanner | `@redact-secret/core` `0.1.0-beta.12`, npm integrity `sha512-fDVwt2U7VFSKb/0ixSuU5e+TOGVaUnyR1sIYwgS4S6gMndFnaq0M7ikaqac8wnTMYfYO/LS12JayXXeKbhE4aw==` (the oracle lockfile's), extracted package tree digest `726421636189573bc76024ecf23ec6bd1d71fef6d8272e5da1b3967dee036d03` |
| Adapter | `redact-secret-core-node` version `1.0.0`, normalization 1, shim SHA-256 `21664407345b099d3f5e44db26bcfb037b2e981635dec0a7b5383b42b737e0a8`, activation `pii:global`, `pii:us` |
| Product identity | `released` for the lockfile package; a candidate needs its own tree digest (docs/cli.md) |

Identities that cannot live in a file of this repository, and how a consumer
obtains them: the **commit SHA** that contains this document (a document cannot
name its own commit; take `rev-parse HEAD` of the checkout, or the squash commit
of the merged P9 pull request) and the **digest of the binary** (there is no public release; CI
publishes an internal engine artifact whose `build-info.json` records the commit and
the binary's SHA-256 and which `tools/ci/verify-engine.mjs` verifies,
docs/ci-artifacts.md; or build with `cargo build --release --locked` and record
`shasum -a 256 target/release/pii-eval`, docs/cli.md). Record both next to every
result. The toolchain, MSRV and `Cargo.lock` rows above are checked by
`oracle_parity_docs.rs`, so a change to any of them fails CI until this table is
updated on purpose.

The scanner's configuration is the adapter's fixed parameters
(`detectorProfile=full`, `findingSource=pii-domain-only`,
`offsetUnit=utf16-code-units`, `sanitizedOutput=true`); a run records its digest.

## 2. What was proven, in the issue's order

1. **Independent conformance first**: P3 to P5 hand-calculated and
   independent-implementation vectors, plus the legacy accounting port's own
   checks and the statistics grid (ADR 0012 P4).
2. **Identical-observation parity**: the same frozen findings (in the order the
   oracle saw them) went to the oracle's own code and to the engine. The
   compatibility protocol reproduces the oracle with **zero differences** in
   outcomes, ten metrics, counts, effective N, statuses, withheld states and
   intervals (540 outcome rows, 181 metric comparisons, 660 statistics
   vectors); every canonical-revision difference is classified, **zero
   unexplained** (report).
3. **Same-pinned-scanner end-to-end**: the real package, through the oracle's own
   adapter, equals the engine's canonical accounting on every metric; the live
   Rust adapter observed the same findings as the oracle's adapter on all 54
   variants (one platform, opt-in; ADR 0012 P8).

## 3. Reproduce

```sh
# 1. Compare the engine with the committed oracle export (offline, CI-equivalent).
cargo test -p pii-eval-cli --locked --test oracle_parity --test oracle_parity_cli --test oracle_parity_docs --test real_scanner

# 2. Regenerate the oracle export and verify it equals the committed one (needs gh read access
#    to the oracle repository and Node >= 22.6; the oracle is fetched at the pin and verified).
tools/oracle-parity/regenerate.sh "$SCRATCH"

# 3. Real scanner (needs the public npm registry): hermetic install, oracle adapter, live Rust run.
tools/oracle-parity/real-scanner/run.sh "$SCRATCH"
```

Fresh checkout, no oracle access: step 1 needs only Rust (the pinned toolchain).
Never use an unpinned oracle checkout; never regenerate against a moved pin
without a new ADR (ADR 0001).

## 3a. benchmarks #664 acceptance text, mapped

Text of [#664](https://github.com/redact-secret/redact-secret-benchmarks/issues/664),
read on 2026-10-03, against what this repository proves:

| #664 | State | Evidence |
| --- | --- | --- |
| Identical pinned scanners/configurations, frozen public synthetic inputs or bound replay observations | Covered | The same frozen observations go to both engines (report); the real pinned scanner (ADR 0012 P8) |
| Case and variant identities/counts, seven methods, both axes, ten metrics, numerator/denominator, intervals, unmeasured/review-required/unstable states | Covered | Report layers `variant`, `outcome*`, `accounting*`, `statistics*` and the scanner statuses; review-required through `tv-unavailable` and `rd-unavailable` |
| Semantic digests | Covered for the engine; the oracle has none | Engine artifact digests are equal across runs (below); the oracle's accounting carries only an unresolved input commitment (report, not compared) |
| Oracle-plan, qualification-plan, diagnostic-balanced and benign-heavy-stress populations kept separately identified | Mechanism covered (schema 1.2); the product-owned plans are benchmarks' | One population per run, as before: benchmarks supplies each plan as its own snapshot. Inside one population artifact the optional schema 1.2 **product projection** carries per (scanner, view, family) rows for a caller-supplied roster of the four view ids ([section 7](#7-schema-12-the-product-projection), [ADR 0016](../adr/0016-product-projection-and-schema-1-2.md)). The parity population itself is still one synthetic population (`parity-synthetic`); no product plan was built or run here |
| Classification; no tuning | Covered | Report census, ADR 0012 P6, section 4 |
| Protected runs reuse approved receipts only | Not applicable | No protected corpus was run (custodian contract) |
| Committed reproducible report, zero unexplained | Covered | `fixtures/oracle-parity/report.json`, generated and compared in CI |
| At least two same-input runs with equal semantic digest | Covered | `oracle_parity.rs` runs the engine at one and four workers and again (equal artifact semantic digest); `oracle_parity_cli.rs` shows byte-identical documents |
| Wrong activation / candidate / population bindings rejected | Covered | Population: `a_manifest_for_another_population_scanner_configuration_or_artifact_is_refused` in `cli_run.rs` (`population-binding-mismatch`, exit 4). Candidate/product: `run_class_and_product_are_independent_identities_each_checked_against_the_manifest` (exit 4, `product`) and `every_provenance_mismatch_is_exit_4_before_any_scanner_starts`. Activation travels in the scanner configuration: a plan whose configuration or adapter version differs is exit 4 `scanner-plan` (the first `cli_run.rs` test above), and the running scanner's activation identity is checked at startup (`PinKind::Activation`, `crates/pii-eval-adapters/tests/process_adapter.rs`). Activation only: `a_manifest_that_changes_only_the_activation_selectors_is_refused_by_name` (`cli_run.rs`) changes nothing in the manifest but the enabled selectors (and the digest that follows them) and asserts the refusals by name: an operator manifest-digest pin (exit 4 `manifest-digest`), replay of the original observations (exit 4 `observation-set`, `configuration-binding-mismatch`) and validation of the original artifact (exit 4 `run-artifact`, `configuration-binding-mismatch`). A manifest with other selectors is a self-consistent *different plan*: run on its own it is accepted as such and records another activation digest and another artifact digest, so it can never pass for the original measurement. Schema 1.2 rows carry the same bindings and are refused when they differ from their artifact ([section 7](#7-schema-12-the-product-projection)) |
| No protected bytes in the report | Covered | Synthetic only; the report test asserts that no authored value appears |

## 4. Mismatch handling

Rules for whoever re-runs or extends the comparison (benchmarks, pii-eval, a
reviewer):

1. **Pin both sides and state the mode.** Oracle commit and tree digest, pii-eval
   commit, protocol revision, snapshot digest, scanner identity, configuration.
   If any identity differs unexplainedly, the comparison is **confounded**: report
   it as confounded and stop (release-regression-check skill).
2. **Same observation first, live scanner second.** A live-scanner difference is
   not interpretable until same-observation parity holds.
3. **Compatibility layers promise equality.** Any difference between the oracle
   and `legacy-first-overlap` or `legacy_accounting` is a defect of the port or
   of the harness. It is never excused as a protocol difference. Fix the port or
   record an unresolved item; do not widen a tolerance.
4. **Attribute every difference of the canonical revision to a classified id**
   (`<ADR>/<row>`, [report](oracle-parity-report.md)):

   | Class | What to do |
   | --- | --- |
   | intended versioned revision (`0004/D3`, `0004/D6`, `0005/A3`, `0005/S1`, `0008/R3`) | A decided protocol change. Benchmarks decides whether it accepts revision 2 for a consumer; until then it reads the compatibility protocol. Never "fix" a canonical value to match the oracle. |
   | old bug (`0004/D1`, `0005/A2`) | Oracle behavior that depends on emission order or locale; the canonical revision removes the dependence. A number that relied on it is reproducible only under the compatibility protocol with the same emission order. A consumer must not re-introduce it without a versioned decision. |
   | compatibility (`0007/D1`, `0007/D4`) | Representation only: variant ids carry a digest of case and slot (compare by slot), authored variants record no operator or seed. |
   | new bug | A defect of the engine. Open an issue in pii-eval with the minimal synthetic vector. N1 (the generator rejected the oracle's 8-frame groups) is the only one found and is fixed (ADR 0012). |
   | unresolved | Not decided; blocks acceptance of that item. None now. |
   | unexplained | Fails the suite. Never accepted. Re-run to exclude nondeterminism, then reduce to a minimal vector. |

5. **Do not tune.** No threshold, tolerance, case or scanner is changed or dropped
   to force parity; an expected result is never changed to match either engine;
   a legacy semantic bug is not fixed to reach or abandon parity without a
   versioned decision and a difference report.
6. **Sanitized reports only.** A report lists identities, enumerated states,
   integers and synthetic case ids; no input text, matched value or raw scanner
   output. For protected populations omit case ids.
7. **Protected corpora are out of scope.** Do not run them for parity. Any
   protected parity comes only from approved receipts through the custodian
   contract (private-custodian), which grants access, not pii-eval or this
   document.
8. **Row-level differences are reproducible.** Every difference in the report has a
   scanner, a case/variant (or a metric) and both values; re-run the one case with
   `cargo test -p pii-eval-cli --test oracle_parity` (the comparator is a pure
   function of the committed data).

## 5. Open items for benchmarks

- Replay of **stored** observation sets against the legacy mode needs the scanner
  emission order carried (`0004/D2`): a stored set holds findings in canonical
  order. Same-observation parity here used the emission order.
- The oracle projections `evidenceByClass`, `contextRoster` and the `evidence`
  block are not carried and were not compared (`0005/A7`). `contextByLanguage` is
  superseded by the language strata (every metric, every cell) and
  `benignByControlClass` by the optional roster-supplied control-class strata of
  schema 1.2 ([section 7](#7-schema-12-the-product-projection)); the oracle's
  numbers were not compared against them (the oracle's grouping differs, A3/A8).
- Population views are carried by schema 1.2 as the optional product projection
  (section 7). The product-owned view membership, thresholds and which view gates
  which family are benchmarks'; the engine only restates the measurement.
- The oracle's evidence-entry checks and JSON-schema validation did not run in the
  harness (`0007/D8`, `D9`; stubs, ADR 0012 P2).
- Replay without the original artifact is impossible for scanners that return
  sanitized output until schema 1.2 carries the verdicts (ADR 0010).
- The real-scanner evidence covers one pinned version, one population and one
  platform for the live run; the committed observation was made on `darwin-arm64`.
- Frozen oracle evidence (`evidence/901/428/*`) was not used; selecting replay
  inputs from it needs its own review.
- Cutover, rollback rehearsal and caller-based retirement remain benchmarks'
  (#665, #666) and are not claimed here.

## 6. How a consumer reads the artifacts

`pii-eval validate` reads schema 1.x documents strictly, reports legacy
revision-1 artifacts as readable and not verifiable (exit 11) and verifies
revision-2 accounting against the snapshot; `pii-eval compare` is a descriptive
diff of two revision-2 artifacts (it refuses legacy artifacts, exit 10).
Compare a candidate run with an oracle-derived baseline through the compatibility
protocol and this suite, not through `compare`. All commands and exit codes:
[docs/cli.md](../cli.md).

## 7. Schema 1.2: the product projection

Requested by #664 ("Schema 1.2 needs a closed optional product-projection block ...").
Design and decisions: [ADR 0016](../adr/0016-product-projection-and-schema-1-2.md).
Contract: `schemas/public-synthetic-artifact.v1.schema.json` (one schema file per
kind and major, superseded in place; the minor is in `schemaVersion` and the `$id`).

**What changes for a consumer.** Nothing unless it asks. Without a roster the public
artifact is the schema 1.1 document byte for byte (a test compares it with the 1.1
golden). With a roster the artifact is sealed under schema **1.2** and carries
`semantic.productProjection`; the internal artifact, the observation sets and the
manifest are byte-identical either way. The block is inside `semantic`, so the
semantic digest (ADR 0003, domain `pii-eval.public-synthetic-artifact/1.2`) covers
it. A 1.1 reader rejects it with `schema-minor-too-new`; pin `artifactSchema.version`
`1.2` to consume it.

**Producing it.**

```sh
pii-eval run --config run-config.json --projection-roster projection-roster.json --out OUT
# or in the configuration: "projection": {"roster": {"path": "...", "rosterDigest": "<sha256>"}}
# (an official run must pin rosterDigest); mode = the configuration's mode.
pii-eval validate OUT/public-synthetic-artifact.json --snapshot snapshot.json \
  --projection-roster projection-roster.json     # recomputes every row from the roster
```

The roster (`pii-eval-projection-roster/1`) is yours: `requiredViews` (a subset of
`oracle-plan`, `qualification-plan`, `diagnostic-balanced`, `benign-heavy-stress`),
the view of every authored case (complete, exclusive), and optionally a control
class (an opaque label) for some cases. Families are the corpus's own; a case that
spans several families without a collision target is refused (split it).

**Shape** (real engine output, abridged: `...` stands for omitted metric results; the
full artifact is `fixtures/contracts/v1/rev2/public-synthetic-artifact.projection.json`):

```json
{
  "schema": "pii-eval.public-synthetic-artifact",
  "schemaVersion": "1.2",
  "semanticDigest": "<sha256 over semantic, domain .../1.2>",
  "semantic": {
    "...": "every 1.1 member, unchanged",
    "productProjection": {
      "rosterDigest": "96fa1097350a6c843b887d0f0dff6960bbf87d5f8ab4a077f724ee372448bc4b",
      "requiredViews": ["oracle-plan", "qualification-plan"],
      "rows": [
        {
          "binding": {
            "activationDigest": "68785ee0037e8b4d5b0ea2b0043e5d897eb942a7bea89a3bd7191510e338b5a3",
            "configurationDigest": "ec0ea698e39929f6aee9ac0e4cf464267a1ca1902e841bb471e95c7f844f6669",
            "population": {
              "populationDigest": "c5249874335d21c02447bac23954d70e20748899f16a43efc56c5568a34a3bae",
              "populationId": "synthetic-demo-population",
              "populationVersion": 1,
              "visibility": "public-synthetic"
            },
            "product": {"kind": "released"},
            "scannerId": "alpha-scan"
          },
          "byControlClass": [],
          "byLanguage": [
            {
              "counts": {"authoredCases": 1, "occurrences": 3, "variants": 3},
              "language": "ko",
              "metrics": ["... ten metric results ..."]
            }
          ],
          "counts": {"authoredCases": 1, "occurrences": 3, "variants": 3},
          "family": "pii:global:email",
          "methodCoverage": [
            {"cases": 1, "method": {"id": "context-discrimination", "version": 2}, "variants": 3}
          ],
          "metrics": [
            {
              "counts": {"eligible": 1, "measured": 1, "notApplicable": 0, "notMeasured": 0,
                         "numerator": 0, "total": 1, "unresolved": 0},
              "effectiveN": 1,
              "metric": {"id": "context-discrimination-rate", "version": 1},
              "status": "measured",
              "value": {"reason": "insufficient-evidence", "state": "withheld"}
            },
            "... nine more, ascending by metric id; a measured value is {\"state\": \"measured\", \"point\": {...}, \"bound\": {...}} ..."
          ],
          "mode": "exploratory",
          "view": "qualification-plan"
        }
      ]
    }
  }
}
```

`byControlClass` and `byLanguage` are omitted when empty (`byLanguage` is always
present for a non-empty cell). Rows are ascending by (`binding.scannerId`, `view`,
`family`), every key once, one `mode` for the whole block.

**What a consumer must reject** (the reference consumer implements all of them,
`examples/consumer/`, pin `artifactSchema.version` `1.2`, optional per-population
`projection: {requiredViews, mode, rosterDigest}`):

| Case | Engine reason code | Reference consumer code |
| --- | --- | --- |
| duplicate (scanner, view, family) rows | `duplicate-identity` | `projection-row-duplicate` |
| a required view with no row for a scanner (the artifact's or the pin's) | `projection-view-missing` | `projection-view-missing` |
| pooled denominators (a row or stratum counting beyond its cases, a scanner's rows adding to more than the population, a metric total beyond its row) | `projection-pooled-denominator` (less than the population: `count-mismatch`) | `projection-pooled-denominator`, `projection-counts-mismatch` |
| unknown mode or view; mixed modes | `schema-violation`; `projection-invalid` | `projection-mode-unknown`, `projection-view-unknown`, `projection-mode-mismatch` |
| scanner / configuration / activation / candidate / population differs from the artifact | `projection-binding-mismatch` | `projection-binding-mismatch` |
| another roster, or no block when pinned | `projection-invalid` (no roster given) | `projection-roster-mismatch`, `projection-missing` |

**What it proves, and what it does not.** `validate --snapshot` (no roster) proves the
structure and bindings; with `--projection-roster` it recomputes every cell, stratum
and count from the authored population and compares (`"recomputed"`). A consumer
that reads only the published block (as the reference consumer does) proves structure,
bindings and no pooling, not the values. Nothing in the block is a verdict: no
threshold, support status or ranking, and qualification stays benchmarks'.
