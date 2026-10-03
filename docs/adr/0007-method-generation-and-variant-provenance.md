# ADR 0007: Method generation and deterministic variant provenance

- Status: accepted for P5 (issue #6); subject to review.
- Date: 2026-10-03
- Related: [ADR 0001](0001-rust-first-and-oracle-pin.md),
  [ADR 0002](0002-freeze-pii-contracts-v1.md),
  [ADR 0003](0003-canonical-serialization-and-semantic-digest.md),
  [ADR 0004](0004-order-invariant-pii-matching.md),
  [ADR 0005](0005-indexed-accounting-and-metric-statistics.md),
  [ownership map](../migration/ownership-map.md), epic #1. Implementation:
  `crates/pii-eval-kernel/src/methods/`. Oracle:
  `benchmarks/evaluation/domains/pii/{methods/*,operators,validators,contract-model}.ts`
  and `benchmarks/evaluation/substrate/{hash,variant-lifecycle}.ts` at
  `4b846967346505baca11e0b98cab1475fbce6773`.

## Context

The contracts (ADR 0002) freeze the seven method ids and versions, the variant
shape (`derivation`: strategy, operator, seed) and the generation rules of a
snapshot (`generator`, `generatorVersion`, `seedDerivation`). They do not say
what a method derives from an authored case, how variant ids and seeds are
formed, or how an unavailable validator is reported. In the oracle each method
is a TypeScript object with `validateCase`, `generate` and `evaluate`, variant
ids are case-local strings (`authored`, `validated`, a frame id, ...), and the
seed of every variant is the case's own free-form `provenance.seed`.

This ADR fixes the Rust definitions, the exact id and seed algorithms, the
validator and operator semantics, the boundaries, the limits, and classifies
every difference from the oracle. The matching rule (ADR 0004) and the
accounting rule (ADR 0005) are unchanged; methods only decide what is fed to
them.

## 1. Identities

| Item | Value |
| --- | --- |
| Generation rule set | `pii-v1-methods` (`METHODS_RULE_ID`), revision 1 (`METHODS_REVISION`) |
| Method versions | the frozen registry's: `type-validation` 2, `context-discrimination` 2, `pii-benign` 3, `jurisdiction-collision` 3, `mutation` 1, `reference-differential` 1, `schema-only` 1 (a test pins `SPECS` to `pii_eval_contracts::METHODS`) |
| Validators | `synthetic-mod10` v1, `us-ssn-allocation` v1 |
| Operators | `invalidate-final-digit` v1 (mutation); `context-frame` v1 (context derivation); `review-hold` v1 (see 4) |
| Seed rules | `pii-seed-v1`, `legacy-case-seed` (section 3) |
| Variant-id domain | `pii-eval.variant-id/1`; seed domain `pii-eval.variant-seed/1` |

The generation revision is independent of the method versions: changing a
method's derivation changes the method version (a protocol revision, ADR 0002);
changing how ids or seeds are formed changes the revision above and the domain
tags. Neither is a refactor.

## 2. What is authored and what is derived

A corpus author writes an `AuthoredCase` (`methods::AuthoredCase`): case id,
lineage, language, jurisdiction, family, **one** input text, the expected
occurrence range, the authored type, validator, sensitivity, context class,
obligation and action expectations, an optional reference, a per-case seed, an
optional authored evidence class, and `MethodParams`. The variant of
`MethodParams` fixes the case's method, so a case cannot name one method and
carry another's parameters. Nothing is scanner output; no field is changed to
match a scanner.

`Generator::new(&GenerationRules, &ValidatorRegistry, GenerationLimits)` derives
contract `Case`s (with `Variant`s, `Derivation`s and `Expectation`s) from them.
The result of one case is a `GeneratedCase`: the contract `Case` plus one
`VariantProvenance` per variant, aligned in ascending variant-id order.
`assemble_body` / `assemble_cases` put generated cases in canonical order for
the contracts to seal and validate (a test seals and validates snapshots of every
method under both seed rules).

Every generated variant has exactly one expected occurrence, `occurrence-1`.

## 3. Deterministic ids, seeds and the pattern generator

All hashes are SHA-256. Fields are combined with an unambiguous
**preimage**: for each field in order, a 4-byte big-endian length followed by its
UTF-8 bytes (`ab`,`c` and `a`,`bc` give different preimages).

```text
preimage(["ab","c"]) = 00 00 00 02 61 62  00 00 00 01 63
sha256 = f2939f903016e5bb29b1e4a61cdbd376220ca03a24180b39995f2d50f2e0a647
```

### Variant id

```text
variantId = slot + "-" + hex(sha256(preimage(["pii-eval.variant-id/1", caseId, slot])))[0..24]
```

`slot` is the oracle's case-local variant id: a lowercase slug of at most 48
bytes (`authored`, `validated`, `collision`, `mutated`, `reference`, the context
frame id, the benign accounting class). The id is therefore at most 73 bytes and
a valid `Id`. It is unique across a snapshot because case ids are unique (the
generator rejects a repeated case id) and the hash binds the pair; a readable
`caseId-slot` concatenation was rejected because `aa-b` + `c-d` and `aa` +
`b-c-d` would collide. A 96-bit digest makes an accidental collision negligible;
`assemble_cases` still checks and refuses a duplicate id. The id does **not**
depend on the seed, the generator or any text, so changing a seed or the
generator version never moves a variant between runs.

### Seed derivation (`generation.seedDerivation`)

The snapshot records the rule id; a generator built for an unknown id fails with
`GeneratorError::UnsupportedSeedDerivation` and generates nothing.

- `pii-seed-v1` (default for new corpora). A variant that is **derived**
  (context frame, mutation) records
  `hex(sha256(preimage(["pii-eval.variant-seed/1", generator, decimal(generatorVersion), caseSeed, caseId, slot])))`
  (64 digits, within the 64-byte seed limit). The case seed is the author's
  per-case seed; the generator identity is part of the preimage, so a new
  generator version yields new seeds and the same ids.
- `legacy-case-seed`. A derived variant records the case seed unchanged, after
  the oracle's free-form seed is made a contract seed by
  `legacy_contract_seed` (every `/` becomes `.`; the contract alphabet is
  `[A-Za-z0-9._-]`). That mapping is **not injective** (`a/b` and `a.b` give one
  seed), so a legacy seed is not bit-identical to the oracle's: a parity
  comparison (P9) must apply the same function to the oracle side. A seed still
  invalid after the mapping is an error.

An **authored** variant records no seed and no operator (the contract forbids
both). A **review-required** variant (validator or reference unavailable,
section 4) records the operator `review-hold` v1 and no seed. The seed is a
label: no method draws randomness from it, so a different seed changes
`derivation.seed` of derived variants and nothing else (tested: ids, text,
expectations, provenance and accounting are equal once seeds are removed).

### `sha256-pattern` v1 (oracle `materializePiiEvidenceCandidate`)

`materialize_sha256_pattern(seed, pattern)`: every `D` of `pattern` becomes a
digit and every `A` an uppercase letter, chosen by `v` = the first eight hex
digits of `sha256(UTF-8 "<seed>/<n>")` as an unsigned number (`n` counts the
substituted characters from 0): `D` -> `v mod 10`, `A` -> `chr(65 + v mod 26)`.
Other characters pass through. It is the deterministic value generator behind
the oracle's synthetic evidence candidates.

### Independent vectors

`crates/pii-eval-kernel/tests/vectors/ids_reference.py` (Python `hashlib`,
written from this specification, run once; CI does not run Python) produced
`ids_vectors.rs`; `tests/methods_ids.rs` checks the kernel against it. The
`sha256-pattern` vectors were additionally checked against a verbatim copy of
the oracle's function (Node `crypto`). Examples:

| Input | Expected |
| --- | --- |
| variant id, case `case-a`, slot `authored` | `authored-63b91cfa65ce88b11f9a390c` |
| variant id, case `aa-b`, slot `c-d` vs case `aa`, slot `b-c-d` | different ids (no concatenation collision) |
| `pii-seed-v1`, generator `pii-generator` v1, case seed `case-seed.1`, case `case-a`, slot `mutated` | `e7a1e720c450edc69dcc10adc3cc283e010b2b19634f9bc47536d3d0d2325f33` |
| same, generator v2 | `c2421479d50e0945a6e425e89188d7cf6da60e5e29621611b032e710f7800703` |
| `sha256-pattern`, seed `seed-one`, pattern `SYNTHETIC-DDDD` | `SYNTHETIC-7274` |
| `sha256-pattern`, seed `pii-benign-collision-v1/example`, pattern `DDD-DD-DDDD` | `125-99-6456` |

## 4. The seven methods

`methods::spec(MethodId)` returns the table below as data (`SPECS`).

| Method (v) | Derives | Slot | Strategy / operator / seed | Requires; refuses (reason) | Feeds |
| --- | --- | --- | --- | --- | --- |
| `schema-only` (1) | the authored variant | `authored` | authored; none | range, scope. Evidence never implies runtime accuracy (`runtime_accuracy_evidence = false`) | generic metrics only |
| `type-validation` (2) | the authored variant, confirmed by the case's validator | `validated` | authored, or review-required + `review-hold` when the validator is unavailable | a validator (`missing-validator`); the validator must agree with the authored type (`validator-expectation-mismatch`: an authored expectation is never changed to a validator's answer) | generic metrics |
| `context-discrimination` (2) | one variant per frame: prefix + candidate + suffix, range recomputed in bytes | frame id | derived; `context-frame` v1; seeded | valid type and `required-for-sensitive-classification` obligation (`context-case-invalid`); at least one frame per class (`context-frames-not-a-trio`; ADR 0008 R5, ADR 0012 N1); one `{{candidate}}` marker (`frame-template-invalid`); class and sensitivity paired (`frame-expectation-mismatch`); at most the per-case limit (`too-many-variants`) | `context-discrimination-rate` and generic |
| `pii-benign` (3) | the authored variant as a benign control | the accounting class | authored | non-sensitive expectation (`not-non-sensitive`); evidence class consistent with the accounting class (`evidence-role-mismatch`); authored validator expectations confirmed (`validator-check-mismatch`, `validator-check-unavailable`) | `benign-suppression-rate` and generic |
| `jurisdiction-collision` (3) | the authored variant with a collision declaration (target = the case family, competitors sorted and unique) | `collision` | authored | non-empty competitors that exclude the target, at most 32 (`invalid-collision`); `cross-family-collision` evidence only; validator checks as above | `jurisdiction-collision-rate` and generic |
| `mutation` (1) | one variant by `invalidate-final-digit` | `mutated` | derived; the authored operator; seeded | a known operator at its version (`operator-unknown`, `operator-version-mismatch`); a final ASCII digit (`operator-not-applicable`) | generic (the authored type becomes `invalid`) |
| `reference-differential` (1) | the authored variant plus the reference's observation | `reference` | authored, or review-required + `review-hold` when the reference is unavailable | a reference (`missing-reference`) | generic |

The generic metrics (`type-miss-rate`, `wrong-family-rate`,
`wrong-jurisdiction-rate`, `sensitive-miss-rate`, `non-sensitive-flag-rate`,
`range-collateral-rate`, `measurable-share`) pool every method's rows by authored
expectation (ADR 0005); the three restricted metrics are fed by their own method
only (a test pins `SPECS` to the metric registry's `restricted_to_method`).
Common refusals for every method: `range-invalid`, `range-out-of-bounds`,
`range-not-on-char-boundary`, `range-offset-too-large`, `text-too-large`,
`family-scope-mismatch`, `evidence-role-mismatch`, `slot-invalid`,
`duplicate-frame`, `missing-evidence-checks`. `RefusalReason::contract_code()` maps a refusal to the
contract's reason code where one exists; the rest are method-level reasons
because the contract's reason-code list is frozen.

### Unavailable validators and references are explicit

A validator observation is `valid`, `invalid` or `unavailable`, and
`unavailable` carries a reason: `unknown-validator`, `validator-version-mismatch`
(the case pins a version; `ValidatorRef` has `id` and `version`) or
`validator-declined`. For `type-validation` and `reference-differential` an
unavailable observation yields a `review-required` variant (operator
`review-hold` v1, because the contract requires an operator on every
review-required variant; the hold transforms nothing), a `ReviewReason`, and an
instruction for the outcome rows: the type axis becomes `not-measured`; the
sensitivity, range and action axes are left alone.

**The gate is derivable from the sealed snapshot.** `account` and the matcher
ignore `derivation.strategy`, so a replay of a stored snapshot would otherwise
score a clean pass for a held variant. `ReviewGate::from_body(&body)` collects
the `review-required` variants and `apply_review_strategy(row, Strategy)` /
`ReviewGate::apply(variant_id, row)` gate a row by strategy alone (a reference
disagreement keeps strategy `authored`, so it never gates). **Whoever turns
matcher output into outcome rows (the run and replay paths, P8) must pass every
row through the gate before accounting, or call `account_gated(body, index,
scanners, rows, mechanics)`, which does so.** `account` itself is unchanged and
stays strategy-agnostic; a test accounts a snapshot with provenance dropped and
gets 7 of 8 measured, against a clean 8 of 8 without the gate.
`apply_review(row, ReviewReason)` remains for callers that hold the generation
provenance and is equivalent for unavailable states. The
variant is therefore counted, in the denominator of every metric it is eligible
for, as not measured, never as a pass or a failure (tested through `account`:
7 eligible, 6 measured, 1 not measured for `type-miss-rate`; without the gate the
same scanner would score a clean 7 of 7). A scanner that did not complete, or
cannot report an axis, is already `not-measured` through ADR 0004 and ADR 0005.

A reference **disagreement** (the reference observes a type different from the
authored one) is `ReviewReason::ReferenceDisagrees`. It is an observation about
the reference: the variant keeps the authored expectation and strategy, the type
axis stays measured, and every count is unchanged (tested). There is no
function that turns a reference's answer into an expectation.

## 5. Validators and the mutation operator

Reproduced from the oracle's `validators.ts` and `operators.ts` (JavaScript
regular expressions: ASCII digits only, no trailing-newline allowance):

- `synthetic-mod10` v1: the value must be exactly `SYNTHETIC-` plus four ASCII
  digits; valid when the sum of the first three digits modulo 10 equals the
  fourth.
- `us-ssn-allocation` v1: nine ASCII digits; invalid when the area is `000`,
  `666` or at least `900`, the group is `00`, or the serial is `0000`.
- `invalidate-final-digit` v1: the candidate must end in an ASCII digit `d`; it
  becomes `(d + 1) mod 10` (so `9` -> `0`); the byte length and range are
  unchanged; the authored type becomes `invalid`; the sensitivity expectation
  is the case's.

Evidence: `tests/methods_oracle.rs::the_validators_reproduce_the_oracle_on_every_vector`
checks 33 edge strings (lengths, case, Unicode digits, trailing newline, area,
group and serial boundaries) whose expected states were produced by the
oracle's own validators; `methods.rs` has the hand-computed method vectors.

## 6. Boundaries

- **Generic observations versus product policy.** `methods::validators` returns
  an observation and nothing else. There is no activation gate, no threshold, no
  support status, no `stable` or `provisional` here; those stay with the product
  owner (the oracle's `qualification/pii-v1.json` gates are product policy,
  ownership map).
- **Population views.** `diagnostic-balanced` and `benign-heavy-stress` are
  authored memberships of cases (`PopulationView`, `ViewRoster`). The kernel
  checks that a roster assigns every case of a snapshot to exactly one view,
  restricts a snapshot body to a view (`ViewRoster::restrict`) so each view is
  accounted on its own with `account`, and reports a view's authored composition
  and whether non-sensitive occurrences strictly outnumber sensitive ones
  (`ViewComposition::benign_dominant`, an observation). It never merges the two
  views, weights them, or reports a combined score; declared base-rate mass,
  per-stratum deltas and verdicts are product policy (oracle
  `docs/specs/pii-populations.md`).
- **Schema-only.** Its rows exercise the contract and the scoring path. They are
  kept in the `schema-only` method stratum; a consumer reporting accuracy reads
  `runtime_accuracy_methods()` (every method but `schema-only`).
- **Purity.** No process, network, clock, random source, environment or file
  access. The validator registry and the limits are explicit arguments.

## 7. Limits and bounded generation

`GenerationLimits` (defaults are the contract maxima; `validate` rejects zero,
values above the contract, and an inconsistent set): variants per case (64),
variants per method and in total (4 000 000 each), authored cases (1 000 000),
text bytes (1 MiB), and a batch of 1024 variants (at least the per-case limit,
at most 65 536).

`Generator::run` is a lazy iterator, one `Result<CaseResult, GenerateError>` per
case, and `GenerationRun::batches` groups the results into batches of at most
`batch_variants` variants plus refusals, with one case of lookahead (a test
pulls 65 of 1000 inputs for the first batch of 64). Only the set of seen case
ids (duplicate detection) grows with the number of cases.

Two kinds of failure, chosen so results never depend on input order:

- **Refusal** (a case-local property): the case is refused with a reason and
  counted. `GenerationReport` keeps cases in, generated, refused by reason and
  per method, and `is_conserved()` checks `cases_in == generated + refused` and
  that the per-method counters add up.
- **Run error** (a run-level limit or a repeated case id): the run ends with
  `GenerateError` and yields nothing more. Truncating at a run-level limit
  would drop a different set of cases for each input order, so the run fails
  instead. Whether a run fails does not depend on order; which of several
  simultaneously exceeded limits is reported first can. `Batches` returns the
  partial batch generated before the error first (it holds valid results) and
  the error on the next call, then ends; nothing generated is dropped.

## 8. Determinism

Tested (`methods_accounting.rs`): 40 shuffles of the input give identical
results, identical reports and an identical sealed snapshot digest; results
generated case by case in 30 shuffled "completion" orders and then assembled
equal the canonical assembly; batch sizes 64, 65, 130 and 1024 give the same
cases, refusals and report; five repetitions are identical; changing seeds or
the seed rule changes only recorded seeds. Output order is canonical (ascending
case id, ascending variant id); no map iteration order, locale-dependent sort or
host value is used. Replays are not a concept here and add no variants.

## 9. Compatibility with the oracle

Executable evidence: `crates/pii-eval-kernel/tests/methods_oracle.rs`. The
vectors in `tests/vectors/oracle_methods.rs` were produced by running **the
oracle's own method code** (methods, operators, validators, `contract-model`,
`hash`, `variant-lifecycle`, `registry` at the pin) on 34 synthetic authored
cases with `tests/vectors/oracle_methods_driver.mjs` (Node 22.16,
`--experimental-strip-types`). Two oracle modules load committed evidence corpora
through Ajv and JSON imports and were replaced by stubs in the scratch tree
(`benign-collision-evidence.ts`: an entry per case from the driver;
`context-evidence.ts`: the real frames of `context-evidence-v1.json`); both stubs are
committed under `tests/vectors/oracle_stubs/` and the pin is in
`regenerate_oracle_vectors.sh`. The method
files are unmodified. Equal for every case: text, candidate range, authored type,
sensitivity, context class, strategy, derived-variant operator, method version,
the oracle's `invalidate` effect, the type-axis gating and the reference
disposition of a perfect scanner, and the collision's sorted competitors.

| Id | Difference | Class |
| --- | --- | --- |
| D1 | Variant id: the oracle's id is the case-local slot (`authored`, a frame id); the kernel's is `slot-<digest>` (section 3), unique across the snapshot. The slot is compared equal. | Contract shape (variant ids are snapshot-unique) |
| D2 | `context-discrimination` frames: the oracle accepts any number of frames; its real groups hold 8 (`en-email-core`) and 11 (`ko-email-core`) frames. Originally the kernel refused any set that was not exactly one frame per class (`context-frames-not-a-trio`). **Resolved in P9 ([ADR 0012](0012-oracle-parity-and-migration-evidence.md) N1):** the generator accepts at least one frame per class, as the contracts and the accounting index have since ADR 0008 R5; a group missing a class is still refused. The oracle's 8-frame group is generated and compared like any other case. | Contract shape; resolved (was a P7 open item); no longer in the census |
| D3 | An unknown validator or reference, or a reference pinned at another version: the oracle throws and aborts the run; the kernel yields a review-required variant with an explicit reason and an unmeasured type axis. | Intentional (unavailable is a state, never an abort and never a pass) |
| D4 | Authored variants: the oracle records operator `authored` v1 and the case seed on every variant; the contract forbids an operator and a seed on an authored variant. A review-required variant records `review-hold` v1 (the oracle: `authored`). | Contract shape |
| D5 | Under `pii-seed-v1` a derived seed is derived (section 3); `legacy-case-seed` reproduces the oracle's seed only up to the D7 mapping. | Intentional (distinct seeds per variant; the legacy rule is kept) |
| D6 | A candidate range inside a multi-byte character: the oracle slices bytes and decodes lossily (a replacement character reaches the validator); the kernel validates character boundaries (ADR 0004) and refuses (`range-not-on-char-boundary`). | Intentional (ADR 0004; Korean, combining marks and emoji are first-class) |
| D7 | Seeds: the oracle's are free-form (`pii-benign-collision-v1/<id>`, `<group>/1`); the contract's seed alphabet is `[A-Za-z0-9._-]`. `legacy_contract_seed` maps `/` to `.`: not injective, so legacy seeds are not bit-identical to the oracle's and P9 must apply the same mapping. The seed is a label, so there is no semantic effect. | Contract shape |
| D8 | Benign evidence: the oracle requires the evidence entry's accounting class to equal the case's exactly (and `collision` null, class not near-miss or cross-family); the kernel checks that the case's class is among the classes the evidence class allows (`reserved-documentation` allows `reserved` and `documentation`) and that the evidence class belongs to the method. The exact match needs the entry's own accounting class, which the kernel does not load. | Open item (evidence loader) |
| D9 | Near-miss evidence on `type-validation`: the oracle requires the entry's validator id, version and expected state to equal the case's validator and authored type. The kernel confirms the validator against the authored type (`validator-expectation-mismatch`) and checks the evidence class's method, but does not compare an entry's validator identity, which it does not load. Cross-family collision evidence must carry a validator check for the target and every competitor (`missing-evidence-checks`); benign evidence has one optional validator in the oracle, so none is required. | Open item (evidence loader) |

The census test covers D1 and D3 to D7 (D2 left it in P9; it fails if one stops occurring or an
undocumented one appears); D8 and D9 are not exercised because the kernel does
not load evidence entries. Same-observation replay parity and live-scanner parity
remain P9.

## 10. What is not here

Adapters, execution, the CLI, worker pools, process control, artifact writing,
the protocol-revision bump and any contract, schema or fixture change belong to
P6/P7/P8. The kernel does not read an evidence corpus: `EvidenceClass`,
`ValidatorCheck` and the context frames are the authored facts such a loader
would supply; loading and validating the oracle's JSON evidence files (Ajv
schemas, content commitments) is the corpus author's tooling, not a kernel
concern.

## 11. Open items for the contract owner (P7), not changed here

> **Update (P7):** items 1 (context trios) and 4 are resolved by [ADR 0008](0008-protocol-revision-2-and-schema-1-1.md) (sections 7 and 1 to 4). The text below is the state when P5 was written.

Reported rather than changed, because contracts, schemas and fixtures are
frozen for this phase:

1. **Context trios (D2).** The contract rule `incomplete-context-trio` and
   `AuthoredIndex::new` require exactly one variant per context class. The
   oracle's groups hold several frames per class, and its metric already judges
   "every endpoint passes" over any number of endpoints (the kernel's group flags
   OR-accumulate over any number of frames). Proposed: relax both to "at least one
   variant per class". Until then a multi-frame group must be split into trio
   cases by the corpus author, which changes the sample count (each trio is one
   sample).
2. **Views and strata.** Schema 1.0 has no view, benign accounting class or
   evidence class field (ADR 0005, A7). The kernel carries the view as an
   external `ViewRoster`, the benign class as the variant slot and the evidence
   class in `VariantProvenance::evidence`. If artifacts must carry them, add
   optional fields (an additive minor change).
3. **Reason codes.** The refusal and unavailable reasons above are method-level
   strings with a contract code where one exists. If the artifact must carry
   them (for example `validator-unavailable`), add codes to the reason-code
   list.
4. **A8** (benign and collision groups count a case when any row passes) is
   unchanged and still P7's decision (ADR 0005).

## 12. Public API for downstream phases

`pii_eval_kernel::methods`: `Generator::{new, generate_case, run, generate_all}`,
`GenerationRun::{report, batches}`, `Batches`, `Batch`, `CaseResult`,
`GenerationOutput`, `GenerationReport`, `MethodReport`, `GenerationLimits`
(`DEFAULT`, `validate`), `GenerationLimit`, `GenerateError`, `GeneratorError`,
`Refusal`, `RefusalReason` (`as_str`, `contract_code`), `GeneratedCase`,
`VariantProvenance`, `ReviewReason`, `ReferenceObservation`, `apply_review`, `apply_review_strategy`, `ReviewGate`, `account_gated`, `legacy_contract_seed`,
`assemble_cases`, `assemble_body`, `AssembleError`; authored input
`AuthoredCase`, `MethodParams`, `ContextFrame`, `ValidatorCheck`, `BenignClass`,
`EvidenceClass`, `CANDIDATE_MARKER`; identity `variant_id`, `derive_seed`,
`SeedRule`, `Slot`, `preimage`, `materialize_sha256_pattern`, `SEED_RULE_V1`,
`SEED_RULE_LEGACY`, `VARIANT_ID_DOMAIN`, `VARIANT_SEED_DOMAIN`; definitions
`SPECS`, `spec`, `MethodSpec`, `runtime_accuracy_methods`; validators
`ValidatorRegistry`, `ValidatorState`, `ValidatorObservation`,
`UnavailableReason`, `ValidatorDef`, `synthetic_mod10`, `us_ssn_allocation`;
operators `apply_mutation`, `Mutation`, `OperatorError`; views
`PopulationView`, `ViewRoster`, `ViewAssignment`, `ViewComposition`, `ViewError`.
The crate API is internal (ARCHITECTURE.md); consumers integrate through
artifacts and the CLI.

P8 builds a snapshot by `Generator::run(...).batches()` over authored cases,
`assemble_body`, `seal`; it replays outcomes by `assess_variant` per variant,
`apply_review` with the variant's `ReviewReason`, then `account`. P9 compares
against the oracle with `legacy-case-seed` and the vectors above.

## 13. Verification

`cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked
-- -D warnings`, `cargo test --workspace --locked` and
`cargo +1.85.0 test --workspace --locked` (CI runs the same). The new suites are
`tests/methods.rs` (positive and negative fixtures per method, contract
validity), `tests/methods_ids.rs` (independent id, seed and pattern vectors),
`tests/methods_oracle.rs` (oracle compatibility, census of D1 to D7) and
`tests/methods_accounting.rs` (matcher and accounting conservation, views,
limits, batching, invariance). Not run in CI: `ids_reference.py` and
`regenerate_oracle_vectors.sh` (it fetches the pinned oracle files with `gh`,
copies the two committed stubs from `tests/vectors/oracle_stubs/`, runs
`oracle_methods_driver.mjs` on Node 22.6 or later and rewrites
`oracle_methods.rs`; a rerun reproduces the committed file byte for byte).
