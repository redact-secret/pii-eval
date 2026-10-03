# Legacy PII ownership map (migration inventory)

Status: inventory only. Nothing was moved or copied from the oracle. This map
records what exists at the pinned oracle commit and who should own it; it does
not establish that any item has been ported, and it makes no parity claim.

- Oracle: `redact-secret/redact-secret-benchmarks`
  commit `4b846967346505baca11e0b98cab1475fbce6773` (develop, 2026-10-02).
  Pin rationale and ADR: [ADR 0001](../adr/0001-rust-first-and-oracle-pin.md).
- Method: the tree at the pin was listed read-only and every path whose name
  matches `pii`, plus every direct importer of `evaluation/domains/pii`,
  `evaluation/substrate` and `accounting/shared`, was read for its stated role.
  Files are classified from header comments and imports, not from running them.
  Classification is a proposal for review; items marked `mixed-split` need a
  decision before any code is written for them.
- Classes:
  - `generic-measurement`: scanner-neutral mechanics that `pii-eval` re-implements
    in Rust (never by importing the TypeScript).
  - `product-policy`: Redact Secret thresholds, support status, populations,
    activation acceptance, publication, cost/size protocols. Stays in benchmarks.
  - `shared-substrate`: used by credential and PII domains (or release tooling).
    Not moved wholesale; only the minimal neutral behavior PII needs is
    re-implemented and conformance-tested, and the original stays in benchmarks.
  - `mixed-split`: one file combines neutral calculation and product decision.
- Targets: `pii-eval: reimplement in Rust` (behavior, not source),
  `benchmarks: retain`, `seam: neutral minimum only`, `corpus author`, or
  `oracle/reference only` (read for behavior or pins, never imported).
- Authored corpus and evidence data (for example `context-evidence-v1.json`) are
  expectations owned by their author and reviewers; `pii-eval` consumes them as
  a versioned snapshot and never edits them to match scanner output.

Totals at the pin: 40 generic-measurement, 160 product-policy, 37
shared-substrate, 16 mixed-split file rows (253 rows) plus the grouped
evidence/holdout rows at the end.

## Legacy contracts later phases must preserve

Source: `benchmarks/evaluation/domains/pii/` at the pin. Versions are the values
found in code; P2 freezes them as the compatibility protocol.

### Versions and identities

| Item | Value at pin |
| --- | --- |
| PII evaluation engine version (`PII_ENGINE_VERSION`) | `1.0.0` |
| Evaluation profile / domain accounting version | `pii-v1` / `pii-v1` (`PII_ACCOUNTING_IDENTITY`) |
| Qualification profile | `qualification/pii-v1.json`, id `pii-v1`, version 1 |
| Accounting mechanics | `minDenominator` 4, `replays` 2, `intervalZ` 1.96, `intervalPrecision` 6 |
| Accounting source identity (observation-side) | `evaluationProfile` `pii-schema-v1`, `domainAccountingVersion` `pii-observation-v1` |
| Validators | `synthetic-mod10` v1, `us-ssn-allocation` v1 (`validators.ts`) |
| Mutation operator | `invalidate-final-digit` v1 (`operators.ts`) |
| Outcome axes | `typeIdentity`, `sensitivityContext` |
| Assertion statuses | `pass`, `fail`, `review-required`, `not-measured` |
| Range states | `exact`, `overbroad`, `partial`, `miss`, `not-applicable` |
| Identity domains | `email`, `payment-card`, `network-address`, `iban`, `phone`, `national-id` |

The thresholds in `qualification/pii-v1.json` (all `0.5`) and its `gates` block
(`requiredMethods`, `minBenignCases` 6, `minBenignAxes` 3, protected/independent
evidence requirements) are product policy; the metric ids and mechanics are
neutral.

### The seven methods

| Method id | Method version | Source |
| --- | --- | --- |
| `type-validation` | 2 | `methods/type-validation.ts` |
| `context-discrimination` | 2 | `methods/context-discrimination.ts` |
| `pii-benign` | 3 | `methods/benign.ts` |
| `jurisdiction-collision` | 3 | `methods/jurisdiction-collision.ts` |
| `mutation` | 1 | `methods/mutation.ts` |
| `reference-differential` | 1 | `methods/reference-differential.ts` |
| `schema-only` | 1 | `methods/schema-only.ts` |

Registered together in `methods/index.ts` (`createPiiMethods`). Required by the
product profile: `type-validation`, `context-discrimination`, `pii-benign`.

### The ten `pii-v1` metrics

Directions and applicability come from `qualification/pii-v1.json`; population,
numerator and denominator are the verbatim `PII_METRIC_LABELS` strings.

| Metric | Direction | Applicability | Population | Numerator | Denominator |
| --- | --- | --- | --- | --- | --- |
| `type-miss-rate` | upper | required | scanner-source x authored valid-type occurrence | type state is miss | resolved type assertions for authored valid types |
| `wrong-family-rate` | upper | required | scanner-source x authored valid-type occurrence | type state is wrong-family | resolved type assertions for authored valid types |
| `wrong-jurisdiction-rate` | upper | jurisdictional | scanner-source x authored jurisdictional valid-type occurrence | type state is wrong-jurisdiction | resolved jurisdictional type assertions |
| `sensitive-miss-rate` | upper | required | scanner-source x authored sensitive occurrence | sensitivity state is miss | resolved sensitivity assertions for authored sensitive occurrences |
| `non-sensitive-flag-rate` | upper | required | scanner-source x authored non-sensitive occurrence | sensitivity state is false-positive | resolved sensitivity assertions for authored non-sensitive occurrences |
| `context-discrimination-rate` | lower | required | complete scanner-source x authored context trios | both sensitive and non-sensitive endpoints pass | resolved complete context trios |
| `benign-suppression-rate` | lower | required | scanner-source x distinct authored benign case | non-sensitive assertion passes | resolved authored benign cases |
| `jurisdiction-collision-rate` | lower | jurisdictional | scanner-source x authored jurisdiction collision case | target family and jurisdiction assertion passes | resolved collision type assertions |
| `range-collateral-rate` | upper | reported-spans | scanner-source x reported span for authored valid type | range is overbroad or partial | exact, overbroad, or partial reported spans |
| `measurable-share` | lower | required | all scanner-source x authored axis assertions | resolved pass or fail assertions | all eligible authored axes including unresolved axes |

### Legacy scanner list and pins

The PII evaluation takes scanners as `RuntimeScanner<PiiFinding>` objects; the
concrete PII-capable scanners found at the pin are:

| Scanner | Kind | Pin at oracle commit | Where pinned | PII use at pin |
| --- | --- | --- | --- | --- |
| `redact-secret` (`@redact-secret/core`) | product runtime library, Node addon / Wasm / Python / Rust surfaces | `0.1.0-beta.12` (lockfile release), plus commit-bound candidates (for example core commits recorded under `evidence/901/428/core-*`) | `package.json`, `package-lock.json` (sha512 integrity), `qualification/suite-v1.json`; candidate installs via `scanners/candidate.mjs` | PII activation through `initialize({ pii: [...] })`; selectors such as `pii:global`; findings mapped by `piiFindingIdentity` to `pii:<scope>:<family>` |
| `flare-redact` | runtime library (npm) | `1.6.1` | `package.json`, `package-lock.json` | informational throughput comparison only (`peer-pii-runtime-throughput-v1`, `supportClaims: false`); its PII detectors are disabled in the credential accuracy adapter |
| `@openredaction/core` (`openredaction`) | runtime library (npm) | `1.1.5` | `package.json`, `package-lock.json` | informational throughput comparison only; personal-data detections carry no family in the credential adapter |
| `gitleaks` | repository scanner (binary) | `8.30.1` | `qualification/suite-v1.json`, `scanners/peer-checksums.json` | credential suite only; no PII adapter at the pin |
| `trufflehog` | repository scanner (binary) | `3.97.4` | `qualification/suite-v1.json`, `scanners/peer-checksums.json` | credential suite only; no PII adapter at the pin |

Notes for P6: only `redact-secret` has a PII scoring path (mapping of product
finding types to PII families). `flare-redact` and `openredaction` are timed
for redaction throughput, not scored on type/sensitivity. Gitleaks and
TruffleHog are credential scanners; the `trufflehog --version` 3.97.4 pin in
this repository's AGENTS.md concerns credential-eval benchmarking and is not a
PII scanner pin. Whether any additional PII scanner is in scope is a P6
decision, not made here.

## Shared-substrate callers

`benchmarks/evaluation/substrate/*` (10 files), `benchmarks/accounting/shared/primitives.ts`
and the domain registry are used by both credential and PII domains. Direct
importers of `evaluation/substrate` or `accounting/shared` found at the pin
(29 files):

- Engine compatibility paths: `benchmarks/engine/{execution,model,provenance,registry}.ts`, `benchmarks/lib/accounting.ts`
- Credential domain: `benchmarks/evaluation/domains/credential/accounting.ts`
- PII domain: `benchmarks/evaluation/domains/pii/{accounting,beta11-qualification,email-network-population,execution,profile}.ts`
- Release tooling: `benchmarks/evaluation/release-record.ts`
- Scripts: `scripts/{measure-peer-pii-runtime-throughput,measure-runtime-comparison,observe-pii-populations,observe-us-ssn-populations,refresh-us-ssn-arrival-data}.mjs`
- Tests: `tests/{accounting-domains,credential-domain,evaluation-substrate,peer-pii-runtime-throughput,pii-accounting,pii-benign-collision-evidence,pii-beta11-protected,pii-domain,pii-methods,pii-populations,pii-protected-support,runtime-comparison}.test.mjs`

Direct importers of `evaluation/domains/pii` outside the PII directory (75
files at the pin) are the product-side consumers: release-record tooling, the
site (`src/`, `web/services/`), PII scripts and PII tests. They are the callers
that benchmarks #665 and #666 must repoint at validated artifacts before any
legacy removal; they are listed in the file table below.

## Workflows, scripts and checks

- PII-specific workflows: `pii-profile-cost.yml`, `pii-profile-cost-v2.yml`,
  `peer-pii-runtime-throughput.yml`. PII steps inside other workflows:
  `publish-site.yml` (`npm run pii:observe:populations`,
  `npm run eval:publish:pii-support`), `performance-evaluation.yml` (optional
  PII variants). `validate.yml` has no PII-specific job; PII tests run through
  `npm test` (`node --import tsx --test tests/*.test.mjs`).
- `package.json` PII scripts (`pii:*`, `study:pii-readiness`,
  `peer-pii-runtime-throughput`, `eval:publish:pii-support`) are listed in
  the file table through the scripts they call.

## File-level table

Paths are relative to the oracle repository root. The six
`.github/workflows` files that mention PII or run it through `npm test` are included individually.

| File | Class | Target | Note |
| --- | --- | --- | --- |
| `.github/workflows/peer-pii-runtime-throughput.yml` | product-policy | benchmarks: retain | informational throughput workflow (#429) |
| `.github/workflows/performance-evaluation.yml` | product-policy | benchmarks: retain | optional pii variants of runtime performance |
| `.github/workflows/pii-profile-cost-v2.yml` | product-policy | benchmarks: retain | PII profile-cost v2 workflow (#428) |
| `.github/workflows/pii-profile-cost.yml` | product-policy | benchmarks: retain | PII profile-cost workflow (#286) |
| `.github/workflows/publish-site.yml` | product-policy | benchmarks: retain | runs pii:observe:populations and eval:publish:pii-support; consumer of artifacts after #665 |
| `.github/workflows/validate.yml` | shared-substrate | seam: neutral minimum only | runs `npm test` (includes all PII tests) and ledger/schema checks; no PII-specific job |
| `benchmarks/accepted-pii-profile-cost.json` | product-policy | benchmarks: retain | accepted tradeoffs |
| `benchmarks/accounting/shared/primitives.ts` | shared-substrate | seam: neutral minimum only | mechanical accounting primitives (proportion, Wilson, identity compatibility); neutral math reimplemented in P4 with independent vectors |
| `benchmarks/engine/execution.ts` | shared-substrate | seam: neutral minimum only | credential-side caller of substrate/accounting-shared (compat path); outside PII scope, must keep working |
| `benchmarks/engine/model.ts` | shared-substrate | seam: neutral minimum only | credential-side caller of substrate/accounting-shared (compat path); outside PII scope, must keep working |
| `benchmarks/engine/provenance.ts` | shared-substrate | seam: neutral minimum only | credential-side caller of substrate/accounting-shared (compat path); outside PII scope, must keep working |
| `benchmarks/engine/registry.ts` | shared-substrate | seam: neutral minimum only | credential-side caller of substrate/accounting-shared (compat path); outside PII scope, must keep working |
| `benchmarks/evaluation/domains/credential/accounting.ts` | shared-substrate | seam: neutral minimum only | credential-side caller of substrate/accounting-shared (compat path); outside PII scope, must keep working |
| `benchmarks/evaluation/domains/pii/accounting.ts` | generic-measurement | pii-eval: reimplement in Rust | ten pii-v1 metric calculation, counters, intervals; imports shared primitives and profile |
| `benchmarks/evaluation/domains/pii/arrival-evidence.ts` | product-policy | benchmarks: retain | beta.10 arrival contract and evidence |
| `benchmarks/evaluation/domains/pii/assessment.ts` | generic-measurement | pii-eval: reimplement in Rust | safe authored-contract projection |
| `benchmarks/evaluation/domains/pii/benign-collision-classes.ts` | generic-measurement | pii-eval: reimplement in Rust | lossy mapping into pii-v1 accounting classes |
| `benchmarks/evaluation/domains/pii/benign-collision-evidence-v1.json` | generic-measurement | corpus author / benchmarks: retain truth | authored synthetic evidence data |
| `benchmarks/evaluation/domains/pii/benign-collision-evidence.ts` | generic-measurement | pii-eval: reimplement in Rust | evidence-corpus loader/validator for pii-benign and jurisdiction-collision |
| `benchmarks/evaluation/domains/pii/beta11-disposition.ts` | product-policy | benchmarks: retain | beta.11 six-row disposition |
| `benchmarks/evaluation/domains/pii/beta11-population-v2.ts` | product-policy | benchmarks: retain | beta.11 pii-context/v2 population plan set |
| `benchmarks/evaluation/domains/pii/beta11-protected.ts` | product-policy | benchmarks: retain | protected-partition lifecycle; custody semantics move to private-custodian handoff |
| `benchmarks/evaluation/domains/pii/beta11-qualification.ts` | product-policy | benchmarks: retain | protected-qualification eligibility and family disposition |
| `benchmarks/evaluation/domains/pii/card-iban-stress/authoring.ts` | product-policy | benchmarks: retain | payment-card/IBAN stress plan (#425); authored truth and plan data |
| `benchmarks/evaluation/domains/pii/card-iban-stress/contract-model.ts` | product-policy | benchmarks: retain | payment-card/IBAN stress plan (#425); authored truth and plan data |
| `benchmarks/evaluation/domains/pii/card-iban-stress/iban-stress-v1.json` | product-policy | benchmarks: retain | payment-card/IBAN stress plan (#425); authored truth and plan data |
| `benchmarks/evaluation/domains/pii/card-iban-stress/iban-stress-v2.json` | product-policy | benchmarks: retain | payment-card/IBAN stress plan (#425); authored truth and plan data |
| `benchmarks/evaluation/domains/pii/card-iban-stress/payment-card-stress-v1.json` | product-policy | benchmarks: retain | payment-card/IBAN stress plan (#425); authored truth and plan data |
| `benchmarks/evaluation/domains/pii/card-iban-stress/payment-card-stress-v2.json` | product-policy | benchmarks: retain | payment-card/IBAN stress plan (#425); authored truth and plan data |
| `benchmarks/evaluation/domains/pii/card-iban-stress/report.ts` | product-policy | benchmarks: retain | stress plan scoring (#425); scoring logic is a parity-test vector source |
| `benchmarks/evaluation/domains/pii/card-iban-stress/stress.ts` | product-policy | benchmarks: retain | stress plan scoring (#425); scoring logic is a parity-test vector source |
| `benchmarks/evaluation/domains/pii/cases.ts` | generic-measurement | pii-eval: reimplement in Rust | schema probes plus evidence-row corpus assembly |
| `benchmarks/evaluation/domains/pii/context-evidence-v1.json` | generic-measurement | corpus author / benchmarks: retain truth | authored synthetic context evidence |
| `benchmarks/evaluation/domains/pii/context-evidence.ts` | generic-measurement | pii-eval: reimplement in Rust | context-discrimination evidence loader/validator |
| `benchmarks/evaluation/domains/pii/context-languages.ts` | generic-measurement | pii-eval: reimplement in Rust | primary context languages and polarity strata |
| `benchmarks/evaluation/domains/pii/context-vocabulary.ts` | product-policy | benchmarks: retain | product pii-context vocabulary identities as seen in activation strings |
| `benchmarks/evaluation/domains/pii/contract-model.ts` | generic-measurement | pii-eval: reimplement in Rust | authority/contract validation |
| `benchmarks/evaluation/domains/pii/contract.ts` | generic-measurement | pii-eval: reimplement in Rust | binds cases and methods to validated evidence; registers domain in shared registry |
| `benchmarks/evaluation/domains/pii/email-network-population.ts` | product-policy | benchmarks: retain | email/network population evidence (#424) |
| `benchmarks/evaluation/domains/pii/email-population-plan-v1.json` | product-policy | benchmarks: retain | product population/qualification/stress plan data |
| `benchmarks/evaluation/domains/pii/email-population-plan-v2.json` | product-policy | benchmarks: retain | product population/qualification/stress plan data |
| `benchmarks/evaluation/domains/pii/email-population-plan-v3.json` | product-policy | benchmarks: retain | product population/qualification/stress plan data |
| `benchmarks/evaluation/domains/pii/email-qualification-v1.json` | product-policy | benchmarks: retain | product population/qualification/stress plan data |
| `benchmarks/evaluation/domains/pii/execution.ts` | generic-measurement | pii-eval: reimplement in Rust | PII_ENGINE_VERSION 1.0.0 orchestration over shared substrate; fresh implementation, substrate is a seam |
| `benchmarks/evaluation/domains/pii/gap-ledger.ts` | product-policy | benchmarks: retain | beta.10 before-state gap ledger |
| `benchmarks/evaluation/domains/pii/holdout-corpus.ts` | mixed-split | split: neutral calc to pii-eval, verdict stays | holdout corpus binding; protected bytes are never in pii-eval |
| `benchmarks/evaluation/domains/pii/holdout.ts` | mixed-split | split: neutral calc to pii-eval, verdict stays | holdout partition handling; protected custody belongs to private-custodian |
| `benchmarks/evaluation/domains/pii/iban-qualification-v1.json` | product-policy | benchmarks: retain | product population/qualification/stress plan data |
| `benchmarks/evaluation/domains/pii/identity-oracle-v1.json` | product-policy | benchmarks: retain | oracle plans bound to product identity |
| `benchmarks/evaluation/domains/pii/identity-oracle.ts` | mixed-split | split: neutral calc to pii-eval, verdict stays | evaluation-only identity/sensitivity oracle; product identity format binding is product-side |
| `benchmarks/evaluation/domains/pii/identity.ts` | generic-measurement | pii-eval: reimplement in Rust | case/variant identity hashing wrapper |
| `benchmarks/evaluation/domains/pii/jurisdictions.ts` | generic-measurement | pii-eval: reimplement in Rust | ISO 3166-1 alpha-2 set pinned to ISO/TC 46 N1127 |
| `benchmarks/evaluation/domains/pii/methods/benign.ts` | generic-measurement | pii-eval: reimplement in Rust | method implementation |
| `benchmarks/evaluation/domains/pii/methods/common.ts` | generic-measurement | pii-eval: reimplement in Rust | method implementation |
| `benchmarks/evaluation/domains/pii/methods/context-discrimination.ts` | generic-measurement | pii-eval: reimplement in Rust | method implementation |
| `benchmarks/evaluation/domains/pii/methods/index.ts` | generic-measurement | pii-eval: reimplement in Rust | method implementation (registry of the seven methods) |
| `benchmarks/evaluation/domains/pii/methods/jurisdiction-collision.ts` | generic-measurement | pii-eval: reimplement in Rust | method implementation |
| `benchmarks/evaluation/domains/pii/methods/mutation.ts` | generic-measurement | pii-eval: reimplement in Rust | method implementation |
| `benchmarks/evaluation/domains/pii/methods/reference-differential.ts` | generic-measurement | pii-eval: reimplement in Rust | method implementation |
| `benchmarks/evaluation/domains/pii/methods/schema-only.ts` | generic-measurement | pii-eval: reimplement in Rust | method implementation |
| `benchmarks/evaluation/domains/pii/methods/type-validation.ts` | generic-measurement | pii-eval: reimplement in Rust | method implementation |
| `benchmarks/evaluation/domains/pii/mixed-parity/authoring.ts` | product-policy | benchmarks: retain | mixed-document parity plan (#427); source of P9 parity inputs |
| `benchmarks/evaluation/domains/pii/mixed-parity/mixed-parity-v1.json` | product-policy | benchmarks: retain | mixed-document parity plan (#427); source of P9 parity inputs |
| `benchmarks/evaluation/domains/pii/mixed-parity/mixed-parity-v2.json` | product-policy | benchmarks: retain | mixed-document parity plan (#427); source of P9 parity inputs |
| `benchmarks/evaluation/domains/pii/mixed-parity/parity.ts` | product-policy | benchmarks: retain | mixed-document parity plan (#427); source of P9 parity inputs |
| `benchmarks/evaluation/domains/pii/mixed-parity/report.ts` | product-policy | benchmarks: retain | mixed-document parity plan (#427); source of P9 parity inputs |
| `benchmarks/evaluation/domains/pii/network-address-population-plan-v1.json` | product-policy | benchmarks: retain | product population/qualification/stress plan data |
| `benchmarks/evaluation/domains/pii/network-address-population-plan-v2.json` | product-policy | benchmarks: retain | product population/qualification/stress plan data |
| `benchmarks/evaluation/domains/pii/network-address-qualification-v1.json` | product-policy | benchmarks: retain | product population/qualification/stress plan data |
| `benchmarks/evaluation/domains/pii/operators.ts` | generic-measurement | pii-eval: reimplement in Rust | mutation operator registry hooks |
| `benchmarks/evaluation/domains/pii/outcome-validation.ts` | generic-measurement | pii-eval: reimplement in Rust | axis state/status validity rules (outcome lattice) |
| `benchmarks/evaluation/domains/pii/payment-card-qualification-v1.json` | product-policy | benchmarks: retain | product population/qualification/stress plan data |
| `benchmarks/evaluation/domains/pii/peer-runtime-throughput.ts` | product-policy | benchmarks: retain | informational peer throughput (#429); not accuracy measurement |
| `benchmarks/evaluation/domains/pii/phone-qualification-v1.json` | product-policy | benchmarks: retain | product population/qualification/stress plan data |
| `benchmarks/evaluation/domains/pii/phone-stress-v2.json` | product-policy | benchmarks: retain | product population/qualification/stress plan data |
| `benchmarks/evaluation/domains/pii/phone-stress-v3.json` | product-policy | benchmarks: retain | product population/qualification/stress plan data |
| `benchmarks/evaluation/domains/pii/pii-context-v2-expectation-revisions-v1.json` | product-policy | benchmarks: retain | product population/qualification/stress plan data |
| `benchmarks/evaluation/domains/pii/populations-v1.json` | product-policy | benchmarks: retain | product-owned populations |
| `benchmarks/evaluation/domains/pii/populations.ts` | mixed-split | split: neutral calc to pii-eval, verdict stays | population contract validation (neutral) plus product population definitions and pin binding |
| `benchmarks/evaluation/domains/pii/product-binding.ts` | product-policy | benchmarks: retain | binding of qualification to product candidate |
| `benchmarks/evaluation/domains/pii/profile-cost-acceptance.ts` | product-policy | benchmarks: retain | accepted cost tradeoffs |
| `benchmarks/evaluation/domains/pii/profile-cost-v2.ts` | product-policy | benchmarks: retain | profile-cost v2 (#428) |
| `benchmarks/evaluation/domains/pii/profile-cost.ts` | product-policy | benchmarks: retain | runtime/size cost protocol of the product artifact (#286) |
| `benchmarks/evaluation/domains/pii/profile.ts` | mixed-split | split: neutral calc to pii-eval, verdict stays | ten metric ids/labels/units are neutral; thresholds, directions-as-policy and gates are product (#662) |
| `benchmarks/evaluation/domains/pii/protected-support-binding.ts` | product-policy | benchmarks: retain | protected support binding path |
| `benchmarks/evaluation/domains/pii/protected-support-bindings-v1.json` | product-policy | benchmarks: retain | product population/qualification/stress plan data |
| `benchmarks/evaluation/domains/pii/qualification.ts` | mixed-split | split: neutral calc to pii-eval, verdict stays | combines generic calculation with fixed thresholds and support verdicts; keep verdicts in benchmarks (#662) |
| `benchmarks/evaluation/domains/pii/runtime-comparison.ts` | product-policy | benchmarks: retain | runtime comparison plan/report (#562) |
| `benchmarks/evaluation/domains/pii/ssn-phone-stress.ts` | product-policy | benchmarks: retain | US SSN/phone stress plans (#426) |
| `benchmarks/evaluation/domains/pii/support-registry-v1.json` | product-policy | benchmarks: retain | product population/qualification/stress plan data |
| `benchmarks/evaluation/domains/pii/support-semantics.ts` | product-policy | benchmarks: retain | protected-disposition to support-matrix binding |
| `benchmarks/evaluation/domains/pii/support-v2.ts` | product-policy | benchmarks: retain | support-matrix v2 projection |
| `benchmarks/evaluation/domains/pii/support.ts` | product-policy | benchmarks: retain | assessment to public support projection |
| `benchmarks/evaluation/domains/pii/trusted-product-bindings-v1.json` | product-policy | benchmarks: retain | product population/qualification/stress plan data |
| `benchmarks/evaluation/domains/pii/types.ts` | generic-measurement | pii-eval: reimplement in Rust | PiiCase/Variant/Finding/Outcome types; two axes; range states |
| `benchmarks/evaluation/domains/pii/us-ssn-qualification-v1.json` | product-policy | benchmarks: retain | product population/qualification/stress plan data |
| `benchmarks/evaluation/domains/pii/us-ssn-stress-v2.json` | product-policy | benchmarks: retain | product population/qualification/stress plan data |
| `benchmarks/evaluation/domains/pii/us-ssn-stress-v3.json` | product-policy | benchmarks: retain | product population/qualification/stress plan data |
| `benchmarks/evaluation/domains/pii/validator-qualification.ts` | mixed-split | split: neutral calc to pii-eval, verdict stays | independent corpus-QA oracle (feeds P9 conformance ideas); product qualification wrapper stays |
| `benchmarks/evaluation/domains/pii/validators.ts` | generic-measurement | pii-eval: reimplement in Rust | validator hook registry (synthetic-mod10 v1, us-ssn-allocation v1) |
| `benchmarks/evaluation/domains/registry.ts` | shared-substrate | seam: neutral minimum only | domain registry registers credential, credential-policy and pii |
| `benchmarks/evaluation/release-record-evidence.ts` | shared-substrate | seam: neutral minimum only | release record evidence |
| `benchmarks/evaluation/release-record.ts` | shared-substrate | seam: neutral minimum only | release record binds PII evidence into product release (benchmarks-owned) |
| `benchmarks/evaluation/substrate/case-lifecycle.ts` | shared-substrate | seam: neutral minimum only | shared by credential and PII domains; do not move wholesale; P2-P4 re-implement only the neutral mechanics PII needs |
| `benchmarks/evaluation/substrate/hash.ts` | shared-substrate | seam: neutral minimum only | shared by credential and PII domains; do not move wholesale; P2-P4 re-implement only the neutral mechanics PII needs |
| `benchmarks/evaluation/substrate/orchestration.ts` | shared-substrate | seam: neutral minimum only | shared by credential and PII domains; do not move wholesale; P2-P4 re-implement only the neutral mechanics PII needs |
| `benchmarks/evaluation/substrate/provenance.ts` | shared-substrate | seam: neutral minimum only | shared by credential and PII domains; do not move wholesale; P2-P4 re-implement only the neutral mechanics PII needs |
| `benchmarks/evaluation/substrate/public-projection.ts` | shared-substrate | seam: neutral minimum only | shared by credential and PII domains; do not move wholesale; P2-P4 re-implement only the neutral mechanics PII needs |
| `benchmarks/evaluation/substrate/registry.ts` | shared-substrate | seam: neutral minimum only | shared by credential and PII domains; do not move wholesale; P2-P4 re-implement only the neutral mechanics PII needs |
| `benchmarks/evaluation/substrate/result-assembly.ts` | shared-substrate | seam: neutral minimum only | shared by credential and PII domains; do not move wholesale; P2-P4 re-implement only the neutral mechanics PII needs |
| `benchmarks/evaluation/substrate/review-state.ts` | shared-substrate | seam: neutral minimum only | shared by credential and PII domains; do not move wholesale; P2-P4 re-implement only the neutral mechanics PII needs |
| `benchmarks/evaluation/substrate/runtime.ts` | shared-substrate | seam: neutral minimum only | shared by credential and PII domains; do not move wholesale; P2-P4 re-implement only the neutral mechanics PII needs |
| `benchmarks/evaluation/substrate/variant-lifecycle.ts` | shared-substrate | seam: neutral minimum only | shared by credential and PII domains; do not move wholesale; P2-P4 re-implement only the neutral mechanics PII needs |
| `benchmarks/lib/accounting.ts` | shared-substrate | seam: neutral minimum only | credential-side caller of substrate/accounting-shared (compat path); outside PII scope, must keep working |
| `benchmarks/studies/pii-readiness.ts` | product-policy | benchmarks: retain | beta.9 readiness study |
| `benchmarks/support/pii-families.ts` | product-policy | benchmarks: retain | PII family list for support taxonomy |
| `docs/decisions/2026-09-27-bind-pii-publication-to-the-measured-product.md` | product-policy | benchmarks: retain (cite from ADRs) | decision/report record |
| `docs/decisions/2026-09-28-add-peer-runtime-pii-redaction-throughput.md` | product-policy | benchmarks: retain (cite from ADRs) | decision/report record |
| `docs/decisions/2026-09-28-retry-transient-pii-profile-cost-adapter-launches.md` | product-policy | benchmarks: retain (cite from ADRs) | decision/report record |
| `docs/decisions/2026-09-29-fix-pii-profile-cost-v2-candidate-artifact-roster.md` | product-policy | benchmarks: retain (cite from ADRs) | decision/report record |
| `docs/decisions/2026-09-29-run-peer-pii-throughput-in-a-pinned-docker-image.md` | product-policy | benchmarks: retain (cite from ADRs) | decision/report record |
| `docs/decisions/2026-10-01-explain-how-pii-and-credentials-are-evaluated-on-one-paired-page-design.md` | product-policy | benchmarks: retain (cite from ADRs) | decision/report record |
| `docs/decisions/2026-10-02-carry-finding-type-keys-and-the-beta11-pii-families-in-the-support-matrix.md` | product-policy | benchmarks: retain (cite from ADRs) | decision/report record |
| `docs/reports/2026-09-25-beta9-258-pii-readiness.md` | product-policy | benchmarks: retain (cite from ADRs) | decision/report record |
| `docs/specs/peer-pii-runtime-throughput.md` | product-policy | benchmarks: retain (cite from ADRs) | decision/spec/report; specs are the best written source for P2 contract freeze |
| `docs/specs/pii-benign-collision-evidence.md` | product-policy | benchmarks: retain (cite from ADRs) | decision/spec/report; specs are the best written source for P2 contract freeze |
| `docs/specs/pii-context-language-contributions.md` | product-policy | benchmarks: retain (cite from ADRs) | decision/spec/report; specs are the best written source for P2 contract freeze |
| `docs/specs/pii-identity-oracle.md` | product-policy | benchmarks: retain (cite from ADRs) | decision/spec/report; specs are the best written source for P2 contract freeze |
| `docs/specs/pii-populations.md` | product-policy | benchmarks: retain (cite from ADRs) | decision/spec/report; specs are the best written source for P2 contract freeze |
| `package-lock.json` | shared-substrate | oracle/reference only | integrity hashes for the three PII-capable npm packages |
| `package.json` | shared-substrate | oracle/reference only | dependency pins: @redact-secret/core 0.1.0-beta.12, flare-redact 1.6.1, @openredaction/core 1.1.5 |
| `qualification/peer-pii-runtime-throughput-v1.json` | product-policy | benchmarks: retain | informational throughput plan; lists three peer tools |
| `qualification/pii-national-id-arrival-v1.json` | product-policy | benchmarks: retain | national-id arrival plan |
| `qualification/pii-profile-cost-v1.json` | product-policy | benchmarks: retain | profile-cost protocol |
| `qualification/pii-profile-cost-v2.json` | product-policy | benchmarks: retain | profile-cost protocol v2 |
| `qualification/pii-profile-cost-workloads-v1.json` | product-policy | benchmarks: retain | synthetic cost workloads |
| `qualification/pii-v1.json` | mixed-split | split: neutral calc to pii-eval, verdict stays | metric ids/mechanics (minDenominator 4, replays 2, z 1.96, precision 6) are neutral; thresholds (0.5 placeholders) and gates are product |
| `qualification/suite-v1.json` | shared-substrate | oracle/reference only | peer pins: redact-secret 0.1.0-beta.12, gitleaks 8.30.1, trufflehog 3.97.4 (credential suite) |
| `scanners/candidate.mjs` | mixed-split | split: neutral calc to pii-eval, verdict stays | candidate install + activation (`initialize({pii})`); piiFindingIdentity maps product finding types to pii:<scope>:<family> (product mapping, adapter-side in P6) |
| `scanners/families.mjs` | mixed-split | oracle/reference only | native label to family mapping (credential-focused; PII labels commented as out of scope) |
| `scanners/index.mjs` | shared-substrate | oracle/reference only | adapter registry (credential adapters redact-secret, gitleaks, trufflehog, flare-redact, openredaction) |
| `scanners/peer-checksums.json` | shared-substrate | oracle/reference only | release archive SHA-256 for gitleaks and trufflehog |
| `scanners/peer-registry.json` | shared-substrate | oracle/reference only | peer kinds and descriptions |
| `scanners/pins.mjs` | shared-substrate | oracle/reference only | peer version assertion against qualification/suite-v1.json |
| `schemas/pii-accounting-report-v1.json` | generic-measurement | pii-eval: reimplement in Rust | accounting report shape; P2 re-derives canonical artifact schema, this is compat input |
| `schemas/pii-assessment-v1.json` | generic-measurement | pii-eval: reimplement in Rust | authored-contract projection shape |
| `schemas/pii-benign-collision-evidence-v1.json` | generic-measurement | pii-eval: reimplement in Rust | evidence-corpus schema |
| `schemas/pii-context-evidence-v1.json` | generic-measurement | pii-eval: reimplement in Rust | evidence-corpus schema |
| `schemas/pii-gap-ledger-v1.json` | product-policy | benchmarks: retain | gap ledger |
| `schemas/pii-population-comparison-v1.json` | mixed-split | split: neutral calc to pii-eval, verdict stays | population comparison; consumer policy composes artifacts |
| `schemas/pii-population-contract-v1.json` | generic-measurement | pii-eval: reimplement in Rust | population contract shape |
| `schemas/pii-population-report-v1.json` | mixed-split | split: neutral calc to pii-eval, verdict stays | population report |
| `schemas/pii-qualification-profile-v1.json` | mixed-split | split: neutral calc to pii-eval, verdict stays | profile with thresholds/gates |
| `schemas/pii-qualification-report-v1.json` | product-policy | benchmarks: retain | qualification verdict report |
| `schemas/pii-support-matrix-v1.json` | product-policy | benchmarks: retain | support matrix |
| `schemas/pii-support-matrix-v2.json` | product-policy | benchmarks: retain | support matrix |
| `schemas/pii-support-registry-v1.json` | product-policy | benchmarks: retain | support registry |
| `schemas/pii-validator-observation-v1.json` | generic-measurement | pii-eval: reimplement in Rust | validator observation shape |
| `schemas/pii-validator-qualification-v1.json` | mixed-split | split: neutral calc to pii-eval, verdict stays | corpus-QA oracle report |
| `scripts/build-pii-profile-cost-browser-bundle-v2.mjs` | product-policy | benchmarks: retain | browser bundle v2 |
| `scripts/build-pii-profile-cost-browser-bundle.mjs` | product-policy | benchmarks: retain | browser bundle |
| `scripts/check-pii-gap-ledger.mjs` | product-policy | benchmarks: retain | ledger check |
| `scripts/collect-pii-profile-cost-sizes-v2.mjs` | product-policy | benchmarks: retain | size collection v2 |
| `scripts/collect-pii-profile-cost-sizes.mjs` | product-policy | benchmarks: retain | size collection |
| `scripts/freeze-pii-profile-cost-thresholds-v2.mjs` | product-policy | benchmarks: retain | threshold freeze v2 |
| `scripts/freeze-pii-profile-cost-thresholds.mjs` | product-policy | benchmarks: retain | threshold freeze |
| `scripts/generate-pii-beta11-population-v2.mjs` | product-policy | benchmarks: retain | plan generation |
| `scripts/generate-pii-card-iban-stress.mjs` | product-policy | benchmarks: retain | plan generation |
| `scripts/generate-pii-mixed-parity.mjs` | product-policy | benchmarks: retain | plan generation |
| `scripts/measure-peer-pii-runtime-throughput.mjs` | product-policy | benchmarks: retain | informational throughput (shared substrate caller) |
| `scripts/measure-pii-arrival-operational.mjs` | product-policy | benchmarks: retain | arrival operational measurement |
| `scripts/measure-pii-arrival-runtime-sample.mjs` | product-policy | benchmarks: retain | arrival runtime sample |
| `scripts/measure-pii-email-network-populations.mjs` | product-policy | benchmarks: retain | population measurement |
| `scripts/measure-pii-mixed-parity.mjs` | product-policy | benchmarks: retain | mixed parity measurement |
| `scripts/measure-pii-profile-cost-v2.mjs` | product-policy | benchmarks: retain | profile cost v2 |
| `scripts/measure-pii-profile-cost.mjs` | product-policy | benchmarks: retain | profile cost |
| `scripts/measure-pii-ssn-phone-stress.mjs` | product-policy | benchmarks: retain | stress measurement |
| `scripts/measure-runtime-comparison.mjs` | product-policy | benchmarks: retain | runtime comparison (shared substrate caller) |
| `scripts/observe-pii-card-iban-stress.mjs` | product-policy | benchmarks: retain | stress observation |
| `scripts/observe-pii-populations.mjs` | mixed-split | split: neutral calc to pii-eval, verdict stays | runs product candidate over populations; drives scanners (neutral execution) bound to product candidate install |
| `scripts/observe-us-ssn-populations.mjs` | product-policy | benchmarks: retain | population measurement |
| `scripts/peer-pii-runtime-throughput/adapters.mjs` | product-policy | oracle/reference only | in-process throughput adapters for redact-secret, flare-redact, openredaction; reference for P6 scanner list |
| `scripts/pii-beta11-protected.mjs` | product-policy | benchmarks: retain | protected lifecycle; custodian handoff |
| `scripts/pii-beta11.mjs` | product-policy | benchmarks: retain | freeze/observe one core commit (beta.11 disposition) |
| `scripts/pii-parity/js-runner.mjs` | product-policy | oracle/reference only | surface-neutral job runner for @redact-secret/core JS API (#427) |
| `scripts/pii-parity/node-child.mjs` | product-policy | oracle/reference only | one JS surface per process |
| `scripts/pii-parity/python_runner.py` | product-policy | oracle/reference only | Python surface runner (#427) |
| `scripts/pii-parity/rust-runner/src/main.rs` | product-policy | oracle/reference only | Rust surface runner (product API, not a pii-eval kernel) |
| `scripts/pii-profile-cost/adapter-protocol.mjs` | product-policy | benchmarks: retain | profile-cost sampler per surface (#286/#428) |
| `scripts/pii-profile-cost/chromium-sample-v2.mjs` | product-policy | benchmarks: retain | profile-cost sampler per surface (#286/#428) |
| `scripts/pii-profile-cost/chromium-sample.mjs` | product-policy | benchmarks: retain | profile-cost sampler per surface (#286/#428) |
| `scripts/pii-profile-cost/cli-sample.mjs` | product-policy | benchmarks: retain | profile-cost sampler per surface (#286/#428) |
| `scripts/pii-profile-cost/node-sample.mjs` | product-policy | benchmarks: retain | profile-cost sampler per surface (#286/#428) |
| `scripts/pii-profile-cost/python-sample.py` | product-policy | benchmarks: retain | profile-cost sampler per surface (#286/#428) |
| `scripts/pii-profile-cost/rust-sample.rs` | product-policy | benchmarks: retain | profile-cost sampler per surface (#286/#428) |
| `scripts/pii-publication-inputs.ts` | product-policy | benchmarks: retain | publication inputs; consumer of artifacts (#665) |
| `scripts/prepare-pii-profile-cost-linux-v2.mjs` | product-policy | benchmarks: retain | linux prep v2 |
| `scripts/prepare-pii-profile-cost-linux.mjs` | product-policy | benchmarks: retain | linux prep |
| `scripts/prepare-pii-profile-cost-size-config-v2.mjs` | product-policy | benchmarks: retain | size config v2 |
| `scripts/prepare-pii-profile-cost-size-config.mjs` | product-policy | benchmarks: retain | size config |
| `scripts/produce-release-record.mjs` | shared-substrate | seam: neutral minimum only | release record producer; imports PII domain |
| `scripts/publish-pii-support.ts` | product-policy | benchmarks: retain | publication; consumer of pii-eval artifacts after benchmarks P5 (#665) |
| `scripts/qualify-pii-family-candidate.mjs` | product-policy | benchmarks: retain | family candidate qualification |
| `scripts/record-pii-support-evidence.ts` | product-policy | benchmarks: retain | support evidence recording |
| `scripts/refresh-us-ssn-arrival-data.mjs` | product-policy | benchmarks: retain | arrival data refresh |
| `scripts/run-peer-pii-runtime-throughput-docker.sh` | product-policy | benchmarks: retain | pinned docker runner |
| `scripts/run-us-ssn-protected-holdout.mjs` | product-policy | benchmarks: retain | protected holdout run; custodian handoff |
| `scripts/score-pii-port-suffix.mjs` | mixed-split | split: neutral calc to pii-eval, verdict stays | port-suffix scoring rule (#451); neutral rule candidate for P3 decision |
| `src/evaluation-domains-v2.ts` | product-policy | benchmarks: retain | site domain evaluation v2 (consumer) |
| `src/evaluation-domains.ts` | product-policy | benchmarks: retain | site domain evaluation (consumer of PII domain internals) |
| `src/pages/domain-evaluation.ts` | product-policy | benchmarks: retain | site page (consumer) |
| `src/pages/pii-support.ts` | product-policy | benchmarks: retain | site page |
| `src/pii-support-model.ts` | product-policy | benchmarks: retain | site model of PII support |
| `tests/accounting-domains.test.mjs` | shared-substrate | seam: neutral minimum only | mixed PII/credential caller or substrate test; keeps running in benchmarks |
| `tests/credential-domain.test.mjs` | shared-substrate | seam: neutral minimum only | mixed PII/credential caller or substrate test; keeps running in benchmarks |
| `tests/evaluation-substrate.test.mjs` | shared-substrate | seam: neutral minimum only | mixed PII/credential caller or substrate test; keeps running in benchmarks |
| `tests/peer-pii-runtime-throughput.test.mjs` | product-policy | benchmarks: retain | product/plan/publication test |
| `tests/peer-runtime-section.test.mjs` | shared-substrate | seam: neutral minimum only | mixed PII/credential caller or substrate test; keeps running in benchmarks |
| `tests/pii-accounting.test.mjs` | generic-measurement | behavior vectors: port as oracle/parity input (P9) | oracle behavior test |
| `tests/pii-arrival-contract.test.mjs` | product-policy | benchmarks: retain | product/plan/publication test |
| `tests/pii-benign-collision-evidence.test.mjs` | generic-measurement | behavior vectors: port as oracle/parity input (P9) | oracle behavior test |
| `tests/pii-beta11-population-v2.test.mjs` | product-policy | benchmarks: retain | product/plan/publication test |
| `tests/pii-beta11-protected.test.mjs` | product-policy | benchmarks: retain | product/plan/publication test |
| `tests/pii-beta11.test.mjs` | product-policy | benchmarks: retain | product/plan/publication test |
| `tests/pii-card-iban-stress.test.mjs` | product-policy | benchmarks: retain | product/plan/publication test |
| `tests/pii-context-evidence.test.mjs` | generic-measurement | behavior vectors: port as oracle/parity input (P9) | oracle behavior test |
| `tests/pii-domain.test.mjs` | generic-measurement | behavior vectors: port as oracle/parity input (P9) | oracle behavior test |
| `tests/pii-email-network-population.test.mjs` | product-policy | benchmarks: retain | product/plan/publication test |
| `tests/pii-gap-ledger.test.mjs` | product-policy | benchmarks: retain | product/plan/publication test |
| `tests/pii-identity-oracle.test.mjs` | generic-measurement | behavior vectors: port as oracle/parity input (P9) | oracle behavior test |
| `tests/pii-methods.test.mjs` | generic-measurement | behavior vectors: port as oracle/parity input (P9) | oracle behavior test |
| `tests/pii-mixed-parity.test.mjs` | product-policy | benchmarks: retain | product/plan/publication test |
| `tests/pii-population-publication.test.mjs` | product-policy | benchmarks: retain | product/plan/publication test |
| `tests/pii-populations.test.mjs` | product-policy | benchmarks: retain | product/plan/publication test |
| `tests/pii-port-suffix-rule.test.mjs` | product-policy | benchmarks: retain | product/plan/publication test |
| `tests/pii-profile-cost-acceptance.test.mjs` | product-policy | benchmarks: retain | product/plan/publication test |
| `tests/pii-profile-cost-v2-roster.test.mjs` | product-policy | benchmarks: retain | product/plan/publication test |
| `tests/pii-profile-cost-v2.test.mjs` | product-policy | benchmarks: retain | product/plan/publication test |
| `tests/pii-profile-cost.test.mjs` | product-policy | benchmarks: retain | product/plan/publication test |
| `tests/pii-protected-support.test.mjs` | product-policy | benchmarks: retain | product/plan/publication test |
| `tests/pii-readiness-study.test.mjs` | product-policy | benchmarks: retain | product/plan/publication test |
| `tests/pii-ssn-phone-stress.test.mjs` | product-policy | benchmarks: retain | product/plan/publication test |
| `tests/pii-support-v2.test.mjs` | product-policy | benchmarks: retain | product/plan/publication test |
| `tests/pii-ui.test.mjs` | product-policy | benchmarks: retain | product/plan/publication test |
| `tests/pii-validator-qualification.test.mjs` | generic-measurement | behavior vectors: port as oracle/parity input (P9) | oracle behavior test |
| `tests/produce-beta10-release-record.test.mjs` | shared-substrate | seam: neutral minimum only | mixed PII/credential caller or substrate test; keeps running in benchmarks |
| `tests/produce-release-record.test.mjs` | shared-substrate | seam: neutral minimum only | mixed PII/credential caller or substrate test; keeps running in benchmarks |
| `tests/release-record.test.mjs` | shared-substrate | seam: neutral minimum only | mixed PII/credential caller or substrate test; keeps running in benchmarks |
| `tests/runtime-comparison.test.mjs` | shared-substrate | seam: neutral minimum only | mixed PII/credential caller or substrate test; keeps running in benchmarks |
| `tests/support-matrix-finding-types-and-pii.test.mjs` | product-policy | benchmarks: retain | product/plan/publication test |
| `web/app/evaluation/pii/page.tsx` | product-policy | benchmarks: retain | site page for the PII domain (consumer) |
| `web/services/domains.ts` | product-policy | benchmarks: retain | imports evaluator internals; to read versioned artifacts instead (#665) |
| `web/services/runtime.ts` | product-policy | benchmarks: retain | imports evaluator internals; to read versioned artifacts instead (#665) |

## Grouped evidence and protected material

Listed by glob rather than per file (85 PII-named files under `evidence/`, 9 under `holdout/`). Frozen evidence is not ported; replay-parity inputs derived from it are selected in P9 after the P2 contract freeze, and only synthetic observations qualify.

| Path group | Class | Target | Note |
| --- | --- | --- | --- |
| `evidence/875..880/pii-*.json (5 dirs x 3-6 files)` | product-policy | benchmarks: retain | family activation, qualification and support-matrix v2 evidence |
| `evidence/286/pii-profile-cost-*.json, evidence/429/peer-pii-runtime-throughput.json, evidence/562/runtime-comparison-pii-*.json` | product-policy | benchmarks: retain | cost/throughput/runtime evidence |
| `evidence/901/428/core-*/ (52 files)` | product-policy | benchmarks: retain | beta.11 freeze/observation/operational/report/disposition per core commit; frozen oracle outputs, candidates for P9 replay parity inputs after contract review |
| `evidence/901/{424,426,451}/, evidence/901/pii-gap-ledger-v1.json` | product-policy | benchmarks: retain | population, stress and gap-ledger evidence |
| `holdout/pii-b11-*.json, holdout/PII-CUSTODIAN.md, holdout/pii-custodian-template.json (9 files)` | product-policy | private-custodian handoff; never copied into pii-eval | protected/holdout partition material; pii-eval must not ingest or copy it |

## Gaps and decisions for later phases

P2 recorded the contract-bearing `mixed-split` decisions in
[ADR 0002](../adr/0002-freeze-pii-contracts-v1.md) (versions and metric
definitions are frozen in `schemas/registry/pii-v1.registry.json` and checked
against the tables above by a test).

- `mixed-split` rows (profile, qualification, populations, identity oracle,
  holdout, validator qualification, `candidate.mjs`, `families.mjs`, port-suffix
  scoring, population schemas) need an explicit neutral/product split before
  implementation. P2 records the split; benchmarks keeps the verdict side.
- Legacy selection (first overlapping finding), duplicate handling and label
  mappings were decided in P3: the legacy rule is reproduced unchanged as
  `legacy-first-overlap` in `pii-eval-compat` (source: `contract-model.ts`
  `interpretPiiOutcome`/`rangeOutcome`, which the map lists as `pii:
  reimplement in Rust`), and the order-invariant `pii-v1-canonical` rule is
  specified in [ADR 0004](../adr/0004-order-invariant-pii-matching.md) with its
  classified difference list. Native label to family mapping stays adapter-side
  (P6).
- The inventory lists importers by direct import. Dynamic or string-built paths
  (for example package scripts calling `tsx` with computed arguments) were not
  traced; P9 must re-check callers before any cutover.
- Evidence files were classified by name and directory, not opened one by one.
