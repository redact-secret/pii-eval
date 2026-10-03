# Custodian contract status (what is decided, what is not)

Status: **read-only extraction, 2026-10-03.** Source: `redact-secret/private-custodian`
`main` at commit `142db34dd4bc02903f47cba951a054351bb55fde` (its head when this was read,
equal to the local checkout) and its open issues #27 to #33 (Epic 2, S1 to S6). Nothing in
that repository was changed. File references below are to that commit.

Rules this repository follows (they are what the worker launcher implements):

1. **Decided** means the custodian's code and documents state it and test it. It is
   implemented exactly as stated, never re-asked and never overridden with a different
   default.
2. **Not decided** means the custodian states the gap, or its documents and code do not
   say. It is isolated behind an adapter with an explicit status (`Decided`, `Proposed`,
   `TestOnly`). A production build runs only adapters that are `Decided`. A `Proposed` or
   `TestOnly` adapter cannot be selected by an operator in a release binary: the production
   path fails closed with a fixed reason, and the test adapters are compiled only with a
   test feature and are absent from the engine artifact built by CI.
3. No field (expiry, freshness, nonce) is added to either side's contract without the
   other side's agreement.

## A. Decided by the custodian

| # | Fact | Evidence |
| --- | --- | --- |
| A1 | The engine is started as `/stage/engine --job /job/job.json`. Mounts: `/stage` read-only, `/input` read-only, `/job` read-only, `/scratch` a size-capped tmpfs and the only writable place; working directory `/scratch`. | `docs/worker-isolation.md` §6-7; `crates/custodian-worker/src/dispatcher.rs` (`program`, `args`, `ro_mounts`); `bwrap.rs` |
| A2 | Staged artifacts are **single regular files** named `engine`, `adapter`, `candidate`, `config` and `scanner-N`. Their SHA-256 is frozen in the approved plan, checked before any protected input is touched, again after staging and after execution. A mismatch is a rejection. Everything except `config` is staged executable. | `dispatcher.rs` `pins()`; `docs/worker-isolation.md` §6 |
| A3 | Protected inputs are flat regular files `/input/<entry>`; entry names match `[a-z0-9][a-z0-9._-]{0,63}`; at most 16 MiB each; **archives are not accepted** for inputs. | `artifacts.rs` (`MAX_INPUT_BYTES`, `validate_member_path`); `docs/worker-isolation.md` §6 |
| A4 | Job document `private-custodian.worker-job/1`: `{schema, domain, protocol{name,version}, roster, entries[]}` where `roster` is the **number of entries**. | `crates/custodian-worker/src/result.rs` `job_document` (`roster: entries.len()`) |
| A5 | Result: exactly one `private-custodian.worker-result/1` JSON document on stdout, at most 64 KiB: `{schema, domain, protocol{name,version}, status: complete\|partial, roster{expected,observed,failed}}`. Unknown fields, duplicate keys, trailing data, another domain or protocol, `expected` different from the authorized roster, `observed > expected`, `failed > observed` and a status that disagrees with the counters are rejected. | `result.rs` `validate_result`; `docs/worker-isolation.md` §7 |
| A6 | Outcome mapping: clean exit with `complete` and `observed = expected`, `failed = 0` is Success; clean `partial` or any failed item is Partial; crash, signal, non-zero exit, timeout and output limits are Failed; a malformed or mismatching document is Rejected. A worker that did not exit cleanly never has its stdout parsed. stderr is counted, discarded, never kept (at most 1 MiB). All of these consume budget except a refusal before exposure. | `docs/worker-isolation.md` §7; `result.rs` |
| A7 | Environment: only `PATH`, `HOME`, `PWD`, `TMPDIR`, `LANG`, `CUSTODIAN_STAGE_ROOT`, `CUSTODIAN_INPUT_ROOT`, `CUSTODIAN_JOB_ROOT`, `CUSTODIAN_SCRATCH` reach the worker; credential-looking names are refused. | `sandbox.rs` `ENV_ALLOWLIST`, `DENY_FRAGMENTS` |
| A8 | Isolation: `bwrap` with new user, IPC, PID, network, UTS (cgroup if available) namespaces, all capabilities dropped, new session, `--clearenv`, read-only `/usr`, `/lib*`, `/bin`, `/sbin`, `/proc`, `/dev`, tmpfs `/scratch`; then `/usr/bin/prlimit --cpu --as --nproc --fsize --core=0 --nofile=256`, then the program. `RLIMIT_AS` is the plan's `memory` limit; it bounds virtual address space. | `crates/custodian-worker/src/bwrap.rs` `build_argv`; `docs/worker-isolation.md` §3, §5 |
| A9 | Quotas come from the approved plan, capped by operator caps (defaults: 3600 s CPU, 3600 s wall, 8192 MiB memory, 4096 MiB storage, 256 processes). The custodian's real Linux tests use cpu 30 s, wall 20 s, **memory 512 MiB**, storage 64 MiB, 32 processes as their "normal" limits. | `dispatcher.rs` `OperatorCaps`; `tests/common/mod.rs` `Limits::normal` |
| A10 | Digest syntax: custodian digests are `sha256:` plus 64 lowercase hex; keyed population commitments are `hmac-sha256:` plus 64 hex; labels (strata, metrics) match `[a-z0-9][a-z0-9._-]{0,63}`. | `crates/custodian-contracts/src/types.rs` |
| A11 | `private-custodian.aggregates/1`: `{schema, domain, protocol{name,version}, roster{expected,observed,failed}, cells[{stratum, metric, numerator, denominator}]}`; 1 to 256 cells; at most 64 KiB; closed (`deny_unknown_fields`); its bytes must hash to the digest in the receipt's `result` reference; its roster must equal the receipt's; strata and metrics must be on the disclosure policy's allowlist; a denominator may not exceed `observed`. | `crates/custodian-disclosure/src/aggregate.rs`; `docs/disclosure.md` |
| A12 | pii-eval deliverables, stated by the custodian: emit `worker-result/1` (domain, protocol, roster counters only); emit the `aggregates/1` artifact bound to the roster counters; keep the protected artifact internal; reject `population-binding-mismatch` and `run-class-mismatch`; a synthetic round trip validating domain, candidate, activation and population bindings. | `docs/benchmarks-integration.md` §4, §5 |
| A13 | Supported isolation: Linux, kernel 5.14 or later, unprivileged user namespaces, bubblewrap 0.8 or later, `prlimit`. macOS and hosts that fail the startup self-check run nothing. A Docker run is **not accepted as evidence**; the evidence is an Ubuntu CI job that fails if an isolation test is skipped. | `docs/worker-isolation.md` §8, §9; custodian `.github/workflows/ci.yml` job `worker-isolation` |

## B. Not decided (and what the launcher does about each)

The numbering is the open-question table of [custodian-boundary.md](custodian-boundary.md) §6.

| Q | Status | What is known | What this repository does |
| --- | --- | --- | --- |
| Q1 roster unit for PII | **Partly decided.** The unit is an input *entry* (A4). What an entry holds for PII and which engine count equals the roster is not specified; entries are opaque to the custodian. | A3, A4, A11 | Adapter `EntryFormat`, status `Proposed`: one entry is one authored case (`pii-eval-worker-entry/1`, engine-owned and opaque to the custodian). Every aggregate denominator must be at most `observed`; if a metric's denominator would exceed it the launcher refuses (`aggregates-roster-violation`) instead of clamping. |
| Q2 delivery of the aggregates artifact | **Not decided.** `release-readiness.md` D2 and R-3: no production code assembles an `ExecutionRecord` or `InternalReceipt` from a `DispatchReport`, "the worker result carries only a roster and the aggregates artifact has no producer". The test-only assembly (`crates/custodian-cli/tests/c12/mod.rs` `assemble`) takes the roster from the validated worker result and makes the receipt's `result` reference the digest of a **separate** aggregates document. The production pipeline is S5, [#32](https://github.com/redact-secret/private-custodian/issues/32). | A5, A11 | Adapter `AggregatesChannel`, status `Proposed`: no production implementation exists, so a release binary refuses (`contract-not-final: aggregates-channel`). A test channel (a file under `/scratch`) exists only behind the test feature. |
| Q3 pii strata and metric labels | **Not decided.** Labels are allowlisted by a per-domain `DisclosurePolicy`; policy values are placeholders (`release-readiness.md` HG-9) and none exists for pii. | A10, A11 | Adapter `AggregateLabels`, status `Proposed`: stratum `overall` and the ten `pii-v1` metric ids, all valid labels. Further strata only after a policy allowlists them. |
| Q4 candidate identity for a package tree | **Not decided.** Staged files are single files; the custodian's candidate id is the SHA-256 of the exact file bytes. The engine pins scanner packages by a **tree** digest. | A2, A10 | Two typed digests that are never converted into each other: the **bundle (archive) file digest** (custodian side) and the **package tree digest** (engine side). The bundle format is `Proposed`. Verifying one never substitutes for verifying the other. |
| Q5 digest syntax | **Decided custodian-side** (A10). The conversion on the engine side is ours. | A10 | Distinct Rust types (`CustodianDigest`, `EngineDigest`, `BundleDigest`, `TreeDigest`); conversions are explicit named functions; no `From` between them. |
| Q6 several scanners | The custodian allows `scanner-N`; the engine artifact has per-scanner metrics but the aggregates have no scanner dimension. | A2, A11 | One scanner per run (our choice, unchanged). |
| Q7 Node under `RLIMIT_AS` | **Untested** by either side. | A8, A9 | Measured on a real Linux bubblewrap host: [custodian-isolation-node.md](custodian-isolation-node.md). The limits are never loosened to make a run pass. |
| Q8 freshness of a stale context | **Not decided.** Neither the worker job document nor `pii-eval-job-context/1` has an expiry field. | A4 | No field is added. A stale or foreign job is detected only by binding mismatch (entries, roster, digests). Time-based freshness stays with the custodian. |
| Q9 where Node, the shim and the package live in the staged set | **Not decided.** The custodian fixes only the names (A2). | A2 | Adapter `StageLayout`, status `Proposed`: `engine` = the `pii-eval` binary, `adapter` = a bundle holding the Node shim, `candidate` = a bundle holding the scanner package, `scanner-0` = the pinned Node runtime, `config` = the worker configuration. |
| Q10 rejection names | **Decided** (A12). | A12 | Implemented: `population-binding-mismatch`, `run-class-mismatch`. |

## C. Custodian issues that relate to this work

The custodian's open issues are Epic 2 [#27](https://github.com/redact-secret/private-custodian/issues/27)
and S1 to S6 ([#28](https://github.com/redact-secret/private-custodian/issues/28) to
[#33](https://github.com/redact-secret/private-custodian/issues/33)). None of them mentions
pii-eval, the aggregates delivery, the candidate packaging or a Node runtime. The
relevant one is S5 [#32](https://github.com/redact-secret/private-custodian/issues/32) (the
request-to-projection pipeline that builds the receipt from a dispatch report and runs a
"real Linux isolation job"). The follow-up issue that records Q2, Q3, Q4, Q7 and Q9 for the
custodian is linked from [custodian-boundary.md](custodian-boundary.md) once it exists.

## D. Correction of an earlier statement

`custodian-boundary.md` Q2 said that `validate_result` hashes the `worker-result/1` stdout
as the private artifact reference and `PrivateAggregates::decode` requires those same bytes
to be an aggregates document, so "one document cannot be both". That was read from the
types and overstated: the custodian's own test-only assembly uses a separate aggregates
document for the receipt's `result` and the worker result only for the roster. What is
established is only that the production assembly does not exist (R-3) and the channel by
which the aggregates document reaches the custodian is unspecified.
