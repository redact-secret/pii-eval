# Custodian boundary and consumer contract

Status: **versioned proposal plus an implemented engine side** (P12, issue #13;
decisions: [ADR 0014](adr/0014-custodian-boundary-and-consumer-contract.md)).
This repository owns measurement and its artifacts. It does not own
authorization, budgets, isolation, disclosure or revocation; those belong to
[private-custodian](https://github.com/redact-secret/private-custodian). Where
that repository has specified something, this document cites it and does not
restate it as ours; where it has not, this document says so and states only what
**this** side offers. Nothing here is deployed, registered or live.

The engine never publishes a protected result. Everything a protected run
produces is internal until the custodian projects it; the engine has no
publication code path for a protected population.

## 1. Evidence base (read on 2026-10-03, read-only)

| Source | What it establishes | State |
| --- | --- | --- |
| private-custodian issues 3 (contracts), 4 (intake), 7 (isolated workers), 12 (benchmarks integration) | The custodian's side of the boundary | All four **closed**; implemented as synthetic-tested libraries, **not deployed** (its `docs/contracts.md`, section 9; `docs/worker-isolation.md`) |
| private-custodian `docs/contracts.md` | Document set, canonical encoding (`custodian-canonical-json/1`), digests (`sha256:` plus 64 hex, domain separated), bounds, freshness and revocation semantics, attestation wording | Specified and implemented |
| private-custodian `docs/worker-isolation.md`, ADR 0042 | **Worker protocol v1**: the engine is started as `/stage/engine --job /job/job.json`; `private-custodian.worker-job/1` in, one `private-custodian.worker-result/1` document on stdout (at most 64 KiB), domain and protocol checked, roster counters checked, non-zero exit never parsed | Specified and implemented custodian-side |
| private-custodian `docs/disclosure.md`, `docs/benchmarks-integration.md` | `private-custodian.aggregates/1` (strict, closed, at most 256 cells and 64 KiB, integer numerator and denominator per policy stratum and metric); the bridge request, signed `PublicProjectionEnvelope`, signed revocation feed and the consumer's verification table | Specified and implemented custodian-side (synthetic) |
| private-custodian `docs/benchmarks-integration.md`, section 4 | Names pii-eval deliverables: emit `worker-result/1`; emit the `aggregates/1` artifact; keep the protected artifact internal; reject population and run-class mismatch; run a synthetic round trip | **Absent engine side** (its `docs/release-readiness.md` D2 and HG-5 list it as a blocker owned by the engines) |
| Local checkout of private-custodian at commit `142db34dd4bc02903f47cba951a054351bb55fde` | The documents above | Not fetched; may be behind its remote |

What the custodian has **not** specified for PII, and which this document
therefore does not invent: what a PII "roster" counts, which strata and metric
labels its disclosure policy allows for the pii domain, how the aggregates
artifact travels (section 6, questions Q1 to Q3), and any transport.

## 2. Responsibilities

| Concern | Custodian | Engine (this repository) | Benchmarks |
| --- | --- | --- | --- |
| Authorize a protected run, reserve budget, bind approval | Yes | Never | Never |
| Verify domain, plan, candidate, configuration, population before dispatch | Yes (hashes checked before any protected input is touched) | Re-checks every identity it is given before launching anything (docs/cli.md) | Never |
| Isolation (network, filesystem, processes, credentials) | Yes; the self-check is the evidence | Process hygiene only; **not a sandbox** (SECURITY.md) | Never |
| Measure | Never | Yes | Never |
| Verify the engine's private output | Yes (strict, bounded, bound to the roster) | Provides `validate` and the accounting verifier | Never |
| Decide what may leave (disclosure, small-cell suppression, release approval) | Yes | Never | Never |
| Sign, publish, revoke | Yes (signed projection envelope and revocation feed) | Never. A signature attests execution identity, not truth | Verifies, never signs |
| Thresholds, support status, stable or provisional | Never | Never | Yes |
| Public synthetic runs | Not involved | Yes, with no custodian and no GitHub | Consumes the public artifact |

## 3. Layers and who owns each contract

| Layer | Document | Owner | Version | State |
| --- | --- | --- | --- | --- |
| L1 job context | `pii-eval-job-context/1` ([docs/cli.md](cli.md)) | pii-eval | 1 (unchanged by P12) | Implemented in the CLI |
| L2 worker job and result | `private-custodian.worker-job/1`, `private-custodian.worker-result/1` | custodian | 1 | Implemented custodian-side; the engine speaks it in `pii-eval worker-job` ([worker-job.md](worker-job.md)), **which refuses in every production build** until the custodian decides the items of [custodian-contract-status.md](custodian-contract-status.md) |
| L3 aggregates | `private-custodian.aggregates/1` | custodian | 1 | Implemented custodian-side; the engine builds it behind a channel adapter that has no production implementation (Q2) |
| L4 internal artifact | `RunArtifact`, schema `pii-eval.run-artifact` 1.1, plus manifest and observation sets | pii-eval | schema 1.1, protocol `pii-v1` revision 2 | Implemented |
| L4 public artifact | `PublicSyntheticArtifact`, schema `pii-eval.public-synthetic-artifact` 1.1 | pii-eval | schema 1.1 | Implemented; **public synthetic runs only** |
| L5 released projection and revocation | `PublicProjectionEnvelope`, `SignedRevocationEnvelope` | custodian | 1 | Implemented custodian-side; consumed by benchmarks, never by the engine |
| Pins and the consumer report | `pii-eval-consumer-pins/1`, `pii-eval-consumer-report/1` | pii-eval (example) | 1 | Implemented in `examples/consumer/` |

L1, L4 and the CLI exit codes are the engine's contract and change only through a
versioned revision. L2, L3 and L5 are the custodian's; this repository follows
them and proposes changes only through section 6. Rust types of the crates are
internal and are not part of any contract (ARCHITECTURE.md).

## 4. The job, step by step (what each side supplies and verifies)

```text
custodian                                          engine (pii-eval run)
---------                                          ---------------------
authorize request, reserve budget (its state)
verify domain, plan, candidate, config, population
verify policy activation is current (its state)
stage inputs read-only; write the job context  --> job context (L1): population digest, manifest digest,
                                                   candidate digest, input root, output root
                                                   [refuses before reading any input if absent or invalid (exit 9)]
                                                   [confines inputs/outputs to the roots; re-checks every digest
                                                    against the snapshot, manifest and scanner (exit 9 or 4)]
                                                   measure; verify the artifact; write INTERNAL documents only
read the internal documents; validate strictly <-- manifest.json, observation-*.json, run-artifact.json
check domain, candidate, scanner activation,
population, manifest, run class, completeness
re-check freshness and revocation NOW
project to an allowlisted aggregate; sign; ledger
release only through an approved envelope
```

| Binding | Supplied by | Carried in | Checked by the engine | Checked by the custodian |
| --- | --- | --- | --- | --- |
| Domain (`pii`) | Approved plan | Protocol identity `pii-v1` in the manifest and artifact; `domain` of L2 and L3 | The CLI is PII only: an artifact is `pii-v1` or it is refused | Result domain and protocol must equal the frozen ones (`worker-result/1` check); the stub also compares the artifact's protocol |
| Candidate | Approved plan (candidate digest) | `candidateDigest` of the job context; `product.candidateDigest` of the scanner identity | Context digest equals the scanner package's tree digest (exit 9 `protected-context-mismatch`); manifest pin (exit 4) | Hash of staged candidate before and after execution; compares the artifact identity |
| Scanner configuration and activation | Approved plan | Manifest digest in the job context; `configurationDigest` and `activationDigest` in the scanner identity | Adapter-derived plan must equal the manifest's; running scanner re-verifies activation (exit 4) | Compares the digests it approved with the artifact's |
| Population | Approved plan, protected storage | `populationDigest` in the job context; `population` in manifest and artifact | Context digest equals the snapshot's (exit 9); manifest binds by digest and run class (exit 4) | Population binding returned by its corpus must equal the plan's; compares the artifact's |
| Run class | Approved plan | `runClass: protected` in context, manifest, artifact | A protected run is official, needs a context, writes no public projection | Artifact must be `protected` |
| Budgets, approvals, expiry, revocation | Custodian | **Nowhere in the engine**: no field of any engine document | Not visible to the engine | Enforced before start and again before release |

**Terminology collision.** The engine's *scanner activation* is the set of
detector selectors a scanner was configured with (`pii:global`, `pii:us`), bound
by `activationDigest`. The custodian's *policy activation* is a signed,
append-only record that makes a disclosure or approval policy current. They are
different things. The engine can attest only the first; the second is entirely
the custodian's freshness state and never reaches the engine. Documents must say
which one they mean.

## 5. Results, failures and exit semantics

Engine exit codes are frozen ([docs/cli.md](cli.md)). The custodian's dispatcher
maps by process outcome, not by our codes: a non-zero exit is `Failed` and
stdout is never parsed (its `docs/worker-isolation.md`, section 7).

| Engine outcome | Exit | What exists | Custodian handling (documented by it) | Consequence for the engine contract |
| --- | --- | --- | --- | --- |
| Measurement complete | 0 | Internal documents, artifact `complete`, scanner `complete` | Parse the result; `Success` only when observed equals expected and nothing failed | The only releasable state |
| Scanner did not complete | 5 | Documents are written and record the failure | Non-zero exit: `Failed`, consumed | The artifact says `incomplete`; never a clean scan. Never released |
| Invalid input, provenance mismatch | 3, 4 | Nothing | `Failed` | Fail closed |
| Refused execution (limits, platform) | 6 | Nothing | `Failed` | Windows and unsupported hosts are refused |
| Output failure | 7 | Possibly partial; no `run-artifact.json` | `Failed` | A directory without `run-artifact.json` is an incomplete run |
| Cancelled | 8 | Nothing committed | `Cancelled` (or `Failed`) | The custodian's supervisor kills the tree on its side as well |
| Protected context missing, invalid, mismatching, path outside | 9 | Nothing written, no input read in the missing case | `Failed` | **Budget consequence:** the custodian records exposure before it opens the corpus, so an engine refusal after staging is still a consumed attempt. Verify the context locally before dispatch |
| Internal error | 1 | Nothing | `Failed` | Never caused by a scanner |

The custodian's outcome classes (its `docs/worker-isolation.md`, section 7): a
clean exit whose stdout is malformed, oversized, of the wrong domain or protocol, or
whose roster counters differ from the authorized roster is **Rejected** (reason
`result_*` or `roster_mismatch`), and a Rejected attempt is consumed; a crash, signal,
timeout, non-zero exit or output over its bound is **Failed**; neither is ever parsed
into a measurement. An engine that prints a wrong roster therefore costs the attempt
just as a refusal after exposure does.

**Reason names.** The custodian's own rejection names for the engine's refusals,
`population-binding-mismatch` and `run-class-mismatch` (its
`docs/benchmarks-integration.md`, section 4), are used by `pii-eval worker-job`
([worker-job.md](worker-job.md)). The standalone `run` and the test stub of
`custodian_round_trip.rs` keep the engine's frozen vocabulary
(`protected-context-mismatch`, exit 9; the stub's `Mismatch` variants).

Every refusal is a closed reason code; no text carries a value, a path or scanner
output (docs/cli.md).

**Expiry and revocation.** The job context has no clock and no revocation field
and the engine has no authority to evaluate either: it grants nothing and
validates structure and digests. Freshness belongs to the custodian: it must
refuse to write a context for an expired or revoked job, and must check current
state again before releasing (a prior success is evidence, never permission:
`docs/contracts.md`, section 5). A leftover context file is still structurally
valid; deleting it after the run is the custodian's job (open question Q8).

## 6. Joint contract: what is decided, what is proposed

**Current state (2026-10-03).** The launcher exists: `pii-eval worker-job`
([worker-job.md](worker-job.md), [ADR 0015](adr/0015-worker-job-launcher-and-contract-adapters.md)).
What the custodian has decided is implemented as stated; every item it has not
decided is an adapter with a status, and a production build refuses with
`contract-not-final` until each is decided. The evidence for every decided and
undecided item, with the custodian's source locations, is in
[custodian-contract-status.md](custodian-contract-status.md), which supersedes the
text below where they differ. The text below is the original proposal (ADR 0014
D4), kept for its reasoning:

- **P1. Owner and shape.** The launcher is engine-owned (it needs the engine's
  identity checks), a subcommand that prints exactly one `worker-result/1` document
  on stdout, and nothing else. Built as `pii-eval worker-job --job FILE` (the name
  differs from the one first proposed).
- **P2. Mapping.** `domain` is `pii`. `protocol` is `{name: "pii-v1", version: "2"}`
  (the protocol id and revision). *Superseded:* `roster` is the number of entries of
  the job (A4), and one entry is one authored case (a proposed adapter, Q1); the
  outcome-row count proposed here does not fit the custodian's job document, whose
  roster is the number of entries. `failed` is 0 for a complete scanner and
  `expected` otherwise; `status` follows coverage only (worker-job.md).
- **P3. Aggregates.** Cells are `{stratum: "overall", metric: <pii-v1 metric id>,
  numerator, denominator}` where the denominator is the metric's `measured` count.
  Ten metric ids and one stratum satisfy the custodian's label pattern. Further
  strata (language, jurisdiction, method) need the custodian's disclosure policy to
  allowlist them first. The engine emits integers only; suppression of small cells
  is the custodian's.
- **P4. Delivery.** Stdout carries `worker-result/1`; the aggregates artifact needs a
  second channel, an adapter with no production implementation (Q2). The synthetic
  test (`crates/pii-eval-cli/tests/custodian_round_trip.rs`) builds both documents
  from the internal artifact as a stub; the engine's own documents come from
  `worker-job` (`worker_custodian.rs` validates them with a replica of the
  custodian's checks).

Open questions for the joint design (nothing below is decided):

| # | Question | Why it matters |
| --- | --- | --- |
| Q1 | What does a PII roster count (inputs, variants, outcome rows)? | The custodian checks `denominator <= observed` and ties counters to the receipt |
| Q2 | How is the aggregates artifact delivered? Established: the custodian's production assembly of an `ExecutionRecord` or `InternalReceipt` from a dispatch report does not exist (its `docs/release-readiness.md` D2 and R-3: "the aggregates artifact has no producer"); its test-only assembly (`crates/custodian-cli/tests/c12/mod.rs` `assemble`) takes the roster from the validated worker result and makes the receipt's `result` reference the digest of a **separate** aggregates document. The channel by which that document reaches the custodian is unspecified | An earlier version of this row said that one document cannot be both; that was read from the types and overstated ([custodian-contract-status.md](custodian-contract-status.md), section D). The engine's adapter for the channel has no production implementation, so a release binary refuses (`contract-not-final: aggregates-channel`); the production pipeline is the custodian's S5 ([#32](https://github.com/redact-secret/private-custodian/issues/32)) |
| Q3 | Which strata and metric labels does the pii disclosure policy allow? | An unlisted label is refused (`stratum_not_allowed`, `metric_not_allowed`) |
| Q4 | Candidate identity: the custodian's candidate id is the SHA-256 of the exact candidate bytes; the engine's candidate digest is the tree digest of a scanner package directory | A package is a tree, not one file; the mapping (or a packaged single artifact) must be agreed |
| Q5 | Digest syntax: custodian `sha256:` plus hex with domain tags; engine bare hex with its own construction | Bridge code must not conflate them; never compare across syntaxes |
| Q6 | One scanner per run: the engine artifact has per-scanner metrics, the aggregates have no scanner dimension | One scanner per run today (docs/cli.md known limits); several need an agreed axis |
| Q7 | Does the isolation self-check cover pii-eval with Node? The engine needs Node and `ps`, and samples memory with `ps`; the custodian applies `RLIMIT_AS`, which a Node runtime may not tolerate | **Untested**; this repository ran no sandbox and makes no claim |
| Q8 | Defence in depth for a stale context file: an optional `notAfter` in a future `pii-eval-job-context/2`, or the custodian removing the file | Not needed for correctness while the custodian owns freshness |
| Q9 | Where the staged scanner package, shim and Node live under `/stage` | The allowlist hashes artifacts by file; the engine pins a package tree |
| Q10 | Adopt the custodian's rejection names (`population-binding-mismatch`, `run-class-mismatch`) in the launcher and the stub | Decided by the custodian; implemented in `worker-job`. The stub of `custodian_round_trip.rs` keeps the engine's vocabulary |

## 7. Raw and internal versus public artifacts

| Document | Class | Who may read it | Notes |
| --- | --- | --- | --- |
| Snapshot, manifest, observation sets of a protected population | Protected / internal | The custodian's worker only | Contain input text, seeds, case identities |
| `run-artifact.json` of any run | Internal | The party that ran it | Per-case rows and observation identities. A protected one never leaves the custodian |
| `public-synthetic-artifact.json` | Public projection | Anyone | Only a `public-synthetic` population can be projected; the schema has one-valued class and visibility types (a protected population cannot be represented) |
| Summary line on stdout | Sanitized | The caller | Identities, statuses, file sizes; counts withheld for protected runs |
| Custodian `PublicProjectionEnvelope`, revocation feed | Public, signed | Benchmarks | Not produced or read by the engine |

A public projection is not a support decision, and a public-synthetic candidate
run remains candidate evidence ([ARCHITECTURE.md](../ARCHITECTURE.md)).

## 8. Disclosure and revocation

The engine participates in neither. Disclosure of a protected aggregate is a
custodian decision made on current state (its `docs/disclosure.md`); the consumer
verifies a signed envelope and the revocation feed (its
`docs/benchmarks-integration.md`, section 2). A consumer of engine artifacts holds
the same obligation for public artifacts in a weaker form: pin exact digests, retire
superseded ones, and re-evaluate when a pin changes (`examples/consumer/`).

## 9. Signatures and attestation

A signature attests execution identity, not truth. A custodian signature attests that a given execution identity (engine, candidate,
configuration, population commitment) produced a given aggregate under its
procedures. It does not attest that the expected results are true, that a reviewer
was independent, or that the scanner is good; the custodian's own contracts say
`ground_truth: not_established` and organizational independence `not_claimed`. The
engine signs nothing. Its semantic digests identify content, not authorship.

## 10. The consumer example

`examples/consumer/` is a dependency-free Node program (standard library only; no
import of any pii-eval code) that reads the published JSON documents and the
caller's exact pins, verifies identity and bindings, rejects wrong, stale and
mismatched artifacts with explicit reasons, composes populations without pooling
and makes no stable or provisional decision. Behavior, the pins format and the
reason codes: [examples/consumer/README.md](../examples/consumer/README.md).
It is a reference for benchmarks' own client (redact-secret-benchmarks issue 665),
not a replacement for it, and it does not verify custodian envelopes.

## 11. Evidence and limits

| Claim | Evidence |
| --- | --- |
| Context-bound protected run; internal documents only; no public projection | `cli_run.rs` protected tests; `custodian_round_trip.rs` |
| Domain, candidate, activation, population, manifest, run class bound and wrong ones refused or rejected | `custodian_round_trip.rs` (engine refusals exit 9; stub rejections) |
| Missing, wrong-domain, expired and revoked jobs never start; revoked results are never released | `custodian_round_trip.rs` |
| Tampered internal artifact fails the engine's verifier | `custodian_round_trip.rs` |
| The consumer accepts only exact, current, complete public artifacts and never the internal one | `examples/consumer/test/consume.test.mjs`; `consumer_fixtures.rs` (fixtures generated by the real engine) |
| No protected population or ledger field in committed documents; the public schema cannot represent either | `public_release_hygiene.rs` |

Limits: the custodian in `custodian_round_trip.rs` is a **stub** written here from the custodian's
documents (the worker-job tests use a replica written from its source, not its code); it proves our side of the contract, not the custodian's code, and no
private-custodian code or test ran. The projection mapping is a proposal. No
sandbox, signature, transport or deployment was exercised. The checks over
committed documents are a tripwire and do not replace a history scan before
publication.
