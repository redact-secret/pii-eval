# ADR 0011: Thin internal GitHub App (service core and Checks)

- Status: accepted for P11 (issue #12); subject to review.
- Date: 2026-10-03
- Related: [ADR 0006](0006-scanner-adapter-boundary.md),
  [ADR 0009](0009-bounded-execution-and-artifact-writing.md),
  [ADR 0010](0010-standalone-cli-workflows.md),
  [SECURITY.md](../../SECURITY.md), [docs/github-app.md](../github-app.md), epic #1.
  Implementation: `crates/pii-eval-app/`.

## Context

ARCHITECTURE.md proposes an internal GitHub App as a thin adapter: it accepts
an evaluation request, invokes the pinned engine, and posts sanitized status. It
holds no corpus, makes no measurement or support decision and is not an
authorization authority. Nothing is installed or deployed: this ADR and the code
define the service and the contracts a deployment must meet, and claim no
permission, installation or running service.

## Decisions

### D1. A new crate, `pii-eval-app`, with a one-way dependency

The App needs a delivery handler, a bounded queue, workers and Check
publication, none of which belongs in the contracts, kernel or adapters (their
guard forbids network and server crates) or in the CLI (which must stay fully
usable with no App). A new crate `pii-eval-app` is justified by that
separation. It depends on `pii-eval-contracts` (digest type), `pii-eval-cli`
(the library entry point `execute`, and the summary schema constant), `serde`,
`serde_json`, `sha2` and, on Unix, `rustix` (group kill; already in the lockfile). **No other workspace crate depends on it**, by any edge
kind. `nothing_in_the_workspace_depends_on_the_app` in
`crates/pii-eval-cli/tests/dependency_policy.rs` runs `cargo tree` for every other
crate with normal, build and dev edges, so the CLI builds and passes its tests
with the app crate absent from its closure. Deleting the app crate means removing
its directory, one workspace member line, the guard's app entries and the CI step.

### D2. A GitHub-independent service boundary

`App::handle_delivery(&RawDelivery) -> Decision` is the whole inbound interface:
three header values and the exact raw body in, an outcome with a stable reason
code, an HTTP status suggestion and bounded safe metadata out. Everything the
service needs from the outside is a trait in `ports.rs`: `HeadResolver`
(current head of a pull request or branch), `ChecksApi` (find, create, update a
check run), `JobRunner`, `CustodianRouter` and `Clock`. The core never imports
an HTTP client, a GitHub type or a credential type, and no credential type
appears in any trait signature, so a runner or worker cannot receive one. Fakes
for all of them live in `testing.rs`.

### D3. The transport adapter is a deployment follow-up, not implemented here

Not implemented: an HTTP server, the GitHub REST client, App JWT signing (RS256)
and installation-token exchange. Each needs a third-party crate class that the
guard forbids (`hyper`/`reqwest`/`ureq`/`rustls`/`openssl`/`tokio` fragments) or
RSA code that must not be hand-written. Considered: `ureq` + `rsa`/`ring` +
`tiny_http`: roughly two dozen crates with TLS, bignum and ASN.1 code, each with
its own MSRV, in a repository whose pure crates keep a minimal closure. The
decision is to keep the core and the traits, which carry all of the risk-bearing
logic (authentication, authorization, replay, staleness, bounds, sanitization),
and to add the transport as a separate follow-up crate or a deployment-owned
binary, reviewed on its own (its dependencies justified in
docs/dependency-policy.md, added to the guard, MSRV re-verified). Until then
the traits are exercised only by fakes: that is a real limit on what is proven.
A transport crate added to `pii-eval-app` fails
`the_app_adds_no_third_party_crate` until the guard is changed on purpose.

### D4. HMAC-SHA256 is hand-written over the reviewed `sha2`

Webhook verification needs HMAC-SHA256 and a constant-time comparison. The
`hmac` crate (RustCrypto) would add a dependency edge and a version pin for
fifteen lines of RFC 2104. `hmac.rs` implements it over the already reviewed
`sha2`, and is pinned by the RFC 4231 test vectors (cases 1, 2 and 6, including a
key longer than the block) and GitHub's documented webhook example. The
comparison folds XOR over all bytes (the length is public). `sha2` itself stays
the primitive: no hash is hand-written. Secrets cannot be cloned, printed,
serialized or compared; `Debug` is fixed text; the bytes are overwritten on
drop (best effort, not a guarantee against copies).

### D5. Order of checks and what is trusted when

1. Body length against the configured cap (413), **before** any hashing or
   parsing.
2. `X-Hub-Signature-256`: present, `sha256=` plus 64 lowercase hex characters,
   HMAC over the exact raw bytes, constant-time compare (401). No metadata is
   produced before this passes.
3. Delivery id syntax and event name syntax (400). Only now is anything
   attributed to the delivery.
4. Replay, part one: a delivery id is looked up in a bounded TTL store and
   recorded only once a request was *admitted*; a repeat within the TTL is
   `duplicate-delivery` (409). The store is only consulted after authenticity.
   **This is best effort**: `X-GitHub-Delivery` is not covered by the HMAC, so a
   replayer sends a captured body under a fresh id, and a store that records every
   id could be flushed by distinct ids. Ids are therefore recorded only for
   admitted requests, and the real defences are the next rules (D5a).
5. Event class: only `issue_comment`, `check_suite` and `check_run` are
   approved; every other well-formed event (a label on a pull request, `push`,
   `ping`, `workflow_dispatch`) is `ignored/event-not-approved`.
6. Strict parsing: the body is validated as JSON in full (skipping an unknown
   field in a derived struct does not validate its string escapes; a fuzz test
   found a lone surrogate passing), then parsed into typed structures naming
   only the fields used, which reject duplicate keys, wrong types and
   out-of-range numbers. Only `action = created` comments that begin with the
   command, and `rerequested` Check events, are requests.
7. Authorization against the policy by numeric id: installation allowlisted,
   repository id belongs to **that** installation (a repository of another
   installation is `installation-repository-mismatch`), repository name equals
   the allowlisted one (stale allowlist detection, case-insensitive), actor id
   on the repository's actor list. A comment's `author_association`, a label, a
   role claim in the payload are never read.
8. Profile selection, current head resolution, stale and fork checks, admission.

Rejected requests record nothing, so GitHub's redelivery of a transiently
failed request (head lookup failed, queue full, store full, shutdown) is simply
processed again.

### D5a. Replay defences that do not depend on the delivery id

- A comment is one request: its `created_at` (strict UTC form) must be within
  `commentMaxAgeSecs` (default 600 s) and at most `clockSkewSecs` (60 s) in the
  future, and its repository-qualified id is spent for the window plus the skew
  (`comment-too-old`, `duplicate-comment`). Without this, a replayed comment
  resolves to the *current* head and would start a job per new commit.
- Check events name their commit and are `stale-head` once it moved. They carry no
  trustworthy timestamp, so they rely on the next rule.
- Per job identity: `retryCooldownSecs` (30 s) after a failed or stale job ends
  and `maxAttempts` runs in total (`retry-cooldown`, `retry-limit`). Evicting a
  job keeps its attempts and end time in a bounded tombstone map (four times the
  job capacity, oldest dropped first), so eviction by a flood of other identities
  does not reset the cap. The cap is exact for the most recent `4 * jobCapacity`
  failed or stale identities and approximate beyond that.
- There are no per-source quotas: the core never sees a source address. Rate
  limiting belongs to the transport (docs/github-app.md).

### D6. Job identity is the SHA-256 of length-prefixed immutable fields

`JobId = sha256(len||domain "pii-eval-app-job/1", repository id, commit, profile
id, engine version, protocol revision, run-config digest, population digest,
population class)`, with 4-byte big-endian length prefixes (so field boundaries
cannot be shifted). The requester and the delivery are not part of it: who asked
does not change what is measured. The same identity requested again is the same
job, which is what makes deduplication and retry reconciliation exact. An
independent Python vector pins the encoding. A profile (policy) carries the
engine version, protocol revision, run-configuration digest and population
digest; the commit is the head at admission.

### D7. What a job measures: pinned profiles, never the commit's contents

The App evaluates pinned engine builds against allowlisted synthetic
populations selected by a **profile**, and attaches the sanitized result to the
commit as a Check. The commit contributes only its id. Nothing in it (pull
request code, fork code, comment text) is fetched, built or executed, and the
default policy refuses pull requests whose head lives in another repository
(`fork-head-not-allowed`). Evaluating a candidate scanner supplied by a pull
request is not supported by this App; it needs a sandboxed execution design that
does not exist here. The CLI runner maps a profile id to a run-configuration
file chosen by the deployment, checks that the file's SHA-256 equals the profile's
`configDigest` (so a changed configuration is `profile-changed`, not a silent
different measurement), and the CLI then verifies the snapshot, manifest and
scanner package digests the configuration pins before launching anything
(ADR 0010, C5). After the run, the reported engine version, protocol revision
and population digest must equal the profile's; otherwise the Check says
`identity-mismatch` and shows none of the run's values.

### D8. Protected jobs are routed, never authorized here

A profile of class `protected` is never given to the runner. A worker hands
the job's identities (never inputs, never results) to a `CustodianRouter`,
records `routed-to-custodian` and publishes nothing. The default router,
`NoCustodian`, always fails, so a protected profile with no custodian ends in
`failed(custodian-unavailable)` and never falls back to a local run. Being on the
allowlist lets an actor *ask*; the custodian decides. A comment or a label alone
grants nothing: both are only inputs to an allowlist the deployment owns, a label
event is not even subscribed to, and the policy decides which profiles a
repository may request.

### D9. Bounded execution, deterministic ids, serialized side effects

The handler never runs a job: it admits and enqueues. A bounded FIFO
(`queue_capacity`, a hard ceiling in the policy) answers `queue-full` (503) when
full, and rolls the admission back. `workers` threads (1 to 8) each run one job
at a time, so at most that many jobs run at once; the in-process runner adds its own
watchdog (job timeout, cooperative cancel that makes the executor kill the
scanner tree) and removes the per-job output directory. The job store, the
delivery store and every limit are bounded; evicting the oldest terminal job or
delivery id weakens deduplication but never grows memory. State is in memory: a
restart forgets it, and GitHub's redelivery or a new request re-admits the work.
Scheduling order never affects a job id or a Check's text.

### D10. State machine, retries and staleness

`Queued -> Running -> Completed | Failed(reason) | Stale | RoutedToCustodian`;
`Failed | Stale -> Queued` (retry, at most `max_attempts` runs). Illegal
transitions are rejected by `Job::transition` (tested exhaustively). A published
result is not rerun. A result computed but not published (`publish-failed`) is
kept, sanitized, and a retry only republishes it. A `create` whose response was
lost is reconciled by `external_id` (the job id) through `ChecksApi::find`.
Staleness: the head is resolved at admission (a Check event naming another
commit is `stale-head`), again before the run (a job whose head moved while
queued never runs and publishes nothing), and again after it (the result is
dropped, and an existing Check is concluded `neutral`/superseded with identities
only). A head that cannot be resolved fails closed
(`failed(head-unverifiable)`). **Residual window**: the head can still move
between the final head check and the Check update (and between any lookup and the
upstream state), which no client-side check can close. The consequence is
limited: a Check is created on, and updated for, its own commit SHA, so a result
that arrives after the head moved is attached to the commit it was measured on
and is never attributed to the newer one. Writes that fail (the stale or
internal-error conclusion, or a publish) are kept on the job and retried by
`App::reconcile` (called by workers before each job and, in a deployment, on a
timer), so a Check is not left "running" forever; at most 16 are retried per
call.

### D11. Check summaries are fixed templates over validated fields

`pii-eval-check-summary/1` is plain ASCII built from a fixed template. The only
variable fields are: job id and commit id (hex), profile id, engine and protocol
identity, the pinned digests, the CLI's manifest, run-artifact and
public-artifact digests, a closed `state`, the outcome-matrix `completeness`
token, public-synthetic population counts (a bounded map of integers),
scanner ids and statuses and failure codes from the manifest (tokens). The CLI's
summary line is parsed into a typed outcome; every field is checked against a
strict charset and bound, unknown fields are ignored and never copied, and any
field that fails makes the whole projection fail (`summary-rejected`) rather
than being repaired. A final guard rejects any byte outside printable ASCII and
newline and any text over 8 KiB. The summary is a measurement, never a verdict:
a complete run is `success` ("the measurement completed", footer says so), an
incomplete one is `failure`, never `success`. Raw scanner output, matched
values, input text, case ids and protected details have no path into it:
runners return typed identities and statuses, and the CLI already withholds them
from its summary. A run whose reported class is not `public-synthetic` is
rejected by the projection.

### D11a. Two runners; only one is for production

`InProcessCliRunner` runs `pii_eval_cli::execute` inside the App process. The
scanner is then a child of the process that holds the webhook secret (and, in a
deployment, the private key and tokens) under the same OS user, which this crate
cannot separate, so it is labeled test and development only.
`ExternalProcessRunner` starts a configured worker command as a separate process
(the `pii-eval` binary, or a wrapper that changes user, enters a container or
sandboxes): fixed absolute program, structured arguments with `{config}`, `{out}`,
`{job_id}`, `{attempt}` placeholders, **cleared environment plus only the
variables the profile names** (names that look like credentials are refused),
stdin and stderr `/dev/null`, stdout read to a fixed bound, a private per-job
directory, its own process group sent `SIGKILL` on timeout, cancel and exit.
The standard library opens every descriptor it creates close-on-exec, so none of
this crate's (the secret file among them) is inherited; a descriptor created
without close-on-exec by other code in the host process cannot be closed from
safe Rust, so the host must not create any (a test compares the worker's
descriptors with those of a plain child). This crate guarantees those properties;
**separating the worker's OS user or container is the deployment's
responsibility** and nothing here verifies it. `rustix` (already in the lockfile
through the adapters, same pin and feature) is added as a direct Unix-only
dependency of the app for the group kill; no new crate enters the lockfile.
Both runners verify the run configuration's digest on the bytes they stage and
hand the worker a private `0600` copy in a `0700` directory (so a swap of the
original after the check changes nothing); the copy requires every `path` and
`dir` in the document to be absolute.

### D12. Credentials and custody (specified, not implemented)

The App needs three secrets: the webhook secret (this crate loads it from a file
with owner-only permissions or from the environment into a `Secret`), the App
private key and the short-lived installation tokens (both owned by the transport
follow-up). None is in the repository, CI, a log line or a job specification; the
runner receives identities only. The webhook secret is loaded only from an owner-only
file (`Secret::from_file`); an environment-variable loader was removed because an
environment is inherited by every child process and visible to same-user tools.
The scanner is process-hygiene-controlled (ADR 0009), not isolated: the
deployment must run the worker command (D11a) as another user or in a container,
which docs/github-app.md lists as a requirement and this crate cannot check.

## Alternatives considered

- A binary in `pii-eval-cli` (`pii-eval app serve`): rejected; it would put the
  server and its dependencies into the crate that must stay usable, small and
  App-free.
- Evaluating the pull request's own scanner build: rejected for this App (D7).
- Trusting `author_association` or a team lookup instead of an actor-id
  allowlist: rejected; an allowlist the deployment owns cannot be widened by a
  payload field, a rename or a role change on GitHub.
- A `workflow_dispatch` trigger: not approved in this revision. It needs an
  extra permission (Actions: read) to receive and adds nothing a comment or a
  rerun does not; it can be added by a reviewed policy change.
- `hmac`/`subtle` crates: see D4. `proptest`: fixed-seed generators, as elsewhere.

## Consequences

- New crate `pii-eval-app` (library, no binary), no new third-party crate, no
  lockfile entry besides the workspace member. MSRV 1.85 re-verified.
- The guard gains `the_app_adds_no_third_party_crate` and
  `nothing_in_the_workspace_depends_on_the_app`; the pure crates, adapters and CLI
  rules are unchanged.
- Tests (no network): forged, missing, malformed and mismatched signatures;
  oversized, malformed, truncated, mutated and random bodies; replay and
  redelivery; unauthorized actor, unknown installation, unknown repository,
  renamed repository, cross-repository confusion in both directions for three
  events; stale head at admission, before and during a run; fork head; profile
  allowlist; queue and store bounds; worker concurrency limit; deduplication;
  deterministic ids; publish retry, lost create response, retry limit; panics;
  protected routing without fallback; sentinel non-leakage in Debug, errors and
  Checks; a real end-to-end run through the CLI library on the quickstart example.

## Gaps and deferrals

- No HTTP server, GitHub REST client, JWT signing or token exchange (D3). The
  `ChecksApi`/`HeadResolver` contracts are specified against GitHub's documented
  behavior but never exercised against GitHub.
- No durable state: a restart loses queued jobs, dedupe memory and Check ids
  (reconciliation by `external_id` recovers Checks).
- No signed-timestamp replay window: GitHub does not sign one; protection is the
  delivery-id store plus idempotent job ids (D5, D6).
- Process hygiene, not isolation, for the scanner; separating its OS user or
  container is the deployment's (D11a, D12).
- Port calls are not interruptible: a hung transport call occupies its thread.
  The timeout contract (`ports::MAX_PORT_CALL_SECS`) and a conformance helper are
  the control; a transport must pass them.
- The transport must reject repeated or non-ASCII signature, delivery and event
  headers (`webhook::select_single_header`); the core accepts `Option<&str>` and
  cannot see duplicates.
- Per-source rate limiting is not available in the core.
- No metrics or log sink: the crate emits nothing; a deployment logs `Decision`
  codes and metadata, which are safe by construction.
- Evaluation of a candidate scanner supplied by a pull request (D7).
