# Internal GitHub App

Status: **the service core is implemented; no App is registered, installed or
deployed, and no permission, secret or endpoint exists.** This document states
what the code does, what a deployment must provide, and which GitHub-side steps
a person must do by hand. Nothing here claims that any of it has been done. The
decisions are [ADR 0011](adr/0011-internal-github-app.md); the code is
`crates/pii-eval-app/`.

The App is a thin adapter. It accepts an evaluation request, runs a pinned
public synthetic profile through the CLI library and posts a sanitized Check. It
holds no corpus, makes no measurement or support decision, never authorizes a
protected run and is not an authorization authority. The CLI works without it
([docs/cli.md](cli.md)); no other crate depends on it.

## What is implemented and what is not

| Part | State |
| --- | --- |
| Signature verification, size cap, strict parsing | Implemented, tested |
| Replay defences: comment age window, single use of a comment id, retry cooldown and cap, best-effort delivery-id store | Implemented, tested (see "Replay" below for what each does and does not give) |
| Allowlist authorization (installation, repository id, actor id, profile) | Implemented, tested |
| Deterministic job ids, job state machine, bounded store and queue, limited workers | Implemented, tested |
| Stale-head handling, retry and publish reconciliation, a tick that finishes Checks whose last update failed (`App::reconcile`) | Implemented, tested against fakes |
| Sanitized Check summaries (`pii-eval-check-summary/1`) | Implemented, tested |
| Runner for production: `ExternalProcessRunner` starts a configured worker command as a separate process (scrubbed environment, no inherited secrets, bounded output, time limit, process-group kill) | Implemented, tested with shell-script workers; separating the OS user or container is the deployment's |
| Runner for tests and development only: `InProcessCliRunner` (`pii_eval_cli::execute` inside the App process) | Implemented, tested end to end on the quickstart example; **never for production**: the scanner would run in the process that holds the secrets |
| Protected routing to private-custodian | Interface only (`CustodianRouter`); no custodian client |
| HTTP server, GitHub REST client (`ChecksApi`, `HeadResolver`), App JWT and installation tokens | **Not implemented** (deployment follow-up, ADR 0011 D3) |
| Durable state, metrics, log sink | Not implemented |

## Request flow

`App::handle_delivery` takes the `X-GitHub-Event`, `X-GitHub-Delivery` and
`X-Hub-Signature-256` values and the exact raw body, and returns a decision:
`accepted`, `ignored` or `rejected`, a stable reason code, an HTTP status to
answer with, and metadata that is only validated text and numbers. Order (each
step before the next):

1. Body size cap (413).
2. HMAC-SHA256 over the raw bytes, constant-time comparison (401).
3. Delivery id and event name syntax (400).
4. Replay, part one: a delivery id seen on an *admitted* request within the TTL is
   `duplicate-delivery` (409). Best effort only, see "Replay" below.
5. Event class: `issue_comment`, `check_suite`, `check_run`; anything else
   authentic is ignored (`event-not-approved`, 200). A label on a pull request, a
   push, a ping and `workflow_dispatch` are all in that group.
6. Strict parsing of only the fields used (400 `payload-malformed`).
7. Authorization against the policy (403).
8. For a comment: its `created_at` must be within `commentMaxAgeSecs` (and not
   more than `clockSkewSecs` in the future) and its id must not have been used
   (`comment-too-old`, `duplicate-comment`, 409).
9. Profile, current head, fork and stale checks, admission (a failed or stale job
   is retried only after `retryCooldownSecs` and at most `maxAttempts` times:
   `retry-cooldown`, `retry-limit`, 429), enqueue (202).

### Replay

`X-GitHub-Delivery` is not covered by the HMAC. Anyone who captured one valid
delivery can resend the body under a fresh delivery id, so the id store is a
convenience (it makes GitHub's own redelivery of an admitted request a clean
409), **not** a replay defence. What actually bounds a replayer:

| Replay | Outcome |
| --- | --- |
| A captured comment, any delivery id, inside the age window | `duplicate-comment`: a comment id starts at most one request (kept for the window plus the skew; keys are repository and comment id) |
| A captured comment after the window | `comment-too-old`; so a replay can never start a job against a newer head than the comment's own time allows |
| A captured `check_suite` / `check_run` rerequest | They name their commit: `stale-head` once the head moved; otherwise the deterministic job id coalesces them or, for a failed or stale job, `retry-cooldown` and `retry-limit` apply |
| Many fresh delivery ids to evict the store | Ids are recorded only for admitted requests, which are bounded by the queue, the job store and the identities above; rejected traffic records nothing |

Limits stated plainly: there are no per-source quotas (the service sees no
source address; a transport or reverse proxy should rate-limit). The retry cap
and cooldown are kept per job identity and survive eviction of the job through a
bounded tombstone map (four times the job capacity, oldest dropped first), so the
cap is exact for the most recent `4 * jobCapacity` failed identities and
approximate beyond that. A redelivery by GitHub of a request older than the
comment window is refused; ask for the run again with a new comment.

Approved requests:

| Event | Request | Notes |
| --- | --- | --- |
| `issue_comment` `created` on a pull request | The first line is exactly `/pii-eval run` or `/pii-eval run <profile>` starting at byte 0 | Edited comments, comments on issues and quoted text are not requests. The rest of the comment is never read or stored. |
| `check_suite` `rerequested` | Default profile of the repository | The named commit must still be the head, else `stale-head`. |
| `check_run` `rerequested` | The profile of the job named by our own `external_id`, else the default | Same head rule. |

Reason codes (stable, never carry text): `payload-too-large`,
`signature-missing`, `signature-malformed`, `signature-mismatch`,
`delivery-id-invalid`, `event-invalid`, `duplicate-delivery`,
`payload-malformed`, `command-malformed`, `event-not-approved`,
`action-not-approved`, `not-a-command`, `not-a-pull-request`,
`installation-not-allowlisted`, `installation-repository-mismatch`,
`repository-not-allowlisted`, `repository-name-mismatch`,
`actor-not-authorized`, `profile-not-allowed`, `fork-head-not-allowed`,
`comment-too-old`, `duplicate-comment`, `retry-cooldown`, `stale-head`,
`head-unresolvable`, `queue-full`, `job-store-full`, `retry-limit`,
`shutting-down`. Transient ones (`head-unresolvable`,
`queue-full`, `job-store-full`, `shutting-down`) do not consume the delivery id,
so GitHub's redelivery is processed.

## Policy file (`pii-eval-app-policy/1`)

Strict JSON (unknown fields, duplicate keys and bad values are errors, size
capped at 256 KiB), owned by the deployment and containing no secret:

```json
{
  "schema": "pii-eval-app-policy/1",
  "profiles": [{"id": "public-default", "class": "public-synthetic",
    "engineVersion": "0.0.0", "protocolRevision": 2,
    "configDigest": "<sha256 of the run configuration document>",
    "populationDigest": "<semantic digest of the population>"}],
  "installations": [{"id": 7, "repositories": [{"id": 42, "fullName": "owner/repo",
    "actors": [1001], "profiles": ["public-default"], "allowForkHeads": false}]}],
  "limits": {"workers": 2},
  "detailsBaseUrl": "https://example.invalid/pii-eval/jobs"
}
```

Repositories and actors are bound by numeric id; a repository belongs to exactly
one installation. The first profile of a repository is its default. `class` is
`public-synthetic` (executed here) or `protected` (only routed). Limits and their
ceilings: `maxBodyBytes` (default 1 MiB, at most 4 MiB), `queueCapacity` (16,
1024), `workers` (2, 8), `jobTimeoutSecs` (900, 3600), `deliveryCapacity` (4096,
1,000,000), `deliveryTtlSecs` (3 days, 14 days), `jobCapacity` (1024, 100,000),
`maxAttempts` (3, 10), `commentMaxAgeSecs` (600, 86,400), `clockSkewSecs` (60, 600),
`retryCooldownSecs` (30, 3,600).

## Check summary (`pii-eval-check-summary/1`)

Plain ASCII, fixed template, title one of: `PII evaluation: running`,
`measurement complete`, `measurement incomplete`, `no measurement`,
`superseded by a newer commit`. The summary lists `schema`, `job`, `commit`,
`profile`, `run-class`, `engine`, `protocol`, `config-digest`,
`population-digest`, `state` (`running`, `complete`, `incomplete`, `failed`,
`superseded`) and, for a measurement, `completeness`, `manifest-digest`,
`run-artifact-digest`, `public-artifact-digest`, `count <name>: <n>` lines for the
public synthetic population, `scanner <id>: <status>` and `failure-codes`. A
failure shows a closed `reason` (`runner-refused`, `identity-mismatch`,
`timeout`, `cancelled`, `summary-rejected`, `run-failed`, `internal-error`,
`stale-head`) and nothing else. The footer states that the Check is a
measurement of public synthetic data and not a support, release or authorization
decision. Conclusions: complete is `success`; incomplete, failed, identity
mismatch are `failure`; time limit `timed_out`; shutdown `cancelled`;
superseded `neutral`. The details link is the deployment's `detailsBaseUrl` plus
the job id.

Never present: raw scanner logs or output, matched values, input text, seeds,
case ids, paths, comment text, error text of any upstream, tokens, anything from
a protected population (such a run is never executed here and a result that
reports another class is rejected).

## Credentials and least privilege

The App needs three secrets. All are held by the deployment, never by the
repository, CI, logs, issues, a job specification or a worker:

| Secret | Use | Custody |
| --- | --- | --- |
| Webhook secret | HMAC of deliveries | Loaded by `Secret::from_file` only (regular file, mode `0600` or stricter); at least 32 bytes; random, unique to this App. There is no environment loader: an environment is inherited by every child and visible to same-user tools, a file with owner-only permissions is not |
| App private key | RS256 JWT (at most ten minutes) to obtain an installation token | Transport follow-up; a secret manager or a root-owned `0600` file; never in a worker's environment |
| Installation token | Checks and head lookups, one hour | Transport follow-up; request it narrowed to one repository and the permissions below; never persisted |

`Secret` has no `Clone`, `Display`, `Serialize` or equality; `Debug` prints
`Secret(<redacted>)`; the bytes are overwritten on drop (best effort).

Repository permissions to request (to be re-checked against GitHub's current
permission and webhook-event tables when the App is registered; this is the
intended minimum, not a verified GitHub fact):

| Permission | Level | Why |
| --- | --- | --- |
| Checks | Read and write | Create and update check runs; receive `check_suite` and `check_run` |
| Pull requests | Read | Resolve a pull request's head and its source repository; receive `issue_comment` on pull requests |
| Contents | Read | Resolve a branch's head commit |
| Metadata | Read | Mandatory |

No other permission: no write access to contents, pull requests, issues, actions,
workflows, administration, secrets or members; no organization or account
permission; no user authorization (OAuth). Subscribed events: **Issue comment,
Check suite, Check run**. Not subscribed: Pull request (labels), Push, Workflow
dispatch, and everything else. Install on selected repositories only, never on
all repositories.

## Manual provisioning prerequisites (none has been done)

1. Decide the owning account and the repositories; record them as the policy.
2. Register a GitHub App on that account with the permissions and events above,
   an active webhook URL (HTTPS, TLS verification on) and a freshly generated
   random webhook secret, and no user authorization or callback.
3. Generate the private key and place it in the deployment's secret store.
4. Install the App on the selected repositories only; record installation and
   repository ids in the policy (numeric ids, not names).
5. Collect the numeric user ids of the people who may request evaluations.
6. Prepare the profiles: pin the run configuration, snapshot, manifest and
   scanner package, compute the configuration digest and the population digest,
   and put both in the profile (`docs/cli.md`).
7. Build the transport follow-up (HTTP listener, `ChecksApi`, `HeadResolver`,
   token exchange), review its dependencies under docs/dependency-policy.md and
   add it to the guard. Transport requirements (checklist, each testable):
   - pass the exact, unmodified raw body to `handle_delivery`;
   - take `X-Hub-Signature-256`, `X-GitHub-Delivery` and `X-GitHub-Event`
     through `webhook::select_single_header`: a header that is repeated, empty
     of a value or not printable ASCII is passed as absent (the first and last
     occurrence of a duplicated header may otherwise disagree);
   - reject a body over the cap while reading it, before buffering it all;
   - answer with `Decision::outcome.http_status()` and nothing from the body;
   - keep every port call within `ports::MAX_PORT_CALL_SECS` (connect, read and
     total timeouts; a stalled upstream is `Err(PortError::Unavailable)`) and
     check it with `testing::assert_port_call_bounded` against a server that
     stalls; the core cannot interrupt a call, a hung one occupies its thread;
   - call `App::reconcile` periodically;
   - rate-limit by source (the core has no per-source quotas).
8. Run jobs with `ExternalProcessRunner`, never `InProcessCliRunner`. What the
   crate guarantees for the worker it starts: a fixed absolute program and
   structured arguments, a cleared environment holding only the variables the
   profile names (credential-looking names are refused), stdin and stderr
   `/dev/null`, a bounded stdout pipe, no descriptor opened by this crate
   inherited, a private `0700` per-job directory holding a verified `0600` copy of
   the run configuration, its own process group killed on timeout, cancel and
   exit. What the deployment must provide, because the crate cannot: run that
   command as an operating-system user (or in a container or sandbox) that cannot
   read the webhook secret file, the private key, the installation tokens or the
   App process's memory; make `{config}` and `{out}` usable by that user; keep
   the host binary free of descriptors opened without close-on-exec; give the
   worker only the network and file access it needs; keep Node and `ps` available
   as the CLI requires. A wrapper that changes user must stay in its process group
   (or the cleanup cannot reach it) and print exactly the CLI's one summary line
   on stdout.
9. Protected profiles additionally need private-custodian's intake
   ([private-custodian#4](https://github.com/redact-secret/private-custodian/issues/4))
   and a `CustodianRouter`; until then they fail closed.
10. Verify with a synthetic repository before trusting the allowlist: a forged,
    replayed and cross-repository delivery must be rejected.

## Threat model

| Actor | Can | Cannot |
| --- | --- | --- |
| Malicious webhook sender (no secret) | Send bytes; cost one size check and one HMAC per request | Be parsed, attributed or counted (nothing before the signature), consume a delivery id, queue a job |
| Replayer holding a captured valid delivery | Resend it, under any delivery id | Start a second job from a comment (single-use comment id, age window), re-run a failed job faster than the cooldown or beyond the cap, or evict recent delivery ids (only admitted requests are recorded). It can cost one HMAC and one parse per request: rate-limiting is the transport's |
| Allowlisted but wrong-scope sender (another repository's actor or installation) | Be rejected with a stable code | Use installation A for repository B: the repository must belong to the delivering installation, by id |
| Malicious pull request author | Choose a branch, commit, comment text, labels, a fork | Select code to run (jobs run pinned profiles only), choose a profile outside the repository's list, request anything without being on the actor list, grant protected access with a comment or a label, get fork heads evaluated by default, inject text into a Check (fixed template) |
| Allowlisted actor | Request public synthetic profiles of their repositories, within queue and retry limits | Request a protected run (it can only be routed, and the custodian decides), see anything from a protected population |
| Malicious scanner (a pinned build gone bad) | What the CLI threat model allows (SECURITY.md): resources within limits, children in its process group, network and files readable by the worker's OS user | Change what a Check says beyond the validated fields (its output is projected, not copied). Whether it can read App secrets depends on the deployment: this crate passes none (scrubbed environment, no inherited descriptors, no secret in arguments), but only running the worker as another user or in a container (step 8) stops it reading secret files or memory of the same user |
| Misconfigured deployment | Widen the allowlist, run workers with secrets, skip TLS | Be detected by this crate; the policy and this document are the controls |

Limits stated plainly: the scanner is not sandboxed by this crate and shares
the worker's OS user unless the deployment separates it; the delivery id and
GitHub deliveries carry no signed timestamp (see "Replay"); state is in memory;
a window remains between the final head check and the Check update (the Check is
attached to its own commit, so a late result is correctly labeled, not
misattributed); the transport against GitHub is unbuilt and untested.
