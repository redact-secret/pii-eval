# Internal engine artifacts and dispatchable workflows

Status: **implemented in CI; internal only.** pii-eval publishes its engine the
way credential-eval shares its own: as a GitHub Actions *workflow artifact*, built
once and reused by other workflows instead of rebuilt. It is **not a release**:
no tag, no GitHub Release, no public download, no package registry. Anyone with
read access to this (private) repository can download an artifact while it is
retained; nobody else can.

## What exists

| File | Role |
| --- | --- |
| `.github/workflows/build-engine.yml` | Builds the engine once with the documented command (`cargo build --release --locked`), writes `build-info.json` and `SHA256SUMS`, verifies them, uploads the artifact. Triggers: `workflow_call` (any workflow can reuse it) and `workflow_dispatch` (by hand). |
| `.github/workflows/ci.yml` | The `engine` job calls `build-engine.yml` on every push to `main` and every pull request, so the documented release build is exercised and an artifact exists for every CI run. The `evaluate` job then calls `evaluate.yml` with the run id of the same run, so every CI run proves that the artifact can be chosen, downloaded, verified and used (no second build). The `check` and `msrv` jobs use `Swatinem/rust-cache` (the cache action credential-eval pins), so repeated builds are incremental. |
| `.github/workflows/evaluate.yml` | A dispatchable workflow that runs a **public, synthetic** evaluation with a **prebuilt** engine artifact. Triggers: `workflow_dispatch` and `workflow_call`. |
| `.github/workflows/isolation.yml`, `tools/isolation/` | The `isolation` job of `ci.yml`: Node and the engine under the custodian's sandbox limits on a hosted Linux runner (`docs/custodian-isolation-node.md`). It uses the verified engine artifact of the same run, never loosens a limit, and fails if its sandbox controls fail. It is a measurement of limits, not a protected evaluation and not a deployment path. |
| `tools/ci/` | Standard library only, unit-tested in `tools/ci/test/`: `build-info.mjs`, `verify-engine.mjs`, `resolve-engine.mjs` (which run's artifact may be used), `summary-line.mjs` (safe output of an untrusted program), `workflow-policy.mjs`, `main-guard.mjs`. |

## The artifact

Name: `pii-eval-engine-<commit sha>-linux-x86_64`, where the commit is
`GITHUB_SHA`. Retention: 30 days for `main`, 3 days for any other ref. Re-running all
jobs of a run replaces the artifact (`overwrite`). Contents, exactly these three
files:

| File | Content |
| --- | --- |
| `pii-eval` | The release binary. Upload and download drop the executable bit; the verifier restores it. |
| `build-info.json` | `pii-eval-build-info/1`: repository, commit (`GITHUB_SHA`: the merge commit for a pull request), `headSha` (the commit the event is about), event name, ref, run id and attempt, target, toolchain (`rustc --version`, SHA-256 of `Cargo.lock` and `rust-toolchain.toml`), binary name, SHA-256, size and `--version` text. Sorted keys, no timestamps. |
| `SHA256SUMS` | Two lines in `sha256sum` format, sorted: `build-info.json` and `pii-eval`. |

The published binary is compiled from a clean `target` directory: the build job's
cache holds registry and git dependencies only (`cache-targets: false`), never
cached build output.

Evaluation output (from `evaluate.yml`) is a second, separate artifact,
`pii-eval-run-<run id>-<attempt>`, retained 14 days. It holds the files the CLI
wrote for a public/synthetic run.

## What the checks prove, and what they do not

Two independent things guard a use of the artifact. Do not confuse them.

1. **Choosing the run** (`tools/ci/resolve-engine.mjs`, from GitHub's own record
   of the run). `build-info.json` and `SHA256SUMS` travel in the same artifact, so
   whoever can write the artifact can rewrite both; **the sums are an integrity
   check against corruption and mistakes, not evidence against a malicious
   writer.** The decision that an engine may be used therefore comes from the run
   record, not from the artifact:
   - the run of the workflow run being executed (the engine was built a moment ago):
     accepted;
   - any other run: completed and successful, event `push` or `workflow_dispatch`, on
     `main`, of this repository (not a fork), from `ci.yml`, `build-engine.yml` or
     `evaluate.yml` on `refs/heads/main`, and exactly one unexpired artifact named
     `pii-eval-engine-<40 hex>-linux-x86_64` whose commit equals the run's head
     commit;
   - anything else (a pull request's run, another branch) is refused unless the
     `allow-unverified-ref` input is `true`. That input means "an unreviewed binary
     runs in this workflow"; it exists for deliberate tests. The artifact name is
     still checked.

   Refusal reason codes: `run-id-invalid`, `run-not-completed`, `run-not-successful`,
   `run-event-not-allowed`, `run-not-on-main`, `run-from-another-repository`,
   `run-from-another-workflow`, `no-engine-artifact`, `several-engine-artifacts`,
   `artifact-commit-differs-from-run`, `usage`, `internal`.
2. **Verifying the files** (`tools/ci/verify-engine.mjs`):

   ```sh
   gh run download <run-id> -n pii-eval-engine-<commit>-linux-x86_64 -D engine
   node tools/ci/verify-engine.mjs --dir engine --repository redact-secret/pii-eval \
     --target linux-x86_64 --make-executable
   ```

   It prints one JSON line (`pii-eval-engine-verify/1`) and exits 0 only if every
   check passes; otherwise it prints a reason code and exits 1 (2 on misuse). Reason
   codes: `dir-unreadable`, `unexpected-file`, `missing-file`, `not-regular-file`,
   `sums-malformed`, `sums-mismatch`, `build-info-invalid`, `binary-mismatch`,
   `commit-mismatch`, `repository-mismatch`, `target-mismatch`, `exec-failed`,
   `version-mismatch`, `usage`. It proves: the directory holds exactly those files,
   the sums match the bytes, `build-info.json` has the closed schema and agrees with
   the binary, the given expectations hold (`evaluate.yml` passes the commit from
   the chosen artifact's name), and the executed `--version` equals what
   `build-info.json` says. The scripts fail closed from any path (a spaced or
   symlinked path once made a guard exit 0; a regression test covers it).

Neither proves the commit is trustworthy, who built it, or that the build is
reproducible: the artifact is neither signed nor attested. Compare semantic digests
of runs, not binaries (`docs/cli.md`). The engine is a program from an artifact: while
`evaluate.yml` runs it, workflow commands are switched off (`::stop-commands::`), the
runner's command files (`GITHUB_ENV`, `GITHUB_PATH`, `GITHUB_OUTPUT`, `GITHUB_STATE`,
`GITHUB_STEP_SUMMARY`) are unset for it, a single file may not exceed 512 MiB, it has
20 minutes, its output goes to files, and only a re-serialized JSON line
(`summary-line.mjs`: the first 64 KiB read, one object, backticks escaped, length
capped) and a stderr excerpt reduced to printable ASCII are printed. **This is not a
sandbox:** the engine runs as the runner user and can read what that user can read.
That is acceptable for an engine built from this repository on `main`, and is the
reason the default refuses anything else.

## Using the artifact from another workflow or action

`evaluate.yml` inputs: `engine-run-id` (a workflow run id; empty means "build one
in this run"), `config` (a relative path inside the checkout, default
`examples/quickstart/run-config.json`: a plain path, no `..`, a regular file that is
not a symlink and stays inside the checkout) and `allow-unverified-ref` (default
`false`). The inputs are single-line text that reaches a shell only through `env:`
after these checks.

1. **Find a run to reuse.** The last successful CI run on `main`:
   `gh run list --workflow ci.yml --branch main --event push --status success --limit 1 --json databaseId --jq '.[0].databaseId'`
2. **Dispatch it.**
   `gh workflow run evaluate.yml --ref main -f engine-run-id=<id> -f config=examples/quickstart/run-config.json`
   The same works from any workflow or tool through the workflow-dispatch API
   (`POST /repos/redact-secret/pii-eval/actions/workflows/evaluate.yml/dispatches`)
   with a token that has `actions: write` on this repository. The run executes
   here, with this repository's own token, and needs nothing else.
3. **Call it from a workflow in this repository.**

   ```yaml
   permissions:
     contents: read
     actions: read
   jobs:
     evaluate:
       uses: ./.github/workflows/evaluate.yml
       with:
         engine-run-id: ""   # empty: build once in this run; or a run id to reuse
   ```

What `evaluate.yml` does: checks the inputs, chooses the artifact (above), downloads
it by exact name, verifies it, runs `pii-eval run` on the configuration, validates
the produced artifact against the snapshot and manifest, writes the engine identity
and the CLI's summaries to the job summary and uploads the output. When
`engine-run-id` is empty it calls `build-engine.yml` first, so one run builds the
engine once. It never rebuilds an engine that exists.

The workflow checks out the dispatched ref for the configuration, snapshot, manifest
and shim; the engine comes from the chosen run, possibly another commit. That is the
point of a prebuilt engine, so the workflow does not refuse a difference: it prints a
notice when the two commits differ and records both in the job summary.

**Across repositories** (not done, and needing manual settings): another
repository can dispatch `evaluate.yml` as above. Reading this repository's
artifacts from another repository's workflow needs a token with `actions: read`
here (a fine-grained token or a GitHub App installation token; the other
repository's `GITHUB_TOKEN` cannot). Calling these workflows with
`uses: redact-secret/pii-eval/.github/workflows/<file>@<sha>` from another private
repository additionally needs this repository's Actions "Access" setting to allow
repositories of the organization. These are statements about GitHub behaviour that
were **not verified here**, and none of this is configured.

## What is not provided

- Only **linux-x86_64**. Development on macOS builds with `cargo build --release --locked`
  (`docs/cli.md`); a macOS or arm64 artifact would need another runner and is not built.
- No signature, no provenance attestation, no reproducible-build claim, no SBOM.
- No release, tag or public distribution. Retention is 30 days on `main` and 3
  elsewhere; a deployment that must keep a binary longer has to copy it out of
  Actions and record its digest.
- The engine alone is not a deployment: it also needs Node 22, `ps`, the shim and
  the pinned scanner package, installed by a person (`docs/cli.md`).
- No protected runs: the CLI refuses a protected run without a custodian job
  context and these workflows supply none. Do not put protected material into a
  configuration, an input or an artifact (SECURITY.md).
- No check that a downloaded zip stays inside its directory beyond what the
  download action does (the verifier sees only what is in the directory it is given).

## Security properties of the workflows

- Every action is pinned by full commit SHA; `permissions` are declared at the top
  of every workflow, are read-only (`contents: read`, plus `actions: read` for
  `evaluate.yml`, which reads the run record and artifacts of runs of this
  repository) and no job asks for more. No secrets.
- Workflow inputs are untrusted text. They reach a shell only through `env:` and are
  checked before use; no `${{ inputs.* }}`, event field, ref, actor, step or job
  output, matrix or secret is interpolated into a script.
- `tools/ci/workflow-policy.mjs` enforces these rules on every workflow in CI
  (pinned `uses:`, top-level `permissions` and no write permission anywhere, no
  `pull_request_target`, no `secrets: inherit`, no `github-script`, no untrusted
  expression inside `run:` however it is wrapped, no `GITHUB_ENV`/`GITHUB_PATH`
  writes); its tests include inputs that must fail.
- Artifacts are readable by everyone with read access to the repository for as long
  as they are retained. They contain the binary and its build information only.
- The run record decision is made by `resolve-engine.mjs` as it exists in the ref
  `evaluate.yml` was dispatched from. Dispatch from `main` (the examples do):
  a dispatch from a pull request branch uses that branch's copy of the guard, which
  is arbitrary code that already runs with this workflow's permissions. Whoever can
  dispatch has write access to the repository.
- A pull request can edit the workflows and `tools/ci` it runs with. What it cannot
  do, by default, is have its binary used by `evaluate.yml` on `main`: the run
  record decides (above). The override exists on purpose and says so.
