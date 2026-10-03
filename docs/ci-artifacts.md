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
| `.github/workflows/build-engine.yml` | Builds the engine once (`cargo build --release --locked -p pii-eval-cli`), writes `build-info.json` and `SHA256SUMS`, verifies them, uploads the artifact. Triggers: `workflow_call` (any workflow can reuse it) and `workflow_dispatch` (by hand). |
| `.github/workflows/ci.yml` | The `engine` job calls `build-engine.yml` on every push to `main` and every pull request, so the documented release build is exercised and an artifact exists for every CI run. The `evaluate` job then calls `evaluate.yml` with the run id of the same run, so every CI run proves that the artifact can be downloaded, verified and used (no second build). The `check` and `msrv` jobs use `Swatinem/rust-cache` (the cache action credential-eval pins) so repeated builds are incremental. |
| `.github/workflows/evaluate.yml` | A dispatchable workflow that runs a **public, synthetic** evaluation with a **prebuilt** engine artifact. Triggers: `workflow_dispatch` and `workflow_call`. |
| `tools/ci/build-info.mjs`, `tools/ci/verify-engine.mjs` | Build information and verification, Node standard library only, unit-tested (`tools/ci/test/`). |
| `tools/ci/workflow-policy.mjs` | The workflow policy check (below), run by `ci.yml`. |

## The artifact

Name: `pii-eval-engine-<commit sha>-linux-x86_64`. Retention: 30 days.
Contents, exactly these three files:

| File | Content |
| --- | --- |
| `pii-eval` | The release binary. Upload and download drop the executable bit; the verifier restores it. |
| `build-info.json` | `pii-eval-build-info/1`: repository, commit, ref, run id and attempt, target, toolchain (`rustc --version`, SHA-256 of `Cargo.lock` and `rust-toolchain.toml`), binary name, SHA-256, size and `--version` text. Sorted keys, no timestamps. |
| `SHA256SUMS` | Two lines in `sha256sum` format, sorted: `build-info.json` and `pii-eval`. |

Evaluation output (from `evaluate.yml`) is a second, separate artifact,
`pii-eval-run-<run id>-<attempt>`, retained 14 days. It holds the files the CLI
wrote for a public/synthetic run.

## Verifying an artifact

```sh
gh run download <run-id> -n pii-eval-engine-<commit>-linux-x86_64 -D engine
node tools/ci/verify-engine.mjs --dir engine --repository redact-secret/pii-eval \
  --target linux-x86_64 --make-executable
```

It prints one JSON line (`pii-eval-engine-verify/1`) and exits 0 only if every check
passes; otherwise it prints a reason code and exits 1 (2 on misuse). Reason codes:
`dir-unreadable`, `unexpected-file`, `missing-file`, `not-regular-file`,
`sums-malformed`, `sums-mismatch`, `build-info-invalid`, `binary-mismatch`,
`commit-mismatch`, `repository-mismatch`, `target-mismatch`, `exec-failed`,
`version-mismatch`, `usage`.

It proves the directory holds exactly those files, the sums match the bytes,
`build-info.json` has the closed schema and agrees with the binary, the optional
expectations hold, and the executed `--version` equals what `build-info.json`
says. It does **not** prove the commit is trustworthy, that the build is
reproducible, or who built it: the artifact is neither signed nor attested.
Compare semantic digests of runs, not binaries (`docs/cli.md`).

## Using the artifact from another workflow or action

`evaluate.yml` inputs: `engine-run-id` (a workflow run id; empty means "build one
in this run") and `config` (a relative path inside the checkout, default
`examples/quickstart/run-config.json`).

1. **Find a run to reuse.** The last successful CI run on `main`:
   `gh run list --workflow ci.yml --branch main --status success --limit 1 --json databaseId --jq '.[0].databaseId'`
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

What `evaluate.yml` does: checks the inputs (digits only; a relative path with no
`..`), downloads the engine artifact of that run, verifies it with
`tools/ci/verify-engine.mjs`, runs `pii-eval run` on the configuration, validates
the produced artifact against the snapshot and manifest, writes the engine
identity and the CLI's one-line summary to the job summary, and uploads the output.
When `engine-run-id` is empty it calls `build-engine.yml` first, so one run builds
the engine once. It never rebuilds an engine that exists.

**Across repositories** (not done, and needing manual settings): another
repository can dispatch `evaluate.yml` as above. Reading this repository's
artifacts from another repository's workflow needs a token with `actions: read`
here (a fine-grained token or a GitHub App installation token; the other
repository's `GITHUB_TOKEN` cannot). Calling these workflows with
`uses: redact-secret/pii-eval/.github/workflows/<file>@<sha>` from another private
repository additionally needs this repository's Actions "Access" setting to allow
repositories of the organization. None of this is configured.

## What is not provided

- Only **linux-x86_64**. Development on macOS builds with `cargo build --release --locked`
  (`docs/cli.md`); a macOS or arm64 artifact would need another runner and is not built.
- No signature, no provenance attestation, no reproducible-build claim, no SBOM.
- No release, tag or public distribution. Retention is 30 days; a deployment that
  must keep a binary longer has to copy it out of Actions and record its digest.
- The engine alone is not a deployment: it also needs Node 22, `ps`, the shim and
  the pinned scanner package, installed by a person (`docs/cli.md`).
- No protected runs: the CLI refuses a protected run without a custodian job
  context and these workflows supply none. Do not put protected material into a
  configuration, an input or an artifact (SECURITY.md).

## Security properties of the workflows

- Every action is pinned by full commit SHA; `permissions` are declared at the top
  of every workflow and are `contents: read` (plus `actions: read` for
  `evaluate.yml`, which reads artifacts of runs of this repository). No secrets.
- Workflow inputs are untrusted text. They reach a shell only through `env:` and are
  checked before use; no `${{ inputs.* }}`, event field, ref, actor or step/job
  output is interpolated into a script.
- `tools/ci/workflow-policy.mjs` enforces these rules on every workflow in CI
  (pinned `uses:`, top-level `permissions`, no `pull_request_target`, no
  `secrets: inherit`, no untrusted expression inside `run:`); its tests include
  inputs that must fail.
- The artifact is verified twice: before upload (`build-engine.yml`) and before use
  (`evaluate.yml`).
- Artifacts are readable by everyone with read access to the repository for as long
  as they are retained. They contain the binary and its build information only.
