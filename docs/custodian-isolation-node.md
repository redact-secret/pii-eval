# Node and the engine under the custodian sandbox limits (`RLIMIT_AS`)

Status: **measured on a real Linux bubblewrap host with synthetic data; the findings are an input for
private-custodian, not a decision.** This answers question Q7 of
[custodian-boundary.md](custodian-boundary.md) §6 and [custodian-contract-status.md](custodian-contract-status.md).
Nothing here is a protected evaluation, and no limit was loosened to make anything pass.

## The question

The custodian applies the approved plan's `memory` limit as `RLIMIT_AS`, a limit on *virtual address
space* (`docs/worker-isolation.md` §5 of private-custodian). The pii engine drives scanners through a Node
runtime, and V8 reserves large virtual regions when it starts (a code range, heap reservations) however little
memory the program really uses. Does a Node runtime start, and does the engine run, under such a limit, and from
which size on?

## Method

- **Sandbox.** `tools/isolation/bwrap-argv.mjs` is a replica of the custodian's launcher vector (`bubblewrap`
  with new user, IPC, PID, network and UTS namespaces, all capabilities dropped, a cleared environment, a
  read-only root holding only `/usr`, `/lib*`, `/bin`, `/sbin`, a `/proc` and a minimal `/dev`, a size-capped tmpfs
  `/scratch`, then `prlimit --cpu --as --nproc --fsize --core=0 --nofile=256`), written from
  `private-custodian@142db34dd4bc02903f47cba951a054351bb55fde` and pinned to it by a fidelity test (the assertions
  of that repository's `tests/argv.rs` plus a golden vector derived by hand from `build_argv`). It is a **replica**,
  not the custodian's code: that repository is private and no credential is available to CI. Two additions, both
  harmless: a read-only mount of this repository at `/repo` (the standalone quickstart reads its example files there)
  and no `/input` or `/job` mount (there is no job). The environment is the four variables the custodian's
  dispatcher sets (`PATH`, `HOME`, `TMPDIR`, `LANG=C`).
- **Limits.** The profile of the custodian's real-isolation tests (`tests/common/mod.rs` `Limits::normal`): CPU 30 s,
  wall 20 s, storage 64 MiB, 32 processes, stdout 64 KiB, stderr 1 MiB; only memory varies. The engine run gets 120 s
  CPU and 60 s wall; it finished in well under a second wherever it passed, so the longer budget biases nothing.
- **Controls first.** Before any size is measured the job proves the sandbox is real: the address-space limit read
  back from `/proc/self/limits` equals the request (and again at every size), the effective capability mask is zero,
  a probe that **does** connect to a host loopback listener when run outside the sandbox cannot reach a public address or that listener from
  inside (and the listener saw no connection from inside), a host canary file is invisible, the environment holds
  only allowlisted names and none of the credential-looking names planted in the launcher's environment, `/scratch`
  is writable and `/usr`, `/stage` and `/` are not. If any control fails the job fails and the measurement is void.
- **Subjects.** The engine built by CI (the verified artifact of the same run), the Node runtime `v22.23.3`
  pinned by sha256 `fde6a4bf8d0562f7751d1a2d6cb9b417c4cfe107bbcb0aa3e9a24e125e348f48` (the job fails if the digest differs), the synthetic quickstart
  (`docs/cli.md`) and its inert fake scanner. "`--jitless`" is a V8 flag; for the whole-engine run a measurement-only
  wrapper named `node` execs the unmodified runtime with that flag, because the engine's adapter starts Node with fixed
  arguments. The grid is 128 MiB steps up to 768 MiB, then 32 MiB steps to 1024 MiB, then 1536, 2048, 4096, 8192 MiB.
- **Host.** Linux 6.17.0-1022-azure, bubblewrap 0.9.0, 2 CPUs, GitHub-hosted `ubuntu-latest`.
- **Runs.** Committed data: run [37126457700](https://github.com/redact-secret/pii-eval/actions/runs/37126457700)
  ([isolation/node-rlimit-as.json](isolation/node-rlimit-as.json)). Two earlier runs of the same job on the same runner
  image, [37125507411](https://github.com/redact-secret/pii-eval/actions/runs/37125507411) and
  [37125748061](https://github.com/redact-secret/pii-eval/actions/runs/37125748061), used a coarser grid (and the first
  lacked the `--jitless` engine column); every size they share with the committed run gave the same result. They are
  repeats on one runner image, not independent hosts.
  Reproduce with the `isolation` workflow (`workflow_dispatch`, or the `isolation` job of `ci.yml`), or run
  `tools/isolation/matrix.mjs` on any Linux host with bubblewrap, `prlimit` and unprivileged user namespaces.

## Result

Controls: **all passed** (limit applied at every size, no capabilities, no egress with a working probe as the positive
control, no host files, scrubbed environment, scratch writable, writes outside scratch denied).

| address space | node starts | node `--jitless` | engine `--version` | engine quickstart run | same, node started with `--jitless` |
| --- | --- | --- | --- | --- | --- |
| 128 MiB | fail (hangs; killed at the wall limit) | fail (hangs; killed at the wall limit) | ok | fail (exit 5) | fail (exit 5) |
| 192 MiB | fail (exit 133) | fail (exit 133) | ok | fail (exit 5) | fail (exit 5) |
| 256 MiB | fail (exit 133) | fail (exit 133) | ok | fail (exit 5) | fail (exit 5) |
| 320 MiB | fail (exit 133) | ok | ok | fail (exit 5) | ok |
| 384 MiB | fail (exit 133) | ok | ok | fail (exit 5) | ok |
| 512 MiB | fail (exit 133) | ok | ok | fail (exit 5) | ok |
| 640 MiB | fail (exit 133) | ok | ok | fail (exit 5) | ok |
| 768 MiB | fail (exit 133) | ok | ok | fail (exit 5) | ok |
| 800 MiB | ok | ok | ok | ok | ok |
| 832 MiB | ok | ok | ok | ok | ok |
| 864 MiB | ok | ok | ok | ok | ok |
| 896 MiB | ok | ok | ok | ok | ok |
| 928 MiB | ok | ok | ok | ok | ok |
| 960 MiB | ok | ok | ok | ok | ok |
| 992 MiB | ok | ok | ok | ok | ok |
| 1024 MiB | ok | ok | ok | ok | ok |
| 1536 MiB | ok | ok | ok | ok | ok |
| 2048 MiB | ok | ok | ok | ok | ok |
| 4096 MiB | ok | ok | ok | ok | ok |
| 8192 MiB | ok | ok | ok | ok | ok |
(The table is generated: `node tools/isolation/render-table.mjs docs/isolation/node-rlimit-as.json`.)

At the 32 MiB resolution of the grid:

- an unmodified Node runtime does not start at 768 MiB and starts at 800 MiB, so its minimum is **above 768 MiB and at most 800 MiB**
  (its idle `VmPeak` is **772.4 MiB**, which fits);
- the whole engine quickstart run has the same boundary (it needs the runtime);
- with Node started with `--jitless` the boundary is **above 256 MiB and at most 320 MiB** (idle `VmPeak` 260.4 MiB);
- the Rust engine alone starts at every size tested, so its minimum is **at or below 128 MiB** (the smallest size tested);
- the series are monotone (no size passes below a size that fails).

Resident memory of an idle Node is about 43 MiB: the floor sits just above the *virtual* peak, the
expected shape of an address-space limit, and the program needs far less memory than it reserves.

Failure modes seen: `Fatal process out of memory: Failed to reserve virtual memory for CodeRange` (512 MiB), `Fatal JavaScript
out of memory: MemoryChunk allocation failed during deserialization` (768 MiB), exit 133 (SIGTRAP through bubblewrap's 128+signal
mapping) at the sizes between, and a hang at 128 MiB that the harness killed at the wall limit. When the runtime cannot start the engine
fails closed: it reports `scanner-failure` and exits 5 (`docs/cli.md`).

## Findings

1. **The custodian's real-isolation test profile (512 MiB) cannot start an unmodified Node runtime, and so cannot run the
   engine.** That profile is the plan of a synthetic Rust fixture engine, and a pii plan may ask for up to the operator
   cap (default 8192 MiB), so this is a conflict with that *test profile*, not with the contract. It does mean a pii plan
   has to be sized for the runtime. A plan below the boundary fails every run **after** exposure, and the custodian's outcome
   table settles a failed run as "failed, consumed" (`docs/worker-isolation.md` §7 of private-custodian).
2. **The conflict comes from the runtime's start-up reservation**: the failure happens when Node starts, before any work. The floor
   is therefore a lower bound for the smallest workload; a real corpus adds heap on top. Only one workload (the quickstart) was
   run, and `VmPeak` was read under an 8192 MiB limit, so how the need grows with the corpus is **not measured here**.
3. **An engine-side option exists and was measured, not adopted**: starting Node with `--jitless` lowers the boundary to between 257
   and 320 MiB (the quickstart passes at the custodian's 512 MiB). It changes how the scanner executes (interpreter only, no JIT), so its
   effect on scanner throughput and on timeouts must be measured before it is pinned in a worker configuration; nothing here enables it.
4. **The Rust engine is not the problem**: it starts at 128 MiB or below.
5. **No limit was loosened.** Only the plan's memory limit varies, to learn what a plan has to request. Raising or removing `RLIMIT_AS` in the
   custodian is not proposed.

## Contract proposals for private-custodian (none is implemented or assumed)

- **P-A. Size the plan to the runtime.** A pii plan's `memory` limit must exceed the pinned runtime's boundary (about 800 MiB for the
  unmodified Node measured here) *plus* headroom for the corpus; the quickstart passes at 1024 MiB. The boundary depends on the Node build
  (pinned by digest in the plan), so it has to be re-measured when the runtime changes.
- **P-B. Fail before exposure, not after.** A plan that cannot start its runtime currently fails after the exposure record and consumes budget. A cheap
  pre-exposure check would avoid that: after staging and before `record_exposure`, the dispatcher starts a synthetic, non-protected probe of the staged
  runtime under the plan's exact limits and settles the attempt through its existing pre-exposure path if it cannot start (the dispatcher's staging-failure
  paths already settle with the exposure still `NotExposed`; which settlement call is right is the custodian's decision). pii-eval can supply the probe (an
  engine-owned pre-flight that starts the pinned runtime and exits); it is **not** implemented because nothing calls it until the custodian agrees.
- **P-C. Declare the requirement.** The engine publishes a minimum virtual address space per pinned runtime (a number the approver can read) instead of it being
  discovered by a failed run.

## The whole worker flow in the same sandbox

The measurement above runs the standalone quickstart. The custodian's whole worker flow (staged identities, the job document,
the launcher, real Node as `scanner-0`, the result and aggregates, the outcome mapping) is run in the same replica sandbox by the CI job
`worker-flow`, with the test engine `worker_test_engine` (the production `pii-eval` refuses until the contract is decided): see
[worker-job.md](worker-job.md), "Real sandbox end to end". It asserts that the custodian's normal 512 MiB profile does **not** succeed, that
1024 MiB and above does, and records how the need grows with the population. The numbers of the latest run are in the job's report
(`pii-eval-worker-e2e/1`).

## Not claimed

- The numbers are for one host image, one kernel, one Node build and the synthetic quickstart (a tiny workload). They are not a general property of
  Node or of the custodian.
- The address-space need for a large population is **not measured here**; it belongs to the worker-launcher change and the deployment verification list.
- This is evidence about limits and about this engine, **not** evidence of isolation on any production host. The custodian's startup self-check on the
  production host, and its own CI job, remain the evidence (A13 in [custodian-contract-status.md](custodian-contract-status.md)). A Docker run is not
  accepted as evidence by the custodian and none was used.
- No seccomp, no cgroup controllers, no per-run host disk quota (the custodian's accepted residual risks).
- The sandbox is a replica of the launcher vector; differences from the real launcher (for example how it detects system roots on the production host) are
  possible and are covered only by the fidelity test.
