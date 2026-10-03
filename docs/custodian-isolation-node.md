# Node and the engine under the custodian sandbox limits (`RLIMIT_AS`)

Status: **measured on a real Linux bubblewrap host with synthetic data; findings are a contract
input for private-custodian, not a decision.** This answers question Q7 of
[custodian-boundary.md](custodian-boundary.md) §6 and [custodian-contract-status.md](custodian-contract-status.md).
Nothing here is a protected evaluation, and no limit was loosened to make anything pass.

## The question

The custodian applies the approved plan's `memory` limit as `RLIMIT_AS`, a limit on *virtual
address space* (`docs/worker-isolation.md` §5 of private-custodian). The pii engine drives scanners
through a Node runtime, and V8 reserves large virtual regions at start-up (a code range, heap
reservations) regardless of how little memory the program really uses. Does a Node runtime start,
and does the engine run, under such a limit, and from which size on?

## Method

- **Sandbox.** `tools/isolation/bwrap-argv.mjs` is a replica of the custodian's launcher vector
  (`bubblewrap` with new user, IPC, PID, network and UTS namespaces, all capabilities dropped, a cleared
  environment with the custodian's allowlist, a read-only root with only `/usr`, `/lib*`, `/bin`, `/sbin`,
  `/proc`, `/dev`, a size-capped tmpfs `/scratch`, then `prlimit --cpu --as --nproc --fsize --core=0
  --nofile=256`), written from `private-custodian@142db34dd4bc02903f47cba951a054351bb55fde` and pinned to
  it by a fidelity test that ports the assertions of that repository's `tests/argv.rs` and a golden vector
  derived by hand from `build_argv`. It is a **replica**, not the custodian's code (the repository is
  private and no credential is available to CI). The only addition is a read-only mount of the repository at `/repo`
  (the standalone quickstart reads its example files there); it relaxes nothing.
- **Limits.** The custodian's documented real-isolation "normal" profile (`tests/common/mod.rs`
  `Limits::normal`): CPU 30 s, wall 20 s, storage 64 MiB, 32 processes, stdout 64 KiB, stderr 1 MiB;
  only memory varies. The engine run gets 120 s CPU and 60 s wall.
- **Controls first.** Before any size is measured the job proves the sandbox is real: the address-space
  limit read back from `/proc/self/limits` equals the request (and again at every size), the effective
  capability mask is zero, a public address and the host's loopback listener are unreachable (and the listener
  saw no connection), a host canary file is invisible, the environment holds only allowlisted names and none of
  the credential-looking names planted in the launcher's environment, `/scratch` is writable and `/usr`,
  `/stage` and `/` are not. If any control fails the job fails and the measurement is void.
- **Subjects.** The engine built by CI (the verified artifact of the same run), the pinned Node runtime
  `v22.23.3` (sha256 `fde6a4bf8d0562f7751d1a2d6cb9b417c4cfe107bbcb0aa3e9a24e125e348f48`), the synthetic quickstart (`docs/cli.md`) and the inert fake scanner.
  "`--jitless`" is a V8 flag; for the whole-engine run a measurement-only wrapper named `node` execs the
  unmodified runtime with that flag, because the engine's adapter starts Node with fixed arguments.
- **Host.** Linux 6.17.0-1022-azure, bubblewrap 0.9.0, 2 CPUs, GitHub-hosted `ubuntu-latest`. Runs:
  [37125507411](https://github.com/redact-secret/pii-eval/actions/runs/37125507411) and
  [37125748061](https://github.com/redact-secret/pii-eval/actions/runs/37125748061) (same results in both).
  Raw data: [isolation/node-rlimit-as.json](isolation/node-rlimit-as.json). Reproduce: the `isolation`
  workflow (`workflow_dispatch`, or the `isolation` job of `ci.yml`), or `tools/isolation/matrix.mjs` on any Linux host with
  bubblewrap, `prlimit` and unprivileged user namespaces.

## Result

Controls: **all passed** (limit applied at every size, no capabilities, no egress, no host files,
scrubbed environment, scratch writable, writes outside scratch denied).

| address space | node starts | node `--jitless` | engine `--version` | engine quickstart run | same, node started with `--jitless` |
| --- | --- | --- | --- | --- | --- |
| 128 MiB | fail (SIGKILL) | fail (SIGKILL) | ok | fail (exit 5) | fail (exit 5) |
| 192 MiB | fail (exit 133) | fail (exit 133) | ok | fail (exit 5) | fail (exit 5) |
| 256 MiB | fail (exit 133) | fail (exit 133) | ok | fail (exit 5) | fail (exit 5) |
| 320 MiB | fail (exit 133) | ok | ok | fail (exit 5) | ok |
| 384 MiB | fail (exit 133) | ok | ok | fail (exit 5) | ok |
| 512 MiB | fail (exit 133) | ok | ok | fail (exit 5) | ok |
| 640 MiB | fail (exit 133) | ok | ok | fail (exit 5) | ok |
| 768 MiB | fail (exit 133) | ok | ok | fail (exit 5) | ok |
| 1024 MiB | ok | ok | ok | ok | ok |
| 1536 MiB | ok | ok | ok | ok | ok |
| 2048 MiB | ok | ok | ok | ok | ok |
| 4096 MiB | ok | ok | ok | ok | ok |
| 8192 MiB | ok | ok | ok | ok | ok |

Smallest size from which every larger size passes (the series are monotone): Node **1024 MiB**,
Node `--jitless` **320 MiB**, the engine alone **128 MiB**, the whole engine
quickstart run **1024 MiB**, and with Node started with `--jitless` **320 MiB**.

Virtual address space of an idle Node (`/proc/self/status`, measured under 8192 MiB): default `VmPeak`
**772 MiB** (resident 43 MiB); with `--jitless` `VmPeak` **260 MiB**
(resident 43 MiB). The floor sits just above `VmPeak`, which is the expected shape of a
virtual-address-space limit: the program needs far less memory than it reserves.

Failure modes seen: `Fatal process out of memory: Failed to reserve virtual memory for CodeRange` (512 MiB), `Fatal
JavaScript out of memory: MemoryChunk allocation failed during deserialization` (768 MiB), a kill before any output (128 MiB).
When the runtime cannot start the engine fails closed: it reports `scanner-failure` and exits 5 (`docs/cli.md`).

## Findings

1. **The custodian's own "normal" test limit (512 MiB) cannot run the engine as built**: the default Node
   runtime does not start below 1024 MiB, and the engine run fails with it. With such a plan every pii run would
   fail after exposure, and the custodian's outcome table consumes the budget for a failed run
   (`docs/worker-isolation.md` §7 of private-custodian: `Failed` is "failed, consumed").
2. **The conflict is real and reproducible, and it is a property of the runtime's start-up reservation, not of
   the corpus**: it does not depend on how much work is done. It also means the floor above is a
   *lower bound for the smallest workload*; a real corpus adds heap on top (not measured here, see below).
3. **An engine-side option exists and was measured, not adopted**: starting Node with `--jitless` lowers the
   floor to 320 MiB (the quickstart passes at the custodian's 512 MiB). It changes how the scanner executes
   (interpreter only, no JIT), so its effect on scanner throughput and on timeouts must be measured before it is
   pinned in a worker configuration; this change does not enable it anywhere.
4. **The Rust engine itself is not the problem**: it starts at 128 MiB.
5. **No limit was loosened.** The measurement varies the plan's memory limit only, to learn what a plan has to
   request. Raising or removing `RLIMIT_AS` in the custodian is not proposed here.

## Contract proposals for private-custodian (none is implemented or assumed)

- **P-A. Size the plan to the runtime.** The pii plan's `memory` limit must be at least the measured floor of the
  pinned runtime *plus* headroom for the corpus; for the unmodified Node runtime that is more than 1024 MiB, not
  512 MiB. The floor depends on the Node build (it is pinned by digest in the plan), so it has to be re-measured when
  the runtime changes.
- **P-B. Fail before exposure, not after.** A plan that cannot start its runtime currently fails after the exposure
  record and consumes budget. A cheap pre-exposure check would avoid that: the dispatcher starts a synthetic,
  non-protected probe of the staged runtime under the plan's exact limits before `record_exposure` and refunds
  (`fail_before_start`) if it cannot start. pii-eval can supply such a probe (an engine-owned pre-flight that starts
  the pinned runtime and exits); it is **not** implemented because nothing calls it until the custodian agrees.
- **P-C. Declare the requirement.** The engine publishes a minimum virtual address space per pinned runtime (a
  number the approver can read), instead of it being discovered by a failed run.

## Not claimed

- The numbers are for one host image, one kernel, one Node build and the synthetic quickstart (tiny workload). They
  are not a general property of Node or of the custodian.
- Real corpora grow the heap; the address-space need for a large population is **not measured here**. The
  full-flow sandbox run with a larger synthetic population is part of the worker-launcher change and the
  deployment verification list.
- This is evidence about limits and about this engine, **not** evidence of isolation on any production host. The
  custodian's startup self-check on the production host, and its own CI job, remain the evidence (A13 in
  [custodian-contract-status.md](custodian-contract-status.md)). A Docker run is not accepted as evidence by the
  custodian and none was used.
- No seccomp, no cgroup controllers, no per-run host disk quota (the custodian's accepted residual risks).
- The sandbox is a replica of the launcher vector; differences from the real launcher (for example how it detects
  system roots on the production host) are possible and are covered only by the fidelity test.
