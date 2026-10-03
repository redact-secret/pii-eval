#!/usr/bin/env node
// The whole custodian worker flow, end to end, in a REAL Linux bubblewrap sandbox with the
// REAL pinned Node runtime, on SYNTHETIC data only (docs/worker-job.md, "real sandbox end
// to end"). Standard library only.
//
//   node tools/isolation/worker-e2e.mjs --engine PATH --node PATH --out FILE \
//     [--node-sha256 HEX] [--summary FILE] [--work DIR] [--bwrap /usr/bin/bwrap]
//
// --engine is target/release/examples/worker_test_engine (built with the cargo feature
// `worker-test-adapters`; it is test code, never the production `pii-eval`). For each
// scenario and memory size it plays the custodian's dispatcher:
//   1. stage the synthetic world (`worker_test_engine stage`), real Node as scanner-0;
//   2. REPLICA pre-run identity check: hash every staged file against the plan-like pins;
//      a mismatch is Rejected before anything runs (dispatcher.rs `pins`/`drive`);
//   3. run `/stage/engine --job /job/job.json` in the replica sandbox (tools/isolation/
//      bwrap-argv.mjs) with the dispatcher's mounts (/stage, /input, /job read-only), its four
//      environment variables and the custodian's "normal" quotas, memory being the variable;
//   4. REPLICA post-run identity re-hash (any drift is Rejected whatever the worker printed);
//   5. `worker_test_engine validate`: the replica of validate_result, the outcome mapping
//      (A6) and PrivateAggregates::decode.
// No limit is ever loosened to make a run pass. Memory is the only variable in the `normal`
// and mismatch scenarios; the hang scenario uses a 5 s wall clock (the only thing that may end
// it) and the population sweep a longer cpu and wall budget (it records, it does not assert).
// There is no protected data: the synthetic job carries the protected RUN CLASS.
// The controls of the isolation measurement
// (limits applied, no capabilities, no egress, no host files, scrubbed environment, writable
// scratch) must pass first, or the run is void. The exit status is non-zero on any violated
// expectation or failed control.
//
// REPLICA, NOT THE CUSTODIAN'S CODE: of private-custodian@142db34 (see bwrap-argv.mjs and
// crates/pii-eval-cli/tests/worker_support/replica.rs). It shows how THIS engine behaves under
// the custodian's documented limits; the custodian's startup self-check on the production host
// remains the evidence of isolation there.
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import { join } from 'node:path';
import { REPLICA_OF, buildArgv, detectSystemRoots } from './bwrap-argv.mjs';
import { MIB, sanitize } from './lib.mjs';
import { ENV, NORMAL, runControls } from './matrix.mjs';
import { isMain } from '../ci/main-guard.mjs';

export const SCHEMA = 'pii-eval-worker-e2e/1';
/** The smallest memory the custodian-normal profile is expected to run the whole flow in (the Q7 measurement). */
export const SUCCESS_FROM_MIB = 1024;
export const NORMAL_MEMS_MIB = [512, 1024, 1536];
export const OTHER_MEM_MIB = 1024;
export const SWEEP_ENTRIES = [20, 100, 400];
export const SWEEP_MEMS_MIB = [1024, 1536];
/** Sweep runs get a longer budget: they record how the address-space need grows, not the time limit. */
export const SWEEP_QUOTAS = { wallMs: 60000, cpuSeconds: 120 };
export const STDERR_PREFIX = 'pii-eval-worker-e2e-aggregates ';
const LAUNCHER_CANARIES = { GITHUB_TOKEN: 'canary-1', LEDGER_TOKEN: 'canary-2', AWS_SECRET_ACCESS_KEY: 'canary-3', APP_PRIVATE_KEY: 'canary-4' };

// --- pure parts (unit-tested in tools/isolation/test/worker-e2e.test.mjs) ----------------------

const REFUSALS = {
  'population-mismatch': 'population-binding-mismatch',
  'run-class-mismatch': 'run-class-mismatch',
  'wrong-bundle-digest': 'candidate-bundle-digest-mismatch',
  'wrong-tree-digest': 'package-tree-digest-mismatch',
  'wrong-runtime-digest': 'runtime-digest-mismatch',
  'stale-job': 'entries-listing-mismatch',
};

/** Every scenario the example can stage, in run order. */
export const SCENARIOS = ['normal', ...Object.keys(REFUSALS), 'scanner-crash', 'scanner-hang', 'staged-file-tampered', 'staged-copy-drift'];

/**
 * The scenario `worker_test_engine stage` builds for a scenario of this table. `staged-copy-drift`
 * is a harness-level scenario (a staged copy changes between staging and launch): the world is `normal`.
 * `scanner-hang` cannot tell an engine hang from a scanner hang: the sandbox only sees that the
 * worker did not finish within its wall clock.
 */
export function stageScenarioOf(scenario) {
  return scenario === 'staged-copy-drift' ? 'normal' : scenario;
}

/** Quota overrides of a scenario (the wall clock of the hang scenario is the only thing that may end it). */
export function quotasFor(scenario) {
  return scenario === 'scanner-hang' ? { wallMs: 5000 } : {};
}

/**
 * What the custodian outcome must be. `ran: false` means the dispatcher's own identity check
 * refuses before the worker starts. Memory only matters for `normal`: below the measured Node
 * boundary the flow must NOT succeed (the Q7 conflict, reproduced end to end).
 */
export function expectationFor(scenario, memMiB) {
  if (scenario === 'normal') {
    if (memMiB >= SUCCESS_FROM_MIB) {
      return { ran: true, outcomes: ['Success'], reasons: ['completed'], aggregatesOk: true, rosterComplete: true };
    }
    // Pinned to what the first CI run showed and the Q7 measurement explains: Node cannot start, the
    // scanner is unavailable, every entry is failed, the custodian settles Partial. The cause is recorded
    // in the same report by the Node start probe at this size.
    return { ran: true, outcomes: ['Partial'], reasons: ['engine_partial'], allFailed: true, notSuccess: true, aggregatesOk: false };
  }
  if (scenario in REFUSALS) {
    return { ran: true, outcomes: ['Failed'], reasons: ['non_zero_exit'], stdoutEmpty: true, nonZeroExit: true, engineReason: REFUSALS[scenario], aggregatesOk: false };
  }
  switch (scenario) {
    case 'scanner-crash':
      return { ran: true, outcomes: ['Partial'], reasons: ['engine_partial'], allFailed: true, aggregatesOk: false };
    case 'scanner-hang':
      return { ran: true, outcomes: ['Failed'], reasons: ['timeout'], aggregatesOk: false };
    // The file the custodian would stage differs from the plan's pin (dispatcher.rs `pins`).
    case 'staged-file-tampered':
      return { ran: false, outcomes: ['Rejected'], reasons: ['identity_mismatch'] };
    // A staged copy changes after staging, before launch (dispatcher.rs `staging.verify`).
    case 'staged-copy-drift':
      return { ran: false, outcomes: ['Rejected'], reasons: ['identity_changed_after_staging'] };
    default:
      throw new Error(`unknown scenario ${scenario}`);
  }
}

/** The list of runs: [{scenario, memMiB, entries}]. */
export function runPlan() {
  const plan = [];
  for (const memMiB of NORMAL_MEMS_MIB) plan.push({ scenario: 'normal', memMiB, entries: 3 });
  for (const scenario of SCENARIOS.filter((s) => s !== 'normal')) plan.push({ scenario, memMiB: OTHER_MEM_MIB, entries: 3 });
  return plan;
}

export function sweepPlan() {
  const plan = [];
  for (const entries of SWEEP_ENTRIES) for (const memMiB of SWEEP_MEMS_MIB) plan.push({ scenario: 'normal', memMiB, entries });
  return plan;
}

/** The `--exit` argument of the example's `validate` for how the worker ended. */
export function terminationArg(t) {
  if (t.timedOut) return 'timeout';
  if (t.outputLimit) return 'output-limit';
  if (t.signal) return `signal:${String(t.signal).replace(/[^A-Z0-9]/g, '').slice(0, 16) || 'UNKNOWN'}`;
  return String(t.exitCode ?? 1);
}

/** Names of staged files that no longer hash to their pin. `hashFile(name)` returns `sha256:<hex>` or null. */
export function identityMismatches(pins, hashFile) {
  return Object.keys(pins)
    .sort()
    .filter((name) => hashFile(name) !== pins[name]);
}

/** The engine's own fixed-vocabulary reason from its stderr line (`pii-eval: <reason> (<exit name>, exit N)`). */
export function engineReasonOf(stderr) {
  const m = /^pii-eval: ([a-z-]+) \(/m.exec(String(stderr));
  return m ? m[1] : null;
}

/** The aggregates document the test channel put on stderr, or null. */
export function aggregatesOf(stderr) {
  const lines = String(stderr)
    .split('\n')
    .filter((l) => l.startsWith(STDERR_PREFIX));
  return lines.length === 1 ? lines[0].slice(STDERR_PREFIX.length) : null;
}

/** Violated expectations of one observed run (empty = as expected). */
export function checkExpectation(exp, obs) {
  const v = [];
  if (obs.ran !== exp.ran) v.push(`ran=${obs.ran}, expected ${exp.ran}`);
  if (!exp.outcomes.includes(obs.outcome)) v.push(`outcome ${obs.outcome}, expected one of ${exp.outcomes.join('/')}`);
  if (exp.reasons && !exp.reasons.includes(obs.reason)) v.push(`reason ${obs.reason}, expected one of ${exp.reasons.join('/')}`);
  if (exp.notSuccess && obs.outcome === 'Success') v.push('the run succeeded below the measured boundary');
  if (exp.aggregatesOk !== undefined && obs.aggregatesOk !== exp.aggregatesOk) v.push(`aggregatesOk ${obs.aggregatesOk}, expected ${exp.aggregatesOk}`);
  if (exp.rosterComplete && !(obs.roster && obs.roster.failed === 0 && obs.roster.observed === obs.roster.expected && obs.roster.expected > 0)) v.push('roster is not complete with failed = 0');
  if (exp.allFailed && !(obs.roster && obs.roster.failed === obs.roster.expected && obs.roster.expected > 0)) v.push('roster does not show every entry failed');
  if (exp.stdoutEmpty && obs.stdoutBytes !== 0) v.push('a refusal printed on stdout');
  if (exp.nonZeroExit && !(Number.isInteger(obs.exitCode) && obs.exitCode !== 0)) v.push('a refusal exited zero');
  if (exp.engineReason && obs.engineReason !== exp.engineReason) v.push(`engine reason ${obs.engineReason}, expected ${exp.engineReason}`);
  return v;
}

/** The shape of one report row; no input text, only counters and fixed vocabulary. */
export function reportRow({ scenario, memMiB, entries, quotas, observed, expectation, violations, sweep }) {
  return {
    scenario,
    memMiB,
    entries,
    quotas,
    ran: observed.ran,
    termination: observed.termination ?? null,
    elapsedMs: observed.elapsedMs ?? null,
    stdoutBytes: observed.stdoutBytes ?? 0,
    engineReason: observed.engineReason ?? null,
    custodian: { outcome: observed.outcome, reason: observed.reason, roster: observed.roster ?? null, aggregatesOk: observed.aggregatesOk },
    ...(sweep ? { sweep: true } : { expected: { outcomes: expectation.outcomes, reasons: expectation.reasons ?? null }, violations }),
  };
}

export function summaryMarkdown(r) {
  const cell = (row) => `${row.custodian.outcome}${row.custodian.reason ? ` (${row.custodian.reason})` : ''}`;
  const lines = [
    '### The custodian flow end to end in a real bubblewrap sandbox, real Node',
    '',
    `Host: ${r.host.kernel}, ${r.host.bwrap}, Node ${r.host.node.version}. Replica of private-custodian@${r.replicaOf.commit.slice(0, 8)}; synthetic data only; the aggregates channel is a test channel.`,
    `Controls: **${r.controls.pass ? 'pass' : 'FAIL'}**. Violated expectations: **${r.violations.length}**.`,
    r.nodeStartProbe
      ? `Node alone at ${r.nodeStartProbe.memMiB} MiB: **${r.nodeStartProbe.started ? 'started' : 'did not start'}** (${r.nodeStartProbe.message || `exit ${r.nodeStartProbe.exitCode}`}).`
      : 'Node start probe: not run.',
    '',
    '| scenario | memory | entries | custodian outcome | engine reason | violations |',
    '| --- | --- | --- | --- | --- | --- |',
    ...r.runs.map((x) => `| ${x.scenario} | ${x.memMiB} MiB | ${x.entries} | ${cell(x)} | ${x.engineReason ?? ''} | ${x.violations.length === 0 ? 'none' : `**${x.violations.length}**`} |`),
    '',
    'Population sweep (recorded, not asserted):',
    '',
    '| entries | memory | custodian outcome | elapsed |',
    '| --- | --- | --- | --- |',
    ...r.sweep.map((x) => `| ${x.entries} | ${x.memMiB} MiB | ${cell(x)} | ${x.elapsedMs} ms |`),
    '',
  ];
  return `${lines.join('\n')}\n`;
}

// --- the sandbox, the example and the dispatcher's checks ---------------------------------------

const sha256File = (p) => createHash('sha256').update(readFileSync(p)).digest('hex');
const hashStaged = (stage) => (name) => {
  try {
    return `sha256:${sha256File(join(stage, name))}`;
  } catch {
    return null;
  }
};

/** A runner for the dispatcher's mount set. With `dir` undefined nothing is mounted (the controls). */
export function makeWorkerRunner({ bwrap, roots }) {
  return function run(program, args, { memMiB, quotas = {}, dir } = {}) {
    const q = { ...NORMAL, ...quotas, memoryBytes: memMiB * MIB };
    const roMounts = dir
      ? [
          { host: join(dir, 'stage'), inner: '/stage' },
          { host: join(dir, 'input'), inner: '/input' },
          { host: join(dir, 'job'), inner: '/job' },
        ]
      : [];
    const argv = buildArgv({ program, args, roMounts, env: ENV, quotas: q }, roots);
    const t0 = Date.now();
    const r = spawnSync(bwrap, argv, {
      env: LAUNCHER_CANARIES,
      timeout: q.wallMs,
      killSignal: 'SIGKILL',
      maxBuffer: 4 * MIB,
      encoding: 'utf8',
    });
    const stdout = String(r.stdout ?? '');
    return {
      exitCode: r.status,
      signal: r.signal,
      timedOut: r.error?.code === 'ETIMEDOUT',
      // stdout is bounded at 64 KiB and stderr at 1 MiB by the dispatcher (sandbox.rs supervise);
      // one byte more is an output-limit kill.
      outputLimit: r.error?.code === 'ENOBUFS' || Buffer.byteLength(stdout) > q.stdoutBytes || Buffer.byteLength(String(r.stderr ?? '')) > q.stderrBytes,
      spawnError: r.error && r.error.code !== 'ETIMEDOUT' && r.error.code !== 'ENOBUFS' ? sanitize(r.error.message, 120) : null,
      stdout,
      stderr: String(r.stderr ?? ''),
      elapsedMs: Date.now() - t0,
    };
  };
}

function stageWorld({ engine, node, work, scenario, entries }) {
  const dir = join(work, `${scenario}-${entries}-${Date.now()}`);
  const args = ['stage', '--out', dir, '--node', node, '--scenario', scenario, '--entries', String(entries)];
  execFileSync(engine, args, { encoding: 'utf8', maxBuffer: MIB });
  return dir;
}

function validateRun({ engine, dir, work, run, aggregates }) {
  const stdoutFile = join(work, 'stdout.txt');
  writeFileSync(stdoutFile, run.stdout);
  const args = ['validate', '--dir', dir, '--stdout', stdoutFile, '--exit', terminationArg(run)];
  if (aggregates !== null) {
    const f = join(work, 'aggregates.json');
    writeFileSync(f, aggregates);
    args.push('--aggregates', f);
  }
  return JSON.parse(execFileSync(engine, args, { encoding: 'utf8', maxBuffer: MIB }).trim());
}

/** Flip one byte of a staged file in place (a copy that drifts after staging). */
function driftStagedFile(dir, name) {
  const p = join(dir, 'stage', name);
  chmodSync(p, 0o700);
  const bytes = readFileSync(p);
  bytes[bytes.length - 1] ^= 1;
  writeFileSync(p, bytes);
  chmodSync(p, 0o500);
}

/**
 * One dispatcher round: stage, the identity check of the source against the plan's pins, (the staged
 * copy is re-hashed once more before launch, dispatcher.rs `staging.verify`), run, re-hash after.
 */
export function dispatch({ engine, node, work, run, scenario, memMiB, entries, quotas }) {
  const dir = stageWorld({ engine, node, work, scenario: stageScenarioOf(scenario), entries });
  try {
    const pins = JSON.parse(readFileSync(join(dir, 'pins.json'), 'utf8')).pins;
    const hash = hashStaged(join(dir, 'stage'));
    if (identityMismatches(pins, hash).length > 0) {
      return { ran: false, outcome: 'Rejected', reason: 'identity_mismatch', roster: null, aggregatesOk: false, stdoutBytes: 0 };
    }
    if (scenario === 'staged-copy-drift') driftStagedFile(dir, 'candidate');
    if (identityMismatches(pins, hash).length > 0) {
      return { ran: false, outcome: 'Rejected', reason: 'identity_changed_after_staging', roster: null, aggregatesOk: false, stdoutBytes: 0 };
    }
    const r = run('/stage/engine', ['--job', '/job/job.json'], { memMiB, quotas, dir });
    if (identityMismatches(pins, hash).length > 0) {
      return { ran: true, outcome: 'Rejected', reason: 'identity_changed_after_execution', roster: null, aggregatesOk: false, stdoutBytes: Buffer.byteLength(r.stdout) };
    }
    const aggregates = aggregatesOf(r.stderr);
    const v = validateRun({ engine, dir, work, run: r, aggregates });
    return {
      ran: true,
      outcome: v.outcome,
      reason: v.reason,
      roster: v.roster,
      aggregatesOk: v.aggregatesOk,
      stdoutBytes: Buffer.byteLength(r.stdout),
      exitCode: r.exitCode,
      engineReason: engineReasonOf(r.stderr),
      elapsedMs: r.elapsedMs,
      termination: { exitCode: r.exitCode, signal: r.signal, timedOut: r.timedOut, outputLimit: r.outputLimit },
      spawnError: r.spawnError,
    };
  } finally {
    // Each world holds a copy of Node (about 100 MiB): never keep more than one.
    rmSync(dir, { recursive: true, force: true });
  }
}

/** The memory of the Node start probe: the custodian's own test profile. */
export const PROBE_MEM_MIB = 512;

/** What the report records about where it ran (the commit and run of the CI job; null elsewhere). */
export function ciIdentity(env) {
  const pick = (k, re) => (typeof env[k] === 'string' && re.test(env[k]) ? env[k] : null);
  return {
    commit: pick('GITHUB_SHA', /^[0-9a-f]{40}$/),
    runId: pick('GITHUB_RUN_ID', /^[0-9]{1,20}$/),
    runAttempt: pick('GITHUB_RUN_ATTEMPT', /^[0-9]{1,6}$/),
  };
}

/** The probe must FAIL at 512 MiB (the Q7 conflict); a start there would void the 512 MiB expectation. */
export function checkProbe(probe) {
  return probe.started ? ['Node started under the custodian test profile; the 512 MiB expectation is stale'] : [];
}

/** Start the staged Node alone (no engine) under `memMiB` and record how it ended, sanitized. */
export function probeNodeStart({ engine, node, work, run, memMiB }) {
  const dir = stageWorld({ engine, node, work, scenario: 'normal', entries: 3 });
  try {
    const r = run('/stage/scanner-0', ['-e', 'process.stdout.write(process.version)'], { memMiB, dir });
    return {
      memMiB,
      started: r.exitCode === 0 && !r.timedOut && !r.signal && /^v\d+\./.test(r.stdout),
      exitCode: r.exitCode,
      signal: r.signal,
      timedOut: r.timedOut,
      // The V8 message (for example "Failed to reserve virtual memory for CodeRange"), printable ASCII only.
      message: sanitize(r.stderr, 300),
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function parseArgs(argv) {
  const o = {};
  for (let i = 0; i < argv.length; i += 2) {
    if (!argv[i].startsWith('--') || i + 1 >= argv.length) throw new Error(`bad argument ${argv[i]}`);
    o[argv[i].slice(2)] = argv[i + 1];
  }
  for (const k of ['engine', 'node', 'out']) if (typeof o[k] !== 'string') throw new Error(`missing --${k}`);
  if (o['node-sha256'] !== undefined && !/^[0-9a-f]{64}$/.test(o['node-sha256'])) throw new Error('bad --node-sha256');
  return o;
}

export async function main(argv) {
  const a = parseArgs(argv);
  const bwrap = a.bwrap ?? '/usr/bin/bwrap';
  for (const f of [a.engine, a.node]) if (!existsSync(f)) throw new Error('a required file is missing');
  chmodSync(a.engine, 0o755);
  if (a['node-sha256'] !== undefined && sha256File(a.node) !== a['node-sha256']) throw new Error('the Node runtime is not the pinned one (digest mismatch)');
  const work = a.work ?? mkdtempSync(join(os.tmpdir(), 'pii-eval-worker-e2e-'));
  mkdirSync(work, { recursive: true });
  const roots = detectSystemRoots();
  const run = makeWorkerRunner({ bwrap, roots });
  const controls = await runControls(run);
  const host = {
    kernel: sanitize(`${os.type()} ${os.release()}`, 100),
    bwrap: sanitize(execFileSync(bwrap, ['--version'], { encoding: 'utf8', env: {} }), 60),
    cpus: os.cpus().length,
    node: { version: sanitize(execFileSync(a.node, ['--version'], { encoding: 'utf8' }), 30), sha256: sha256File(a.node) },
    engine: { sha256: sha256File(a.engine) },
  };
  const runs = [];
  const sweep = [];
  const violations = [];
  let nodeStartProbe = null;
  if (controls.pass) {
    // The cause of the 512 MiB result, in the same report: does the pinned Node start at all at that size?
    nodeStartProbe = probeNodeStart({ engine: a.engine, node: a.node, work, run, memMiB: PROBE_MEM_MIB });
    for (const x of checkProbe(nodeStartProbe)) violations.push(`node-start-probe@${PROBE_MEM_MIB}MiB: ${x}`);
    process.stdout.write(`${JSON.stringify({ nodeStartProbe })}\n`);
    for (const p of runPlan()) {
      const quotas = quotasFor(p.scenario);
      const observed = dispatch({ engine: a.engine, node: a.node, work, run, ...p, quotas });
      const expectation = expectationFor(p.scenario, p.memMiB);
      const v = checkExpectation(expectation, observed);
      const row = reportRow({ ...p, quotas: { ...NORMAL, ...quotas }, observed, expectation, violations: v });
      runs.push(row);
      for (const x of v) violations.push(`${p.scenario}@${p.memMiB}MiB: ${x}`);
      process.stdout.write(`${JSON.stringify(row)}\n`);
    }
    for (const p of sweepPlan()) {
      const observed = dispatch({ engine: a.engine, node: a.node, work, run, ...p, quotas: SWEEP_QUOTAS });
      const row = reportRow({ ...p, quotas: { ...NORMAL, ...SWEEP_QUOTAS }, observed, expectation: null, violations: [], sweep: true });
      sweep.push(row);
      process.stdout.write(`${JSON.stringify(row)}\n`);
    }
  }
  const result = {
    schema: SCHEMA,
    replicaOf: REPLICA_OF,
    ci: ciIdentity(process.env),
    host,
    profile: { ...NORMAL, note: 'the custodian normal profile; memory is the only variable in the normal and mismatch scenarios; the hang scenario has a 5 s wall clock and the sweep a longer cpu and wall budget; no limit is loosened to make a run pass' },
    controls,
    nodeStartProbe,
    runs: runs.map((r) => ({ ...r, violations: r.violations ?? [] })),
    sweep,
    violations,
    pass: controls.pass && violations.length === 0 && runs.length === runPlan().length,
  };
  writeFileSync(a.out, `${JSON.stringify(result, null, 2)}\n`);
  if (a.summary) writeFileSync(a.summary, summaryMarkdown(result), { flag: 'a' });
  if (!a.work) rmSync(work, { recursive: true, force: true });
  process.stdout.write(`${JSON.stringify({ schema: SCHEMA, controlsPass: controls.pass, runs: runs.length, violations: violations.length, pass: result.pass })}\n`);
  return result.pass ? 0 : 1;
}

if (isMain(import.meta.url)) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e) => {
      process.stderr.write(`worker-e2e: ${sanitize(e.message, 200)}\n`);
      process.exit(2);
    },
  );
}
