#!/usr/bin/env node
// Measures how the pii-eval engine and a pinned Node runtime behave under the
// custodian's worker sandbox limits (docs/custodian-isolation-node.md), on a REAL Linux
// bubblewrap host. Standard library only. Synthetic data only: the quickstart example.
//
//   node tools/isolation/matrix.mjs --stage DIR --repo DIR --out FILE \
//     [--summary FILE] [--mem-mib 128,192,...] [--bwrap /usr/bin/bwrap]
//
// DIR holds `engine` (the pii-eval binary) and `node` (the pinned Node runtime), both
// executable. `--repo` is the repository checkout, mounted read-only at /repo (an
// addition to the custodian's mount set, needed because the standalone quickstart reads
// its example files there; it is not a relaxation of any limit).
//
// What it will NOT do: lower or raise any limit to make a command pass. Memory is the
// variable being measured; every other quota is the custodian's documented "normal"
// test profile (cpu 30 s, wall 20 s, storage 64 MiB, 32 processes) except where noted.
// The controls (limits applied, no capabilities, no egress, no host files, scrubbed
// environment, writable scratch) must pass first, or the measurement is void and the
// exit status is non-zero: a measurement without a real sandbox proves nothing.
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import { join } from 'node:path';
import { ENV_ALLOWLIST, REPLICA_OF, buildArgv, detectSystemRoots } from './bwrap-argv.mjs';
import { MIB, envNamesOutsideAllowlist, floorOf, parseAddressSpaceLimit, parseCapEff, parseVmLines, sanitize } from './lib.mjs';
import { isMain } from '../ci/main-guard.mjs';

export const SCHEMA = 'pii-eval-isolation-node/1';
// The custodian's "normal" real-isolation profile (tests/common/mod.rs `Limits::normal`),
// memory excluded: it is the variable.
const NORMAL = { cpuSeconds: 30, wallMs: 20000, storageBytes: 64 * MIB, maxProcesses: 32, stdoutBytes: 65536, stderrBytes: MIB };
const CUSTODIAN_NORMAL_MEM_MIB = 512;
const DEFAULT_SIZES = [128, 192, 256, 320, 384, 512, 640, 768, 1024, 1536, 2048, 4096, 8192];
const ENV = [
  ['PATH', '/usr/bin:/bin'],
  ['HOME', '/scratch'],
  ['TMPDIR', '/scratch'],
  ['LANG', 'C.UTF-8'],
];
const CANARY_FILE = '/tmp/pii-eval-isolation-canary';
// Names that look like the credentials the custodian's self-check plants in the launcher's environment.
const LAUNCHER_CANARIES = { GITHUB_TOKEN: 'canary-1', LEDGER_TOKEN: 'canary-2', AWS_SECRET_ACCESS_KEY: 'canary-3', APP_PRIVATE_KEY: 'canary-4' };

const sha256File = (p) => createHash('sha256').update(readFileSync(p)).digest('hex');

function parseArgs(argv) {
  const o = {};
  for (let i = 0; i < argv.length; i += 2) {
    if (!argv[i].startsWith('--') || i + 1 >= argv.length) throw new Error(`bad argument ${argv[i]}`);
    o[argv[i].slice(2)] = argv[i + 1];
  }
  for (const k of ['stage', 'repo', 'out']) if (typeof o[k] !== 'string') throw new Error(`missing --${k}`);
  return o;
}

export function makeRunner({ bwrap, stage, repo, roots }) {
  return function run(program, args, { memMiB, quotas = {}, mounts = true } = {}) {
    const q = { ...NORMAL, ...quotas, memoryBytes: memMiB * MIB };
    const spec = {
      program,
      args,
      roMounts: mounts ? [{ host: stage, inner: '/stage' }, { host: repo, inner: '/repo' }] : [],
      env: ENV,
      quotas: q,
    };
    const argv = buildArgv(spec, roots);
    const t0 = Date.now();
    const r = spawnSync(bwrap, argv, {
      env: LAUNCHER_CANARIES,
      timeout: q.wallMs + 5000,
      killSignal: 'SIGKILL',
      maxBuffer: 4 * MIB,
      encoding: 'utf8',
    });
    return {
      exitCode: r.status,
      signal: r.signal,
      timedOut: r.error?.code === 'ETIMEDOUT',
      spawnError: r.error && r.error.code !== 'ETIMEDOUT' ? sanitize(r.error.message, 120) : null,
      stdout: String(r.stdout ?? ''),
      stderr: String(r.stderr ?? ''),
      elapsedMs: Date.now() - t0,
    };
  };
}

const ok = (r) => r.exitCode === 0 && !r.timedOut && !r.signal;
const brief = (r) => ({
  ok: ok(r),
  exitCode: r.exitCode,
  signal: r.signal,
  timedOut: r.timedOut,
  elapsedMs: r.elapsedMs,
  stdout: sanitize(r.stdout, 200),
  stderr: sanitize(r.stderr, 300),
});

async function controls(run, listener) {
  const out = {};
  const mem = CUSTODIAN_NORMAL_MEM_MIB;
  const limits = run('/usr/bin/cat', ['/proc/self/limits'], { memMiB: mem });
  const as = parseAddressSpaceLimit(limits.stdout);
  out.rlimitsApplied = { pass: ok(limits) && as && as.soft === mem * MIB && as.hard === mem * MIB, requestedBytes: mem * MIB, observed: as };
  const status = run('/usr/bin/cat', ['/proc/self/status'], { memMiB: mem });
  const cap = parseCapEff(status.stdout);
  out.noCapabilities = { pass: ok(status) && /^0+$/.test(cap ?? 'x'), capEff: cap };
  const net1 = run('/bin/bash', ['-c', '(exec 3<>/dev/tcp/1.1.1.1/53) 2>/dev/null && echo CONNECTED || echo BLOCKED'], { memMiB: mem });
  const net2 = run('/bin/bash', ['-c', `(exec 3<>/dev/tcp/127.0.0.1/${listener.port}) 2>/dev/null && echo CONNECTED || echo BLOCKED`], { memMiB: mem });
  await new Promise((r) => setTimeout(r, 200));
  out.egressDenied = { pass: net1.stdout.trim() === 'BLOCKED' && net2.stdout.trim() === 'BLOCKED' && listener.connections === 0, publicAddress: net1.stdout.trim(), hostLoopback: net2.stdout.trim(), hostListenerConnections: listener.connections };
  const canary = run('/usr/bin/cat', [CANARY_FILE], { memMiB: mem });
  out.hostFilesAbsent = { pass: !ok(canary) && !canary.stdout.includes('canary-content') };
  const env = run('/usr/bin/env', [], { memMiB: mem });
  const outside = envNamesOutsideAllowlist(env.stdout, ENV_ALLOWLIST);
  const leaked = Object.keys(LAUNCHER_CANARIES).filter((n) => env.stdout.includes(n) || env.stdout.includes(LAUNCHER_CANARIES[n]));
  out.envScrubbed = { pass: ok(env) && outside.length === 0 && leaked.length === 0, namesOutsideAllowlist: outside, leakedCanaries: leaked };
  const scratch = run('/bin/sh', ['-c', 'head -c 4096 /dev/zero > /scratch/probe && echo OK'], { memMiB: mem });
  out.scratchWritable = { pass: ok(scratch) && scratch.stdout.trim() === 'OK' };
  const writeOutside = run('/bin/sh', ['-c', 'touch /usr/x 2>/dev/null; touch /stage/x 2>/dev/null; touch /x 2>/dev/null && echo WROTE || echo DENIED'], { memMiB: mem });
  out.writeOutsideScratchDenied = { pass: writeOutside.stdout.trim() === 'DENIED' };
  const root = run('/usr/bin/ls', ['/'], { memMiB: mem });
  out.visibleRoot = { entries: sanitize(root.stdout, 200) };
  out.pass = Object.values(out).every((v) => v.pass !== false);
  return out;
}

export async function main(argv) {
  const a = parseArgs(argv);
  const bwrap = a.bwrap ?? '/usr/bin/bwrap';
  const sizes = a['mem-mib'] ? a['mem-mib'].split(',').map(Number) : DEFAULT_SIZES;
  if (sizes.some((n) => !Number.isInteger(n) || n < 16 || n > 65536)) throw new Error('bad --mem-mib');
  const stage = join(a.stage);
  for (const f of ['engine', 'node']) {
    if (!existsSync(join(stage, f))) throw new Error(`missing ${f} in the stage directory`);
    chmodSync(join(stage, f), 0o755);
  }
  // A MEASUREMENT-ONLY wrapper: the engine's adapter starts Node with fixed arguments, so to learn
  // what `--jitless` would buy the whole engine run without changing the engine, the engine is pointed
  // at a file named `node` that execs the pinned runtime with that flag. Nothing is loosened; the
  // wrapper only changes how the unmodified runtime is started. Whether to adopt such a flag is a
  // separate decision (docs/custodian-isolation-node.md).
  mkdirSync(join(stage, 'jitless'), { recursive: true });
  writeFileSync(join(stage, 'jitless', 'node'), '#!/bin/sh\nexec /stage/node --jitless "$@"\n', { mode: 0o755 });
  chmodSync(join(stage, 'jitless', 'node'), 0o755);
  writeFileSync(CANARY_FILE, 'canary-content\n', { mode: 0o600 });
  const roots = detectSystemRoots();
  const run = makeRunner({ bwrap, stage, repo: a.repo, roots });

  const listener = { port: 0, connections: 0 };
  const server = net.createServer((s) => {
    listener.connections += 1;
    s.destroy();
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  listener.port = server.address().port;

  const host = {
    kernel: sanitize(`${os.type()} ${os.release()}`, 100),
    bwrap: sanitize(execFileSync(bwrap, ['--version'], { encoding: 'utf8', env: {} }), 60),
    cpus: os.cpus().length,
    node: { version: sanitize(execFileSync(join(stage, 'node'), ['--version'], { encoding: 'utf8' }), 30), sha256: sha256File(join(stage, 'node')) },
    engine: { sha256: sha256File(join(stage, 'engine')), version: sanitize(execFileSync(join(stage, 'engine'), ['--version'], { encoding: 'utf8' }), 100) },
  };

  const ctl = await controls(run, listener);
  server.close();

  const nodeStart = new Map();
  const nodeJitless = new Map();
  const engineVersion = new Map();
  const engineRun = new Map();
  const engineRunJitless = new Map();
  const rows = [];
  for (const mem of sizes) {
    const lim = run('/usr/bin/cat', ['/proc/self/limits'], { memMiB: mem });
    const limit = parseAddressSpaceLimit(lim.stdout);
    const n1 = run('/stage/node', ['-e', 'process.stdout.write(process.version)'], { memMiB: mem });
    const n2 = run('/stage/node', ['--jitless', '-e', 'process.stdout.write(process.version)'], { memMiB: mem });
    const e1 = run('/stage/engine', ['--version'], { memMiB: mem });
    const e2 = run('/stage/engine', ['run', '--config', '/repo/examples/quickstart/run-config.json', '--node', '/stage/node', '--out', '/scratch/out'], {
      memMiB: mem,
      quotas: { wallMs: 60000, cpuSeconds: 120 },
    });
    const e3 = run('/stage/engine', ['run', '--config', '/repo/examples/quickstart/run-config.json', '--node', '/stage/jitless/node', '--out', '/scratch/out'], {
      memMiB: mem,
      quotas: { wallMs: 60000, cpuSeconds: 120 },
    });
    nodeStart.set(mem, ok(n1));
    nodeJitless.set(mem, ok(n2));
    engineVersion.set(mem, ok(e1));
    const engineOk = ok(e2) && /"name":"success"/.test(e2.stdout);
    engineRun.set(mem, engineOk);
    const jitlessOk = ok(e3) && /"name":"success"/.test(e3.stdout);
    engineRunJitless.set(mem, jitlessOk);
    rows.push({
      memMiB: mem,
      limitApplied: limit !== null && limit.soft === mem * MIB && limit.hard === mem * MIB,
      nodeStart: brief(n1),
      nodeJitless: brief(n2),
      engineVersion: brief(e1),
      engineQuickstartRun: { ...brief(e2), ok: engineOk },
      engineQuickstartRunNodeJitless: { ...brief(e3), ok: jitlessOk },
    });
  }
  const big = Math.max(...sizes);
  const vm = run('/stage/node', ['-e', "const s=require('fs').readFileSync('/proc/self/status','utf8');process.stdout.write(s.split('\\n').filter(l=>/^(VmPeak|VmSize|VmRSS|VmHWM):/.test(l)).join(';'))"], { memMiB: big });
  const vmIdle = ok(vm) ? parseVmLines(vm.stdout.replace(/;/g, '\n')) : null;
  const vmJit = run('/stage/node', ['--jitless', '-e', "const s=require('fs').readFileSync('/proc/self/status','utf8');process.stdout.write(s.split('\\n').filter(l=>/^(VmPeak|VmSize|VmRSS|VmHWM):/.test(l)).join(';'))"], { memMiB: big });
  const vmJitless = ok(vmJit) ? parseVmLines(vmJit.stdout.replace(/;/g, '\n')) : null;

  const floors = {
    nodeStartMiB: floorOf(sizes, nodeStart),
    nodeJitlessMiB: floorOf(sizes, nodeJitless),
    engineVersionMiB: floorOf(sizes, engineVersion),
    engineQuickstartRunMiB: floorOf(sizes, engineRun),
    engineQuickstartRunNodeJitlessMiB: floorOf(sizes, engineRunJitless),
  };
  const everyLimitApplied = rows.every((r) => r.limitApplied);
  const result = {
    schema: SCHEMA,
    replicaOf: REPLICA_OF,
    host,
    profile: { ...NORMAL, note: 'custodian normal profile except memory (the variable) and a longer wall/cpu budget for the engine run', custodianNormalMemoryMiB: CUSTODIAN_NORMAL_MEM_MIB },
    controls: ctl,
    everyLimitApplied,
    nodeVirtualMemoryKbAtIdle: { default: vmIdle, jitless: vmJitless, measuredUnderMemMiB: big },
    floors,
    custodianNormalMemory: {
      memMiB: CUSTODIAN_NORMAL_MEM_MIB,
      nodeStarts: nodeStart.get(CUSTODIAN_NORMAL_MEM_MIB) ?? null,
      engineQuickstartRuns: engineRun.get(CUSTODIAN_NORMAL_MEM_MIB) ?? null,
      engineQuickstartRunsWithNodeJitless: engineRunJitless.get(CUSTODIAN_NORMAL_MEM_MIB) ?? null,
    },
    matrix: rows,
  };
  writeFileSync(a.out, `${JSON.stringify(result, null, 2)}\n`);
  if (a.summary) writeFileSync(a.summary, summaryMarkdown(result), { flag: 'a' });
  process.stdout.write(`${JSON.stringify({ schema: SCHEMA, controlsPass: ctl.pass, everyLimitApplied, floors: Object.fromEntries(Object.entries(floors).map(([k, v]) => [k, v.floor])) })}\n`);
  return ctl.pass && everyLimitApplied ? 0 : 1;
}

export function summaryMarkdown(r) {
  const cell = (b) => (b.ok ? 'ok' : `**fail** (${b.timedOut ? 'timeout' : b.signal ?? `exit ${b.exitCode}`})`);
  const lines = [
    '### Node and the engine under the custodian sandbox limits (`RLIMIT_AS`)',
    '',
    `Host: ${r.host.kernel}, ${r.host.bwrap}, Node ${r.host.node.version}. Replica of private-custodian@${r.replicaOf.commit.slice(0, 8)}; synthetic data only.`,
    `Controls (limits applied, no capabilities, no egress, no host files, scrubbed environment, writable scratch): **${r.controls.pass ? 'pass' : 'FAIL'}**.`,
    '',
    '| address space | limit applied | node starts | node --jitless | engine --version | engine quickstart run | same, node started with --jitless |',
    '| --- | --- | --- | --- | --- | --- | --- |',
    ...r.matrix.map((m) => `| ${m.memMiB} MiB | ${m.limitApplied ? 'yes' : '**NO**'} | ${cell(m.nodeStart)} | ${cell(m.nodeJitless)} | ${cell(m.engineVersion)} | ${cell(m.engineQuickstartRun)} | ${m.engineQuickstartRunNodeJitless ? cell(m.engineQuickstartRunNodeJitless) : 'n/a'} |`),
    '',
    `Floors (smallest size from which every larger size passes): node ${r.floors.nodeStartMiB.floor} MiB, node --jitless ${r.floors.nodeJitlessMiB.floor} MiB, engine quickstart run ${r.floors.engineQuickstartRunMiB.floor} MiB, engine quickstart run with node --jitless ${r.floors.engineQuickstartRunNodeJitlessMiB ? r.floors.engineQuickstartRunNodeJitlessMiB.floor : 'n/a'} MiB.`,
    `The custodian's own "normal" test limit is ${r.custodianNormalMemory.memMiB} MiB: node starts = ${r.custodianNormalMemory.nodeStarts}, engine quickstart runs = ${r.custodianNormalMemory.engineQuickstartRuns}.`,
    '',
  ];
  return `${lines.join('\n')}\n`;
}

if (isMain(import.meta.url)) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e) => {
      process.stderr.write(`isolation-matrix: ${sanitize(e.message, 200)}\n`);
      process.exit(2);
    },
  );
}
