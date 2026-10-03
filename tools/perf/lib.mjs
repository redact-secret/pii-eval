// Pure helpers and host probes of the performance orchestrator (P10, ADR 0013). Plain Node >= 22, no packages.
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import os from 'node:os';
import { join } from 'node:path';

export const sha256 = (data) => createHash('sha256').update(data).digest('hex');

/** Median of a non-empty list of numbers (mean of the two middle values for an even count). */
export function median(values) {
  if (values.length === 0) return null;
  const v = [...values].sort((a, b) => a - b);
  const m = v.length >> 1;
  return v.length % 2 ? v[m] : (v[m - 1] + v[m]) / 2;
}

/** n, median, MAD (median absolute deviation, unscaled), min and max. The MAD is the uncertainty reported. */
export function summarize(values) {
  const v = values.filter((x) => typeof x === 'number' && Number.isFinite(x));
  if (v.length === 0) return { n: 0 };
  const med = median(v);
  return { n: v.length, median: med, mad: median(v.map((x) => Math.abs(x - med))), min: Math.min(...v), max: Math.max(...v) };
}

/**
 * Parse the resource report of `/usr/bin/time -l` (macOS, bytes) or `/usr/bin/time -v` (GNU, KiB) from stderr.
 * Returns null when neither format is recognised. All values are numbers; memory is in bytes.
 */
export function parseTimeOutput(text) {
  const num = (re) => { const m = re.exec(text); return m ? Number(m[1]) : null; };
  const mac = /^\s*([\d.]+)\s+real\s+([\d.]+)\s+user\s+([\d.]+)\s+sys\s*$/m.exec(text);
  if (mac) {
    return {
      format: 'bsd-l', wallS: Number(mac[1]), userS: Number(mac[2]), sysS: Number(mac[3]),
      maxRssBytes: num(/^\s*(\d+)\s+maximum resident set size/m),
      peakFootprintBytes: num(/^\s*(\d+)\s+peak memory footprint/m),
      instructions: num(/^\s*(\d+)\s+instructions retired/m),
      cycles: num(/^\s*(\d+)\s+cycles elapsed/m),
      pageReclaims: num(/^\s*(\d+)\s+page reclaims/m),
      involuntaryContextSwitches: num(/^\s*(\d+)\s+involuntary context switches/m),
    };
  }
  const user = num(/User time \(seconds\):\s*([\d.]+)/);
  const wall = /Elapsed \(wall clock\) time \(h:mm:ss or m:ss\):\s*(?:(\d+):)?(\d+):([\d.]+)/.exec(text);
  if (user !== null && wall) {
    return {
      format: 'gnu-v', wallS: Number(wall[1] ?? 0) * 3600 + Number(wall[2]) * 60 + Number(wall[3]), userS: user,
      sysS: num(/System time \(seconds\):\s*([\d.]+)/),
      maxRssBytes: (num(/Maximum resident set size \(kbytes\):\s*(\d+)/) ?? 0) * 1024, peakFootprintBytes: null,
      instructions: null, cycles: null, pageReclaims: num(/Minor \(reclaiming a frame\) page faults:\s*(\d+)/),
      involuntaryContextSwitches: num(/Involuntary context switches:\s*(\d+)/),
    };
  }
  return null;
}

/** The argv that wraps `argv` in the platform's resource-reporting `time`. */
export function timedArgv(argv, platform = process.platform) {
  return platform === 'darwin' ? ['/usr/bin/time', '-l', ...argv] : ['/usr/bin/time', '-v', ...argv];
}

/**
 * Run `argv` under `time`, bounded by `timeoutMs` and `maxBuffer`. Returns the child's stdout, its exit status and the
 * parsed resource report. The `time` report is at the END of stderr; anything the child wrote to stderr precedes it.
 */
export function runTimed(argv, { timeoutMs = 900_000, cwd, env, maxBuffer = 1 << 28 } = {}) {
  const [cmd, ...rest] = timedArgv(argv);
  const r = spawnSync(cmd, rest, { cwd, env, encoding: 'utf8', timeout: timeoutMs, maxBuffer });
  const usage = parseTimeOutput(r.stderr ?? '');
  return { status: r.status, signal: r.signal, stdout: r.stdout ?? '', stderr: r.stderr ?? '', usage, timedOut: r.error?.code === 'ETIMEDOUT' };
}

const sh = (cmd, args) => { try { return execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch { return null; } };

const ticks = () => os.cpus().reduce((t, c) => ({ idle: t.idle + c.times.idle, all: t.all + c.times.user + c.times.nice + c.times.sys + c.times.idle + c.times.irq }), { idle: 0, all: 0 });

/** CPU idle percentage over `windowMs` (all logical CPUs, from the kernel's cumulative tick counters), or null when no tick advanced. */
export async function idlePercent(windowMs = 500) {
  const a = ticks();
  await new Promise((r) => setTimeout(r, windowMs));
  const b = ticks();
  const all = b.all - a.all;
  return all > 0 ? (100 * (b.idle - a.idle)) / all : null;
}

/** Wait (bounded) until the machine is idle enough. Returns the last reading and whether the bound was hit. */
export async function waitForQuiet({ minIdle, maxWaitMs, pollMs = 3000 }) {
  const start = Date.now();
  let idle = await idlePercent();
  let waited = 0;
  while (idle !== null && idle < minIdle && Date.now() - start < maxWaitMs) {
    await new Promise((r) => setTimeout(r, pollMs));
    waited = Date.now() - start;
    idle = await idlePercent();
  }
  return { idle, waitedMs: waited, noisy: idle !== null && idle < minIdle, loadavg1: os.loadavg()[0] };
}

/** Best-effort read of the checked-out commit without running a VCS tool (worktree or plain checkout). */
export function readHead(root) {
  try {
    let gitDir = join(root, '.git');
    try { const dot = readFileSync(gitDir, 'utf8'); if (dot.startsWith('gitdir:')) gitDir = dot.slice(7).trim(); } catch { /* a directory */ }
    const head = readFileSync(join(gitDir, 'HEAD'), 'utf8').trim();
    if (!head.startsWith('ref:')) return head;
    const ref = head.slice(4).trim();
    let common = gitDir;
    try { common = join(gitDir, readFileSync(join(gitDir, 'commondir'), 'utf8').trim()); } catch { /* no commondir */ }
    for (const base of [gitDir, common]) {
      if (existsSync(join(base, ref))) return readFileSync(join(base, ref), 'utf8').trim();
    }
    const packed = readFileSync(join(common, 'packed-refs'), 'utf8').split('\n').find((l) => l.endsWith(` ${ref}`));
    return packed ? packed.split(' ')[0] : null;
  } catch { return null; }
}

export function hostMetadata(root) {
  const mac = process.platform === 'darwin';
  const sysctl = (k) => (mac ? sh('sysctl', ['-n', k]) : null);
  const cpus = os.cpus();
  return {
    os: { platform: process.platform, release: os.release(), version: mac ? sh('sw_vers', ['-productVersion']) : os.version(), arch: process.arch },
    cpu: { model: sysctl('machdep.cpu.brand_string') ?? cpus[0]?.model ?? null, logicalCpus: os.availableParallelism(),
      physicalCpus: Number(sysctl('hw.physicalcpu')) || null,
      performanceCores: Number(sysctl('hw.perflevel0.logicalcpu')) || null, efficiencyCores: Number(sysctl('hw.perflevel1.logicalcpu')) || null },
    memoryBytes: os.totalmem(),
    power: mac ? (sh('pmset', ['-g', 'batt']) ?? '').split('\n')[0] : null,
    loadavgAtStart: os.loadavg(),
    node: { version: process.version, icu: process.versions.icu, v8: process.versions.v8 },
    rust: { rustc: sh('rustc', ['-Vv'])?.split('\n').filter((l) => /^(rustc|host|release|LLVM)/.test(l)) ?? null, cargo: sh('cargo', ['-V']) },
    toolchainFileSha256: existsSync(join(root, 'rust-toolchain.toml')) ? sha256(readFileSync(join(root, 'rust-toolchain.toml'))) : null,
    releaseProfile: 'workspace [profile.release]: overflow-checks = true; defaults otherwise (opt-level 3, no LTO, 16 codegen units, panic unwind)',
    rustflags: process.env.RUSTFLAGS ?? process.env.CARGO_ENCODED_RUSTFLAGS ?? null,
    time: { collector: mac ? '/usr/bin/time -l (BSD): real/user/sys, maximum resident set size, peak memory footprint' : '/usr/bin/time -v (GNU)' },
  };
}
