#!/usr/bin/env node
// Performance suite orchestrator (P10, issue #11, ADR 0013). Documented in docs/performance.md.
//
//   node tools/perf/run.mjs plan <suite.json> --scratch <dir>          validate every workload, print sizes (no measurement)
//   node tools/perf/run.mjs run  <suite.json> --scratch <dir> --out <result.json> [--trials N] [--only <cell-id-prefix>]
//        [--resume] [--oracle-root <dir>] [--cli-bin <pii-eval>] [--cli-bin-before <pii-eval of the build to compare against>] [--perf-bin <perf example>] [--real-package <dir> --real-root <dir>]
//   node tools/perf/run.mjs host                                       print the host and toolchain metadata
//
// What it does for each cell of the suite (a cell is one workload; its parameters are the whole data):
//   1. generates the workload with make-workload.mjs and checks its digest against the suite's record;
//   2. produces the oracle observations (oracle-bench.mjs --phase export-only) that the Rust side reads;
//   3. runs every measure N times (after W discarded warm-up trials), ONE FRESH PROCESS PER TRIAL under
//      `/usr/bin/time`, interleaving the measures trial by trial so that slow drift of the machine hits them alike;
//      before each trial it waits (bounded) for the CPU to be idle and records the reading, flagging trials that
//      never got a quiet machine;
//   4. subtracts the matching `prepare` baseline process (load + generation + frozen-observation preparation, no
//      measured work) from wall, CPU and peak RSS, so the reported cost is the measured work.
// A measure whose predicted time (extrapolated from the smaller cells) exceeds --max-measure-seconds is SKIPPED and
// the skip is recorded; nothing runs unbounded. Results are written as JSON with the host metadata; no wall-time
// assertion is made anywhere (the CI guard counts work, it does not time it).
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { hostMetadata, median, readHead, runTimed, sha256, summarize, waitForQuiet } from './lib.mjs';
import { render } from './make-workload.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..', '..');
const NODE = process.execPath;
const REGISTER = join(ROOT, 'tools', 'oracle-parity', 'register.mjs');
let PERF_BIN = join(ROOT, 'target', 'release', 'examples', 'perf');
let CLI_BIN = join(ROOT, 'target', 'release', 'pii-eval');
let CLI_BIN_BEFORE = null; // measures with `"bin": "before"` run this binary (an A/B comparison of two builds)
const binOf = (m) => (m.bin === 'before' ? CLI_BIN_BEFORE : CLI_BIN);
const FAKE_CORE = join(ROOT, 'crates', 'pii-eval-adapters', 'tests', 'fixtures', 'fake-core');
export const RESULT_SCHEMA = 'pii-eval-perf-result/1';
export const SUITE_SCHEMA = 'pii-eval-perf-suite/1';

const args = process.argv.slice(2);
const command = args.shift();
const take = (name, dflt = null) => { const i = args.indexOf(name); if (i < 0) return dflt; const v = args[i + 1]; args.splice(i, 2); return v; };

function loadSuite(path) {
  const suite = JSON.parse(readFileSync(path, 'utf8'));
  if (suite.schema !== SUITE_SCHEMA || !/^[a-z0-9-]{1,40}$/.test(suite.id) || !Array.isArray(suite.cells)) throw new Error('not a perf suite');
  for (const k of ['trials', 'warmupTrials', 'innerRepeat']) if (!Number.isInteger(suite[k]) || suite[k] < 0 || suite[k] > 50) throw new Error(`suite.${k} out of range`);
  return suite;
}

const MEASURE_DEFAULTS = {
  oracle: { baseline: 'oracle-prepare' },
  'oracle-real': { baseline: 'oracle-prepare' },
  'rust-generate': { baseline: 'rust-prepare' },
  'rust-replay': { baseline: 'rust-prepare' },
  'rust-compat': { baseline: 'rust-prepare' },
  'rust-engine': { baseline: 'rust-prepare', workers: 4, perScanner: 2, batch: 2, replays: 2 },
  'cli-run': { baseline: null, workers: 2, replays: 2, pin: 'candidate' },
  'cli-replay': { baseline: null, workers: 2, replays: 2, pin: 'candidate' },
  'scanner-rust': { baseline: null, pin: 'candidate', texts: 200, sessions: 3 },
  'scanner-node': { baseline: null, pin: 'candidate', texts: 200 },
  'rust-parse': { baseline: 'rust-parse-base', doc: 'artifact', stage: 'full' },
  'rust-parse-base': { baseline: null, doc: 'manifest', stage: 'full' },
  'oracle-prepare': { baseline: null },
  'rust-prepare': { baseline: null },
};
const norm = (m) => { const o = typeof m === 'string' ? { name: m } : m; if (!(o.name in MEASURE_DEFAULTS)) throw new Error(`unknown measure ${o.name}`); return { ...MEASURE_DEFAULTS[o.name], ...o }; };
const label = (m) => (m.bin ? `${labelOf(m)}-${m.bin}` : labelOf(m));
const labelOf = (m) => (m.name === 'rust-engine' ? `rust-engine-w${m.workers}-p${m.perScanner}-b${m.batch}-r${m.replays}` : m.name === 'rust-parse' ? `rust-parse-${m.doc}-${m.stage}` : m.name === 'cli-run' || m.name === 'cli-replay' ? `${m.name}-${m.pin}-w${m.workers}-r${m.replays}` : m.name === 'oracle' && m.replays ? `oracle-r${m.replays}` : m.name);

function packageFor(pin, realPackage) {
  if (pin === 'candidate') return { dir: FAKE_CORE, entry: 'lib/index.js' };
  if (!realPackage) throw new Error('the released pin needs --real-package (PII_EVAL_REAL_PACKAGE): the hermetic install of tools/oracle-parity/real-scanner');
  return { dir: realPackage, entry: 'dist/index.js' };
}

/** Generate and VALIDATE one cell's workload. Returns paths and the recorded identity. */
function prepareWorkload(cell, scratch, { needObservations }) {
  const dir = join(scratch, 'workloads');
  mkdirSync(dir, { recursive: true });
  const { text, digest } = render(cell.workload);
  if (cell.digest && cell.digest !== digest) throw new Error(`cell ${cell.id}: workload digest ${digest} differs from the suite's record ${cell.digest}`);
  const workloadPath = join(dir, `${cell.id}.json`);
  writeFileSync(workloadPath, text);
  const input = JSON.parse(text);
  const out = { workloadPath, digest, bytes: Buffer.byteLength(text), cases: input.cases.length, scanners: input.scanners.length, obsPath: null };
  if (needObservations) {
    out.obsPath = join(dir, `${cell.id}.obs.json`);
    if (!existsSync(out.obsPath)) {
      const r = spawnSync(NODE, ['--experimental-strip-types', '--no-warnings', '--import', REGISTER, join(HERE, 'oracle-bench.mjs'), ctx.oracleRoot, workloadPath, '--phase', 'export-only', '--export', out.obsPath],
        { encoding: 'utf8', maxBuffer: 1 << 28, timeout: 1_800_000 });
      if (r.status !== 0) throw new Error(`cell ${cell.id}: oracle export failed: ${(r.stderr || '').slice(0, 400)}`);
      out.exportInfo = JSON.parse(r.stdout.trim().split('\n').pop()).counts;
    }
    const exp = JSON.parse(readFileSync(out.obsPath, 'utf8'));
    if (exp.workloadSha256 !== digest) throw new Error(`cell ${cell.id}: observations were produced for another workload`);
  }
  return out;
}

let ctx = {};

function buildArgv(m, c, suite) {
  const inner = String(suite.innerRepeat);
  const rust = (mode, extra = []) => [PERF_BIN, mode, '--workload', c.workloadPath, '--observations', c.obsPath, ...extra];
  const oracle = (extra = []) => [NODE, '--experimental-strip-types', '--no-warnings', '--import', REGISTER, join(HERE, 'oracle-bench.mjs'), ctx.oracleRoot, c.workloadPath, ...extra];
  switch (m.name) {
    case 'oracle': return oracle(['--repeat', inner, ...(m.replays ? ['--replays', String(m.replays)] : [])]);
    case 'oracle-real': return oracle(['--repeat', inner, '--real-root', ctx.realRoot]);
    case 'oracle-prepare': return oracle(['--phase', 'prepare']);
    case 'rust-prepare': return rust('prepare');
    case 'rust-generate': return rust('generate', ['--repeat', inner]);
    case 'rust-replay': return rust('replay', ['--repeat', inner]);
    case 'rust-compat': return rust('compat', ['--repeat', inner]);
    case 'rust-engine': return rust('engine', ['--repeat', inner, '--workers', String(m.workers), '--per-scanner', String(m.perScanner), '--batch', String(m.batch), '--replays', String(m.replays)]);
    case 'rust-parse': case 'rust-parse-base': {
      const file = { snapshot: ['snapshot.json'], artifact: ['run', 'run-artifact.json'], manifest: ['run', 'manifest.json'], public: ['run', 'public-synthetic-artifact.json'],
        observation: ['run', 'observation-perf-scanner-00.json'] }[m.doc];
      return [PERF_BIN, 'parse', '--doc', join(c.emitDir, ...file), '--kind', m.doc === 'public' ? 'artifact' : m.doc, '--stage', m.stage, '--repeat', '1'];
    }
    case 'scanner-rust': { const p = packageFor(m.pin, ctx.realPackage); return [PERF_BIN, 'scanner', '--package', p.dir, '--pin', m.pin, '--texts', String(m.texts), '--sessions', String(m.sessions)]; }
    case 'scanner-node': { const p = packageFor(m.pin, ctx.realPackage); return [NODE, join(HERE, 'scanner-bench.mjs'), p.dir, p.entry, '--texts', String(m.texts)]; }
    default: throw new Error(`no argv for ${m.name}`);
  }
}

/** Per-phase summary of the tool's own JSON: cold = first in-process repetition, warm = median of the others. */
function innerPhases(json) {
  if (!json) return null;
  const out = {};
  const rest = (arr) => (arr.length > 1 ? { warm: median(arr.slice(1)), warmMin: Math.min(...arr.slice(1)) } : { warm: null, warmMin: null });
  if (json.phasesMs) {
    for (const [k, arr] of Object.entries(json.phasesMs)) out[k] = { cold: arr[0], ...rest(arr) };
  } else if (Array.isArray(json.trials) && json.trials.length) {
    for (const k of Object.keys(json.trials[0])) { const arr = json.trials.map((t) => t[k]); out[k] = { cold: arr[0], ...rest(arr) }; }
  } else if (json.mode === 'scanner' || json.mode === 'scanner-node') {
    for (const k of ['startupMs', 'scanAllMs', 'finishMs']) if (Array.isArray(json[k])) out[k] = { cold: json[k][0], ...rest(json[k]) };
    for (const k of ['planMs', 'importMs', 'initializeMs', 'scanAllMs']) if (typeof json[k] === 'number') out[k] = { cold: json[k], warm: null };
    if (json.perScanMs) out.perScanMedianMs = { cold: json.perScanMs.median, warm: null };
  }
  return out;
}

function trialRecord(r, quiet, parsed) {
  const u = r.usage;
  return {
    ok: r.status === 0 && !!u, status: r.status, timedOut: r.timedOut,
    wallMs: u ? u.wallS * 1000 : null, userMs: u ? u.userS * 1000 : null, sysMs: u ? u.sysS * 1000 : null,
    maxRssBytes: u?.maxRssBytes ?? null, peakFootprintBytes: u?.peakFootprintBytes ?? null, instructions: u?.instructions ?? null, cycles: u?.cycles ?? null,
    idlePercent: quiet.idle, loadavg1: quiet.loadavg1, noisy: quiet.noisy, waitedForQuietMs: quiet.waitedMs,
    inner: parsed,
  };
}

function lastJson(stdout) {
  const line = stdout.trim().split('\n').pop();
  try { return JSON.parse(line); } catch { return null; }
}

function summarizeTrials(trials) {
  const ok = trials.filter((t) => t.ok);
  const s = (k) => summarize(ok.map((t) => t[k]));
  const phaseNames = new Set(ok.flatMap((t) => Object.keys(t.phases ?? {})));
  const phases = {};
  for (const k of phaseNames) {
    phases[k] = { cold: summarize(ok.map((t) => t.phases?.[k]?.cold)), warm: summarize(ok.map((t) => t.phases?.[k]?.warm)), warmMin: summarize(ok.map((t) => t.phases?.[k]?.warmMin)) };
  }
  return { trials: trials.length, ok: ok.length, noisyTrials: trials.filter((t) => t.noisy).length,
    wallMs: s('wallMs'), userMs: s('userMs'), sysMs: s('sysMs'), cpuMs: summarize(ok.map((t) => t.userMs + t.sysMs)),
    maxRssBytes: s('maxRssBytes'), peakFootprintBytes: s('peakFootprintBytes'), instructions: s('instructions'), phases };
}

/** Median-based difference of the measure over its baseline (the measured work, load and generation removed). */
function netOf(sum, base) {
  if (!base || !sum.wallMs.n || !base.wallMs.n) return null;
  const d = (k, f) => (sum[k].n && base[k].n ? sum[k][f] - base[k][f] : null);
  const both = (k) => ({ median: d(k, 'median'), min: d(k, 'min') });
  return { wallMs: both('wallMs'), cpuMs: both('cpuMs'), instructions: both('instructions'), maxRssBytes: both('maxRssBytes'), peakFootprintBytes: both('peakFootprintBytes') };
}

async function runCell(cell, suite, opts, history) {
  const measures = [...new Set(cell.measures.map(norm).flatMap((m) => [m, ...(m.baseline ? [norm(m.baseline)] : [])].map((x) => JSON.stringify(x))))].map((s) => JSON.parse(s));
  const needObs = measures.some((m) => /^(rust|oracle-prepare)/.test(m.name) || m.name === 'oracle' || m.name === 'oracle-real') || cell.measures.some((m) => (typeof m === 'string' ? m : m.name).startsWith('cli-'));
  const c = prepareWorkload(cell, opts.scratch, { needObservations: needObs });
  if (measures.some((m) => m.name.startsWith('rust-parse'))) {
    // Documents for the parse measures: one in-process run's snapshot, manifest, observation sets and artifacts (untimed).
    c.emitDir = join(opts.scratch, 'emit', cell.id);
    rmSync(c.emitDir, { recursive: true, force: true });
    const r = spawnSync(PERF_BIN, ['emit', '--workload', c.workloadPath, '--observations', c.obsPath, '--dir', c.emitDir, '--workers', '4'], { encoding: 'utf8', maxBuffer: 1 << 26 });
    if (r.status !== 0) throw new Error(`cell ${cell.id}: emit failed: ${r.stderr.slice(0, 300)}`);
  }
  // cli-run: documents prepared once per variant of the measure (not timed).
  for (const m of measures.filter((x) => x.name === 'cli-run' || x.name === 'cli-replay')) {
    const p = packageFor(m.pin, ctx.realPackage);
    m.dir = join(opts.scratch, 'cli', `${cell.id}-${label(m)}`);
    rmSync(m.dir, { recursive: true, force: true });
    const r = spawnSync(PERF_BIN, ['emit-cli', '--workload', c.workloadPath, '--observations', c.obsPath, '--dir', m.dir, '--package', p.dir, '--pin', m.pin, '--workers', String(m.workers), '--replays', String(m.replays)], { encoding: 'utf8', maxBuffer: 1 << 26 });
    if (r.status !== 0) throw new Error(`cell ${cell.id}: emit-cli failed: ${r.stderr.slice(0, 300)}`);
    if (m.name === 'cli-replay') {
      // The original run (untimed) whose observations are replayed; the replay needs it for the sanitized-output verdicts.
      const o = spawnSync(binOf(m), ['run', '--config', join(m.dir, 'run-config.json'), '--node', NODE, '--out', join(m.dir, 'orig')], { encoding: 'utf8', maxBuffer: 1 << 26 });
      if (o.status !== 0) throw new Error(`cell ${cell.id}: the original run failed: ${o.stdout.slice(0, 300)}`);
    }
  }
  const result = { id: cell.id, axis: cell.axis, trials: cell.trials ?? opts.trials, warmupTrials: cell.warmupTrials ?? suite.warmupTrials, workload: { params: cell.workload, digest: c.digest, bytes: c.bytes, cases: c.cases, scanners: c.scanners }, measures: {} };
  const records = new Map(); // label -> trials
  const skipped = new Map();
  for (const m of measures) {
    const prev = history.get(label(m));
    const size = c.bytes;
    if (prev && prev.length >= 1) {
      const last = prev[prev.length - 1];
      const exponent = prev.length >= 2 ? Math.min(2.5, Math.max(1, Math.log(last.perTrialS / prev[prev.length - 2].perTrialS) / Math.log(last.size / prev[prev.length - 2].size))) : 1.5;
      const predicted = last.perTrialS * (size / last.size) ** exponent;
      const total = predicted * ((cell.trials ?? opts.trials) + (cell.warmupTrials ?? suite.warmupTrials));
      if (predicted > opts.maxMeasureSeconds || total > opts.maxMeasureSeconds * 4) { skipped.set(label(m), { predictedPerTrialS: predicted, exponent, reason: 'predicted time exceeds the bound' }); continue; }
    }
    records.set(label(m), []);
  }
  const nTrials = cell.trials ?? opts.trials;
  const warmup = cell.warmupTrials ?? suite.warmupTrials;
  for (let t = 0; t < warmup + nTrials; t++) {
    for (const m of measures) {
      const key = label(m);
      if (!records.has(key)) continue;
      const quiet = await waitForQuiet({ minIdle: opts.minIdle, maxWaitMs: opts.maxQuietWaitMs });
      let argv = buildArgv_(m, c, suite, t);
      const r = runTimed(argv, { timeoutMs: opts.trialTimeoutMs });
      let parsed = lastJson(r.stdout);
      if (m.name === 'cli-replay') rmSync(join(m.dir, `out-${t}`), { recursive: true, force: true });
      if (m.name === 'cli-run') {
        const art = join(m.dir, `out-${t}`, 'run-artifact.json');
        parsed = null;
        if (existsSync(art)) {
          const d = JSON.parse(readFileSync(art, 'utf8')).diagnostics;
          parsed = { mode: 'cli-run', phasesMs: Object.fromEntries(d.phases.map((p) => [p.phase, [p.durationMs]])) };
        }
        rmSync(join(m.dir, `out-${t}`), { recursive: true, force: true });
      }
      const rec = trialRecord(r, quiet, parsed);
      rec.phases = innerPhases(parsed);
      if (t >= warmup) records.get(key).push(rec);
      else rec.warmup = true;
      if (!rec.ok && t >= warmup) console.error(`trial failed: ${cell.id} ${key}: status ${r.status} ${r.stderr.slice(0, 200)}`);
    }
  }
  for (const m of measures) {
    const key = label(m);
    if (!records.has(key)) { result.measures[key] = { skipped: skipped.get(key) }; continue; }
    const trials = records.get(key);
    const summary = summarizeTrials(trials);
    const first = trials.find((x) => x.inner)?.inner ?? null;
    const base = m.baseline ? summarizeTrials(records.get(label(norm(m.baseline))) ?? []) : null;
    result.measures[key] = {
      params: Object.fromEntries(Object.entries(m).filter(([k]) => !['baseline', 'dir'].includes(k))),
      summary, netOfBaseline: base ? { baseline: label(norm(m.baseline)), ...netOf(summary, base) } : null,
      // identities and exact counts reported by the tool (digests, counts, row counts), from the last trial
      reported: first ? Object.fromEntries(Object.entries(first).filter(([k]) => !['phasesMs', 'trials', 'perScanMs', 'startupMs', 'scanAllMs', 'finishMs', 'equalToOracleCounts'].includes(k))) : null,
      trials: trials.map((x) => ({ wallMs: x.wallMs, cpuMs: x.userMs + x.sysMs, maxRssBytes: x.maxRssBytes, idlePercent: x.idlePercent, noisy: x.noisy, ok: x.ok })),
    };
    if (summary.ok) {
      const h = history.get(key) ?? [];
      h.push({ size: c.bytes, perTrialS: summary.wallMs.median / 1000 });
      history.set(key, h);
    }
  }
  return result;
}

function buildArgv_(m, c, suite, t) {
  if (m.name === 'cli-run') return [binOf(m), 'run', '--config', join(m.dir, 'run-config.json'), '--node', NODE, '--out', join(m.dir, `out-${t}`)];
  if (m.name === 'cli-replay') {
    return [binOf(m), 'replay', '--snapshot', join(m.dir, 'snapshot.json'), '--manifest', join(m.dir, 'orig', 'manifest.json'), '--observation', join(m.dir, 'orig', 'observation-redact-secret-core.json'),
      '--original', join(m.dir, 'orig', 'run-artifact.json'), '--out', join(m.dir, `out-${t}`)];
  }
  return buildArgv(m, c, suite);
}

/**
 * Untimed fidelity check (`verify <suite> ... --out <existing result.json>`): for every cell of the result that has a
 * `rust-compat` measure, generate the workload, have the oracle evaluate it once (--phase export-only --with-counts, cells of
 * at most `--max-verify-cases` cases) and require the Rust oracle-faithful path to reproduce the oracle's metric counts
 * exactly. The outcome is written into the cell as `verification`; it proves the two sides were doing the same work.
 */
function verify(suite, cells, opts) {
  const out = opts.out;
  if (!out || !existsSync(out)) throw new Error('verify needs --out <existing result.json>');
  const result = JSON.parse(readFileSync(out, 'utf8'));
  for (const cell of cells) {
    const target = result.cells.find((c) => c.id === cell.id);
    if (!target || !cell.measures.some((m) => (typeof m === 'string' ? m : m.name) === 'rust-compat')) continue;
    if (cell.workload.cases > opts.maxVerifyCases) { target.verification = { equalToOracleCounts: null, reason: `not run: more than ${opts.maxVerifyCases} cases` }; continue; }
    const { text, digest } = render(cell.workload);
    const dir = join(opts.scratch, 'verify');
    mkdirSync(dir, { recursive: true });
    const w = join(dir, `${cell.id}.json`);
    const o = join(dir, `${cell.id}.counts.obs.json`);
    writeFileSync(w, text);
    const e = spawnSync(NODE, ['--experimental-strip-types', '--no-warnings', '--import', REGISTER, join(HERE, 'oracle-bench.mjs'), ctx.oracleRoot, w, '--phase', 'export-only', '--with-counts', '--export', o], { encoding: 'utf8', maxBuffer: 1 << 28 });
    if (e.status !== 0) throw new Error(`verify ${cell.id}: oracle failed: ${e.stderr.slice(0, 300)}`);
    const r = spawnSync(PERF_BIN, ['compat', '--workload', w, '--observations', o, '--repeat', '1'], { encoding: 'utf8', maxBuffer: 1 << 28 });
    if (r.status !== 0) throw new Error(`verify ${cell.id}: perf compat failed: ${r.stderr.slice(0, 300)}`);
    const j = lastJson(r.stdout);
    target.verification = { equalToOracleCounts: j.equalToOracleCounts, workloadDigest: digest, method: 'oracle evaluated once on this workload; Rust legacy rule + oracle accounting port compared on all ten metrics x seven count fields + effective N, per scanner' };
    rmSync(o, { force: true });
    console.error(`verify ${cell.id}: ${j.equalToOracleCounts}`);
  }
  writeFileSync(out, `${JSON.stringify(result, null, 1)}\n`);
}

async function main() {
  if (command === 'host') { console.log(JSON.stringify(hostMetadata(ROOT), null, 1)); return; }
  const suitePath = args.shift();
  if (!suitePath) throw new Error('usage: run.mjs plan|run <suite.json> --scratch <dir> [--out <result.json>]');
  const suite = loadSuite(suitePath);
  const scratchArg = take('--scratch');
  if (!scratchArg) throw new Error('--scratch <dir> is required');
  const scratch = resolve(scratchArg);
  mkdirSync(scratch, { recursive: true });
  ctx = {
    oracleRoot: resolve(take('--oracle-root') ?? join(scratch, 'oracle')),
    realPackage: take('--real-package') ?? process.env.PII_EVAL_REAL_PACKAGE ?? null,
    realRoot: take('--real-root') ?? process.env.PII_EVAL_REAL_ROOT ?? null,
  };
  const opts = {
    scratch, trials: Number(take('--trials') ?? suite.trials), only: take('--only'), cliBin: take('--cli-bin'), cliBinBefore: take('--cli-bin-before'), perfBin: take('--perf-bin'),
    maxMeasureSeconds: Number(take('--max-measure-seconds') ?? 300), minIdle: Number(take('--min-idle') ?? 50),
    out: take('--out'), maxVerifyCases: Number(take('--max-verify-cases') ?? 6400),
    maxQuietWaitMs: Number(take('--max-quiet-wait-seconds') ?? 15) * 1000, trialTimeoutMs: Number(take('--trial-timeout-seconds') ?? 900) * 1000,
  };
  // Copies of the release binaries can be measured (a suite must not race a rebuild; before/after an optimization).
  if (opts.cliBin) CLI_BIN = resolve(opts.cliBin);
  if (opts.cliBinBefore) CLI_BIN_BEFORE = resolve(opts.cliBinBefore);
  if (opts.perfBin) PERF_BIN = resolve(opts.perfBin);
  const cells = suite.cells.filter((c) => !opts.only || c.id.startsWith(opts.only));
  if (command === 'plan') {
    // Validation only: every workload is generated and its digest compared with the suite's record. Nothing is measured.
    for (const cell of cells) {
      const { text, digest } = render(cell.workload);
      const input = JSON.parse(text);
      console.log(JSON.stringify({ id: cell.id, axis: cell.axis, digest, recorded: cell.digest ?? null, match: !cell.digest || cell.digest === digest, bytes: Buffer.byteLength(text), cases: input.cases.length, sha256: sha256(text).slice(0, 12) }));
      if (cell.digest && cell.digest !== digest) process.exitCode = 1;
    }
    return;
  }
  if (command === 'verify') return verify(suite, cells, opts);
  if (command !== 'run') throw new Error(`unknown command ${command}`);
  const out = opts.out;
  if (!out) throw new Error('--out <result.json> is required');
  for (const bin of [PERF_BIN, CLI_BIN]) if (!existsSync(bin)) throw new Error(`missing ${bin}: cargo build --release --locked --example perf -p pii-eval-cli && cargo build --release --locked -p pii-eval-cli`);
  if (!existsSync(join(ctx.oracleRoot, 'package.json'))) throw new Error(`no oracle at ${ctx.oracleRoot}: node tools/oracle-parity/fetch-oracle.mjs <scratch>`);
  const host = hostMetadata(ROOT);
  const result = {
    schema: RESULT_SCHEMA, suite: suite.id, suiteSha256: sha256(readFileSync(suitePath)), startedAt: new Date().toISOString(),
    repository: { head: readHead(ROOT), note: 'HEAD of the checkout the suite ran in; the working tree may contain uncommitted P10 changes' },
    host, binaries: { perfSha256: sha256(readFileSync(PERF_BIN)), cliSha256: sha256(readFileSync(CLI_BIN)), ...(CLI_BIN_BEFORE ? { cliBeforeSha256: sha256(readFileSync(CLI_BIN_BEFORE)) } : {}) },
    oracle: JSON.parse(readFileSync(join(ROOT, 'tools', 'oracle-parity', 'oracle-files.json'), 'utf8')).pin,
    protocol: { trials: opts.trials, warmupTrials: suite.warmupTrials, innerRepeat: suite.innerRepeat, minIdlePercent: opts.minIdle, maxMeasureSeconds: opts.maxMeasureSeconds,
      statistic: 'median over trials; uncertainty is the median absolute deviation (unscaled); min and max kept', interleaved: true },
    cells: [],
  };
  const history = new Map();
  // --resume continues an interrupted run: cells already in --out are kept and skipped (same suite, same host assumed).
  const resumed = args.includes('--resume') ? (args.splice(args.indexOf('--resume'), 1), existsSync(out) ? JSON.parse(readFileSync(out, 'utf8')) : null) : null;
  if (resumed && resumed.suite === suite.id) { result.cells.push(...resumed.cells); if (resumed.rerun) result.rerun = resumed.rerun; result.startedAt = resumed.startedAt; result.resumedAt = [...(resumed.resumedAt ?? []), new Date().toISOString()]; }
  for (const cell of cells) {
    if (result.cells.some((c) => c.id === cell.id)) continue;
    console.error(`cell ${cell.id} (${cell.axis})`);
    result.cells.push(await runCell(cell, suite, opts, history));
    writeFileSync(out, `${JSON.stringify(result, null, 1)}\n`);
  }
  result.finishedAt = new Date().toISOString();
  result.hostAtEnd = { loadavg: os.loadavg() };
  writeFileSync(out, `${JSON.stringify(result, null, 1)}\n`);
  console.error(`wrote ${out}`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => { console.error(`error: ${e.message}`); process.exit(1); });
}
