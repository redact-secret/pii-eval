#!/usr/bin/env node
// Turn result files (`run.mjs` output) into the Markdown tables of docs/performance.md, so the numbers in the
// document are generated from the committed raw artifacts and never typed by hand (P10, ADR 0013).
//
//   node tools/perf/report.mjs <result.json>...            tables on stdout
//   node tools/perf/report.mjs --compare <before.json> <after.json>   per-cell before/after of every measure both contain
//
// Conventions: `x ± y` is the median over trials ± the unscaled median absolute deviation; `min` is the smallest
// trial (contention only ever adds time, so the minimum is the best estimate of the intrinsic cost); phase values
// are the minimum over the warm in-process repetitions unless the column says `cold`. Memory is MiB, time ms.
import { readFileSync } from 'node:fs';

const MIB = 1024 * 1024;
const f = (x, d = 1) => (x === null || x === undefined || Number.isNaN(x) ? 'n/a' : Number(x).toFixed(d));
const pm = (s, d = 1, scale = 1) => (s && s.n ? `${f(s.median / scale, d)} ± ${f(s.mad / scale, d)}` : 'n/a');
const mn = (s, d = 1, scale = 1) => (s && s.n ? f(s.min / scale, d) : 'n/a');
const ph = (m, name, which = 'warmMin') => m?.summary?.phases?.[name]?.[which];
const pick = (m, name, which = 'warmMin') => { const s = ph(m, name, which); return s && s.n ? s.min : null; };
const net = (m, k, stat = 'min') => m?.netOfBaseline?.[k]?.[stat] ?? null;
const table = (head, rows) => [`| ${head.join(' | ')} |`, `| ${head.map(() => '---').join(' | ')} |`, ...rows.map((r) => `| ${r.join(' | ')} |`)].join('\n');
const ratio = (a, b) => (a && b ? f(a / b, 1) : 'n/a');
const load = (p) => JSON.parse(readFileSync(p, 'utf8'));

// Cells of one workload (same digest) are one row: a suite may measure the oracle in its own cell (one trial) when it is too slow to repeat.
function merged(cells) {
  const byDigest = new Map();
  for (const c of cells) {
    const k = c.workload.digest;
    const prev = byDigest.get(k);
    byDigest.set(k, prev ? { ...prev, trials: `${prev.trials}/${c.trials}`, measures: { ...prev.measures, ...c.measures } } : { ...c });
  }
  return [...byDigest.values()];
}

// Axes that vary only an executor setting: the in-process engine run (stand-in scanner) against its settings.
function engineAxisTable(axis, cells) {
  const rows = cells.map((c) => {
    const eng = Object.values(c.measures).find((m) => m.params?.name === 'rust-engine' && !m.skipped);
    const ora = Object.values(c.measures).find((m) => m.params?.name === 'oracle' && !m.skipped);
    if (!eng) return null;
    const counts = eng.reported?.counts;
    return [eng.params[axis === 'workers' ? 'workers' : axis === 'batch' ? 'batch' : 'replays'], counts?.variants, counts?.scanners, eng.params.perScanner, pm(eng.summary.phases.run.warmMin, 1), mn(eng.summary.phases.run.warmMin, 1),
      f(pick(eng, 'kernel'), 1), f(pick(eng, 'standInScannerSum'), 1), f(pick(eng, 'scanCalls'), 0), f(net(eng, 'maxRssBytes', 'median') / MIB, 1), f(net(eng, 'instructions', 'median') / 1e6, 0),
      ora ? f(pick(ora, 'executeMs') + pick(ora, 'accountMs'), 0) : 'n/a', c.trials];
  }).filter(Boolean);
  const label = axis === 'workers' ? 'workers (= per-scanner sessions)' : axis === 'batch' ? 'variants per batch' : 'replay passes';
  return `### Axis: ${axis}\n\n${table([label, 'variants', 'scanners', 'sessions per scanner', 'engine run ms (warm min over trials, ± MAD)', 'min', 'kernel ms', 'stand-in scanner ms (sum over workers)', 'scan calls', 'net peak RSS MiB', 'net Minstr', 'TS exec+account ms', 'trials'], rows)}`;
}

function axisTables(result) {
  const out = [];
  const axes = [...new Set(result.cells.map((c) => c.axis))];
  for (const axis of axes) {
    const cells = merged(result.cells.filter((c) => c.axis === axis));
    if (['workers', 'batch', 'replays'].includes(axis)) { out.push(engineAxisTable(axis, cells)); continue; }
    const rows = [];
    for (const c of cells) {
      const M = c.measures;
      const get = (k) => M[k] && !M[k].skipped ? M[k] : null;
      const ora = get('oracle') ?? Object.values(M).find((m) => m.params?.name === 'oracle' && !m.skipped);
      const rep = get('rust-replay');
      const cmp = get('rust-compat');
      const eng = Object.values(M).find((m) => m.params?.name === 'rust-engine' && !m.skipped);
      const gen = get('rust-generate');
      const counts = (rep ?? eng ?? cmp)?.reported?.counts;
      const v = counts?.variants ?? c.workload.cases;
      const tsKernel = ora ? pick(ora, 'executeMs') + pick(ora, 'accountMs') : null;
      const tsGen = ora ? pick(ora, 'generateMs') : null;
      const compat = cmp ? pick(cmp, 'interpret') + pick(cmp, 'account') : null;
      const kern = rep ? pick(rep, 'assembleKernel') : null;
      rows.push([
        `${axis === 'language' ? `ko ${c.workload.params.koShare}%` : axis === 'text' ? `${c.workload.params.padBytes} B` : axis === 'scanners' ? c.workload.params.scanners : axis === 'findings' ? c.workload.params.findings : axis === 'replays' ? (eng?.params?.replays ?? ora?.params?.replays ?? '') : axis === 'workers' ? (eng?.params?.workers ?? '') : axis === 'batch' ? (eng?.params?.batch ?? '') : c.workload.params.cases}`,
        v, counts?.findings ?? '', f(counts?.textBytes ? counts.textBytes / 1024 : null, 0),
        ora ? `${f(tsKernel, 0)}` : (M.oracle?.skipped ? 'skipped' : 'n/a'), ora ? f(tsGen, 0) : 'n/a', gen ? f(pick(gen, 'generate'), 1) : 'n/a',
        compat ? f(compat, 2) : 'n/a', kern ? f(kern, 2) : 'n/a', ora ? ratio(tsKernel, compat) : 'n/a', ora && eng ? ratio(tsKernel, pick(eng, 'run')) : 'n/a',
        rep ? f(pick(rep, 'assemble'), 1) : 'n/a', rep ? f(pick(rep, 'verify'), 1) : 'n/a', rep ? f(pick(rep, 'serialize'), 1) : 'n/a',
        rep ? f(pick(rep, 'parse'), 1) : 'n/a', eng ? f(pick(eng, 'run'), 1) : 'n/a', c.trials,
      ]);
    }
    out.push(`### Axis: ${axis}\n\n${table(['value', 'variants', 'findings', 'text KiB', 'TS exec+account', 'TS generate', 'Rust generate', 'Rust compat (oracle rule)', 'Rust kernel (assess+account)', 'TS / compat', 'TS / engine run', 'Rust assemble', 'verify', 'serialize', 'parse', 'engine run', 'trials'], rows)}`);
    const mem = [];
    for (const c of cells) {
      const M = c.measures;
      const ora = M.oracle && !M.oracle.skipped ? M.oracle : null;
      const rep = M['rust-replay'] && !M['rust-replay'].skipped ? M['rust-replay'] : null;
      const eng = Object.values(M).find((m) => m.params?.name === 'rust-engine' && !m.skipped);
      if (!ora && !rep && !eng) continue;
      mem.push([c.id, ora ? f(net(ora, 'maxRssBytes', 'median') / MIB, 1) : 'n/a', rep ? f(net(rep, 'maxRssBytes', 'median') / MIB, 1) : 'n/a', eng ? f(net(eng, 'maxRssBytes', 'median') / MIB, 1) : 'n/a',
        ora ? f(net(ora, 'instructions', 'median') / 1e6, 0) : 'n/a', rep ? f(net(rep, 'instructions', 'median') / 1e6, 0) : 'n/a']);
    }
    if (mem.length) out.push(`${table(['cell', 'TS net peak RSS MiB', 'Rust replay net peak RSS MiB', 'Rust engine net peak RSS MiB', 'TS net Minstr', 'Rust replay net Minstr'], mem)}`);
  }
  return out.join('\n\n');
}

function compare(a, b) {
  const rows = [];
  for (const ca of a.cells) {
    const cb = b.cells.find((c) => c.id === ca.id);
    if (!cb) continue;
    for (const [key, ma] of Object.entries(ca.measures)) {
      const mb = cb.measures[key];
      if (!mb || ma.skipped || mb.skipped) continue;
      const sa = ma.summary; const sb = mb.summary;
      rows.push([ca.id, key, pm(sa.wallMs, 0), pm(sb.wallMs, 0), pm(sa.cpuMs, 0), pm(sb.cpuMs, 0), f((sa.instructions.median ?? 0) / 1e6, 0), f((sb.instructions.median ?? 0) / 1e6, 0), ratio(sa.instructions.median, sb.instructions.median)]);
    }
  }
  return table(['cell', 'measure', 'before wall ms', 'after wall ms', 'before CPU ms', 'after CPU ms', 'before Minstr', 'after Minstr', 'instr before/after'], rows);
}

const cpuOf = (m) => m?.summary?.cpuMs;
const cold = (m, name) => m?.summary?.phases?.[name]?.cold;

function pipelineTables(result) {
  const out = [];
  const find = (cell, prefix) => Object.entries(cell.measures).find(([k, m]) => k.startsWith(prefix) && !m.skipped)?.[1];
  const byAxis = (axis) => merged(result.cells.filter((c) => c.axis === axis));
  for (const axis of ['pipeline-cases', 'real-cases']) {
    const cells = byAxis(axis).sort((a, b) => a.workload.params.cases - b.workload.params.cases);
    if (!cells.length) continue;
    const rows = [];
    for (const c of cells) {
      for (const [key, m] of Object.entries(c.measures)) {
        if (m.skipped || !/^(cli-run|cli-replay|oracle-real)/.test(key)) continue;
        const phase = (n) => f(cold(m, n)?.median, 0);
        rows.push([c.workload.params.cases, key, pm(m.summary.wallMs, 0), mn(m.summary.wallMs, 0), pm(cpuOf(m), 0), f((m.summary.instructions.median ?? 0) / 1e6, 0), f((m.summary.maxRssBytes.median ?? 0) / MIB, 0),
          /^cli-run/.test(key) ? `${phase('scanner-startup')} / ${phase('scan')} / ${phase('kernel-replay')} / ${phase('materialization')} / ${phase('serialization')} / ${phase('total')}` : '', c.trials]);
      }
    }
    out.push(`### ${axis === 'pipeline-cases' ? 'Full CLI over the inert fake scanner package' : 'Real scanner: oracle in-process adapter against the Rust CLI (oracle-real rows: 3 evaluations per process; cli-run rows: 1 run)'}\n\n${table(['cases', 'measure', 'wall ms (median ± MAD)', 'wall min', 'CPU ms (user+sys)', 'Minstr', 'peak RSS MiB', 'startup / scan / kernel / materialization / serialization / total ms (diagnostics, summed over sessions for startup and scan)', 'trials'], rows)}`);
  }
  for (const axis of ['pipeline-workers', 'real-workers']) {
    const cells = byAxis(axis).sort((a, b) => a.workload.params.cases - b.workload.params.cases || 0);
    if (!cells.length) continue;
    const rows = cells.map((c) => {
      const m = find(c, 'cli-run');
      if (!m) return null;
      const phase = (n) => f(cold(m, n)?.median, 0);
      return [m.params.workers, pm(m.summary.wallMs, 0), mn(m.summary.wallMs, 0), pm(cpuOf(m), 0), f((m.summary.instructions.median ?? 0) / 1e6, 0), f((m.summary.maxRssBytes.median ?? 0) / MIB, 0), phase('scanner-startup'), phase('scan'), phase('total'), `${m.summary.noisyTrials}/${m.summary.ok}`];
    }).filter(Boolean);
    out.push(`### Worker oversubscription (${axis === 'pipeline-workers' ? 'inert fake package' : 'real scanner'}, host has ${result.host.cpu.logicalCpus} logical CPUs)\n\n${table(['workers', 'wall ms', 'wall min', 'CPU ms', 'Minstr', 'peak RSS MiB (largest process)', 'startup ms (sum)', 'scan ms (sum)', 'total phase ms', 'noisy/ok trials'], rows)}`);
  }
  for (const axis of ['scanner', 'real-scanner']) {
    const cells = byAxis(axis);
    for (const c of cells) {
      const rows = [];
      for (const [key, m] of Object.entries(c.measures)) {
        if (m.skipped) continue;
        const P = m.summary.phases;
        const w = (n) => (P[n] ? `${f(P[n].cold?.median, 1)} (min ${f(P[n].cold?.min, 1)})` : 'n/a');
        rows.push([key, m.params.pin, w('startupMs'), w('importMs'), w('initializeMs'), w('planMs'), w('scanAllMs'), P.perScanMedianMs ? `${f(P.perScanMedianMs.cold.median * 1000, 0)}` : 'n/a', w('finishMs')]);
      }
      out.push(`### Scanner startup and per-scan latency (${c.id}; ${c.measures[Object.keys(c.measures)[0]]?.params?.texts ?? ''} texts per session)\n\n${table(['measure', 'package', 'session start ms', 'import ms', 'initialize ms', 'plan ms', 'scan all ms', 'per-scan median µs', 'finish ms'], rows)}`);
    }
  }
  return out.join('\n\n');
}

function memoryTables(result) {
  const cells = merged(result.cells.filter((c) => c.axis === 'parse')).sort((a, b) => a.workload.params.cases - b.workload.params.cases);
  if (!cells.length) return '';
  const rows = [];
  const keys = [];
  for (const [key, m] of Object.entries(cells[0].measures)) if (key !== 'rust-parse-base' && !m.skipped) keys.push(key);
  for (const key of keys) {
    const cols = cells.map((c) => {
      const m = c.measures[key]; const base = c.measures['rust-parse-base'];
      if (!m || m.skipped || !base) return null;
      const above = m.summary.maxRssBytes.median - base.summary.maxRssBytes.median;
      return { ratio: above / m.reported.bytes, above, bytes: m.reported.bytes };
    });
    const last = cols[cols.length - 1];
    const first = cells[0].measures[key];
    rows.push([first.params.doc, first.params.stage, f(last.bytes / MIB, 1), f(last.above / MIB, 0), ...cols.map((x) => f(x.ratio, 1))]);
  }
  const head = ['document', 'stage', `document MiB (${cells[cells.length - 1].workload.params.cases} cases)`, 'peak RSS above baseline MiB', ...cells.map((c) => `ratio at ${c.workload.params.cases} cases`)];
  return `### Parse peak memory by stage (peak RSS above a process that parses a 4 KB manifest, over the document's bytes)\n\n${table(head, rows)}`;
}

function ceilingTable(result) {
  const rows = result.cells.slice().sort((a, b) => a.workload.params.cases - b.workload.params.cases).map((c) => {
    const m = Object.values(c.measures).find((x) => !x.skipped);
    const rep = m?.reported;
    if (!rep) return null;
    return [c.workload.params.cases, rep.counts?.variants, rep.rows, f(rep.artifactBytes / MIB, 1), f(rep.observationBytes / MIB, 1), `${f(33554432 / MIB, 0)}`, rep.parseRefusal ? 'artifact does not parse (over the cap)' : 'parses', rep.writerRefusal ? `refused: ${rep.writerRefusal}` : 'written and round-tripped'];
  }).filter(Boolean);
  return table(['cases', 'variants', 'outcome rows (2 scanners)', 'run artifact MiB (pretty JSON)', 'both observation sets MiB', 'document cap MiB', 'artifact parse', 'atomic writer'], rows);
}

function abTable(result) {
  const rows = [];
  for (const c of result.cells.slice().sort((a, b) => a.workload.params.cases - b.workload.params.cases)) {
    const before = Object.entries(c.measures).find(([k]) => k.endsWith('-before'))?.[1];
    const after = Object.entries(c.measures).find(([k]) => k.endsWith('-after'))?.[1];
    if (!before || !after || before.skipped || after.skipped) continue;
    const b = before.summary; const a = after.summary;
    rows.push([c.workload.params.cases, pm(b.wallMs, 0), pm(a.wallMs, 0), ratio(b.wallMs.median, a.wallMs.median), pm(b.cpuMs, 0), pm(a.cpuMs, 0), ratio(b.cpuMs.median, a.cpuMs.median),
      f(b.instructions.median / 1e6, 0), f(a.instructions.median / 1e6, 0), ratio(b.instructions.median, a.instructions.median), `${f(b.maxRssBytes.min / MIB, 0)}-${f(b.maxRssBytes.max / MIB, 0)}`, `${f(a.maxRssBytes.min / MIB, 0)}-${f(a.maxRssBytes.max / MIB, 0)}`, c.trials]);
  }
  return `${table(['cases', 'before wall ms', 'after wall ms', 'wall before/after', 'before CPU ms', 'after CPU ms', 'CPU before/after', 'before Minstr', 'after Minstr', 'instr before/after', 'before RSS MiB (min-max)', 'after RSS MiB (min-max)', 'trials'], rows)}`;
}

/** Least-squares slope of log(y) on log(x) over the points with y >= floorMs (below it the timer sets the value, not the work). */
function exponent(points, floorMs = 1) {
  const p = points.filter(([x, y]) => x > 0 && y !== null && y >= floorMs).map(([x, y]) => [Math.log(x), Math.log(y)]);
  if (p.length < 3) return null;
  const mx = p.reduce((a, q) => a + q[0], 0) / p.length;
  const my = p.reduce((a, q) => a + q[1], 0) / p.length;
  return p.reduce((a, q) => a + (q[0] - mx) * (q[1] - my), 0) / p.reduce((a, q) => a + (q[0] - mx) ** 2, 0);
}

function exponents(result) {
  const cells = merged(result.cells.filter((c) => c.axis === 'cases')).sort((a, b) => a.workload.params.cases - b.workload.params.cases);
  if (cells.length < 3) return '';
  const col = (label, fn) => {
    const pts = cells.map((c) => [c.workload.params.cases, fn(c.measures)]);
    const used = pts.filter(([, y]) => y !== null && y >= 1);
    const e = exponent(pts);
    return [label, e === null ? 'n/a' : f(e, 2), used.length];
  };
  const g = (M, k) => (M[k] && !M[k].skipped ? M[k] : null);
  const rows = [
    col('TS execute + account', (M) => { const m = g(M, 'oracle'); return m ? pick(m, 'executeMs') + pick(m, 'accountMs') : null; }),
    col('TS generate', (M) => { const m = g(M, 'oracle'); return m ? pick(m, 'generateMs') : null; }),
    col('Rust generate', (M) => { const m = g(M, 'rust-generate'); return m ? pick(m, 'generate') : null; }),
    col('Rust compat (interpret + account)', (M) => { const m = g(M, 'rust-compat'); return m ? pick(m, 'interpret') + pick(m, 'account') : null; }),
    col('Rust kernel (assess + account)', (M) => { const m = g(M, 'rust-replay'); return m ? pick(m, 'assembleKernel') : null; }),
    col('Rust assemble', (M) => { const m = g(M, 'rust-replay'); return m ? pick(m, 'assemble') : null; }),
    col('Rust verify', (M) => { const m = g(M, 'rust-replay'); return m ? pick(m, 'verify') : null; }),
    col('Rust serialize', (M) => { const m = g(M, 'rust-replay'); return m ? pick(m, 'serialize') : null; }),
    col('Rust parse', (M) => { const m = g(M, 'rust-replay'); return m ? pick(m, 'parse') : null; }),
    col('Rust engine run (4 workers, stand-in scanner)', (M) => { const m = Object.values(M).find((x) => x.params?.name === 'rust-engine' && !x.skipped); return m ? pick(m, 'run') : null; }),
  ];
  return `Scaling exponents on the cases axis (least-squares slope of log time on log cases, points of at least 1 ms; 1.0 is linear, 2.0 quadratic):\n\n${table(['phase', 'exponent', 'points used'], rows)}`;
}

const args = process.argv.slice(2);
if (args[0] === '--compare') console.log(compare(load(args[1]), load(args[2])));
else for (const p of args) {
  const r = load(p);
  const body = r.suite === 'scaling' ? `${axisTables(r)}\n\n${exponents(r)}` : r.suite === 'memory' ? memoryTables(r) : r.suite === 'replay-lookup' ? abTable(r) : r.suite === 'ceilings' ? ceilingTable(r) : (r.suite === 'pipeline' || r.suite === 'real-scanner') ? pipelineTables(r) : axisTables(r);
  console.log(`## ${r.suite} (${r.startedAt})\n\n${body}\n`);
}
