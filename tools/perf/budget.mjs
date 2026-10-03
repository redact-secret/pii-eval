#!/usr/bin/env node
// Derive performance budgets from measured results ONLY (P10, ADR 0013).
//
//   node tools/perf/budget.mjs <scaling.json> [<pipeline.json> <memory.json> ...] > budgets.json
//
// A budget is the observed upper envelope of one per-unit cost at a reference cell of a committed result:
// the largest value any trial of that cell produced (in-process phases: the largest per-trial minimum over
// the warm repetitions; memory: the largest peak over the baseline process's smallest). No multiplier and no
// target is applied. The recording host was shared with other work (host metadata and per-trial idle readings
// are in the result files), so the envelope includes that noise: it is a ceiling for a regression check on the
// same kind of host, not a promise about any other machine. Scaling shapes are budgeted as the largest
// log-log slope between neighbouring sizes of an axis.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const files = process.argv.slice(2);
if (files.length === 0) { console.error('usage: budget.mjs <result.json>...'); process.exit(2); }
const results = files.map((p) => ({ path: p, bytes: readFileSync(p), json: JSON.parse(readFileSync(p, 'utf8')) }));
const find = (suite, cellId) => results.find((r) => r.json.suite === suite)?.json.cells.find((c) => c.id === cellId);
const measureOf = (cell, key) => cell?.measures?.[key] && !cell.measures[key].skipped ? cell.measures[key] : null;
const phaseMax = (m, name) => m?.summary?.phases?.[name]?.warmMin?.max ?? null;
const phaseMed = (m, name) => m?.summary?.phases?.[name]?.warmMin?.median ?? null;
const rowsOf = (m) => m?.reported?.rows ?? (m?.reported?.counts ? m.reported.counts.scanners * m.reported.counts.variants : null);
const budgets = [];
const add = (b) => { if (b.ceiling !== null && Number.isFinite(b.ceiling)) budgets.push(b); };
const r = (x, d = 3) => (x === null ? null : Number(x.toFixed(d)));

// ---- in-process phases per row (Rust release build, frozen observations) ----
const ref = find('scaling', 'cases-025600') ?? find('scaling', 'cases-006400');
if (ref) {
  const rep = measureOf(ref, 'rust-replay');
  const rows = rowsOf(rep);
  for (const [phase, label] of [['assembleKernel', 'kernel assess+account'], ['assemble', 'assemble (kernel, rows, observation sets, artifact, public projection, seals)'],
    ['verify', 'verify accounting'], ['validate', 'validate artifact'], ['serialize', 'serialize artifact (pretty JSON)'], ['parse', 'parse artifact (strict tree, typed, validate)'], ['digest', 'semantic digest of the artifact']]) {
    add({ id: `rust.${phase}.us-per-row`, cell: ref.id, what: label, unit: 'microseconds per outcome row', median: r(phaseMed(rep, phase) * 1000 / rows), ceiling: r(phaseMax(rep, phase) * 1000 / rows) });
  }
  const cmp = measureOf(ref, 'rust-compat');
  if (cmp) add({ id: 'rust.compat.us-per-row', cell: ref.id, what: 'legacy rule + oracle accounting port', unit: 'microseconds per outcome row',
    median: r((phaseMed(cmp, 'interpret') + phaseMed(cmp, 'account')) * 1000 / rows), ceiling: r((phaseMax(cmp, 'interpret') + phaseMax(cmp, 'account')) * 1000 / rows) });
  const base = measureOf(ref, 'rust-prepare');
  if (rep && base && rows) {
    add({ id: 'rust.replay.peak-rss-bytes-per-row', cell: ref.id, what: 'replay process peak RSS above the prepare baseline (all documents and their serialization alive)', unit: 'bytes per outcome row',
      median: r((rep.summary.maxRssBytes.median - base.summary.maxRssBytes.median) / rows, 0), ceiling: r((rep.summary.maxRssBytes.max - base.summary.maxRssBytes.min) / rows, 0) });
  }
  const eng = Object.entries(ref.measures).find(([k, m]) => m.params?.name === 'rust-engine' && !m.skipped)?.[1];
  if (eng) add({ id: 'rust.engine.us-per-row', cell: ref.id, what: 'executor + assemble with a stand-in scanner (4 workers, 2 replays)', unit: 'microseconds per outcome row', median: r(phaseMed(eng, 'run') * 1000 / rows), ceiling: r(phaseMax(eng, 'run') * 1000 / rows) });
}

// ---- scaling shape: largest log-log slope between neighbouring sizes on the cases axis ----
const scaling = results.find((r0) => r0.json.suite === 'scaling')?.json;
if (scaling) {
  // Cells of one workload (the oracle may have its own single-trial cell) are one point.
  const byCases = new Map();
  for (const c of scaling.cells.filter((x) => x.axis === 'cases')) {
    const prev = byCases.get(c.workload.params.cases);
    byCases.set(c.workload.params.cases, prev ? { ...prev, measures: { ...prev.measures, ...c.measures } } : c);
  }
  const cells = [...byCases.values()].sort((a, b) => a.workload.params.cases - b.workload.params.cases);
  const slope = (pick) => {
    let worst = null;
    for (let i = 1; i < cells.length; i++) {
      const a = pick(cells[i - 1]); const b = pick(cells[i]);
      if (!a || !b) continue;
      const s = Math.log(b.y / a.y) / Math.log(b.x / a.x);
      worst = worst === null ? s : Math.max(worst, s);
    }
    return worst;
  };
  const forPhase = (key, name) => (c) => { const m = measureOf(c, key); const v = phaseMed(m, name); return m && v ? { x: m.reported.counts.variants, y: v } : null; };
  for (const [key, name, id] of [['rust-replay', 'assembleKernel', 'kernel'], ['rust-replay', 'assemble', 'assemble'], ['rust-replay', 'parse', 'parse'], ['rust-replay', 'serialize', 'serialize']]) {
    // Only sizes whose phase is at least 1 ms count: below that the timer, not the work, sets the value.
    const s = (() => { let worst = null; for (let i = 1; i < cells.length; i++) { const a = forPhase(key, name)(cells[i - 1]); const b = forPhase(key, name)(cells[i]); if (!a || !b || a.y < 1) continue; const v = Math.log(b.y / a.y) / Math.log(b.x / a.x); worst = worst === null ? v : Math.max(worst, v); } return worst; })();
    if (s !== null) add({ id: `rust.${id}.scaling-exponent`, cell: 'cases axis, sizes with phase >= 1 ms', what: `largest log-log slope of ${name} against variants`, unit: 'exponent (1 = linear)', median: null, ceiling: r(s, 2) });
  }
  const sTs = slope((c) => { const m = measureOf(c, 'oracle'); const e = phaseMed(m, 'executeMs'); const a = phaseMed(m, 'accountMs'); return m && e ? { x: c.workload.cases, y: e + a } : null; });
  if (sTs !== null) add({ id: 'ts.exec-account.scaling-exponent', cell: 'cases axis', what: 'largest log-log slope of the oracle execute+account against cases (reference, not a budget on this repository)', unit: 'exponent', median: null, ceiling: r(sTs, 2) });
}
// ---- full CLI (pipeline suite, inert fake package): evaluator-only instructions and process peak RSS per variant ----
const pipe = find('pipeline', 'pipeline-cases-025600');
if (pipe) {
  const variants = 25617; // exact: the workload's variant count (cases + the two context groups' extra variants)
  for (const [key, m] of Object.entries(pipe.measures)) {
    if (m.skipped || !/^cli-(run|replay)-/.test(key)) continue;
    const kind = key.startsWith('cli-run') ? 'run' : 'replay';
    add({ id: `cli.${kind}.evaluator-instructions-per-variant`, cell: pipe.id, what: `pii-eval ${kind} (${key}): instructions retired by the evaluator process (scanner children are not counted)`, unit: 'instructions per variant',
      median: r(m.summary.instructions.median / variants, 0), ceiling: r(m.summary.instructions.max / variants, 0) });
    add({ id: `cli.${kind}.peak-rss-bytes-per-variant`, cell: pipe.id, what: `pii-eval ${kind}: peak RSS of the largest process`, unit: 'bytes per variant', median: r(m.summary.maxRssBytes.median / variants, 0), ceiling: r(m.summary.maxRssBytes.max / variants, 0) });
  }
}

// ---- parse memory: the largest ratio of peak RSS above the baseline process to the document, per document kind and stage ----
const mem = results.find((r0) => r0.json.suite === 'memory')?.json;
if (mem) {
  const worst = new Map();
  for (const c of mem.cells) {
    const base = c.measures['rust-parse-base'];
    if (!base || base.skipped) continue;
    for (const [key, m] of Object.entries(c.measures)) {
      if (key === 'rust-parse-base' || m.skipped) continue;
      const bytes = m.reported?.bytes;
      if (!bytes) continue;
      const ratio0 = (m.summary.maxRssBytes.max - base.summary.maxRssBytes.min) / bytes;
      const k = `${m.params.doc}.${m.params.stage}`;
      const prev = worst.get(k);
      worst.set(k, { ratio: Math.max(prev?.ratio ?? 0, ratio0), cells: [...(prev?.cells ?? []), c.id] });
    }
  }
  for (const [k, v] of [...worst.entries()].sort()) {
    add({ id: `parse.${k}.peak-rss-ratio`, cell: `memory suite, ${v.cells.length} sizes`, what: `peak RSS above the baseline process over document bytes (${k})`, unit: 'ratio', median: null, ceiling: r(v.ratio, 1) });
  }
}

console.log(JSON.stringify({
  schema: 'pii-eval-perf-budgets/1',
  rule: 'budget = observed upper envelope at the reference cell (largest trial); no multiplier, no target; see docs/performance.md',
  derivedFrom: results.map((x) => ({ file: x.path.split('/').slice(-2).join('/'), suite: x.json.suite, sha256: createHash('sha256').update(x.bytes).digest('hex') })),
  budgets: budgets.filter((b) => !b.id.startsWith('ts.')),
  // Measurements of the TypeScript oracle kept for comparison; they bind nothing in this repository.
  references: budgets.filter((b) => b.id.startsWith('ts.')).map(({ ceiling, ...rest }) => ({ ...rest, observed: ceiling })),
}, null, 1));
