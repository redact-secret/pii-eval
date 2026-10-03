#!/usr/bin/env node
// Writes the committed suite files next to this script (P10, ADR 0013): `node tools/perf/suites/generate.mjs`.
// A suite lists cells (a cell is one workload: its parameters and the measures to take); every cell records the
// digest of the workload its parameters generate, so `run.mjs plan` detects any drift of the generator. Axes:
//   cases      size of the population (variants follow: about one per case plus the two fixed context groups)
//   scanners   number of scanners over the same population
//   findings   overlapping findings per variant (the behaviour's own plus noise around the candidate)
//   language   share of Korean text (UTF-8 multi-byte ranges)
//   text       bytes of text after the candidate
//   replays    scanner replay passes (the oracle and the engine both allow it; the engine requires >= 2)
//   workers    in-process executor workers (oversubscription: the host has 10 logical CPUs)
//   batch      variants per executor batch
// `pipeline` adds the full CLI (`pii-eval run` and `replay` over the inert fake scanner package, one scanner per run),
// worker oversubscription of real scanner processes, and scanner startup; `memory` adds document parse memory.
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { render } from '../make-workload.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const pad4 = (n) => String(n).padStart(6, '0');
const cell = (axis, tag, workload, measures, extra = {}) => {
  const w = { id: `${axis}-${tag}`, ...workload };
  return { id: w.id, axis, trials: 3, ...extra, workload: w, digest: render(w).digest, measures };
};
const kernel = ['oracle', 'rust-generate', 'rust-replay', 'rust-compat', { name: 'rust-engine', workers: 4, perScanner: 2, batch: 2, replays: 2 }];
const suite = (id, description, cells, extra = {}) => ({ schema: 'pii-eval-perf-suite/1', id, description, trials: 5, warmupTrials: 1, innerRepeat: 3, ...extra, cells });
const write = (s) => writeFileSync(join(HERE, `${s.id}.json`), `${JSON.stringify(s, null, 1)}\n`);

// ---- scaling: evaluator work on frozen observations, TypeScript oracle against the Rust release build ----
const scaling = [];
const rustOnly = kernel.filter((m) => m !== 'oracle');
for (const [n, trials] of [[100, 7], [400, 7], [1600, 5], [6400, 5]]) scaling.push(cell('cases', pad4(n), { cases: n, scanners: 2, findings: 1 }, kernel, { trials }));
// The oracle needs minutes per run at this size (its accounting is superlinear), so it gets one measured run in its own cell
// of the same workload; the Rust measures keep their trials.
scaling.push(cell('cases', pad4(25600), { cases: 25600, scanners: 2, findings: 1 }, rustOnly, { trials: 5 }));
for (const s of [1, 2, 4, 8, 16]) scaling.push(cell('scanners', pad4(s), { cases: 800, scanners: s, findings: 1 }, kernel));
for (const f of [1, 4, 16, 64, 256, 1024]) scaling.push(cell('findings', pad4(f), { cases: 200, scanners: 2, findings: f, padBytes: 1024 }, kernel));
for (const k of [0, 25, 50, 100]) scaling.push(cell('language', `ko${pad4(k)}`, { cases: 800, scanners: 2, findings: 1, koShare: k }, kernel));
for (const p of [0, 1024, 16384, 262144]) scaling.push(cell('text', pad4(p), { cases: 100, scanners: 2, findings: 1, padBytes: p }, kernel));
for (const r of [2, 3, 4, 8]) scaling.push(cell('replays', pad4(r), { cases: 1600, scanners: 2, findings: 1 }, [{ name: 'oracle', replays: r }, { name: 'rust-engine', workers: 4, perScanner: 2, batch: 2, replays: r }]));
for (const w of [1, 2, 4, 8, 16, 32]) scaling.push(cell('workers', pad4(w), { cases: 6400, scanners: 4, findings: 1 }, [{ name: 'rust-engine', workers: w, perScanner: w, batch: 2, replays: 2 }]));
for (const b of [1, 2, 8, 32, 128]) scaling.push(cell('batch', pad4(b), { cases: 6400, scanners: 2, findings: 1 }, [{ name: 'rust-engine', workers: 4, perScanner: 2, batch: b, replays: 2 }]));
// last: it is the slowest cell by far
scaling.push({ ...cell('cases', pad4(25600), { cases: 25600, scanners: 2, findings: 1 }, ['oracle'], { trials: 1, warmupTrials: 0 }), id: 'cases-025600-oracle' });
write(suite('scaling', 'Evaluator scaling over frozen observations: oracle against Rust, increasing size per axis.', scaling));

// ---- pipeline: the CLI end to end over the inert fake scanner package (the real package is opt-in, see docs/performance.md) ----
const pipeline = [];
for (const [n, trials] of [[400, 5], [1600, 5], [6400, 3], [25600, 3]]) {
  pipeline.push(cell('pipeline-cases', pad4(n), { cases: n, scanners: 1, findings: 1 }, [{ name: 'cli-run', pin: 'candidate', workers: 4, replays: 2 }, { name: 'cli-replay', pin: 'candidate', workers: 4, replays: 2 }], { trials }));
}
for (const w of [1, 2, 4, 8, 16, 32]) {
  pipeline.push(cell('pipeline-workers', pad4(w), { cases: 3200, scanners: 1, findings: 1 }, [{ name: 'cli-run', pin: 'candidate', workers: w, replays: 2 }]));
}
pipeline.push(cell('scanner', 'candidate', { cases: 10, scanners: 1 }, [{ name: 'scanner-rust', pin: 'candidate', texts: 2000, sessions: 5 }, { name: 'scanner-node', pin: 'candidate', texts: 2000 }]));
write(suite('pipeline', 'Full CLI pipeline, replay, worker oversubscription and scanner startup over the inert fake package.', pipeline));

// ---- memory: parse memory of engine-produced documents of increasing size ----
const memory = [];
for (const n of [400, 1600, 6400, 25600]) {
  const m = [];
  for (const doc of ['snapshot', 'observation', 'artifact']) for (const stage of ['full', 'strict', 'typed', 'validate']) m.push({ name: 'rust-parse', doc, stage });
  memory.push(cell('parse', pad4(n), { cases: n, scanners: 2, findings: 1 }, m, { trials: 3 }));
}
write(suite('memory', 'Peak memory of parsing documents of increasing size, by stage (strict value tree, typed parse, typed parse plus validation and digest, all three).', memory));
// ---- replay-lookup: A/B of one optimization (ADR 0013): `before` and `after` builds of the same CLI, same inputs ----
const lookup = [];
for (const [n, trials] of [[400, 5], [1600, 5], [6400, 5], [12800, 5], [25600, 5]]) {
  lookup.push(cell('replay-lookup', pad4(n), { cases: n, scanners: 1, findings: 1 },
    [{ name: 'cli-replay', pin: 'candidate', workers: 4, replays: 2, bin: 'before' }, { name: 'cli-replay', pin: 'candidate', workers: 4, replays: 2, bin: 'after' }], { trials }));
}
write(suite('replay-lookup', 'A/B of the replay variant lookup (quadratic nth walk before, indexed list after): same documents, two builds, interleaved trials.', lookup));
// ---- real-scanner (opt-in: needs --real-package and --real-root, the hermetic install of tools/oracle-parity/real-scanner) ----
const real = [];
for (const [n, trials] of [[100, 5], [400, 5], [1600, 5], [6400, 3]]) {
  real.push(cell('real-cases', pad4(n), { cases: n, scanners: 1, findings: 1 },
    ['oracle-real', { name: 'cli-run', pin: 'released', workers: 4, replays: 2 }, { name: 'cli-run', pin: 'released', workers: 1, replays: 2 }], { trials }));
}
for (const w of [1, 2, 4, 8, 16, 32]) real.push(cell('real-workers', pad4(w), { cases: 1600, scanners: 1, findings: 1 }, [{ name: 'cli-run', pin: 'released', workers: w, replays: 2 }]));
real.push(cell('real-scanner', 'released', { cases: 10, scanners: 1 }, [{ name: 'scanner-rust', pin: 'released', texts: 2000, sessions: 5 }, { name: 'scanner-node', pin: 'released', texts: 2000 }]));
write(suite('real-scanner', 'The real @redact-secret/core 0.1.0-beta.12 (opt-in): oracle adapter in-process against the Rust CLI over a process boundary, worker oversubscription, scanner startup.', real));
// ---- ceilings: where the 32 MiB document cap stops the writer (the run is measured, the refusal is the result) ----
const ceilings = [];
for (const n of [25600, 28000, 30000, 32000]) ceilings.push(cell('ceiling', pad4(n), { cases: n, scanners: 2, findings: 1 }, ['rust-replay'], { trials: 1, warmupTrials: 0 }));
write(suite('ceilings', 'Population sizes around the point where a pretty-printed run artifact exceeds the 32 MiB document cap and the atomic writer refuses it.', ceilings, { warmupTrials: 0, trials: 1, innerRepeat: 1 }));
console.log('suites written');
