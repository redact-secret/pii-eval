#!/usr/bin/env node
// Replay the four complete benchmark populations (issue #32) with a pii-eval binary and emit the handoff summary.
//   node replay-populations.mjs <pii-eval binary> <conversion dir> <work dir>
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const [binary, conv, work] = process.argv.slice(2);
const sha = b => createHash('sha256').update(b).digest('hex');
const VIEWS = ['oracle-plan', 'qualification-plan', 'diagnostic-balanced', 'benign-heavy-stress'];
const run = (args) => spawnSync(binary, args, { encoding: 'utf8', maxBuffer: 1 << 28 });
const out = [];
for (const view of VIEWS) {
  const dir = join(conv, view);
  const file = n => join(dir, n);
  const runs = [];
  for (let i = 1; i <= 3; i++) {
    const o = join(work, view, `run${i}`);
    rmSync(o, { recursive: true, force: true });
    mkdirSync(join(work, view), { recursive: true });
    const r = run(['replay', '--snapshot', file('snapshot.json'), '--manifest', file('manifest.json'), '--observation', file('observation.json'), '--out', o, '--projection-roster', file('projection-roster.json'), '--projection-mode', 'exploratory']);
    if (r.status !== 0) throw new Error(`${view}: replay failed ${r.status}: ${r.stderr.slice(0, 600)}`);
    const summary = JSON.parse(r.stdout.split('\n')[0]);
    if (summary.state !== 'replayed' || summary.semantic?.scannersLaunched !== 0) throw new Error(`${view}: not a replay`);
    runs.push({ bytes: readFileSync(join(o, 'public-synthetic-artifact.json')), summary });
  }
  const equal = runs.every(r => sha(r.bytes) === sha(runs[0].bytes));
  const artifact = JSON.parse(runs[0].bytes.toString('utf8'));
  const v = run(['validate', join(work, view, 'run1', 'public-synthetic-artifact.json'), '--snapshot', file('snapshot.json'), '--projection-roster', file('projection-roster.json')]);
  const census = JSON.parse(readFileSync(file('census.json'), 'utf8'));
  const sem = artifact.semantic;
  const states = (axis) => sem.outcomes.reduce((m, o) => ((m[o[axis]] = (m[o[axis]] ?? 0) + 1), m), {});
  const metrics = Object.fromEntries(sem.scannerMetrics[0].metrics.map(m => [m.metric.id, { status: m.status, counts: m.counts, effectiveN: m.effectiveN, value: m.value }]));
  out.push({
    view,
    benchmarkMemberships: census.benchmarkCases,
    carried: census.convertedCases,
    notRepresentable: census.excludedCases,
    snapshotDigest: JSON.parse(readFileSync(file('snapshot.json'), 'utf8')).semanticDigest,
    manifestDigest: JSON.parse(readFileSync(file('manifest.json'), 'utf8')).semanticDigest,
    observationDigest: JSON.parse(readFileSync(file('observation.json'), 'utf8')).semanticDigest,
    rosterSha256: sha(readFileSync(file('projection-roster.json'))),
    artifactSemanticDigest: artifact.semanticDigest,
    artifactSchemaVersion: artifact.schemaVersion,
    artifactFileSha256: sha(runs[0].bytes),
    replaysByteEqual: equal,
    validateStatus: v.status,
    outcomes: sem.outcomes.length,
    typeIdentity: states('typeIdentity'),
    sensitivityContext: states('sensitivityContext'),
    range: states('range'),
    metricsKeys: Object.keys(metrics),
    metrics,
  });
}
writeFileSync(join(work, 'summary.json'), `${JSON.stringify(out, null, 1)}\n`);
for (const r of out) console.log(r.view, r.carried, '/', r.benchmarkMemberships, r.artifactSchemaVersion, r.artifactSemanticDigest.slice(0, 16), 'equal', r.replaysByteEqual, 'validate', r.validateStatus, JSON.stringify(r.range));
