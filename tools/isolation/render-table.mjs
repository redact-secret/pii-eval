#!/usr/bin/env node
// Renders the measurement table of docs/custodian-isolation-node.md from the raw results, so
// the document's table is generated, not typed.   node tools/isolation/render-table.mjs RESULTS.json
import { readFileSync } from 'node:fs';
import { isMain } from '../ci/main-guard.mjs';

export function cell(b) {
  if (b.ok) return 'ok';
  if (b.timedOut) return 'fail (hangs; killed at the wall limit)';
  if (b.signal) return `fail (${b.signal})`;
  return `fail (exit ${b.exitCode})`;
}

export function renderTable(r) {
  const head = [
    '| address space | node starts | node `--jitless` | engine `--version` | engine quickstart run | same, node started with `--jitless` |',
    '| --- | --- | --- | --- | --- | --- |',
  ];
  const rows = r.matrix.map((m) => `| ${m.memMiB} MiB | ${cell(m.nodeStart)} | ${cell(m.nodeJitless)} | ${cell(m.engineVersion)} | ${cell(m.engineQuickstartRun)} | ${cell(m.engineQuickstartRunNodeJitless)} |`);
  return `${[...head, ...rows].join('\n')}\n`;
}

if (isMain(import.meta.url)) {
  if (process.argv.length !== 3) {
    process.stderr.write('usage: render-table.mjs RESULTS.json\n');
    process.exit(2);
  }
  process.stdout.write(renderTable(JSON.parse(readFileSync(process.argv[2], 'utf8'))));
}
