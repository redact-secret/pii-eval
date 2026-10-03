#!/usr/bin/env node
// Scanner speed WITHOUT the evaluator (P10, ADR 0013): the lower bound the process adapter is compared with.
//
// Usage: node tools/perf/scanner-bench.mjs <package-dir> <entry-relative> [--texts N]
//
// Loads the scanner package in this process exactly as the production shim does
// (`crates/pii-eval-adapters/shims/node/redact-secret-core.mjs`: `initialize({ pii })`, then one
// `scanAndRedact(text, { limits })` per input), over the same synthetic texts as
// `perf scanner` (`<i>: contact person@example.invalid ssn=123-45-6789 value <i>`, 64 distinct, cycled).
// It reports module load + initialize time and the per-call latency of the scanner itself. The difference
// between this and `perf scanner` is what the process boundary, the JSON line protocol, the pin
// verification and the Rust adapter cost.
import { isAbsolute, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const args = process.argv.slice(2);
const flagIndex = args.indexOf('--texts');
const texts = flagIndex >= 0 ? Number(args.splice(flagIndex, 2)[1]) : 200;
const [dir, entry] = args;
if (!dir || !entry || !Number.isInteger(texts) || texts < 1 || texts > 100000) {
  console.error('usage: scanner-bench.mjs <package-dir> <entry-relative> [--texts N<=100000]');
  process.exit(2);
}
const entryPath = isAbsolute(entry) ? entry : resolve(dir, entry);
const list = Array.from({ length: 64 }, (_, i) => `${i}: contact person@example.invalid ssn=123-45-6789 value ${i}`);

const t0 = performance.now();
const core = await import(pathToFileURL(entryPath).href);
const t1 = performance.now();
await core.initialize({ pii: ['pii:global', 'pii:us'] });
const t2 = performance.now();
const limits = { maxInputBytes: 1 << 20, maxFindings: 10000 };
const per = [];
let findings = 0;
const c0 = process.cpuUsage();
const s0 = performance.now();
for (let i = 0; i < texts; i++) {
  const t = performance.now();
  const r = core.scanAndRedact(list[i % list.length], { limits });
  per.push(performance.now() - t);
  findings += (r.findings ?? []).length;
}
const total = performance.now() - s0;
const c1 = process.cpuUsage(c0);
per.sort((a, b) => a - b);
const at = (q) => per[Math.round((per.length - 1) * q)];
console.log(JSON.stringify({
  mode: 'scanner-node', texts, importMs: t1 - t0, initializeMs: t2 - t1, scanAllMs: total, scanCpuMs: (c1.user + c1.system) / 1000,
  perScanMs: { n: per.length, min: per[0], median: at(0.5), p95: at(0.95), max: per[per.length - 1], sum: per.reduce((a, b) => a + b, 0) },
  findings, node: process.version,
}));
