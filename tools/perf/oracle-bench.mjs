#!/usr/bin/env node
// Time the pinned TypeScript oracle's own code on a synthetic perf workload (P10, ADR 0013).
//
// Usage (Node 22, `--experimental-strip-types`, hooks as for tools/oracle-parity):
//   node --experimental-strip-types --no-warnings --import tools/oracle-parity/register.mjs \
//        tools/perf/oracle-bench.mjs <oracle-root> <workload.json> [--repeat R] [--replays N]
//             [--phase full|prepare|export-only [--with-counts]] [--export out.json] [--real-root <dir>]
//
// <oracle-root> is `<scratch>/oracle` written by tools/oracle-parity/fetch-oracle.mjs (the pinned commit;
// the tree digest is verified before anything runs). One process = one trial: the first repetition is
// the cold one (module and JIT warm-up included), later ones are warm. Phases per repetition:
//   generate  the oracle's methods over the authored cases (variant generation only)
//   execute   `executePiiEvaluation`: generation again, scratch-directory writes, scanner replays over
//             frozen findings, normalization, outcome interpretation, result assembly, artifact digest
//   account   `piiAccountingRowsFromEvaluation` + `accountPiiRows` (the ten metrics) for every scanner
// `execute` includes everything the oracle does per run, in its own shape (it writes every input to a
// scratch directory, which the Rust in-process path does not; docs/performance.md says so). Wall time is
// performance.now(); CPU is process.cpuUsage() (user + system of this process, all threads).
// Peak RSS is reported by the orchestrator from /usr/bin/time, not here.
// With --export the file the Rust perf harness reads is written: generated variants and the frozen
// findings of every scanner (integers and strings only). --phase prepare stops after workload preparation
// (the baseline whose process cost is subtracted from `full`); --phase export-only writes the export without
// running the oracle's evaluation (for sizes the oracle's quadratic accounting cannot do in reasonable time;
// the export then has no oracle metric counts). --replays sets the oracle's replay passes (default 2, its own).
// --real-root runs the REAL scanner through the oracle's own adapter (the hermetic install of
// tools/oracle-parity/real-scanner) instead of the frozen findings.
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { onDiskTreeDigest, sha256, stableJson } from '../oracle-parity/lib.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const flag = (name, dflt) => { const i = args.indexOf(name); if (i < 0) return dflt; const v = args[i + 1]; args.splice(i, 2); return v; };
const repeat = Number(flag('--repeat', '1'));
const replays = Number(flag('--replays', '2'));
const phase = flag('--phase', 'full');
const withCounts = args.includes('--with-counts') ? (args.splice(args.indexOf('--with-counts'), 1), true) : false;
const realRoot = flag('--real-root', null);
const exportPath = flag('--export', null);
const [root, inputPath] = args;
if (!root || !inputPath || !Number.isInteger(repeat) || repeat < 1 || repeat > 50 || !Number.isInteger(replays) || replays < 1 || replays > 16
  || !['full', 'prepare', 'export-only'].includes(phase)) {
  console.error('usage: oracle-bench.mjs <oracle-root> <workload.json> [--repeat R<=50] [--replays N<=16] [--phase full|prepare|export-only] [--export out.json] [--real-root dir]');
  process.exit(2);
}
const spec = JSON.parse(readFileSync(join(HERE, '..', 'oracle-parity', 'oracle-files.json'), 'utf8'));
const treeDigest = onDiskTreeDigest(root, spec);
if (treeDigest !== spec.treeDigest) throw new Error(`the oracle files under ${root} are not the pinned files`);
const inputBytes = readFileSync(inputPath);
const input = JSON.parse(inputBytes.toString('utf8'));
if (input.schema !== 'pii-eval-parity-input/1' || input.workload?.schema !== 'pii-eval-perf-workload/1') throw new Error('not a perf workload');

const imp = (p) => import(pathToFileURL(resolve(root, p)).href);
const D = 'benchmarks/evaluation/domains/pii';
const { createRegistry } = await imp('benchmarks/evaluation/substrate/registry.ts');
const { createPiiValidators } = await imp(`${D}/validators.ts`);
const { createPiiOperators } = await imp(`${D}/operators.ts`);
const { executePiiEvaluation, piiAccounting } = await imp(`${D}/execution.ts`);
const { accountPiiRows, piiAccountingRowsFromEvaluation } = await imp(`${D}/accounting.ts`);
const { PII_METRIC_IDS } = await imp(`${D}/profile.ts`);
const methodFile = async (f) => imp(`${D}/methods/${f}.ts`);
const { schemaOnly } = await methodFile('schema-only');
const { typeValidation } = await methodFile('type-validation');
const { contextDiscrimination } = await methodFile('context-discrimination');
const { piiBenign } = await methodFile('benign');
const { jurisdictionCollision } = await methodFile('jurisdiction-collision');
const { mutation } = await methodFile('mutation');
const { referenceDifferential } = await methodFile('reference-differential');

const stock = createPiiValidators();
const unavailable = { id: 'unavailable-test', version: 1, validate: () => ({ state: 'unavailable' }) };
const validators = createPiiValidators([stock.get('synthetic-mod10'), stock.get('us-ssn-allocation'), unavailable]);
const methods = createRegistry('PII method', ['validateCase', 'generate', 'evaluate']);
for (const m of [schemaOnly, typeValidation(validators, {}), contextDiscrimination, piiBenign(validators, {}),
  jurisdictionCollision(validators, {}), mutation(createPiiOperators()), referenceDifferential(validators)]) methods.register(m);

const authority = [{ sourceKind: 'standard', sourceId: 'synthetic-authority', locator: 'section:synthetic', revision: '1',
  supports: ['lexical', 'validation', 'allocation', 'sensitivity', 'reserved-control'] }];
const bl = (s) => Buffer.byteLength(s);
function piiCase(c) {
  const content = `${c.prefix}${c.value}${c.suffix}`;
  const metadata = {};
  if (c.accountingClass) metadata.accountingClass = c.accountingClass;
  if (c.operator) metadata.operator = c.operator;
  if (c.competing) metadata.collision = { targetFamily: c.family, competingFamilies: c.competing };
  if (c.contextGroup) metadata.contextEvidenceGroup = c.contextGroup;
  return {
    id: c.id, method: c.method, visibility: 'development', input: { id: c.id, path: `pii/${c.id}.txt`, content },
    candidate: { start: bl(c.prefix), end: bl(c.prefix) + bl(c.value) },
    contract: { category: 'pii', family: c.family, displayName: 'Synthetic Identifier', identityDomain: c.identityDomain, scope: c.scope,
      typeExpectation: { state: c.type, validator: c.validator }, sensitivityExpectation: c.sensitivity,
      context: { obligation: c.obligation, class: c.contextClass, language: c.language }, authority, referenceEvidence: c.reference,
      qualificationProfile: { id: 'pii-v1', version: 1 } },
    provenance: { source: 'synthetic/perf', sourceHash: 'a'.repeat(64), seed: c.seed, rationale: 'synthetic perf case', sources: ['synthetic'] },
    ...(Object.keys(metadata).length ? { metadata } : {}),
  };
}
const piiCases = input.cases.map(piiCase);
const authored = new Map(input.cases.map((c) => [c.id, c]));

// ---- workload preparation (not timed as oracle work): recipes -> frozen findings per variant ----
const prepStart = performance.now();
const generated = piiCases.map((c) => ({ c, variants: methods.get(c.method).generate(c) }));
const orderedVariants = [];
for (const { c, variants } of generated) for (const v of variants) orderedVariants.push({ caseId: c.id, slot: v.id, variant: v });
orderedVariants.sort((a, b) => (a.caseId < b.caseId ? -1 : a.caseId > b.caseId ? 1 : a.slot < b.slot ? -1 : a.slot > b.slot ? 1 : 0));
function resolveFinding(t, entry) {
  const c = authored.get(entry.caseId);
  const v = entry.variant;
  const bytes = Buffer.from(v.fixture.content);
  const len = bytes.length;
  let start = Math.max(0, Math.min(len, v.candidate.start + t.ds));
  let end = Math.max(0, Math.min(len, v.candidate.end + t.de));
  const continuation = (i) => i > 0 && i < len && (bytes[i] & 0xc0) === 0x80;
  while (continuation(start)) start -= 1;
  while (continuation(end)) end += 1;
  const out = { start, end };
  const family = t.family === '$family' ? c.family : t.family;
  if (family !== null && family !== undefined) out.family = family;
  const jurisdiction = t.jurisdiction === '$jurisdiction' ? c.jurisdiction : t.jurisdiction;
  if (jurisdiction !== null && jurisdiction !== undefined) out.jurisdiction = jurisdiction;
  const sensitive = t.sensitive === '$expected' ? v.contract.sensitivityExpectation === 'sensitive' : t.sensitive;
  if (sensitive !== null && sensitive !== undefined) out.sensitive = sensitive;
  return out;
}
const frozen = new Map();
let findingTotal = 0;
for (const s of input.scanners) {
  const byPath = new Map();
  let i = 0;
  for (const entry of orderedVariants) {
    const templates = s.recipe.all.cycle[i % s.recipe.all.cycle.length];
    i += 1;
    const found = templates.map((t) => resolveFinding(t, entry));
    findingTotal += found.length;
    byPath.set(entry.variant.fixture.path, found);
  }
  frozen.set(s.id, byPath);
}
const prepMs = performance.now() - prepStart;
const scannerOf = (s) => {
  const byPath = frozen.get(s.id);
  return { id: s.id, mode: 'test', configuration: { frozen: true, id: s.id },
    async version() { return '1.0.0'; },
    async scan(_dir, inputs) { return inputs.flatMap((i) => (byPath.get(i.path) ?? []).map((f) => ({ path: i.path, ...f }))); } };
};
let scanners = input.scanners.map(scannerOf);
let scannerSpecs = input.scanners;
if (realRoot) {
  // The oracle's own candidate adapter over the hermetic install (as export-oracle.mjs does), PII findings only.
  const REAL_SELECTORS = ['pii:global', 'pii:us'];
  const { loadCandidate } = await imp('scanners/candidate.mjs');
  const loaded = await loadCandidate({ root: resolve(realRoot), declaredVersion: '0.1.0-beta.12' }, null, { pii: REAL_SELECTORS });
  scannerSpecs = [{ id: 'redact-secret-core' }];
  scanners = [{ id: 'redact-secret-core', mode: 'candidate', capabilities: { ranges: true, classification: true },
    configuration: { adapter: 'redact-secret-core', findings: 'pii-domain-only', requestedSelectors: REAL_SELECTORS },
    async version() { return loaded.version; },
    async scan(directory, fixtures) { return (await loaded.scan(directory, fixtures)).filter((f) => typeof f.family === 'string' && f.family.startsWith('pii:')); } }];
}

const trials = [];
let lastArtifact;
// export-only normally skips the evaluation; --with-counts runs it once so the export carries the oracle's metric counts.
const reduced = phase === 'prepare' || (phase === 'export-only' && !withCounts);
for (let r = 0; r < (reduced ? 0 : phase === 'export-only' ? 1 : repeat); r++) {
  const t0 = performance.now(); const c0 = process.cpuUsage();
  for (const c of piiCases) methods.get(c.method).generate(c);
  const t1 = performance.now(); const c1 = process.cpuUsage();
  const artifact = await executePiiEvaluation({ cases: piiCases, methods, scanners, runId: '00000000-0000-4000-8000-000000000001', accounting: { ...piiAccounting, replays } });
  const t2 = performance.now(); const c2 = process.cpuUsage();
  const reports = scannerSpecs.map((s) => accountPiiRows(piiAccountingRowsFromEvaluation(artifact, s.id)));
  const t3 = performance.now(); const c3 = process.cpuUsage();
  const cpu = (a, b) => (b.user - a.user + (b.system - a.system)) / 1000;
  trials.push({ generateMs: t1 - t0, executeMs: t2 - t1, accountMs: t3 - t2, totalMs: t3 - t0,
    generateCpuMs: cpu(c0, c1), executeCpuMs: cpu(c1, c2), accountCpuMs: cpu(c2, c3) });
  lastArtifact = { artifact, reports };
}

// Semantic fingerprint of what the oracle computed: metric counts and effective N per scanner (integers).
const metricCounts = reduced ? [] : lastArtifact.reports.map((rep, i) => ({ scanner: scannerSpecs[i].id, rowCount: rep.rowCount,
  metrics: Object.fromEntries(PII_METRIC_IDS.map((id) => [id, { status: rep.metrics[id].status, counts: { ...rep.metrics[id].counts }, effectiveN: rep.metrics[id].effectiveN }])) }));
const outcomeDigest = reduced ? null : sha256(stableJson(lastArtifact.artifact.results.map((r) => ({ id: r.id, outcomes: r.outcomes.map((o) => ({ s: o.scanner, v: o.variant, t: o.typeIdentity.state, c: o.sensitivityContext.state, r: o.range, n: o.observed.findingCount })) }))));
const result = {
  schema: 'pii-eval-perf-oracle-trial/1',
  workloadSha256: sha256(inputBytes),
  counts: { cases: piiCases.length, variants: orderedVariants.length, scanners: scanners.length, findings: realRoot ? null : findingTotal, replays },
  phase, scannerKind: realRoot ? 'real' : 'frozen',
  prepMs, trials,
  fingerprint: { metricCountsSha256: sha256(stableJson(metricCounts)), outcomesSha256: outcomeDigest },
  runtime: { node: process.version, v8: process.versions.v8, icu: process.versions.icu },
  // maxRSS in KiB (libuv normalizes macOS bytes to KiB).
  rusageMaxRssKiB: process.resourceUsage().maxRSS,
};
if (exportPath && !realRoot) {
  const exp = {
    schema: 'pii-eval-perf-observations/1',
    workloadSha256: result.workloadSha256,
    provenance: { oracleCommit: spec.pin, oracleFilesTreeDigest: treeDigest, node: process.version, tool: 'tools/perf/oracle-bench.mjs' },
    cases: generated.map(({ c, variants }) => ({ id: c.id, method: c.method,
      variants: variants.map((v) => ({ slot: v.id, text: v.fixture.content, candidate: { ...v.candidate }, expectation: { contextClass: v.contract.context.class, sensitivity: v.contract.sensitivityExpectation } })) })),
    scanners: input.scanners.map((s) => ({ id: s.id, status: 'complete',
      returned: orderedVariants.map((e) => ({ case: e.caseId, slot: e.slot, findings: frozen.get(s.id).get(e.variant.fixture.path) })),
      ...(reduced ? {} : { metricCounts: metricCounts.find((m) => m.scanner === s.id) }) })),
  };
  writeFileSync(exportPath, stableJson(exp).replace(/[^\x00-\x7f]/g, (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`));
}
console.log(JSON.stringify(result));
