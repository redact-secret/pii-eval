#!/usr/bin/env node
// Run the pinned oracle's OWN code on the frozen parity input and export what it did.
//
// Usage (Node >= 22.6, see README.md; `regenerate.sh` runs exactly this):
//   node --experimental-strip-types --no-warnings --import ./register.mjs \
//        export-oracle.mjs <oracle-root> <input.json> <out.json> [<real-core-install-dir>]
// With the fourth argument the synthetic scanners are replaced by the REAL pinned scanner (see
// real-scanner/README.md): the oracle's own `loadCandidate` runs `@redact-secret/core` 0.1.0-beta.12 from a
// hermetic install and only the observation and the oracle's outcomes and accounting are exported.
// where <oracle-root> is `<scratch>/oracle` written by fetch-oracle.mjs.
//
// The oracle code that runs is, unmodified and at the pinned commit: the seven methods, the operators and
// validators, `executePiiEvaluation` (generation, scanner runtime with replays and failure states,
// outcome interpretation `interpretPiiOutcome`), `piiAccountingRowsFromEvaluation`, `accountPiiRows`
// (the ten metrics) and `proportion` (the Wilson interval). Only module loading is adapted (hooks.mjs):
// Ajv and the benign/collision evidence loader are stubs. Nothing is computed by the Rust side here.
//
// The output has only integers and strings (no floats, no timestamps, no host paths) and sorted keys,
// so a rerun with the same oracle, Node version and input is byte-identical.
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { onDiskTreeDigest, sha256, stableJson } from './lib.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const [, , root, inputPath, outPath, realRoot] = process.argv;
if (!root || !inputPath || !outPath) {
  console.error('usage: export-oracle.mjs <oracle-root> <input.json> <out.json>');
  process.exit(2);
}
const spec = JSON.parse(readFileSync(join(HERE, 'oracle-files.json'), 'utf8'));
const treeDigest = onDiskTreeDigest(root, spec);
if (treeDigest !== spec.treeDigest) throw new Error(`the oracle files under ${root} are not the pinned files (tree digest ${treeDigest})`);
const inputBytes = readFileSync(inputPath);
const input = JSON.parse(inputBytes.toString('utf8'));
if (input.schema !== 'pii-eval-parity-input/1') throw new Error('unknown input schema');

const imp = (p) => import(pathToFileURL(resolve(root, p)).href);
const D = 'benchmarks/evaluation/domains/pii';
const { createRegistry } = await imp('benchmarks/evaluation/substrate/registry.ts');
const { createPiiValidators } = await imp(`${D}/validators.ts`);
const { createPiiOperators } = await imp(`${D}/operators.ts`);
const { executePiiEvaluation, PII_ENGINE_VERSION } = await imp(`${D}/execution.ts`);
const { accountPiiRows, piiAccountingRowsFromEvaluation } = await imp(`${D}/accounting.ts`);
const { PII_METRIC_IDS, piiV1Profile } = await imp(`${D}/profile.ts`);
const { proportion } = await imp('benchmarks/accounting/shared/primitives.ts');
const { piiTypeStatus, piiSensitivityStatus } = await imp(`${D}/outcome-validation.ts`);
const methodFile = async (f) => imp(`${D}/methods/${f}.ts`);
const { schemaOnly } = await methodFile('schema-only');
const { typeValidation } = await methodFile('type-validation');
const { contextDiscrimination } = await methodFile('context-discrimination');
const { piiBenign } = await methodFile('benign');
const { jurisdictionCollision } = await methodFile('jurisdiction-collision');
const { mutation } = await methodFile('mutation');
const { referenceDifferential } = await methodFile('reference-differential');

// methods/index.ts is not loaded (it imports the real evidence loader); the registry is assembled here
// from the unmodified method files, exactly as methods/index.ts does.
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
    provenance: { source: 'synthetic/parity', sourceHash: 'a'.repeat(64), seed: c.seed, rationale: 'synthetic parity case', sources: ['synthetic'] },
    ...(Object.keys(metadata).length ? { metadata } : {}),
  };
}
const piiCases = input.cases.map(piiCase);
const authored = new Map(input.cases.map((c) => [c.id, c]));

// What the oracle's methods generate, for the record and to expand the scanner recipes.
const generated = piiCases.map((c) => ({ c, variants: methods.get(c.method).generate(c) }));
const variantsOf = new Map(); // path -> {case, slot, variant}
for (const { c, variants } of generated) for (const v of variants) variantsOf.set(v.fixture.path, { caseId: c.id, slot: v.id, variant: v });
const orderedVariants = [...variantsOf.values()].sort((a, b) => (a.caseId < b.caseId ? -1 : a.caseId > b.caseId ? 1 : a.slot < b.slot ? -1 : a.slot > b.slot ? 1 : 0));

// ---- scanner recipes -> frozen findings, per variant, in emission order ----
function resolveFinding(t, entry) {
  const c = authored.get(entry.caseId);
  const v = entry.variant;
  const bytes = Buffer.from(v.fixture.content);
  const len = bytes.length;
  let start = Math.max(0, Math.min(len, v.candidate.start + t.ds));
  let end = Math.max(0, Math.min(len, v.candidate.end + t.de));
  if (!t.raw) {
    // Offsets are snapped to UTF-8 character boundaries (start backwards, end forwards) so that a
    // recipe never produces a range inside a character by accident; `raw: true` keeps it as given.
    const continuation = (i) => i > 0 && i < len && (bytes[i] & 0xc0) === 0x80;
    while (continuation(start)) start -= 1;
    while (continuation(end)) end += 1;
  }
  const out = { start, end };
  const family = t.family === '$family' ? c.family : t.family;
  if (family !== null && family !== undefined) out.family = family;
  const jurisdiction = t.jurisdiction === '$jurisdiction' ? c.jurisdiction : t.jurisdiction;
  if (jurisdiction !== null && jurisdiction !== undefined) out.jurisdiction = jurisdiction;
  const sensitive = t.sensitive === '$expected' ? v.contract.sensitivityExpectation === 'sensitive' : t.sensitive;
  if (sensitive !== null && sensitive !== undefined) out.sensitive = sensitive;
  return out;
}
const frozen = new Map(); // scanner id -> Map(path -> findings)
for (const s of input.scanners) {
  const byPath = new Map();
  const perCase = new Map();
  let i = 0;
  for (const entry of orderedVariants) {
    const override = s.recipe.cases?.[entry.caseId];
    const rule = override ?? s.recipe.all;
    let templates = [];
    if (rule) {
      const index = override ? (perCase.get(entry.caseId) ?? 0) : i;
      templates = rule.cycle[index % rule.cycle.length];
    }
    if (override) perCase.set(entry.caseId, (perCase.get(entry.caseId) ?? 0) + 1);
    i += 1;
    byPath.set(entry.variant.fixture.path, templates.map((t) => resolveFinding(t, entry)));
  }
  frozen.set(s.id, byPath);
}

// ---- RuntimeScanner objects over the frozen findings ----
function runtimeScanner(s) {
  const byPath = frozen.get(s.id);
  let calls = 0;
  return {
    id: s.id, mode: 'test', configuration: { frozen: true, id: s.id },
    capabilities: s.status === 'unsupported' ? { ranges: false, classification: true } : undefined,
    async version() {
      if (s.status === 'unavailable') throw new Error('unavailable');
      return '1.0.0';
    },
    async scan(_dir, inputs) {
      calls += 1;
      if (s.status === 'error') throw new Error('scan failed');
      if (s.status === 'unstable' && calls % 2 === 0) return [];
      return inputs.flatMap((input) => (byPath.get(input.path) ?? []).map((f) => ({ path: input.path, ...f })));
    },
  };
}

// ---- the real scanner (opt-in mode): the oracle's own candidate adapter over a hermetic install ----
const REAL_ID = 'redact-secret-core';
const REAL_SELECTORS = ['pii:global', 'pii:us'];
let scannerSpecs = input.scanners;
let scanners = input.scanners.map(runtimeScanner);
if (realRoot) {
  const { loadCandidate } = await imp('scanners/candidate.mjs');
  const loaded = await loadCandidate({ root: resolve(realRoot), declaredVersion: '0.1.0-beta.12' }, null, { pii: REAL_SELECTORS });
  const captured = new Map();
  frozen.set(REAL_ID, captured);
  scannerSpecs = [{ id: REAL_ID, status: 'complete' }];
  // Same wrapper as the oracle's PII observer (scripts/observe-pii-populations.mjs): only PII findings are observations.
  scanners = [{
    id: REAL_ID, mode: 'candidate', capabilities: { ranges: true, classification: true },
    configuration: { adapter: REAL_ID, findings: 'pii-domain-only', requestedSelectors: REAL_SELECTORS },
    async version() { return loaded.version; },
    async scan(directory, fixtures) {
      const found = (await loaded.scan(directory, fixtures)).filter((f) => typeof f.family === 'string' && f.family.startsWith('pii:'));
      captured.clear();
      for (const f of found) {
        const { path, start, end, family, jurisdiction, sensitive } = f;
        if (!captured.has(path)) captured.set(path, []);
        captured.get(path).push({ start, end, family, ...(jurisdiction ? { jurisdiction } : {}), ...(typeof sensitive === 'boolean' ? { sensitive } : {}) });
      }
      return found;
    },
  }];
}

const RUN_ID = '00000000-0000-4000-8000-000000000001';
const artifact = await executePiiEvaluation({ cases: piiCases, methods, scanners, runId: RUN_ID });

// ---- export helpers ----
const places = (n) => n;
const rateOf = (r, p = 6) => r === null ? { kind: 'null' } : r === 'insufficient-evidence' ? { kind: 'insufficient-evidence' }
  : { kind: 'value', point: r.point.toFixed(places(p)), bound: r.bound === null ? null : r.bound.toFixed(places(p)), n: r.n, direction: r.direction };
const metricsOf = (report) => Object.fromEntries(PII_METRIC_IDS.map((id) => {
  const m = report.metrics[id];
  return [id, { status: m.status, counts: { ...m.counts }, effectiveN: m.effectiveN, direction: m.direction, rate: rateOf(m.rate) }];
}));
const accountingOf = (report) => ({ rowCount: report.rowCount, sourceCaseCount: report.sourceCaseCount, metrics: metricsOf(report) });

const outcomeOf = (o) => ({
  type: { state: o.typeIdentity.state, status: o.typeIdentity.status }, sensitivity: { state: o.sensitivityContext.state, status: o.sensitivityContext.status },
  range: o.range, observed: { findingCount: o.observed.findingCount, families: [...o.observed.families], jurisdictions: [...o.observed.jurisdictions] },
});

const caseExport = generated.map(({ c, variants }) => {
  const result = artifact.results.find((r) => r.id === c.id);
  return {
    id: c.id, method: c.method, methodVersion: variants[0].transformation.methodVersion, family: c.contract.family, scope: c.contract.scope,
    language: c.contract.context.language,
    variants: variants.map((v) => {
      const rv = result.variants.find((x) => x.id === v.id);
      return { slot: v.id, strategy: v.strategy, text: v.fixture.content, candidate: { ...v.candidate }, operator: v.transformation.operator,
        operatorVersion: v.transformation.operatorVersion, expectation: { ...rv.expectation } };
    }),
  };
});

const scannerExport = scannerSpecs.map((s) => {
  const observation = artifact.scanners.find((x) => x.id === s.id);
  const rows = piiAccountingRowsFromEvaluation(artifact, s.id);
  const report = accountPiiRows(rows);
  const returned = orderedVariants.map((e) => ({ case: e.caseId, slot: e.slot, findings: frozen.get(s.id).get(e.variant.fixture.path) ?? [] }));
  const outcomes = orderedVariants.map((e) => {
    const result = artifact.results.find((r) => r.id === e.caseId);
    const o = result.outcomes.find((x) => x.scanner === s.id && x.variant === e.slot);
    return { case: e.caseId, slot: e.slot, ...outcomeOf(o) };
  });
  return {
    id: s.id, declaredStatus: s.status, status: observation.status,
    replays: observation.replays ? { count: observation.replays.count, agreed: observation.replays.agreed, divergentPaths: (observation.replays.divergentPaths ?? []).length } : undefined,
    returned, outcomes, accounting: accountingOf(report),
  };
});

// ---- hand-built accounting vectors ----
const vsource = { schemaVersion: 1, engineVersion: PII_ENGINE_VERSION, domain: 'pii', reportProfile: { id: 'pii-evaluation', version: 1 },
  evaluationProfile: 'pii-schema-v1', domainAccountingVersion: 'pii-observation-v1', runId: '00000000-0000-4000-8000-000000000002',
  startedAt: '2026-01-01T00:00:00.000Z', finishedAt: '2026-01-01T00:00:01.000Z',
  provenance: { sourceRevision: null, candidateArtifactHash: null, planHash: null },
  scanner: { id: 'vector-scanner', version: '1.0.0', mode: 'test', configurationHash: 'b'.repeat(64), status: 'complete' } };
function vectorRows(v) {
  return v.cases.flatMap((c) => {
    const family = c.scope === 'global' ? 'pii:global:email' : 'pii:us:ssn';
    return c.variants.map((r) => ({
      source: vsource, caseId: c.id, method: c.method, family, scope: c.scope, variant: r.slot, strategy: 'authored', scanner: 'vector-scanner',
      qualificationProfile: { id: 'pii-v1', version: 1 }, authority,
      expectation: { type: r.type, sensitivity: r.sensitivity, contextObligation: 'none', contextClass: r.contextClass, language: 'en', validatorApplicable: false, referenceApplicable: false },
      methodEvidence: { evidenceClass: null, controlClass: c.controlClass ?? null, validatorEvidence: [], validatorState: null,
        collision: c.collision ? { targetFamily: family, competingFamilies: ['pii:global:phone'] } : null, referenceState: null },
      outcome: { scanner: 'vector-scanner', variant: r.slot,
        typeIdentity: { axis: 'type-identity', status: piiTypeStatus(r.typeState), state: r.typeState, reason: 'x' },
        sensitivityContext: { axis: 'sensitivity-context', status: piiSensitivityStatus(r.sensitivityState), state: r.sensitivityState, reason: 'x' },
        range: r.range, observed: { findingCount: 0, families: [], jurisdictions: [] } },
    }));
  });
}
const vectorExport = input.accountingVectors.map((v) => {
  try {
    return { id: v.id, accounting: accountingOf(accountPiiRows(vectorRows(v))) };
  } catch (error) {
    return { id: v.id, throws: String(error.message) };
  }
});

// ---- statistics ----
const mech = (z, p) => ({ ...piiV1Profile.mechanics, intervalZ: Number(z), intervalPrecision: p });
const stat = (k, n, direction, z, p) => ({ numerator: k, denominator: n, direction, intervalZ: z, intervalPrecision: p, rate: rateOf(proportion(k, n, direction, mech(z, p)), p) });
const grid = [];
for (let n = 1; n <= input.statistics.grid.maxDenominator; n++) for (let k = 0; k <= n; k++) for (const d of ['upper', 'lower']) {
  grid.push(stat(k, n, d, input.statistics.grid.mechanics.intervalZ, input.statistics.grid.mechanics.intervalPrecision));
}
const singles = input.statistics.single.map((s) => stat(s.numerator, s.denominator, s.direction, s.intervalZ, s.intervalPrecision));

// ---- provenance ----
const scriptFiles = ['export-oracle.mjs', 'hooks.mjs', 'register.mjs', 'lib.mjs', 'make-input.mjs', 'oracle-files.json', 'stubs/ajv.mjs', 'stubs/benign-collision-evidence.mjs'];
const out = {
  schema: 'pii-eval-oracle-export/1',
  provenance: {
    oracle: { repository: 'redact-secret/redact-secret-benchmarks', commit: spec.pin, fileCount: spec.files.length, filesTreeDigest: treeDigest, engineVersion: PII_ENGINE_VERSION,
      profile: { id: piiV1Profile.id, version: piiV1Profile.version } },
    runtime: { node: process.version, icu: process.versions.icu, unicode: process.versions.unicode },
    adaptations: ['ajv replaced by a stub that accepts every document', 'benign-collision-evidence.ts replaced by a stub (no entries)', 'json imports without attributes loaded as JSON modules'],
    scripts: Object.fromEntries(scriptFiles.map((f) => [f, sha256(readFileSync(join(HERE, f)))])),
    inputSha256: sha256(inputBytes),
  },
  mechanics: { minDenominator: piiV1Profile.mechanics.minDenominator, replays: piiV1Profile.mechanics.replays, intervalZ: '1.96', intervalPrecision: piiV1Profile.mechanics.intervalPrecision },
  cases: caseExport,
  scanners: scannerExport,
  accountingVectors: vectorExport,
  statistics: { grid, singles },
};
function realProvenance() {
  const lockText = readFileSync(join(realRoot, 'package-lock.json'));
  const lock = JSON.parse(lockText.toString('utf8'));
  const packages = Object.keys(lock.packages).filter((n) => n.startsWith('node_modules/@redact-secret/')).sort().map((name) => {
    let installed = null;
    try { installed = JSON.parse(readFileSync(join(realRoot, name, 'package.json'), 'utf8')).version; } catch { /* not installed for this platform */ }
    return { name: name.replace('node_modules/', ''), lockVersion: lock.packages[name].version, integrity: lock.packages[name].integrity, installedVersion: installed };
  });
  return {
    package: '@redact-secret/core', version: '0.1.0-beta.12', platform: `${process.platform}-${process.arch}`, lockSha256: sha256(lockText), packages,
    install: 'npm ci --ignore-scripts from a lockfile of the oracle lockfile @redact-secret entries (real-scanner/make-lock.mjs)',
    adapter: 'the oracle scanners/candidate.mjs loadCandidate with the wrapper of scripts/observe-pii-populations.mjs (family prefix pii: only)',
    selectors: REAL_SELECTORS,
  };
}
const final = realRoot
  ? { schema: 'pii-eval-real-scanner-export/1', provenance: { ...out.provenance, realScanner: realProvenance() }, cases: caseExport, scanners: scannerExport }
  : out;
// Non-ASCII characters are written as \u escapes so that invisible characters are reviewable.
const text = stableJson(final).replace(/[^\x00-\x7f]/g, (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`);
writeFileSync(outPath, text);
console.log(`exported ${caseExport.length} cases, ${scannerExport.length} scanners${realRoot ? ' (real scanner)' : `, ${vectorExport.length} vectors, ${grid.length + singles.length} statistics vectors`}`);
