#!/usr/bin/env node
// Deterministic synthetic performance workloads (P10, issue #11, ADR 0013).
//
// A workload is a handful of GENERATOR PARAMETERS; the data is derived from them here, never
// committed. The output has the same format as the frozen parity input
// (`pii-eval-parity-input/1`, see tools/oracle-parity/make-input.mjs), so the pinned TypeScript
// oracle and the Rust engine consume exactly the same authored cases and the same scanner
// recipes. Same parameters => byte-identical output (the digest is the identity of a workload).
//
// Usage:
//   node tools/perf/make-workload.mjs <params.json | inline-json> <out.json>   writes the input, prints its digest
//   node tools/perf/make-workload.mjs --check <params.json | inline-json>      prints the digest and counts only
//
// Parameters (all integers; defaults in brackets):
//   id            workload name (letters, digits, '-')
//   cases [20]    number of authored cases (the number of generated variants is larger, see counts)
//   koShare [25]  percent of cases whose text is Korean (the rest English); chosen by case index
//   scanners [1]  number of complete synthetic scanners (recipes rotate through the behaviours)
//   findings [1]  findings every scanner reports per variant: the behaviour's own finding(s) plus
//                 overlapping noise findings around the candidate (many overlapping findings axis)
//   padBytes [0]  extra text bytes after the candidate (ASCII for en, Hangul for ko), so that
//                 `findings` overlapping findings can have distinct ranges and text size can vary
// Data policy: every value is a documented synthetic or public-test value (the same set as the
// parity input); no real identifier, no protected corpus.
import { readFileSync, writeFileSync } from 'node:fs';
import { sha256, stableJson } from '../oracle-parity/lib.mjs';

export const SCHEMA = 'pii-eval-perf-workload/1';
const DEFAULTS = { cases: 20, koShare: 25, scanners: 1, findings: 1, padBytes: 0 };
const LIMITS = { cases: 200_000, koShare: 100, scanners: 32, findings: 2000, padBytes: 524_288 };

export function normalize(raw) {
  // A workload file records its parameters under `workload` together with the schema tag; accept that form back.
  const { schema, ...given } = raw;
  if (schema !== undefined && schema !== SCHEMA) throw new Error('unknown workload schema');
  const p = { ...DEFAULTS, ...given };
  if (typeof p.id !== 'string' || !/^[A-Za-z0-9-]{1,64}$/.test(p.id)) throw new Error('id must be 1-64 of [A-Za-z0-9-]');
  for (const k of Object.keys(DEFAULTS)) {
    if (!Number.isInteger(p[k]) || p[k] < (k === 'koShare' || k === 'padBytes' ? 0 : 1) || p[k] > LIMITS[k]) throw new Error(`parameter ${k} out of range`);
  }
  for (const k of Object.keys(p)) if (k !== 'id' && !(k in DEFAULTS)) throw new Error(`unknown parameter ${k}`);
  return { id: p.id, cases: p.cases, koShare: p.koShare, scanners: p.scanners, findings: p.findings, padBytes: p.padBytes };
}

const EMAIL = { family: 'pii:global:email', scope: 'global', identityDomain: 'email', jurisdiction: null };
const SYN = { family: 'pii:global:synthetic-reference', scope: 'global', identityDomain: 'payment-card', jurisdiction: null };
const SSN = { family: 'pii:us:ssn', scope: 'jurisdiction:US', identityDomain: 'national-id', jurisdiction: 'US' };
const BENIGN = ['reserved', 'documentation', 'test-value', 'public-operational', 'placeholder', 'context-negative'];
const benignSetup = (cls) => ({
  reserved: { fam: SSN, value: '000000000', type: 'invalid', validator: 'us-ssn-allocation' },
  documentation: { fam: EMAIL, value: 'person@example.invalid' },
  'test-value': { fam: SYN, value: 'SYNTHETIC-0000' },
  'public-operational': { fam: EMAIL, value: 'postmaster@example.invalid' },
  placeholder: { fam: SYN, value: 'SYNTHETIC-0001', type: 'invalid' },
  'context-negative': { fam: EMAIL, value: 'sample@example.invalid' },
})[cls];

// The kind of case i. The oracle's accounting accepts a context-discrimination case only under the id of one
// of its two committed evidence groups (`en-email-core`, `ko-email-core`; 8 and 11 variants), so those two cases
// are always present (when `cases` >= 2) and every other case is one of the kinds below.
const KINDS = ['so-email', 'so-ssn', 'tv-syn-valid', 'tv-ssn-invalid', 'pb', 'jc-ssn', 'mu-syn', 'rd-syn', 'tv-syn-invalid'];

export function buildCases(p) {
  const cases = [];
  for (let i = 0; i < p.cases; i++) {
    const fixed = p.cases >= 2 && i < 2;
    const kind = fixed ? 'cd' : KINDS[i % KINDS.length];
    const ko = fixed ? i === 1 : (i * 37) % 100 < p.koShare;
    const language = ko ? 'ko' : 'en';
    const id = fixed ? (ko ? 'ko-email-core' : 'en-email-core') : `${p.id}-${String(i).padStart(7, '0')}`;
    const pad = p.padBytes === 0 ? '' : ko ? ' ' + '한'.repeat(Math.ceil(p.padBytes / 3)) : ' ' + 'x'.repeat(p.padBytes);
    const lead = ko ? '값=' : 'value=';
    const o = { id, language, validator: null, type: 'valid', sensitivity: 'not-established', contextClass: 'neutral', obligation: 'none',
      reference: null, accountingClass: null, operator: null, competing: null, contextGroup: null };
    let fam; let value; let method; let prefix = lead;
    switch (kind) {
      case 'so-email': method = 'schema-only'; fam = EMAIL; value = 'person@example.invalid'; o.sensitivity = i % 2 ? 'sensitive' : 'non-sensitive'; o.contextClass = i % 2 ? 'sensitive' : 'non-sensitive'; break;
      case 'so-ssn': method = 'schema-only'; fam = SSN; value = '123-45-6789'; prefix = ko ? '번호=' : 'ssn='; o.sensitivity = 'sensitive'; o.contextClass = 'sensitive'; break;
      case 'tv-syn-valid': method = 'type-validation'; fam = SYN; value = ['SYNTHETIC-1236', 'SYNTHETIC-2248', 'SYNTHETIC-5555'][i % 3]; o.validator = 'synthetic-mod10'; o.sensitivity = 'sensitive'; o.contextClass = 'sensitive'; break;
      case 'tv-syn-invalid': method = 'type-validation'; fam = SYN; value = ['SYNTHETIC-1237', 'SYNTHETIC-9999'][i % 2]; o.validator = 'synthetic-mod10'; o.type = 'invalid'; o.sensitivity = 'non-sensitive'; o.contextClass = 'non-sensitive'; break;
      case 'tv-ssn-invalid': method = 'type-validation'; fam = SSN; value = ['666123456', '123450000'][i % 2]; o.validator = 'us-ssn-allocation'; o.type = 'invalid'; o.sensitivity = 'non-sensitive'; o.contextClass = 'non-sensitive'; prefix = ko ? '번호=' : 'ssn='; break;
      case 'pb': { method = 'pii-benign'; const cls = BENIGN[i % BENIGN.length]; const b = benignSetup(cls);
        fam = b.fam; value = b.value; o.accountingClass = cls; o.sensitivity = 'non-sensitive'; o.contextClass = 'non-sensitive'; if (b.type) o.type = b.type; if (b.validator) o.validator = b.validator; break; }
      case 'jc-ssn': method = 'jurisdiction-collision'; fam = SSN; value = ['111111111', '222222222', '333333333'][i % 3]; o.validator = 'us-ssn-allocation'; o.sensitivity = 'sensitive'; o.contextClass = 'sensitive'; o.competing = ['pii:kr:national-id', 'pii:global:synthetic-reference']; prefix = ko ? '번호=' : 'ssn='; break;
      case 'mu-syn': method = 'mutation'; fam = SYN; value = 'SYNTHETIC-1236'; o.operator = 'invalidate-final-digit'; break;
      case 'rd-syn': method = 'reference-differential'; fam = SYN; value = ['SYNTHETIC-1236', 'SYNTHETIC-1237'][i % 2]; o.reference = { id: 'synthetic-mod10', version: 1 }; o.sensitivity = 'sensitive'; o.contextClass = 'sensitive'; break;
      case 'cd': method = 'context-discrimination'; fam = EMAIL; value = 'subject@example.invalid'; o.obligation = 'required-for-sensitive-classification'; o.contextGroup = ko ? 'ko-email-core' : 'en-email-core'; break;
      default: throw new Error('unreachable');
    }
    cases.push({ id, method, family: fam.family, scope: fam.scope, identityDomain: fam.identityDomain, jurisdiction: fam.jurisdiction,
      language, prefix: `${id}: ${prefix}`, value, suffix: pad, type: o.type, validator: o.validator, sensitivity: o.sensitivity,
      contextClass: o.contextClass, obligation: o.obligation, reference: o.reference, seed: `perf-seed/${id}`, accountingClass: o.accountingClass,
      operator: o.operator, competing: o.competing, contextGroup: o.contextGroup });
  }
  return cases;
}

const f = (o) => ({ ds: 0, de: 0, family: '$family', jurisdiction: '$jurisdiction', sensitive: '$expected', ...o });
const BEHAVIOURS = [
  [f({})], // exact
  [], // miss
  [f({ ds: -2, de: 3 })], // overbroad
  [f({ de: -3 })], // partial
  [f({ family: 'pii:global:phone', jurisdiction: null, sensitive: true })], // wrong family
  [f({ family: 'pii:kr:national-id', jurisdiction: 'KR', sensitive: true })], // wrong jurisdiction
  [f({ sensitive: true })], // flags everything
  [f({ sensitive: false })], // flags nothing
];

// The k-th noise finding: a range overlapping the candidate, distinct for k < 16 * padded width,
// alternating between the expected family, another family and no sensitivity opinion.
function noise(k) {
  const ds = -(1 + (k % 16));
  const de = 1 + Math.floor(k / 16);
  switch (k % 3) {
    case 0: return f({ ds, de });
    case 1: return f({ ds, de, family: 'pii:global:phone', jurisdiction: null, sensitive: k % 2 === 0 });
    default: return f({ ds, de, sensitive: false });
  }
}

export function buildScanners(p) {
  const scanners = [];
  for (let s = 0; s < p.scanners; s++) {
    const cycle = BEHAVIOURS.map((_, j) => {
      const base = BEHAVIOURS[(j + s) % BEHAVIOURS.length];
      const extra = [];
      for (let k = 0; k < p.findings - 1; k++) extra.push(noise(k + s));
      return [...base, ...extra];
    });
    scanners.push({ id: `perf-scanner-${String(s).padStart(2, '0')}`, status: 'complete', recipe: { all: { cycle } } });
  }
  return scanners;
}

export function buildInput(raw) {
  const p = normalize(raw);
  return {
    schema: 'pii-eval-parity-input/1',
    workload: { schema: SCHEMA, ...p },
    population: { id: `perf-${p.id}`, version: 1, visibility: 'public-synthetic' },
    cases: buildCases(p),
    scanners: buildScanners(p),
    accountingVectors: [],
    statistics: { grid: { maxDenominator: 0, mechanics: { intervalZ: '1.96', intervalPrecision: 6 } }, single: [] },
  };
}

export function render(raw) {
  const text = stableJson(buildInput(raw)).replace(/[^\x00-\x7f]/g, (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`);
  return { text, digest: sha256(text) };
}

export const readParams = (arg) => (arg.trim().startsWith('{') ? JSON.parse(arg) : JSON.parse(readFileSync(arg, 'utf8')));

if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const check = args[0] === '--check';
  if (check) args.shift();
  if (args.length < (check ? 1 : 2)) {
    console.error('usage: make-workload.mjs [--check] <params.json|inline-json> [<out.json>]');
    process.exit(2);
  }
  const params = readParams(args[0]);
  const { text, digest } = render(params);
  if (!check) writeFileSync(args[1], text);
  const input = JSON.parse(text);
  console.log(JSON.stringify({ digest, bytes: Buffer.byteLength(text), cases: input.cases.length, scanners: input.scanners.length, params: input.workload }));
}
