#!/usr/bin/env node
// Authoring script for the frozen parity input `fixtures/oracle-parity/input.json`.
//
// The input is the ONLY authored data of the parity harness: synthetic cases (values such as
// `SYNTHETIC-1236` and `person@example.invalid`), scanner recipes (what each synthetic scanner reports,
// relative to the authored candidate range), hand-built accounting vectors and a statistics grid.
// It never holds a real identifier, a protected corpus or scanner output. Nothing in it is changed to
// match an engine: a difference between the two engines is classified, never edited away.
//
// Usage: node tools/oracle-parity/make-input.mjs <out.json>
// The committed file is this script's output; `regenerate.sh` rebuilds it and compares byte for byte.
import { writeFileSync } from 'node:fs';
import { stableJson } from './lib.mjs';

const EMAIL = { family: 'pii:global:email', scope: 'global', identityDomain: 'email', jurisdiction: null };
const SYN = { family: 'pii:global:synthetic-reference', scope: 'global', identityDomain: 'payment-card', jurisdiction: null };
const IBAN = { family: 'pii:global:iban', scope: 'global', identityDomain: 'iban', jurisdiction: null };
const SSN = { family: 'pii:us:ssn', scope: 'jurisdiction:US', identityDomain: 'national-id', jurisdiction: 'US' };

const cases = [];
function add(id, method, fam, prefix, value, suffix, o = {}) {
  cases.push({
    id, method, family: fam.family, scope: fam.scope, identityDomain: fam.identityDomain, jurisdiction: fam.jurisdiction,
    // Every authored text starts with its case id, so that no two variants share a text (a frozen
    // observation can then be keyed by text in the engine end-to-end check).
    language: o.language ?? 'en', prefix: `${id}: ${prefix}`, value, suffix, type: o.type ?? 'valid', validator: o.validator ?? null,
    sensitivity: o.sensitivity ?? 'not-established', contextClass: o.contextClass ?? 'neutral', obligation: o.obligation ?? 'none',
    reference: o.reference ?? null, seed: `parity-seed/${id}`, accountingClass: o.accountingClass ?? null, operator: o.operator ?? null,
    competing: o.competing ?? null, contextGroup: o.contextGroup ?? null,
  });
}

// schema-only
add('so-email-1', 'schema-only', EMAIL, 'contact=', 'person@example.invalid', '', { sensitivity: 'non-sensitive', contextClass: 'non-sensitive' });
add('so-ssn-1', 'schema-only', SSN, 'ssn=', '111111111', '', { sensitivity: 'sensitive', contextClass: 'sensitive' });
add('so-ko-mid', 'schema-only', EMAIL, '연락처=', 'person@example.invalid', ' 끝', { language: 'ko', sensitivity: 'non-sensitive', contextClass: 'non-sensitive' });
// Real-shaped, documented public-test values (an RFC 2606 `.invalid` mailbox and the ordinary dashed
// nine-digit SSN shape with a valid allocation): they give a real scanner something to find in the
// opt-in same-pinned-scanner run (tools/oracle-parity/real-scanner).
add('so-email-2', 'schema-only', EMAIL, 'mail=', 'person@example.invalid', '', { sensitivity: 'sensitive', contextClass: 'sensitive' });
add('so-iban-1', 'schema-only', IBAN, 'iban ', 'DE89370400440532013000', '', { sensitivity: 'sensitive', contextClass: 'sensitive' });
add('so-ssn-dash', 'schema-only', SSN, 'ssn=', '123-45-6789', '', { sensitivity: 'sensitive', contextClass: 'sensitive' });
// type-validation
for (const [i, v] of ['SYNTHETIC-1236', 'SYNTHETIC-2248', 'SYNTHETIC-5555'].entries()) {
  add(`tv-syn-valid-${i + 1}`, 'type-validation', SYN, 'ref=', v, '', { validator: 'synthetic-mod10', type: 'valid', sensitivity: 'sensitive', contextClass: 'sensitive' });
}
for (const [i, v] of ['SYNTHETIC-1237', 'SYNTHETIC-9999'].entries()) {
  add(`tv-syn-invalid-${i + 1}`, 'type-validation', SYN, 'ref=', v, ' tail', { validator: 'synthetic-mod10', type: 'invalid', sensitivity: 'non-sensitive', contextClass: 'non-sensitive' });
}
for (const [i, v] of ['111111111', '123456789'].entries()) {
  add(`tv-ssn-valid-${i + 1}`, 'type-validation', SSN, 'ssn=', v, '', { validator: 'us-ssn-allocation', type: 'valid', sensitivity: 'sensitive', contextClass: 'sensitive' });
}
for (const [i, v] of ['666123456', '123450000'].entries()) {
  add(`tv-ssn-invalid-${i + 1}`, 'type-validation', SSN, 'ssn=', v, '', { validator: 'us-ssn-allocation', type: 'invalid', sensitivity: 'non-sensitive', contextClass: 'non-sensitive' });
}
add('tv-unavailable', 'type-validation', SYN, 'ref=', 'SYNTHETIC-1236', '', { validator: 'unavailable-test', type: 'valid', sensitivity: 'sensitive', contextClass: 'sensitive' });
// context-discrimination (the oracle's real groups)
add('en-email-core', 'context-discrimination', EMAIL, 'value=', 'subject@example.invalid', '', { obligation: 'required-for-sensitive-classification', contextGroup: 'en-email-core' });
add('ko-email-core', 'context-discrimination', EMAIL, '값=', 'subject@example.invalid', '', { language: 'ko', obligation: 'required-for-sensitive-classification', contextGroup: 'ko-email-core' });
// pii-benign (one variant per case: the oracle refuses several)
const benign = { sensitivity: 'non-sensitive', contextClass: 'non-sensitive' };
add('pb-reserved', 'pii-benign', SSN, 'ssn=', '000000000', '', { ...benign, type: 'invalid', validator: 'us-ssn-allocation', accountingClass: 'reserved' });
add('pb-documentation', 'pii-benign', EMAIL, 'mail=', 'person@example.invalid', '', { ...benign, accountingClass: 'documentation' });
add('pb-test-value', 'pii-benign', SYN, 'ref=', 'SYNTHETIC-0000', '', { ...benign, accountingClass: 'test-value' });
add('pb-public-operational', 'pii-benign', EMAIL, 'mail=', 'postmaster@example.invalid', '', { ...benign, accountingClass: 'public-operational' });
add('pb-placeholder', 'pii-benign', SYN, 'ref=', 'SYNTHETIC-0001', '', { ...benign, type: 'invalid', accountingClass: 'placeholder' });
add('pb-context-negative', 'pii-benign', EMAIL, 'example ', 'sample@example.invalid', '', { ...benign, accountingClass: 'context-negative' });
// jurisdiction-collision
for (let i = 1; i <= 3; i++) {
  add(`jc-ssn-${i}`, 'jurisdiction-collision', SSN, 'ssn=', ['111111111', '222222222', '333333333'][i - 1], '', {
    validator: 'us-ssn-allocation', sensitivity: 'sensitive', contextClass: 'sensitive', competing: ['pii:kr:national-id', 'pii:global:synthetic-reference'],
  });
}
for (let i = 1; i <= 2; i++) {
  add(`jc-syn-${i}`, 'jurisdiction-collision', SYN, 'ref=', ['SYNTHETIC-1236', 'SYNTHETIC-2248'][i - 1], '', {
    validator: 'synthetic-mod10', sensitivity: 'sensitive', contextClass: 'sensitive', competing: ['pii:us:ssn'],
  });
}
// mutation
add('mu-syn-1', 'mutation', SYN, 'ref=', 'SYNTHETIC-1236', '', { operator: 'invalidate-final-digit' });
add('mu-syn-wrap', 'mutation', SYN, 'ref=', 'SYNTHETIC-1239', ' tail', { sensitivity: 'sensitive', contextClass: 'sensitive', operator: 'invalidate-final-digit' });
add('mu-ssn-1', 'mutation', SSN, '번호=', '111111119', '', { language: 'ko', validator: 'us-ssn-allocation', operator: 'invalidate-final-digit' });
add('mu-ssn-2', 'mutation', SSN, 'ssn=', '123456789', '', { sensitivity: 'sensitive', contextClass: 'sensitive', operator: 'invalidate-final-digit' });
// reference-differential
const ref = (id) => ({ id, version: 1 });
add('rd-agree', 'reference-differential', SYN, 'ref=', 'SYNTHETIC-1236', '', { reference: ref('synthetic-mod10'), sensitivity: 'sensitive', contextClass: 'sensitive' });
add('rd-disagree', 'reference-differential', SYN, 'ref=', 'SYNTHETIC-1237', '', { reference: ref('synthetic-mod10'), sensitivity: 'sensitive', contextClass: 'sensitive' });
add('rd-unavailable', 'reference-differential', SYN, 'ref=', 'SYNTHETIC-1236', '', { reference: ref('unavailable-test'), sensitivity: 'sensitive', contextClass: 'sensitive' });
add('rd-ssn', 'reference-differential', SSN, 'ssn=', '111111111', '', { reference: ref('us-ssn-allocation'), sensitivity: 'sensitive', contextClass: 'sensitive' });

// ---------------------------------------------------------------------------------------------
// Scanner recipes. A recipe is an ordered list of rules; the first rule whose `when` matches a
// generated variant decides the findings reported for it, in the order listed. Offsets are relative to
// the variant's candidate range, clamped to the text and snapped to character boundaries (`raw: true`
// keeps the offset as given: the `parity-midchar` scanner uses it on purpose). Tokens: family "$family" is the case's
// family; jurisdiction "$jurisdiction" is the case's jurisdiction (omitted for global cases);
// sensitive "$expected" is true exactly when the variant's authored sensitivity is "sensitive".
// ---------------------------------------------------------------------------------------------
const f = (o) => ({ ds: 0, de: 0, family: '$family', jurisdiction: '$jurisdiction', sensitive: '$expected', ...o });
const none = (o) => { const x = f(o); for (const k of Object.keys(o)) if (o[k] === null) delete x[k]; return x; };
const B = {
  exact: [f({})],
  miss: [],
  over: [f({ ds: -2, de: 3 })],
  part: [f({ de: -3 })],
  wrongfam: [f({ family: 'pii:global:phone', jurisdiction: null, sensitive: true })],
  wrongjur: [f({ family: 'pii:kr:national-id', jurisdiction: 'KR', sensitive: true })],
  nojur: [none({ jurisdiction: null })],
  nofam: [none({ family: null, jurisdiction: null })],
  flagall: [f({ sensitive: true })],
  noflag: [f({ sensitive: false })],
  nosens: [none({ sensitive: null })],
};
const M = [
  [f({ ds: -4, de: 4, family: 'pii:global:phone', jurisdiction: null, sensitive: false }), f({})],
  [f({}), f({ ds: -4, de: 4, family: 'pii:global:phone', jurisdiction: null, sensitive: false })],
  [f({ de: -3 }), f({ ds: -2, de: 2 })],
  [f({}), f({})],
  [none({ sensitive: null }), f({})],
  [f({ family: 'pii:global:phone', jurisdiction: null, sensitive: true }), f({})],
  [f({ ds: -1, de: 1 }), f({ ds: -1, de: 3 })],
  [none({ sensitive: null })],
  [f({ de: -3 }), f({ ds: 3 })],
  [f({ ds: -1, de: 1, sensitive: false }), f({ ds: -1, de: 1 })],
];

// The variants a scanner is asked about are known only after generation (frame ids are the oracle's);
// recipes are therefore expressed per CASE with a behaviour list cycled over the case's variants in
// ascending slot order, and are expanded to explicit per-variant rules by the export driver, which
// records the expansion in the export (so both engines read the same frozen findings).
const cycle = (names) => ({ cycle: names.map((n) => (typeof n === 'string' ? B[n] : n)) });
const scanners = [
  { id: 'parity-baseline', status: 'complete', recipe: { all: cycle(['exact']) } },
  { id: 'parity-mixed', status: 'complete', recipe: { all: cycle(['exact', 'miss', 'over', 'part', 'wrongfam', 'wrongjur', 'nojur', 'nofam', 'flagall', 'noflag', 'nosens']) } },
  { id: 'parity-multi', status: 'complete', recipe: { all: cycle(M) } },
  { id: 'parity-nosens', status: 'complete', recipe: { all: cycle(['nosens']) } },
  { id: 'parity-midchar', status: 'complete', recipe: { all: cycle(['exact']), cases: { 'so-ko-mid': cycle([[f({ ds: -2, raw: true })]]) } } },
  { id: 'parity-unsupported', status: 'unsupported', recipe: {} },
  { id: 'parity-error', status: 'error', recipe: {} },
  { id: 'parity-unavailable', status: 'unavailable', recipe: {} },
  { id: 'parity-unstable', status: 'unstable', recipe: { all: cycle(['exact']) } },
  { id: 'parity-badrange', status: 'complete', recipe: { all: cycle(['exact']), cases: { 'tv-syn-valid-1': cycle([[f({ de: -14 })]]) } } },
];

// ---------------------------------------------------------------------------------------------
// Hand-built accounting vectors: rows are fed straight to the accounting of each engine (the oracle's
// exported `accountPiiRows`). Case ids and variant slots use [a-z0-9-] only, so the oracle's
// locale-dependent `localeCompare` agrees with a byte-wise comparison (ICU orders hyphen, digits,
// lowercase letters in byte order).
// ---------------------------------------------------------------------------------------------
const row = (slot, type, sens, ts, ss, range, extra = {}) => ({ slot, type, sensitivity: sens, typeState: ts, sensitivityState: ss, range, contextClass: 'neutral', ...extra });
const vc = (id, method, scope, variants, extra = {}) => ({ id, method, scope, variants, ...extra });
const G = 'global';
const US = 'jurisdiction:US';
const vectors = [
  { id: 'uniform', note: 'six single-variant cases: every bucket rule, withheld states from small effective N', scanner: 'complete', cases: [
    vc('t1', 'type-validation', G, [row('v1', 'valid', 'sensitive', 'miss', 'miss', 'miss')]),
    vc('t2', 'type-validation', G, [row('v1', 'valid', 'sensitive', 'correct', 'correct', 'exact')]),
    vc('t3', 'type-validation', G, [row('v1', 'valid', 'sensitive', 'wrong-family', 'correct', 'partial')]),
    vc('t4', 'type-validation', G, [row('v1', 'valid', 'non-sensitive', 'correct', 'false-positive', 'overbroad')]),
    vc('b1', 'pii-benign', G, [row('v1', 'invalid', 'non-sensitive', 'invalid-correct', 'correct', 'miss')], { controlClass: 'placeholder' }),
    vc('b2', 'pii-benign', G, [row('v1', 'invalid', 'non-sensitive', 'invalid-accepted', 'false-positive', 'exact')], { controlClass: 'reserved' }),
  ] },
  { id: 'jurisdiction-rates', note: 'jurisdictional cases: wrong-jurisdiction and collision populations', scanner: 'complete', cases: [
    vc('j1', 'type-validation', US, [row('v1', 'valid', 'sensitive', 'correct', 'correct', 'exact')]),
    vc('j2', 'type-validation', US, [row('v1', 'valid', 'sensitive', 'wrong-jurisdiction', 'correct', 'exact')]),
    vc('j3', 'type-validation', US, [row('v1', 'valid', 'sensitive', 'wrong-family', 'miss', 'partial')]),
    vc('j4', 'type-validation', US, [row('v1', 'valid', 'sensitive', 'correct', 'correct', 'overbroad')]),
    vc('k1', 'jurisdiction-collision', US, [row('v1', 'valid', 'sensitive', 'correct', 'correct', 'exact')], { collision: true }),
    vc('k2', 'jurisdiction-collision', US, [row('v1', 'valid', 'sensitive', 'wrong-jurisdiction', 'correct', 'exact')], { collision: true }),
    vc('k3', 'jurisdiction-collision', US, [row('v1', 'valid', 'sensitive', 'wrong-family', 'miss', 'miss')], { collision: true }),
    vc('k4', 'jurisdiction-collision', US, [row('v1', 'valid', 'sensitive', 'correct', 'correct', 'exact')], { collision: true }),
  ] },
  { id: 'a2-invalid-variant-sorts-first', note: 'A2: a valid group whose first variant (by id) is invalid is not applicable to the valid-type metrics in the oracle', scanner: 'complete', cases: [
    vc('m1', 'type-validation', G, [row('a-invalid', 'invalid', 'non-sensitive', 'invalid-correct', 'correct', 'miss'), row('b-valid', 'valid', 'sensitive', 'miss', 'miss', 'miss')]),
    vc('m2', 'type-validation', G, [row('a-valid', 'valid', 'sensitive', 'correct', 'correct', 'exact'), row('b-invalid', 'invalid', 'non-sensitive', 'invalid-accepted', 'false-positive', 'overbroad')]),
    vc('m3', 'type-validation', G, [row('a-valid', 'valid', 'sensitive', 'correct', 'correct', 'exact')]),
    vc('m4', 'type-validation', G, [row('a-valid', 'valid', 'sensitive', 'miss', 'miss', 'miss')]),
    vc('m5', 'type-validation', G, [row('a-valid', 'valid', 'sensitive', 'wrong-family', 'correct', 'partial')]),
  ] },
  { id: 'a2-not-measured-invalid-variant', note: 'A2: a not-measured invalid variant turns a valid group not-measured in the oracle', scanner: 'complete', cases: [
    vc('n1', 'type-validation', G, [row('a-valid', 'valid', 'sensitive', 'correct', 'correct', 'exact'), row('b-invalid', 'invalid', 'non-sensitive', 'not-measured', 'correct', 'miss')]),
    vc('n2', 'type-validation', G, [row('a-valid', 'valid', 'sensitive', 'miss', 'miss', 'miss')]),
    vc('n3', 'type-validation', G, [row('a-valid', 'valid', 'sensitive', 'correct', 'correct', 'exact')]),
    vc('n4', 'type-validation', G, [row('a-valid', 'valid', 'sensitive', 'correct', 'correct', 'exact')]),
  ] },
  { id: 'a3-benign-two-variants', note: 'A3: the oracle throws on a benign case with several variants', scanner: 'complete', cases: [
    vc('p1', 'pii-benign', G, [row('v1', 'invalid', 'non-sensitive', 'invalid-correct', 'correct', 'miss'), row('v2', 'invalid', 'non-sensitive', 'invalid-correct', 'false-positive', 'exact')], { controlClass: 'placeholder' }),
  ] },
  { id: 'a8-collision-any-versus-all', note: 'A8: a collision case counts when ANY row passes in the oracle; ALL rows in the canonical accounting', scanner: 'complete', cases: [
    vc('q1', 'jurisdiction-collision', US, [row('v1', 'valid', 'sensitive', 'correct', 'correct', 'exact'), row('v2', 'valid', 'sensitive', 'correct', 'correct', 'exact')], { collision: true }),
    vc('q2', 'jurisdiction-collision', US, [row('v1', 'valid', 'sensitive', 'correct', 'correct', 'exact'), row('v2', 'valid', 'sensitive', 'wrong-jurisdiction', 'correct', 'exact')], { collision: true }),
    vc('q3', 'jurisdiction-collision', US, [row('v1', 'valid', 'sensitive', 'wrong-family', 'correct', 'exact'), row('v2', 'valid', 'sensitive', 'wrong-jurisdiction', 'correct', 'exact')], { collision: true }),
    vc('q4', 'jurisdiction-collision', US, [row('v1', 'valid', 'sensitive', 'correct', 'correct', 'exact'), row('v2', 'valid', 'sensitive', 'correct', 'correct', 'exact'), row('v3', 'valid', 'sensitive', 'correct', 'correct', 'exact')], { collision: true }),
  ] },
  { id: 'unresolved-and-not-measured', note: 'review-required sensitivity (not-established), not-measured axes and a not-applicable range of a complete scanner', scanner: 'complete', cases: [
    vc('u1', 'type-validation', G, [row('v1', 'valid', 'not-established', 'correct', 'unresolved', 'exact')]),
    vc('u2', 'type-validation', G, [row('v1', 'valid', 'not-established', 'miss', 'unresolved', 'miss')]),
    vc('u3', 'type-validation', G, [row('v1', 'valid', 'sensitive', 'not-measured', 'not-measured', 'exact')]),
    vc('u4', 'type-validation', G, [row('v1', 'valid', 'sensitive', 'correct', 'correct', 'not-applicable')]),
    vc('u5', 'type-validation', G, [row('v1', 'valid', 'non-sensitive', 'correct', 'correct', 'exact')]),
    vc('u6', 'type-validation', G, [row('v1', 'valid', 'sensitive', 'wrong-family', 'miss', 'overbroad')]),
  ] },
  { id: 'all-not-applicable', note: 'a population with no valid type, no sensitive occurrence and no jurisdiction: zero denominators', scanner: 'complete', cases: [
    vc('z1', 'type-validation', G, [row('v1', 'invalid', 'non-sensitive', 'invalid-correct', 'correct', 'miss')]),
    vc('z2', 'type-validation', G, [row('v1', 'invalid', 'non-sensitive', 'invalid-accepted', 'false-positive', 'exact')]),
  ] },
];

// Statistics grid: the oracle's `proportion` on every (numerator, denominator) with denominator up to
// 24, both directions, at the pii-v1 mechanics, plus single vectors at other precisions and large counts.
const statistics = {
  grid: { maxDenominator: 24, mechanics: { minDenominator: 4, intervalZ: '1.96', intervalPrecision: 6 } },
  single: [
    { numerator: 3, denominator: 20, direction: 'upper', intervalZ: '1.96', intervalPrecision: 1 },
    { numerator: 7, denominator: 20, direction: 'upper', intervalZ: '1.96', intervalPrecision: 1 },
    { numerator: 1, denominator: 128, direction: 'upper', intervalZ: '1.96', intervalPrecision: 6 },
    { numerator: 1, denominator: 128, direction: 'lower', intervalZ: '1.96', intervalPrecision: 6 },
    { numerator: 127, denominator: 128, direction: 'upper', intervalZ: '1.96', intervalPrecision: 6 },
    { numerator: 0, denominator: 1000, direction: 'upper', intervalZ: '1.96', intervalPrecision: 12 },
    { numerator: 1000, denominator: 1000, direction: 'lower', intervalZ: '1.96', intervalPrecision: 12 },
    { numerator: 500000000, denominator: 1000000000, direction: 'upper', intervalZ: '1.96', intervalPrecision: 12 },
    { numerator: 1, denominator: 1000000000000, direction: 'upper', intervalZ: '1.96', intervalPrecision: 12 },
    { numerator: 3, denominator: 8, direction: 'lower', intervalZ: '1', intervalPrecision: 3 },
    { numerator: 1, denominator: 4, direction: 'upper', intervalZ: '2.5', intervalPrecision: 2 },
    { numerator: 5, denominator: 8, direction: 'upper', intervalZ: '1.96', intervalPrecision: 2 },
  ],
};

const input = {
  schema: 'pii-eval-parity-input/1',
  note: 'Synthetic only. Authored by tools/oracle-parity/make-input.mjs; never edited to match an engine.',
  population: { id: 'parity-synthetic', version: 1, visibility: 'public-synthetic' },
  cases,
  scanners,
  accountingVectors: vectors,
  statistics,
};
writeFileSync(process.argv[2], stableJson(input));
