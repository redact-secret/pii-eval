// Oracle driver for the P5 compatibility vectors (crates/pii-eval-kernel/tests/vectors/oracle_methods.rs).
//
// It runs the PINNED ORACLE's own method code (redact-secret/redact-secret-benchmarks at commit
// 4b846967346505baca11e0b98cab1475fbce6773: methods/*.ts, operators.ts, validators.ts,
// contract-model.ts, substrate/{hash,variant-lifecycle,registry}.ts) on synthetic authored cases and
// writes what the oracle produced as a Rust table. Expected values therefore come from the oracle,
// never from the Rust implementation.
//
// Two oracle modules load committed evidence corpora through Ajv and JSON imports and are replaced by
// stubs in the scratch tree: benign-collision-evidence.ts (entries are supplied per case) and
// context-evidence.ts (frames are the real frames of context-evidence-v1.json at the pin). The method
// files themselves are unmodified.
//
// Usage (Node >= 22.6):
//   node --experimental-strip-types oracle_methods_driver.mjs <oracle-tree> <context-evidence-v1.json> <out.rs>
// where <oracle-tree> holds the pinned files at their repository paths (see ADR 0007, section 13).

import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const [, , tree, contextJson, out] = process.argv;
const groups = JSON.parse((await import('node:fs')).readFileSync(contextJson, 'utf8')).groups;
const frameOf = (groupId, frameId) => groups.find(g => g.id === groupId).frames.find(f => f.id === frameId);
const trio = (id, language, a, b, c) => ({ id, language, identityDomain: 'email', frames: [a, b, c] });
const extra = [
  trio('en-trio-test', 'en', frameOf('en-email-core', 'en-case-equals'), frameOf('en-email-core', 'en-neutral'), frameOf('en-email-core', 'en-negative')),
  trio('ko-trio-test', 'ko', frameOf('ko-email-core', 'ko-colon'), frameOf('ko-email-core', 'ko-neutral'), frameOf('ko-email-core', 'ko-negative')),
  trio('ko-invisible-trio-test', 'ko', frameOf('ko-email-core', 'ko-governed-invisible'), frameOf('ko-email-core', 'ko-neutral'), frameOf('ko-email-core', 'ko-negative')),
];
process.env.PII_CONTEXT_JSON = contextJson;
process.env.PII_EXTRA_GROUPS = JSON.stringify(extra);

const imp = async p => import(resolve(tree, p));
const { createRegistry } = await imp('benchmarks/evaluation/substrate/registry.ts');
const { createPiiValidators } = await imp('benchmarks/evaluation/domains/pii/validators.ts');
const { createPiiOperators } = await imp('benchmarks/evaluation/domains/pii/operators.ts');
const m = async f => imp(`benchmarks/evaluation/domains/pii/methods/${f}.ts`);
const { schemaOnly } = await m('schema-only');
const { typeValidation } = await m('type-validation');
const { contextDiscrimination } = await m('context-discrimination');
const { piiBenign } = await m('benign');
const { jurisdictionCollision } = await m('jurisdiction-collision');
const { mutation } = await m('mutation');
const { referenceDifferential } = await m('reference-differential');
// methods/index.ts imports the real evidence loaders, so the registry is assembled here from the method files.
const createPiiMethods = (validators, operators) => {
  const registry = createRegistry('PII method', ['validateCase', 'generate', 'evaluate']);
  for (const method of [schemaOnly, typeValidation(validators, {}), contextDiscrimination, piiBenign(validators, {}),
    jurisdictionCollision(validators, {}), mutation(operators), referenceDifferential(validators)]) registry.register(method);
  return registry;
};

const stock = createPiiValidators();
const unavailable = { id: 'unavailable-test', version: 1, validate: () => ({ state: 'unavailable' }) };
const validators = createPiiValidators([stock.get('synthetic-mod10'), stock.get('us-ssn-allocation'), unavailable]);
const methods = createPiiMethods(validators, createPiiOperators());

const authority = [{ sourceKind: 'standard', sourceId: 'synthetic-authority', locator: 'section:synthetic', revision: '1',
  supports: ['lexical', 'validation', 'allocation', 'sensitivity', 'reserved-control'] }];
const SYN = { family: 'pii:global:synthetic-reference', scope: 'global', identityDomain: 'payment-card', jurisdiction: null };
const SSN = { family: 'pii:us:ssn', scope: 'jurisdiction:US', identityDomain: 'national-id', jurisdiction: 'US' };
const EMAIL = { family: 'pii:global:email', scope: 'global', identityDomain: 'email', jurisdiction: null };
const bl = s => Buffer.byteLength(s);

function mk(name, method, fam, prefix, value, suffix, o = {}) {
  const content = `${prefix}${value}${suffix}`;
  const language = o.language ?? 'en';
  const c = {
    id: name.replace('/', '-'), method, visibility: 'development',
    input: { id: name.replace('/', '-'), path: `pii/${name.replace('/', '-')}.txt`, content },
    candidate: o.candidate ?? { start: bl(prefix), end: bl(prefix) + bl(value) },
    contract: { category: 'pii', family: fam.family, displayName: 'Synthetic Identifier', identityDomain: fam.identityDomain, scope: fam.scope,
      typeExpectation: { state: o.type ?? 'valid', validator: o.validator ?? null }, sensitivityExpectation: o.sensitivity ?? 'not-established',
      context: { obligation: o.obligation ?? 'none', class: o.contextClass ?? 'neutral', language }, authority,
      referenceEvidence: o.reference ?? null, qualificationProfile: { id: 'pii-v1', version: 1 } },
    provenance: { source: 'synthetic/p5-driver', sourceHash: 'a'.repeat(64), seed: o.seed ?? `${name}/1`, rationale: 'synthetic p5 vector', sources: ['synthetic'] },
    ...(o.metadata ? { metadata: o.metadata } : {}),
  };
  return { name, c, fam, o, prefix, value, suffix };
}

const e = (validator, expected) => ({ id: validator, version: 1, expected });
const ev = (evidenceClass, accountingClass, validator, collision = null) => ({ id: `evidence-${evidenceClass}`, evidenceClass, accountingClass,
  contextGroup: null, validator, collision });

const cases = [
  mk('schema-only/email-probe', 'schema-only', EMAIL, 'contact=', 'person@example.invalid', '', { sensitivity: 'non-sensitive', contextClass: 'non-sensitive' }),
  mk('schema-only/ko-prefix', 'schema-only', EMAIL, '연락처=', 'person@example.invalid', ' 끝', { language: 'ko', sensitivity: 'non-sensitive', contextClass: 'non-sensitive' }),
  // The oracle never checks character boundaries: it slices bytes and decodes lossily.
  mk('schema-only/mid-character-range', 'schema-only', EMAIL, '연락처=', 'x', '', { candidate: { start: 1, end: 10 } }),
  mk('type-validation/mod10-valid', 'type-validation', SYN, 'ref=', 'SYNTHETIC-1236', '', { validator: 'synthetic-mod10', type: 'valid' }),
  mk('type-validation/mod10-invalid', 'type-validation', SYN, 'ref=', 'SYNTHETIC-1237', '', { validator: 'synthetic-mod10', type: 'invalid' }),
  mk('type-validation/ssn-valid', 'type-validation', SSN, 'ssn=', '111111111', '', { validator: 'us-ssn-allocation', type: 'valid' }),
  mk('type-validation/ssn-area-666', 'type-validation', SSN, 'ssn=', '666123456', '', { validator: 'us-ssn-allocation', type: 'invalid' }),
  mk('type-validation/ssn-group-00', 'type-validation', SSN, 'ssn=', '123001234', '', { validator: 'us-ssn-allocation', type: 'invalid' }),
  mk('type-validation/ssn-serial-0000', 'type-validation', SSN, 'ssn=', '123450000', '', { validator: 'us-ssn-allocation', type: 'invalid' }),
  mk('type-validation/ssn-area-900', 'type-validation', SSN, 'ssn=', '900123456', '', { validator: 'us-ssn-allocation', type: 'invalid' }),
  mk('type-validation/mismatch', 'type-validation', SYN, 'ref=', 'SYNTHETIC-1237', '', { validator: 'synthetic-mod10', type: 'valid' }),
  mk('type-validation/unknown-validator', 'type-validation', SYN, 'ref=', 'SYNTHETIC-1236', '', { validator: 'no-such-validator', type: 'valid' }),
  mk('type-validation/unavailable', 'type-validation', SYN, 'ref=', 'SYNTHETIC-1236', '', { validator: 'unavailable-test', type: 'valid' }),
  mk('context-discrimination/en-trio', 'context-discrimination', EMAIL, 'value=', 'subject@example.invalid', '', { obligation: 'required-for-sensitive-classification', metadata: { contextEvidenceGroup: 'en-trio-test' } }),
  mk('context-discrimination/ko-trio', 'context-discrimination', EMAIL, 'value=', 'subject@example.invalid', '', { language: 'ko', obligation: 'required-for-sensitive-classification', metadata: { contextEvidenceGroup: 'ko-trio-test' } }),
  mk('context-discrimination/ko-invisible', 'context-discrimination', EMAIL, '값=', 'subject@example.invalid', '', { language: 'ko', obligation: 'required-for-sensitive-classification', metadata: { contextEvidenceGroup: 'ko-invisible-trio-test' } }),
  mk('context-discrimination/en-full-group', 'context-discrimination', EMAIL, 'value=', 'subject@example.invalid', '', { obligation: 'required-for-sensitive-classification', metadata: { contextEvidenceGroup: 'en-email-core' } }),
  mk('pii-benign/reserved-ssn', 'pii-benign', SSN, 'ssn=', '000000000', '', { type: 'invalid', validator: 'us-ssn-allocation', sensitivity: 'non-sensitive', contextClass: 'non-sensitive',
    metadata: { accountingClass: 'reserved', stubEntry: ev('reserved-documentation', 'reserved', e('us-ssn-allocation', 'invalid')) } }),
  mk('pii-benign/placeholder', 'pii-benign', SYN, 'ref=', 'SYNTHETIC-0000', '', { sensitivity: 'non-sensitive', contextClass: 'non-sensitive', metadata: { accountingClass: 'placeholder' } }),
  mk('pii-benign/sensitive-refused', 'pii-benign', SYN, 'ref=', 'SYNTHETIC-0000', '', { sensitivity: 'sensitive', metadata: { accountingClass: 'placeholder' } }),
  mk('pii-benign/check-mismatch', 'pii-benign', SSN, 'ssn=', '000000000', '', { type: 'invalid', validator: 'us-ssn-allocation', sensitivity: 'non-sensitive', contextClass: 'non-sensitive',
    metadata: { accountingClass: 'reserved', stubEntry: ev('reserved-documentation', 'reserved', e('us-ssn-allocation', 'valid')) } }),
  mk('jurisdiction-collision/ssn-collision', 'jurisdiction-collision', SSN, 'ssn=', '111111111', '', { validator: 'us-ssn-allocation', sensitivity: 'sensitive', contextClass: 'sensitive',
    metadata: { collision: { targetFamily: 'pii:us:ssn', competingFamilies: ['pii:kr:national-id', 'pii:global:synthetic-reference', 'pii:kr:national-id'] },
      stubEntry: ev('cross-family-collision', null, e('us-ssn-allocation', 'valid'), { target: { family: 'pii:us:ssn', scope: 'jurisdiction:US', validator: e('us-ssn-allocation', 'valid') },
        competitors: [{ family: 'pii:global:synthetic-reference', scope: 'global', validator: e('synthetic-mod10', 'invalid') },
          { family: 'pii:kr:national-id', scope: 'jurisdiction:KR', validator: e('synthetic-mod10', 'invalid') }],
        expectedOutcomes: { family: 'correct', jurisdiction: 'correct', sensitivity: 'sensitive' } }) } }),
  mk('jurisdiction-collision/target-in-competing', 'jurisdiction-collision', SSN, 'ssn=', '111111111', '', { validator: 'us-ssn-allocation', sensitivity: 'sensitive', contextClass: 'sensitive',
    metadata: { collision: { targetFamily: 'pii:us:ssn', competingFamilies: ['pii:us:ssn'] } } }),
  mk('mutation/mod10', 'mutation', SYN, 'ref=', 'SYNTHETIC-1236', '', { metadata: { operator: 'invalidate-final-digit' } }),
  mk('mutation/wrap9', 'mutation', SYN, 'ref=', 'SYNTHETIC-1239', ' tail', { sensitivity: 'sensitive', contextClass: 'sensitive', metadata: { operator: 'invalidate-final-digit' } }),
  mk('mutation/ko-prefix-ssn', 'mutation', SSN, '번호=', '111111119', '', { validator: 'us-ssn-allocation', metadata: { operator: 'invalidate-final-digit' } }),
  mk('mutation/already-invalid', 'mutation', SYN, 'ref=', 'SYNTHETIC-1237', '', { type: 'invalid', metadata: { operator: 'invalidate-final-digit' } }),
  mk('mutation/no-final-digit', 'mutation', EMAIL, 'contact=', 'person@example.invalid', '', { metadata: { operator: 'invalidate-final-digit' } }),
  mk('mutation/unknown-operator', 'mutation', SYN, 'ref=', 'SYNTHETIC-1236', '', { metadata: { operator: 'no-such-operator' } }),
  mk('reference-differential/agree', 'reference-differential', SYN, 'ref=', 'SYNTHETIC-1236', '', { reference: { id: 'synthetic-mod10', version: 1 }, type: 'valid' }),
  mk('reference-differential/disagree', 'reference-differential', SYN, 'ref=', 'SYNTHETIC-1237', '', { reference: { id: 'synthetic-mod10', version: 1 }, type: 'valid' }),
  mk('reference-differential/unavailable', 'reference-differential', SYN, 'ref=', 'SYNTHETIC-1236', '', { reference: { id: 'unavailable-test', version: 1 }, type: 'valid' }),
  mk('reference-differential/unknown-reference', 'reference-differential', SYN, 'ref=', 'SYNTHETIC-1236', '', { reference: { id: 'no-such-validator', version: 1 }, type: 'valid' }),
  mk('reference-differential/version-mismatch', 'reference-differential', SYN, 'ref=', 'SYNTHETIC-1236', '', { reference: { id: 'synthetic-mod10', version: 2 }, type: 'valid' }),
];

// Escape for a Rust string literal (non-ASCII as \u{..}).
const rs = s => '"' + [...s].map(ch => {
  const cp = ch.codePointAt(0);
  if (ch === '\\') return '\\\\'; if (ch === '"') return '\\"'; if (ch === '\n') return '\\n';
  return cp >= 0x20 && cp < 0x7f ? ch : `\\u{${cp.toString(16)}}`;
}).join('') + '"';
const opt = (v, f = rs) => (v === null || v === undefined ? 'None' : `Some(${f(v)})`);
const pair = (a, b) => `(${rs(a)}, ${b})`;

function row(entry) {
  const { name, c, fam, o } = entry;
  let expect;
  try {
    const method = methods.get(c.method);
    const variants = method.generate(c);
    // Evaluate against one perfect scanner, to learn how the oracle gates the type axis and the reference disposition.
    const scanner = { id: 'fake', status: 'complete', findings: variants.map(v => ({ path: v.fixture.path, start: v.candidate.start, end: v.candidate.end,
      family: v.contract.family, ...(fam.jurisdiction ? { jurisdiction: fam.jurisdiction } : {}), sensitive: true })) };
    const ev = method.evaluate({ case: c, variants, observations: [scanner] });
    const vs = variants.map((v, i) => `OracleVariant { slot: ${rs(v.id)}, strategy: ${rs(v.strategy)}, operator: ${pair(v.transformation.operator, v.transformation.operatorVersion)}, `
      + `method_version: ${v.transformation.methodVersion}, type_effect: ${rs(v.transformation.expectationEffect.type)}, sensitivity_effect: ${rs(v.transformation.expectationEffect.sensitivity)}, `
      + `text: ${rs(v.fixture.content)}, start: ${v.candidate.start}, end: ${v.candidate.end}, type_expectation: ${rs(v.contract.typeExpectation.state)}, `
      + `sensitivity: ${rs(v.contract.sensitivityExpectation)}, context_class: ${rs(v.contract.context.class)}, seed: ${rs(v.provenance.seed)}, `
      + `outcome_type_state: ${rs(ev.outcomes[i].typeIdentity.state)}, disposition: ${opt(ev.evidence?.disposition ?? null)} }`);
    const collision = c.method === 'jurisdiction-collision' ? variants[0].evidence.competingFamilies : [];
    expect = `Expect::Variants { variants: &[${vs.join(', ')}], competing_sorted: &[${collision.map(rs).join(', ')}] }`;
  } catch (err) {
    expect = `Expect::Error(${rs(String(err.message))})`;
  }
  const meta = c.metadata ?? {};
  const checks = [];
  if (meta.stubEntry?.validator) checks.push([meta.stubEntry.validator.id, meta.stubEntry.validator.version, meta.stubEntry.validator.expected]);
  if (meta.stubEntry?.collision) for (const party of [meta.stubEntry.collision.target, ...meta.stubEntry.collision.competitors])
    checks.push([party.validator.id, party.validator.version, party.validator.expected]);
  const groupFrames = meta.contextEvidenceGroup
    ? [...groups, ...extra].find(g => g.id === meta.contextEvidenceGroup).frames.map(f => [f.id, f.template, f.contextClass, f.sensitivity]) : [];
  return `    OracleCase {\n        name: ${rs(name)}, method: ${rs(c.method)}, family: ${rs(c.contract.family)}, jurisdiction: ${opt(fam.jurisdiction)}, language: ${rs(c.contract.context.language)},\n`
    + `        text: ${rs(c.input.content)}, start: ${c.candidate.start}, end: ${c.candidate.end}, type_expectation: ${rs(c.contract.typeExpectation.state)},\n`
    + `        validator: ${opt(c.contract.typeExpectation.validator, v => `(${rs(v)}, 1)`)}, sensitivity: ${rs(c.contract.sensitivityExpectation)},\n`
    + `        context_class: ${rs(c.contract.context.class)}, context_obligation: ${rs(c.contract.context.obligation)},\n`
    + `        reference: ${opt(c.contract.referenceEvidence, r => `(${rs(r.id)}, ${r.version})`)}, seed: ${rs(c.provenance.seed)},\n`
    + `        accounting_class: ${opt(meta.accountingClass ?? null)}, evidence_class: ${opt(meta.stubEntry?.evidenceClass ?? null)}, operator: ${opt(meta.operator ?? null)},\n`
    + `        frames: &[${groupFrames.map(f => `(${f.map(rs).join(', ')})`).join(', ')}],\n`
    + `        competing: &[${(meta.collision?.competingFamilies ?? []).map(rs).join(', ')}],\n`
    + `        checks: &[${checks.map(k => `(${rs(k[0])}, ${k[1]}, ${rs(k[2])})`).join(', ')}],\n`
    + `        expect: ${expect},\n    },`;
}

const header = `// GENERATED by oracle_methods_driver.mjs from the pinned oracle's own method code
// (redact-secret/redact-secret-benchmarks @ 4b846967346505baca11e0b98cab1475fbce6773). Do not edit by hand:
// every \`expect\` value was produced by the oracle, not by the Rust implementation.
pub struct OracleVariant {
    pub slot: &'static str,
    pub strategy: &'static str,
    pub operator: (&'static str, u32),
    pub method_version: u32,
    pub type_effect: &'static str,
    pub sensitivity_effect: &'static str,
    pub text: &'static str,
    pub start: u64,
    pub end: u64,
    pub type_expectation: &'static str,
    pub sensitivity: &'static str,
    pub context_class: &'static str,
    pub seed: &'static str,
    /// \`typeIdentity.state\` of the oracle's outcome for one perfect scanner, after the method's own gating.
    pub outcome_type_state: &'static str,
    /// \`evidence.disposition\` of the oracle's \`evaluate\` (reference-differential only).
    pub disposition: Option<&'static str>,
}

pub enum Expect {
    Variants {
        variants: &'static [OracleVariant],
        competing_sorted: &'static [&'static str],
    },
    Error(&'static str),
}

pub struct OracleCase {
    pub name: &'static str,
    pub method: &'static str,
    pub family: &'static str,
    pub jurisdiction: Option<&'static str>,
    pub language: &'static str,
    pub text: &'static str,
    pub start: u64,
    pub end: u64,
    pub type_expectation: &'static str,
    pub validator: Option<(&'static str, u32)>,
    pub sensitivity: &'static str,
    pub context_class: &'static str,
    pub context_obligation: &'static str,
    pub reference: Option<(&'static str, u32)>,
    pub seed: &'static str,
    pub accounting_class: Option<&'static str>,
    pub evidence_class: Option<&'static str>,
    pub operator: Option<&'static str>,
    /// (id, template, context class, sensitivity)
    pub frames: &'static [(&'static str, &'static str, &'static str, &'static str)],
    pub competing: &'static [&'static str],
    /// (validator id, version, expected state)
    pub checks: &'static [(&'static str, u32, &'static str)],
    pub expect: Expect,
}

pub const ORACLE_CASES: &[OracleCase] = &[
`;
// Validator vectors: the oracle's own validators on edge strings (JS regexes: ASCII digits only, no trailing-newline allowance).
const strings = {
  'synthetic-mod10': ['SYNTHETIC-1236', 'SYNTHETIC-1237', 'SYNTHETIC-0000', 'SYNTHETIC-9997', 'SYNTHETIC-9990', 'synthetic-1236', 'SYNTHETIC-123', 'SYNTHETIC-12345',
    ' SYNTHETIC-1236', 'SYNTHETIC-1236\n', 'SYNTHETIC-\u0661\u0662\u0663\u0666', 'SYNTHETIC-12a6', 'SYNTHETIC1236', ''],
  'us-ssn-allocation': ['111111111', '000123456', '666123456', '665123456', '667123456', '899123456', '900123456', '999123456', '123001234', '123450000', '001010001',
    '12345678', '1234567890', '12345678a', '123-45-6789', '\u0660\u0661\u0662\u0663\u0664\u0665\u0666\u0667\u0668', '123456789\n', '000000000', ''],
};
const vectors = Object.entries(strings).flatMap(([id, values]) => values.map(v => `    (${rs(id)}, ${rs(v)}, ${rs(stock.get(id).validate(v).state)}),`));
const validatorTable = `\n/// (validator id, input, state) as produced by the oracle's own validators.\npub const ORACLE_VALIDATOR_VECTORS: &[(&str, &str, &str)] = &[\n${vectors.join('\n')}\n];\n`;
writeFileSync(out, header + cases.map(row).join('\n') + '\n];\n' + validatorTable);
