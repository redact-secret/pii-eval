// INERT TEST FAKE of the @redact-secret/core API subset the production shim
// calls (initialize, piiActivation, scan, scanAndRedact, VERSION, RANGE_UNIT).
// It lets the real shim and the Rust vocabulary run end to end in CI without
// installing any scanner. Synthetic detection only; error codes mirror the
// real package's fixed codes.

export const VERSION = '0.1.0-beta.12';
export const RANGE_UNIT = 'utf16-code-units';

let selectors = [];

const fail = (code) => Object.assign(new Error('fixed'), { code });

export async function initialize(options) {
  const requested = options?.pii ?? [];
  for (const s of requested) {
    if (!/^pii:(global|[a-z]{2})$/.test(s)) throw fail('PII_SELECTOR_INVALID');
    if (!['pii:global', 'pii:us'].includes(s)) throw fail('PII_SELECTOR_UNSUPPORTED');
  }
  selectors = [...requested].sort();
}

export function piiActivation() {
  const families = [];
  if (selectors.length > 0) families.push('pii:global:email');
  if (selectors.includes('pii:us')) families.push('pii:us:ssn');
  return `credentials=full;selectors=${selectors.length ? selectors.join(',') : 'off'};families=${families.sort().join(',')};vocabulary=pii-context/v2`;
}

function findAll(text, limits) {
  const found = [];
  const add = (re, type, detector, action) => {
    for (const m of text.matchAll(re)) {
      found.push({ id: '', type, detector, confidence: 'high', obfuscation: 'none', start: m.index, end: m.index + m[0].length, action });
    }
  };
  if (selectors.length > 0) {
    add(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, 'pii_global_email', 'pii-domain', 'redact');
    if (selectors.includes('pii:us')) add(/\b\d{3}-\d{2}-\d{4}\b/g, 'pii_jurisdiction_us_ssn', 'pii-domain', 'warn');
  }
  add(/AKIA[A-Z0-9]{16}/g, 'aws_access_key_id', 'aws', 'redact');
  found.sort((a, b) => a.start - b.start);
  if (limits && found.length > limits.maxFindings) throw fail('FINDING_LIMIT_EXCEEDED');
  return found.map((f, i) => ({ ...f, id: `finding-${i + 1}` }));
}

export const scan = (text, options) => {
  if (options?.limits && Buffer.byteLength(text) > options.limits.maxInputBytes) throw fail('INPUT_LIMIT_EXCEEDED');
  return findAll(text, options?.limits);
};

export const scanAndRedact = (text, options) => {
  const findings = scan(text, options);
  let out = '';
  let at = 0;
  let n = 0;
  for (const f of findings) {
    if (f.action !== 'redact' && f.action !== 'block') continue;
    n += 1;
    out += `${text.slice(at, f.start)}<SECRET_${n}>`;
    at = f.end;
  }
  return { text: out + text.slice(at), findings };
};
