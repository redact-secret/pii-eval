// pii-eval scanner shim for @redact-secret/core (protocol pii-eval-adapter/1).
//
// A transport, not a decision maker. It reads JSON lines on stdin, calls the
// scanner, and writes JSON lines on stdout. It receives only run configuration
// (init) and input text (scan). It has no access to expected labels, ranges or
// case identities and never interprets the text: the text is passed to the
// scanner and nothing else.
//
// It forwards the scanner's native values (offsets in UTF-16 code units, type
// label, detector id, action word, activation identity) untouched. Mapping them
// to neutral findings, validating offsets and every pin check happen in Rust.
//
// Output hygiene: nothing is written to stdout except protocol lines. Errors
// are reported as fixed codes; scanner messages, stacks and input text never
// leave this process, and uncaught errors exit without printing.
//
// Usage (argv is fixed by the Rust adapter): node redact-secret-core.mjs <absolute path of dist/index.js>

import { isAbsolute } from 'node:path';
import { pathToFileURL } from 'node:url';

const PROTOCOL = 'pii-eval-adapter/1';
// One scan line is at most 1 MiB of text; JSON escaping can expand control
// characters six-fold, so 8 MiB bounds the buffer without rejecting valid input.
const MAX_STDIN_LINE_CHARS = 8 * 1024 * 1024;

process.on('uncaughtException', () => process.exit(70));
process.on('unhandledRejection', () => process.exit(70));

const write = (message) => new Promise((resolve) => {
  if (process.stdout.write(`${JSON.stringify(message)}\n`)) resolve();
  else process.stdout.once('drain', resolve);
});

const entry = process.argv[2];
let core = null;
let returnOutput = false;
let limits = null;
let initialized = false;

const initCode = (error) => {
  switch (error && error.code) {
    case 'PII_SELECTOR_UNSUPPORTED': return 'unsupported-selector';
    case 'PII_SELECTOR_INVALID': return 'invalid-selector';
    default: return 'initialization-failed';
  }
};

const scanCode = (error) => {
  switch (error && error.code) {
    case 'INPUT_LIMIT_EXCEEDED': return 'input-limit';
    case 'FINDING_LIMIT_EXCEEDED': return 'finding-limit';
    default: return 'scanner-error';
  }
};

async function handleInit(message) {
  if (initialized) return write({ type: 'error', stage: 'init', code: 'protocol-error' });
  initialized = true;
  const activation = message.activation;
  const bounds = message.limits;
  if (message.protocol !== PROTOCOL || !Array.isArray(activation) ||
      activation.some((s) => typeof s !== 'string') || typeof message.returnOutput !== 'boolean' ||
      !bounds || !Number.isSafeInteger(bounds.maxInputBytes) || !Number.isSafeInteger(bounds.maxFindings)) {
    return write({ type: 'error', stage: 'init', code: 'protocol-error' });
  }
  if (typeof entry !== 'string' || !isAbsolute(entry)) {
    return write({ type: 'error', stage: 'init', code: 'initialization-failed' });
  }
  try {
    core = await import(pathToFileURL(entry).href);
    await core.initialize(activation.length > 0 ? { pii: activation } : undefined);
  } catch (error) {
    return write({ type: 'error', stage: 'init', code: initCode(error) });
  }
  returnOutput = message.returnOutput;
  limits = { maxInputBytes: bounds.maxInputBytes, maxFindings: bounds.maxFindings };
  return write({
    type: 'ready',
    protocol: PROTOCOL,
    scanner: { id: 'redact-secret-core', version: String(core.VERSION) },
    runtime: { name: 'node', version: process.version },
    activation: String(core.piiActivation()),
    offsetUnit: String(core.RANGE_UNIT),
  });
}

async function handleScan(message) {
  const seq = message.seq;
  if (!initialized || core === null || !Number.isSafeInteger(seq) || typeof message.text !== 'string') {
    return write({ type: 'error', stage: 'scan', seq: Number.isSafeInteger(seq) ? seq : 0, code: 'protocol-error' });
  }
  let result;
  try {
    if (returnOutput) {
      const r = core.scanAndRedact(message.text, { limits });
      result = { findings: r.findings, output: r.text };
    } else {
      result = { findings: core.scan(message.text, { limits }) };
    }
  } catch (error) {
    return write({ type: 'error', stage: 'scan', seq, code: scanCode(error) });
  }
  const findings = result.findings.map((f) => {
    const out = { start: f.start, end: f.end, type: String(f.type), detector: String(f.detector) };
    if (typeof f.action === 'string') out.action = f.action;
    return out;
  });
  const reply = { type: 'result', seq, findings };
  if (returnOutput) reply.output = result.output;
  return write(reply);
}

let chain = Promise.resolve();
let buffered = '';

function enqueue(line) {
  chain = chain.then(async () => {
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      return write({ type: 'error', stage: initialized ? 'scan' : 'init', seq: 0, code: 'protocol-error' });
    }
    if (message === null || typeof message !== 'object') {
      return write({ type: 'error', stage: initialized ? 'scan' : 'init', seq: 0, code: 'protocol-error' });
    }
    switch (message.type) {
      case 'init': return handleInit(message);
      case 'scan': return handleScan(message);
      case 'shutdown': return process.exit(0); // earlier replies were awaited, so they are flushed
      default: return write({ type: 'error', stage: initialized ? 'scan' : 'init', seq: 0, code: 'protocol-error' });
    }
  });
}

process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  buffered += chunk;
  let newline;
  while ((newline = buffered.indexOf('\n')) !== -1) {
    const line = buffered.slice(0, newline);
    buffered = buffered.slice(newline + 1);
    if (line.length > 0) enqueue(line);
  }
  if (buffered.length > MAX_STDIN_LINE_CHARS) process.exit(70);
});
process.stdin.on('end', () => { chain.then(() => process.exit(0)); });
