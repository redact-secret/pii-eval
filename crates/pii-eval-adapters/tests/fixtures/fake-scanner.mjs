// INERT TEST FAKE for pii-eval-adapters. It is not a scanner and not the
// production shim. It speaks protocol pii-eval-adapter/1 and misbehaves on
// demand so the Rust adapter's failure handling can be tested without any
// real scanner. All data is synthetic. The input text selects a misbehavior
// (a prefix such as "#crash"); the production shim never interprets text.
//
// Startup behavior comes from the configuration parameter "startup".

import { spawn as spawnChild } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const PROTOCOL = 'pii-eval-adapter/1';
const SENTINEL = 'zq-sentinel-7731';
const held = []; // memory kept alive on purpose by the `#mem` misbehavior

const out = (obj) => process.stdout.write(`${JSON.stringify(obj)}\n`);
const raw = (s) => process.stdout.write(s);

let params = {};
let activation = [];
let returnOutput = false;
let maxFindings = 10000;
const seen = [];

const scannerId = () => (params.startup === 'wrong-id' ? 'other-scanner' : 'fake-scanner');

function activationIdentity() {
  const selectors = params.startup === 'wrong-activation' ? [] : [...activation].sort();
  const families = ['pii:global:email', 'pii:global:iban'];
  if (activation.includes('pii:us')) families.push('pii:us:ssn');
  return `credentials=full;selectors=${selectors.length ? selectors.join(',') : 'off'};families=${families.sort().join(',')};vocabulary=pii-context/v2`;
}

function init(msg) {
  params = msg.parameters ?? {};
  activation = msg.activation;
  returnOutput = msg.returnOutput;
  maxFindings = msg.limits.maxFindings;
  const mode = params.startup ?? 'normal';
  if (mode === 'crash') process.exit(3);
  if (mode === 'exit0') process.exit(0);
  if (mode === 'hang') { setInterval(() => {}, 1000); return; }
  if (mode === 'bad-json') { raw('{nope\n'); return; }
  if (mode.startsWith('init-error-')) {
    out({ type: 'error', stage: 'init', code: mode.slice('init-error-'.length) });
    return;
  }
  if (activation.includes('pii:kr')) {
    out({ type: 'error', stage: 'init', code: 'unsupported-selector' });
    return;
  }
  if (mode === 'stderr-flood') process.stderr.write(`${SENTINEL}\n`.repeat(40000));
  out({
    type: 'ready',
    protocol: PROTOCOL,
    scanner: { id: scannerId(), version: mode === 'wrong-version' ? '9.9.9' : '1.0.0' },
    runtime: { name: mode === 'wrong-runtime' ? 'deno' : 'node', version: process.version },
    activation: activationIdentity(),
    offsetUnit: mode === 'wrong-unit' ? 'utf8-bytes' : 'utf16-code-units',
  });
  if (mode === 'noread') {
    // Hostile: answer the first scans before they are asked, then stop reading
    // stdin so the writer side backs up.
    for (let i = 1; i <= 8; i += 1) out({ type: 'result', seq: i, findings: [], output: '' });
    process.stdin.pause();
    setInterval(() => {}, 1000);
  }
}

function detect(text) {
  const findings = [];
  const replace = [];
  const add = (re, type, detector, action, redact) => {
    for (const m of text.matchAll(re)) {
      findings.push({ start: m.index, end: m.index + m[0].length, type, detector, action });
      if (redact) replace.push([m.index, m.index + m[0].length]);
    }
  };
  add(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, 'pii_global_email', 'pii-domain', 'redact', true);
  if (activation.includes('pii:us')) {
    add(/\b\d{3}-\d{2}-\d{4}\b/g, 'pii_jurisdiction_us_ssn', 'pii-domain', 'warn', false);
  }
  add(/AKIA[A-Z0-9]{16}/g, 'aws_access_key_id', 'aws', 'redact', true);
  findings.sort((a, b) => a.start - b.start);
  let output = '';
  let at = 0;
  for (const [s, e] of replace.sort((a, b) => a[0] - b[0])) { output += text.slice(at, s) + '<R>'; at = e; }
  output += text.slice(at);
  return { findings, output };
}

function result(seq, findings, output) {
  const reply = { type: 'result', seq, findings };
  if (returnOutput) reply.output = output;
  return reply;
}

function scan(msg) {
  const { seq, text } = msg;
  const f = (start, end, extra = {}) => ({ start, end, type: 'pii_global_email', detector: 'pii-domain', action: 'redact', ...extra });
  if (text.startsWith('#crash')) process.exit(3);
  if (text.startsWith('#hang')) { setInterval(() => {}, 1000); return; }
  if (text.startsWith('#huge')) { raw(`${'x'.repeat(10 * 1024 * 1024)}\n`); return; }
  if (text.startsWith('#malformed')) { raw('{not json\n'); return; }
  if (text.startsWith('#truncated')) { raw('{"type":"result"'); process.exit(0); }
  if (text.startsWith('#exit0')) process.exit(0);
  if (text.startsWith('#null')) { raw(`{"type":"result","seq":${seq},"findings":[],"output":null}\n`); return; }
  if (text.startsWith('#dupkeys')) { raw(`{"type":"result","seq":${seq},"seq":${seq},"findings":[]}\n`); return; }
  if (text.startsWith('#wrongseq')) { out(result(seq + 5, [], text)); return; }
  if (text.startsWith('#badrange')) { out(result(seq, [f(0, text.length + 10)], text)); return; }
  if (text.startsWith('#emptyrange')) { out(result(seq, [f(1, 1)], text)); return; }
  if (text.startsWith('#invertedrange')) { out(result(seq, [f(3, 1)], text)); return; }
  if (text.startsWith('#midpair')) { const i = text.indexOf('\u{1F600}'); out(result(seq, [f(i + 1, i + 2)], text)); return; }
  if (text.startsWith('#unknownaction')) { out(result(seq, [f(0, 2, { action: 'explode' })], text)); return; }
  if (text.startsWith('#extra')) { out({ ...result(seq, [], text), message: SENTINEL }); return; }
  if (text.startsWith('#scanerr')) { out({ type: 'error', stage: 'scan', seq, code: 'scanner-error' }); return; }
  if (text.startsWith('#inputlimit')) { out({ type: 'error', stage: 'scan', seq, code: 'input-limit' }); return; }
  if (text.startsWith('#findinglimit')) { out({ type: 'error', stage: 'scan', seq, code: 'finding-limit' }); return; }
  if (text.startsWith('#badcode')) { out({ type: 'error', stage: 'scan', seq, code: SENTINEL }); return; }
  if (text.startsWith('#toomany')) { out(result(seq, Array.from({ length: maxFindings + 1 }, () => f(0, 1)), text)); return; }
  if (text.startsWith('#dupfind')) { out(result(seq, [f(0, 2), f(0, 2)], text)); return; }
  if (text.startsWith('#undeclared')) { out(result(seq, [f(0, 2, { type: 'pii_jurisdiction_us_ssn' })], text)); return; }
  if (text.startsWith('#pid')) { out(result(seq, [], String(process.pid))); return; }
  if (text.startsWith('#unmapped')) { out(result(seq, [f(0, 2, { type: 'pii_novel_kind' })], text)); return; }
  if (text.startsWith('#env')) { out(result(seq, [], JSON.stringify(Object.keys(process.env).sort()))); return; }
  if (text.startsWith('#audit')) { out(result(seq, [], JSON.stringify(seen))); return; }
  if (text.startsWith('#params')) { out(result(seq, [], JSON.stringify(params))); return; }
  if (text.startsWith('#stderr')) { process.stderr.write(`${SENTINEL}\n`.repeat(40000)); }
  // P7 misbehaviors: descendants, memory, temporary files, slowness, flakiness.
  // `<path>` below is a file the test chose; the fake writes only a number to it.
  if (text.startsWith('#spawn')) {
    // "#spawn<mode> <path>": start a descendant that outlives this process, record
    // its pid in <path>, then behave per mode (reply, crash or hang).
    const [head, file] = text.split(' ');
    const holder = head.includes('holding') ? 'inherit' : 'ignore';
    const child = spawnChild(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: ['ignore', holder, holder] });
    writeFileSync(file, String(child.pid));
    if (head.startsWith('#spawncrash')) process.exit(3);
    if (head.startsWith('#spawnhang')) { setInterval(() => {}, 1000); return; }
    const d = detect(text);
    out(result(seq, d.findings, d.output));
    return;
  }
  if (text.startsWith('#mem')) {
    // "#mem <MB>": allocate and touch that many MB, hold them, answer after a while.
    const mb = Number(text.split(' ')[1]);
    held.push(Buffer.alloc(mb * 1024 * 1024, 1));
    setTimeout(() => { const d = detect(text); out(result(seq, d.findings, d.output)); }, 3000);
    return;
  }
  if (text.startsWith('#tmpwrite')) {
    // "#tmpwrite <MB>": write that many MB under TMPDIR, hold, answer after a while.
    const mb = Number(text.split(' ')[1]);
    writeFileSync(join(process.env.TMPDIR ?? '/nonexistent', 'fill.bin'), Buffer.alloc(mb * 1024 * 1024, 2));
    setTimeout(() => { const d = detect(text); out(result(seq, d.findings, d.output)); }, 3000);
    return;
  }
  if (text.startsWith('#tmpdir')) { out(result(seq, [], String(process.env.TMPDIR))); return; }
  if (text.startsWith('#slow')) {
    // "#slow <ms>": answer normally after that many milliseconds.
    const ms = Number(text.split(' ')[1]);
    setTimeout(() => { const d = detect(text); out(result(seq, d.findings, d.output)); }, ms);
    return;
  }
  if (text.startsWith('#flaky')) {
    // "#flaky <path>": the answer alternates between processes: report one
    // finding when a counter kept in <path> is odd, none when it is even.
    const file = text.split(' ')[1];
    let n = 0;
    try { n = Number(readFileSync(file, 'utf8')); } catch { n = 0; }
    n += 1;
    writeFileSync(file, String(n));
    const findings = n % 2 === 1 ? [f(0, 2)] : [];
    out(result(seq, findings, text));
    return;
  }
  const d = detect(text);
  out(result(seq, d.findings, d.output));
}

let buffered = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  buffered += chunk;
  let nl;
  while ((nl = buffered.indexOf('\n')) !== -1) {
    const line = buffered.slice(0, nl);
    buffered = buffered.slice(nl + 1);
    const msg = JSON.parse(line);
    seen.push(Object.keys(msg).sort());
    if (msg.type === 'init') init(msg);
    else if (msg.type === 'scan') scan(msg);
    else if (msg.type === 'shutdown') process.exit(0);
  }
});
process.stdin.on('end', () => process.exit(0));
