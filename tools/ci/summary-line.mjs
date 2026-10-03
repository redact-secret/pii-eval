#!/usr/bin/env node
// Turns the output of an UNTRUSTED program into one safe line for a job summary
// or a log (docs/ci-artifacts.md). Standard library only.
//
//   node tools/ci/summary-line.mjs FILE
//
// Reads FILE, requires its first line to be one JSON object, and prints that
// object re-serialized on a single line with every backtick escaped and the
// length capped. Anything else prints a fixed marker instead. The point: a
// hostile or broken program cannot inject workflow commands (`::...::` at the
// start of a line), break out of a fenced code block in the summary, or flood
// the log through what this prints.
import { closeSync, openSync, readSync } from 'node:fs';
import { isMain } from './main-guard.mjs';

export const MAX = 4000;
// Only the head of the file is read: the program that wrote it is untrusted and may
// have written without limit.
export const READ_LIMIT = 64 * 1024;

export function readHead(path) {
  const fd = openSync(path, 'r');
  try {
    const buf = Buffer.alloc(READ_LIMIT);
    const n = readSync(fd, buf, 0, READ_LIMIT, 0);
    return buf.subarray(0, n).toString('utf8');
  } finally {
    closeSync(fd);
  }
}

export function safeLine(text) {
  const first = String(text).split('\n', 1)[0];
  let value;
  try {
    value = JSON.parse(first);
  } catch {
    return '{"unreadable":true}';
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return '{"unreadable":true}';
  const out = JSON.stringify(value).replaceAll('`', '\\u0060').replaceAll('\u2028', '\\u2028').replaceAll('\u2029', '\\u2029');
  return out.length > MAX ? '{"truncated":true}' : out;
}

if (isMain(import.meta.url)) {
  if (process.argv.length !== 3) {
    process.stderr.write('usage: summary-line.mjs FILE\n');
    process.exit(2);
  }
  let text = '';
  try {
    text = readHead(process.argv[2]);
  } catch {
    text = '';
  }
  process.stdout.write(`${safeLine(text)}\n`);
}
