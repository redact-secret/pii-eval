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
import { readFileSync } from 'node:fs';
import { isMain } from './main-guard.mjs';

export const MAX = 4000;

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
    text = readFileSync(process.argv[2], 'utf8');
  } catch {
    text = '';
  }
  process.stdout.write(`${safeLine(text)}\n`);
}
