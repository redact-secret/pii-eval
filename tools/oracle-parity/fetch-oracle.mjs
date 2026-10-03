#!/usr/bin/env node
// Fetch the pinned oracle files into a scratch directory and verify them.
//
// Oracle: redact-secret/redact-secret-benchmarks at the commit pinned in ADR 0001.
// Needs: `gh` (authenticated, read access to that repository) and Node >= 22.6.
// The CI of this repository has no access to the oracle and never runs this script;
// it runs against the committed exports (see tools/oracle-parity/README.md).
//
// Usage: node tools/oracle-parity/fetch-oracle.mjs <scratch-dir>
//
// What it checks, in order:
//   1. the commit SHA that the API reports for the pin equals the pinned SHA;
//   2. every file listed in oracle-files.json has, byte for byte, the git blob SHA
//      that the commit's own tree lists for that path (so a file cannot differ from
//      the pinned commit even if the transport were wrong);
//   3. the recorded tree digest (sha256 over the sorted "path NUL blob-sha" lines of
//      the listed files) equals the one in oracle-files.json.
// It writes the files under <scratch-dir>/oracle/<repository path>, unmodified.
// The local working checkout of the oracle is never read.

import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gitBlobSha1, treeDigest } from './lib.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = 'repos/redact-secret/redact-secret-benchmarks';
const spec = JSON.parse(readFileSync(join(HERE, 'oracle-files.json'), 'utf8'));
const scratch = process.argv[2];
if (!scratch) {
  console.error('usage: fetch-oracle.mjs <scratch-dir>');
  process.exit(2);
}
// A transient network failure is retried a bounded number of times; anything else is fatal.
const gh = (args, raw = false) => {
  for (let attempt = 1; ; attempt++) {
    try {
      return execFileSync('gh', ['api', ...args], { maxBuffer: 1 << 28, stdio: ['ignore', 'pipe', 'pipe'], ...(raw ? {} : { encoding: 'utf8' }) });
    } catch (error) {
      if (attempt >= 5) throw error;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1000 * attempt);
    }
  }
};

const commit = JSON.parse(gh([`${REPO}/commits/${spec.pin}`]));
if (commit.sha !== spec.pin) throw new Error(`commit mismatch: got ${commit.sha}`);
const tree = JSON.parse(gh([`${REPO}/git/trees/${spec.pin}?recursive=1`]));
if (tree.truncated) throw new Error('tree listing truncated');
const blobs = new Map(tree.tree.filter((e) => e.type === 'blob').map((e) => [e.path, e.sha]));

const got = new Map();
for (const path of [...spec.files].sort()) {
  const want = blobs.get(path);
  if (!want) throw new Error(`not in the pinned tree: ${path}`);
  const data = gh([`${REPO}/contents/${path}?ref=${spec.pin}`, '-H', 'Accept: application/vnd.github.raw'], true);
  const blob = gitBlobSha1(data);
  if (blob !== want) throw new Error(`blob sha mismatch: ${path}`);
  const out = join(resolve(scratch), 'oracle', path);
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, data);
  got.set(path, blob);
}
const digest = treeDigest(spec.files, (p) => got.get(p));
if (spec.treeDigest === 'UNSET') {
  // Bootstrap only, used when the file list is edited: print the digest to record.
  console.log(`tree digest to record: ${digest}`);
  process.exit(3);
}
if (digest !== spec.treeDigest) throw new Error(`tree digest mismatch: got ${digest}`);
console.log(`oracle ${spec.pin} verified: ${spec.files.length} files, tree digest ${digest}`);
