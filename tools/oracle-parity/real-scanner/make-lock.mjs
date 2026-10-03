#!/usr/bin/env node
// Write a hermetic install description for `@redact-secret/core` 0.1.0-beta.12 from the PINNED
// ORACLE lockfile: a package.json that depends on exactly the pinned version, and a
// package-lock.json holding only the `@redact-secret/*` entries of the oracle lockfile, byte for
// byte (version, resolved URL, sha512 integrity). `npm ci` installs exactly those tarballs and
// refuses any whose integrity differs. Nothing else is installed.
//
// Usage: node make-lock.mjs <oracle-root> <install-dir>
//   <oracle-root>  `<scratch>/oracle`, written by ../fetch-oracle.mjs (its package-lock.json is
//                  part of the verified oracle files)
//   <install-dir>  a new scratch directory
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { sha256, stableJson } from '../lib.mjs';

const [, , oracleRoot, installDir] = process.argv;
if (!oracleRoot || !installDir) {
  console.error('usage: make-lock.mjs <oracle-root> <install-dir>');
  process.exit(2);
}
const VERSION = '0.1.0-beta.12';
const lock = JSON.parse(readFileSync(join(oracleRoot, 'package-lock.json'), 'utf8'));
const entries = Object.entries(lock.packages).filter(([name]) => name.startsWith('node_modules/@redact-secret/'));
const core = lock.packages['node_modules/@redact-secret/core'];
if (!core || core.version !== VERSION) throw new Error('the oracle lockfile does not pin @redact-secret/core 0.1.0-beta.12');
for (const [name, entry] of entries) {
  if (entry.version !== VERSION || !/^sha512-/.test(entry.integrity ?? '') || !/^https:\/\/registry\.npmjs\.org\//.test(entry.resolved ?? '')) {
    throw new Error(`unexpected lock entry ${name}`);
  }
}
const packageJson = { name: 'pii-eval-real-scanner-install', private: true, version: '0.0.0', dependencies: { '@redact-secret/core': VERSION } };
const packageLock = {
  name: packageJson.name, version: packageJson.version, lockfileVersion: 3, requires: true,
  packages: { '': { name: packageJson.name, version: packageJson.version, dependencies: packageJson.dependencies }, ...Object.fromEntries(entries) },
};
mkdirSync(installDir, { recursive: true });
writeFileSync(join(installDir, 'package.json'), stableJson(packageJson));
const lockText = stableJson(packageLock);
writeFileSync(join(installDir, 'package-lock.json'), lockText);
console.log(JSON.stringify({ lockSha256: sha256(lockText), packages: entries.map(([n, e]) => `${n}@${e.version} ${e.integrity}`) }, null, 1));
