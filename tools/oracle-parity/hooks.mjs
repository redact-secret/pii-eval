// Node module-customization hooks that let the pinned, UNMODIFIED oracle sources run under
// Node 22 type stripping without installing any package. Registered by register.mjs.
//
// 1. `ajv` is replaced by a stub that accepts every document (stubs/ajv.mjs). The oracle uses it only
//    to schema-validate its own committed JSON and its own reports. Consequence, stated in the
//    report: the oracle's JSON-schema checks do not run here; its semantic checks do.
// 2. `.json` imports without an import attribute (the oracle's TypeScript has none) are loaded as
//    JSON modules.
// 3. `benign-collision-evidence.ts` is replaced by a stub (stubs/benign-collision-evidence.mjs): the
//    real module loads an evidence corpus through further modules that the harness does not fetch.
//    The synthetic cases carry no evidence entry, so the oracle's evidence checks are not exercised
//    (ADR 0007 D8 and D9 stay open items of the evidence loader).
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const AJV_STUB = pathToFileURL(join(HERE, 'stubs', 'ajv.mjs')).href;
const EVIDENCE_STUB = pathToFileURL(join(HERE, 'stubs', 'benign-collision-evidence.mjs')).href;

export async function resolve(specifier, context, nextResolve) {
  if (specifier === 'ajv') return { url: AJV_STUB, format: 'module', shortCircuit: true };
  // The real module is not fetched, so this must be decided before the default resolution.
  if (specifier.startsWith('.') && specifier.endsWith('/benign-collision-evidence.ts')) {
    return { url: EVIDENCE_STUB, format: 'module', shortCircuit: true };
  }
  return nextResolve(specifier, context);
}

export async function load(url, context, nextLoad) {
  if (url.endsWith('.json') && context.importAttributes?.type === undefined) {
    const text = readFileSync(new URL(url), 'utf8');
    return { format: 'module', source: `export default ${text};`, shortCircuit: true };
  }
  return nextLoad(url, context);
}
