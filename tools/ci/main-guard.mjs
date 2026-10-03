// `isMain(import.meta.url)`: true when this module is the script node was started
// with. Comparing `import.meta.url` with `file://${process.argv[1]}` is wrong: the
// URL percent-encodes spaces and other characters and resolves symlinks, so the
// comparison is false for such paths and a CLI guarded by it silently does
// nothing and exits 0. For a verifier that fails open, which is the worst case.
import { realpathSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

export function isMain(metaUrl, argv1 = process.argv[1]) {
  if (typeof argv1 !== 'string' || argv1 === '') return false;
  try {
    return pathToFileURL(realpathSync(argv1)).href === metaUrl;
  } catch {
    return false;
  }
}
