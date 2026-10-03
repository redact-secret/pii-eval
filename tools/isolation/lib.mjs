// Pure helpers of the isolation measurement (tools/isolation/matrix.mjs), kept free of
// processes so they are unit-tested everywhere. Standard library only.

export const MIB = 1024 * 1024;

/** Printable ASCII only, newlines and tabs become spaces, capped. Never echoes control bytes. */
export function sanitize(text, max = 300) {
  const flat = String(text ?? '')
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/[^\x20-\x7e]/g, '?')
    .trim();
  return flat.length > max ? `${flat.slice(0, max)}...` : flat;
}

/** `Max address space  N  N  bytes` from /proc/self/limits: soft and hard in bytes, or null for unlimited. */
export function parseAddressSpaceLimit(limitsText) {
  const line = String(limitsText).split('\n').find((l) => l.startsWith('Max address space'));
  if (!line) return null;
  const m = /^Max address space\s+(unlimited|\d+)\s+(unlimited|\d+)\s+bytes/.exec(line);
  if (!m) return null;
  const n = (s) => (s === 'unlimited' ? null : Number(s));
  return { soft: n(m[1]), hard: n(m[2]) };
}

/** Effective capability mask from /proc/self/status. */
export function parseCapEff(statusText) {
  const m = /^CapEff:\s*([0-9a-f]+)$/m.exec(String(statusText));
  return m ? m[1] : null;
}

/** `VmPeak: 123 kB` style lines, as numbers of kB. */
export function parseVmLines(text) {
  const out = {};
  for (const m of String(text).matchAll(/(VmPeak|VmSize|VmRSS|VmHWM):\s*(\d+)\s*kB/g)) out[m[1]] = Number(m[2]);
  return out;
}

/**
 * The smallest value of `sizes` from which `ok(size)` holds for every larger size too
 * (so a lucky pass below a failure does not count), and whether the series is monotone.
 * `results` maps size -> boolean.
 */
export function floorOf(sizes, results) {
  const sorted = [...sizes].sort((a, b) => a - b);
  let floor = null;
  for (let i = sorted.length - 1; i >= 0; i -= 1) {
    if (results.get(sorted[i]) === true) floor = sorted[i];
    else break;
  }
  const passes = sorted.map((s) => results.get(s) === true);
  const firstPass = passes.indexOf(true);
  const monotone = firstPass === -1 || passes.slice(firstPass).every(Boolean);
  return { floor, monotone };
}

/** The environment names a worker sees must all be on the allowlist; PWD/OLDPWD/SHLVL/_ are shell artefacts. */
export function envNamesOutsideAllowlist(envText, allowlist) {
  const shellArtefacts = new Set(['OLDPWD', 'SHLVL', '_']);
  return String(envText)
    .split('\n')
    .map((l) => l.split('=', 1)[0])
    .filter((n) => n && !allowlist.includes(n) && !shellArtefacts.has(n));
}
