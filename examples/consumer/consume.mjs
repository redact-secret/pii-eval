#!/usr/bin/env node
// Reference consumer of pii-eval public artifacts (P12, docs/custodian-boundary.md).
//
// Standard library only. It imports no pii-eval code (no Rust crate, no kernel,
// no contract type): everything it knows comes from the published document
// format (schemas/, docs/adr/0003 for the digest) and from the pins the CALLER
// supplies. It verifies; it never decides. There is no threshold, no support
// status, no stable/provisional verdict and no ranking anywhere in this file,
// and populations are never pooled: every population keeps its own identity,
// counts and denominators in the report.
//
//   node consume.mjs --pins pins.json ARTIFACT.json [ARTIFACT.json ...]
//
// stdout: one JSON line (pii-eval-consumer-report/1). Exit 0 only when every
// supplied artifact was accepted and every pinned population is satisfied.
// Exit 1: at least one artifact rejected or a pinned population missing.
// Exit 2: usage error or unreadable pins.

import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { basename } from "node:path";
import { fileURLToPath } from "node:url";

export const REPORT_SCHEMA = "pii-eval-consumer-report/1";
export const PINS_SCHEMA = "pii-eval-consumer-pins/1";
export const DIGEST_CONSTRUCTION = "pii-eval-semantic-digest/1";
export const PUBLIC_SCHEMA = "pii-eval.public-synthetic-artifact";
export const INTERNAL_SCHEMA = "pii-eval.run-artifact";
/** Document size cap of the format (docs/adr/0003). */
export const MAX_DOCUMENT_BYTES = 32 * 1024 * 1024;
const MAX_DEPTH = 32;
// The public artifact has exactly these members (schemas/public-synthetic-artifact.v1.schema.json,
// additionalProperties false); `diagnostics` exists only on the internal artifact, which is refused.
const TOP_LEVEL_FIELDS = ["schema", "schemaVersion", "semantic", "semanticDigest"];
const MAX_SAFE = Number.MAX_SAFE_INTEGER;

/** The closed vocabulary of the schema 1.2 product projection (ADR 0016). */
export const PROJECTION_VIEWS = ["benign-heavy-stress", "diagnostic-balanced", "oracle-plan", "qualification-plan"];
export const PROJECTION_MODES = ["exploratory", "official"];

/** The ten metric ids of protocol pii-v1 (docs/migration/ownership-map.md). */
export const METRIC_IDS = [
  "benign-suppression-rate",
  "context-discrimination-rate",
  "jurisdiction-collision-rate",
  "measurable-share",
  "non-sensitive-flag-rate",
  "range-collateral-rate",
  "sensitive-miss-rate",
  "type-miss-rate",
  "wrong-family-rate",
  "wrong-jurisdiction-rate",
];

/** Every rejection reason this program can report (documented in README.md). */
export const REASON_CODES = [
  "artifact-digest-not-pinned",
  "artifact-superseded",
  "digest-mismatch",
  "document-malformed",
  "document-too-large",
  "document-unreadable",
  "engine-mismatch",
  "incomplete-measurement",
  "internal-artifact-not-consumable",
  "legacy-schema-version",
  "manifest-mismatch",
  "manifest-superseded",
  "metrics-malformed",
  "metrics-missing",
  "population-digest-mismatch",
  "population-not-pinned",
  "population-version-mismatch",
  "population-visibility-mismatch",
  "projection-binding-mismatch",
  "projection-counts-mismatch",
  "projection-malformed",
  "projection-missing",
  "projection-mode-mismatch",
  "projection-mode-unknown",
  "projection-pooled-denominator",
  "projection-roster-mismatch",
  "projection-row-duplicate",
  "projection-view-missing",
  "projection-view-unknown",
  "protocol-mismatch",
  "run-class-mismatch",
  "scanner-activation-mismatch",
  "scanner-adapter-mismatch",
  "scanner-artifact-mismatch",
  "scanner-configuration-mismatch",
  "scanner-missing",
  "scanner-not-pinned",
  "scanner-product-mismatch",
  "scanner-version-mismatch",
  "schema-unsupported",
  "schema-version-unsupported",
  "unexpected-top-level-field",
];

// ---------------------------------------------------------------------------
// Strict JSON (ADR 0003): no duplicate keys, no null, integers only (|n| <=
// 2^53-1), no BOM, no trailing data, bounded nesting. JSON.parse cannot do this
// (it silently keeps the last duplicate and reads 1.0 as 1).
// ---------------------------------------------------------------------------

export class FormatError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

export function parseStrictJson(text) {
  if (typeof text !== "string") throw new FormatError("not-text");
  if (text.charCodeAt(0) === 0xfeff) throw new FormatError("byte-order-mark");
  let i = 0;
  const ws = () => {
    while (i < text.length && " \t\n\r".includes(text[i])) i++;
  };
  const value = (depth) => {
    if (depth > MAX_DEPTH) throw new FormatError("nesting-too-deep");
    ws();
    const c = text[i];
    if (c === "{") {
      i++;
      const out = Object.create(null);
      ws();
      if (text[i] === "}") {
        i++;
        return out;
      }
      for (;;) {
        ws();
        if (text[i] !== '"') throw new FormatError("malformed-json");
        const key = string();
        if (key in out) throw new FormatError("duplicate-key");
        ws();
        if (text[i++] !== ":") throw new FormatError("malformed-json");
        out[key] = value(depth + 1);
        ws();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i++] === "}") return out;
        throw new FormatError("malformed-json");
      }
    }
    if (c === "[") {
      i++;
      const out = [];
      ws();
      if (text[i] === "]") {
        i++;
        return out;
      }
      for (;;) {
        out.push(value(depth + 1));
        ws();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i++] === "]") return out;
        throw new FormatError("malformed-json");
      }
    }
    if (c === '"') return string();
    if (text.startsWith("true", i)) {
      i += 4;
      return true;
    }
    if (text.startsWith("false", i)) {
      i += 5;
      return false;
    }
    if (text.startsWith("null", i)) throw new FormatError("null-not-allowed");
    return number();
  };
  const string = () => {
    const start = i++;
    while (i < text.length && text[i] !== '"') {
      if (text[i] === "\\") i++;
      i++;
    }
    if (i >= text.length) throw new FormatError("malformed-json");
    i++;
    let s;
    try {
      s = JSON.parse(text.slice(start, i));
    } catch {
      throw new FormatError("malformed-json");
    }
    // A lone surrogate escape is not a valid Unicode string (the engine's parser refuses it).
    if (!s.isWellFormed()) throw new FormatError("invalid-unicode");
    return s;
  };
  const number = () => {
    const m = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(text.slice(i, i + 40));
    if (!m) throw new FormatError("malformed-json");
    i += m[0].length;
    if (m[2] !== undefined || m[3] !== undefined) throw new FormatError("float-not-allowed");
    if (m[0] === "-0") throw new FormatError("float-not-allowed");
    const n = Number(m[0]);
    if (!Number.isSafeInteger(n) || Math.abs(n) > MAX_SAFE) throw new FormatError("integer-out-of-range");
    return n;
  };
  const result = value(0);
  ws();
  if (i !== text.length) throw new FormatError("malformed-json");
  return result;
}

// ---------------------------------------------------------------------------
// Canonical form and semantic digest (ADR 0003).
// ---------------------------------------------------------------------------

function canonicalString(s) {
  let out = '"';
  for (const ch of s) {
    const cp = ch.codePointAt(0);
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (cp < 0x20) out += "\\u" + cp.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}

export function canonicalize(v) {
  if (typeof v === "string") return canonicalString(v);
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) throw new FormatError("float-not-allowed");
    return String(v);
  }
  if (Array.isArray(v)) return "[" + v.map(canonicalize).join(",") + "]";
  if (v && typeof v === "object") {
    // Ascending UTF-8 byte order of the keys (not UTF-16 code unit order).
    const keys = Object.keys(v).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
    return "{" + keys.map((k) => canonicalString(k) + ":" + canonicalize(v[k])).join(",") + "}";
  }
  throw new FormatError("unsupported-value");
}

export function semanticDigest(doc) {
  const domain = `${doc.schema}/${doc.schemaVersion}`;
  const input = `${DIGEST_CONSTRUCTION}\n${domain}\n${canonicalize(doc.semantic)}`;
  return createHash("sha256").update(input, "utf8").digest("hex");
}

// ---------------------------------------------------------------------------
// Verification of one artifact against one population pin.
// ---------------------------------------------------------------------------

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const same = (a, b) => canonicalize(a) === canonicalize(b);

function reason(code, field) {
  return field === undefined ? { code } : { code, field };
}

/**
 * Verify one parsed document against the whole pin set. Returns
 * `{ pin, reasons }`; the artifact is accepted exactly when `reasons` is empty.
 * `pin` is the population pin the artifact claims to belong to (matched by the
 * artifact's own population id), or undefined when it matches none.
 */
export function verifyArtifact(doc, pins) {
  const reasons = [];
  if (!isObject(doc) || typeof doc.schema !== "string") {
    return { pin: undefined, reasons: [reason("document-malformed", "schema")] };
  }
  if (doc.schema === INTERNAL_SCHEMA) {
    // The internal artifact carries per-case rows and observation identities. A
    // consumer never reads it; protected results arrive only through a
    // custodian-approved projection (docs/custodian-boundary.md).
    return { pin: undefined, reasons: [reason("internal-artifact-not-consumable", "schema")] };
  }
  if (doc.schema !== pins.artifactSchema.id) {
    return { pin: undefined, reasons: [reason("schema-unsupported", "schema")] };
  }
  if (doc.schemaVersion !== pins.artifactSchema.version) {
    reasons.push(
      doc.schemaVersion === "1.0"
        ? reason("legacy-schema-version", "schemaVersion")
        : reason("schema-version-unsupported", "schemaVersion"),
    );
    return { pin: undefined, reasons };
  }
  if (!isObject(doc.semantic) || typeof doc.semanticDigest !== "string") {
    return { pin: undefined, reasons: [reason("document-malformed", "semantic")] };
  }
  const sem = doc.semantic;
  // 0. Only the four members of the format. Anything outside `semantic` is not
  //    covered by the digest, so an extra member would travel unchecked.
  for (const k of Object.keys(doc)) {
    if (!TOP_LEVEL_FIELDS.includes(k)) {
      reasons.push(reason("unexpected-top-level-field", k));
      break;
    }
  }
  // 1. The stated digest is the digest of the body. Without this check every
  //    other field could be edited and still compare equal to a pin.
  let recomputed;
  try {
    recomputed = semanticDigest(doc);
  } catch {
    return { pin: undefined, reasons: [reason("document-malformed", "semantic")] };
  }
  if (recomputed !== doc.semanticDigest) reasons.push(reason("digest-mismatch", "semanticDigest"));

  // 2. Which population is it claiming to be?
  const popId = isObject(sem.population) ? sem.population.populationId : undefined;
  const pin = pins.populations.find((p) => p.population.populationId === popId);
  if (!pin) {
    reasons.push(reason("population-not-pinned", "population.populationId"));
    return { pin: undefined, reasons };
  }
  const bound = pin.population;

  // 3. Exact artifact pin, stale artifact, identities.
  if (doc.semanticDigest !== pin.artifactDigest) {
    reasons.push(
      pin.retiredArtifactDigests.includes(doc.semanticDigest)
        ? reason("artifact-superseded", "semanticDigest")
        : reason("artifact-digest-not-pinned", "semanticDigest"),
    );
  }
  if (!same(sem.engine, pins.engine)) reasons.push(reason("engine-mismatch", "engine"));
  if (!same(sem.protocol, pins.protocol)) reasons.push(reason("protocol-mismatch", "protocol"));
  if (sem.runClass !== pin.runClass) reasons.push(reason("run-class-mismatch", "runClass"));
  const p = sem.population;
  if (p.populationVersion !== bound.populationVersion) reasons.push(reason("population-version-mismatch", "population.populationVersion"));
  if (p.populationDigest !== bound.populationDigest) reasons.push(reason("population-digest-mismatch", "population.populationDigest"));
  if (p.visibility !== bound.visibility) reasons.push(reason("population-visibility-mismatch", "population.visibility"));
  if (sem.manifestDigest !== pin.manifestDigest) {
    reasons.push(
      pin.retiredManifestDigests.includes(sem.manifestDigest)
        ? reason("manifest-superseded", "manifestDigest")
        : reason("manifest-mismatch", "manifestDigest"),
    );
  }

  // 4. Scanner identities (candidate/configuration/activation bindings).
  const scanners = Array.isArray(sem.scanners) ? sem.scanners : [];
  const seen = new Set();
  for (const s of scanners) {
    const id = isObject(s) && isObject(s.identity) ? s.identity.scannerId : undefined;
    const want = pin.scanners.find((w) => w.scannerId === id);
    if (!want) {
      reasons.push(reason("scanner-not-pinned", "scanners"));
      continue;
    }
    seen.add(id);
    reasons.push(...compareScanner(s.identity, want));
    if (s.status !== "complete") reasons.push(reason("incomplete-measurement", "scanners.status"));
  }
  for (const want of pin.scanners) {
    if (!seen.has(want.scannerId)) reasons.push(reason("scanner-missing", "scanners"));
  }

  // 5. Completeness is reported, never assumed. An incomplete measurement
  //    stays incomplete; it is not turned into a number or a pass.
  if (pins.requireComplete) {
    if (sem.completeness !== "complete") reasons.push(reason("incomplete-measurement", "completeness"));
    if (!Array.isArray(sem.failures) || sem.failures.length !== 0) reasons.push(reason("incomplete-measurement", "failures"));
  }

  // 6. The metrics block must be present and arithmetically sane for every
  //    pinned scanner. (The engine's own verifier recomputes the values from
  //    the rows; this consumer reads only the public projection.)
  reasons.push(...checkMetrics(sem, pin));

  // 7. The product projection (schema 1.2), when the artifact carries one or
  //    the pin requires one.
  reasons.push(...checkProjection(sem, pin));

  return { pin, reasons: dedupe(reasons) };
}

const IDENTITY_FIELDS = [
  ["product", "scanner-product-mismatch"],
  ["artifactDigest", "scanner-artifact-mismatch"],
  ["configurationDigest", "scanner-configuration-mismatch"],
  ["activationDigest", "scanner-activation-mismatch"],
  ["adapter", "scanner-adapter-mismatch"],
  ["scannerVersion", "scanner-version-mismatch"],
];

function compareScanner(got, want) {
  const out = [];
  for (const [field, code] of IDENTITY_FIELDS) {
    if (!same(got[field], want[field])) out.push(reason(code, `scanners.identity.${field}`));
  }
  return out;
}

function checkMetrics(sem, pin) {
  const out = [];
  const blocks = Array.isArray(sem.scannerMetrics) ? sem.scannerMetrics : [];
  for (const want of pin.scanners) {
    const block = blocks.find((b) => isObject(b) && b.scannerId === want.scannerId);
    if (!block || !Array.isArray(block.metrics)) {
      out.push(reason("metrics-missing", "scannerMetrics"));
      continue;
    }
    const ids = block.metrics.map((m) => (isObject(m) && isObject(m.metric) ? m.metric.id : undefined));
    if (!same(ids.slice().sort(), METRIC_IDS.slice().sort())) out.push(reason("metrics-missing", "scannerMetrics.metrics"));
    for (const m of block.metrics) {
      const c = isObject(m) ? m.counts : undefined;
      const fields = ["eligible", "measured", "notApplicable", "notMeasured", "numerator", "total", "unresolved"];
      const ok =
        isObject(c) &&
        fields.every((f) => Number.isSafeInteger(c[f]) && c[f] >= 0) &&
        c.numerator <= c.measured &&
        c.measured <= c.eligible &&
        c.eligible <= c.total;
      if (!ok || !Number.isSafeInteger(m.effectiveN) || m.effectiveN < 0) {
        out.push(reason("metrics-malformed", "scannerMetrics.metrics.counts"));
        break;
      }
    }
  }
  return out;
}

const COUNT_FIELDS = ["authoredCases", "occurrences", "variants"];
const ROW_FIELDS = ["binding", "byControlClass", "byLanguage", "counts", "family", "methodCoverage", "metrics", "mode", "view"];
const BLOCK_FIELDS = ["requiredViews", "rosterDigest", "rows"];
const HEX = /^[0-9a-f]{64}$/;

const keysAre = (o, allowed, required) =>
  Object.keys(o).every((k) => allowed.includes(k)) && required.every((k) => k in o);
const nat = (n) => Number.isSafeInteger(n) && n >= 0;
const countsOk = (c) =>
  isObject(c) &&
  keysAre(c, COUNT_FIELDS, COUNT_FIELDS) &&
  COUNT_FIELDS.every((f) => nat(c[f])) &&
  c.variants >= c.authoredCases &&
  c.occurrences >= c.variants;

/** A metric list is the ten metrics, each once, with sane counts that fit `cases`. */
function metricProblems(metrics, cases, path, out) {
  if (!Array.isArray(metrics)) return out.push(reason("projection-malformed", path));
  const ids = metrics.map((m) => (isObject(m) && isObject(m.metric) ? m.metric.id : undefined));
  if (!same(ids.slice().sort(), METRIC_IDS.slice().sort())) return out.push(reason("projection-malformed", path));
  for (const m of metrics) {
    const c = m.counts;
    const fields = ["eligible", "measured", "notApplicable", "notMeasured", "numerator", "total", "unresolved"];
    const ok =
      isObject(c) && fields.every((f) => nat(c[f])) && nat(m.effectiveN) &&
      c.numerator <= c.measured && c.measured <= c.eligible && c.eligible <= c.total;
    if (!ok) return out.push(reason("projection-malformed", path));
    // One sample is one authored case (a trio for context discrimination); the
    // axis-assertion metric counts at most two assertions per case. A larger
    // total counts cases the row does not hold: a pooled denominator.
    const per = m.metric.id === "measurable-share" ? 2 : 1;
    if (c.total > cases * per) return out.push(reason("projection-pooled-denominator", path));
  }
}

/**
 * The schema 1.2 product projection (ADR 0016): one population, per
 * (scanner, view, family) rows. Rejects duplicate rows, absent required views,
 * pooled denominators, unknown modes and views, and a row whose binding differs
 * from the artifact. Never merges rows and never derives a verdict.
 */
function checkProjection(sem, pin) {
  const out = [];
  const block = sem.productProjection;
  const want = pin.projection;
  if (block === undefined) {
    if (want) out.push(reason("projection-missing", "productProjection"));
    return out;
  }
  const malformed = (field) => out.push(reason("projection-malformed", field));
  if (!isObject(block) || !keysAre(block, BLOCK_FIELDS, BLOCK_FIELDS) || !HEX.test(block.rosterDigest) || !Array.isArray(block.rows) || !Array.isArray(block.requiredViews)) {
    malformed("productProjection");
    return out;
  }
  const required = block.requiredViews;
  if (required.length === 0) malformed("productProjection.requiredViews");
  for (const v of required) if (!PROJECTION_VIEWS.includes(v)) out.push(reason("projection-view-unknown", "productProjection.requiredViews"));
  if (required.some((v, i) => i > 0 && !(required[i - 1] < v))) malformed("productProjection.requiredViews");
  if (want) {
    if (want.rosterDigest && want.rosterDigest !== block.rosterDigest) out.push(reason("projection-roster-mismatch", "productProjection.rosterDigest"));
    for (const v of want.requiredViews) if (!required.includes(v)) out.push(reason("projection-view-missing", "productProjection.requiredViews"));
  }

  const scanners = Array.isArray(sem.scanners) ? sem.scanners.filter(isObject) : [];
  const seen = new Set();
  const sums = new Map();
  let mode;
  block.rows.forEach((row, i) => {
    const at = `productProjection.rows[${i}]`;
    if (!isObject(row) || !keysAre(row, ROW_FIELDS, ["binding", "counts", "family", "methodCoverage", "metrics", "mode", "view"])) return malformed(at);
    if (!PROJECTION_MODES.includes(row.mode)) out.push(reason("projection-mode-unknown", `${at}.mode`));
    if (!PROJECTION_VIEWS.includes(row.view)) out.push(reason("projection-view-unknown", `${at}.view`));
    else if (!required.includes(row.view)) out.push(reason("projection-view-unknown", `${at}.view`));
    if (typeof row.family !== "string" || row.family.length === 0) return malformed(`${at}.family`);
    if (!isObject(row.binding) || typeof row.binding.scannerId !== "string") return malformed(`${at}.binding`);
    const key = `${row.binding.scannerId}|${row.view}|${row.family}`;
    if (seen.has(key)) out.push(reason("projection-row-duplicate", at));
    seen.add(key);
    // One mode for the whole artifact, and the pinned one when pinned.
    if (PROJECTION_MODES.includes(row.mode)) {
      mode ??= row.mode;
      if (row.mode !== mode || (want?.mode && row.mode !== want.mode)) out.push(reason("projection-mode-mismatch", `${at}.mode`));
    }
    // Binding: the row says it belongs to this artifact's scanner and population.
    const s = scanners.find((x) => isObject(x.identity) && x.identity.scannerId === row.binding.scannerId);
    const b = row.binding;
    const bound =
      s !== undefined &&
      b.configurationDigest === s.identity.configurationDigest &&
      b.activationDigest === s.identity.activationDigest &&
      same(b.product, s.identity.product) &&
      same(b.population, sem.population);
    if (!bound) out.push(reason("projection-binding-mismatch", `${at}.binding`));
    // Counts: the row's own, inside the row's own cases.
    if (!countsOk(row.counts)) return malformed(`${at}.counts`);
    const cov = row.methodCoverage;
    if (!Array.isArray(cov) || cov.some((m) => !isObject(m) || !nat(m.cases) || !nat(m.variants))) return malformed(`${at}.methodCoverage`);
    if (cov.reduce((a, m) => a + m.cases, 0) !== row.counts.authoredCases || cov.reduce((a, m) => a + m.variants, 0) !== row.counts.variants) {
      out.push(reason("projection-counts-mismatch", `${at}.methodCoverage`));
    }
    metricProblems(row.metrics, row.counts.authoredCases, `${at}.metrics`, out);
    for (const [name, partition] of [["byLanguage", true], ["byControlClass", false]]) {
      const strata = row[name];
      if (strata === undefined) continue;
      if (!Array.isArray(strata) || strata.some((x) => !isObject(x) || !countsOk(x.counts))) {
        malformed(`${at}.${name}`);
        continue;
      }
      strata.forEach((x, j) => metricProblems(x.metrics, x.counts.authoredCases, `${at}.${name}[${j}].metrics`, out));
      const total = (f) => strata.reduce((a, x) => a + x.counts[f], 0);
      const over = COUNT_FIELDS.some((f) => total(f) > row.counts[f]);
      const under = partition && strata.length > 0 && COUNT_FIELDS.some((f) => total(f) < row.counts[f]);
      if (over) out.push(reason("projection-pooled-denominator", `${at}.${name}`));
      else if (under) out.push(reason("projection-counts-mismatch", `${at}.${name}`));
    }
    const sum = sums.get(row.binding.scannerId) ?? { authoredCases: 0, occurrences: 0, variants: 0 };
    for (const f of COUNT_FIELDS) sum[f] += row.counts[f];
    sums.set(row.binding.scannerId, sum);
  });
  // Every scanner has every required view, and its rows add up to the
  // population exactly: more is a pooled denominator, less a missing cell.
  const pc = sem.populationCounts;
  for (const s of scanners) {
    const id = s.identity?.scannerId;
    for (const v of required) {
      if (!block.rows.some((r) => isObject(r) && isObject(r.binding) && r.binding.scannerId === id && r.view === v)) {
        out.push(reason("projection-view-missing", "productProjection.rows"));
      }
    }
    const sum = sums.get(id) ?? { authoredCases: 0, occurrences: 0, variants: 0 };
    if (isObject(pc) && COUNT_FIELDS.some((f) => sum[f] > pc[f])) out.push(reason("projection-pooled-denominator", "productProjection.rows"));
    else if (isObject(pc) && COUNT_FIELDS.some((f) => sum[f] !== pc[f])) out.push(reason("projection-counts-mismatch", "productProjection.rows"));
  }
  return out;
}

function dedupe(reasons) {
  const seen = new Set();
  return reasons.filter((r) => {
    const k = `${r.code}|${r.field ?? ""}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

// ---------------------------------------------------------------------------
// Pins.
// ---------------------------------------------------------------------------

const HEX64 = /^[0-9a-f]{64}$/;
export const PUBLIC_SCHEMA_VERSION = "1.1";
/** The schema versions a pin may name. 1.2 adds the optional product projection (ADR 0016). */
export const PUBLIC_SCHEMA_VERSIONS = ["1.1", "1.2"];

/**
 * Validate and normalize the caller's pin document, strictly: an unusable pin
 * file is a usage error (exit 2), never a quiet partial pin. Throws FormatError.
 */
export function loadPins(text) {
  const p = parseStrictJson(text);
  const need = (cond, code) => {
    if (!cond) throw new FormatError(code);
  };
  const str = (v) => typeof v === "string" && v.length > 0;
  need(isObject(p) && p.schema === PINS_SCHEMA, "pins-schema");
  need(isObject(p.engine) && isObject(p.protocol), "pins-identity");
  need(
    isObject(p.artifactSchema) && p.artifactSchema.id === PUBLIC_SCHEMA && PUBLIC_SCHEMA_VERSIONS.includes(p.artifactSchema.version),
    "pins-artifact-schema",
  );
  need(typeof p.requireComplete === "boolean", "pins-require-complete");
  need(Array.isArray(p.populations) && p.populations.length > 0, "pins-populations");
  const labels = new Set();
  const ids = new Set();
  for (const q of p.populations) {
    need(isObject(q) && str(q.label) && !labels.has(q.label), "pins-label");
    labels.add(q.label);
    const pop = q.population;
    need(
      isObject(pop) && str(pop.populationId) && !ids.has(pop.populationId) && Number.isSafeInteger(pop.populationVersion) &&
        HEX64.test(pop.populationDigest) && pop.visibility === "public-synthetic",
      "pins-population",
    );
    ids.add(pop.populationId);
    need(q.runClass === "public-synthetic", "pins-run-class");
    need(HEX64.test(q.artifactDigest) && HEX64.test(q.manifestDigest), "pins-digests");
    q.retiredArtifactDigests ??= [];
    q.retiredManifestDigests ??= [];
    need(
      Array.isArray(q.retiredArtifactDigests) && Array.isArray(q.retiredManifestDigests) &&
        [...q.retiredArtifactDigests, ...q.retiredManifestDigests].every((d) => HEX64.test(d)),
      "pins-retired",
    );
    // A digest cannot be both the head and retired.
    need(!q.retiredArtifactDigests.includes(q.artifactDigest) && !q.retiredManifestDigests.includes(q.manifestDigest), "pins-head-retired");
    // An optional projection pin: the views the population's artifact must
    // cover, the mode, and optionally the roster digest. Schema 1.2 only.
    if (q.projection !== undefined) {
      const w = q.projection;
      need(
        p.artifactSchema.version === "1.2" && isObject(w) && Array.isArray(w.requiredViews) && w.requiredViews.length > 0 &&
          w.requiredViews.every((v) => PROJECTION_VIEWS.includes(v)) && new Set(w.requiredViews).size === w.requiredViews.length &&
          (w.mode === undefined || PROJECTION_MODES.includes(w.mode)) && (w.rosterDigest === undefined || HEX64.test(w.rosterDigest)),
        "pins-projection",
      );
    }
    need(Array.isArray(q.scanners) && q.scanners.length > 0, "pins-scanners");
    const scannerIds = new Set();
    for (const s of q.scanners) {
      need(
        isObject(s) && str(s.scannerId) && !scannerIds.has(s.scannerId) && isObject(s.product) && str(s.product.kind) &&
          HEX64.test(s.artifactDigest) && HEX64.test(s.configurationDigest) && HEX64.test(s.activationDigest) &&
          isObject(s.adapter) && str(s.scannerVersion),
        "pins-scanner",
      );
      scannerIds.add(s.scannerId);
    }
  }
  return p;
}

// ---------------------------------------------------------------------------
// Composition: several populations side by side, never pooled.
// ---------------------------------------------------------------------------

/**
 * `artifacts` is a list of `{ name, text }` or `{ name, failure }` (a reason object). Returns the report. The
 * report depends on the pins and on the artifacts' content only, not on the
 * order in which they were supplied.
 */
export function consume(pins, artifacts) {
  const rejections = [];
  const acceptedByLabel = new Map();
  const considered = [...artifacts].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  for (const art of considered) {
    let doc;
    let reasons;
    let pin;
    if (art.failure) {
      // The file could not be read as a bounded UTF-8 document: carry the explicit code.
      reasons = [art.failure];
    } else if (Buffer.byteLength(art.text, "utf8") > MAX_DOCUMENT_BYTES) {
      reasons = [reason("document-too-large")];
    } else {
      try {
        doc = parseStrictJson(art.text);
        ({ pin, reasons } = verifyArtifact(doc, pins));
      } catch (e) {
        reasons = [e instanceof FormatError ? reason("document-malformed", e.code) : reason("document-unreadable")];
      }
    }
    if (reasons.length > 0) {
      rejections.push({ file: art.name, label: pin?.label, reasons });
    } else if (!acceptedByLabel.has(pin.label)) {
      acceptedByLabel.set(pin.label, { name: art.name, doc });
    }
    // The same document supplied twice is one acceptance, not two samples.
  }
  const populations = pins.populations.map((pin) => {
    const hit = acceptedByLabel.get(pin.label);
    if (!hit) return { label: pin.label, populationId: pin.population.populationId, status: "missing" };
    const sem = hit.doc.semantic;
    return {
      artifactDigest: hit.doc.semanticDigest,
      file: hit.name,
      label: pin.label,
      population: sem.population,
      populationCounts: sem.populationCounts,
      populationId: pin.population.populationId,
      productProjection: sem.productProjection,
      scanners: pin.scanners.map((want) => {
        const s = sem.scanners.find((x) => x.identity.scannerId === want.scannerId);
        const block = sem.scannerMetrics.find((b) => b.scannerId === want.scannerId);
        return {
          identity: s.identity,
          metrics: block.metrics,
          scannerId: want.scannerId,
          status: s.status,
        };
      }),
      status: "accepted",
    };
  });
  const complete = rejections.length === 0 && populations.every((p) => p.status === "accepted");
  return {
    complete,
    // Always "none": this program verifies identity and composes. It never
    // decides support, thresholds, stable or provisional status.
    decision: "none",
    // Always "none": each population keeps its own counts and denominators.
    pooling: "none",
    populations,
    rejections,
    schema: REPORT_SCHEMA,
  };
}

function sortedJson(v) {
  if (Array.isArray(v)) return "[" + v.map(sortedJson).join(",") + "]";
  if (v && typeof v === "object") {
    const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + sortedJson(v[k])).join(",") + "}";
  }
  return JSON.stringify(v);
}

export function renderReport(report) {
  return sortedJson(report) + "\n";
}

// ---------------------------------------------------------------------------
// Command line.
// ---------------------------------------------------------------------------

/** Read a bounded, strictly valid UTF-8 file. Throws FormatError with the explicit failure code. */
function readBounded(path) {
  let bytes;
  try {
    const st = statSync(path);
    if (!st.isFile()) throw new FormatError("document-unreadable");
    if (st.size > MAX_DOCUMENT_BYTES) throw new FormatError("document-too-large");
    bytes = readFileSync(path);
  } catch (e) {
    throw e instanceof FormatError ? e : new FormatError("document-unreadable");
  }
  if (bytes.length > MAX_DOCUMENT_BYTES) throw new FormatError("document-too-large");
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new FormatError("invalid-utf8");
  }
}

function failureOf(e) {
  const code = e instanceof FormatError ? e.code : "document-unreadable";
  return code === "invalid-utf8" ? reason("document-malformed", "invalid-utf8") : reason(code);
}

export function main(argv, stdout = process.stdout, stderr = process.stderr) {
  let pinsPath;
  const files = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--pins") pinsPath = argv[++i];
    else if (argv[i].startsWith("--")) {
      stderr.write("usage: consume.mjs --pins PINS.json ARTIFACT.json...\n");
      return 2;
    } else files.push(argv[i]);
  }
  if (!pinsPath || files.length === 0) {
    stderr.write("usage: consume.mjs --pins PINS.json ARTIFACT.json...\n");
    return 2;
  }
  let pins;
  try {
    pins = loadPins(readBounded(pinsPath));
  } catch (e) {
    stderr.write(`consume: pins unusable (${e instanceof FormatError ? e.code : "unreadable"})\n`);
    return 2;
  }
  const artifacts = files.map((f) => {
    try {
      return { name: basename(f), text: readBounded(f) };
    } catch (e) {
      // An unreadable or oversized file is a rejected artifact, never skipped.
      return { name: basename(f), failure: failureOf(e) };
    }
  });
  const report = consume(pins, artifacts);
  stdout.write(renderReport(report));
  return report.complete ? 0 : 1;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  process.exitCode = main(process.argv.slice(2));
}
