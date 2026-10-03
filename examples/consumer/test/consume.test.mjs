// Tests of the reference consumer. Run: node --test examples/consumer/test
// (Node 22, no install step, no network). The artifacts under ../fixtures were
// produced by the real engine (crates/pii-eval-cli/tests/consumer_fixtures.rs);
// mutated variants are re-sealed with the consumer's own digest function, which
// the positive tests have shown to reproduce the engine's digests exactly.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  canonicalize,
  consume,
  loadPins,
  REASON_CODES,
  parseStrictJson,
  renderReport,
  semanticDigest,
} from "../consume.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "..", "fixtures");
const cli = join(here, "..", "consume.mjs");
const read = (n) => readFileSync(join(fixtures, n), "utf8");

const A1 = "population-a-v1.public-synthetic-artifact.json";
const A2 = "population-a-v2.public-synthetic-artifact.json";
const OTHER = "population-a-v2.other-candidate.public-synthetic-artifact.json";
const INTERNAL = "population-a-v2.run-artifact.json";
const B1 = "population-b-v1.public-synthetic-artifact.json";

const pinsText = read("pins.json");
const pins = () => loadPins(pinsText);
const art = (name, text = read(name)) => ({ name, text });

/** Edit the semantic body of an artifact and re-seal it with a correct digest. */
function mutated(name, edit) {
  const doc = JSON.parse(read(name));
  edit(doc.semantic);
  doc.semanticDigest = semanticDigest(doc);
  return JSON.stringify(doc);
}

function codesOf(report, file) {
  const r = report.rejections.find((x) => x.file === file);
  assert.ok(r, `${file} was rejected`);
  return r.reasons.map((x) => x.code);
}

// -- format ---------------------------------------------------------------

test("canonical form sorts keys by UTF-8 bytes and escapes only what the format escapes", () => {
  // U+FF5E sorts after U+10000 by UTF-8 bytes, before it by UTF-16 code units.
  assert.equal(canonicalize({ "\u{10000}": 1, "～": 2, b: 3, a: 4 }), '{"a":4,"b":3,"～":2,"\u{10000}":1}');
  assert.equal(canonicalize("a\"b\\c\n\u007f/ "), '"a\\"b\\\\c\\u000a\u007f/ "');
});

test("strict parsing rejects what the format rejects", () => {
  const bad = {
    '{"a":1,"a":2}': "duplicate-key",
    '{"a":null}': "null-not-allowed",
    '{"a":1.0}': "float-not-allowed",
    '{"a":1e2}': "float-not-allowed",
    '{"a":-0}': "float-not-allowed",
    '{"a":9007199254740992}': "integer-out-of-range",
    "{}x": "malformed-json",
    "﻿{}": "byte-order-mark",
    ["[".repeat(40) + "]".repeat(40)]: "nesting-too-deep",
  };
  for (const [text, code] of Object.entries(bad)) {
    assert.throws(() => parseStrictJson(text), { code }, text);
  }
  assert.deepEqual({ ...parseStrictJson('{"a":[1,-2,true],"b":"\\u00e9"}') }, { a: [1, -2, true], b: "é" });
});

// -- acceptance -----------------------------------------------------------

test("two separately identified populations are composed side by side and never pooled", () => {
  const report = consume(pins(), [art(A2), art(B1)]);
  assert.equal(report.complete, true);
  assert.equal(report.decision, "none");
  assert.equal(report.pooling, "none");
  assert.deepEqual(report.rejections, []);
  assert.deepEqual(
    report.populations.map((p) => [p.label, p.status, p.population.populationVersion]),
    [
      ["population-a", "accepted", 2],
      ["population-b", "accepted", 1],
    ],
  );
  // Each population keeps its own identity, counts and denominators.
  const [a, b] = report.populations;
  assert.notEqual(a.population.populationDigest, b.population.populationDigest);
  assert.notDeepEqual(a.populationCounts, b.populationCounts);
  const metricsOf = (p) => p.scanners[0].metrics;
  assert.equal(metricsOf(a).length, 10);
  assert.notDeepEqual(
    metricsOf(a).map((m) => m.counts),
    metricsOf(b).map((m) => m.counts),
  );
  // No field of the report pools, ranks or decides.
  const names = new Set();
  const walk = (v) => {
    if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === "object")
      for (const [k, x] of Object.entries(v)) {
        names.add(k);
        walk(x);
      }
  };
  walk(report);
  for (const forbidden of ["pooled", "combined", "overall", "rank", "score", "verdict", "stable", "provisional", "status-decision", "threshold", "support"]) {
    assert.ok(!names.has(forbidden), forbidden);
  }
});

test("the report depends on the artifacts, not on the order they were given", () => {
  const one = renderReport(consume(pins(), [art(A2), art(B1)]));
  const two = renderReport(consume(pins(), [art(B1), art(A2)]));
  assert.equal(one, two);
});

test("a withheld metric stays withheld and is never turned into a number", () => {
  const report = consume(pins(), [art(A2), art(B1)]);
  const withheld = report.populations.flatMap((p) => p.scanners[0].metrics).filter((m) => m.value.state === "withheld");
  assert.ok(withheld.length > 0, "the synthetic populations are small, so some metrics are withheld");
  for (const m of withheld) assert.ok(!("point" in m.value) && typeof m.value.reason === "string");
});

// -- rejection ------------------------------------------------------------

test("a superseded (stale) artifact is rejected with its reasons", () => {
  const report = consume(pins(), [art(A1), art(A2), art(B1)]);
  assert.equal(report.complete, false);
  const codes = codesOf(report, A1);
  for (const c of ["artifact-superseded", "manifest-superseded", "population-version-mismatch", "population-digest-mismatch"]) {
    assert.ok(codes.includes(c), c);
  }
  // The head is still accepted and composed; the stale file is not.
  assert.deepEqual(report.populations.map((p) => p.status), ["accepted", "accepted"]);
  assert.equal(report.populations[0].file, A2);
});

test("an artifact that is the right population but another candidate build is rejected", () => {
  const report = consume(pins(), [art(OTHER), art(B1)]);
  const codes = codesOf(report, OTHER);
  for (const c of ["scanner-artifact-mismatch", "scanner-product-mismatch", "artifact-digest-not-pinned", "manifest-mismatch"]) {
    assert.ok(codes.includes(c), c);
  }
  assert.equal(report.populations[0].status, "missing");
});

test("the internal run artifact is never consumable", () => {
  const report = consume(pins(), [art(INTERNAL), art(B1)]);
  assert.deepEqual(codesOf(report, INTERNAL), ["internal-artifact-not-consumable"]);
  assert.equal(report.populations[0].status, "missing");
});

test("a legacy schema 1.0 artifact is rejected", () => {
  const legacy = readFileSync(join(here, "..", "..", "..", "fixtures", "contracts", "v1", "public-synthetic-artifact.json"), "utf8");
  const report = consume(pins(), [art("legacy.json", legacy), art(B1)]);
  assert.deepEqual(codesOf(report, "legacy.json"), ["legacy-schema-version"]);
});

test("an edited body fails its digest even when every edited field would otherwise match", () => {
  const doc = JSON.parse(read(A2));
  doc.semantic.populationCounts.variants += 1;
  const report = consume(pins(), [art(A2, JSON.stringify(doc)), art(B1)]);
  assert.ok(codesOf(report, A2).includes("digest-mismatch"));
});

test("bindings are checked one by one against the exact pins", () => {
  const cases = [
    ["engine-mismatch", (s) => (s.engine.version = "9.9.9")],
    ["protocol-mismatch", (s) => (s.protocol.version = 3)],
    ["run-class-mismatch", (s) => (s.runClass = "protected")],
    ["population-visibility-mismatch", (s) => (s.population.visibility = "protected")],
    ["population-digest-mismatch", (s) => (s.population.populationDigest = "0".repeat(64))],
    ["manifest-mismatch", (s) => (s.manifestDigest = "1".repeat(64))],
    ["scanner-activation-mismatch", (s) => (s.scanners[0].identity.activationDigest = "2".repeat(64))],
    ["scanner-configuration-mismatch", (s) => (s.scanners[0].identity.configurationDigest = "3".repeat(64))],
    ["scanner-artifact-mismatch", (s) => (s.scanners[0].identity.artifactDigest = "4".repeat(64))],
    ["scanner-version-mismatch", (s) => (s.scanners[0].identity.scannerVersion = "0.0.1")],
    ["scanner-adapter-mismatch", (s) => (s.scanners[0].identity.adapter.adapterVersion = "9.0.0")],
    ["incomplete-measurement", (s) => (s.scanners[0].status = "failed")],
    ["incomplete-measurement", (s) => (s.completeness = "incomplete")],
    ["metrics-missing", (s) => s.scannerMetrics[0].metrics.pop()],
    ["metrics-malformed", (s) => (s.scannerMetrics[0].metrics[0].counts.numerator = 1000)],
    ["scanner-missing", (s) => (s.scanners = [])],
    ["artifact-digest-not-pinned", (s) => (s.populationCounts.variants += 1)],
  ];
  for (const [code, edit] of cases) {
    const report = consume(pins(), [art(A2, mutated(A2, edit)), art(B1)]);
    assert.ok(codesOf(report, A2).includes(code), `${code}: ${JSON.stringify(codesOf(report, A2))}`);
    assert.equal(report.complete, false, code);
  }
});

test("a candidate result is never accepted as released", () => {
  const p = JSON.parse(pinsText);
  p.populations[0].scanners[0].product = { kind: "released" };
  const report = consume(loadPins(JSON.stringify(p)), [art(A2), art(B1)]);
  assert.ok(codesOf(report, A2).includes("scanner-product-mismatch"));
});

test("an artifact for a population that is not pinned is rejected, and a missing one is reported", () => {
  const other = mutated(A2, (s) => (s.population.populationId = "somebody-elses-population"));
  const report = consume(pins(), [art("elsewhere.json", other), art(B1)]);
  assert.deepEqual(codesOf(report, "elsewhere.json"), ["population-not-pinned"]);
  assert.deepEqual(report.populations.map((p) => p.status), ["missing", "accepted"]);
  assert.equal(report.complete, false);
});

test("a missing population is not filled in from another", () => {
  const report = consume(pins(), [art(B1)]);
  assert.deepEqual(report.populations.map((p) => p.status), ["missing", "accepted"]);
  assert.equal(report.complete, false);
});

test("the same document supplied twice is one acceptance", () => {
  const report = consume(pins(), [art(A2), art("copy.json", read(A2)), art(B1)]);
  assert.equal(report.complete, true);
  assert.equal(report.populations[0].file, "copy.json" < A2 ? "copy.json" : A2);
});

test("malformed input is a rejection, never a crash or a pass", () => {
  for (const text of ["", "{", "[]", '{"schema": 1}', '{"schema":"pii-eval.public-synthetic-artifact","schemaVersion":"1.1","semantic":{},"semanticDigest":"x"}', '{"a":1,"a":2}']) {
    const report = consume(pins(), [art("bad.json", text), art(A2), art(B1)]);
    assert.equal(report.complete, false, text);
    assert.ok(report.rejections.some((r) => r.file === "bad.json"), text);
  }
});

test("pins that are not exact are refused", () => {
  const p = JSON.parse(pinsText);
  assert.throws(() => loadPins(JSON.stringify({ ...p, schema: "other/1" })), { code: "pins-schema" });
  assert.throws(() => loadPins(JSON.stringify({ ...p, populations: [] })), { code: "pins-populations" });
  assert.throws(() => loadPins(JSON.stringify({ ...p, requireComplete: "yes" })), { code: "pins-require-complete" });
  const dup = { ...p, populations: [p.populations[0], p.populations[0]] };
  assert.throws(() => loadPins(JSON.stringify(dup)), { code: "pins-label" });
});

test("pins are validated strictly: unusable pins are never partially applied", () => {
  const edit = (f) => {
    const p = JSON.parse(pinsText);
    f(p);
    return JSON.stringify(p);
  };
  const bad = {
    "pins-artifact-schema": (p) => (p.artifactSchema.version = "1.0"),
    "pins-run-class": (p) => (p.populations[0].runClass = "protected"),
    "pins-population": (p) => (p.populations[0].population.visibility = "protected"),
    "pins-digests": (p) => (p.populations[0].artifactDigest = "abc"),
    "pins-head-retired": (p) => p.populations[0].retiredArtifactDigests.push(p.populations[0].artifactDigest),
    "pins-scanner": (p) => delete p.populations[0].scanners[0].activationDigest,
    "pins-scanners": (p) => (p.populations[0].scanners = []),
  };
  for (const [code, f] of Object.entries(bad)) assert.throws(() => loadPins(edit(f)), { code }, code);
  const noAdapter = edit((p) => delete p.populations[1].scanners[0].adapter);
  assert.throws(() => loadPins(noAdapter), { code: "pins-scanner" });
});

test("an injected top-level member is rejected, not accepted unchecked", () => {
  const doc = JSON.parse(read(A2));
  doc.rawOutput = "secret";
  const report = consume(pins(), [art(A2, JSON.stringify(doc)), art(B1)]);
  assert.deepEqual(codesOf(report, A2), ["unexpected-top-level-field"]);
  assert.equal(report.rejections[0].reasons[0].field, "rawOutput");
  assert.equal(report.populations[0].status, "missing");
});

test("unreadable, oversized and non-UTF-8 files carry their explicit codes", () => {
  const dir = mkdtempSync(join(tmpdir(), "consume-test-"));
  try {
    const big = join(dir, "big.json");
    writeFileSync(big, Buffer.alloc(33 * 1024 * 1024, 0x20));
    const badUtf8 = join(dir, "bad-utf8.json");
    writeFileSync(badUtf8, Buffer.from([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d]));
    const surrogate = join(dir, "surrogate.json");
    writeFileSync(surrogate, '{"a":"\\ud800"}');
    const out = run(["--pins", join(fixtures, "pins.json"), big, join(dir, "missing.json"), badUtf8, surrogate, join(fixtures, A2), join(fixtures, B1)]);
    assert.equal(out.status, 1);
    const report = JSON.parse(out.stdout);
    const by = Object.fromEntries(report.rejections.map((r) => [r.file, r.reasons[0]]));
    assert.deepEqual(by["big.json"], { code: "document-too-large" });
    assert.deepEqual(by["missing.json"], { code: "document-unreadable" });
    assert.deepEqual(by["bad-utf8.json"], { code: "document-malformed", field: "invalid-utf8" });
    assert.deepEqual(by["surrogate.json"], { code: "document-malformed", field: "invalid-unicode" });
    assert.equal(report.populations.every((p) => p.status === "accepted"), true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// -- command line and independence ----------------------------------------

function run(args) {
  const r = spawnSync(process.execPath, [cli, ...args], { encoding: "utf8" });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

test("exit codes: 0 only when everything supplied was accepted", () => {
  const f = (n) => join(fixtures, n);
  const ok = run(["--pins", f("pins.json"), f(A2), f(B1)]);
  assert.equal(ok.status, 0, ok.stderr);
  assert.equal(ok.stdout.split("\n").length, 2, "one line of JSON");
  assert.equal(JSON.parse(ok.stdout).schema, "pii-eval-consumer-report/1");
  const stale = run(["--pins", f("pins.json"), f(A1), f(A2), f(B1)]);
  assert.equal(stale.status, 1);
  const missingFile = run(["--pins", f("pins.json"), f("nope.json"), f(A2), f(B1)]);
  assert.equal(missingFile.status, 1);
  assert.equal(run([]).status, 2);
  assert.equal(run(["--pins", f("nope.json"), f(A2)]).status, 2);
  assert.equal(run(["--pins", f("pins.json"), "--unknown", f(A2)]).status, 2);
});

test("REASON_CODES is exactly the set of codes the source can emit", () => {
  const source = readFileSync(cli, "utf8");
  const emitted = new Set([...source.matchAll(/reason\("([a-z-]+)"/g)].map((m) => m[1]));
  for (const m of source.matchAll(/\["[A-Za-z]+", "(scanner-[a-z-]+)"\]/g)) emitted.add(m[1]);
  assert.deepEqual([...emitted].sort(), [...REASON_CODES].sort());
  assert.equal(new Set(REASON_CODES).size, REASON_CODES.length);
});

test("the consumer imports only the Node standard library and no pii-eval code", () => {
  const source = readFileSync(cli, "utf8");
  const imports = [...source.matchAll(/^import .* from "([^"]+)";$/gm)].map((m) => m[1]);
  assert.ok(imports.length > 0);
  for (const spec of imports) assert.ok(spec.startsWith("node:"), spec);
  assert.ok(!/require\(|import\(/.test(source), "no dynamic loading");
  for (const forbidden of ["crates/", "pii_eval", "kernel", "Cargo"]) {
    assert.ok(!source.replace(/\/\/.*$/gm, "").includes(forbidden), forbidden);
  }
});
