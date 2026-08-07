// The gaps script reports on MITRE's data, so a silent mis-parse would turn
// every finding into confident nonsense addressed to its maintainers.
//
// This nearly happened. The first reader hardcoded indentation columns; ATLAS
// puts sequence items at the SAME column as their key, so it matched nothing
// and reported "YAML distinct edges: 0" while still printing findings built on
// that empty parse. The guard below is what makes the hand-rolled reader an
// acceptable trade for having no dependencies.
//
// Run: node --test

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const SCRIPT = fileURLToPath(new URL('../scripts/atlas-gaps.mjs', import.meta.url));

// Minimal ATLAS-shaped YAML: sequence items at the same column as their key,
// which is the shape that broke the first reader.
const YAML = `id: ATLAS
name: ATLAS Matrix
matrices:
- id: ATLAS
  techniques:
  - id: AML.T0100
    name: Parent Technique
    created_date: 2021-05-13
  - id: AML.T0100.000
    name: Child With No Mitigation
    created_date: 2026-01-15
  mitigations:
  - id: AML.M0100
    name: Some Control
    created_date: 2021-05-13
    techniques:
    - id: AML.T0100
      use: 'covers the parent only'
`;

const STIX = JSON.stringify({
  type: 'bundle', id: 'bundle--t',
  objects: [
    { type: 'attack-pattern', id: 'ap-1', name: 'Parent Technique',
      external_references: [{ source_name: 'mitre-atlas', external_id: 'AML.T0100' }] },
    { type: 'course-of-action', id: 'coa-1', name: 'Some Control',
      external_references: [{ source_name: 'mitre-atlas', external_id: 'AML.M0100' }] },
    { type: 'relationship', id: 'rel-1', relationship_type: 'mitigates', source_ref: 'coa-1', target_ref: 'ap-1' }
  ]
});

// The script refuses to report over a parse that looks too thin — see the
// REFUSES test below. Any fixture that needs to reach the reporting stage has
// to clear that floor, so build a realistic-sized corpus rather than lowering
// the guard.
function paddedYaml() {
  const pad = Array.from({ length: 170 }, (_, i) => {
    const n = String(i).padStart(3, '0');
    return `  - id: AML.T9${n}\n    name: Padding ${n}\n    created_date: 2021-05-13`;
  }).join('\n');
  const mits = Array.from({ length: 35 }, (_, i) => {
    const n = String(i).padStart(3, '0');
    const refs = [0, 1, 2, 3]
      .map((k) => `    - id: AML.T9${String((i * 4 + k) % 170).padStart(3, '0')}\n      use: 'x'`)
      .join('\n');
    return `  - id: AML.M9${n}\n    name: Pad Control ${n}\n    created_date: 2021-05-13\n    techniques:\n${refs}`;
  }).join('\n');
  return YAML.replace('  mitigations:', `${pad}\n  mitigations:`).replace(/$/, `\n${mits}\n`);
}

function run(files, expectFail = false) {
  const dir = mkdtempSync(join(tmpdir(), 'atlas-gaps-'));
  for (const [n, b] of Object.entries(files)) writeFileSync(join(dir, n), b);
  try {
    const out = execFileSync('node', [SCRIPT, '--yaml', join(dir, 'a.yaml'), '--stix', join(dir, 'b.json'), '--json'],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    if (expectFail) assert.fail('the script accepted a parse it should have refused');
    return JSON.parse(out);
  } catch (err) {
    if (!expectFail) throw err;
    return { failed: true, status: err.status, stderr: String(err.stderr ?? '') };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('reads sequence items that sit at their key\'s column', () => {
  // 2 techniques / 1 mitigation is below the sanity floor, so relax it by
  // padding the file to a realistic size rather than weakening the guard.
  const pad = Array.from({ length: 170 }, (_, i) => {
    const n = String(i).padStart(3, '0');
    return `  - id: AML.T9${n}\n    name: Padding ${n}\n    created_date: 2021-05-13`;
  }).join('\n');
  // Each pad mitigation covers several techniques: the guard's floor is 100
  // edges, calibrated for the real corpus, and it correctly rejected a fixture
  // carrying 36. Padding the fixture is the fix; lowering the floor would have
  // been quietly disarming the thing under test.
  const mits = Array.from({ length: 35 }, (_, i) => {
    const n = String(i).padStart(3, '0');
    const refs = [0, 1, 2, 3]
      .map((k) => `    - id: AML.T9${String((i * 4 + k) % 170).padStart(3, '0')}\n      use: 'x'`)
      .join('\n');
    return `  - id: AML.M9${n}\n    name: Pad Control ${n}\n    created_date: 2021-05-13\n    techniques:\n${refs}`;
  }).join('\n');
  const big = YAML.replace('  mitigations:', `${pad}\n  mitigations:`).replace(/$/, `\n${mits}\n`);
  const r = run({ 'a.yaml': big, 'b.json': STIX });
  assert.ok(r.parsed.techniques >= 170, `parsed only ${r.parsed.techniques} techniques`);
  assert.ok(r.parsed.edges >= 35, `parsed only ${r.parsed.edges} edges`);
});

test('REFUSES to report findings over a parse that produced nothing', () => {
  // The exact failure that shipped: a file the reader cannot understand must
  // stop the run, not yield a clean-looking report with zero in every field.
  const unparseable = YAML.replace(/^ {2}/gm, '\t');
  const r = run({ 'a.yaml': unparseable, 'b.json': STIX }, true);
  assert.equal(r.status, 2, 'expected a hard exit, not a report');
  assert.match(r.stderr, /parse looks wrong|refusing/i);
});

// ---------------------------------------------------------------------------
// This script keeps its own copy of atlasId so it stays runnable standalone —
// which is the property that lets anyone outside this repository reproduce the
// findings. A copy can drift, and it already did once (`===` in src/atlas.mjs,
// `startsWith` here). These drive the SCRIPT over the same cases AC16 pins on
// src/atlas.mjs, so a divergence in either copy fails a test rather than
// silently changing what gets counted.

test('the script does not import anything outside node: builtins', () => {
  // Its whole reason for existing is that a MITRE engineer can download this
  // one file and run it. An import of ../src/* passes the repo test suite and
  // breaks that, which is exactly how this regressed.
  const src = readFileSync(SCRIPT, 'utf8');
  const imports = [...src.matchAll(/^\s*import\s+.*?from\s+['"]([^'"]+)['"]/gm)].map((m) => m[1]);
  assert.ok(imports.length > 0, 'expected at least one import to check');
  for (const spec of imports) {
    assert.ok(
      spec.startsWith('node:'),
      `standalone execution is a requirement: ${spec} is not a node: builtin`
    );
  }
});

test('the script counts a namespaced ATLAS source rather than dropping it', () => {
  const stix = JSON.parse(STIX);
  stix.objects.find((o) => o.id === 'ap-1').external_references[0].source_name = 'mitre-atlas-c';
  const r = run({ 'a.yaml': paddedYaml(), 'b.json': JSON.stringify(stix) });
  assert.equal(
    r.findings.find((f) => f.finding.includes('different mitigation edges')).stixDistinctEdges, 1,
    'a strict === matcher drops this edge and sees zero'
  );
});

test('the script is case-insensitive on source_name', () => {
  const stix = JSON.parse(STIX);
  stix.objects.find((o) => o.id === 'ap-1').external_references[0].source_name = 'MITRE-ATLAS';
  stix.objects.find((o) => o.id === 'coa-1').external_references[0].source_name = 'Mitre-Atlas';
  const r = run({ 'a.yaml': paddedYaml(), 'b.json': JSON.stringify(stix) });
  assert.equal(
    r.findings.find((f) => f.finding.includes('different mitigation edges')).stixDistinctEdges, 1,
    'casing must not decide whether an edge is counted'
  );
});

test('the script ignores a mitre-atlas reference whose external_id is not an AML id', () => {
  // The real ATLAS Matrix object carries exactly this shape.
  const stix = JSON.parse(STIX);
  stix.objects.push({
    type: 'x-mitre-matrix', id: 'matrix-1', name: 'ATLAS Matrix',
    external_references: [{ source_name: 'mitre-atlas', external_id: 'mitre-atlas' }]
  });
  const r = run({ 'a.yaml': paddedYaml(), 'b.json': JSON.stringify(stix) });
  assert.equal(
    r.findings.find((f) => f.finding.includes('different mitigation edges')).stixDistinctEdges, 1,
    'the matrix object must not be admitted as a technique or mitigation'
  );
});
