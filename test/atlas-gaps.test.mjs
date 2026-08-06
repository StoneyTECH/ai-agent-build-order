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
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
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
