// Acceptance criteria for the coverage join.
//
// The property under test is the same one the whole repo defends: an assertion
// of ours must never be readable as MITRE's. Here that reduces to one rule —
// an `asserted` edge cannot produce `held`, however green the gate is.
//
// Run: node --test

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { repoAtlasCoverage, coverageFor } from '../src/atlas-coverage.mjs';

const CROSSWALK = JSON.parse(
  readFileSync(fileURLToPath(new URL('../crosswalk.v1.json', import.meta.url)), 'utf8')
);

function fixture(files) {
  const dir = mkdtempSync(join(tmpdir(), 'build-order-cov-'));
  for (const [rel, body] of Object.entries(files)) {
    const full = join(dir, rel);
    mkdirSync(join(full, '..'), { recursive: true });
    writeFileSync(full, body);
  }
  return dir;
}

// ---------------------------------------------------------------- the ceiling

test('an asserted edge can NEVER reach held, however green the gate', () => {
  assert.equal(coverageFor('asserted', 'held'), 'attested');
  assert.equal(coverageFor('asserted', 'attested'), 'attested');
});

test('a mitigation-backed edge inherits the gate verdict unchanged', () => {
  assert.equal(coverageFor('mitigation-backed', 'held'), 'held');
  assert.equal(coverageFor('mitigation-backed', 'attested'), 'attested');
});

test('gap and unknown pass through for both edge classes', () => {
  for (const cls of ['asserted', 'mitigation-backed']) {
    assert.equal(coverageFor(cls, 'gap'), 'gap');
    assert.equal(coverageFor(cls, 'unknown'), 'unknown');
  }
});

// ------------------------------------------------------------ over real data

test('no asserted technique is ever reported held against a real repo', () => {
  const dir = fixture({
    'server.mjs': `import { z } from 'zod';
server.registerTool('run', { inputSchema: { p: z.object({}) } }, handler);`,
    'auth.mjs': `export function assumeRole(principal) { return workloadIdentity(principal); }`,
    'policy.mjs': `export const allowedTools = ['read'];`,
    'ledger.mjs': `export const writeReceipt = (r) => auditLog.append(r);`,
    'recover.mjs': `const budget = { timeoutMs: 30_000 }; export const rollback = () => revert();`
  });
  try {
    const r = repoAtlasCoverage(dir, CROSSWALK);
    const bad = r.techniques.filter((t) => t.edgeClass === 'asserted' && t.coverage === 'held');
    assert.deepEqual(bad.map((t) => t.technique), [], 'an opinion of ours was rendered as proof');
    // and the ceiling actually engaged rather than being vacuously satisfied
    assert.ok(r.cappedByCeiling > 0, 'no edge was capped — the test proved nothing');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a repo with no controls claims no coverage', () => {
  const dir = fixture({ 'README.md': '# we have an allowlist and typed tools with inputSchema' });
  try {
    const r = repoAtlasCoverage(dir, CROSSWALK);
    assert.equal(r.summary.held, 0);
    assert.equal(r.summary.attested, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a technique reached by two gates takes its best verdict', () => {
  // Coverage is a disjunction: one held control is enough, and a gap in an
  // unrelated gate must not erase a technique another gate genuinely covers.
  const cw = {
    atlas: { release: 'v-test', mitigations: [{ id: 'AML.M9001', techniques: ['AML.T9001'] }] },
    gates: [
      { n: 5, key: 'tools', atlas: [{ class: 'mitigation-backed', mitigation: 'AML.M9001' }] },
      { n: 3, key: 'scope', atlas: [{ class: 'mitigation-backed', mitigation: 'AML.M9001' }] }
    ]
  };
  const dir = fixture({
    // gate 5 held; gate 3 tripped into a gap by a wildcard grant.
    // The marker is the tool's own escape hatch, and it is needed here for the
    // reason it exists: this line is a FIXTURE of a bad control, and without it
    // the wildcard trips gate 3 against this repository itself. A value-shaped
    // anti-pattern cannot be demoted the way a keyword can — the grant really
    // is a quoted star, so `permissions: "*"` in a real config must still fire.
    'server.mjs': `server.registerTool('run', { inputSchema: {} }, h);`,
    'bad.mjs': `export const permissions = '*';`   // build-order:allow
  });
  try {
    const r = repoAtlasCoverage(dir, cw);
    const t = r.techniques.find((x) => x.technique === 'AML.T9001');
    assert.equal(t.coverage, 'held', 'a gap elsewhere erased a genuinely covered technique');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the report names the ATLAS release it was computed against', () => {
  const dir = fixture({ '.keep': '' });
  try {
    const r = repoAtlasCoverage(dir, CROSSWALK);
    assert.equal(r.atlasRelease, CROSSWALK.atlas.release);
    assert.ok(r.atlasRelease, 'a coverage number with no release is unreadable six months on');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
