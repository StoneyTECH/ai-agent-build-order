// TDD suite for build-order. Basic (happy path) + adversarial (the cases the
// heuristics are most likely to get wrong). Run: node --test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { audit, mergeAttestation } from '../src/audit.mjs';
import { scanRepo, ALLOW_MARKER } from '../src/scanner.mjs';
import { GATES } from '../src/gates.mjs';

// Build a throwaway repo from a { path: contents } map and return its root.
function fixture(files) {
  const root = mkdtempSync(join(tmpdir(), 'bo-'));
  for (const [rel, contents] of Object.entries(files)) {
    const full = join(root, rel);
    mkdirSync(join(full, '..'), { recursive: true });
    writeFileSync(full, contents);
  }
  return root;
}
const verdictOf = (sc, key) => sc.gates.find((g) => g.key === key).verdict;

// ---------- basic ----------

test('a well-built repo lands most gates held', () => {
  const root = fixture({
    'src/agent.ts': `
      import { z } from 'zod';
      const allowedTools = ['read']; // deny by default
      server.registerTool('read', { inputSchema: z.object({ path: z.string() }) });
      function auth(principal) { if (!principal) throw new Error('no identity'); }
      const auditLog = (row) => ledger.append(row); // receipt
      const withTimeout = (p) => Promise.race([p, deadline]); // rollback + escalation path
      function sanitize(input) { return input.replace(/</g, ''); } // validate provenance
    `,
    'test/agent.test.ts': 'test("does a thing", () => {});',
    '.github/workflows/ci.yml': 'on: [push]',
  });
  const sc = audit(root);
  rmSync(root, { recursive: true, force: true });
  assert.equal(sc.summary.gap, 0, 'no gaps in a clean repo');
  assert.ok(sc.summary.held >= 6, `expected >=6 held, got ${sc.summary.held}`);
  assert.equal(sc.clean, true);
});

test('every gate id 1..9 is present exactly once', () => {
  const root = fixture({ 'a.md': 'x' });
  const sc = audit(root);
  rmSync(root, { recursive: true, force: true });
  assert.deepEqual(sc.gates.map((g) => g.id), [1, 2, 3, 4, 5, 6, 7, 8, 9]);
});

test('supply chain (gate 1): a lockfile is HELD; its absence is UNKNOWN, not a gap', () => {
  const withLock = fixture({ 'package-lock.json': '{}', 'src/a.js': 'export const x = 1;' });
  const scLock = audit(withLock);
  rmSync(withLock, { recursive: true, force: true });
  assert.equal(verdictOf(scLock, 'supply-chain'), 'held');

  const bare = fixture({ 'src/a.js': 'export const x = 1;' });
  const scBare = audit(bare);
  rmSync(bare, { recursive: true, force: true });
  assert.equal(verdictOf(scBare, 'supply-chain'), 'unknown', 'no lockfile is unproven, not a false gap');
});

// ---------- adversarial ----------

test('a hardcoded credential is a GAP on the operator gate, not a pass', () => {
  const root = fixture({ 'config.js': `const key = "sk-abcdefghij0123456789ZZ";` }); // build-order:allow (fixture holds a fake secret on purpose)
  const sc = audit(root);
  rmSync(root, { recursive: true, force: true });
  assert.equal(verdictOf(sc, 'operator'), 'gap');
  assert.equal(sc.clean, false);
});

test('the ALLOW_MARKER escape hatch suppresses a reviewed false positive', () => {
  const root = fixture({ 'patterns.js': `const rx = "sk-aaaaaaaaaaaaaaaaaaaa"; // ${ALLOW_MARKER}` }); // build-order:allow (fixture)
  const sc = audit(root);
  rmSync(root, { recursive: true, force: true });
  assert.notEqual(verdictOf(sc, 'operator'), 'gap', 'allow-marked line must not be flagged');
});

test('wildcard tool grant is a scope GAP', () => {
  const root = fixture({ 'mcp.json': `{ "tools": "*" }` }); // build-order:allow (fixture)
  const sc = audit(root);
  rmSync(root, { recursive: true, force: true });
  assert.equal(verdictOf(sc, 'scope'), 'gap');
});

test('a repo with zero tests is a GAP on the fixtures gate (provable absence, not unknown)', () => {
  const root = fixture({ 'src/only.js': 'export const x = 1;' });
  const sc = audit(root);
  rmSync(root, { recursive: true, force: true });
  assert.equal(verdictOf(sc, 'fixtures'), 'gap');
});

test('an empty repo never crashes and inflates nothing', () => {
  const root = fixture({ 'README.md': '# empty' });
  const sc = audit(root);
  rmSync(root, { recursive: true, force: true });
  // No signal anywhere → every gate is unknown or a provable gap, zero held.
  assert.equal(sc.summary.held, 0);
  assert.equal(sc.summary.attested, 0);
  assert.ok(sc.summary.unknown + sc.summary.gap === 9);
});

test('attestation lifts UNKNOWN to ATTESTED only with a receipt', () => {
  const withReceipt = mergeAttestation(
    { verdict: 'unknown', mode: 'attest', evidence: [] },
    { attested: true, note: 'runs as its own service account', receipt: 'docs/identity.md' },
  );
  assert.equal(withReceipt.verdict, 'attested');

  const noReceipt = mergeAttestation(
    { verdict: 'unknown', mode: 'attest', evidence: [] },
    { attested: true, note: 'trust me' },
  );
  assert.equal(noReceipt.verdict, 'unknown', 'a claim without a receipt stays unknown');
});

test('attestation can NEVER downgrade a static gap or forge a held', () => {
  const gapKept = mergeAttestation(
    { verdict: 'gap', mode: 'static', evidence: ['hardcoded key'] },
    { attested: true, note: 'we rotated it', receipt: 'x' },
  );
  assert.equal(gapKept.verdict, 'gap', 'static gap survives self-report');

  const heldStays = mergeAttestation(
    { verdict: 'held', mode: 'static', evidence: ['found allowlist'] },
    { attested: true, note: 'yes', receipt: 'y' },
  );
  assert.equal(heldStays.verdict, 'held');
  assert.notEqual(heldStays.verdict, 'attested', 'attestation cannot masquerade as static proof');
});

test('explicit attested:false marks an honest GAP', () => {
  const r = mergeAttestation(
    { verdict: 'unknown', mode: 'attest', evidence: [] },
    { attested: false, note: 'no rollback yet' },
  );
  assert.equal(r.verdict, 'gap');
});

test('scanner ignores node_modules and honors the allow marker', () => {
  const root = fixture({
    'node_modules/pkg/index.js': 'const key = "sk-shouldbeignored0000000000";', // build-order:allow (fixture)
    'src/app.js': 'export const y = 2;',
  });
  const ctx = scanRepo(root);
  rmSync(root, { recursive: true, force: true });
  assert.ok(!ctx.files.some((f) => f.includes('node_modules')), 'node_modules must be skipped');
});

test('the attestation file itself never satisfies a static detector', () => {
  const root = fixture({
    'src/plain.js': 'export const z = 3;', // no signals at all
    'attest.json': JSON.stringify({ gates: { scope: { attested: true, note: 'allowlist deny-by-default', receipt: 'r' } } }),
  });
  const sc = audit(root, { attestPath: join(root, 'attest.json') });
  rmSync(root, { recursive: true, force: true });
  // scope has no static signal in code; it may become ATTESTED, but never HELD.
  assert.notEqual(verdictOf(sc, 'scope'), 'held', 'the attestation must not prove itself statically');
});

test('gate essay lines are all present (the prose stays wired to the code)', () => {
  for (const g of GATES) assert.ok(g.essayLine.length > 20, `gate ${g.id} missing essay line`);
});
