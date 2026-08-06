// The check the scorecard never ran on itself.
//
// A probe that cannot fail proves nothing. Before this file, seven of nine
// gates reported HELD against a directory containing no implementation at all
// — only two markdown files DESCRIBING the gates. The self-audit looked clean
// because it passed `--ignore gates.mjs,examples,CROSSWALK.md,README.md`; a
// hand-maintained exclusion list was doing the work the detectors claimed to
// do. Any repo that ADOPTS this framework ships exactly that documentation, so
// the failing input was the expected one.
//
// Two directions, both required. A detector that answers `unknown` for
// everything passes a negative control and is equally worthless, so every case
// below pins what the verdict must be, not merely what it must not be.
//
// Run: node --test

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { audit } from '../src/audit.mjs';

// Prose that name-drops every keyword all nine detectors look for. If a gate
// can be satisfied by talking about a control, this trips it.
const DESCRIBES_EVERYTHING = `
# Agent design notes — documentation only, nothing implemented here

We authenticate the caller and give the agent a service account principal identity.
Tools use an allowlist with deny-by-default scopes, least-privilege and RBAC.
Retrieved context is validated with zod, checked for provenance and prompt
injection from untrusted sources against a source allowlist.
Every tool has an inputSchema; we registerTool with a typed JSONSchema contract.
Runs emit an audit log and a receipt into a ledger as structured logs.
Never-states are hard stops. Budgets and timeouts expire, with rollback,
escalation, circuit breakers and human-in-the-loop HITL retry.
`;

function fixture(files) {
  const dir = mkdtempSync(join(tmpdir(), 'build-order-nc-'));
  for (const [rel, body] of Object.entries(files)) {
    const full = join(dir, rel);
    mkdirSync(join(full, '..'), { recursive: true });
    writeFileSync(full, body);
  }
  return dir;
}

test('NEGATIVE: prose describing every gate satisfies none of them', () => {
  const dir = fixture({ 'DESIGN.md': DESCRIBES_EVERYTHING });
  try {
    const held = audit(dir).gates.filter((g) => g.verdict === 'held');
    assert.deepEqual(
      held.map((g) => g.key),
      [],
      `documentation alone satisfied ${held.length} gate(s): ` +
        held.map((g) => `${g.key} <- ${g.evidence?.[0]}`).join('; ')
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('NEGATIVE: a self-report can never satisfy a static detector', () => {
  // attestation.json is excluded unconditionally. It used to be excluded only
  // when --attest was passed, so an audit run WITHOUT the flag read our own
  // claims as static evidence.
  const dir = fixture({
    'attestation.json': JSON.stringify({
      gates: {
        tools: { attested: true, receipt: 'mcp/server.mjs inputSchema registerTool z.object' },
        receipts: { attested: true, receipt: 'emits an audit log and a receipt to the ledger' }
      }
    }, null, 2)
  });
  try {
    const held = audit(dir).gates.filter((g) => g.verdict === 'held');
    assert.deepEqual(held.map((g) => g.key), [], 'the attestation file proved itself');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('POSITIVE: a real implementation is still detected', () => {
  // The other half. Without this, "return unknown always" would pass above.
  const dir = fixture({
    'server.mjs': `import { z } from 'zod';
server.registerTool('run', { inputSchema: { path: z.object({ p: z.string() }) } }, handler);`,
    'auth.mjs': `export function assumeRole(principal) { return workloadIdentity(principal); }`,
    'policy.mjs': `export const allowedTools = ['read']; // deny-by-default`,
    'audit.mjs': `export const writeReceipt = (r) => auditLog.append(r);`,
    'recover.mjs': `const budget = { timeoutMs: 30_000 }; export const rollback = () => revert();`
  });
  try {
    const byKey = Object.fromEntries(audit(dir).gates.map((g) => [g.key, g.verdict]));
    for (const key of ['operator', 'scope', 'evidence', 'tools', 'receipts', 'way-home']) {
      assert.equal(byKey[key], 'held', `gate ${key} missed a real implementation`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('POSITIVE: an empty tree inflates nothing', () => {
  const dir = fixture({ '.keep': '' });
  try {
    const a = audit(dir);
    assert.equal(a.summary.held, 0);
    assert.equal(a.summary.attested, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
