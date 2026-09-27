// TDD suite for build-order. Basic (happy path) + adversarial (the cases the
// heuristics are most likely to get wrong). Run: node --test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { audit, mergeAttestation } from '../src/audit.mjs';
import { scanRepo, ALLOW_MARKER } from '../src/scanner.mjs';
import { GATES, looksLikeHardcodedSecret } from '../src/gates.mjs';

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

// ---------- adversarial: the VALUE has to look like a secret, not just the label ----------
//
// A label ending in key/token/secret proves nothing on its own — a mature
// codebase is full of them. Flagging the label was this detector's worst
// false-positive source, and the reason auditing a whole monorepo was useless.

// Each line has the shape of a real false positive found auditing real
// repositories. The values are synthetic stand-ins: this repo never carries
// another repo's audit output (see SECURITY.md).
const NOT_CREDENTIALS = [
  'const job = { idempotencyKey: "idempotency:orders-human-approval" };',       // colon-namespaced id
  'const cfg = { secret: "secretmanager.googleapis.com" };',                 // a hostname
  '      - --secret="${_API_TOKEN_SECRET_ID}"',                       // a Cloud Build substitution
  'const apiKey = "${fakeApiKey}";',                                         // a template interpolation
  'const vaultSecret = "/run/secrets/app.json";',                            // a path
  'const secret = "https://secretmanager.googleapis.com/v1/projects/p/s";',  // a locator
  'OBJECT_LIST_TOKEN_SECRET="object-store-list-api-token"',          // a Secret Manager NAME
  'const modelKey = "large-model-47-provider-direct-us";',                  // a model identifier
  'idempotencyKey: "{changeRequestId}:{evidenceObjectSha256}",',             // a template
  "export const NUMBERED_SECRET = 'projects/123456789012/secrets/app-content-authoring-profile';", // a resource path; GCP puts a 12-digit project number in it
  'claimKey: "ledger-authoritative-graph-store",',                             // a long word is not entropy
  "const PKCE_VERIFIER_KEY = 'appPkceCodeVerifier';",                        // camelCase words: the NAME a verifier is stored under
  "const ID_TOKEN_KEY = 'consoleIdToken';",                                  // ditto, passed to localStorage.setItem
  'const CACHE_KEY = "UserPreferences";',                                    // PascalCase words
];

// ...and the ones that must never go quiet. If any of these stops flagging,
// the fix bought its false-positive rate with a false negative.
const CREDENTIALS = [
  'const key = "sk-abcdefghij0123456789ZZ";',                                  // build-order:allow (fixture)
  'const OPENAI_KEY = "sk-live-not-a-real-key-abcdefghijklmnop";',             // build-order:allow (fixture) — leaky-agent's line: `-` is not a namespace separator
  'password = "9f8Xq2Lm4Rt7Vz0Bn5Kd";',                                        // build-order:allow (fixture) — opaque high-entropy run
  'api_token: "aGVsbG8gd29ybGQgdGhpcyBpcyBub3QgcmVhbA=="',                     // build-order:allow (fixture) — base64
  'const credential = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.dozjgNryP4J3jVmNHl0w5N";', // build-order:allow (fixture) — a JWT is dotted but is not a hostname
  'password = "correct-horse-battery-staple";',                                // build-order:allow (fixture) — no segment is secret-sized, but a password label holds the password
  // The bounds of the compound exemption: words and IDs inside a compound are
  // names, but only those. Each line below sits just outside it.
  'const JWT_SECRET = "thisismysecretkey";',                                   // build-order:allow (fixture) — ONE long run gets no benefit of the doubt
  'apiKey: "deploy-9f8xq2lm4rt7vz0bn5kd"',                                     // build-order:allow (fixture) — lowercase, but letters with digits is entropy
  'sessionToken: "user-qzvxkwplmnrtbcgfhjds"',                                 // build-order:allow (fixture) — a lowercase run longer than a word
  'const signingKey = "projects/p/secrets/9f8Xq2Lm4Rt7Vz0Bn5Kd";',             // build-order:allow (fixture) — a resource path cannot launder an opaque run
  // Case changes separate words only when every part IS a word. Random
  // mixed-case letters, with or without digits, stay an opaque run.
  'apiKey: "aBcDeFgHiJkLmNoPqRsT"',                                            // build-order:allow (fixture) — alternating case is not words
  'const token = "QmVyYXplbGlmZXNhdmVy";',                                     // build-order:allow (fixture) — letters-only base64
  'password = "correctHorseBatteryStaple";',                                   // build-order:allow (fixture) — a camelCase passphrase under a password label
];

test('a *_SECRET label may hold a secret NAME; a password label holds the password', () => {
  // Secret managers name their secrets, so `*_KEY`/`*_TOKEN`/`*_SECRET` routinely
  // point at a resource instead of holding one — 46 lines of one real repo were
  // exactly this, and they were the whole reason `--target .` was unusable.
  assert.equal(looksLikeHardcodedSecret('SIGNING_KEY_SECRET = "release-evidence-signing";'), false);
  // Nobody stores the *name* of a password. Same value, different claim.
  assert.equal(looksLikeHardcodedSecret('password = "release-evidence-signing";'), true); // build-order:allow (fixture)
});

test('a labelled value that is a reference or an identifier is NOT a credential', () => {
  for (const line of NOT_CREDENTIALS) {
    assert.equal(looksLikeHardcodedSecret(line), false, `false positive on: ${line}`);
  }
});

test('a labelled value that is actually secret-shaped is STILL a credential', () => {
  for (const line of CREDENTIALS) {
    assert.equal(looksLikeHardcodedSecret(line), true, `false negative on: ${line}`);
  }
});

test('a benign labelled value cannot hide a real key later on the same line', () => {
  const line = '{ secret: "secretmanager.googleapis.com", apiKey: "9f8Xq2Lm4Rt7Vz0Bn5Kd" }'; // build-order:allow (fixture)
  assert.equal(looksLikeHardcodedSecret(line), true, 'the scan must not stop at the first labelled value');
});

test('a mature repo full of *Key/*Secret labels is not a false GAP', () => {
  const root = fixture({
    'src/queue.ts': NOT_CREDENTIALS.join('\n'),
    'cloudbuild.yaml': 'steps:\n  - args: [ "--secret=${_API_TOKEN_SECRET_ID}" ]\n',
  });
  const sc = audit(root);
  rmSync(root, { recursive: true, force: true });
  assert.notEqual(verdictOf(sc, 'operator'), 'gap', 'labels alone must not fail the operator gate');
});

test('false positives ahead of a real key do not crowd it out of the hit limit', () => {
  const root = fixture({
    // The benign lines come first and outnumber the evidence limit. Filtering
    // has to happen while scanning, not after the hits are already capped.
    'src/config.ts': `${NOT_CREDENTIALS.join('\n')}\nconst signingKey = "9f8Xq2Lm4Rt7Vz0Bn5Kd";\n`, // build-order:allow (fixture)
  });
  const sc = audit(root);
  rmSync(root, { recursive: true, force: true });
  assert.equal(verdictOf(sc, 'operator'), 'gap', 'a real key after six false positives is still a gap');
});

test('wildcard tool grant is a scope GAP', () => {
  const root = fixture({ 'mcp.json': `{ "tools": "*" }` }); // build-order:allow (fixture)
  const sc = audit(root);
  rmSync(root, { recursive: true, force: true });
  assert.equal(verdictOf(sc, 'scope'), 'gap');
});

// A check that allow_all is OFF is deny-by-default code: the opposite of a
// wildcard grant. The detector used to match the word wherever it appeared,
// so a real repo's destroy-gate, which refuses any rule with allow_all set,
// read as granting everything.
test('code that refuses allow_all is not a wildcard grant', () => {
  const root = fixture({
    'src/gate.mjs': [
      'if (!isNullish(rule.allow_all)) throw new Error("allow_all is not permitted");',
      'const denied = { allow_all: null, allowAll: false };',
      'const ok = dryRun && isNullish(dryRunRule.allow_all);',
      'if (policy.allowAll === true) reject(policy);',
    ].join('\n'),
  });
  const sc = audit(root);
  rmSync(root, { recursive: true, force: true });
  assert.notEqual(verdictOf(sc, 'scope'), 'gap', 'a check that denies allow_all was read as granting it');
});

test('switching allow_all on is still a scope GAP', () => {
  for (const [file, grant] of [
    ['src/policy.mjs', 'const policy = { allow_all: true };'],      // build-order:allow (fixture)
    ['agent/config.py', 'ALLOW_ALL = True'],                        // build-order:allow (fixture)
    ['config.yaml', 'allow-all: yes'],                              // build-order:allow (fixture)
    ['config.json', '{ "allowAll": "*" }'],                         // build-order:allow (fixture)
    ['src/server.ts', 'permissions.allowAll();'],                   // build-order:allow (fixture)
  ]) {
    const root = fixture({ [file]: grant });
    const sc = audit(root);
    rmSync(root, { recursive: true, force: true });
    assert.equal(verdictOf(sc, 'scope'), 'gap', `a real grant went undetected in ${file}: ${grant}`);
  }
});

test('a repo with zero tests is a GAP on the fixtures gate (provable absence, not unknown)', () => {
  const root = fixture({ 'src/only.js': 'export const x = 1;' });
  const sc = audit(root);
  rmSync(root, { recursive: true, force: true });
  assert.equal(verdictOf(sc, 'fixtures'), 'gap');
});

// A gap on gate 8 claims PROVABLE absence, so every mainstream test layout has
// to count. pytest discovers test_*.py anywhere, Go keeps *_test.go beside the
// code, Jest reads __tests__/, RSpec reads spec/. Missing the first made the
// tool assert "no tests" about a real repo with eight pytest tests in it.
test("each ecosystem's own test naming counts as a fixture", () => {
  for (const [file, body] of [
    ['tools/test_parser.py', 'def test_roundtrip():\n    assert True\n'],
    ['pkg/parse/parse_test.go', 'package parse\n'],
    ['src/__tests__/app.js', 'it("renders", () => {});\n'],
    ['spec/models/user_spec.rb', 'describe User do; end\n'],
  ]) {
    const root = fixture({ [file]: body, 'src/app.js': 'export const x = 1;' });
    const sc = audit(root);
    rmSync(root, { recursive: true, force: true });
    assert.equal(verdictOf(sc, 'fixtures'), 'held', `${file} was not recognized as a test`);
  }
});

test('a name that merely contains "test" is not a fixture', () => {
  const root = fixture({ 'src/attest.py': 'x = 1', 'src/contest_rules.py': 'y = 2', 'src/latest.go': 'package src' });
  const sc = audit(root);
  rmSync(root, { recursive: true, force: true });
  assert.equal(verdictOf(sc, 'fixtures'), 'gap', 'attest.py, contest_rules.py and latest.go are not tests');
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
