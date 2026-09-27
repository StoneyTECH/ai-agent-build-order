// The tarball is the product. `npx github:StoneyTECH/ai-agent-build-order`
// packs this repository and runs whatever that package holds, so the package
// is held to the tool's own rules: ship an allowlist, not "everything nobody
// remembered to ignore" (gate 3, deny by default), and make that a test rather
// than a habit (gate 7).
//
// Before `files` existed, `npm pack` here shipped 29 files: the test suite, the
// leaky-agent fixture with its fake key, and an untracked
// .claude/settings.local.json that git ignores and npm does not. Packed from
// the main checkout, it also swept in 30 files of another session's worktree.
//
// Run: node --test

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { audit } from '../src/audit.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));

// What a consumer receives, and nothing else. README, LICENSE and package.json
// ride along whatever `files` says; everything else has to be named to ship.
const SHIPPED = ['LICENSE', 'README.md', 'bin', 'crosswalk.v1.json', 'mcp', 'package.json', 'src'];

let work, packed, installed;

before(() => {
  work = mkdtempSync(join(tmpdir(), 'bo-pack-'));
  const [p] = JSON.parse(execFileSync('npm', ['pack', '--json', '--ignore-scripts', '--pack-destination', work], { cwd: ROOT, encoding: 'utf8' }));
  packed = p.files.map((f) => f.path).sort();
  // Unpack it where a consumer's resolver would find it, with no repo around it.
  installed = join(work, 'node_modules', 'build-order');
  mkdirSync(installed, { recursive: true });
  execFileSync('tar', ['-xzf', join(work, p.filename), '-C', installed, '--strip-components=1']);
});

after(() => rmSync(work, { recursive: true, force: true }));

const run = (bin, args) => spawnSync(process.execPath, [bin, ...args], { encoding: 'utf8' });
const withoutTimestamp = (json) => { const o = JSON.parse(json); delete o.generated; return o; };

test('the tarball ships an allowlist, not whatever is lying in the directory', () => {
  const top = [...new Set(packed.map((f) => f.split('/')[0]))].sort();
  assert.deepEqual(top, SHIPPED);
});

test('every module the CLI, the library and the MCP server load is in it', () => {
  const runtime = ['bin/build-order.mjs', 'mcp/build-order-mcp.mjs', 'crosswalk.v1.json',
    ...readdirSync(join(ROOT, 'src')).map((f) => `src/${f}`)];
  for (const f of runtime) assert.ok(packed.includes(f), `${f} is not in the tarball`);
});

test('the packed CLI gives the same answers as the tested source', () => {
  // An allowlist that drops a runtime file ships a tool that cannot run. Parity
  // with the source tree, from the tarball alone, is the proof it can.
  const src = join(ROOT, 'bin', 'build-order.mjs');
  const dist = join(installed, 'bin', 'build-order.mjs');
  const leaky = join(ROOT, 'examples', 'leaky-agent');

  const a = run(src, ['audit', leaky, '--json']);
  const b = run(dist, ['audit', leaky, '--json']);
  assert.equal(a.status, 1, 'the source CLI must block the leaky agent');
  assert.equal(b.status, 1, `the packed CLI must block it too: ${b.stderr}`);
  assert.deepEqual(withoutTimestamp(b.stdout), withoutTimestamp(a.stdout));

  const c = run(src, ['atlas', '--json']);
  const d = run(dist, ['atlas', '--json']);
  assert.equal(d.status, 0, `the packed atlas report must load its crosswalk: ${d.stderr}`);
  assert.deepEqual(JSON.parse(d.stdout), JSON.parse(c.stdout));
});

test('a consumer can import the engine and locate the crosswalk and manifest', () => {
  // What the StoneyTech-Compliance gate needs once it depends on the package
  // instead of a vendored copy: the engine, the crosswalk it maps gates
  // through, and the installed version for its provenance line.
  const probe = `
    import { createRequire } from 'node:module';
    const require = createRequire(process.cwd() + '/');
    const { audit } = await import('build-order');
    const crosswalk = require.resolve('build-order/crosswalk.v1.json');
    const { version } = require('build-order/package.json');
    console.log(JSON.stringify({ audit: typeof audit, crosswalk, version }));
  `;
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', probe], { cwd: work, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  const got = JSON.parse(r.stdout);
  assert.equal(got.audit, 'function');
  assert.equal(got.crosswalk, join(realpathSync(installed), 'crosswalk.v1.json'));
  assert.equal(got.version, pkg.version);
});

test('the scorecard names the version that produced it', () => {
  // A receipt that misstates its producer is not a receipt (gate 6). The engine
  // hardcodes its version, so a release bump has to move both or fail here.
  const dir = mkdtempSync(join(tmpdir(), 'bo-ver-'));
  writeFileSync(join(dir, 'README.md'), '# x');
  try {
    assert.equal(audit(dir).version, pkg.version);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the manifest carries what provenance verification checks', () => {
  // npm rejects a provenance-signed publish whose repository.url does not match
  // the repo that built it. Better to learn that here than at release time.
  assert.equal(pkg.repository?.url, 'git+https://github.com/StoneyTECH/ai-agent-build-order.git');
  // And never publish without provenance, including by accident from a laptop.
  assert.equal(pkg.publishConfig?.provenance, true);
});
