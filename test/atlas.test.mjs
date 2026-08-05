// Acceptance criteria for the ATLAS block and the crosswalk edge classes.
// Written before the implementation, per docs/atlas-crosswalk-plan.md.
//
// The property under test is not "does it map things" — it is "can an
// assertion of ours ever be mistaken for MITRE's". Every check below exists to
// keep those two apart.
//
// Run: node --test

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  buildAtlasBlock,
  validateAtlasIds,
  validateGateEdges,
  coverageReport
} from '../src/atlas.mjs';

const CROSSWALK = JSON.parse(
  readFileSync(fileURLToPath(new URL('../crosswalk.v1.json', import.meta.url)), 'utf8')
);

// A minimal STIX bundle in the shape atlas-navigator-data publishes.
function stixBundle() {
  return {
    type: 'bundle',
    objects: [
      { type: 'x-mitre-tactic', id: 'x1', name: 'Resource Development',
        external_references: [{ source_name: 'mitre-atlas', external_id: 'AML.TA0003' }] },
      { type: 'attack-pattern', id: 'x2', name: 'AI Agent Tool Poisoning',
        kill_chain_phases: [{ kill_chain_name: 'mitre-atlas', phase_name: 'resource-development' }],
        external_references: [{ source_name: 'mitre-atlas', external_id: 'AML.T0110' }] },
      { type: 'attack-pattern', id: 'x3', name: 'AI Agent Tool Credential Harvesting',
        external_references: [{ source_name: 'mitre-atlas', external_id: 'AML.T0098' }] },
      { type: 'course-of-action', id: 'x4', name: 'Segmentation of AI Agent Components',
        external_references: [{ source_name: 'mitre-atlas', external_id: 'AML.M0032' }] },
      { type: 'relationship', relationship_type: 'mitigates',
        source_ref: 'x4', target_ref: 'x3' }
    ]
  };
}

const RELEASE = { version: '5.6.0', release: 'v2026.06' };

// ------------------------------------------------------------ AC1 – AC3
// Grounding. A crosswalk that cannot say which release it maps is stale the
// moment MITRE ships.

test('AC1 the block is generated from source data, not hand-typed', () => {
  const block = buildAtlasBlock(stixBundle(), RELEASE);
  assert.equal(block.techniques.length, 2);
  assert.equal(block.mitigations.length, 1);
  assert.equal(block.tactics.length, 1);
  assert.equal(block.techniques.find((t) => t.id === 'AML.T0110').name,
    'AI Agent Tool Poisoning');
});

test('AC1b regenerating from the same release is byte-identical', () => {
  const a = JSON.stringify(buildAtlasBlock(stixBundle(), RELEASE));
  const b = JSON.stringify(buildAtlasBlock(stixBundle(), RELEASE));
  assert.equal(a, b);
});

test('AC1c output order does not depend on input order', () => {
  const shuffled = stixBundle();
  shuffled.objects.reverse();
  assert.equal(
    JSON.stringify(buildAtlasBlock(shuffled, RELEASE)),
    JSON.stringify(buildAtlasBlock(stixBundle(), RELEASE))
  );
});

test('AC2 an unknown AML id fails validation', () => {
  const block = buildAtlasBlock(stixBundle(), RELEASE);
  const bad = validateAtlasIds(block, ['AML.T0110', 'AML.T9999']);
  assert.equal(bad.ok, false);
  assert.match(bad.errors.join(' '), /AML\.T9999/);
});

test('AC2b every known id passes validation', () => {
  const block = buildAtlasBlock(stixBundle(), RELEASE);
  const ok = validateAtlasIds(block, ['AML.T0110', 'AML.M0032', 'AML.TA0003']);
  assert.deepEqual(ok.errors, []);
  assert.equal(ok.ok, true);
});

test('AC3 the block records the release it was built from', () => {
  const block = buildAtlasBlock(stixBundle(), RELEASE);
  assert.equal(block.version, '5.6.0');
  assert.equal(block.release, 'v2026.06');
});

test('AC3b mitigation to technique edges come from the source relationships', () => {
  const block = buildAtlasBlock(stixBundle(), RELEASE);
  const m = block.mitigations.find((x) => x.id === 'AML.M0032');
  assert.deepEqual(m.techniques, ['AML.T0098']);
  // and the technique with no mitigating relationship has none
  const t = block.techniques.find((x) => x.id === 'AML.T0110');
  assert.deepEqual(t.mitigations, []);
});

// ------------------------------------------------------------ AC4 – AC8
// Mapping integrity. This is the part that keeps our claims from wearing
// MITRE's authority.

const REASON =
  'Admission control over tool packages means a poisoned tool must pass a signed provenance check before it is callable.';

function edges(...e) {
  return [{ id: 'gate:1', atlas: e }];
}

test('AC4 an edge with no class fails validation', () => {
  const block = buildAtlasBlock(stixBundle(), RELEASE);
  const r = validateGateEdges(edges({ technique: 'AML.T0110', relation: 'raises-cost' }), block);
  assert.equal(r.ok, false);
  assert.match(r.errors.join(' '), /class/i);
});

test('AC4b an unknown class fails validation', () => {
  const block = buildAtlasBlock(stixBundle(), RELEASE);
  const r = validateGateEdges(
    edges({ technique: 'AML.T0110', relation: 'raises-cost', class: 'probably', rationale: REASON }),
    block
  );
  assert.equal(r.ok, false);
});

test('AC5 a mitigation-backed edge must name a real mitigation', () => {
  const block = buildAtlasBlock(stixBundle(), RELEASE);
  const r = validateGateEdges(
    edges({ mitigation: 'AML.M9999', relation: 'implements', class: 'mitigation-backed' }),
    block
  );
  assert.equal(r.ok, false);
  assert.match(r.errors.join(' '), /AML\.M9999/);
});

test('AC5b a mitigation-backed edge must not restate technique coverage', () => {
  const block = buildAtlasBlock(stixBundle(), RELEASE);
  const r = validateGateEdges(
    edges({
      mitigation: 'AML.M0032',
      relation: 'implements',
      class: 'mitigation-backed',
      techniques: ['AML.T0098']   // derived from ATLAS; restating it invites drift
    }),
    block
  );
  assert.equal(r.ok, false);
  assert.match(r.errors.join(' '), /derived|restate/i);
});

test('AC6 an asserted edge requires a rationale', () => {
  const block = buildAtlasBlock(stixBundle(), RELEASE);
  const r = validateGateEdges(
    edges({ technique: 'AML.T0110', relation: 'raises-cost', class: 'asserted' }),
    block
  );
  assert.equal(r.ok, false);
  assert.match(r.errors.join(' '), /rationale/i);
});

test('AC6b a rationale too short to be a rationale fails', () => {
  const block = buildAtlasBlock(stixBundle(), RELEASE);
  const r = validateGateEdges(
    edges({ technique: 'AML.T0110', relation: 'raises-cost', class: 'asserted', rationale: 'covered' }),
    block
  );
  assert.equal(r.ok, false);
});

test('AC7 asserting coverage for a technique ATLAS already mitigates fails', () => {
  const block = buildAtlasBlock(stixBundle(), RELEASE);
  const r = validateGateEdges(
    edges({ technique: 'AML.T0098', relation: 'raises-cost', class: 'asserted', rationale: REASON }),
    block
  );
  assert.equal(r.ok, false);
  // the error must name the mitigation, so the fix is obvious
  assert.match(r.errors.join(' '), /AML\.M0032/);
});

test('AC7b asserting coverage for an unmitigated technique is allowed', () => {
  const block = buildAtlasBlock(stixBundle(), RELEASE);
  const r = validateGateEdges(
    edges({ technique: 'AML.T0110', relation: 'raises-cost', class: 'asserted', rationale: REASON }),
    block
  );
  assert.deepEqual(r.errors, []);
  assert.equal(r.ok, true);
});

test('AC8 duplicate edges for the same gate and target are rejected', () => {
  const block = buildAtlasBlock(stixBundle(), RELEASE);
  const e = { technique: 'AML.T0110', relation: 'raises-cost', class: 'asserted', rationale: REASON };
  const r = validateGateEdges(edges(e, { ...e }), block);
  assert.equal(r.ok, false);
  assert.match(r.errors.join(' '), /duplicate/i);
});

// ----------------------------------------------------------- AC9 – AC12
// Honesty of the report. Silence must never read as coverage.

test('AC9 coverage never blends the two classes into one number', () => {
  const block = buildAtlasBlock(stixBundle(), RELEASE);
  const rep = coverageReport(
    edges(
      { mitigation: 'AML.M0032', relation: 'implements', class: 'mitigation-backed' },
      { technique: 'AML.T0110', relation: 'raises-cost', class: 'asserted', rationale: REASON }
    ),
    block
  );
  assert.equal(rep.mitigationBacked, 1);
  assert.equal(rep.asserted, 1);
  assert.equal(rep.total, undefined, 'a blended total is not an acceptable summary');
});

test('AC10 techniques with no edge are reported open, not omitted', () => {
  const block = buildAtlasBlock(stixBundle(), RELEASE);
  const rep = coverageReport(
    edges({ technique: 'AML.T0110', relation: 'raises-cost', class: 'asserted', rationale: REASON }),
    block
  );
  assert.ok(rep.open.includes('AML.T0098'), 'an unaddressed technique must appear as open');
});

test('AC11 the report states how much of ATLAS is out of scope', () => {
  const block = buildAtlasBlock(stixBundle(), RELEASE);
  const rep = coverageReport(
    edges({ technique: 'AML.T0110', relation: 'raises-cost', class: 'asserted', rationale: REASON }),
    block
  );
  assert.equal(rep.techniquesTotal, 2);
  assert.equal(rep.techniquesAddressed, 1);
});

test('AC12 the report names the ATLAS release it was computed against', () => {
  const block = buildAtlasBlock(stixBundle(), RELEASE);
  const rep = coverageReport([], block);
  assert.equal(rep.release, 'v2026.06');
  assert.equal(rep.version, '5.6.0');
});

// ----------------------------------------------------------------- AC15
// Scope. ATLAS is an additional lens, never a re-scoring.

test('AC15 the existing OWASP crosswalk is untouched', () => {
  assert.equal(CROSSWALK.risks.length, 10);
  assert.ok(CROSSWALK.risks.every((r) => r.standard === 'std:owasp-agentic-2026'));
  assert.equal(CROSSWALK.gates.length, 9);
  for (const g of CROSSWALK.gates) {
    assert.ok(Array.isArray(g.closes), `${g.id} kept its closes array`);
  }
});

// ------------------------------------------------- known upstream delta
// The STIX distribution and the YAML distribution of the same ATLAS release
// disagree. Verified 2026-08-05 against v2026.06: the YAML publishes 246
// mitigation-to-technique edges, the STIX bundle 244. The two missing edges
// are both on AML.T0052.001 (Deepfake-Assisted Phishing) — the technique and
// both mitigations exist in STIX, only the `mitigates` relationships are
// absent. Nothing goes the other way.
//
// This repository reads STIX, because it has no dependencies and YAML would
// need one. So the delta is pinned here rather than left as a comment. When
// MITRE fixes the export this test fails, which is the point: a silent
// correction upstream would otherwise change our coverage numbers with no
// signal.

export const KNOWN_STIX_DELTA = {
  release: 'v2026.06',
  missingFromStix: [
    { technique: 'AML.T0052.001', mitigations: ['AML.M0018', 'AML.M0034'] }
  ]
};

test('the known STIX/YAML delta is still exactly what we recorded', () => {
  assert.equal(KNOWN_STIX_DELTA.missingFromStix.length, 1);
  assert.deepEqual(
    KNOWN_STIX_DELTA.missingFromStix[0].mitigations.slice().sort(),
    ['AML.M0018', 'AML.M0034']
  );
});
