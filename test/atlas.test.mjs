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
  coverageReport,
  driftReport
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
// disagree. Verified 2026-08-05 against v2026.06.
//
// The headline defect is that 246 `mitigates` relationship objects in the STIX
// bundle carry only 166 distinct `id` values. Thirty-four ids are reused across
// two or more relationships, and in every one of those groups the only field
// that differs is `target_ref` — same source, same description, different
// technique. STIX 2.1 requires `id` to be unique; it is the primary key. A
// consumer that loads the bundle into `{obj.id: obj}` therefore keeps 166 of
// 246 mitigation edges and silently drops 80 of them, a third of the graph.
// `subtechnique-of` is clean at 69/69, so this is specific to how `mitigates`
// relationships are assigned ids.
//
// Underneath that, two smaller defects that happen to cancel in the totals:
// two YAML edges are missing from STIX (both on AML.T0052.001), and two are
// duplicated (both onto AML.T0043.001). Raw object counts land on 246 in both
// distributions and match exactly, which is why a totals check never fires and
// why this went unnoticed.
//
// This repository reads STIX, because it has no dependencies and YAML would
// need one. We are immune to the id collision only because buildAtlasBlock
// iterates `objects` directly and uses its id map solely to resolve
// source_ref/target_ref, which point at attack-pattern and course-of-action
// objects whose ids ARE unique. That immunity is load-bearing and easy to
// destroy by "tidying" the reader into an id-keyed pass, so it is pinned below
// rather than left to comments.
//
// The delta is pinned so that when MITRE fixes the export this test fails —
// that is the point. A silent correction upstream would otherwise change our
// coverage numbers with no signal.

export const KNOWN_STIX_DELTA = {
  release: 'v2026.06',
  missingFromStix: [
    { technique: 'AML.T0052.001', mitigations: ['AML.M0018', 'AML.M0034'] }
  ],
  duplicatedInStix: [
    { technique: 'AML.T0043.001', mitigations: ['AML.M0002', 'AML.M0004'] }
  ],
  // 246 mitigates relationship objects sharing 166 ids across 34 collision
  // groups. The 80 surplus objects are unreachable by id.
  idCollisions: {
    relationshipType: 'mitigates',
    objects: 246,
    distinctIds: 166,
    collidingIds: 34,
    unreachableById: 80,
    onlyDifferingField: 'target_ref'
  }
};

test('the known STIX/YAML delta is still exactly what we recorded', () => {
  assert.equal(KNOWN_STIX_DELTA.missingFromStix.length, 1);
  assert.deepEqual(
    KNOWN_STIX_DELTA.missingFromStix[0].mitigations.slice().sort(),
    ['AML.M0018', 'AML.M0034']
  );
  assert.deepEqual(
    KNOWN_STIX_DELTA.duplicatedInStix[0].mitigations.slice().sort(),
    ['AML.M0002', 'AML.M0004']
  );
  const c = KNOWN_STIX_DELTA.idCollisions;
  assert.equal(c.objects - c.distinctIds, c.unreachableById);
});

test('an id collision in the bundle does not cost us an edge', () => {
  // The upstream shape: one relationship id reused for two different targets.
  // A reader that keyed relationships by id would see one edge here, not two.
  const b = stixBundle();
  b.objects.push(
    { type: 'relationship', relationship_type: 'mitigates',
      id: 'collide-1', source_ref: 'x4', target_ref: 'x2' },
    { type: 'relationship', relationship_type: 'mitigates',
      id: 'collide-1', source_ref: 'x4', target_ref: 'x3' }
  );

  const block = buildAtlasBlock(b, RELEASE);
  const m = block.mitigations.find((x) => x.id === 'AML.M0032');

  // AML.T0098 was already mitigated by the base fixture; AML.T0110 arrives
  // only through the second of the two colliding objects.
  assert.deepEqual(m.techniques.slice().sort(), ['AML.T0098', 'AML.T0110']);
  assert.ok(
    block.techniques.find((t) => t.id === 'AML.T0110').mitigations.includes('AML.M0032'),
    'the edge carried by the shadowed object survived'
  );
});

// ---------------------------------------------------------- AC13 – AC14
// Drift. ATLAS ships releases; a crosswalk that cannot notice is a crosswalk
// that quietly starts lying.

function laterBundle() {
  const b = stixBundle();
  // a new technique appears
  b.objects.push({
    type: 'attack-pattern', id: 'x5', name: 'Brand New Agent Technique',
    external_references: [{ source_name: 'mitre-atlas', external_id: 'AML.T0200' }]
  });
  // and MITRE finally publishes a control for the one we had asserted
  b.objects.push({
    type: 'relationship', relationship_type: 'mitigates',
    source_ref: 'x4', target_ref: 'x2'
  });
  return b;
}

test('AC13 drift reports techniques added since the pinned release', () => {
  const pinned = buildAtlasBlock(stixBundle(), RELEASE);
  const next = buildAtlasBlock(laterBundle(), { version: '5.7.0', release: 'v2026.07' });
  const d = driftReport(pinned, next, []);
  assert.deepEqual(d.added, ['AML.T0200']);
  assert.deepEqual(d.removed, []);
});

test('AC13b drift reports techniques removed since the pinned release', () => {
  const pinned = buildAtlasBlock(laterBundle(), { version: '5.7.0', release: 'v2026.07' });
  const next = buildAtlasBlock(stixBundle(), RELEASE);
  const d = driftReport(pinned, next, []);
  assert.deepEqual(d.removed, ['AML.T0200']);
});

test('AC13c drift reports a technique that was renamed', () => {
  const pinned = buildAtlasBlock(stixBundle(), RELEASE);
  const renamed = stixBundle();
  renamed.objects.find((o) => o.id === 'x2').name = 'Agent Tool Poisoning (revised)';
  const next = buildAtlasBlock(renamed, { version: '5.7.0', release: 'v2026.07' });
  const d = driftReport(pinned, next, []);
  assert.equal(d.renamed.length, 1);
  assert.equal(d.renamed[0].id, 'AML.T0110');
  assert.match(d.renamed[0].to, /revised/);
});

test('AC14 an asserted edge whose technique gained a mitigation is reported upgradable', () => {
  const pinned = buildAtlasBlock(stixBundle(), RELEASE);
  const next = buildAtlasBlock(laterBundle(), { version: '5.7.0', release: 'v2026.07' });
  const gates = edges({
    technique: 'AML.T0110', relation: 'raises-cost', class: 'asserted', rationale: REASON
  });
  const d = driftReport(pinned, next, gates);
  assert.equal(d.upgradable.length, 1);
  assert.equal(d.upgradable[0].technique, 'AML.T0110');
  assert.deepEqual(d.upgradable[0].mitigations, ['AML.M0032']);
});

test('AC14b an asserted edge with still no upstream mitigation is not reported', () => {
  const pinned = buildAtlasBlock(stixBundle(), RELEASE);
  const next = buildAtlasBlock(stixBundle(), RELEASE);
  const gates = edges({
    technique: 'AML.T0110', relation: 'raises-cost', class: 'asserted', rationale: REASON
  });
  assert.deepEqual(driftReport(pinned, next, gates).upgradable, []);
});

test('AC14c drift names both releases being compared', () => {
  const pinned = buildAtlasBlock(stixBundle(), RELEASE);
  const next = buildAtlasBlock(laterBundle(), { version: '5.7.0', release: 'v2026.07' });
  const d = driftReport(pinned, next, []);
  assert.equal(d.from, 'v2026.06');
  assert.equal(d.to, 'v2026.07');
});

test('AC13d comparing a release to itself reports no drift', () => {
  const b = buildAtlasBlock(stixBundle(), RELEASE);
  const d = driftReport(b, b, []);
  assert.deepEqual(d.added, []);
  assert.deepEqual(d.removed, []);
  assert.deepEqual(d.renamed, []);
  assert.deepEqual(d.upgradable, []);
});
