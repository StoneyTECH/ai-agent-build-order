// Write the ATLAS edges onto the nine gates, then validate them.
//
// Run: node scripts/map-gates.mjs [--write]
//
// Without --write it validates and prints; with --write it updates
// crosswalk.v1.json. Nothing here decides coverage — validateGateEdges does,
// and it refuses anything unlabelled, unjustified, or already covered by a
// published ATLAS mitigation.

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { buildAtlasBlock, validateGateEdges, coverageReport, validateAtlasIds } from '../src/atlas.mjs';

const RELEASE = { version: '5.6.0', release: 'v2026.06' };
const stixPath = process.argv.includes('--stix')
  ? process.argv[process.argv.indexOf('--stix') + 1]
  : new URL('../../stix.json', import.meta.url);

const block = buildAtlasBlock(JSON.parse(readFileSync(stixPath, 'utf8')), RELEASE);

// ---------------------------------------------------------------------------
// The mapping.
//
// mitigation-backed: this gate implements a control ATLAS publishes. Technique
// coverage is derived from ATLAS and deliberately not restated.
//
// asserted: ATLAS names the technique and publishes no control for it. The
// rationale is ours and has to stand on its own.
//
// Gates 8 and 9 carry no ATLAS edges. Regression corpora and recovery paths are
// engineering disciplines ATLAS has no vocabulary for, and inventing edges to
// avoid an empty list would be the exact laundering this design exists to stop.
// ---------------------------------------------------------------------------

const MAPPING = {
  'gate:1': [
    { mitigation: 'AML.M0023', relation: 'implements', class: 'mitigation-backed' },
    { mitigation: 'AML.M0016', relation: 'implements', class: 'mitigation-backed' },
    { mitigation: 'AML.M0014', relation: 'implements', class: 'mitigation-backed' },
    { technique: 'AML.T0104', relation: 'raises-cost', class: 'asserted',
      rationale: 'Admission control over tool packages means a published poisoned tool must clear a signed provenance check and an SBOM entry before it becomes callable. It does not stop publication; it stops adoption without a recorded decision.' },
    { technique: 'AML.T0110', relation: 'raises-cost', class: 'asserted',
      rationale: 'Dependency scanning and a written approval policy mean a tool that changes behaviour after adoption surfaces as a diff against the recorded SBOM rather than as silent drift.' },
    { technique: 'AML.T0109', relation: 'raises-cost', class: 'asserted',
      rationale: 'Pinning to immutable versions or digests rather than mutable tags removes the mechanism a rug pull depends on: repointing a name that was already reviewed under different content.' },
    { technique: 'AML.T0011.002', relation: 'raises-cost', class: 'asserted',
      rationale: 'A poisoned tool entering through the dependency tree is caught by the same admission gate as any other component, because the gate keys on provenance rather than on whether the artifact is an agent tool.' }
  ],
  'gate:2': [
    { mitigation: 'AML.M0027', relation: 'implements', class: 'mitigation-backed' },
    { mitigation: 'AML.M0026', relation: 'implements', class: 'mitigation-backed' },
    { mitigation: 'AML.M0019', relation: 'implements', class: 'mitigation-backed' }
  ],
  'gate:3': [
    { mitigation: 'AML.M0028', relation: 'implements', class: 'mitigation-backed' },
    { mitigation: 'AML.M0032', relation: 'implements', class: 'mitigation-backed' },
    { mitigation: 'AML.M0005', relation: 'implements', class: 'mitigation-backed' },
    { technique: 'AML.T0034.002', relation: 'raises-cost', class: 'asserted',
      rationale: 'A deny-by-default scope with an explicit ceiling bounds what an agent can consume before a human is asked, which converts unbounded resource consumption into a refusal at a stated limit.' }
  ],
  'gate:4': [
    { mitigation: 'AML.M0025', relation: 'implements', class: 'mitigation-backed' },
    { mitigation: 'AML.M0030', relation: 'implements', class: 'mitigation-backed' }
  ],
  'gate:5': [
    { mitigation: 'AML.M0033', relation: 'implements', class: 'mitigation-backed' },
    { technique: 'AML.T0084.001', relation: 'raises-cost', class: 'asserted',
      rationale: 'Typed tool contracts published from source mean a tool definition discovered by an adversary reveals only the schema already intended to be public, and any capability outside that schema is not reachable through the contract.' },
    { technique: 'AML.T0099', relation: 'raises-cost', class: 'asserted',
      rationale: 'A typed contract validates tool output against a declared schema before it re-enters the agent, so poisoned data must survive structural validation rather than arriving as free text the model will trust.' },
    { technique: 'AML.T0010.005', relation: 'raises-cost', class: 'asserted',
      rationale: 'Tools reachable only through a declared, typed contract cannot be invoked as an ambient capability, which removes the implicit-authority path this technique relies on.' },
    { technique: 'AML.T0084.003', relation: 'raises-cost', class: 'asserted',
      rationale: 'When each tool call is typed and logged individually, a chain of calls is enumerable after the fact rather than opaque, so an unexpected call sequence is visible in the receipt.' }
  ],
  'gate:6': [
    { mitigation: 'AML.M0024', relation: 'implements', class: 'mitigation-backed' },
    { technique: 'AML.T0103', relation: 'raises-cost', class: 'asserted',
      rationale: 'A receipt schema that records which agent ran, under whose authority, and against what definition of done makes an unauthorised agent deployment an absence in the ledger rather than an indistinguishable run.' }
  ],
  'gate:7': [
    { mitigation: 'AML.M0029', relation: 'implements', class: 'mitigation-backed' },
    { mitigation: 'AML.M0020', relation: 'implements', class: 'mitigation-backed' },
    { technique: 'AML.T0002.002', relation: 'raises-cost', class: 'asserted',
      rationale: 'Never-states expressed as code rather than as instructions cannot be edited by changing agent configuration, so a modified configuration still meets a hard stop the configuration does not control.' }
  ],
  'gate:8': [],
  'gate:9': []
};

// ---------------------------------------------------------------------------

const crosswalkPath = fileURLToPath(new URL('../crosswalk.v1.json', import.meta.url));
const crosswalk = JSON.parse(readFileSync(crosswalkPath, 'utf8'));

const gates = crosswalk.gates.map((g) => ({ ...g, atlas: MAPPING[g.id] ?? [] }));

// Every AML id we cite must exist in the pinned release.
const cited = gates.flatMap((g) => g.atlas.map((e) => e.mitigation || e.technique));
const ids = validateAtlasIds(block, cited);
const edgeCheck = validateGateEdges(gates, block);

for (const e of [...ids.errors, ...edgeCheck.errors]) console.error(`  REJECTED  ${e}`);
if (!ids.ok || !edgeCheck.ok) {
  console.error(`\n  ${ids.errors.length + edgeCheck.errors.length} problem(s). Nothing written.`);
  process.exit(1);
}

const rep = coverageReport(gates, block);
console.log(`  ATLAS ${rep.version} (${rep.release})`);
console.log(`  mitigation-backed edges: ${rep.mitigationBacked}`);
console.log(`  asserted edges:          ${rep.asserted}`);
console.log(`  techniques addressed:    ${rep.techniquesAddressed} of ${rep.techniquesTotal}`);
console.log(`  open:                    ${rep.open.length}`);
console.log(`  gates with no ATLAS edge: ${gates.filter((g) => !g.atlas.length).map((g) => g.id).join(', ') || 'none'}`);

if (process.argv.includes('--write')) {
  crosswalk.standards.push({
    id: 'std:mitre-atlas',
    name: 'MITRE ATLAS',
    version: RELEASE.version,
    release: RELEASE.release,
    url: 'https://atlas.mitre.org/',
    canonical: 'https://github.com/mitre-atlas/atlas-data'
  });
  crosswalk.atlas = block;
  crosswalk.gates = gates;
  writeFileSync(crosswalkPath, `${JSON.stringify(crosswalk, null, 2)}\n`);
  console.log('\n  crosswalk.v1.json updated.');
}
