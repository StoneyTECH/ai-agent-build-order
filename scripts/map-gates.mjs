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

// --verify validates what is committed, using the ATLAS block already in the
// crosswalk. No network, no vendored bundle — so CI can enforce the edge rules
// on every push without depending on MITRE being reachable.
const VERIFY_ONLY = process.argv.includes('--verify');

const committed = JSON.parse(
  readFileSync(fileURLToPath(new URL('../crosswalk.v1.json', import.meta.url)), 'utf8')
);

const block = VERIFY_ONLY
  ? committed.atlas
  : buildAtlasBlock(JSON.parse(readFileSync(stixPath, 'utf8')), RELEASE);

if (VERIFY_ONLY && !block) {
  console.error('  no ATLAS block in crosswalk.v1.json');
  process.exit(1);
}

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
      rationale: 'For a tool delivered AS A PACKAGE, dependency scanning and a written approval policy mean behaviour that changes after adoption surfaces as a diff against the recorded SBOM rather than as silent drift. This does not reach a hosted tool whose behaviour changes server-side: the endpoint, the version and the SBOM entry are all unchanged, and ATLAS names MCP connections explicitly. Narrowed deliberately rather than claimed whole.' },
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
    // AML.T0084.001 (Tool Definitions) was asserted here and is WITHDRAWN.
    // It is a Discovery technique — an adversary finding out what tools exist.
    // The rationale claimed a contract published from source "reveals only the
    // schema already intended to be public", which is a restatement of "keep
    // secrets out of tool metadata", a different control on a different gate.
    // It also points the wrong way: a clean typed contract is BETTER
    // reconnaissance material than an undocumented one. That trade is worth
    // making for defender clarity, but it is a design choice of ours, not a
    // mitigation we can offer for this technique.
    { technique: 'AML.T0099', relation: 'raises-cost', class: 'asserted',
      rationale: 'A typed contract stops STRUCTURAL smuggling in tool output: unexpected fields, type confusion, and payloads shaped to confuse a parser must survive schema validation before re-entering the agent. It does close to nothing against injection carried inside a string the schema permits, which is the dominant case — a poisoned response of the right shape is still poisoned. Claimed at the size it actually holds.' },
    { technique: 'AML.T0010.005', relation: 'raises-cost', class: 'asserted',
      rationale: 'Tools reachable only through a declared, typed contract cannot be invoked as an ambient capability, which removes the implicit-authority path this technique relies on. Bounded by the runtime actually enforcing the contract: if any approved tool can emit arbitrary shell, the contract is decorative for everything downstream of it.' },
    { technique: 'AML.T0084.003', relation: 'raises-cost', class: 'asserted',
      rationale: 'The technique describes extracting call chains that connect user input or LLM output to an execution sink such as exec, eval or os.popen. When every tool is reached through a schema-validated contract there is no such sink at the end of the chain: model output arrives as typed arguments to a declared operation, never as free text to an interpreter. An adversary can still extract the chain and finds nothing exploitable at the end of it.' }
  ],
  'gate:6': [
    { mitigation: 'AML.M0024', relation: 'implements', class: 'mitigation-backed' },
    { technique: 'AML.T0103', relation: 'raises-cost', class: 'asserted',
      rationale: 'A receipt recording which agent ran, under whose authority, and against what definition of done makes an unauthorised deployment DETECTABLE — it is not preventive, and the gap it leaves is only a signal if the ledger is reconciled against an independent inventory of what is actually running. Two limits stated rather than buried: whoever can deploy can usually write receipts unless custody is separate, and an agent stood up outside the sanctioned path never touches this system at all.' }
  ],
  'gate:7': [
    { mitigation: 'AML.M0029', relation: 'implements', class: 'mitigation-backed' },
    { mitigation: 'AML.M0020', relation: 'implements', class: 'mitigation-backed' }
    // AML.T0002.002 (AI Agent Configuration) was asserted here and is
    // WITHDRAWN. The technique is Resource Development — acquiring PUBLICLY
    // ACCESSIBLE config files to learn capabilities or harvest credentials.
    // The rationale argued about resisting MODIFICATION of configuration,
    // which is the wrong axis: moving hard stops into code does nothing to
    // stop someone reading a config that should never have been public. The
    // real mitigation is not publishing configs and not putting credentials in
    // them, which belongs to gates 1 and 2. Withdrawn rather than stretched.
  ],
  'gate:8': [],
  'gate:9': []
};

// ---------------------------------------------------------------------------

const crosswalkPath = fileURLToPath(new URL('../crosswalk.v1.json', import.meta.url));
const crosswalk = committed;

const gates = VERIFY_ONLY
  ? crosswalk.gates
  : crosswalk.gates.map((g) => ({ ...g, atlas: MAPPING[g.id] ?? [] }));

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
  // Upsert, not push. The first --write added std:mitre-atlas; every later one
  // would have appended a second copy, so re-running the generator after an
  // ATLAS release would quietly leave the file citing two different versions
  // of the same standard.
  const std = {
    id: 'std:mitre-atlas',
    name: 'MITRE ATLAS',
    version: RELEASE.version,
    release: RELEASE.release,
    url: 'https://atlas.mitre.org/',
    canonical: 'https://github.com/mitre-atlas/atlas-data'
  };
  const at = crosswalk.standards.findIndex((s) => s.id === std.id);
  if (at === -1) crosswalk.standards.push(std);
  else crosswalk.standards[at] = std;
  crosswalk.atlas = block;
  crosswalk.gates = gates;
  writeFileSync(crosswalkPath, `${JSON.stringify(crosswalk, null, 2)}\n`);
  console.log('\n  crosswalk.v1.json updated.');
}
