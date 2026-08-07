#!/usr/bin/env node
// atlas-gaps.mjs — mechanical findings about the ATLAS distributions themselves.
//
// Everything here is derived from MITRE's own published data and asks nothing
// of anyone's judgment about security controls. Run it against the two
// distributions and it reproduces exactly; that is the point. We make no claim
// in this file about what mitigates what — only about where the data
// disagrees with itself or is structurally incomplete.
//
// SELF-CONTAINED ON PURPOSE. Download this one file and run it — node: builtins
// only, nothing to install, no checkout required. That property is the whole
// reason anyone outside this repository can reproduce the findings, so it is a
// requirement rather than a convenience. If you are tempted to import a helper
// here, don't; see the note above atlasId.
//
//   node atlas-gaps.mjs --yaml ATLAS.yaml --stix stix-atlas.json
//   node atlas-gaps.mjs --yaml ... --stix ... --json
//
// Sources:
//   https://github.com/mitre-atlas/atlas-data           dist/ATLAS.yaml
//   https://github.com/mitre-atlas/atlas-navigator-data dist/stix-atlas.json

import { readFileSync } from 'node:fs';

const arg = (k) => { const i = process.argv.indexOf(k); return i === -1 ? null : process.argv[i + 1]; };
const JSON_OUT = process.argv.includes('--json');
const yamlPath = arg('--yaml');
const stixPath = arg('--stix');

if (!yamlPath || !stixPath) {
  console.error('usage: atlas-gaps.mjs --yaml dist/ATLAS.yaml --stix dist/stix-atlas.json [--json]');
  process.exit(2);
}

// --------------------------------------------------------------- YAML reader
// A deliberately small reader for the shape ATLAS.yaml actually has, so this
// script has no dependencies and MITRE can run it without installing anything.
// It reads only what the findings need: technique ids, names, creation dates,
// and each mitigation's technique list.
// Indentation is discovered, not assumed. YAML lets a sequence item sit at the
// same column as its key (`  mitigations:` then `  - id:`), and hardcoding
// columns produced a reader that silently returned ZERO edges — a report that
// looked clean because its input never loaded. Depth is taken from the first
// entry of each section, and the result is checked against known totals below.
function readAtlasYaml(text) {
  const out = { techniques: new Map(), mitigations: new Map() };
  const indent = (l) => l.match(/^\s*/)[0].length;
  const lines = text.split('\n');

  let section = null;      // 'techniques' | 'mitigations'
  let entryIndent = null;  // column of `- id:` for entries in this section
  let cur = null;
  let inTechList = false;

  for (const raw of lines) {
    const line = raw.replace(/\s+$/, '');
    if (!line.trim()) continue;
    const ind = indent(line);
    const body = line.trim();

    // A top-level section key. Anything else at that depth ends the section.
    const sec = body.match(/^(techniques|mitigations|tactics|case-studies):$/);
    if (sec && ind <= 2) {
      section = sec[1] === 'techniques' || sec[1] === 'mitigations' ? sec[1] : null;
      entryIndent = null; cur = null; inTechList = false;
      continue;
    }
    if (!section) continue;

    const idm = body.match(/^-\s+id:\s*(\S+)/);
    if (idm) {
      const id = idm[1].replace(/['"]/g, '');
      if (entryIndent === null) entryIndent = ind;          // first entry sets the depth
      if (ind === entryIndent) {                            // a new entry
        cur = { id, techniques: [] };
        inTechList = false;
        out[section].set(id, cur);
      } else if (inTechList && cur && ind > entryIndent) {  // a technique reference
        cur.techniques.push(id);
      }
      continue;
    }
    if (!cur) continue;

    // Keys of the current entry sit one level in from the entry marker.
    if (ind > entryIndent) {
      const nm = body.match(/^name:\s*(.+)$/);
      if (nm) { cur.name = nm[1].trim().replace(/^['"]|['"]$/g, ''); inTechList = false; continue; }
      const cd = body.match(/^created_date:\s*['"]?([\d-]+)/);
      if (cd) { cur.created = cd[1]; inTechList = false; continue; }
      if (/^techniques:$/.test(body)) { inTechList = section === 'mitigations'; continue; }
      // any other key at entry-key depth closes the technique list
      if (/^[\w-]+:/.test(body) && ind === entryIndent + 2) inTechList = false;
    }
  }
  return out;
}

// The reader is hand-rolled so this script has no dependencies. That trade is
// only acceptable if the parse is checked: a silent mis-parse here would turn
// every finding below into confident nonsense.
function assertParsed({ techniques, mitigations }) {
  const edges = [...mitigations.values()].reduce((n, m) => n + m.techniques.length, 0);
  const named = [...techniques.values()].filter((t) => t.name).length;
  const dated = [...techniques.values()].filter((t) => t.created).length;
  const problems = [];
  if (techniques.size < 100) problems.push(`only ${techniques.size} techniques parsed`);
  if (mitigations.size < 20) problems.push(`only ${mitigations.size} mitigations parsed`);
  if (edges < 100) problems.push(`only ${edges} mitigation->technique edges parsed`);
  if (named < techniques.size) problems.push(`${techniques.size - named} techniques parsed with no name`);
  if (dated < techniques.size * 0.9) problems.push(`${techniques.size - dated} techniques parsed with no created_date`);
  if (problems.length) {
    console.error('atlas-gaps: the YAML parse looks wrong, refusing to report findings over it:');
    for (const p of problems) console.error(`  - ${p}`);
    process.exit(2);
  }
  return { techniques: techniques.size, mitigations: mitigations.size, edges };
}

// --------------------------------------------------------------- STIX reader
// A deliberate duplicate of atlasId in src/atlas.mjs, kept here so this file
// stays runnable on its own. The two copies previously drifted — `===` there,
// `startsWith` here — which is a real hazard, because the caller in src skips
// whatever this returns null for and raises nothing. Importing was the obvious
// fix and it was the wrong one: it broke standalone execution, which is the
// property that lets anyone else reproduce the findings.
//
// So: copy the code, test the behaviour. test/atlas-gaps.test.mjs drives this
// script over namespaced and mixed-case sources through the same expectations
// AC16 pins on src/atlas.mjs. If either copy drifts, one of those fails.
//
// Match by case-folded prefix so neither casing nor a namespaced source decides
// whether an object joins; return an id only when it is shaped like an ATLAS id,
// because the ATLAS Matrix object carries a mitre-atlas reference whose
// external_id is the literal string "mitre-atlas".
const atlasId = (o) => {
  const ref = (o?.external_references || [])
    .find((r) => (r?.source_name || '').toLowerCase().startsWith('mitre-atlas'));
  const id = ref ? ref.external_id : null;
  return id && /^AML\./.test(id) ? id : null;
};

function readStix(bundle) {
  const objects = bundle.objects || [];
  // Resolve refs through non-relationship objects only. Those ids ARE unique;
  // relationship ids are not, which is finding 1.
  const byRef = new Map(objects.filter((o) => o.type !== 'relationship').map((o) => [o.id, o]));
  const rels = objects.filter((o) => o.type === 'relationship');
  return { objects, byRef, rels };
}

// ------------------------------------------------------------------ findings
const yaml = readAtlasYaml(readFileSync(yamlPath, 'utf8'));
const parsed = assertParsed(yaml);
const stix = readStix(JSON.parse(readFileSync(stixPath, 'utf8')));

// FINDING 1 — relationship id collisions.
// STIX 2.1 requires `id` to be unique; it is the primary key. Where several
// relationships share one id, a consumer that loads the bundle into a map
// keyed by id silently keeps one and drops the rest.
const byId = new Map();
for (const r of stix.rels) (byId.get(r.id) ?? byId.set(r.id, []).get(r.id)).push(r);
const collisions = [...byId.entries()].filter(([, v]) => v.length > 1);
const differingField = (group) => {
  const keys = new Set(group.flatMap((o) => Object.keys(o)));
  return [...keys].filter((k) => new Set(group.map((o) => JSON.stringify(o[k]))).size > 1);
};
const finding1 = {
  finding: 'relationship ids are reused across distinct relationships',
  spec: 'STIX 2.1 requires id to be unique within a bundle',
  relationshipObjects: stix.rels.length,
  distinctIds: byId.size,
  unreachableByIdKeyedRead: stix.rels.length - byId.size,
  collidingIds: collisions.length,
  fieldsThatDifferWithinAGroup: [...new Set(collisions.flatMap(([, g]) => differingField(g)))],
  byRelationshipType: Object.fromEntries(
    [...new Set(stix.rels.map((r) => r.relationship_type))].map((t) => {
      const rs = stix.rels.filter((r) => r.relationship_type === t);
      return [t, { objects: rs.length, distinctIds: new Set(rs.map((r) => r.id)).size }];
    })
  ),
  example: collisions.length ? { id: collisions[0][0], targets: collisions[0][1].map((r) => r.target_ref) } : null,
};

// FINDING 2 — the two distributions disagree on which edges exist.
const yamlEdges = new Set();
for (const m of yaml.mitigations.values()) for (const t of m.techniques) yamlEdges.add(`${m.id}|${t}`);
const stixPairs = new Map();
for (const r of stix.rels) {
  if (r.relationship_type !== 'mitigates') continue;
  const s = atlasId(stix.byRef.get(r.source_ref) || {});
  const t = atlasId(stix.byRef.get(r.target_ref) || {});
  if (s && t) stixPairs.set(`${s}|${t}`, (stixPairs.get(`${s}|${t}`) ?? 0) + 1);
}
const finding2 = {
  finding: 'the YAML and STIX distributions of the same release publish different mitigation edges',
  yamlDistinctEdges: yamlEdges.size,
  stixDistinctEdges: stixPairs.size,
  stixRawMitigatesObjects: [...stixPairs.values()].reduce((a, b) => a + b, 0),
  note: 'raw object counts can match while distinct edges differ, which is why a totals check does not detect this',
  missingFromStix: [...yamlEdges].filter((k) => !stixPairs.has(k)).map((k) => k.replace('|', ' -> ')),
  duplicatedInStix: [...stixPairs].filter(([, c]) => c > 1).map(([k, c]) => `${k.replace('|', ' -> ')} (x${c})`),
  extraInStix: [...stixPairs.keys()].filter((k) => !yamlEdges.has(k)).map((k) => k.replace('|', ' -> ')),
};

// FINDING 3 — sub-techniques with no mitigation whose parent has one.
// Reported as CANDIDATES, not defects: a sub-technique can be different enough
// that the parent's control genuinely does not carry down. The judgment is
// MITRE's. What the data shows is where that judgment has not been recorded,
// and that it clusters in one year.
const covers = new Map();
for (const m of yaml.mitigations.values()) for (const t of m.techniques) {
  if (!covers.has(t)) covers.set(t, []);
  covers.get(t).push(m.id);
}
const candidates = [];
for (const [tid, t] of yaml.techniques) {
  if ((tid.match(/\./g) || []).length !== 2) continue;
  const parent = tid.slice(0, tid.lastIndexOf('.'));
  const p = yaml.techniques.get(parent);
  if (!p) continue;
  if (covers.has(parent) && !covers.has(tid)) {
    candidates.push({
      subTechnique: tid, name: t.name, created: (t.created || '').slice(0, 4),
      parent, parentName: p.name, parentMitigations: covers.get(parent).sort(),
    });
  }
}
const byYear = {};
for (const c of candidates) byYear[c.created || 'unknown'] = (byYear[c.created || 'unknown'] ?? 0) + 1;
const finding3 = {
  finding: 'sub-techniques carry no mitigation while their parent technique does',
  interpretation: 'CANDIDATES for review, not asserted defects — whether a parent control carries down is MITRE\'s call',
  count: candidates.length,
  bySubTechniqueCreationYear: byYear,
  candidates: candidates.sort((a, b) => (b.created || '').localeCompare(a.created || '')),
};

const report = { atlasYaml: yamlPath, atlasStix: stixPath, parsed, findings: [finding1, finding2, finding3] };

if (JSON_OUT) { console.log(JSON.stringify(report, null, 2)); process.exit(0); }

console.log(`\n  parsed: ${parsed.techniques} techniques, ${parsed.mitigations} mitigations, ${parsed.edges} edges`);
const f1 = finding1, f2 = finding2, f3 = finding3;
console.log(`\n1. ${f1.finding}`);
console.log(`   ${f1.spec}`);
console.log(`   ${f1.relationshipObjects} relationship objects carry ${f1.distinctIds} distinct ids`);
console.log(`   ${f1.unreachableByIdKeyedRead} unreachable by an id-keyed read, across ${f1.collidingIds} colliding ids`);
console.log(`   only differing field(s) within a colliding group: ${f1.fieldsThatDifferWithinAGroup.join(', ') || 'none'}`);
for (const [t, v] of Object.entries(f1.byRelationshipType)) {
  console.log(`     ${t}: ${v.objects} objects, ${v.distinctIds} distinct ids`);
}

console.log(`\n2. ${f2.finding}`);
console.log(`   YAML distinct edges: ${f2.yamlDistinctEdges}   STIX distinct edges: ${f2.stixDistinctEdges}   STIX raw objects: ${f2.stixRawMitigatesObjects}`);
console.log(`   ${f2.note}`);
for (const e of f2.missingFromStix) console.log(`     missing from STIX:   ${e}`);
for (const e of f2.duplicatedInStix) console.log(`     duplicated in STIX:  ${e}`);
for (const e of f2.extraInStix) console.log(`     extra in STIX:       ${e}`);

console.log(`\n3. ${f3.finding}`);
console.log(`   ${f3.interpretation}`);
console.log(`   ${f3.count} candidates; by sub-technique creation year: ${JSON.stringify(f3.bySubTechniqueCreationYear)}`);
for (const c of f3.candidates) {
  console.log(`     ${c.created}  ${c.subTechnique.padEnd(16)} ${c.name.slice(0, 32).padEnd(34)} parent ${c.parent} has ${c.parentMitigations.join(',')}`);
}
console.log('');
