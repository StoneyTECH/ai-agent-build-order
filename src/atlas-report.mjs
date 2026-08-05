// Rendering for the ATLAS crosswalk, and the one place that loads the pinned
// block off disk.
//
// The rendering rules exist to stop a reader drawing a conclusion the data
// does not support: the two edge classes never appear as one number, open
// techniques are counted out loud, and every output names the release it was
// computed against.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { coverageReport, driftReport } from './atlas.mjs';

const CROSSWALK = fileURLToPath(new URL('../crosswalk.v1.json', import.meta.url));

export function loadCrosswalk(path = CROSSWALK) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

/** Coverage for the crosswalk as shipped. */
export function atlasCoverage(crosswalk = loadCrosswalk()) {
  if (!crosswalk.atlas) return null;
  return coverageReport(crosswalk.gates, crosswalk.atlas);
}

export function renderCoverageMarkdown(crosswalk = loadCrosswalk()) {
  const rep = atlasCoverage(crosswalk);
  if (!rep) return 'No ATLAS block in this crosswalk.';

  const gates = crosswalk.gates.filter((g) => (g.atlas || []).length);
  const empty = crosswalk.gates.filter((g) => !(g.atlas || []).length);

  const out = [];
  out.push(`# ATLAS coverage — ${rep.version} (${rep.release})`);
  out.push('');
  // Deliberately two rows and no total. One blended number would let an edge
  // we asserted count the same as one MITRE published.
  out.push('| edge class | count | whose authority |');
  out.push('|---|---|---|');
  out.push(`| mitigation-backed | ${rep.mitigationBacked} | MITRE |`);
  out.push(`| asserted | ${rep.asserted} | ours |`);
  out.push('');
  out.push(
    `${rep.techniquesAddressed} of ${rep.techniquesTotal} techniques addressed. ` +
      `**${rep.open.length} open.**`
  );
  out.push('');
  out.push(
    'Open means no gate has anything to say about it. Most of ATLAS concerns ' +
      'training-time and model-theft attacks that build-time gates do not touch, ' +
      'so a large open count is the expected result rather than a gap.'
  );

  if (empty.length) {
    out.push('');
    out.push(
      `Gates with no ATLAS edge: ${empty.map((g) => `\`${g.key}\``).join(', ')}. ` +
        'Left empty on purpose — inventing an edge so no gate looks bare would ' +
        'undo the point of labelling authority at all.'
    );
  }

  out.push('');
  out.push('## Edges by gate');
  out.push('');
  for (const g of gates) {
    out.push(`### ${g.id} — ${g.title}`);
    out.push('');
    for (const e of g.atlas) {
      if (e.class === 'mitigation-backed') {
        const m = crosswalk.atlas.mitigations.find((x) => x.id === e.mitigation);
        out.push(
          `- **${e.mitigation}** ${m ? m.name : ''} — *mitigation-backed*, ` +
            `covers ${m ? m.techniques.length : 0} technique(s) per ATLAS`
        );
      } else {
        const t = crosswalk.atlas.techniques.find((x) => x.id === e.technique);
        out.push(`- **${e.technique}** ${t ? t.name : ''} — *asserted*, no ATLAS mitigation exists`);
        out.push(`  - ${e.rationale}`);
      }
    }
    out.push('');
  }
  return out.join('\n');
}

/** Drift against a newer ATLAS block. */
export function renderDriftMarkdown(nextBlock, crosswalk = loadCrosswalk()) {
  const d = driftReport(crosswalk.atlas, nextBlock, crosswalk.gates);
  const out = [`# ATLAS drift — ${d.from} → ${d.to}`, ''];

  if (!d.added.length && !d.removed.length && !d.renamed.length && !d.upgradable.length) {
    out.push('No drift. The pinned release still matches.');
    return out.join('\n');
  }

  if (d.upgradable.length) {
    out.push('## Upgrade these edges');
    out.push('');
    out.push(
      'MITRE has published a control for a technique this crosswalk asserts ' +
        'coverage for. Cite theirs instead of ours.'
    );
    out.push('');
    for (const u of d.upgradable) {
      out.push(`- ${u.gate}: **${u.technique}** now has ${u.mitigations.join(', ')}`);
    }
    out.push('');
  }
  if (d.added.length) {
    out.push(`## Added (${d.added.length})`, '', ...d.added.map((i) => `- ${i}`), '');
  }
  if (d.removed.length) {
    out.push(`## Removed (${d.removed.length})`, '', ...d.removed.map((i) => `- ${i}`), '');
  }
  if (d.renamed.length) {
    out.push(`## Renamed (${d.renamed.length})`, '');
    for (const r of d.renamed) out.push(`- ${r.id}: "${r.from}" → "${r.to}"`);
    out.push('');
  }
  return out.join('\n');
}
