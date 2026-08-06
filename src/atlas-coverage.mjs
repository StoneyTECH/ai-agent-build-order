// atlas-coverage.mjs — join a per-repo gate audit to the ATLAS crosswalk, so a
// technique carries a verdict about a real target instead of a rationale about
// the world.
//
// Two things were already true separately and never joined:
//   crosswalk.v1.json  "gate 5 bears on AML.T0099"      — a claim about the world
//   audit()            "gate 5 is held in this repo"    — a fact about a repo
//
// Joining them is mechanical, because the gate keys line up. What is NOT
// mechanical is how much authority the result inherits, and that is the whole
// reason this file exists rather than a dozen lines inside audit().

import { audit } from './audit.mjs';

// The ceiling.
//
// A gate verdict answers "is this control present here" — static evidence can
// settle that. A crosswalk edge answers "does that control bear on this
// technique". For a `mitigation-backed` edge, MITRE answered the second half:
// we cite their published control and inherit their authority, so `held` can
// stay `held`. For an `asserted` edge there is no published control, the second
// half is OUR reasoning, and no amount of static evidence about our code can
// promote our opinion into MITRE's.
//
// So: implementation is provable, efficacy is not. An asserted edge tops out at
// `attested` permanently, however green the gate is. This is the limitations
// review turned into code — it is the difference between "we run this control"
// and "this control works", and only the first is ours to claim.
export function coverageFor(edgeClass, gateVerdict) {
  if (gateVerdict === 'gap' || gateVerdict === 'unknown') return gateVerdict;
  if (edgeClass === 'mitigation-backed') return gateVerdict;
  return gateVerdict === 'held' ? 'attested' : gateVerdict;
}

const RANK = { held: 0, attested: 1, unknown: 2, gap: 3 };

// A technique reached by several gates takes its best verdict — coverage is a
// disjunction, one held control is enough. A gap in an unrelated gate must not
// erase a technique another gate genuinely covers.
function best(rows) {
  return rows.reduce((a, b) => (RANK[b.coverage] < RANK[a.coverage] ? b : a));
}

export function repoAtlasCoverage(target, crosswalk, opts = {}) {
  const a = audit(target, opts);
  const gateByKey = Object.fromEntries(a.gates.map((g) => [g.key, g]));
  const mitById = Object.fromEntries((crosswalk.atlas?.mitigations ?? []).map((m) => [m.id, m]));
  const rows = [];

  for (const g of crosswalk.gates ?? []) {
    const gate = gateByKey[g.key];
    if (!gate) continue;
    for (const e of g.atlas ?? []) {
      // A mitigation-backed edge names a MITIGATION; its techniques come from
      // MITRE's own `mitigates` relationships, which we never author. An
      // asserted edge names the technique directly, because ATLAS publishes no
      // control to hang it on.
      const expand = e.technique
        ? [{ technique: e.technique, via: null }]
        : (mitById[e.mitigation]?.techniques ?? []).map((t) => ({ technique: t, via: e.mitigation }));

      for (const { technique, via } of expand) {
        rows.push({
          technique,
          gate: g.n,
          gateKey: g.key,
          edgeClass: e.class,
          via,
          gateVerdict: gate.verdict,
          coverage: coverageFor(e.class, gate.verdict),
          // an asserted edge carries our reasoning; keep it attached to the
          // verdict so nobody reads `attested` as though MITRE said it
          rationale: e.class === 'asserted' ? (e.rationale ?? null) : null,
          evidence: gate.evidence?.[0] ?? null,
        });
      }
    }
  }

  const byTechnique = new Map();
  for (const r of rows) {
    const prev = byTechnique.get(r.technique);
    byTechnique.set(r.technique, prev ? best([prev, r]) : r);
  }

  const techniques = [...byTechnique.values()].sort((x, y) => (x.technique < y.technique ? -1 : 1));
  const summary = { held: 0, attested: 0, gap: 0, unknown: 0 };
  for (const t of techniques) summary[t.coverage] += 1;

  return {
    tool: 'build-order/atlas-coverage',
    target,
    generated: a.generated,
    atlasRelease: crosswalk.atlas?.release ?? null,
    atlasVersion: crosswalk.atlas?.version ?? null,
    gates: a.summary,
    techniques,
    summary,
    // How many technique verdicts were capped by the ceiling above. This is
    // reported rather than hidden: it is the count of places where we hold the
    // control but not the authority, and it should be read every time.
    cappedByCeiling: techniques.filter((t) => t.edgeClass === 'asserted' && t.gateVerdict === 'held').length,
  };
}
