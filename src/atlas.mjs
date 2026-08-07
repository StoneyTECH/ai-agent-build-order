// MITRE ATLAS crosswalk support.
//
// This does not restate ATLAS. It reads a pinned release, keeps the ids and
// the mitigation-to-technique edges MITRE publishes, and validates our own
// gate mappings against them.
//
// The load-bearing rule: a mapping backed by an ATLAS mitigation carries
// MITRE's authority; a mapping we assert carries only ours. Those two must
// never blend, in the data or in the report. Everything below serves that.
//
// Source: mitre-atlas/atlas-navigator-data, dist/stix-atlas.json — STIX rather
// than the YAML distribution, because this repository has no dependencies and
// JSON parses natively.

const ATLAS_SOURCE = 'mitre-atlas';
const ATLAS_ID = /^AML\./;
const EDGE_CLASSES = ['mitigation-backed', 'asserted'];
const MIN_RATIONALE = 40;

/**
 * Pull the ATLAS id (AML.T0110, AML.M0032, AML.TA0003) off a STIX object.
 *
 * Exported and shared with scripts/atlas-gaps.mjs, which used to carry its own
 * copy. The two had drifted: `=== 'mitre-atlas'` here, `startsWith('mitre-atlas')`
 * there. They agree on the current release — the bundle publishes exactly one
 * source_name, 222 references, no case variance — so nothing was ever lost.
 * But the stricter test fails SILENTLY. buildAtlasBlock skips any object this
 * returns null for, so the day MITRE namespaces a source, one file would keep
 * those objects and the other would drop them with no error raised. Two
 * definitions of the same join is the defect; the casing was only its symptom.
 *
 * Prefix, so a namespaced source is kept rather than dropped. Case-folded, so
 * casing can never be the reason an id fails to join. Shape-checked, because a
 * loose source match alone would newly admit the ATLAS Matrix object, whose
 * mitre-atlas reference carries the literal external_id "mitre-atlas" rather
 * than an AML id.
 */
export function atlasId(obj) {
  const ref = (obj?.external_references || [])
    .find((r) => (r?.source_name || '').toLowerCase().startsWith(ATLAS_SOURCE));
  const id = ref ? ref.external_id : null;
  return id && ATLAS_ID.test(id) ? id : null;
}

/**
 * Build the crosswalk's `atlas` block from a STIX bundle.
 *
 * Sorted by id throughout, so regenerating from the same release produces
 * byte-identical output regardless of the order STIX happened to list objects
 * in. A block that churns on every regeneration is a block nobody can review.
 */
export function buildAtlasBlock(bundle, { version, release }) {
  const objects = bundle.objects || [];
  const byRef = new Map(objects.map((o) => [o.id, o]));

  const tactics = [];
  const techniques = new Map();
  const mitigations = new Map();

  for (const o of objects) {
    const id = atlasId(o);
    if (!id) continue;
    if (o.type === 'x-mitre-tactic') tactics.push({ id, name: o.name });
    else if (o.type === 'attack-pattern') techniques.set(id, { id, name: o.name, mitigations: [] });
    else if (o.type === 'course-of-action') mitigations.set(id, { id, name: o.name, techniques: [] });
  }

  // Mitigation coverage comes from MITRE's own relationships. We never author
  // this edge — that is the whole point of joining on the control.
  for (const o of objects) {
    if (o.type !== 'relationship' || o.relationship_type !== 'mitigates') continue;
    const m = atlasId(byRef.get(o.source_ref) || {});
    const t = atlasId(byRef.get(o.target_ref) || {});
    if (!m || !t) continue;
    if (mitigations.has(m) && !mitigations.get(m).techniques.includes(t)) {
      mitigations.get(m).techniques.push(t);
    }
    if (techniques.has(t) && !techniques.get(t).mitigations.includes(m)) {
      techniques.get(t).mitigations.push(m);
    }
  }

  const byId = (a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  const sortInner = (x) => ({
    ...x,
    ...(x.techniques ? { techniques: [...x.techniques].sort() } : {}),
    ...(x.mitigations ? { mitigations: [...x.mitigations].sort() } : {})
  });

  return {
    source: 'mitre-atlas/atlas-navigator-data',
    version,
    release,
    tactics: tactics.sort(byId),
    techniques: [...techniques.values()].map(sortInner).sort(byId),
    mitigations: [...mitigations.values()].map(sortInner).sort(byId)
  };
}

/** Every AML id cited anywhere must exist in the pinned release. */
export function validateAtlasIds(block, ids) {
  const known = new Set([
    ...block.tactics.map((t) => t.id),
    ...block.techniques.map((t) => t.id),
    ...block.mitigations.map((m) => m.id)
  ]);
  const errors = ids
    .filter((id) => !known.has(id))
    .map((id) => `unknown ATLAS id ${id} — not present in ${block.release}`);
  return { ok: errors.length === 0, errors };
}

/**
 * Validate the gate mappings.
 *
 * Refusing bad edges matters more than accepting good ones. An unlabelled or
 * unjustified edge launders our judgment as MITRE's, which is the one failure
 * this crosswalk cannot survive.
 */
export function validateGateEdges(gates, block) {
  const errors = [];
  const mitById = new Map(block.mitigations.map((m) => [m.id, m]));
  const techById = new Map(block.techniques.map((t) => [t.id, t]));

  for (const gate of gates) {
    const seen = new Set();

    for (const [i, e] of (gate.atlas || []).entries()) {
      const at = `${gate.id} atlas[${i}]`;

      if (!EDGE_CLASSES.includes(e.class)) {
        errors.push(
          `${at}: class must be one of ${EDGE_CLASSES.join(', ')}, got ${JSON.stringify(e.class)}`
        );
        continue;
      }

      const target = e.mitigation || e.technique;
      if (!target) {
        errors.push(`${at}: edge names neither a mitigation nor a technique`);
        continue;
      }
      if (seen.has(target)) {
        errors.push(`${at}: duplicate edge for ${target}`);
        continue;
      }
      seen.add(target);

      if (e.class === 'mitigation-backed') {
        if (!e.mitigation) {
          errors.push(`${at}: a mitigation-backed edge must name a mitigation`);
        } else if (!mitById.has(e.mitigation)) {
          errors.push(`${at}: unknown mitigation ${e.mitigation} in ${block.release}`);
        }
        // Technique coverage is derived from ATLAS. Restating it here means two
        // sources of truth, and the copy goes stale the first time MITRE ships.
        if (e.techniques) {
          errors.push(
            `${at}: do not restate techniques on a mitigation-backed edge — coverage is derived from ATLAS`
          );
        }
      }

      if (e.class === 'asserted') {
        if (!e.technique) {
          errors.push(`${at}: an asserted edge must name a technique`);
          continue;
        }
        if (!techById.has(e.technique)) {
          errors.push(`${at}: unknown technique ${e.technique} in ${block.release}`);
          continue;
        }
        if (typeof e.rationale !== 'string' || e.rationale.trim().length < MIN_RATIONALE) {
          errors.push(
            `${at}: an asserted edge requires a rationale of at least ${MIN_RATIONALE} characters — it carries our authority, not MITRE's`
          );
        }
        // If MITRE published a control, use it. Asserting over the top of an
        // existing mitigation claims credit for work already done, and hides
        // the stronger citation.
        const covered = techById.get(e.technique).mitigations;
        if (covered.length) {
          errors.push(
            `${at}: ${e.technique} already has ATLAS mitigation ${covered.join(', ')} — use a mitigation-backed edge instead of asserting`
          );
        }
      }
    }
  }

  return { ok: errors.length === 0, errors };
}

/**
 * Coverage, reported so it cannot be misread.
 *
 * There is deliberately no blended total. A single number would let an
 * asserted edge count the same as a MITRE-backed one, which is exactly the
 * conflation the two classes exist to prevent. Unaddressed techniques are
 * listed rather than omitted, because silence reads as coverage.
 */
export function coverageReport(gates, block) {
  const addressed = new Set();
  let mitigationBacked = 0;
  let asserted = 0;

  for (const gate of gates) {
    for (const e of gate.atlas || []) {
      if (e.class === 'mitigation-backed' && e.mitigation) {
        mitigationBacked += 1;
        const m = block.mitigations.find((x) => x.id === e.mitigation);
        for (const t of (m && m.techniques) || []) addressed.add(t);
      } else if (e.class === 'asserted' && e.technique) {
        asserted += 1;
        addressed.add(e.technique);
      }
    }
  }

  const all = block.techniques.map((t) => t.id);
  return {
    version: block.version,
    release: block.release,
    mitigationBacked,
    asserted,
    techniquesTotal: all.length,
    techniquesAddressed: addressed.size,
    open: all.filter((id) => !addressed.has(id)).sort()
  };
}

/**
 * Compare a pinned release against a newer one.
 *
 * ATLAS ships releases. A crosswalk that cannot notice is a crosswalk that
 * quietly starts lying — it keeps citing ids that moved, and it keeps
 * asserting coverage for techniques MITRE has since published a control for.
 *
 * `upgradable` is the one that matters. An asserted edge carries our authority
 * because no ATLAS mitigation existed. The moment one does, the honest move is
 * to cite MITRE instead of ourselves, and this is what surfaces that.
 */
export function driftReport(pinned, next, gates) {
  const before = new Map(pinned.techniques.map((t) => [t.id, t]));
  const after = new Map(next.techniques.map((t) => [t.id, t]));

  const added = [...after.keys()].filter((id) => !before.has(id)).sort();
  const removed = [...before.keys()].filter((id) => !after.has(id)).sort();

  const renamed = [...before.values()]
    .filter((t) => after.has(t.id) && after.get(t.id).name !== t.name)
    .map((t) => ({ id: t.id, from: t.name, to: after.get(t.id).name }))
    .sort((a, b) => (a.id < b.id ? -1 : 1));

  const upgradable = [];
  for (const gate of gates) {
    for (const e of gate.atlas || []) {
      if (e.class !== 'asserted' || !e.technique) continue;
      const now = after.get(e.technique);
      if (now && now.mitigations.length) {
        upgradable.push({
          gate: gate.id,
          technique: e.technique,
          mitigations: [...now.mitigations].sort()
        });
      }
    }
  }

  return { from: pinned.release, to: next.release, added, removed, renamed, upgradable };
}
