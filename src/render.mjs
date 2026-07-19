// render.mjs — turn a scorecard object into markdown (the receipt) or a line.
const ICON = { held: '✅ HELD', attested: '📝 ATTESTED', gap: '❌ GAP', unknown: '❔ UNKNOWN' };

export function renderMarkdown(sc) {
  const rows = sc.gates.map((g) => {
    const evidence = g.evidence.join('<br>').replace(/\|/g, '\\|');
    return `| ${g.id} | ${g.title} | ${ICON[g.verdict]} | ${g.mode} | ${evidence} |`;
  });
  const s = sc.summary;
  return [
    '# Build Order Scorecard',
    '',
    `**Target:** \`${sc.target}\` · **Files scanned:** ${sc.filesScanned} · **Tool:** ${sc.tool} v${sc.version} · **Generated:** ${sc.generated}`,
    '',
    `**${s.held} held · ${s.attested} attested · ${s.gap} gap · ${s.unknown} unknown** of ${s.total} gates — ${sc.clean ? 'no hard gaps' : `${s.gap} gap(s) block a clean build`}`,
    '',
    '| # | Gate | Verdict | Mode | Evidence |',
    '|---|------|---------|------|----------|',
    ...rows,
    '',
    '> **HELD** = static evidence found in the tree. **ATTESTED** = self-reported with a receipt reference, not independently proven. **GAP** = a static anti-pattern was found, or the gate is provably absent, or it was attested as not implemented. **UNKNOWN** = no signal and no attestation.',
    '>',
    "> Attested and unknown are **not** passes. Static detectors are heuristics: they find signals, not guarantees. The order of the gates is the order the rails get laid, from [\"Everything Gets Rebuilt\"](https://stoneytech.net/learn/2026-07-18-everything-gets-rebuilt).",
    '',
  ].join('\n');
}

export function renderLine(sc) {
  const s = sc.summary;
  return `build-order: ${s.held} held · ${s.attested} attested · ${s.gap} gap · ${s.unknown} unknown (${sc.clean ? 'clean' : 'BLOCKED'})`;
}
