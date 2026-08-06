#!/usr/bin/env node
// build-order — audit an AI agent build against the nine-gate Build Order.
//
//   build-order audit <path> [--attest file.json] [--out SCORECARD.md] [--json]
//
// Exit code is 1 when any gate is a hard GAP, so it works as a CI gate.
// Attested and unknown never fail the build; they are open questions, not proof.
import { writeFileSync } from 'node:fs';
import { audit } from '../src/audit.mjs';
import { renderMarkdown, renderLine } from '../src/render.mjs';
import { renderCoverageMarkdown, atlasCoverage } from '../src/atlas-report.mjs';
import { repoAtlasCoverage } from '../src/atlas-coverage.mjs';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

function parseArgs(argv) {
  const args = { _: [], attest: null, out: null, json: false, ignore: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--attest') args.attest = argv[++i];
    else if (a === '--out') args.out = argv[++i];
    else if (a === '--ignore') args.ignore = (argv[++i] || '').split(',').filter(Boolean);
    else if (a === '--json') args.json = true;
    else if (a === '-h' || a === '--help') args.help = true;
    else args._.push(a);
  }
  return args;
}

const USAGE = `build-order — audit an agent build against the nine-gate Build Order

Usage:
  build-order audit <path> [--attest file.json] [--out SCORECARD.md] [--json]
  build-order atlas [--json]
  build-order atlas-coverage <path> [--attest f.json] [--ignore a,b] [--json]

Verdicts:
  HELD      static evidence in the repo        ATTESTED  self-reported, receipt required
  GAP       anti-pattern or provable absence   UNKNOWN   no signal, no attestation

Exit 1 if any gate is a GAP. Attested/unknown do not fail the build.

atlas prints crosswalk coverage in the abstract: which techniques the nine
gates bear on at all. atlas-coverage answers it for ONE repo, by joining the
gate verdicts of that tree to the crosswalk. An edge this project asserts can
never report HELD there, however green the gate — we can prove we run a
control, never that it works.
Edges backed by a published ATLAS mitigation and edges this project asserts
are counted separately and never summed.`;

function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args._[0] === 'atlas' && !args.help) {
    const rep = atlasCoverage();
    if (!rep) {
      console.error('build-order: no ATLAS block in crosswalk.v1.json');
      process.exit(2);
    }
    console.log(args.json ? JSON.stringify(rep, null, 2) : renderCoverageMarkdown());
    process.exit(0);   // reporting coverage is never a build failure
  }

  if (args._[0] === 'atlas-coverage' && args._[1] && !args.help) {
    const cw = JSON.parse(readFileSync(fileURLToPath(new URL('../crosswalk.v1.json', import.meta.url)), 'utf8'));
    let rep;
    try {
      rep = repoAtlasCoverage(args._[1], cw, { attestPath: args.attest, ignore: args.ignore });
    } catch (err) {
      console.error(`build-order: ${err.message}`);
      process.exit(2);
    }
    if (args.json) console.log(JSON.stringify(rep, null, 2));
    else {
      const s = rep.summary;
      console.log(`ATLAS coverage for ${rep.target} — ${rep.atlasRelease}`);
      console.log(`  ${s.held} held · ${s.attested} attested · ${s.gap} gap · ${s.unknown} unknown  (${rep.techniques.length} techniques)`);
      console.log(`  ${rep.cappedByCeiling} capped by the asserted ceiling: our control, not MITRE's authority`);
    }
    process.exit(0);   // reporting coverage is never a build failure
  }

  if (args.help || args._[0] !== 'audit' || !args._[1]) {
    console.log(USAGE);
    process.exit(args.help ? 0 : 2);
  }
  const target = args._[1];
  let sc;
  try {
    sc = audit(target, { attestPath: args.attest, ignore: args.ignore });
  } catch (err) {
    console.error(`build-order: ${err.message}`);
    process.exit(2);
  }

  if (args.json) console.log(JSON.stringify(sc, null, 2));
  else console.log(renderMarkdown(sc));

  if (args.out) {
    writeFileSync(args.out, renderMarkdown(sc));
    console.error(`\n${renderLine(sc)} → ${args.out}`);
  }

  process.exit(sc.clean ? 0 : 1);
}

main();
