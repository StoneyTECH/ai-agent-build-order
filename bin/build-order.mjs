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

Verdicts:
  HELD      static evidence in the repo        ATTESTED  self-reported, receipt required
  GAP       anti-pattern or provable absence   UNKNOWN   no signal, no attestation

Exit 1 if any gate is a GAP. Attested/unknown do not fail the build.`;

function main() {
  const args = parseArgs(process.argv.slice(2));
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
