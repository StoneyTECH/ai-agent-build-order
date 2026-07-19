// audit.mjs — run the nine gates over a target, merge attestation, score it.
import { basename } from 'node:path';
import { readFileSync } from 'node:fs';
import { scanRepo } from './scanner.mjs';
import { GATES } from './gates.mjs';

export const VERDICTS = ['held', 'attested', 'gap', 'unknown'];

// Merge one gate's static result with its attestation entry.
// Rules, in order of authority:
//  1. A static gap wins over any self-report. You do not get to attest away an
//     anti-pattern the tool can see.
//  2. Static held stays held; an attestation note is appended as extra colour.
//  3. Only an UNKNOWN can be lifted by attestation, and only to `attested`
//     (self-reported, receipt required) — never to `held`. A claim is not a
//     receipt, so the tool refuses to render one as proof.
export function mergeAttestation(result, att) {
  if (!att) return result;
  if (result.verdict === 'gap') {
    return att.attested
      ? { ...result, evidence: [...result.evidence, `NOTE: attested as handled, but the static anti-pattern stands — resolve before trusting the attestation`] }
      : result;
  }
  if (result.verdict === 'held') {
    return att.note ? { ...result, evidence: [...result.evidence, `attestation: ${att.note}`] } : result;
  }
  // result.verdict === 'unknown'
  if (att.attested === true) {
    if (!att.receipt) {
      return { verdict: 'unknown', mode: 'attest', evidence: [...result.evidence, 'attested but NO receipt reference given — a claim without evidence is still unknown'] };
    }
    return { verdict: 'attested', mode: 'attest', evidence: [`self-attested: ${att.note ?? 'no note'}`, `receipt: ${att.receipt}`] };
  }
  if (att.attested === false) {
    return { verdict: 'gap', mode: 'attest', evidence: [`explicitly attested as NOT implemented${att.note ? `: ${att.note}` : ''}`] };
  }
  return result;
}

export function loadAttestation(path) {
  if (!path) return {};
  const raw = JSON.parse(readFileSync(path, 'utf8'));
  return raw.gates ?? raw; // accept {gates:{...}} or a bare {key:{...}}
}

export function audit(target, { attestPath = null, ignore = [], now = new Date().toISOString() } = {}) {
  const attestation = attestPath ? loadAttestation(attestPath) : {};
  const ignoreFiles = attestPath ? [basename(attestPath)] : [];
  // Never let the attestation file or a prior scorecard satisfy a static
  // detector — that would be the report proving itself. `ignore` lets a repo
  // exclude files that describe the patterns rather than implement them (a
  // rule list, a spec) so prose about a gate is not mistaken for the gate.
  const ctx = scanRepo(target, { ignoreFiles: [...ignoreFiles, 'SCORECARD.md'], ignorePaths: ignore });

  const gates = GATES.map((g) => {
    const raw = g.detect(ctx);
    const merged = mergeAttestation(raw, attestation[g.key]);
    return { id: g.id, key: g.key, title: g.title, essayLine: g.essayLine, ...merged };
  });

  const summary = { held: 0, attested: 0, gap: 0, unknown: 0, total: gates.length };
  for (const g of gates) summary[g.verdict] += 1;

  return {
    tool: 'build-order',
    version: '0.1.0',
    target,
    generated: now,
    filesScanned: ctx.files.length,
    gates,
    summary,
    // A build is "clean" for CI when nothing is a hard gap. Attested and
    // unknown are open questions, not failures — they just aren't proof yet.
    clean: summary.gap === 0,
  };
}
