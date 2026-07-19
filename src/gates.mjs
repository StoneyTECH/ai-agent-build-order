// gates.mjs — the eight gates of the Build Order, each turned into a detector.
//
// Every detector returns { verdict, mode, evidence[] } where verdict is one of:
//   held     — static evidence for the gate was found in the repo
//   gap      — a static anti-pattern was found (or the thing is provably absent)
//   unknown  — no static signal either way; the gate needs an attestation
//
// These detectors are deliberately HEURISTIC. They read the repo the way a
// reviewer skims it: they find signals, not guarantees. "held" means "the
// evidence is in the tree," never "this is correct." The tool's whole honesty
// depends on saying unknown when it cannot see, and never inflating a claim.

const ev = (hits) => hits.map((h) => `${h.file}:${h.line} — ${h.text}`);

// Secret-shaped literals, assembled from fragments so this source file carries
// no real-looking token and never trips its own scan. build-order:allow
const SECRET_PATTERNS = [
  new RegExp('AKIA' + '[0-9A-Z]{16}'),                                   // build-order:allow
  new RegExp('sk-' + '[A-Za-z0-9_-]{16,}'),                              // build-order:allow
  // a *_KEY / *_TOKEN / *_SECRET var assigned a long, space-free literal
  new RegExp('\\b\\w*(key|token|secret|password|passwd|credential)\\b\\s*[:=]\\s*[\'"][^\'"\\s]{12,}[\'"]', 'i'), // build-order:allow
  new RegExp('Bearer\\s+[A-Za-z0-9._-]{20,}'),                           // build-order:allow
];

export const GATES = [
  {
    id: 1,
    key: 'operator',
    title: 'Name the operator',
    essayLine: "Authenticate who's asking, and give the agent an identity of its own, so every action traces back to a person or a policy.",
    detect(ctx) {
      // Anti-pattern first: a hardcoded credential is the loudest failure of
      // "run under an identity." If one is present, that is a gap, full stop.
      for (const p of SECRET_PATTERNS) {
        const hits = ctx.grep(p, { limit: 3, skipAllowed: true });
        if (hits.length) return { verdict: 'gap', mode: 'static', evidence: [`hardcoded credential-shaped literal: ${ev(hits).join('; ')}`] };
      }
      const id = ctx.grep(/principal|service.?account|agent.?identity|caller.?identity|assume.?role|workload.?identity|per-agent (identity|credential)|authenticat/i, { limit: 4 });
      if (id.length) return { verdict: 'held', mode: 'static', evidence: ev(id) };
      return { verdict: 'unknown', mode: 'attest', evidence: ['no identity/principal wiring detected; attest how the agent runs under its own identity'] };
    },
  },
  {
    id: 2,
    key: 'scope',
    title: 'Draw the scope, deny by default',
    essayLine: 'Write down what the agent may touch and deny everything else by default; a boundary that was never written down was never a boundary.',
    detect(ctx) {
      // `\*(?!\*)` so markdown bold (**Tool:**) is not read as a wildcard grant.
      const wild = ctx.grep(/allow[_-]?all|tools?["']?\s*[:=]\s*["']?\*(?!\*)|permissions?["']?\s*[:=]\s*["']?\*(?!\*)/i, { limit: 3, skipAllowed: true });
      if (wild.length) return { verdict: 'gap', mode: 'static', evidence: [`wildcard grant (no deny-by-default): ${ev(wild).join('; ')}`] };
      const allow = ctx.grep(/allow[_-]?list|allowed[_-]?tools|permitted[_-]?tools|deny[_-]?by[_-]?default|scopes?\s*[:=]|\bRBAC\b|least[_-]?privilege/i, { limit: 4 });
      if (allow.length) return { verdict: 'held', mode: 'static', evidence: ev(allow) };
      return { verdict: 'unknown', mode: 'attest', evidence: ['no scope allowlist detected; attest the deny-by-default boundary'] };
    },
  },
  {
    id: 3,
    key: 'evidence',
    title: 'Classify the evidence',
    essayLine: 'Decide which sources may enter context and how freshness and provenance get checked, and treat every input as adversarial until it proves otherwise.',
    detect(ctx) {
      const val = ctx.grep(/zod|pydantic|ajv|joi|\.parse\(|validate[_-]?input|sanitiz|provenance|prompt[_-]?injection|untrusted|allowed[_-]?sources|source[_-]?allowlist/i, { limit: 4 });
      if (val.length) return { verdict: 'held', mode: 'static', evidence: ev(val) };
      return { verdict: 'unknown', mode: 'attest', evidence: ['no input-validation/provenance checks detected; attest how retrieved context is classified'] };
    },
  },
  {
    id: 4,
    key: 'tools',
    title: 'Type the tools',
    essayLine: 'The model proposes and the tool performs; identity, authorization, typed inputs, idempotency, and limits hold at that seam, the one place they can be enforced rather than requested.',
    detect(ctx) {
      const typed = ctx.grep(/inputSchema|input_schema|args_schema|registerTool|server\.tool|z\.object|JSONSchema|@tool|tool\(\{|function[_-]?schema/i, { limit: 4 });
      if (typed.length) return { verdict: 'held', mode: 'static', evidence: ev(typed) };
      return { verdict: 'unknown', mode: 'attest', evidence: ['no typed tool schemas detected; attest that tools enforce typed inputs and per-tool auth'] };
    },
  },
  {
    id: 5,
    key: 'receipts',
    title: 'Define done, keep the receipt',
    essayLine: 'A model saying "done" is a claim; a receipt is evidence. Keep the sources, the policy result, the changed state.',
    detect(ctx) {
      const rec = ctx.grep(/audit[_-]?log|audit[_-]?trail|receipt|\bledger\b|structured[_-]?log|record.*(state|change|decision)|evidence[_-]?(bundle|record)/i, { limit: 4 });
      if (rec.length) return { verdict: 'held', mode: 'static', evidence: ev(rec) };
      return { verdict: 'unknown', mode: 'attest', evidence: ['no audit-trail/receipt emission detected; attest what proves a run actually happened'] };
    },
  },
  {
    id: 6,
    key: 'never-states',
    title: 'Gate the never-states',
    essayLine: 'Anything that must not happen deserves a hard stop in code, not a warning in capital letters.',
    detect(ctx) {
      const hard = ctx.grep(/throw new|raise \w+Error|\bassert\b|process\.exit|sys\.exit|abort\(|panic!|\.reject\(|Forbidden|deny\(|kill[_-]?switch|circuit[_-]?breaker/i, { limit: 4 });
      if (hard.length) return { verdict: 'held', mode: 'static', evidence: ev(hard) };
      return { verdict: 'unknown', mode: 'attest', evidence: ['no in-code hard stops detected; a warning in a prompt is not a gate'] };
    },
  },
  {
    id: 7,
    key: 'fixtures',
    title: 'Turn failures into fixtures',
    essayLine: 'When a run fails, turn the failure into a fixture: a regression case, a graph edge, a tighter template that every future run walks through.',
    detect(ctx) {
      const testFiles = ctx.paths(/(^|\/)tests?\/|\.(test|spec)\.[mc]?[jt]sx?$|(^|\/)eval|_test\.py$|mitre_probe|regression/i);
      const ci = ctx.hasPath(/\.github\/workflows\/|\.gitlab-ci|circleci|Jenkinsfile/i);
      if (testFiles.length) {
        const note = [`${testFiles.length} test/eval file(s): ${testFiles.slice(0, 4).join(', ')}${testFiles.length > 4 ? ' …' : ''}`];
        if (ci) note.push('CI workflow present');
        return { verdict: 'held', mode: 'static', evidence: note };
      }
      // Absence of ANY test is a legible gap, not an unknown.
      return { verdict: 'gap', mode: 'static', evidence: ['no test/eval/regression files found — failures have nowhere to become fixtures'] };
    },
  },
  {
    id: 8,
    key: 'way-home',
    title: 'Build the way home',
    essayLine: 'Budgets that expire, an escalation that lands with a person, a rollback that has actually been run, and a recovery model vetted on your own hardware before an incident asks.',
    detect(ctx) {
      const home = ctx.grep(/timeout|budget|deadline|rollback|revert|compensat|escalat|human[_-]?in[_-]?the[_-]?loop|\bHITL\b|retry|circuit[_-]?breaker|abort[_-]?signal/i, { limit: 4 });
      if (home.length) return { verdict: 'held', mode: 'static', evidence: ev(home) };
      return { verdict: 'unknown', mode: 'attest', evidence: ['no budgets/rollback/escalation detected; attest the recovery path and who it lands on'] };
    },
  },
];
