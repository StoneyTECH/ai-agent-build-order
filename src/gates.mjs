// gates.mjs — the nine gates of the Build Order, each turned into a detector.
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
  new RegExp('AKIA' + '[0-9A-Z]{16}', 'i'),                              // build-order:allow
  new RegExp('sk-(?:proj-)?' + '[A-Za-z0-9]{20,}', 'i'),                 // build-order:allow (no hyphens in body: "risk-management-framework" is not a key)
  new RegExp('Bearer\\s+[A-Za-z0-9._-]{20,}', 'i'),                      // build-order:allow
];

// The shortest unbroken run of characters that could carry a secret's entropy.
// It is both the floor for a whole value and, below, the floor for any one
// segment of it — the same argument applies at both scales, so it is one number.
const MIN_SECRET_RUN = 12;

// A *_KEY / *_TOKEN / *_SECRET label assigned a long, space-free literal.
// Global on purpose: one line can carry several assignments, and a benign one
// first must not hide a real key second.
const LABELLED_LITERAL = new RegExp('\\b\\w*(key|token|secret|password|passwd|credential)\\b\\s*[:=]\\s*[\'"]([^\'"\\s]{' + MIN_SECRET_RUN + ',})[\'"]', 'gi'); // build-order:allow

// Does this line hardcode a credential? The label is only the doorway — a
// mature codebase is full of names ending in Key or Secret — so the VALUE has
// to carry the match. Exported because it is the detector most worth testing
// directly: its false positives are what make an audit unreadable.
export function looksLikeHardcodedSecret(line) {
  if (SECRET_PATTERNS.some((p) => p.test(line))) return true;
  for (const m of line.matchAll(LABELLED_LITERAL)) if (isSecretShapedValue(m[2], m[1])) return true;
  return false;
}

// A reference names a secret; it is never one. `${VAR}` and `$(cmd)`
// substitutions, `{placeholder}` and `<placeholder>` templates, `%VAR%`
// expansion — all resolve elsewhere, so the literal sitting in the file is a
// variable's name, not its contents.
const REFERENCE_VALUE = /\$\{|\$\(|\{\w+\}|%\w+%|<[^>]*>/;

// A URL is a locator.
const URL_VALUE = /^[a-z][a-z0-9+.-]*:\/\//i;

// Word-ish: a plain word or a short number. Anything mixing cases, letters and
// digits, or running longer than a word is entropy, and entropy is the tell.
const WORDISH = (seg) => /^[A-Za-z]{1,24}$/.test(seg) || /^[0-9]{1,6}$/.test(seg);

const segments = (v) => v.split(/[._:/\\-]+/).filter(Boolean);

// A dotted or namespaced identifier — a hostname, a resource path, a log or
// idempotency key. Every segment is word-ish, so there is nowhere in the string
// for a secret to hide. The trigger is a NAMESPACING separator (`.` `:` `/`),
// which is what tells `secretmanager.googleapis.com` from a long opaque run.
const isNamespacedValue = (v) => /[.:/]/.test(v) && segments(v).every(WORDISH);

// Nothing in it is secret-sized. A string whose every segment falls under the
// floor is a compound of short tokens — `gpt-55-openai-us`,
// `cloudflare-r2-read-access-key-id`, `standards-led-evidence-signing`. Secret
// managers *name* their secrets, so a *_KEY / *_TOKEN / *_SECRET label holding
// one of these is a pointer, not a credential. That single shape accounted for
// 46 of this detector's 50 hits on a real monorepo, none of them real.
const hasNoSecretSizedRun = (v) => segments(v).every((s) => s.length < MIN_SECRET_RUN);

// ...but nobody stores the *name* of a password, so the rule above does not
// apply to a password label. That is what keeps `password = "correct-horse-
// battery-staple"` a gap while `SIGNING_KEY_SECRET = "standards-led-evidence-
// signing"` goes quiet — same shape, different claim about what it holds.
const NAMEABLE_LABEL = /key|token|secret|credential/i;

// The label got us here; the value decides. Whatever survives is an opaque,
// entropy-bearing run of characters — which is what a secret actually looks like.
function isSecretShapedValue(value, label) {
  if (REFERENCE_VALUE.test(value) || URL_VALUE.test(value)) return false;
  if (isNamespacedValue(value)) return false;
  if (NAMEABLE_LABEL.test(label) && hasNoSecretSizedRun(value)) return false;
  return true;
}

export const GATES = [
  {
    id: 1,
    key: 'supply-chain',
    title: 'Vet the supply chain',
    essayLine: 'Approve the model, dependencies, datasets, and tool code you admit, and refuse the rest; the attack that opened the essay arrived as a dataset, not a prompt.',
    detect(ctx) {
      // Positive evidence that admitted materials are inventoried and pinned:
      // an SBOM/AI-BOM, or a dependency lockfile. Absence is not a gap on its
      // own (provenance may be vetted out of band) — it is unproven, so the
      // build attests the model, dataset, and dependency provenance instead.
      const sbom = ctx.paths(/\.cdx\.json$|(^|\/)(sbom|bom)\.(json|xml)$/i);
      if (sbom.length) return { verdict: 'held', mode: 'static', evidence: [`SBOM/AI-BOM present: ${sbom.slice(0, 3).join(', ')}`] };
      const lock = ctx.paths(/(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Cargo\.lock|Gemfile\.lock|go\.sum)$/i);
      if (lock.length) return { verdict: 'held', mode: 'static', evidence: [`dependency lockfile present: ${lock.slice(0, 3).join(', ')}`] };
      return { verdict: 'unknown', mode: 'attest', evidence: ['no SBOM or dependency lockfile found; attest the model, dataset, and dependency provenance you admit'] };
    },
  },
  {
    id: 2,
    key: 'operator',
    title: 'Name the operator',
    essayLine: "Authenticate who's asking, and give the agent an identity of its own, so every action traces back to a person or a policy.",
    detect(ctx) {
      // Anti-pattern first: a hardcoded credential is the loudest failure of
      // "run under an identity." If one is present, that is a gap, full stop.
      const secrets = ctx.grep(looksLikeHardcodedSecret, { limit: 3, skipAllowed: true });
      if (secrets.length) return { verdict: 'gap', mode: 'static', evidence: [`hardcoded credential-shaped literal: ${ev(secrets).join('; ')}`] };
      const id = ctx.grep(/principal|service.?account|agent.?identity|caller.?identity|assume.?role|workload.?identity|per-agent (identity|credential)|authenticat/i, { limit: 4 });
      if (id.length) return { verdict: 'held', mode: 'static', evidence: ev(id) };
      return { verdict: 'unknown', mode: 'attest', evidence: ['no identity/principal wiring detected; attest how the agent runs under its own identity'] };
    },
  },
  {
    id: 3,
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
    id: 4,
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
    id: 5,
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
    id: 6,
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
    id: 7,
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
    id: 8,
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
    id: 9,
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
