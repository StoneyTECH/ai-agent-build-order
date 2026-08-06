// scanner.mjs — read-only repo walker with a grep the gate detectors share.
// No network, no writes, no eval. It only reads files under the target root.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, basename } from 'node:path';

const DEFAULT_IGNORE_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', '.svelte-kit', '.wrangler',
  'coverage', '__pycache__', '.venv', 'venv', '.next', '.turbo', 'vendor',
]);

// Only scan text/code files. Binaries and lockfiles carry no signal and
// would just add noise (and false positives) to the heuristics.
const TEXT_EXT = /\.(m?[jt]sx?|py|go|rs|rb|java|kt|cs|php|json|ya?ml|toml|svx|svelte|md|mdx|sh|bash|zsh|env|cfg|conf|ini|txt|Dockerfile)$/i;
const TEXT_NAME = /^(Dockerfile|Makefile|\.env[.\w-]*|\.mcp\.json|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Cargo\.lock|Gemfile\.lock|go\.sum)$/i;

// Files where a control is IMPLEMENTED rather than described. A detector that
// looks for code should be pointed here, because the same token that proves a
// control in source ("inputSchema") merely mentions it in a README table.
// Config stays in scope: a tool manifest genuinely declares typed tools.
export const CODE_EXT = /\.(m?[jt]sx?|py|go|rs|rb|java|kt|cs|php|json|ya?ml|toml|svelte|sh|bash|zsh)$/i;

// Artifacts that DESCRIBE controls, including our own self-reports. These can
// never satisfy a static detector — that would be the report proving itself.
// Excluded unconditionally: the old guard only applied when --attest was
// passed, so running without the flag let attestation.json become evidence.
// gates.mjs and the negative-control fixture used to be listed here too. They
// are not any more: classifyHit() demotes their prose because it sits inside
// string literals, which is the general form of the same problem.
const SELF_DESCRIBING = /^(attestation\.json|SCORECARD\.md|CROSSWALK\.md|crosswalk\.v\d+\.json)$/i;

// Comment-leading syntax across the languages TEXT_EXT admits.
const COMMENT_RE = /^\s*(\/\/|\/\*|\*|#|<!--|--)/;
const OVERSCAN = 4;

// Data formats are quoted all the way down, and a quoted key there IS the
// declaration — `"zod": "^3.23.0"` genuinely admits a dependency. String
// demotion below would read every one of them as mere mention, so it is not
// applied to these.
const DATA_EXT = /\.(json|ya?ml|toml|cfg|conf|ini|env)$/i;

// Remove string and regex literals and trailing line comments, so what is left
// is code position. Deliberately naive: it only has to be right often enough
// to rank. Regex literals matter more than they look — a detector's own
// pattern `/principal|service.?account/` contains every keyword it hunts for,
// in what would otherwise read as code position, so the file defining the
// detectors satisfies all of them.
const stripLiterals = (s) =>
  s.replace(/`(?:\\.|[^`\\])*`/g, '``')
    .replace(/'(?:\\.|[^'\\])*'/g, "''")
    .replace(/"(?:\\.|[^"\\])*"/g, '""')
    .replace(/([(,=:[]\s*)\/(?:\\.|\[(?:\\.|[^\]\\])*\]|[^/\\\n])+\/[gimsuy]*/g, '$1//')
    .replace(/(^|[^:])\/\/.*$/, '$1');

// Where did the match actually land? A token inside a string literal is the
// control being TALKED ABOUT — `rationale: 'a deny-by-default scope...'` is our
// crosswalk prose, not a boundary. A token in code position is the control.
// This generalises what a filename exclusion list can only special-case: it
// catches gates.mjs's essayLine strings, map-gates.mjs's rationales and the
// CLI's own verdict legend without naming any of them.
// An import specifier is quoted but structural: `import { z } from 'zod'` is
// how a dependency is actually taken on, not a sentence about one. Demoting it
// was a false negative the positive half of the negative control caught
// immediately — gate 4 stopped seeing zod in a file that genuinely imports it.
const IMPORT_RE = /^\s*(import\b|export\s.*\bfrom\b|from\s+\S+\s+import\b|\w+\s*[:=]\s*require\(|require\()/;

// Inside a multi-line template literal the interior lines carry no delimiter
// at all, so they look like bare code to any per-line rule. That is where CLI
// usage text, SQL and — for agent repos especially — prompt bodies live. The
// caller tracks backtick parity down the file and passes it in.
export function classifyHit(text, matches, relPath = '', inTemplate = false) {
  if (COMMENT_RE.test(text)) return 'comment';
  if (DATA_EXT.test(relPath)) return 'code';
  if (IMPORT_RE.test(text)) return 'code';
  if (inTemplate) return 'string';
  return matches(stripLiterals(text)) ? 'code' : 'string';
}

// Unescaped backticks on a line, ignoring any inside quotes or comments.
export const flipsTemplate = (line) => {
  const bare = line.replace(/'(?:\\.|[^'\\])*'/g, "''").replace(/"(?:\\.|[^"\\])*"/g, '""');
  return ((bare.match(/(?<!\\)`/g) || []).length % 2) === 1;
};

const RANK = { code: 0, string: 1, comment: 2 };

// Hits that are actual implementation, not mentions of one.
export const codeHits = (hits) => hits.filter((h) => h.kind === 'code');

// A line carrying this marker is skipped by anti-pattern scans. It is the
// tool's own escape hatch for a reviewed false positive — the same "gate the
// never-states, but allow the vetted exception" idea it audits for.
export const ALLOW_MARKER = 'build-order:allow';

export function scanRepo(root, { ignoreDirs = DEFAULT_IGNORE_DIRS, ignoreFiles = [], ignorePaths = [], maxFileBytes = 512 * 1024 } = {}) {
  const ignoreFileSet = new Set(ignoreFiles.map((f) => basename(f)));
  const skip = (rel) => ignorePaths.some((p) => rel.includes(p));
  const files = [];
  const walk = (dir) => {
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const full = join(dir, e.name);
      const rel = relative(root, full);
      if (skip(rel)) continue;
      if (e.isDirectory()) {
        if (!ignoreDirs.has(e.name)) walk(full);
      } else if (e.isFile()) {
        if (ignoreFileSet.has(e.name)) continue;
        if (SELF_DESCRIBING.test(e.name)) continue;
        if (TEXT_EXT.test(e.name) || TEXT_NAME.test(e.name)) files.push(full);
      }
    }
  };
  walk(root);
  return new RepoContext(root, files, maxFileBytes);
}

export class RepoContext {
  constructor(root, files, maxFileBytes) {
    this.root = root;
    this.files = files;
    this.maxFileBytes = maxFileBytes;
    this._cache = new Map();
  }

  rel(f) { return relative(this.root, f) || basename(f); }

  read(f) {
    if (this._cache.has(f)) return this._cache.get(f);
    let text = '';
    try {
      if (statSync(f).size <= this.maxFileBytes) text = readFileSync(f, 'utf8');
    } catch { /* unreadable file → treated as empty */ }
    this._cache.set(f, text);
    return text;
  }

  // Case-insensitive, non-global grep. Returns up to `limit` hits as
  // { file, line, text }. `skipAllowed` drops lines carrying ALLOW_MARKER.
  //
  // `pattern` is a regex/string, or a predicate over the line for detectors a
  // regex cannot express. The predicate runs here rather than over the returned
  // hits so rejections never consume `limit` — otherwise a handful of near
  // misses at the top of a tree would crowd out the real finding below them.
  grep(pattern, { include, limit = 5, skipAllowed = false } = {}) {
    let matches;
    if (typeof pattern === 'function') {
      matches = pattern;
    } else {
      const src = pattern instanceof RegExp ? pattern.source : pattern;
      const flags = (pattern instanceof RegExp ? pattern.flags : '').replace('g', '');
      const rx = new RegExp(src, flags.includes('i') ? flags : flags + 'i');
      matches = (line) => rx.test(line);
    }
    const hits = [];
    for (const f of this.files) {
      const relPath = this.rel(f);
      if (include && !include.test(relPath)) continue;
      const text = this.read(f);
      if (!text) continue;
      const lines = text.split('\n');
      let inTemplate = false;
      for (let i = 0; i < lines.length; i++) {
        const wasInTemplate = inTemplate;
        if (flipsTemplate(lines[i])) inTemplate = !inTemplate;
        if (skipAllowed && lines[i].includes(ALLOW_MARKER)) continue;
        if (matches(lines[i])) {
          hits.push({
            file: relPath, line: i + 1, text: lines[i].trim().slice(0, 140),
            // a line that OPENS a template is still code; its interior is not
            kind: classifyHit(lines[i], matches, relPath, wasInTemplate && inTemplate)
          });
          // Keep collecting past `limit` so ranking has something to choose
          // from, but stop well short of scanning the whole tree for nothing.
          if (hits.length >= limit * OVERSCAN) { i = lines.length; break; }
        }
      }
      if (hits.length >= limit * OVERSCAN) break;
    }
    // A comment or a string that MENTIONS a control is not the control. Both
    // are kept — a caller may legitimately want them — but code position sorts
    // first, so the evidence line that lands in the receipt is the strongest
    // available rather than merely the earliest in the file.
    return hits.sort((a, b) => RANK[a.kind] - RANK[b.kind]).slice(0, limit);
  }

  // Does any file's relative path match? (presence of test dirs, CI, etc.)
  hasPath(pattern) {
    const rx = pattern instanceof RegExp ? pattern : new RegExp(pattern);
    return this.files.some((f) => rx.test(this.rel(f)));
  }

  paths(pattern) {
    const rx = pattern instanceof RegExp ? pattern : new RegExp(pattern);
    return this.files.map((f) => this.rel(f)).filter((p) => rx.test(p));
  }
}
