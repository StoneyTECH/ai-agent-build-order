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
  grep(pattern, { include, limit = 5, skipAllowed = false } = {}) {
    const src = pattern instanceof RegExp ? pattern.source : pattern;
    const flags = (pattern instanceof RegExp ? pattern.flags : '').replace('g', '');
    const rx = new RegExp(src, flags.includes('i') ? flags : flags + 'i');
    const hits = [];
    for (const f of this.files) {
      const relPath = this.rel(f);
      if (include && !include.test(relPath)) continue;
      const text = this.read(f);
      if (!text) continue;
      const lines = text.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (skipAllowed && lines[i].includes(ALLOW_MARKER)) continue;
        if (rx.test(lines[i])) {
          hits.push({ file: relPath, line: i + 1, text: lines[i].trim().slice(0, 140) });
          if (hits.length >= limit) return hits;
        }
      }
    }
    return hits;
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
