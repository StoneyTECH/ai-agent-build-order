# Build Order Scorecard

**Target:** `.` · **Files scanned:** 19 · **Tool:** build-order v0.1.0 · **Generated:** 2026-08-06T03:44:04.655Z

**5 held · 3 attested · 1 gap · 0 unknown** of 9 gates — 1 gap(s) block a clean build

| # | Gate | Verdict | Mode | Evidence |
|---|------|---------|------|----------|
| 1 | Vet the supply chain | 📝 ATTESTED | attest | self-attested: no required runtime dependencies; the only deps are the optional MCP SDK and zod used by the MCP wrapper, so no production lockfile is shipped. Admitted materials are Node stdlib only<br>receipt: package.json (optionalDependencies only, no dependencies block) |
| 2 | Name the operator | 📝 ATTESTED | attest | self-attested: read-only CLI/MCP tool; runs under the invoking user or MCP session identity, holds no credentials of its own and requests none<br>receipt: src/scanner.mjs (no network, no writes) + bin/build-order.mjs |
| 3 | Draw the scope, deny by default | ❌ GAP | static | wildcard grant (no deny-by-default): test/negative-control.test.mjs:124 — 'notes.mjs': `// never write permissions: "*" or tools: "*" in a config; test/negative-control.test.mjs:127 — const real = fixture({ 'config.mjs': `export const permissions = "*";` }); |
| 4 | Classify the evidence | ✅ HELD | static | bin/build-order.mjs:65 — const cw = JSON.parse(readFileSync(fileURLToPath(new URL('../crosswalk.v1.json', import.meta.url)), 'utf8'));<br>mcp/build-order-mcp.mjs:16 — import { z } from 'zod';<br>package.json:20 — "zod": "^3.23.0"<br>scripts/map-gates.mjs:25 — const committed = JSON.parse(<br>attestation: every input is treated as adversarial: file reads are size-capped, non-text files are skipped, and the attestation file can never satisfy a static detector |
| 5 | Type the tools | ✅ HELD | static | mcp/build-order-mcp.mjs:22 — server.registerTool(<br>mcp/build-order-mcp.mjs:28 — inputSchema: {<br>mcp/build-order-mcp.mjs:44 — server.registerTool(<br>mcp/build-order-mcp.mjs:50 — inputSchema: {<br>attestation: CLI args are parsed explicitly; the MCP wrapper exposes one typed tool (build_order_audit) with a declared input schema |
| 6 | Define done, keep the receipt | ✅ HELD | static | src/audit.mjs:29 — if (!att.receipt) { |
| 7 | Gate the never-states | ✅ HELD | static | bin/build-order.mjs:58 — process.exit(2);<br>bin/build-order.mjs:61 — process.exit(0);   // reporting coverage is never a build failure<br>bin/build-order.mjs:71 — process.exit(2);<br>bin/build-order.mjs:80 — process.exit(0);   // reporting coverage is never a build failure |
| 8 | Turn failures into fixtures | ✅ HELD | static | 4 test/eval file(s): test/atlas-coverage.test.mjs, test/atlas.test.mjs, test/audit.test.mjs, test/negative-control.test.mjs<br>CI workflow present |
| 9 | Build the way home | 📝 ATTESTED | attest | self-attested: stateless read-only auditor: nothing to roll back. Its stop condition is exit code 1 on any GAP, which is how it lands with a human in CI<br>receipt: bin/build-order.mjs process.exit(sc.clean ? 0 : 1) + .github/workflows/self-audit.yml |

> **HELD** = static evidence found in the tree. **ATTESTED** = self-reported with a receipt reference, not independently proven. **GAP** = a static anti-pattern was found, or the gate is provably absent, or it was attested as not implemented. **UNKNOWN** = no signal and no attestation.
>
> Attested and unknown are **not** passes. Static detectors are heuristics: they find signals, not guarantees. The order of the gates is the order the rails get laid, from ["Everything Gets Rebuilt"](https://stoneytech.net/learn/2026-07-18-everything-gets-rebuilt).
