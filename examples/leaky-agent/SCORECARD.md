# Build Order Scorecard

**Target:** `examples/leaky-agent` · **Files scanned:** 1 · **Tool:** build-order v0.1.0 · **Generated:** 2026-07-18T22:26:59.481Z

**0 held · 0 attested · 3 gap · 5 unknown** of 8 gates — 3 gap(s) block a clean build

| # | Gate | Verdict | Mode | Evidence |
|---|------|---------|------|----------|
| 1 | Name the operator | ❌ GAP | static | hardcoded credential-shaped literal: agent.js:6 — const OPENAI_KEY = "sk-live-not-a-real-key-abcdefghijklmnop"; // <- gate 1 |
| 2 | Draw the scope, deny by default | ❌ GAP | static | wildcard grant (no deny-by-default): agent.js:9 — const agentConfig = { tools: "*", permissions: "*" }; // <- gate 2 |
| 3 | Classify the evidence | ❔ UNKNOWN | attest | no input-validation/provenance checks detected; attest how retrieved context is classified |
| 4 | Type the tools | ❔ UNKNOWN | attest | no typed tool schemas detected; attest that tools enforce typed inputs and per-tool auth |
| 5 | Define done, keep the receipt | ❔ UNKNOWN | attest | no audit-trail/receipt emission detected; attest what proves a run actually happened |
| 6 | Gate the never-states | ❔ UNKNOWN | attest | no in-code hard stops detected; a warning in a prompt is not a gate |
| 7 | Turn failures into fixtures | ❌ GAP | static | no test/eval/regression files found — failures have nowhere to become fixtures |
| 8 | Build the way home | ❔ UNKNOWN | attest | no budgets/rollback/escalation detected; attest the recovery path and who it lands on |

> **HELD** = static evidence found in the tree. **ATTESTED** = self-reported with a receipt reference, not independently proven. **GAP** = a static anti-pattern was found, or the gate is provably absent, or it was attested as not implemented. **UNKNOWN** = no signal and no attestation.
>
> Attested and unknown are **not** passes. Static detectors are heuristics: they find signals, not guarantees. The order of the gates is the order the rails get laid, from ["Everything Gets Rebuilt"](https://stoneytech.net/learn/2026-07-18-everything-gets-rebuilt).
