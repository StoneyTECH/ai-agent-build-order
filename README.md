# build-order

> **Start with [CROSSWALK.md](CROSSWALK.md).** This repo is a principal architect's *reference architecture* for agent assurance: the nine-gate Build Order laid in dependency order, and for each gate, the [OWASP Agentic Top 10 (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) risk it closes, the determinism rung it lives on, and the **mature tool** that enforces it. For real detection, adopt those tools ([Snyk agent-scan](https://github.com/snyk/agent-scan), [agent-audit](https://github.com/HeadyZhang/agent-audit), AgentAuditKit) — this maps you to them and sequences their adoption. The audit CLI below is a teaching self-check, not a competitor to them.

**Audit an AI agent build against the nine-gate Build Order.** Static where it can detect, attested where it can't, and every gate labeled which — so a self-report is never rendered as proof.

This is the proof-of-work companion to the essay [*Everything Gets Rebuilt*](https://stoneytech.net/learn/2026-07-18-everything-gets-rebuilt). The essay ends with nine steps, in the order the rails get laid. This repo turns those steps into a check an agent can run against its own build before it is granted authority. The essay is the demo; this is the receipt.

```
npx build-order audit ./my-agent
```

## The nine gates

| # | Gate | The question it asks |
|---|------|----------------------|
| 1 | Vet the supply chain | Are the model, dependencies, datasets, and tool code inventoried and pinned, or admitted on faith? |
| 2 | Name the operator | Does every action trace to an identity, or is a static key doing the work? |
| 3 | Draw the scope | Is there an allowlist and deny-by-default, or a wildcard grant? |
| 4 | Classify the evidence | Is retrieved context validated, or does it flow straight into the prompt? |
| 5 | Type the tools | Do tools enforce typed inputs at the seam, or take free-form blobs? |
| 6 | Define done, keep the receipt | Is there an audit trail, or just the word "done"? |
| 7 | Gate the never-states | Is the never-state a hard stop in code, or a warning in the prompt? |
| 8 | Turn failures into fixtures | Do failures become regression cases, or vanish? |
| 9 | Build the way home | Are there budgets, escalation, and a tested rollback before the incident? |

## The verdicts (this is the whole point)

Each gate returns one of four, and the tool is careful never to inflate:

- **✅ HELD** — static evidence is in the tree.
- **📝 ATTESTED** — self-reported *with a receipt reference*. A claim, not a proof. It is tracked separately from HELD and never counted as it.
- **❌ GAP** — a static anti-pattern was found, the control is provably absent, or it was attested as *not* implemented.
- **❔ UNKNOWN** — no signal, and no attestation. The tool refuses to guess.

A static **GAP always wins** over a self-report — you cannot attest away a hardcoded key the tool can see. An **UNKNOWN can only rise to ATTESTED**, never to HELD, and only if the attestation carries a receipt. A claim without a receipt stays UNKNOWN. That rule is the essay's *"'done' is a claim, a receipt is evidence,"* enforced in code ([`src/audit.mjs`](src/audit.mjs)).

## What it catches — `examples/leaky-agent`

A deliberately bad build: a hardcoded key, wildcard tool grants, untyped tool calls, web text straight into the prompt, no receipt, no stop, no tests, no way home. <!-- build-order:allow — this line describes the anti-patterns, it doesn't commit them -->

<!-- The comment above is build-order's own escape hatch, used here on itself: a reviewed false positive on a line that talks about the patterns instead of implementing them. -->

```
$ build-order audit examples/leaky-agent
0 held · 0 attested · 3 gap · 6 unknown of 9 gates — 3 gap(s) block a clean build
```

Gate 2 flags the key, gate 3 the wildcard, gate 8 the absent tests; the other six are UNKNOWN because the controls are simply not there to find. Nothing is HELD, and the run exits non-zero. Full card: [`examples/leaky-agent/SCORECARD.md`](examples/leaky-agent/SCORECARD.md).

## Hybrid: fill the gaps with receipts

Static detection can't see everything — an identity boundary or a tested rollback often lives in infra, not the tree. Attest those in a JSON file, each with a receipt the reader can open:

```json
{
  "gates": {
    "operator": { "attested": true, "note": "runs under its own service account", "receipt": "docs/identity.md" },
    "way-home": { "attested": false, "note": "no rollback yet" }
  }
}
```

```
build-order audit ./my-agent --attest attestation.json
```

`attested: true` with a receipt → **ATTESTED**. Without a receipt → stays **UNKNOWN**. `attested: false` → an honest **GAP**.

## For an agent, over MCP

[`mcp/build-order-mcp.mjs`](mcp/build-order-mcp.mjs) exposes one typed tool, `build_order_audit`, so an agent connected to it can scan its **own** working directory before acting. A GAP comes back as an error, so the agent shouldn't proceed blind. Drop the `registerTool` block into any MCP server (it's written to fold into the StoneyTECH public MCP).

## Limitations — read this before you trust a green card

The static detectors are **heuristics**: they find signals, not guarantees. HELD means *the evidence is in the tree*, never *this is correct*.

They also over-match on **repos that describe these patterns** rather than implement them — a rule list, a spec, or this repo. build-order's own source names every keyword it hunts for, so scanning itself is a weak signal; that's why the self-audit excludes its rule definitions (`--ignore gates.mjs`) and why the honest proofs here are the **20-test suite** and the **leaky-agent capture**, not a self-issued green card. When a detector fires on a reviewed false positive, silence it on that line with a `build-order:allow` comment — the same "gate the never-state, but allow the vetted exception" idea the tool audits for.

The secret detector on gate 2 requires the **value** to look like a secret, not just the label — a mature codebase is full of names ending in `Key` or `Secret` that hold references (`${VAR}`), hostnames, paths, or resource names. It reads a value as a name, not a credential, when no run of characters in it is long enough to carry a secret's entropy. The deliberate trade: a hyphenated passphrase under a `*_KEY`/`*_TOKEN`/`*_SECRET` label reads as a resource name and goes quiet. Under a `password` label it still flags, because nobody stores the *name* of a password.

This is an assurance *aid*, not a certification. It tells you where to look. It does not tell you that you are safe.

## Dogfood

`.github/workflows/self-audit.yml` runs the tool inside its own CI: the unit suite, an assertion that `leaky-agent` is still caught (if it ever passes, a detector regressed), and a self-audit that emits a receipt. The auditor rides the rails it lays.

## License

MIT.
