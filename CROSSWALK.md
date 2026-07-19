# The Build Order Crosswalk

**A principal architect's reference architecture for agent assurance.** This is not a scanner and not a standard. It is the sequencing layer *between* them: the nine-gate Build Order laid in dependency order, and for each gate, the OWASP risk it closes, the determinism rung it should live on, and the mature tool that enforces it. Detection belongs to the scanners below; **judgment — order, placement, and build-vs-buy — is what an architect adds.**

Every row is constrained to a primary source. Where a secondary source and the primary disagreed (they did — see the note at the end), the primary won.

> **Why nine and not eight.** The first cut of this crosswalk had eight gates and exposed its own hole: OWASP **ASI04, Agentic Supply-Chain Compromise**, had no gate — even though a malicious dataset (a supply-chain attack) is the incident that opens the essay. Using the standard to stress-test the architecture is the point of a crosswalk, so the architecture grew a gate. That is the method working, in the open.

## The ground

- **The standard:** [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) (ASI01–ASI10), peer-reviewed, published 2025-12-09. Canonical enumeration: [OWASP GitHub](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications).
- **The governance:** [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework); ISO/IEC 42001.
- **The mature tools** (adopt these; do not reinvent):
  - [Snyk agent-scan](https://github.com/snyk/agent-scan) — MCP discovery; tool poisoning, tool shadowing, toxic flows.
  - [agent-audit](https://github.com/HeadyZhang/agent-audit) — 72 rules mapped to all ten ASI, AST tool-boundary taint tracking, MIT.
  - AgentAuditKit — 225 rules, SARIF for GitHub Security, evidence mapped to 13 compliance frameworks.
  - [mcp-audit](https://github.com/apisec-inc/mcp-audit) — MCP config, cross-server attack paths, AI-BOM.

## The authoritative OWASP Agentic Top 10 (2026)

ASI01 Agent Goal Hijacking · ASI02 Tool Misuse & Exploitation · ASI03 Identity & Privilege Abuse · ASI04 Agentic Supply-Chain Compromise · ASI05 Unexpected Code Execution · ASI06 Memory & Context Poisoning · ASI07 Insecure Inter-Agent Communication · ASI08 Cascading Failures · ASI09 Human-Agent Trust Exploitation · ASI10 Rogue Agents.

## The crosswalk

Determinism rung is from [The Determinism Ladder](https://stoneytech.net/determinism-ladder): where a control should *live* so it holds by construction, not by hope.

| # | Gate | Determinism rung | OWASP risk it closes | Enforcing tool | Build / buy |
|---|------|------------------|----------------------|----------------|-------------|
| 1 | Vet the supply chain | Build-time admission (CI + code) | **ASI04** Supply-Chain Compromise; supports ASI06 | SBOM / AI-BOM (CycloneDX, mcp-audit), dependency scanning (Snyk), model + dataset provenance | **Adopt** SBOM + dep scanning; **author** the approval policy |
| 2 | Name the operator | Identity / policy, in code | **ASI03** Identity & Privilege; supports ASI09, ASI10 | Cloud IAM, workload identity, OWASP NHI Top 10 | **Adopt** — identity is solved; carry no static keys |
| 3 | Draw the scope, deny by default | Gate / policy-as-code | **ASI02** Tool Misuse; **ASI03** | Policy-as-code (OPA); Snyk agent-scan, mcp-audit flag wildcard grants | **Adopt** engine, **author** the policy |
| 4 | Classify the evidence | Retrieval + code validation | **ASI06** Memory & Context Poisoning; **ASI01** Goal Hijack via injected context | agent-audit / Snyk injection detection; guardrails frameworks at runtime | **Buy** detection, **build** the provenance rule |
| 5 | Type the tools | Typed contract, in code | **ASI02** Tool Misuse; **ASI05** Code Execution; **ASI07** inter-agent | agent-audit tool-boundary taint tracking; typed MCP schemas | **Build** the contracts, **buy** the taint scanner |
| 6 | Define done, keep the receipt | Code + eval | **ASI10** Rogue Agents; **ASI08** Cascading; **ASI09** Trust | Observability / audit-log platforms; AI-BOM (mcp-audit) | **Adopt** logging, **define** the receipt schema |
| 7 | Gate the never-states | Gate — hard stop in code | **ASI05** Unexpected Code Execution; **ASI02**; **ASI08** | Sandboxing (microVMs, gVisor); guardrails; agent-audit flags `eval()`/`shell=True` | **Adopt** sandbox, **author** the never-states |
| 8 | Turn failures into fixtures | Eval / CI | **ASI08** Cascading; process control across all | LLM red-team / eval frameworks (DeepTeam maps to OWASP Agentic); CI | **Adopt** the harness, **build** the corpus |
| 9 | Build the way home | Gate + human escalation | **ASI08** Cascading Failures; **ASI10** Rogue; **ASI09** oversight | Circuit breakers, orchestration rollback, HITL platforms | **Build** the recovery path, **adopt** the primitives |

## What the nine gates still under-cover

Even at nine, two risks are only half-closed. A principal architect names them rather than claiming full coverage.

- **ASI07 — Insecure Inter-Agent Communication: partial.** Gate 5 types the tools, but message trust, replay, and impersonation *between* agents are under-served. Thin for any multi-agent system; strengthen gate 5 with signed, typed inter-agent contracts before you go multi-agent.
- **ASI09 — Human-Agent Trust Exploitation: partial.** A UX and design risk (humans over-trusting agent output), only glanced by gate 6 (receipts) and gate 9 (escalation). It needs a presentation-layer control — surfaced provenance, confidence, and refusal — that build-time gates don't reach.

## What this is, and what it is not

Crosswalks and posture-scoring for OWASP Agentic already exist (for example, the GenAI-Security-Crosswalk project). The format is not novel, and this document does not pretend it is. Two things here are the architect's contribution and are not in a risk list or a scanner:

1. **Sequence.** The gates are in *laying order* — supply chain, then identity, then scope, then evidence, then typed tools, then receipts, then never-states, then fixtures, then recovery — because each depends on the one before it. A risk list is unordered; a construction order is not.
2. **Placement.** Each control is pinned to a determinism rung, upstream of runtime. "This belongs in a typed tool contract, not a prompt warning" is a call no scanner makes for you.

For **detection**, run the tools above. For **conformance**, read the OWASP standard. This is the map that tells you the order to adopt them in and where each control has to live.

## Provenance note

The authoritative ASI01–ASI10 enumeration here is taken from the OWASP primary source. A widely-cited secondary blog listed ASI05–ASI08 as four different categories; it was wrong. Grounding a reference architecture on a secondary paraphrase would have mis-mapped half the coverage. Pull the primary. Always.
