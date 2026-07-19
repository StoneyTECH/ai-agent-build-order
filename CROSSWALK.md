# The Build Order Crosswalk

**A principal architect's reference architecture for agent assurance.** This is not a scanner and not a standard. It is the sequencing layer *between* them: the eight-gate Build Order laid in dependency order, and for each gate, the OWASP risk it closes, the determinism rung it should live on, and the mature tool that enforces it. Detection belongs to the scanners below; **judgment — order, placement, and build-vs-buy — is what an architect adds.**

Every row is constrained to a primary source. Where a secondary source and the primary disagreed (they did — see the note at the end), the primary won.

## The ground

- **The standard:** [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) (ASI01–ASI10), peer-reviewed, published 2025-12-09. Canonical enumeration: [OWASP GitHub](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications).
- **The governance:** [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework); ISO/IEC 42001.
- **The mature tools** (adopt these; do not reinvent):
  - [Snyk agent-scan](https://github.com/snyk/agent-scan) — MCP discovery; tool poisoning, tool shadowing, toxic flows.
  - [agent-audit](https://github.com/HeadyZhang/agent-audit) — 72 rules mapped to all ten ASI, AST tool-boundary taint tracking, MIT.
  - AgentAuditKit — 225 rules, SARIF for GitHub Security, evidence mapped to 13 compliance frameworks.
  - [mcp-audit](https://github.com/apisec-inc/mcp-audit) — MCP config, cross-server attack paths, AI-BOM.

## The crosswalk

Determinism rung is from [The Determinism Ladder](https://stoneytech.net/determinism-ladder): where a control should *live* so it holds by construction, not by hope.

| # | Gate | Determinism rung | OWASP risk it closes | Enforcing tool | Build / buy |
|---|------|------------------|----------------------|----------------|-------------|
| 1 | Name the operator | Identity / policy, in code | **ASI03** Identity & Privilege; supports ASI09, ASI10 | Cloud IAM, workload identity, OWASP NHI Top 10 | **Adopt** — identity is solved; carry no static keys |
| 2 | Draw the scope, deny by default | Gate / policy-as-code | **ASI02** Tool Misuse; **ASI03** | Policy-as-code (OPA); Snyk agent-scan, mcp-audit flag wildcard grants | **Adopt** engine, **author** the policy |
| 3 | Classify the evidence | Retrieval + code validation | **ASI06** Memory & Context Poisoning; **ASI01** Goal Hijack via injected context | agent-audit / Snyk injection detection; guardrails frameworks at runtime | **Buy** detection, **build** the provenance rule |
| 4 | Type the tools | Typed contract, in code | **ASI02** Tool Misuse; **ASI05** Code Execution; **ASI07** inter-agent | agent-audit tool-boundary taint tracking; typed MCP schemas | **Build** the contracts, **buy** the taint scanner |
| 5 | Define done, keep the receipt | Code + eval | **ASI10** Rogue Agents; **ASI08** Cascading; **ASI09** Trust | Observability / audit-log platforms; AI-BOM (mcp-audit) | **Adopt** logging, **define** the receipt schema |
| 6 | Gate the never-states | Gate — hard stop in code | **ASI05** Unexpected Code Execution; **ASI02**; **ASI08** | Sandboxing (microVMs, gVisor); guardrails; agent-audit flags `eval()`/`shell=True` | **Adopt** sandbox, **author** the never-states |
| 7 | Turn failures into fixtures | Eval / CI | **ASI08** Cascading; process control across all | LLM red-team / eval frameworks (DeepTeam maps to OWASP Agentic); CI | **Adopt** the harness, **build** the corpus |
| 8 | Build the way home | Gate + human escalation | **ASI08** Cascading Failures; **ASI10** Rogue; **ASI09** oversight | Circuit breakers, orchestration rollback, HITL platforms | **Build** the recovery path, **adopt** the primitives |

## Where the architecture under-covers the standard

The crosswalk earns its keep here: pointed at the standard, the eight gates leave three risks thin. A principal architect names the gap rather than hiding it.

- **ASI04 — Agentic Supply-Chain Compromise: not a gate.** The Build Order's prose says "approve the model and dependencies," but there is no distinct gate for vetting model provenance, dependency integrity, or dataset trust. This is the exact class that took down Hugging Face (a malicious dataset). **Fix:** add a supply-chain gate, or fold SBOM/AI-BOM (CycloneDX, mcp-audit) and dependency scanning (Snyk) into gates 1 and 3.
- **ASI07 — Insecure Inter-Agent Communication: partial.** Gate 4 types the tools, but multi-agent message trust, replay, and impersonation between agents are under-served. Thin for any multi-agent system.
- **ASI09 — Human-Agent Trust Exploitation: partial.** This is a UX and design risk (humans over-trusting agent output), only glanced by gate 5 (receipts) and gate 8 (escalation). It needs a presentation-layer control the build gates don't reach.

## What this is, and what it is not

Crosswalks and posture-scoring for OWASP Agentic already exist (for example, the GenAI-Security-Crosswalk project). The format is not novel, and this document does not pretend it is. Two things here are the architect's contribution and are not in a risk list or a scanner:

1. **Sequence.** The gates are in *laying order* — identity before scope before typed tools before receipts before gates before fixtures before recovery — because each depends on the one before it. A risk list is unordered; a construction order is not.
2. **Placement.** Each control is pinned to a determinism rung, upstream of runtime. "This belongs in a typed tool contract, not a prompt warning" is a call no scanner makes for you.

For **detection**, run the tools above. For **conformance**, read the OWASP standard. This is the map that tells you the order to adopt them in and where each control has to live.

## Provenance note

The authoritative ASI01–ASI10 enumeration here is taken from the OWASP primary source. A widely-cited secondary blog listed ASI05–ASI08 as four different categories; it was wrong. Grounding a reference architecture on a secondary paraphrase would have mis-mapped half the coverage. Pull the primary. Always.
