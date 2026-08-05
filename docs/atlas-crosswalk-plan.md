# MITRE ATLAS crosswalk — design and backlog

STATUS: PLAN ONLY. Nothing built. Grounded against ATLAS **v5.6.0**, release
`v2026.06` (published 2026-06-30), pulled from `mitre-atlas/atlas-data`.

---

## Why ATLAS, and where it does not belong

ATLAS is an adversary-behaviour knowledge base for AI systems — the ATT&CK
shape applied to machine learning and, increasingly, to agents. Sixteen
tactics, 170 techniques, 35 mitigations.

**It does not belong on a SAST/SCA gate.** A static scanner finds weakness
classes in source and known advisories in dependencies; CWE and the OWASP Top
10 are the correct taxonomies for that. ATLAS describes what an adversary does
to a running AI system — prompt injection, RAG poisoning, jailbreaks. No file
scanner detects `LLM Jailbreak`. Mapping ATLAS onto dependency findings would
be taxonomy theatre.

**It belongs here**, on the nine Build Order gates, alongside the OWASP Agentic
Top 10. The gates are build-time controls over an agent system, which is the
thing ATLAS describes attacks against.

---

## The load-bearing design decision

ATLAS ships mitigations, and **every one of the 35 carries a `techniques`
array** — 246 mitigation-to-technique edges in total. That means the crosswalk
does not have to invent the hard half of the mapping.

```
gate  →  ATLAS mitigation  →  techniques      (ATLAS supplies this edge)
```

A gate implements a control. ATLAS mitigations *are* controls. Joining on the
control is honest, and the technique coverage falls out of MITRE's own data
rather than our judgment.

That only works where ATLAS has a mitigation. It frequently does not.

### The coverage gap, measured

| | YAML dist | STIX dist |
|---|---|---|
| techniques total | 170 | 170 |
| mitigation-to-technique edges | 246 | **244** |
| techniques with at least one mitigation | 75 | 74 |
| **techniques with no mitigation at all** | **95** | **96** |

The two distributions of the same release disagree. Verified 2026-08-05: the
STIX bundle is missing both `mitigates` relationships for `AML.T0052.001`
(Deepfake-Assisted Phishing) — `AML.M0018` and `AML.M0034`. The technique and
both mitigations are present in STIX; only the relationships are absent, and
nothing is missing in the other direction.

This repository reads **STIX**, because it has no dependencies and the YAML
would need a parser. The delta is pinned in `test/atlas.test.mjs` rather than
left in a comment, so a silent upstream correction fails a test instead of
quietly moving the coverage numbers.

Roughly 30 of the unmitigated techniques are agent or LLM relevant.

The unmitigated set includes the entire agent-tool supply-chain cluster:

- `AML.T0104` Publish Poisoned AI Agent Tool
- `AML.T0110` AI Agent Tool Poisoning
- `AML.T0011.002` Poisoned AI Agent Tool
- `AML.T0099` AI Agent Tool Data Poisoning
- `AML.T0109` AI Supply Chain Rug Pull
- `AML.T0111` AI Supply Chain Reputation Inflation
- `AML.T0084.001` Tool Definitions
- `AML.T0002.002` AI Agent Configuration

**ATLAS names these attacks and ships no controls for them.** That is where a
build-order gate has something to say, and it is the reason this crosswalk is
worth publishing rather than being a lookup table anyone could generate.

### Two mapping classes, and they must be labelled differently

This repo already draws one honesty line — *static where detectable, attested
where not*. The ATLAS crosswalk needs the same line in a second place:

| class | meaning | authority |
|---|---|---|
| `mitigation-backed` | the gate implements an ATLAS mitigation; technique coverage comes from ATLAS's own edges | MITRE |
| `asserted` | no ATLAS mitigation exists; the gate is claimed to raise cost anyway | **ours**, with written rationale |

An `asserted` edge without a rationale is the same defect as a suppression
without a reason. It must not be possible to file one.

---

## Schema

`crosswalk.v1.json` already anticipates this. It carries a `standards` array
(currently OWASP Agentic 2026, NIST AI RMF, ISO/IEC 42001) and every risk names
its `standard`. Gates already declare `closes` and `supports`.

Additions:

```jsonc
// standards[]
{
  "id": "std:mitre-atlas",
  "name": "MITRE ATLAS",
  "version": "5.6.0",
  "release": "v2026.06",
  "url": "https://atlas.mitre.org/",
  "canonical": "https://github.com/mitre-atlas/atlas-data"
}
```

```jsonc
// new top-level: atlas
{
  "atlas": {
    "tactics":     [ { "id": "AML.TA0001", "name": "AI Attack Staging" } ],
    "techniques":  [ { "id": "AML.T0110", "name": "AI Agent Tool Poisoning",
                       "tactic": "AML.TA0003", "mitigations": [] } ],
    "mitigations": [ { "id": "AML.M0032", "name": "Segmentation of AI Agent Components",
                       "techniques": ["AML.T0098"] } ]
  }
}
```

```jsonc
// gates[] gains one field
{
  "id": "gate:1",
  "atlas": [
    { "mitigation": "AML.M0032", "relation": "implements", "class": "mitigation-backed" },
    { "technique": "AML.T0110",  "relation": "raises-cost", "class": "asserted",
      "rationale": "Admission control over tool packages means a poisoned tool
                    must pass a signed-provenance check before it is callable.
                    ATLAS publishes no mitigation for this technique." }
  ]
}
```

Version is pinned because ATLAS moves. A crosswalk that does not name its
release is stale the moment MITRE ships.

---

## Acceptance criteria

Written before implementation, per the delivery rule for verifiers and mapping
tables.

**Grounding**
- AC1 — The ATLAS block is generated from `atlas-data` at a pinned release, not
  hand-typed. Regenerating from the same release produces a byte-identical block.
- AC2 — Every `AML.T*`, `AML.M*`, and `AML.TA*` id referenced anywhere in the
  crosswalk exists in the pinned ATLAS data. An unknown id fails validation.
- AC3 — The recorded `version` and `release` match the source archive actually used.

**Mapping integrity**
- AC4 — Every gate ATLAS edge declares a `class` of `mitigation-backed` or
  `asserted`. A missing or unknown class fails validation.
- AC5 — A `mitigation-backed` edge names a mitigation that exists, and its
  technique coverage is *derived* from ATLAS's `techniques` array rather than
  restated in the file. Restating it fails validation.
- AC6 — An `asserted` edge names a technique and carries a `rationale` long
  enough to be a rationale.
- AC7 — An `asserted` edge whose technique **does** have an ATLAS mitigation
  fails validation, with a message naming the mitigation. If MITRE published a
  control, use it rather than asserting.
- AC8 — Duplicate edges for the same gate and target are rejected.

**Honesty of the report**
- AC9 — Coverage output distinguishes mitigation-backed from asserted counts.
  A single blended number is not an acceptable summary.
- AC10 — Techniques with no gate edge are reported as **open**, not omitted.
  Silence must not read as coverage.
- AC11 — The report states total technique count and how many are addressed, so
  a reader can see that most of ATLAS is out of scope for a build-time audit.
- AC12 — Output names the ATLAS release it was computed against.

**Drift**
- AC13 — Running against a newer ATLAS release reports techniques that are new,
  removed, or renamed since the pinned release.
- AC14 — A technique that gains an ATLAS mitigation upstream, and which the
  crosswalk currently covers with an `asserted` edge, is reported so the edge
  can be upgraded to `mitigation-backed`.

**Scope**
- AC15 — Nothing in this crosswalk changes the OWASP Agentic mapping or gate
  verdicts. ATLAS is an additional lens, not a re-scoring.

---

## Non-goals

- **Not a detection claim.** ATLAS describes adversary behaviour at runtime. A
  build-time audit cannot detect `LLM Jailbreak`; it can only report whether a
  control that raises its cost is present. The output must not imply otherwise.
- **Not full coverage.** Most of ATLAS concerns training-time and model-theft
  attacks that nine build gates have no opinion about. Reporting those as open
  is the correct behaviour, not a defect to fix.
- **Not a replacement for the OWASP mapping.** Different granularity, different
  purpose: OWASP frames risk closure, ATLAS frames adversary cost.

---

## Sequence

1. Vendor the pinned ATLAS release and generate the `atlas` block. Verify AC1–AC3.
2. Add schema validation for the edge classes. Verify AC4–AC8 with fixtures,
   including the AC7 case that must fail.
3. Map the nine gates. Expect most gates to touch few techniques; say so.
4. Add coverage reporting. Verify AC9–AC12.
5. Add drift reporting against a newer release. Verify AC13–AC14.
6. Write the crosswalk page in `CROSSWALK.md` beside the OWASP one.

Steps 1 and 2 carry the value. A mapping without the class distinction is worse
than no mapping, because it launders our assertions as MITRE's.
