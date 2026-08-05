# Security Policy

build-order is an assurance aid for agent builds. It reads repositories and
writes verdicts, so its own boundaries matter.

## Reportable issues

Please report:

- path traversal or escape from the audited target directory
- shell injection through target paths, ignore patterns, or CLI arguments
- MCP surfaces that widen tool authority beyond the audited target
- a detector that can be silenced by attacker-controlled repository content
- credential or token exposure in receipts, attestations, or audit output

## Not in scope

- a detector heuristic disagreeing with your judgment on a specific repository
- crosswalk mapping opinions, unless the mapping misstates a cited standard
- framework version drift by itself — pinned versions are stated in the output
- false positives already documented under **Limitations** in the README

A detector that misses something is a bug worth filing as an issue. It is not a
vulnerability in this tool unless the miss is attacker-controllable.

## Reporting

Use a private GitHub security advisory for anything sensitive. Do not publish
live credentials, private repository details, or exploit instructions in a
public issue.

## Operating assumption

This repository should remain safe to publish. It contains code, rule
definitions, crosswalk data, docs, and synthetic fixtures. It should not
contain real audit output, receipts from private repositories, credentials, or
customer-shaped examples.

`examples/leaky-agent` is a deliberately vulnerable fixture. It exists to prove
the detectors still fire. Do not deploy it, and do not copy from it.
