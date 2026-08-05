#!/usr/bin/env node
// build-order-mcp — expose the nine-gate audit as one MCP tool, so an agent
// connected to it can scan its OWN working directory before it acts.
//
// This is the piece that plugs into the StoneyTECH public MCP. It declares a
// typed input schema (gate 4, dogfooded) and performs no writes — it only reads
// the target path and returns a scorecard.
//
//   npm i @modelcontextprotocol/sdk zod
//   node mcp/build-order-mcp.mjs           # stdio server
//
// To fold into an existing server (e.g. stoneytech-site-mcp), copy the
// registerTool block below next to its other server.registerTool(...) calls.
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { audit } from '../src/audit.mjs';
import { renderMarkdown, renderLine } from '../src/render.mjs';
import { atlasCoverage, renderCoverageMarkdown } from '../src/atlas-report.mjs';

export function registerBuildOrder(server) {
  server.registerTool(
    'build_order_audit',
    {
      title: 'Build Order audit',
      description:
        'Audit an agent build/codebase against the nine-gate Build Order (identity, scope, evidence, tools, receipts, never-states, fixtures, way-home). Read-only. Returns a scorecard: held / attested / gap / unknown per gate. Point it at your own working directory before granting the agent authority.',
      inputSchema: {
        path: z.string().describe('Absolute or relative path to the repo/build to audit'),
        attestPath: z.string().optional().describe('Optional attestation JSON: receipts for gates that cannot be statically proven'),
        ignore: z.array(z.string()).optional().describe('Path substrings to exclude (rule lists, generated files) so prose about a gate is not mistaken for the gate'),
      },
    },
    async ({ path, attestPath = null, ignore = [] }) => {
      const sc = audit(path, { attestPath, ignore });
      return {
        content: [{ type: 'text', text: renderMarkdown(sc) }],
        structuredContent: sc,
        isError: !sc.clean, // a GAP surfaces as an error so the agent must not proceed blind
        _meta: { summary: renderLine(sc) },
      };
    },
  );
  server.registerTool(
    'build_order_atlas_coverage',
    {
      title: 'Build Order ATLAS coverage',
      description:
        'Report how the nine Build Order gates map to MITRE ATLAS. Two edge classes are counted separately and never summed: mitigation-backed edges implement a control ATLAS publishes and carry MITRE authority, asserted edges cover techniques ATLAS names but publishes no control for and carry only this project\'s authority, each with a written rationale. Techniques no gate addresses are reported as open rather than omitted, because silence would read as coverage. Read-only, no arguments, answers from the pinned release recorded in the crosswalk.',
      inputSchema: {
        outputFormat: z.enum(['markdown', 'json']).optional().describe('Defaults to markdown'),
      },
    },
    async ({ outputFormat = 'markdown' }) => {
      const rep = atlasCoverage();
      if (!rep) {
        return {
          content: [{ type: 'text', text: 'No ATLAS block in this crosswalk.' }],
          isError: true,
        };
      }
      return {
        content: [
          {
            type: 'text',
            text: outputFormat === 'json' ? JSON.stringify(rep, null, 2) : renderCoverageMarkdown(),
          },
        ],
        structuredContent: rep,
        // Coverage is never a failure. Open techniques are the expected state,
        // not a gap for an agent to treat as blocking.
        _meta: {
          summary: `ATLAS ${rep.release}: ${rep.mitigationBacked} mitigation-backed, ${rep.asserted} asserted, ${rep.open.length} open`,
        },
      };
    },
  );

  return server;
}

// Standalone entrypoint.
if (import.meta.url === `file://${process.argv[1]}`) {
  const server = new McpServer({ name: 'build-order', version: '0.1.0' });
  registerBuildOrder(server);
  await server.connect(new StdioServerTransport());
}
