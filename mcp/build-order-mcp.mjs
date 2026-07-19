#!/usr/bin/env node
// build-order-mcp — expose the eight-gate audit as one MCP tool, so an agent
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

export function registerBuildOrder(server) {
  server.registerTool(
    'build_order_audit',
    {
      title: 'Build Order audit',
      description:
        'Audit an agent build/codebase against the eight-gate Build Order (identity, scope, evidence, tools, receipts, never-states, fixtures, way-home). Read-only. Returns a scorecard: held / attested / gap / unknown per gate. Point it at your own working directory before granting the agent authority.',
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
  return server;
}

// Standalone entrypoint.
if (import.meta.url === `file://${process.argv[1]}`) {
  const server = new McpServer({ name: 'build-order', version: '0.1.0' });
  registerBuildOrder(server);
  await server.connect(new StdioServerTransport());
}
