import { TsharkRunner } from './tsharkRunner';
import { SessionStore } from '../storage/sessionStore';
import { ToolCall, ToolResult } from '../types';

/**
 * ToolExecutor — handles LLM tool calls during analysis.
 *
 * Manages the tool loop: LLM calls tool → executor runs it → result goes back to LLM.
 * Max 25 rounds per turn to prevent infinite loops.
 */
export class ToolExecutor {
  private tshark: TsharkRunner;
  private store: SessionStore;

  private static readonly MAX_ROUNDS = 25;

  constructor(tshark: TsharkRunner) {
    this.tshark = tshark;
    this.store = SessionStore.getInstance();
  }

  /**
   * Get tool definitions in OpenAI-compatible format.
   * captureFileId is optional — defaults to the first capture in the session.
   */
  getToolDefinitions(): any[] {
    const tools = [
      {
        name: 'getPacketRange',
        description: 'Fetch packets by frame number range. Use this to page through sections of a capture. captureFileId is optional.',
        parameters: {
          type: 'object',
          properties: {
            captureFileId: { type: 'string', description: 'Optional — capture file ID. Omit to use the loaded capture.' },
            startFrame: { type: 'number', description: 'First frame number (inclusive)' },
            endFrame: { type: 'number', description: 'Last frame number (inclusive, max 500 range)' },
            filter: { type: 'string', description: 'Optional Wireshark display filter' },
          },
          required: ['startFrame', 'endFrame'],
        },
      },
      {
        name: 'applyFilter',
        description: 'Apply a Wireshark display filter and return matching packets. captureFileId is optional.',
        parameters: {
          type: 'object',
          properties: {
            captureFileId: { type: 'string', description: 'Optional — capture file ID. Omit to use the loaded capture.' },
            filter: { type: 'string', description: 'Wireshark display filter expression' },
            maxPackets: { type: 'number', description: 'Maximum packets to return (default 100)' },
          },
          required: ['filter'],
        },
      },
      {
        name: 'getConversations',
        description: 'List all TCP/UDP conversations with statistics. captureFileId is optional.',
        parameters: {
          type: 'object',
          properties: {
            captureFileId: { type: 'string', description: 'Optional — capture file ID. Omit to use the loaded capture.' },
            protocol: { type: 'string', enum: ['tcp', 'udp', 'ip'], description: 'Protocol (default tcp)' },
          },
          required: [],
        },
      },
      {
        name: 'getExpertInfo',
        description: 'Get Wireshark expert information — errors, warnings, notes. captureFileId is optional.',
        parameters: {
          type: 'object',
          properties: {
            captureFileId: { type: 'string', description: 'Optional — capture file ID. Omit to use the loaded capture.' },
            severity: { type: 'string', enum: ['error', 'warning', 'note', 'chat', 'all'], description: 'Filter by severity' },
          },
          required: [],
        },
      },
      {
        name: 'followStream',
        description: 'Reconstruct and view the application-layer payload of a TCP stream.',
        parameters: {
          type: 'object',
          properties: {
            captureFileId: { type: 'string', description: 'Optional — capture file ID. Omit to use the loaded capture.' },
            streamIndex: { type: 'number', description: 'TCP stream index to follow' },
            format: { type: 'string', enum: ['ascii', 'hex', 'raw'], description: 'Output format' },
          },
          required: ['streamIndex'],
        },
      },
      {
        name: 'runTshark',
        description: 'Run any read-only tshark command for specialized analysis. The capture file is already provided automatically — do NOT include -r or the filename in your args.',
        parameters: {
          type: 'object',
          properties: {
            captureFileId: { type: 'string', description: 'Optional — capture file ID. Omit to use the loaded capture.' },
            args: { type: 'string', description: 'tshark arguments ONLY. Do NOT include -r, -i, or any filename. Example: "-Y http -T fields -e frame.number"' },
          },
          required: ['args'],
        },
      },
      {
        name: 'queryGraph',
        description: 'Query the traffic graph using a structured pattern. Use this instead of raw tshark when you need to understand network topology, find connections, or trace paths. The graph contains IP nodes, port nodes, protocol nodes, stream nodes, and connection edges.',
        parameters: {
          type: 'object',
          properties: {
            startNodeType: { type: 'string', enum: ['ip', 'port', 'protocol', 'stream', 'host', 'packet'], description: 'Type of node to start from' },
            startNodeProperties: { type: 'object', description: 'Properties to match start node, e.g., {address: "10.0.1.5"} or {zone: "external"}' },
            edgeType: { type: 'string', enum: ['connects', 'uses_port', 'uses_protocol', 'belongs_to', 'has_packet', 'initiates'], description: 'Edge type to traverse' },
            endNodeType: { type: 'string', enum: ['ip', 'port', 'protocol', 'stream', 'host', 'packet'], description: 'Type of node to find' },
            endNodeProperties: { type: 'object', description: 'Properties to match end node, e.g., {zone: "internal"} or {number: 443}' },
            direction: { type: 'string', enum: ['out', 'in', 'both'], description: 'Edge direction (default both)' },
            limit: { type: 'number', description: 'Max results (default 20)' },
          },
          required: [],
        },
      },
      {
        name: 'getGraphStats',
        description: 'Get statistics about the traffic graph: node counts, top talkers, protocol breakdown. Use this to understand the overall network topology before diving into specifics.',
        parameters: {
          type: 'object',
          properties: {},
          required: [],
        },
      },
      {
        name: 'findPaths',
        description: 'Find communication paths between two network entities. Use this to trace how traffic flows from external IPs to internal assets, or to identify multi-hop connections.',
        parameters: {
          type: 'object',
          properties: {
            fromNodeType: { type: 'string', enum: ['ip', 'port', 'stream'], description: 'Source node type' },
            fromNodeProperties: { type: 'object', description: 'Source node match, e.g., {zone: "external"} or {address: "203.0.113.5"}' },
            toNodeType: { type: 'string', enum: ['ip', 'port', 'stream'], description: 'Target node type' },
            toNodeProperties: { type: 'object', description: 'Target node match, e.g., {zone: "internal"} or {number: 3306}' },
            maxHops: { type: 'number', description: 'Max path length (default 3)' },
          },
          required: ['fromNodeType', 'fromNodeProperties', 'toNodeType', 'toNodeProperties'],
        },
      },
      {
        name: 'getViolations',
        description: 'List all compliance violations found so far.',
        parameters: {
          type: 'object',
          properties: {},
          required: [],
        },
      },
    ];

    // Wrap in OpenAI-compatible format
    return tools.map(t => ({
      type: 'function',
      function: {
        name: t.name,
        description: t.description,
        parameters: t.parameters,
      },
    }));
  }

  /**
   * Resolve the capture file path from args or session.
   */
  private resolveCaptureFile(args: any, sessionId: string): string | undefined {
    const session = this.store.getSession(sessionId);
    if (!session || session.captureFiles.length === 0) return undefined;

    const id = args.captureFileId || args.captureFile || args.file;
    if (!id) return session.captureFiles[0]?.filePath;

    // Try matching by ID
    let cf = session.captureFiles.find(c => c.id === id);
    // Try by filename
    if (!cf) cf = session.captureFiles.find(c => c.name === id);
    // Try by path suffix
    if (!cf) cf = session.captureFiles.find(c => c.filePath.endsWith(id));
    // Fallback
    if (!cf) cf = session.captureFiles[0];

    return cf?.filePath;
  }

  /**
   * Execute a single tool call.
   */
  async executeTool(toolCall: ToolCall, sessionId: string): Promise<ToolResult> {
    const { name, arguments: args } = toolCall;
    const filePath = this.resolveCaptureFile(args, sessionId);

    // Graph tools don't need a filePath — they use the session graph
    const graphTools = ['queryGraph', 'getGraphStats', 'findPaths'];
    if (!filePath && !graphTools.includes(name)) {
      return {
        toolCallId: toolCall.id,
        name,
        result: 'Error: No capture file available in this session. Upload a pcap file first.',
      };
    }

    console.log(`[Tool] ${name} called with args:`, JSON.stringify(args));
    try {
      let result = '';

      switch (name) {
        case 'getPacketRange': {
          if (!filePath) throw new Error('No capture file');
          const start = args.startFrame || 1;
          const end = Math.min(args.endFrame || 100, start + 499);
          result = await this.tshark.getPacketRange(filePath, start, end, args.filter);
          break;
        }

        case 'applyFilter': {
          if (!filePath) throw new Error('No capture file');
          result = await this.tshark.applyFilter(filePath, args.filter, args.maxPackets || 100);
          break;
        }

        case 'getConversations': {
          if (!filePath) throw new Error('No capture file');
          result = await this.tshark.getConversations(filePath, args.protocol || 'tcp');
          break;
        }

        case 'getExpertInfo': {
          if (!filePath) throw new Error('No capture file');
          result = await this.tshark.getExpertInfo(filePath, args.severity);
          break;
        }

        case 'followStream': {
          if (!filePath) throw new Error('No capture file');
          result = await this.tshark.followStream(filePath, args.streamIndex, args.format || 'ascii');
          break;
        }

        case 'runTshark': {
          if (!filePath) throw new Error('No capture file');
          // Sanitize args: strip any -r/-i flags and filenames the LLM might have included
          let sanitizedArgs = (args.args || '')
            .replace(/\s+-r\s+\S+/gi, '')
            .replace(/\s+-i\s+\S+/gi, '')
            .replace(/\bGT_\w+\.pcap\b/gi, '')
            .replace(/\b\S+\.pcap(?:ng)?\b/gi, '')
            .trim();
          result = await this.tshark.runTshark(filePath, sanitizedArgs);
          break;
        }

        case 'getViolations': {
          const session = this.store.getSession(sessionId);
          const findings = session?.findings.filter(f => !f.dismissed) || [];
          if (findings.length === 0) {
            result = 'No compliance violations found yet. Use getPacketRange or applyFilter to inspect traffic.';
          } else {
            result = findings.map(f =>
              `[${f.severity.toUpperCase()}] ${f.ruleId}: ${f.description}\n  Evidence: packets ${f.evidencePacketNumbers.join(', ')}`
            ).join('\n\n');
          }
          break;
        }

        case 'queryGraph': {
          const graph = this.store.getGraph(sessionId);
          if (!graph) {
            result = 'No traffic graph available. The graph is built automatically when a pcap is uploaded. If missing, the capture may be too small or graph build failed.';
            break;
          }
          const q = {
            startNode: args.startNodeType ? {
              type: args.startNodeType,
              properties: args.startNodeProperties || {},
            } : undefined,
            edgeType: args.edgeType,
            endNode: args.endNodeType ? {
              type: args.endNodeType,
              properties: args.endNodeProperties || {},
            } : undefined,
            direction: args.direction || 'both',
            limit: args.limit || 20,
          };
          const qr = graph.query(q);
          result = JSON.stringify({
            nodes: qr.nodes.map(n => ({ id: n.id, type: n.type, properties: n.properties })),
            edges: qr.edges.map(e => ({ id: e.id, type: e.type, source: e.source, target: e.target, properties: e.properties })),
            count: qr.nodes.length,
          }, null, 2);
          break;
        }

        case 'getGraphStats': {
          const graph = this.store.getGraph(sessionId);
          if (!graph) {
            result = 'No traffic graph available.';
            break;
          }
          const stats = graph.getStats();
          result = JSON.stringify({
            nodeCount: stats.nodeCount,
            edgeCount: stats.edgeCount,
            nodeCountsByType: stats.nodeCountsByType,
            edgeCountsByType: stats.edgeCountsByType,
            topTalkers: stats.topTalkers.slice(0, 10),
            protocolBreakdown: stats.protocolBreakdown,
          }, null, 2);
          break;
        }

        case 'findPaths': {
          const graph = this.store.getGraph(sessionId);
          if (!graph) {
            result = 'No traffic graph available.';
            break;
          }
          const q = {
            pathFrom: {
              type: args.fromNodeType,
              properties: args.fromNodeProperties || {},
            },
            pathTo: {
              type: args.toNodeType,
              properties: args.toNodeProperties || {},
            },
            maxHops: args.maxHops || 3,
          };
          const qr = graph.query(q);
          result = JSON.stringify({
            pathCount: qr.paths.length,
            paths: qr.paths.map(path => path.map(n => ({ id: n.id, type: n.type, properties: n.properties }))),
            nodes: qr.nodes.map(n => ({ id: n.id, type: n.type, properties: n.properties })),
            edges: qr.edges.map(e => ({ id: e.id, type: e.type, source: e.source, target: e.target })),
          }, null, 2);
          break;
        }

        default:
          result = `Unknown tool: ${name}`;
      }

      const MAX_RESULT_CHARS = 50000;
      if (result.length > MAX_RESULT_CHARS) {
        result = result.substring(0, MAX_RESULT_CHARS) +
          `\n\n... (truncated from ${result.length} chars. Use a more specific filter.)`;
      }

      return { toolCallId: toolCall.id, name, result };
    } catch (err: any) {
      return {
        toolCallId: toolCall.id,
        name,
        result: `Error: ${err.message}`,
      };
    }
  }

  getMaxRounds(): number {
    return ToolExecutor.MAX_ROUNDS;
  }
}
