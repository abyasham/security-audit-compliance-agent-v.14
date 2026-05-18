/**
 * ComplianceJudge Tool Loop Implementation
 * 
 * This file contains the agentic tool loop for ComplianceJudge.
 * Separated for clarity during implementation.
 * 
 * To be merged back into complianceJudge.ts
 */

import { ChatMessage, ToolCall } from '../types';
import { PolicyAgentOutput } from './policyAgent';
import { NetworkAgentOutput } from './networkAgent';

/**
 * Tool definitions for ComplianceJudge.
 * These allow the LLM to actively investigate potential violations.
 */
export function getJudgeTools() {
  return [
    {
      name: 'applyTsharkFilter',
      description: 'Apply a Wireshark display filter to find matching packets',
      inputSchema: {
        type: 'object',
        properties: {
          filter: {
            type: 'string',
            description: 'Wireshark display filter (e.g., "tcp.port==80 && http", "tls.handshake.version==0x0301")',
          },
          maxPackets: {
            type: 'number',
            description: 'Maximum packets to return (default: 50)',
          },
        },
        required: ['filter'],
      },
    },
    {
      name: 'getPacketRange',
      description: 'Fetch specific packet range by frame numbers',
      inputSchema: {
        type: 'object',
        properties: {
          startFrame: {
            type: 'number',
            description: 'First frame number (inclusive)',
          },
          endFrame: {
            type: 'number',
            description: 'Last frame number (inclusive, max 100 packets)',
          },
        },
        required: ['startFrame', 'endFrame'],
      },
    },
    {
      name: 'getStreamDetail',
      description: 'Get detailed analysis of a specific TCP stream',
      inputSchema: {
        type: 'object',
        properties: {
          streamId: {
            type: 'number',
            description: 'TCP stream index',
          },
        },
        required: ['streamId'],
      },
    },
    {
      name: 'verifyViolation',
      description: 'Mark a rule violation as verified with evidence',
      inputSchema: {
        type: 'object',
        properties: {
          ruleId: {
            type: 'string',
            description: 'Rule ID being verified',
          },
          violated: {
            type: 'boolean',
            description: 'True if violation confirmed, false if rule is compliant',
          },
          confidence: {
            type: 'number',
            description: 'Confidence score 0.0-1.0',
          },
          evidence: {
            type: 'string',
            description: 'Specific evidence from packet analysis',
          },
          packetNumbers: {
            type: 'array',
            items: { type: 'number' },
            description: 'Packet frame numbers as evidence',
          },
        },
        required: ['ruleId', 'violated', 'confidence', 'evidence'],
      },
    },
  ];
}

/**
 * LLM-based judgment with agentic tool loop.
 * 
 * The Judge reviews rule-based findings and uses tools to:
 * 1. Verify low-confidence violations
 * 2. Gather additional evidence
 * 3. Check for policy violations missed by rule-based matching
 */
export async function performLLMJudgmentWithTools(
  this: any, // ComplianceJudge instance
  policyOutput: PolicyAgentOutput,
  networkOutput: NetworkAgentOutput,
  llmConfig?: any
): Promise<any[]> {
  console.log('[ComplianceJudge] Starting LLM judgment with tool loop...');

  const systemPrompt = `You are the Compliance Judge in a security audit system.

Your job: Review policy rules against network traffic analysis and VERIFY violations using tools.

POLICY RULES:
${JSON.stringify(policyOutput.rules.slice(0, 20), null, 2)}

NETWORK ANALYSIS SUMMARY:
- Total packets: ${networkOutput.summary.totalPackets}
- Conversations: ${networkOutput.conversations.length}
- Anomalies detected: ${networkOutput.anomalies.length}
- Expert warnings: ${networkOutput.expertWarnings}, errors: ${networkOutput.expertErrors}
- HTTP requests: ${networkOutput.httpRequests}
- TLS versions: ${networkOutput.tlsVersions.join(', ')}
- Plaintext auth streams: ${networkOutput.plaintextAuthStreams}

TOP ANOMALIES:
${JSON.stringify(networkOutput.anomalies.slice(0, 10), null, 2)}

Your task:
1. For each policy rule, determine if the network traffic violates it
2. Use tools to gather evidence:
   - applyTsharkFilter: Search for specific traffic patterns
   - getPacketRange: Inspect specific packets
   - getStreamDetail: Analyze TCP streams in detail
3. Call verifyViolation for each rule with your assessment

Focus on rules related to the detected anomalies first.`;

  const userPrompt = `Review all ${policyOutput.rules.length} policy rules against the network traffic.

Use tools to verify violations. For each rule, check:
- Do the anomalies match this rule?
- Can I find evidence in the packets?
- What's my confidence level?

Start with high-priority rules (CRITICAL and HIGH severity).`;

  const messages: ChatMessage[] = [
    { role: 'system', content: systemPrompt },
    { role: 'user', content: userPrompt },
  ];

  const toolDefinitions = getJudgeTools();
  const verifiedFindings: any[] = [];
  let roundCount = 0;
  const maxRounds = 15; // Allow up to 15 tool-use rounds

  this.llm.setSelectedProvider(llmConfig);

  while (roundCount < maxRounds) {
    roundCount++;
    console.log(`[ComplianceJudge] Tool loop round ${roundCount}/${maxRounds}`);

    try {
      const response = await this.llm.chatComplete(messages, toolDefinitions);

      // Handle tool calls
      if (response.toolCalls && response.toolCalls.length > 0) {
        for (const toolCall of response.toolCalls) {
          console.log(`[ComplianceJudge] Executing tool: ${toolCall.name}`);
          
          const result = await this.executeJudgeTool(toolCall);

          // If verifyViolation, store the finding
          if (toolCall.name === 'verifyViolation') {
            verifiedFindings.push(result.finding);
          }

          // Add messages to conversation history
          messages.push({
            role: 'assistant',
            content: response.content || '',
            toolCalls: [toolCall],
          });

          messages.push({
            role: 'tool',
            content: result.result.substring(0, 2000), // Truncate for context budget
            tool_call_id: toolCall.id,
          });
        }
        continue; // Keep looping
      }

      // Natural language response — synthesis complete
      console.log(`[ComplianceJudge] Synthesis reached after ${roundCount} rounds`);
      break;
    } catch (err: any) {
      console.error(`[ComplianceJudge] Tool loop error round ${roundCount}:`, err.message);
      break;
    }
  }

  console.log(`[ComplianceJudge] Tool loop complete. Verified ${verifiedFindings.length} findings.`);
  return verifiedFindings;
}

/**
 * Execute a single tool call from the Judge LLM.
 */
export async function executeJudgeTool(this: any, toolCall: ToolCall): Promise<{ result: string; finding?: any }> {
  const args = toolCall.arguments;

  try {
    switch (toolCall.name) {
      case 'applyTsharkFilter': {
        const filter = args.filter || '';
        const maxPackets = args.maxPackets || 50;
        if (!this.captureFilePath) {
          return { result: 'Error: No capture file available' };
        }
        const packets = await this.tshark.applyFilter(this.captureFilePath, filter, maxPackets);
        const lines = packets.split('\n').filter((l: string) => l.trim());
        return { result: `Found ${lines.length} packets matching filter "${filter}":\n${packets.substring(0, 2000)}` };
      }

      case 'getPacketRange': {
        const start = args.startFrame || 1;
        const end = Math.min(args.endFrame || start + 10, start + 100);
        if (!this.captureFilePath) {
          return { result: 'Error: No capture file available' };
        }
        const packets = await this.tshark.applyFilter(
          this.captureFilePath,
          `frame.number>=${start} && frame.number<=${end}`,
          end - start + 1
        );
        return { result: `Packets ${start}-${end}:\n${packets.substring(0, 2000)}` };
      }

      case 'getStreamDetail': {
        const streamId = args.streamId;
        if (!this.captureFilePath) {
          return { result: 'Error: No capture file available' };
        }
        const stream = await this.tshark.applyFilter(
          this.captureFilePath,
          `tcp.stream==${streamId}`,
          100
        );
        return { result: `TCP stream ${streamId} detail:\n${stream.substring(0, 3000)}` };
      }

      case 'verifyViolation': {
        const finding = {
          ruleId: args.ruleId,
          violated: args.violated === true,
          confidence: typeof args.confidence === 'number' ? args.confidence : 0.5,
          evidence: args.evidence || '',
          packetNumbers: Array.isArray(args.packetNumbers) ? args.packetNumbers : [],
        };
        return {
          result: `Verified: Rule ${args.ruleId} is ${args.violated ? 'VIOLATED' : 'COMPLIANT'} (confidence: ${args.confidence})`,
          finding,
        };
      }

      default:
        return { result: `Unknown tool: ${toolCall.name}` };
    }
  } catch (err: any) {
    return { result: `Tool execution error: ${err.message}` };
  }
}
