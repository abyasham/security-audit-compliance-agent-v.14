"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ContextAssembler = void 0;
/**
 * ContextAssembler — builds the prompt for the LLM.
 *
 * Ported from NetTrace Agentix's contextAssembler.ts, adapted for SACA:
 * - Policy-violating packets get HIGHEST priority in context
 * - Anomalous packets get second priority
 * - Policy text is injected alongside packet data
 * - Context is limited to uploaded artifacts (policy + capture)
 */
class ContextAssembler {
    // Conservative chars-per-token estimate for mixed content
    static CHARS_PER_TOKEN = 3;
    /**
     * Build the complete system prompt for compliance auditing.
     */
    async assembleSystemPrompt(session) {
        const sections = [
            this.getBaseSystemPrompt(),
            this.getAgentPrompt(session),
            this.getPolicyContext(session),
            this.getCaptureSummary(session),
        ];
        return sections.filter(Boolean).join('\n\n');
    }
    /**
     * Build the user message with packet data context.
     */
    async assembleUserMessage(session, userQuery) {
        const parts = [userQuery];
        // Add packet summary context
        if (session.captureFiles.length > 0) {
            const summary = session.captureFiles.map(c => `- ${c.name}: ${c.summary?.totalPackets || '?'} packets, ${c.summary?.tcpStreamCount || '?'} TCP streams`).join('\n');
            parts.push(`\n\n**Loaded Captures:**\n${summary}`);
        }
        // Add policy summary
        if (session.policy) {
            const ruleCount = session.policy.rules?.length || 0;
            parts.push(`\n\n**Security Policy:** ${session.policy.policyName} (${ruleCount} rules)`);
            if (session.policy.rawText) {
                // Include truncated policy text for LLM context
                const maxPolicyChars = 15000;
                const policyText = session.policy.rawText.length > maxPolicyChars
                    ? session.policy.rawText.substring(0, maxPolicyChars) + '\n\n...[policy text truncated]...'
                    : session.policy.rawText;
                parts.push(`\n\n**Policy Document Content:**\n\`\`\`\n${policyText}\n\`\`\``);
            }
        }
        return parts.join('\n');
    }
    /**
     * Estimate token count for budget management.
     */
    countTokens(text) {
        return Math.ceil(text.length / ContextAssembler.CHARS_PER_TOKEN);
    }
    /**
     * Check if content fits within budget.
     */
    fitsInBudget(text, budget) {
        return this.countTokens(text) <= budget;
    }
    // ─── Private Helpers ────────────────────────────────────────────────────
    getBaseSystemPrompt() {
        return `You are SACA (Security Audit Compliance Agent), an AI security auditor.

Your role is to analyze network packet captures and cross-reference them against security policy documents to find compliance violations.

## Core Responsibilities

1. **Analyze network traffic** using the available tools (getPacketRange, applyFilter, getConversations, getExpertInfo, followStream, runTshark)
2. **Query the traffic graph** for topology-aware analysis (queryGraph, getGraphStats, findPaths)
3. **Understand the security policy** provided in context
4. **Identify compliance violations** by comparing traffic against policy rules
5. **Cite specific evidence** — always reference packet numbers, protocols, IPs, and ports
6. **Generate an audit report** when asked

## How to Use Tools

### Packet-Level Tools (raw tshark)
- Use getPacketRange to load packets for detailed inspection
- Use applyFilter to isolate specific traffic types (e.g., HTTP, TLS, DNS)
- Use getConversations to understand connections
- Use getExpertInfo to find Wireshark-detected issues

### Graph Tools (LightRAG — network topology)
- Use getGraphStats first to understand the network topology (top talkers, protocol breakdown)
- Use queryGraph to find connections matching patterns (e.g., external IPs talking to internal ports)
- Use findPaths to trace multi-hop communication paths
- Graph tools are FAST and work well for large captures where packet-level tools would be slow

### General Rules
- NEVER make up packet data — always use tools to fetch real data
- When you find a violation, check it against the policy rules using your understanding
- For large captures (>10K packets), prefer graph tools for initial topology analysis, then use packet tools for detailed evidence
- IMPORTANT: If a tool returns empty results, that means NO MATCHES WERE FOUND — the tool worked correctly. Do NOT claim the tool failed. Try a different filter or approach instead.
- If no policy is uploaded, analyze the capture for general security issues (plaintext protocols, deprecated TLS, suspicious ports, etc.) and tell the user which policy areas these would violate.

## Analysis Workflow (CRITICAL — Follow This)

When asked to find compliance violations, follow this EXACT workflow:

**Phase 1 — Topology (2-3 graph queries MAX):**
1. getGraphStats → understand the network
2. queryGraph for one or two specific patterns (e.g., external to internal, or port 80)
3. STOP topology analysis — you now have enough context

**Phase 2 — Evidence (3-5 packet-level queries):**
4. applyFilter for specific protocols of interest (http, tls, ftp, dns)
5. getPacketRange for the first 50-100 packets to sample traffic
6. getExpertInfo for errors/warnings
7. If you found suspicious traffic, followStream or getConversations

**Phase 3 — Synthesis (STOP QUERYING — WRITE FINDINGS):**
8. After at most 8 total tool calls, STOP querying and write your findings
9. For each violation found, cite: packet numbers, src/dst IPs, protocol, policy rule violated
10. If you found NO violations after reasonable exploration, report that clearly
11. NEVER query more than 10 times total — the user wants findings, not endless exploration

## Evidence Requirements

For EVERY violation you report, you MUST include:
- The specific packet number(s)
- The source and destination IPs
- The protocol and relevant details
- Which policy rule it violates
- Why this is a compliance issue`;
    }
    getAgentPrompt(session) {
        if (session.activeAgent?.systemPrompt) {
            return `## Agent Instructions\n\n${session.activeAgent.systemPrompt}`;
        }
        return '';
    }
    getPolicyContext(session) {
        if (!session.policy) {
            return '## Security Policy\n\nNo security policy has been uploaded. Ask the user to upload one.';
        }
        const rules = session.policy.rules || [];
        let context = `## Security Policy: ${session.policy.policyName}\n`;
        if (session.policy.framework) {
            context += `\nFramework: ${session.policy.framework}`;
        }
        if (session.policy.version) {
            context += `\nVersion: ${session.policy.version}`;
        }
        if (rules.length > 0) {
            context += `\n\n### Policy Rules (${rules.length} total)\n\n`;
            for (const rule of rules) {
                context += `**${rule.id}**: ${rule.name} (${rule.severity.toUpperCase()})\n`;
                context += `- ${rule.description}\n`;
                if (rule.standard)
                    context += `- Standard: ${rule.standard}\n`;
                context += `- Category: ${rule.category}\n`;
                const conditions = rule.conditions || [];
                if (conditions.length > 0) {
                    context += `- Conditions: ${conditions.map((c) => `${c.field} ${c.operator} ${c.value}`).join(', ')}\n`;
                }
                context += '\n';
            }
        }
        return context;
    }
    getCaptureSummary(session) {
        if (session.captureFiles.length === 0) {
            return '## Network Capture\n\nNo capture loaded.';
        }
        const parts = session.captureFiles.map(c => {
            let s = `### ${c.name}\n`;
            if (c.summary) {
                s += `- Total packets: ${c.summary.totalPackets.toLocaleString()}\n`;
                s += `- TCP streams: ${c.summary.tcpStreamCount}\n`;
                s += `- Duration: ${c.summary.durationSeconds.toFixed(1)}s\n`;
                s += `- Time range: ${c.summary.startTime} → ${c.summary.endTime}\n`;
                if (c.summary.protocolBreakdown && Object.keys(c.summary.protocolBreakdown).length > 0) {
                    s += `- Protocols: ${Object.entries(c.summary.protocolBreakdown)
                        .sort((a, b) => b[1] - a[1])
                        .slice(0, 10)
                        .map(([proto, count]) => `${proto}(${count})`)
                        .join(', ')}\n`;
                }
            }
            return s;
        });
        return `## Network Capture Summary\n\n${parts.join('\n')}`;
    }
}
exports.ContextAssembler = ContextAssembler;
//# sourceMappingURL=contextAssembler.js.map