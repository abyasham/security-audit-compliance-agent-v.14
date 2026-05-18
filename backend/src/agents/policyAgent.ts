import { LLMGateway } from '../services/llmGateway';
import { ParsedPolicy, PolicyRule, PolicyCategory, Severity, ComparisonOp, ChatMessage } from '../types';
import { PolicyKnowledgeGraph } from '../services/policyKnowledgeGraph';

/**
 * PolicyAgent — Agent 1 of the SACA Multi-Agent Architecture (Option B: Parallel + Judge)
 *
 * Role: Parse policy documents into structured, machine-readable rules with
 * unique IDs, severity, category, and detection logic.
 *
 * Input:  PDF/DOCX/TXT policy file (raw text from PolicyParser)
 * Output: JSON array of PolicyRule objects with detection_logic hints
 */
export interface AgentRule extends PolicyRule {
  detectionLogic: string;
  evidenceRequired: string[];
}

export interface PolicyAgentOutput {
  policyName: string;
  version?: string;
  framework?: string;
  rules: AgentRule[];
  rawTextLength: number;
  ruleCount: number;
  categories: string[];
  severities: Record<Severity, number>;
}

export class PolicyAgent {
  private llm: LLMGateway;


  constructor(preferredProvider?: string) {
    // Use per-agent provider if specified, otherwise fall back to global chain
    if (preferredProvider) {
      const gateway = LLMGateway.forProvider(preferredProvider as any);
      if (gateway) {
        this.llm = gateway;
        console.log(`[PolicyAgent] Using dedicated provider: ${preferredProvider}`);
      } else {
        console.warn(`[PolicyAgent] Provider ${preferredProvider} not available, falling back to global chain`);
        this.llm = new LLMGateway();
      }
    } else {
      this.llm = new LLMGateway();
    }
  }

  /**
   * Parse a policy document into structured rules using an LLM.
   *
   * @param parsedPolicy The initial ParsedPolicy (from PolicyParser) containing rawText
   * @param llmConfig Optional session-specific LLM config
   */
  async analyze(parsedPolicy: ParsedPolicy, llmConfig?: any): Promise<PolicyAgentOutput> {
    const rawText = parsedPolicy.rawText || '';

    if (!rawText.trim()) {
      // If no raw text (e.g. JSON/YAML input), return existing structured rules enriched
      const enriched = this.enrichRules(parsedPolicy.rules || []);
      return this.buildOutput(parsedPolicy, enriched);
    }

    // Use LLM to extract rules from raw policy text.
    const extractedRules = await this.extractRulesWithLLM(rawText, parsedPolicy, llmConfig);

    // Deterministic fallback for robustness when LLM extraction is empty/partial.
    const fallbackRules = extractedRules.length === 0
      ? this.extractRulesHeuristically(rawText, parsedPolicy)
      : [];

    // Merge with any existing structured rules from JSON/YAML input
    const allRules: AgentRule[] = [
      ...this.enrichRules(parsedPolicy.rules || []),
      ...extractedRules,
      ...fallbackRules,
    ];

    // Deduplicate by semantic fingerprint (ID-only dedupe can miss near-duplicates).
    const seen = new Set<string>();
    const deduped = allRules.filter(r => {
      const fp = `${r.id}::${r.name.toLowerCase()}::${(r.standard || '').toLowerCase()}::${r.description.toLowerCase().slice(0, 200)}`;
      if (seen.has(fp)) return false;
      seen.add(fp);
      return true;
    });

    return this.buildOutput(parsedPolicy, deduped);
  }

  /**
   * Call the LLM to extract structured rules from unstructured policy text.
   */
  private async extractRulesWithLLM(
    rawText: string,
    parsedPolicy: ParsedPolicy,
    llmConfig?: any
  ): Promise<AgentRule[]> {
    const extractionContext = this.buildPolicyExtractionContext(rawText, 22000);

    const systemPrompt = `You are the Policy Parser Agent for a network security compliance system.
Your job: read a security policy document and extract a machine-readable list of rules.

Output STRICT JSON. No markdown, no explanations, no prose. ONLY a JSON array.

Each rule MUST have:
- id: a short unique ID like "R001", "R002", etc.
- name: concise rule title (max 80 chars)
- description: what the rule requires
- category: one of [encryption, network-segmentation, access-control, protocol-compliance, authentication, logging, data-exfiltration]
- severity: one of [critical, high, medium, low, info]
- standard: the EXACT provision / clause / section number from the document (e.g., "ETSI EN 303 645 Provision 5.1", "ISO 27001 A.13.1", "NIST 800-53 AC-2"). If the document uses numbered provisions like "5.1", "5.2", "5.3", you MUST include them here.
- conditions: array of condition objects with { field, operator, value }
  - operator must be one of [equals, notEquals, greaterThan, lessThan, contains, notContains, in, notIn, inZone, matches]
- detectionLogic: a plain-English description of what network traffic pattern would violate this rule
- evidenceRequired: array of evidence fields needed to prove a violation (e.g., ["packet_numbers", "src_ip", "dst_ip", "protocol", "port"])

CRITICAL: For standards documents (ETSI EN 303 645, ISO 27001, NIST, etc.), every rule MUST cite the exact provision number, clause, or section from the original text. Do NOT omit this. Examples:
- "ETSI EN 303 645 Provision 5.1"
- "ETSI EN 303 645 Provision 5.2"
- "ISO 27001 Clause A.9.4.2"
- "NIST SP 800-53 Rev 5 AC-2"

Rules to extract:
- Encryption requirements (TLS versions, cipher suites, certificate validation)
- Network segmentation rules (allowed zones, forbidden cross-zone traffic)
- Access control (authentication methods, session timeouts, MFA)
- Protocol compliance (allowed ports, forbidden protocols, version requirements)
- Logging & audit requirements
- Data exfiltration prevention (egress filtering, DLP)

If the document contains no actionable network rules, return an empty array [].`;

    const userPrompt = `Extract structured compliance rules from this policy document.

Policy name: ${parsedPolicy.policyName}
Framework: ${parsedPolicy.framework || 'Unknown'}

---

${extractionContext}

---

Return ONLY a JSON array of rules. Do not wrap in markdown code fences.`;

    const messages: ChatMessage[] = [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userPrompt },
    ];

    try {
      this.llm.setSelectedProvider(llmConfig);
      const response = await this.llm.chatComplete(messages);

      const rules = this.parseRulesFromLLM(response.content);
      console.log(`[PolicyAgent] Extracted ${rules.length} rules from LLM`);
      return rules;
    } catch (err: any) {
      console.error('[PolicyAgent] LLM extraction failed:', err.message);
      // Fallback: return empty, let the pipeline continue with existing rules
      return [];
    }
  }

  /**
   * Parse the LLM response into AgentRule objects.
   */
  private parseRulesFromLLM(content: string): AgentRule[] {
    // Try to extract JSON from the response (handle code fences)
    let jsonText = content.trim();
    const fenceMatch = jsonText.match(/```(?:json)?\s*([\s\S]*?)```/);
    if (fenceMatch) jsonText = fenceMatch[1].trim();

    // If response starts with [ it's likely the raw array
    const arrayStart = jsonText.indexOf('[');
    const arrayEnd = jsonText.lastIndexOf(']');
    if (arrayStart !== -1 && arrayEnd !== -1 && arrayEnd > arrayStart) {
      jsonText = jsonText.substring(arrayStart, arrayEnd + 1);
    }

    try {
      const data = JSON.parse(jsonText);
      const rawRules = Array.isArray(data)
        ? data
        : (Array.isArray((data as any)?.rules) ? (data as any).rules : []);
      if (!Array.isArray(rawRules)) return [];

      return rawRules.map((rule: any, index: number) => this.normalizeRule(rule, index));
    } catch {
      console.error('[PolicyAgent] Failed to parse LLM JSON response');
      return [];
    }
  }

  /**
   * Normalize a raw rule object into a valid AgentRule.
   */
  private normalizeRule(raw: any, index: number): AgentRule {
    const validCategories: PolicyCategory[] = [
      'encryption', 'network-segmentation', 'access-control',
      'protocol-compliance', 'authentication', 'logging', 'data-exfiltration',
    ];
    const validSeverities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
    const validOps: ComparisonOp[] = [
      'equals', 'notEquals', 'greaterThan', 'lessThan',
      'contains', 'notContains', 'in', 'notIn', 'inZone', 'matches',
    ];

    const combinedText = `${raw.name || ''} ${raw.description || ''} ${raw.detectionLogic || raw.detection_logic || ''}`;
    const category = validCategories.includes(raw.category)
      ? raw.category
      : this.inferCategoryFromText(combinedText);
    const severity = validSeverities.includes(raw.severity)
      ? raw.severity
      : this.inferSeverityFromText(combinedText);

    const conditions = (raw.conditions || []).map((c: any) => ({
      field: String(c.field || ''),
      operator: validOps.includes(c.operator) ? c.operator : 'equals',
      value: c.value ?? '',
    }));

    const normalized: AgentRule = {
      id: raw.id || `R${String(index + 1).padStart(3, '0')}`,
      name: raw.name || `Rule ${index + 1}`,
      description: raw.description || '',
      category,
      severity,
      standard: raw.standard || raw.clause || raw.provision || raw.section,
      conditions,
      detectionLogic: raw.detectionLogic || raw.detection_logic || '',
      evidenceRequired: Array.isArray(raw.evidenceRequired)
        ? raw.evidenceRequired
        : (Array.isArray(raw.evidence_required) ? raw.evidence_required : []),
    };

    if (!normalized.detectionLogic || normalized.detectionLogic.trim().length < 10) {
      normalized.detectionLogic = this.inferDetectionLogicFromRule(normalized);
    }
    if (!normalized.evidenceRequired || normalized.evidenceRequired.length === 0) {
      normalized.evidenceRequired = this.inferEvidenceRequiredFromRule(normalized);
    }

    return normalized;
  }

  /**
   * Enrich existing structured rules with agent fields if missing.
   */
  private enrichRules(rules: PolicyRule[]): AgentRule[] {
    return rules.map((r) => {
      const enriched: AgentRule = {
        ...r,
        detectionLogic: this.inferDetectionLogicFromRule(r),
        evidenceRequired: this.inferEvidenceRequiredFromRule(r),
      };
      return enriched;
    });
  }

  private inferCategoryFromText(text: string): PolicyCategory {
    const t = text.toLowerCase();
    if (/(tls|ssl|https|encrypt|cipher|certificate|in transit|secure communication)/.test(t)) return 'encryption';
    if (/(segment|zone|subnet|east-west|north-south|dmz)/.test(t)) return 'network-segmentation';
    if (/(auth|password|mfa|credential|identity|session|login)/.test(t)) return 'authentication';
    if (/(log|audit|retention|siem|monitor)/.test(t)) return 'logging';
    if (/(exfil|egress|outbound|dlp|leak)/.test(t)) return 'data-exfiltration';
    if (/(protocol|port|http|dns|arp|icmp|ftp|telnet|ssh)/.test(t)) return 'protocol-compliance';
    return 'access-control';
  }

  private inferSeverityFromText(text: string): Severity {
    const t = text.toLowerCase();
    if (/(critical|immediately|must not|never|strictly prohibited|catastrophic)/.test(t)) return 'critical';
    if (/(high|shall|must|required|mandatory)/.test(t)) return 'high';
    if (/(should|recommended|important)/.test(t)) return 'medium';
    if (/(may|optional|advisory)/.test(t)) return 'low';
    return 'medium';
  }

  private inferDetectionLogicFromRule(rule: PolicyRule): string {
    const name = rule.name.toLowerCase();
    const desc = rule.description.toLowerCase();
    const text = `${name} ${desc}`;

    if (/(encrypt|tls|https|secure communication|in transit)/.test(text)) {
      return 'Flag plaintext protocols or weak TLS/SSL versions where secure communication is required.';
    }
    if (/(arp|dns|spoof|integrity)/.test(text)) {
      return 'Flag ARP/DNS spoofing or integrity anomalies, including conflicting ARP mappings and suspicious DNS responses.';
    }
    if (/(password|auth|mfa|login|credential)/.test(text)) {
      return 'Flag brute-force patterns, repeated login attempts, plaintext credentials, and weak authentication flows.';
    }
    if (/(segment|zone|subnet|isolat)/.test(text)) {
      return 'Flag unauthorized cross-zone traffic and unexpected access between restricted segments.';
    }
    if (/(xss|sql|injection|sanitize|input validation|upload)/.test(text)) {
      return 'Flag HTTP requests containing injection payloads, unsafe uploads, or malicious URI/query patterns.';
    }
    if (/(egress|exfil|outbound|dlp)/.test(text)) {
      return 'Flag anomalous outbound transfers, C2-like traffic patterns, and DNS tunneling indicators.';
    }
    if (/(log|audit|monitor)/.test(text)) {
      return 'Flag traffic patterns indicating missing logging, untracked admin actions, or suspicious unaudited protocols.';
    }

    return 'Flag network traffic that violates this policy clause based on protocol, flow, and payload evidence.';
  }

  private inferEvidenceRequiredFromRule(rule: PolicyRule): string[] {
    const base = ['packet_numbers', 'src_ip', 'dst_ip', 'protocol'];
    const text = `${rule.name} ${rule.description}`.toLowerCase();

    if (/(port|service|protocol|segment|zone|egress)/.test(text)) base.push('dst_port');
    if (/(tls|ssl|cipher|certificate|encrypt)/.test(text)) base.push('tls_version');
    if (/(http|xss|sql|upload|uri|payload)/.test(text)) base.push('http_uri');
    if (/(dns|arp|spoof|integrity)/.test(text)) base.push('dns_arp_fields');
    if (/(auth|password|credential|session|token|cookie)/.test(text)) base.push('auth_artifacts');

    return Array.from(new Set(base));
  }

  private buildPolicyExtractionContext(rawText: string, maxChars: number): string {
    const cleaned = rawText.replace(/\r/g, '\n');
    const lines = cleaned.split('\n').map(l => l.trim()).filter(Boolean);

    const prioritized: string[] = [];
    const seen = new Set<string>();

    // Prefer normative clauses that typically produce enforceable controls.
    const pushIf = (line: string): void => {
      const key = line.toLowerCase();
      if (seen.has(key)) return;
      seen.add(key);
      prioritized.push(line);
    };

    for (const line of lines) {
      if (/(\bshall\b|\bmust\b|\brequired\b|\bmandatory\b|\bprohibited\b|\bmust not\b|\bshould\b)/i.test(line)) {
        pushIf(line);
      }
    }

    for (const line of lines) {
      if (/(\b\d+(?:\.\d+)+\b|clause\s+\d+|section\s+\d+|control\s+[a-z0-9.-]+)/i.test(line)) {
        pushIf(line);
      }
    }

    const graph = PolicyKnowledgeGraph.fromPolicyText(cleaned);
    const policyKeywords = [
      'security', 'encryption', 'tls', 'https', 'authentication', 'password', 'credential',
      'access', 'network', 'segment', 'zone', 'protocol', 'port', 'logging', 'audit',
      'egress', 'exfiltration', 'dns', 'arp', 'integrity', 'confidentiality',
    ];
    const graphClauses = graph.retrieveClauseContext(policyKeywords, 120);

    const head = cleaned.substring(0, Math.floor(maxChars * 0.30));
    const context = [
      '--- DOCUMENT HEAD (for definitions/scope) ---',
      head,
      '',
      '--- CLAUSE GRAPH RETRIEVAL (high-signal neighborhoods) ---',
      graphClauses,
      '',
      '--- NORMATIVE PRIORITY LINES (fallback) ---',
      prioritized.join('\n'),
    ].join('\n');

    console.log(`[PolicyAgent] Policy graph context: nodes=${graph.getNodeCount()}, prioritized=${prioritized.length}`);
    return context.substring(0, maxChars);
  }

  private extractRulesHeuristically(rawText: string, parsedPolicy: ParsedPolicy): AgentRule[] {
    const lines = rawText
      .replace(/\r/g, '\n')
      .split('\n')
      .map(l => l.trim())
      .filter(l => l.length > 20);

    const candidates = lines.filter(l =>
      /(\bshall\b|\bmust\b|\brequired\b|\bmandatory\b|\bprohibited\b|\bmust not\b)/i.test(l)
    );

    const maxRules = Math.min(24, candidates.length);
    const rules: AgentRule[] = [];

    for (let i = 0; i < maxRules; i++) {
      const clauseText = candidates[i];
      const clauseMatch = clauseText.match(/(?:clause|section|provision|control)?\s*(\d+(?:\.\d+)+|[A-Z]-\d+(?:\.\d+)*)/i);
      const category = this.inferCategoryFromText(clauseText);
      const severity = this.inferSeverityFromText(clauseText);
      const id = `H${String(i + 1).padStart(3, '0')}`;
      const name = clauseText.substring(0, 80);

      const baseRule: PolicyRule = {
        id,
        name,
        description: clauseText,
        category,
        severity,
        standard: clauseMatch?.[1] ? `${parsedPolicy.framework || parsedPolicy.policyName} ${clauseMatch[1]}` : undefined,
        conditions: [],
      };

      rules.push({
        ...baseRule,
        detectionLogic: this.inferDetectionLogicFromRule(baseRule),
        evidenceRequired: this.inferEvidenceRequiredFromRule(baseRule),
      });
    }

    if (rules.length > 0) {
      console.log(`[PolicyAgent] Heuristic fallback extracted ${rules.length} clause-derived rules`);
    }

    return rules;
  }

  private buildOutput(parsedPolicy: ParsedPolicy, rules: AgentRule[]): PolicyAgentOutput {
    const severities: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const r of rules) severities[r.severity]++;

    return {
      policyName: parsedPolicy.policyName,
      version: parsedPolicy.version,
      framework: parsedPolicy.framework,
      rules,
      rawTextLength: (parsedPolicy.rawText || '').length,
      ruleCount: rules.length,
      categories: [...new Set(rules.map(r => r.category))],
      severities,
    };
  }
}
