import { LLMGateway } from '../services/llmGateway';
import { ChatMessage, ComplianceFinding, Severity, PolicyCategory, ToolCall } from '../types';
import { PolicyAgentOutput, AgentRule } from './policyAgent';
import { NetworkAgentOutput, TrafficAnomaly, TrafficConversation } from './networkAgent';
import { TsharkRunner } from '../services/tsharkRunner';

/**
 * ComplianceJudge — Agent 3 of the SACA Multi-Agent Architecture (Option B: Parallel + Judge)
 *
 * Role: Cross-reference structured policy rules against structured traffic reports
 * and produce verified violations with confidence scores (0.0–1.0).
 *
 * Input:  PolicyAgentOutput (rules) + NetworkAgentOutput (traffic report)
 * Output: Array of ComplianceFinding with confidence scores
 */

export interface JudgeFinding extends ComplianceFinding {
  confidence: number; // 0.0 – 1.0
  status: 'violated' | 'compliant' | 'suspicious';
  evidence: {
    streamId?: number;
    packetRange?: string;
    srcIp?: string;
    dstIp?: string;
    dstPort?: number;
    protocol?: string;
    details: string;
  };
  reasoning: string;
}

export interface ComplianceJudgeOutput {
  findings: JudgeFinding[];
  summary: {
    totalRules: number;
    violated: number;
    compliant: number;
    suspicious: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    averageConfidence: number;
  };
}

export class ComplianceJudge {
  private llm: LLMGateway;
  private tshark: TsharkRunner;
  private captureFilePath: string = ''; // Set during evaluate()

  constructor(preferredProvider?: string, tshark?: TsharkRunner) {
    if (preferredProvider) {
      const gateway = LLMGateway.forProvider(preferredProvider as any);
      if (gateway) {
        this.llm = gateway;
        console.log(`[ComplianceJudge] Using dedicated provider: ${preferredProvider}`);
      } else {
        console.warn(`[ComplianceJudge] Provider ${preferredProvider} not available, falling back to global chain`);
        this.llm = new LLMGateway();
      }
    } else {
      this.llm = new LLMGateway();
    }
    this.tshark = tshark || new TsharkRunner();
  }

  /**
   * Evaluate policy rules against network traffic and produce verified findings.
   *
   * @param policyOutput Output from PolicyAgent
   * @param networkOutput Output from NetworkAgent
   * @param llmConfig Optional session-specific LLM config
   */
  async evaluate(
    policyOutput: PolicyAgentOutput,
    networkOutput: NetworkAgentOutput,
    llmConfig?: any,
    captureFilePath?: string
  ): Promise<ComplianceJudgeOutput> {
    // Store capture file path for tool use
    this.captureFilePath = captureFilePath || networkOutput.fileName || '';
    console.log(`[ComplianceJudge] Evaluating with capture: ${this.captureFilePath}`);

    // Phase 1: Rule-based matching (fast, deterministic)
    const ruleBasedFindings = await this.performRuleBasedMatching(policyOutput.rules, networkOutput);

    // Phase 2: LLM-based judgment with TOOL LOOP (✅ NEW)
    const llmFindings = await this.performLLMJudgmentWithTools(policyOutput, networkOutput, llmConfig);

    // Phase 3: Merge and deduplicate
    const allFindings = this.mergeFindings(ruleBasedFindings, llmFindings);

    // Phase 4: Build summary
    const summary = this.buildSummary(allFindings, policyOutput.rules.length);

    return { findings: allFindings, summary };
  }

  // ─── Phase 1: Rule-Based Matching ─────────────────────────────────────────

  private async performRuleBasedMatching(
    rules: AgentRule[],
    network: NetworkAgentOutput
  ): Promise<JudgeFinding[]> {
    const findings: JudgeFinding[] = [];

    for (const rule of rules) {
      const matched = await this.matchRuleAgainstTraffic(rule, network);
      if (matched.length > 0) {
        for (const match of matched) {
          const flowOnly = match.evidenceType === 'flow';
          const allowFlowViolation = this.ruleAllowsFlowViolation(rule);
          const status: JudgeFinding['status'] = flowOnly && !allowFlowViolation ? 'suspicious' : 'violated';
          const adjustedConfidence = status === 'suspicious'
            ? Math.max(0.45, match.confidence - 0.2)
            : match.confidence;
          findings.push(this.createFinding(rule, match, status, adjustedConfidence));
        }
      } else {
        // Rule not violated — mark as compliant with low confidence (we didn't see it)
        findings.push(this.createFinding(rule, null, 'compliant', 0.3));
      }
    }

    // Also check anomalies that don't map to explicit rules
    for (const anomaly of network.anomalies) {
      const mappedRule = this.mapAnomalyToRule(anomaly, rules);
      const preserveStandalone = anomaly.type === 'session_hijacking' || anomaly.type === 'dns_tunneling' || anomaly.type === 'dns_tunnel';
      if (mappedRule && anomaly.payloadEvidence) {
        const existing = findings.find(f => f.ruleId === mappedRule.id && f.status === 'violated');
        if (!existing) {
          const packetRange = this.toPacketRange(anomaly.packetNumbers || []);
          const conv = anomaly.streamId !== undefined
            ? network.conversations.find(c => c.streamId === anomaly.streamId)
            : undefined;
          const match = {
            confidence: Math.min(0.98, Math.max(0.8, anomaly.confidence)),
            evidenceType: 'payload' as const,
            evidence: {
              streamId: anomaly.streamId,
              packetRange,
              srcIp: anomaly.srcIp || conv?.srcIp,
              dstIp: anomaly.dstIp || conv?.dstIp,
              dstPort: anomaly.dstPort || conv?.dstPort,
              protocol: conv?.protocol,
              details: anomaly.description,
            },
          };
          findings.push(this.createFinding(mappedRule, match, 'violated', match.confidence));
        }
      } else if (!mappedRule || preserveStandalone) {
        // Unmapped anomaly — create a generic finding
        findings.push(this.createAnomalyFinding(anomaly, network));
      }
    }

    return findings;
  }

  private async matchRuleAgainstTraffic(
    rule: AgentRule,
    network: NetworkAgentOutput
  ): Promise<Array<{ confidence: number; evidence: JudgeFinding['evidence']; evidenceType: 'payload' | 'flow' | 'protocol' }>> {
    const matches: Array<{ confidence: number; evidence: JudgeFinding['evidence']; evidenceType: 'payload' | 'flow' | 'protocol' }> = [];

    const logic = rule.detectionLogic.toLowerCase();
    const name = rule.name.toLowerCase();
    const desc = rule.description.toLowerCase();
    const clausePacketNumbers = await this.extractClauseEvidencePackets(rule, network, 40);
    const clausePacketRange = clausePacketNumbers.length > 0
      ? this.toPacketRange(clausePacketNumbers)
      : undefined;

    // Encryption rules
    if (rule.category === 'encryption' || logic.includes('tls') || logic.includes('ssl') || logic.includes('encrypt')) {
      // Check for weak TLS versions
      if ((logic.includes('1.0') || logic.includes('1.1') || name.includes('weak')) && network.tlsVersions.length > 0) {
        const weakVersions = network.tlsVersions.filter(v => v === 'TLS 1.0' || v === 'TLS 1.1');
        if (weakVersions.length > 0) {
          matches.push({
            confidence: 0.92,
            evidenceType: 'protocol',
            evidence: {
              protocol: 'tls',
              packetRange: clausePacketRange,
              details: `Weak TLS versions detected: ${weakVersions.join(', ')}`,
            },
          });
        }
      }
      // Check for plaintext HTTP when encryption is required
      if ((logic.includes('http') || name.includes('plaintext') || desc.includes('plain')) && network.httpRequests > 0) {
        const httpConvs = network.conversations.filter(c => c.protocol === 'http' || c.dstPort === 80);
        for (const conv of httpConvs.slice(0, 3)) {
          matches.push({
            confidence: 0.95,
            evidenceType: 'protocol',
            evidence: {
              streamId: conv.streamId,
              packetRange: clausePacketRange,
              srcIp: conv.srcIp,
              dstIp: conv.dstIp,
              dstPort: conv.dstPort,
              protocol: 'http',
              details: `Plaintext HTTP traffic on stream ${conv.streamId}: ${conv.srcIp} -> ${conv.dstIp}:${conv.dstPort}`,
            },
          });
        }
      }
    }

    // Protocol compliance rules
    if (rule.category === 'protocol-compliance' || logic.includes('port') || logic.includes('protocol')) {
      // Check for forbidden ports
      const forbiddenPorts = this.extractPortsFromLogic(logic);
      for (const conv of network.conversations) {
        if (forbiddenPorts.includes(conv.dstPort)) {
          matches.push({
            confidence: 0.88,
            evidenceType: 'protocol',
            evidence: {
              streamId: conv.streamId,
              packetRange: clausePacketRange,
              srcIp: conv.srcIp,
              dstIp: conv.dstIp,
              dstPort: conv.dstPort,
              protocol: conv.protocol,
              details: `Traffic to forbidden port ${conv.dstPort} on stream ${conv.streamId}`,
            },
          });
        }
      }
    }

    // Network segmentation / attack surface rules
    const isAttackSurfaceRule = logic.includes('attack surface') || logic.includes('exposed') || logic.includes('unnecessary') || logic.includes('port') || logic.includes('service') || name.includes('attack surface') || name.includes('minimize');
    if (isAttackSurfaceRule) {
      // SYN scans indicate exposed attack surfaces / open ports
      for (const scan of network.synScanIndicators.slice(0, 5)) {
        matches.push({
          confidence: Math.min(0.95, 0.7 + scan.synCount * 0.005),
          evidenceType: 'flow',
          evidence: {
            packetRange: this.toPacketRange(scan.packetNumbers),
            srcIp: scan.srcIp,
            dstIp: scan.dstIp,
            dstPort: scan.dstPort,
            protocol: 'tcp',
            details: `${scan.synCount} SYN scan packets from ${scan.srcIp} to ${scan.dstIp}:${scan.dstPort}. ${scan.retransmitCount > 3 ? 'Retransmissions suggest automated probing.' : 'Multiple source ports indicate port scanning.'}`,
          },
        });
      }
    }

    if (rule.category === 'network-segmentation' || logic.includes('zone') || logic.includes('segment')) {
      // Simple heuristic: flag traffic from external-looking IPs to internal-looking IPs
      for (const conv of network.conversations) {
        if (this.looksExternal(conv.srcIp) && this.looksInternal(conv.dstIp)) {
          matches.push({
            confidence: 0.75,
            evidenceType: 'flow',
            evidence: {
              streamId: conv.streamId,
              packetRange: clausePacketRange,
              srcIp: conv.srcIp,
              dstIp: conv.dstIp,
              dstPort: conv.dstPort,
              protocol: conv.protocol,
              details: `Cross-zone traffic: external ${conv.srcIp} -> internal ${conv.dstIp}`,
            },
          });
        }
      }
    }

    // Access control / authentication rules
    if (rule.category === 'authentication' || rule.category === 'access-control' || logic.includes('auth') || logic.includes('mfa')) {
      // Plaintext auth
      if (network.plaintextAuthStreams > 0) {
        const authConvs = network.conversations.filter(c =>
          c.protocol === 'http' || c.protocol === 'ftp' || c.protocol === 'telnet'
        );
        for (const conv of authConvs.slice(0, 3)) {
          matches.push({
            confidence: 0.82,
            evidenceType: 'protocol',
            evidence: {
              streamId: conv.streamId,
              packetRange: clausePacketRange,
              srcIp: conv.srcIp,
              dstIp: conv.dstIp,
              dstPort: conv.dstPort,
              protocol: conv.protocol,
              details: `Potential plaintext authentication on ${conv.protocol} stream ${conv.streamId}`,
            },
          });
        }
      }
    }

    // Brute force attacks map specifically to password/auth rules
    const isPasswordRule = logic.includes('password') || logic.includes('default') || name.includes('password') || name.includes('default');
    if (isPasswordRule) {
      // Sort: put SSH (port 22) last so it wins deduplication when confidence is tied at 0.95
      const sortedBf = [...network.bruteForceIndicators.slice(0, 5)].sort((a, b) => {
        if (a.dstPort === 22 && b.dstPort !== 22) return 1;
        if (b.dstPort === 22 && a.dstPort !== 22) return -1;
        return b.attemptCount - a.attemptCount;
      });
      for (const bf of sortedBf) {
        const isRelevantPort = bf.dstPort === 22 || bf.dstPort === 23 || bf.dstPort === 3389 || bf.dstPort === 9999 || bf.dstPort === 443;
        if (isRelevantPort) {
          // Boost confidence slightly for SSH to ensure it wins merge
          const confidenceBoost = bf.dstPort === 22 ? 0.01 : 0;
          const baseConfidence = Math.min(0.95, 0.75 + bf.attemptCount * 0.002);
          const finalConfidence = bf.dstPort === 22 ? Math.min(0.96, baseConfidence + 0.01) : baseConfidence;
          matches.push({
            confidence: finalConfidence,
            evidenceType: 'flow',
            evidence: {
              packetRange: this.toPacketRange(bf.packetNumbers),
              srcIp: bf.srcIp,
              dstIp: bf.dstIp,
              dstPort: bf.dstPort,
              protocol: 'tcp',
              details: `${bf.attemptCount} brute force connection attempts from ${bf.srcIp} to ${bf.dstIp}:${bf.dstPort}. ${bf.uniqueSrcPorts > 5 ? 'Multiple source ports indicate credential spraying.' : 'Repeated attempts suggest weak/default passwords.'}`,
            },
          });
        }
      }
    }

    // Data exfiltration rules
    if (rule.category === 'data-exfiltration' || logic.includes('exfil') || logic.includes('egress')) {
      // Flag large outbound transfers to external IPs
      for (const conv of network.conversations) {
        if (this.looksInternal(conv.srcIp) && this.looksExternal(conv.dstIp) && conv.totalBytes > 100000) {
          matches.push({
            confidence: 0.70,
            evidenceType: 'flow',
            evidence: {
              streamId: conv.streamId,
              packetRange: clausePacketRange,
              srcIp: conv.srcIp,
              dstIp: conv.dstIp,
              dstPort: conv.dstPort,
              protocol: conv.protocol,
              details: `Large outbound transfer: ${conv.totalBytes} bytes from internal ${conv.srcIp} to external ${conv.dstIp}`,
            },
          });
        }
      }
    }

    // If clause packets exist but match payload didn't set a range, backfill so findings can cite packets.
    if (clausePacketRange) {
      for (const m of matches) {
        if (!m.evidence.packetRange) {
          m.evidence.packetRange = clausePacketRange;
        }
      }
    }

    return matches;
  }

  private async extractClauseEvidencePackets(
    rule: AgentRule,
    network: NetworkAgentOutput,
    maxPackets: number
  ): Promise<number[]> {
    const packets = new Set<number>();
    const ruleText = this.normalizeRuleText(rule);

    // Pull packet numbers directly from matching anomalies first (high-signal evidence).
    for (const anomaly of network.anomalies) {
      const score = this.scoreRuleMatch(anomaly, rule);
      if (score >= 2) {
        for (const n of anomaly.packetNumbers || []) {
          if (Number.isFinite(n) && packets.size < maxPackets) packets.add(n);
        }
      }
      if (packets.size >= maxPackets) break;
    }

    // Add protocol-specific evidence by policy clause intent.
    for (const filter of this.getClauseEvidenceFilters(ruleText)) {
      if (packets.size >= maxPackets) break;
      const nums = await this.queryPacketNumbers(filter, 12);
      for (const n of nums) {
        if (packets.size < maxPackets) packets.add(n);
      }
    }

    return Array.from(packets).sort((a, b) => a - b);
  }

  private getClauseEvidenceFilters(ruleText: string): string[] {
    const filters: string[] = [];
    const add = (f: string): void => {
      if (!filters.includes(f)) filters.push(f);
    };

    if (this.containsAny(ruleText, ['secure communication', 'communication security', 'in transit', 'transit', 'encryption', 'encrypted', 'tls', 'https', 'confidentiality', 'integrity', 'authenticate', 'authentication of traffic'])) {
      add('tls || ssl || quic || dtls');
      add('http.request || tcp.port == 80');
      add('arp');
      add('dns.flags.response == 1');
    }

    if (this.containsAny(ruleText, ['arp', 'spoof', 'poison', 'man in the middle', 'mitm'])) {
      add('arp');
      add('arp.duplicate-address-detected || arp.duplicate-address-frame');
    }

    if (this.containsAny(ruleText, ['dns', 'spoof', 'cache poisoning', 'resolver integrity'])) {
      add('dns.flags.response == 1');
      add('dns.flags.rcode != 0');
      add('dns.qry.type == 16');
    }

    if (this.containsAny(ruleText, ['password', 'credential', 'authentication', 'login', 'default password', 'brute force', 'lockout'])) {
      add('tcp.flags.syn == 1 && tcp.flags.ack == 0');
      add('http.authorization || http.cookie || ftp.request.command == USER || ftp.request.command == PASS');
      add('ssh');
    }

    if (this.containsAny(ruleText, ['attack surface', 'recon', 'scan', 'discovery', 'exposed service', 'unused service', 'open port'])) {
      add('tcp.flags.syn == 1 && tcp.flags.ack == 0');
      add('icmp.type == 8 || arp.opcode == 1');
    }

    if (this.containsAny(ruleText, ['xss', 'sql injection', 'injection', 'input validation', 'sanitize', 'upload'])) {
      add('http.request');
    }

    if (this.containsAny(ruleText, ['data exfiltration', 'egress', 'outbound transfer', 'telemetry', 'data loss', 'dlp', 'c2', 'command and control'])) {
      add('dns.qry.type == 16 || dns.qry.name.len > 50');
      add('tcp.len > 1200');
    }

    return filters;
  }

  private async queryPacketNumbers(filter: string, maxPackets: number): Promise<number[]> {
    if (!this.captureFilePath || this.captureFilePath.length < 3) return [];
    try {
      const raw = await this.tshark.runTshark(
        this.captureFilePath,
        `-Y "${filter.replace(/"/g, '\\"')}" -T fields -e frame.number -c ${maxPackets}`
      );
      return raw
        .split('\n')
        .map(l => parseInt(l.trim(), 10))
        .filter(n => Number.isFinite(n));
    } catch {
      return [];
    }
  }

  private toPacketRange(packetNumbers: number[] | undefined): string | undefined {
    if (!packetNumbers || packetNumbers.length === 0) return undefined;
    const unique = Array.from(new Set(packetNumbers.filter(n => Number.isFinite(n)))).sort((a, b) => a - b);
    if (unique.length === 0) return undefined;

    const ranges: string[] = [];
    let start = unique[0];
    let prev = unique[0];

    for (let i = 1; i < unique.length; i++) {
      const curr = unique[i];
      if (curr === prev + 1) {
        prev = curr;
        continue;
      }
      ranges.push(start === prev ? `${start}` : `${start}-${prev}`);
      start = curr;
      prev = curr;
    }
    ranges.push(start === prev ? `${start}` : `${start}-${prev}`);

    return ranges.join(', ');
  }

  private mapAnomalyToRule(anomaly: TrafficAnomaly, rules: AgentRule[]): AgentRule | undefined {
    let bestRule: AgentRule | undefined;
    let bestScore = 0;

    for (const rule of rules) {
      const score = this.scoreRuleMatch(anomaly, rule);
      if (score > bestScore) {
        bestScore = score;
        bestRule = rule;
      }
    }

    return bestScore >= 2 ? bestRule : undefined;
  }

  private scoreRuleMatch(anomaly: TrafficAnomaly, rule: AgentRule): number {
    const ruleText = this.normalizeRuleText(rule);
    const anomalyText = `${anomaly.type} ${anomaly.description}`.toLowerCase();
    let score = 0;

    if (this.containsAny(ruleText, ['shall', 'must', 'mandate', 'required', 'requirement', 'prohibit', 'forbid', 'ensure'])) {
      score += 0.5;
    }

    if (anomaly.payloadEvidence) score += 0.5;

    const anomalyTypePhrase = anomaly.type.replace(/_/g, ' ');
    if (ruleText.includes(anomalyTypePhrase)) score += 1;

    // Common policy language: "shall ensure secure communication" should match
    // transport security failures and DNS/ARP integrity violations.
    if (
      this.containsAny(ruleText, [
        'secure communication',
        'communication security',
        'in transit',
        'transport security',
        'confidentiality',
        'integrity',
      ]) &&
      this.containsAny(anomalyText, ['tls', 'plaintext', 'http', 'arp', 'dns', 'spoof', 'hijack', 'mitm'])
    ) {
      score += 1.5;
    }

    for (const signal of this.getAnomalySignals(anomalyText)) {
      if (signal.match && this.containsAny(ruleText, signal.keywords)) {
        score += 1;
      }
    }

    const category = (rule.category || '').toLowerCase();
    if (category.includes('authentication') && this.containsAny(anomalyText, ['brute', 'credential', 'password', 'session'])) score += 1;
    if (category.includes('encryption') && this.containsAny(anomalyText, ['tls', 'plaintext', 'http', 'https'])) score += 1;
    if (category.includes('availability') && this.containsAny(anomalyText, ['dos', 'ddos', 'flood'])) score += 1;
    if (category.includes('network') && this.containsAny(anomalyText, ['dns', 'arp', 'spoof', 'hijack', 'poison', 'mitm', 'resolver'])) score += 1.5;
    if (category.includes('integrity') && this.containsAny(anomalyText, ['spoof', 'hijack', 'poison', 'tamper', 'manipulate'])) score += 1.5;

    return score;
  }

  private normalizeRuleText(rule: AgentRule): string {
    return `${rule.name} ${rule.description} ${rule.detectionLogic} ${rule.standard}`.toLowerCase();
  }

  private ruleAllowsFlowViolation(rule: AgentRule): boolean {
    const text = this.normalizeRuleText(rule);
    const category = (rule.category || '').toLowerCase();
    return this.containsAny(text, [
      'scan',
      'recon',
      'discovery',
      'syn',
      'probe',
      'flood',
      'dos',
      'ddos',
      'availability',
      'rate limit',
      'brute force',
      'credential spray',
      'attack surface',
      'exposed service',
    ]) || category.includes('availability');
  }

  private containsAny(text: string, needles: string[]): boolean {
    return needles.some(n => text.includes(n));
  }

  private getAnomalySignals(anomalyText: string): Array<{ match: boolean; keywords: string[] }> {
    return [
      {
        match: this.containsAny(anomalyText, ['arp', 'spoof', 'poison']),
        keywords: ['arp', 'spoof', 'poison', 'integrity', 'authenticate', 'authentication of traffic', 'man-in-the-middle', 'mitm', 'secure communication'],
      },
      {
        match: this.containsAny(anomalyText, ['dns', 'spoof', 'poison', 'dns_tunnel', 'dns_tunneling']),
        keywords: ['dns', 'spoof', 'poison', 'integrity', 'authenticate', 'resolver', 'name resolution', 'secure communication', 'communication integrity', 'tunnel', 'exfiltration'],
      },
      {
        match: this.containsAny(anomalyText, ['dns_hijack', 'rogue_responder', 'unauthorized_device_responder', 'answer_inconsistency']),
        keywords: ['dns', 'hijack', 'rogue', 'unauthorized', 'resolver', 'name resolution', 'integrity', 'authenticity', 'spoof', 'cache poisoning', 'secure communication'],
      },
      {
        match: this.containsAny(anomalyText, ['brute', 'credential', 'password', 'login']),
        keywords: ['password', 'default', 'credential', 'authentication', 'login', 'lockout', 'rate limit', 'access control', 'identity verification', 'failed login'],
      },
      {
        match: this.containsAny(anomalyText, ['syn_scan', 'port_scan', 'scan', 'recon', 'discovery']),
        keywords: ['scan', 'recon', 'attack surface', 'exposed', 'port', 'service', 'enumeration', 'discovery', 'minimize services', 'unnecessary services'],
      },
      {
        match: this.containsAny(anomalyText, ['fingerprint', 'os_fingerprinting', 'os detection', 'banner grabbing']),
        keywords: ['fingerprint', 'os detection', 'recon', 'enumeration', 'attack surface', 'discovery', 'minimize services', 'exposed services'],
      },
      {
        match: this.containsAny(anomalyText, ['xss', 'cross-site', '<script', 'javascript:']),
        keywords: ['xss', 'cross-site', 'script', 'input validation', 'sanitize', 'encoding', 'output encoding', 'user input', 'injection'],
      },
      {
        match: this.containsAny(anomalyText, ['sqli', 'sql injection', 'sql']),
        keywords: ['sql', 'injection', 'query', 'parameter', 'input validation', 'sanitize', 'parameterized', 'prepared statement', 'user input'],
      },
      {
        match: this.containsAny(anomalyText, ['directory_traversal', 'path traversal', '../']),
        keywords: ['directory', 'path', 'traversal', 'file access', 'input validation', 'path normalization', 'least privilege'],
      },
      {
        match: this.containsAny(anomalyText, ['upload', 'file upload', 'multipart']),
        keywords: ['upload', 'file', 'validation', 'malware', 'content type', 'file type', 'scan uploaded', 'sanitize uploads'],
      },
      {
        match: this.containsAny(anomalyText, ['dos', 'ddos', 'flood']),
        keywords: ['availability', 'resilience', 'rate limit', 'flood', 'dos', 'ddos', 'service continuity', 'outage', 'degradation'],
      },
      {
        match: this.containsAny(anomalyText, ['session', 'cookie', 'token', 'hijack', 'session_hijacking']),
        keywords: ['session', 'cookie', 'token', 'auth', 'confidentiality', 'integrity', 'session management', 'replay', 'token protection'],
      },
      {
        match: this.containsAny(anomalyText, ['exfil', 'data_exfiltration', 'c2', 'egress']),
        keywords: ['exfil', 'data loss', 'dlp', 'egress', 'telemetry', 'outbound', 'c2', 'command and control', 'data leakage', 'monitor outbound'],
      },
      {
        match: this.containsAny(anomalyText, ['tls', 'plaintext', 'http', 'unencrypted', 'ssl']),
        keywords: ['encryption', 'tls', 'https', 'secure channel', 'secure communication', 'in transit', 'transport security', 'confidentiality', 'integrity'],
      },
      {
        match: this.containsAny(anomalyText, ['mirai', 'botnet', 'malware']),
        keywords: ['malware', 'botnet', 'integrity', 'unauthorized code', 'software integrity', 'code integrity', 'unauthorized software'],
      },
    ];
  }

  private createFinding(
    rule: AgentRule,
    match: { confidence: number; evidence: JudgeFinding['evidence'] } | null,
    status: JudgeFinding['status'],
    confidence: number
  ): JudgeFinding {
    return {
      id: `F-${rule.id}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      ruleId: rule.id,
      ruleName: rule.name,
      ruleDescription: rule.description,
      category: rule.category,
      severity: rule.severity,
      standard: rule.standard,
      policyContext: rule.description,
      evidencePacketNumbers: match?.evidence?.packetRange
        ? this.parsePacketRange(match.evidence.packetRange)
        : [],
      description: match
        ? `${rule.standard ? `[${rule.standard}] ` : ''}${match.evidence.details}`
        : (status === 'compliant' ? 'No violation detected' : 'Inconclusive'),
      timestamp: new Date().toISOString(),
      dismissed: false,
      confidence,
      status,
      evidence: match?.evidence || { details: 'No specific evidence' },
      reasoning: match
        ? `${rule.standard ? `${rule.standard}: ` : ''}Matched rule "${rule.name}" against traffic with confidence ${confidence}. Detection logic: ${rule.detectionLogic}`
        : `No traffic matched rule "${rule.name}"${rule.standard ? ` (${rule.standard})` : ''}. Marked as ${status}.`,
    };
  }

  private createAnomalyFinding(anomaly: TrafficAnomaly, network: NetworkAgentOutput): JudgeFinding {
    const conv = anomaly.streamId !== undefined
      ? network.conversations.find(c => c.streamId === anomaly.streamId)
      : undefined;

    const anomalyKey = [
      anomaly.type || 'unknown',
      anomaly.srcIp || 'na',
      anomaly.dstIp || 'na',
      anomaly.dstPort ?? 'na',
    ].join(':');

    return {
      id: `F-ANOM-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      ruleId: `ANOMALY:${anomalyKey}`,
      ruleName: `Anomaly: ${anomaly.type}`,
      ruleDescription: anomaly.description,
      category: 'protocol-compliance',
      severity: anomaly.severity,
      policyContext: 'Detected by Network Agent anomaly analysis',
      evidencePacketNumbers: anomaly.packetNumbers,
      description: anomaly.description,
      timestamp: new Date().toISOString(),
      dismissed: false,
      confidence: 0.55,
      status: 'suspicious',
      evidence: {
        streamId: anomaly.streamId,
        srcIp: conv?.srcIp,
        dstIp: conv?.dstIp,
        dstPort: conv?.dstPort,
        protocol: conv?.protocol,
        details: anomaly.description,
      },
      reasoning: `Network Agent identified anomaly type "${anomaly.type}" with severity ${anomaly.severity}. This is flagged as suspicious activity until a policy clause is matched.`,
    };
  }

  // ─── Phase 2: LLM Judgment WITH TOOL LOOP ─────────────────────────────────

  /**
   * Agentic LLM judgment with tool loop (NettraceAgentix-inspired).
   */
  private async performLLMJudgmentWithTools(
    policy: PolicyAgentOutput,
    network: NetworkAgentOutput,
    llmConfig?: any
  ): Promise<JudgeFinding[]> {
    console.log('[ComplianceJudge] Starting tool loop judgment...');

    const systemPrompt = this.buildJudgeSystemPrompt(policy, network);
    const userPrompt = `Review all ${policy.rules.length} policy rules. Use tools to verify violations. Call verifyViolation for each assessment.`;

    const messages: ChatMessage[] = [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userPrompt },
    ];

    const toolDefinitions = this.getJudgeTools();
    const verifiedFindings: any[] = [];
    let roundCount = 0;
    const maxRounds = 15;

    this.llm.setSelectedProvider(llmConfig);

    while (roundCount < maxRounds) {
      roundCount++;
      try {
        const response = await this.llm.chatComplete(messages, toolDefinitions);
        if (response.toolCalls && response.toolCalls.length > 0) {
          for (const toolCall of response.toolCalls) {
            const result = await this.executeJudgeTool(toolCall);
            if (toolCall.name === 'verifyViolation' && result.finding) {
              verifiedFindings.push(result.finding);
            }
            messages.push(
              { role: 'assistant', content: response.content || '', toolCalls: [toolCall] },
              { role: 'tool', content: result.result.substring(0, 2000), tool_call_id: toolCall.id }
            );
          }
          continue;
        }
        break;
      } catch (err: any) {
        console.error(`[ComplianceJudge] Round ${roundCount} error:`, err.message);
        break;
      }
    }

    console.log(`[ComplianceJudge] Verified ${verifiedFindings.length} findings in ${roundCount} rounds`);
    return verifiedFindings.map((vf: any) => this.convertVerifiedFinding(vf, policy.rules));
  }

  /**
   * Fallback: Original LLM judgment without tools.
   */
  private async performLLMJudgment(
    policyOutput: PolicyAgentOutput,
    networkOutput: NetworkAgentOutput,
    llmConfig?: any
  ): Promise<JudgeFinding[]> {
    // Only use LLM for rules that weren't clearly matched or have ambiguous detection logic
    const ambiguousRules = policyOutput.rules.filter(r =>
      !r.detectionLogic || r.detectionLogic.length < 10
    );

    if (ambiguousRules.length === 0) return [];

    const promptData = {
      rules: ambiguousRules.map(r => ({
        id: r.id,
        name: r.name,
        description: r.description,
        category: r.category,
        severity: r.severity,
        detectionLogic: r.detectionLogic,
      })),
      traffic: {
        totalPackets: networkOutput.summary.totalPackets,
        durationSeconds: networkOutput.summary.durationSeconds,
        protocolBreakdown: networkOutput.summary.protocolBreakdown,
        tcpStreams: networkOutput.summary.tcpStreamCount,
        topConversations: networkOutput.conversations.slice(0, 10).map(c => ({
          streamId: c.streamId,
          protocol: c.protocol,
          srcIp: c.srcIp,
          dstIp: c.dstIp,
          dstPort: c.dstPort,
          packetCount: c.packetCount,
          notes: c.notes,
        })),
        anomalies: networkOutput.anomalies.slice(0, 10).map(a => ({
          type: a.type,
          description: a.description,
          severity: a.severity,
        })),
        tlsVersions: networkOutput.tlsVersions,
        httpRequests: networkOutput.httpRequests,
      },
    };

    const systemPrompt = `You are the Compliance Judge Agent for a security compliance system.
Your job: cross-reference policy rules against network traffic and produce verified violations.

Output STRICT JSON array. No markdown, no explanations. ONLY JSON.

Each finding MUST have:
- ruleId: the ID of the rule being evaluated
- status: one of [violated, compliant, suspicious]
- confidence: a number between 0.0 and 1.0 (use 0.0-0.3 for compliant, 0.7-0.95 for violated, 0.4-0.6 for suspicious)
- evidence: object with { streamId?, srcIp?, dstIp?, dstPort?, protocol?, details }
- reasoning: brief explanation of your judgment

Rules for confidence:
- 0.90-1.00: Definite violation with clear evidence
- 0.70-0.89: Likely violation with good evidence
- 0.40-0.69: Inconclusive — some indicators but not enough evidence
- 0.10-0.39: Likely compliant — no matching traffic found
- 0.00-0.09: Definitely compliant — rule explicitly satisfied

Only return findings for rules where you have enough information to make a judgment. If a rule cannot be evaluated from the given data, return status "suspicious".`;

    const userPrompt = `Evaluate these policy rules against the network traffic summary:

${JSON.stringify(promptData, null, 2)}

Return ONLY a JSON array of findings, one per rule.`;

    const messages: ChatMessage[] = [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userPrompt },
    ];

    try {
      this.llm.setSelectedProvider(llmConfig);
      const response = await this.llm.chatComplete(messages);

      const findings = this.parseLLMFindings(response.content, policyOutput.rules);
      console.log(`[ComplianceJudge] LLM produced ${findings.length} findings`);
      return findings;
    } catch (err: any) {
      console.error('[ComplianceJudge] LLM judgment failed:', err.message);
      return [];
    }
  }

  private parseLLMFindings(content: string, rules: AgentRule[]): JudgeFinding[] {
    let jsonText = content.trim();
    const fenceMatch = jsonText.match(/```(?:json)?\s*([\s\S]*?)```/);
    if (fenceMatch) jsonText = fenceMatch[1].trim();

    const arrayStart = jsonText.indexOf('[');
    const arrayEnd = jsonText.lastIndexOf(']');
    if (arrayStart !== -1 && arrayEnd !== -1 && arrayEnd > arrayStart) {
      jsonText = jsonText.substring(arrayStart, arrayEnd + 1);
    }

    try {
      const data = JSON.parse(jsonText);
      if (!Array.isArray(data)) return [];

      return data.map((f: any) => {
        const rule = rules.find(r => r.id === f.ruleId);
        const status = ['violated', 'compliant', 'suspicious'].includes(f.status) ? f.status : 'suspicious';
        const confidence = typeof f.confidence === 'number'
          ? Math.max(0, Math.min(1, f.confidence))
          : 0.5;

        return {
          id: `F-${f.ruleId || 'UNK'}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
          ruleId: f.ruleId || 'UNK',
          ruleName: rule?.name || f.ruleName || 'Unknown Rule',
          ruleDescription: rule?.description || '',
          category: rule?.category || 'protocol-compliance',
          severity: rule?.severity || 'medium',
          standard: rule?.standard,
          policyContext: rule?.description || '',
          evidencePacketNumbers: Array.isArray(f.evidence?.packetNumbers) ? f.evidence.packetNumbers : [],
          description: f.evidence?.details || f.reasoning || 'No description',
          timestamp: new Date().toISOString(),
          dismissed: false,
          confidence,
          status,
          evidence: {
            streamId: f.evidence?.streamId ?? f.evidence?.stream_id,
            srcIp: f.evidence?.srcIp ?? f.evidence?.src_ip,
            dstIp: f.evidence?.dstIp ?? f.evidence?.dst_ip,
            dstPort: f.evidence?.dstPort ?? f.evidence?.dst_port,
            protocol: f.evidence?.protocol,
            details: f.evidence?.details || '',
          },
          reasoning: f.reasoning || '',
        };
      });
    } catch {
      return [];
    }
  }

  // ─── Phase 3: Merge & Deduplicate ─────────────────────────────────────────

  private mergeFindings(ruleBased: JudgeFinding[], llmBased: JudgeFinding[]): JudgeFinding[] {
    const byRuleId = new Map<string, JudgeFinding>();

    // Prefer rule-based findings (higher confidence in deterministic matching)
    // Keep the highest-confidence finding per ruleId
    for (const f of ruleBased) {
      const existing = byRuleId.get(f.ruleId);
      if (!existing || f.confidence > existing.confidence) {
        byRuleId.set(f.ruleId, f);
      }
    }

    // LLM override: only override rule-based compliant findings if LLM confidence is significantly higher
    for (const f of llmBased) {
      const existing = byRuleId.get(f.ruleId);
      if (!existing) {
        byRuleId.set(f.ruleId, f);
      } else if (existing.status !== 'violated' && f.confidence > existing.confidence + 0.15) {
        byRuleId.set(f.ruleId, f);
      }
    }

    return Array.from(byRuleId.values());
  }

  // ─── Summary Builder ──────────────────────────────────────────────────────

  private buildSummary(findings: JudgeFinding[], totalRules: number): ComplianceJudgeOutput['summary'] {
    const violated = findings.filter(f => f.status === 'violated').length;
    const compliant = findings.filter(f => f.status === 'compliant').length;
    const suspicious = findings.filter(f => f.status === 'suspicious').length;

    const confidences = findings.map(f => f.confidence);
    const avgConfidence = confidences.length > 0
      ? Math.round((confidences.reduce((a, b) => a + b, 0) / confidences.length) * 100) / 100
      : 0;

    return {
      totalRules,
      violated,
      compliant,
      suspicious,
      criticalCount: findings.filter(f => f.severity === 'critical' && f.status === 'violated').length,
      highCount: findings.filter(f => f.severity === 'high' && f.status === 'violated').length,
      mediumCount: findings.filter(f => f.severity === 'medium' && f.status === 'violated').length,
      lowCount: findings.filter(f => f.severity === 'low' && f.status === 'violated').length,
      averageConfidence: avgConfidence,
    };
  }

  // ─── Helpers ──────────────────────────────────────────────────────────────

  private extractPortsFromLogic(logic: string): number[] {
    const ports: number[] = [];
    const matches = logic.matchAll(/port\s*(?:==?|equals)\s*(\d+)/gi);
    for (const m of matches) ports.push(parseInt(m[1]));
    return ports;
  }

  private looksExternal(ip: string): boolean {
    // Simple heuristics for external IPs
    if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.')) return false;
    if (ip === '127.0.0.1') return false;
    return true;
  }

  private looksInternal(ip: string): boolean {
    return !this.looksExternal(ip);
  }

  private parsePacketRange(range: string): number[] {
    const nums: number[] = [];
    for (const part of range.split(',')) {
      const trimmed = part.trim();
      if (trimmed.includes('-')) {
        const [start, end] = trimmed.split('-').map(s => parseInt(s.trim()));
        if (!isNaN(start) && !isNaN(end)) {
          for (let i = start; i <= end; i++) nums.push(i);
        }
      } else {
        const n = parseInt(trimmed);
        if (!isNaN(n)) nums.push(n);
      }
    }
    return nums;
  }

  // ─── NEW: Agentic Tool Loop (NettraceAgentix-Inspired) ────────────────────

  /**
   * Get tool definitions for ComplianceJudge's agentic tool loop.
   */
  private getJudgeTools(): any[] {
    return [
      {
        type: 'function',
        function: {
          name: 'applyTsharkFilter',
          description: 'Apply Wireshark filter to find packets',
          parameters: {
            type: 'object',
            properties: {
              filter: { type: 'string', description: 'Wireshark filter' },
              maxPackets: { type: 'number', description: 'Max packets (default: 50)' },
            },
            required: ['filter'],
          },
        },
      },
      {
        type: 'function',
        function: {
          name: 'getPacketRange',
          description: 'Fetch packet range',
          parameters: {
            type: 'object',
            properties: {
              startFrame: { type: 'number', description: 'First frame' },
              endFrame: { type: 'number', description: 'Last frame (max 100)' },
            },
            required: ['startFrame', 'endFrame'],
          },
        },
      },
      {
        type: 'function',
        function: {
          name: 'verifyViolation',
          description: 'Mark rule violated/compliant',
          parameters: {
            type: 'object',
            properties: {
              ruleId: { type: 'string', description: 'Rule ID' },
              violated: { type: 'boolean', description: 'True if violated' },
              confidence: { type: 'number', description: 'Confidence 0.0-1.0' },
              evidence: { type: 'string', description: 'Evidence' },
              packetNumbers: { type: 'array', items: { type: 'number' } },
              srcIp: { type: 'string' },
              dstIp: { type: 'string' },
              dstPort: { type: 'number' },
            },
            required: ['ruleId', 'violated', 'confidence', 'evidence'],
          },
        },
      },
    ];
  }

  /**
   * Execute a tool call from Judge LLM.
   */
  private async executeJudgeTool(toolCall: ToolCall): Promise<{ result: string; finding?: any }> {
    const args = toolCall.arguments;
    try {
      switch (toolCall.name) {
        case 'applyTsharkFilter': {
          if (!this.captureFilePath) return { result: 'Error: No capture file' };
          const packets = await this.tshark.applyFilter(this.captureFilePath, args.filter || '', args.maxPackets || 50);
          const lines = packets.split('\n').filter((l: string) => l.trim());
          return { result: `Found ${lines.length} packets: "${args.filter}":\n${packets.substring(0, 2000)}` };
        }
        case 'getPacketRange': {
          if (!this.captureFilePath) return { result: 'Error: No capture file' };
          const start = args.startFrame || 1;
          const end = Math.min(args.endFrame || start + 10, start + 100);
          const packets = await this.tshark.applyFilter(this.captureFilePath, `frame.number>=${start} && frame.number<=${end}`, end - start + 1);
          return { result: `Packets ${start}-${end}:\n${packets.substring(0, 2000)}` };
        }
        case 'getStreamDetail': {
          if (!this.captureFilePath) return { result: 'Error: No capture file' };
          const stream = await this.tshark.applyFilter(this.captureFilePath, `tcp.stream==${args.streamId}`, 100);
          return { result: `Stream ${args.streamId}:\n${stream.substring(0, 3000)}` };
        }
        case 'verifyViolation': {
          const finding = {
            ruleId: args.ruleId,
            violated: args.violated === true,
            confidence: typeof args.confidence === 'number' ? Math.max(0, Math.min(1, args.confidence)) : 0.5,
            evidence: args.evidence || '',
            packetNumbers: Array.isArray(args.packetNumbers) ? args.packetNumbers : [],
            srcIp: args.srcIp,
            dstIp: args.dstIp,
            dstPort: args.dstPort,
          };
          return { result: `Verified: ${args.ruleId} = ${args.violated ? 'VIOLATED' : 'COMPLIANT'} (${args.confidence})`, finding };
        }
        default:
          return { result: `Unknown tool: ${toolCall.name}` };
      }
    } catch (err: any) {
      return { result: `Tool error: ${err.message}` };
    }
  }

  /**
   * Build system prompt for Judge's tool loop.
   */
  private buildJudgeSystemPrompt(policy: PolicyAgentOutput, network: NetworkAgentOutput): string {
    return `You are the Compliance Judge. Verify policy violations using tools.

POLICY RULES (${policy.rules.length}):
${JSON.stringify(policy.rules.slice(0, 15).map(r => ({ id: r.id, name: r.name, category: r.category, severity: r.severity, standard: r.standard })), null, 2)}

NETWORK ANALYSIS:
- Packets: ${network.summary.totalPackets}, Streams: ${network.summary.tcpStreamCount}
- Anomalies: ${network.anomalies.length}, Warnings: ${network.expertWarnings}, Errors: ${network.expertErrors}
- HTTP: ${network.httpRequests}, TLS: ${network.tlsVersions.join(', ')}

TOP ANOMALIES:
${JSON.stringify(network.anomalies.slice(0, 8), null, 2)}

TOOLS:
1. applyTsharkFilter - Search traffic patterns
2. getPacketRange - Inspect packets
3. getStreamDetail - Analyze TCP stream
4. verifyViolation - Mark rule violated/compliant

For each rule, investigate and call verifyViolation. Prioritize CRITICAL/HIGH rules.`;
  }

  /**
   * Convert verified finding to JudgeFinding format.
   */
  private convertVerifiedFinding(verified: any, rules: any[]): JudgeFinding {
    const rule = rules.find(r => r.id === verified.ruleId);
    if (!rule) {
      return {
        id: `F-VER-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        ruleId: verified.ruleId,
        ruleName: `Rule ${verified.ruleId}`,
        ruleDescription: verified.evidence,
        category: 'protocol-compliance',
        severity: 'medium',
        policyContext: verified.evidence,
        evidencePacketNumbers: verified.packetNumbers || [],
        description: verified.evidence,
        timestamp: new Date().toISOString(),
        dismissed: false,
        confidence: verified.confidence,
        status: verified.violated ? 'violated' : 'compliant',
        evidence: { srcIp: verified.srcIp, dstIp: verified.dstIp, dstPort: verified.dstPort, details: verified.evidence },
        reasoning: `LLM-verified (conf: ${verified.confidence})`,
      };
    }
    return {
      id: `F-VER-${rule.id}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      ruleId: rule.id,
      ruleName: rule.name,
      ruleDescription: rule.description,
      category: rule.category,
      severity: rule.severity,
      standard: rule.standard,
      policyContext: rule.description,
      evidencePacketNumbers: verified.packetNumbers || [],
      description: `${rule.standard ? `[${rule.standard}] ` : ''}${verified.evidence}`,
      timestamp: new Date().toISOString(),
      dismissed: false,
      confidence: verified.confidence,
      status: verified.violated ? 'violated' : 'compliant',
      evidence: { srcIp: verified.srcIp, dstIp: verified.dstIp, dstPort: verified.dstPort, details: verified.evidence },
      reasoning: `${rule.standard ? `${rule.standard}: ` : ''}Tool-verified. ${verified.evidence}`,
    };
  }
}
