// ─── Capture & Packet Types ───────────────────────────────────────────────

export interface CaptureFile {
  /** Unique session-local ID */
  id: string;
  /** Original uploaded filename */
  name: string;
  /** Absolute path on disk */
  filePath: string;
  /** File size in bytes */
  sizeBytes: number;
  /** MIME type */
  mimeType: string;
  /** Whether this file has been parsed by tshark */
  parsed: boolean;
  /** Parsed summary (populated after tshark analysis) */
  summary?: CaptureSummary;
}

export interface CaptureSummary {
  totalPackets: number;
  durationSeconds: number;
  protocolBreakdown: Record<string, number>;
  tcpStreamCount: number;
  udpStreamCount: number;
  startTime: string;
  endTime: string;
  expertInfo?: ExpertInfoSummary;
}

export interface ExpertInfoSummary {
  errors: number;
  warnings: number;
  notes: number;
  chats: number;
  details: ExpertInfoEntry[];
}

export interface ExpertInfoEntry {
  severity: 'error' | 'warning' | 'note' | 'chat';
  group: string;
  message: string;
  packetNumber: number;
  protocol: string;
}

// ─── Stream / Conversation Types ──────────────────────────────────────────

export interface TcpStream {
  index: number;
  source: string;
  destination: string;
  packetCount: number;
  totalBytes: number;
  durationSeconds: number;
  appProtocol?: string;
  anomalies: StreamAnomaly[];
  anomalyScore: number;
  captureFileId: string;
}

export interface StreamAnomaly {
  type: 'retransmission' | 'rst' | 'zero-window' | 'tls-alert' | 'http-error'
      | 'timeout' | 'duplicate-ack' | 'out-of-order' | 'malformed'
      | 'fragment' | 'checksum-error' | 'suspicious-flags' | 'icmp-error';
  count: number;
  description: string;
  packetNumbers: number[];
}

// ─── Policy Types ─────────────────────────────────────────────────────────

export type PolicyCategory =
  | 'encryption'
  | 'network-segmentation'
  | 'access-control'
  | 'protocol-compliance'
  | 'authentication'
  | 'logging'
  | 'data-exfiltration';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type ComparisonOp =
  | 'equals' | 'notEquals'
  | 'greaterThan' | 'lessThan'
  | 'contains' | 'notContains'
  | 'in' | 'notIn'
  | 'inZone' | 'matches';

export interface PolicyRule {
  id: string;
  name: string;
  description: string;
  category: PolicyCategory;
  severity: Severity;
  standard?: string;
  conditions: RuleCondition[];
}

export interface RuleCondition {
  field: string;
  operator: ComparisonOp;
  value: any;
}

export interface ParsedPolicy {
  policyName: string;
  version?: string;
  effectiveDate?: string;
  framework?: string;
  sourceFormat: 'pdf' | 'docx' | 'json' | 'yaml' | 'text';
  rawText?: string;
  rules: PolicyRule[];
  networkZones?: Record<string, string[]>;
  authorizedServers?: Record<string, string[]>;
}

// ─── Compliance / Finding Types ───────────────────────────────────────────

export interface ComplianceFinding {
  id: string;
  ruleId: string;
  ruleName: string;
  ruleDescription: string;
  category: PolicyCategory;
  severity: Severity;
  standard?: string;
  policyContext: string;
  evidencePacketNumbers: number[];
  description: string;
  timestamp: string;
  dismissed: boolean;
  userNote?: string;
  /** Confidence score (0.0–1.0) — added in v0.2 Multi-Agent Architecture */
  confidence?: number;
  /** Evaluation status — added in v0.2 */
  status?: 'violated' | 'compliant' | 'suspicious';
  /** Structured evidence — added in v0.2 */
  evidence?: {
    streamId?: number;
    packetRange?: string;
    srcIp?: string;
    dstIp?: string;
    dstPort?: number;
    protocol?: string;
    details: string;
  };
  /** Judge reasoning — added in v0.2 */
  reasoning?: string;
}

export interface ComplianceSummary {
  totalRules: number;
  passedRules: number;
  failedRules: number;
  findings: ComplianceFinding[];
  passRate: number;
  /** Average confidence across all findings — added in v0.2 */
  averageConfidence?: number;
  /** Counts by status — added in v0.2 */
  statusCounts?: {
    violated: number;
    compliant: number;
    suspicious: number;
  };
}

// ─── Multi-Agent Analysis Types (v0.2) ────────────────────────────────────

export interface AnalyzeRequest {
  sessionId: string;
}

export interface AnalyzeResponse {
  findings: ComplianceFinding[];
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
  agentMetadata: {
    policyRulesExtracted: number;
    trafficConversationsAnalyzed: number;
    trafficAnomaliesDetected: number;
    processingTimeMs: number;
    providersUsed?: {
      policy: string;
      network: string;
      judge: string;
    };
  };
}

// ─── LLM Provider Types ───────────────────────────────────────────────────

export type LLMProviderType = 'ollama' | 'deepseek' | 'openrouter' | 'openai';

export interface LLMProviderConfig {
  type: LLMProviderType;
  baseUrl?: string;
  apiKey?: string;
  model: string;
  isActive: boolean;
}

export interface LLMConfig {
  primary: LLMProviderConfig;
  fallback?: LLMProviderConfig;
  secondary?: LLMProviderConfig;
  /** Per-agent provider overrides. If set, the agent uses this provider instead of the global chain. */
  agentProviders?: {
    policy?: LLMProviderType;
    network?: LLMProviderType;
    judge?: LLMProviderType;
  };
  tokenBudget: {
    maxInputTokens: number;
    reserveForResponse: number;
  };
}

// ─── Tool Types ───────────────────────────────────────────────────────────

export interface ToolDefinition {
  name: string;
  description: string;
  parameters: Record<string, any>;
  handler: (args: any) => Promise<string>;
}

// ─── Agent Types ──────────────────────────────────────────────────────────

export interface AgentDefinition {
  name: string;
  displayName: string;
  description: string;
  systemPrompt: string;
  tools?: string[];
  autoFilters?: {
    displayFilter?: string;
    excludeProtocols?: string[];
  };
  followups?: Array<{ label: string; prompt: string }>;
}

// ─── Chat Types (OpenAI-compatible) ───────────────────────────────────────

export interface ChatMessage {
  role: 'user' | 'assistant' | 'system' | 'tool';
  content: string;
  tool_call_id?: string;  // Required for 'tool' role messages
  toolCalls?: ToolCall[];
  toolResults?: ToolResult[];
}

export interface ToolCall {
  id: string;
  name: string;
  arguments: Record<string, any>;
}

export interface ToolResult {
  toolCallId: string;
  name: string;
  result: string;
}

// ─── Session Types ────────────────────────────────────────────────────────

export interface Session {
  id: string;
  createdAt: string;
  updatedAt: string;
  captureFiles: CaptureFile[];
  policy?: ParsedPolicy;
  findings: ComplianceFinding[];
  chatHistory: ChatMessage[];
  llmConfig: LLMConfig;
  activeAgent?: AgentDefinition;
}

// ─── API Types ────────────────────────────────────────────────────────────

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
}
