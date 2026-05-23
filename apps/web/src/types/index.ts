// ─── API Types ──────────────────────────────────────────────────────────────

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
}

// ─── Session Types ─────────────────────────────────────────────────────────

export interface Session {
  id: string;
  createdAt: string;
  updatedAt: string;
  captureFiles: CaptureFile[];
  policy?: ParsedPolicy;
  findings: ComplianceFinding[];
  llmConfig: LLMConfig;
}

export interface CaptureFile {
  id: string;
  name: string;
  filePath: string;
  sizeBytes: number;
  parsed: boolean;
  summary?: CaptureSummary;
}

export interface CaptureSummary {
  packetCount: number;
  durationSeconds: number;
  protocolBreakdown: Record<string, number>;
  tcpStreamCount: number;
  startTime: string;
  endTime: string;
}

// ─── Policy Types ──────────────────────────────────────────────────────────

export interface ParsedPolicy {
  policyName: string;
  version?: string;
  sourceFormat: 'pdf' | 'docx' | 'json' | 'yaml' | 'text';
  rawText?: string;
  rules: PolicyRule[];
}

export interface PolicyRule {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  standard?: string;
}

// ─── Compliance Types ──────────────────────────────────────────────────────

export interface ComplianceFinding {
  id: string;
  ruleId: string;
  ruleName: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  description: string;
  evidencePacketNumbers: number[];
  timestamp: string;
  dismissed: boolean;
  standard?: string;
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
  };
}

// ─── LLM Config Types ──────────────────────────────────────────────────────

export type LLMProviderType = 'ollama' | 'deepseek' | 'openrouter' | 'openrouter2' | 'openai' | 'kimi' | 'nvidia';

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
  agentProviders?: {
    policy?: LLMProviderType;
    network?: LLMProviderType;
    judge?: LLMProviderType;
  };
}

// ─── Chat Types ────────────────────────────────────────────────────────────

export interface ChatMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

export interface SseChunk {
  type: 'chunk' | 'done' | 'error';
  content?: string;
  error?: string;
}

// ─── App State Types ──────────────────────────────────────────────────────

export type AppStep = 'upload' | 'configure' | 'analyze' | 'results';
