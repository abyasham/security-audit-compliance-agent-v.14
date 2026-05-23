"""Pydantic models for SACA v14 Python Core — mirrors backend/src/types/index.ts."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ─── Capture & Packet Types ────────────────────────────────────────────

class ExpertInfoSeverity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    NOTE = "note"
    CHAT = "chat"


class ExpertInfoEntry(BaseModel):
    severity: ExpertInfoSeverity
    group: str
    message: str
    packet_number: int = Field(alias="packetNumber")
    protocol: str


class ExpertInfoSummary(BaseModel):
    errors: int = 0
    warnings: int = 0
    notes: int = 0
    chats: int = 0
    details: list[ExpertInfoEntry] = Field(default_factory=list)


class CaptureSummary(BaseModel):
    total_packets: int = Field(alias="totalPackets")
    duration_seconds: float = Field(alias="durationSeconds")
    protocol_breakdown: dict[str, int] = Field(alias="protocolBreakdown")
    tcp_stream_count: int = Field(alias="tcpStreamCount")
    udp_stream_count: int = Field(alias="udpStreamCount")
    start_time: str = Field(alias="startTime")
    end_time: str = Field(alias="endTime")
    expert_info: ExpertInfoSummary | None = Field(default=None, alias="expertInfo")


class CaptureFile(BaseModel):
    id: str
    name: str
    file_path: str = Field(alias="filePath")
    size_bytes: int = Field(alias="sizeBytes")
    mime_type: str = Field(alias="mimeType")
    parsed: bool = False
    summary: CaptureSummary | None = None


# ─── Stream / Conversation Types ───────────────────────────────────────

class StreamAnomalyType(str, Enum):
    RETRANSMISSION = "retransmission"
    RST = "rst"
    ZERO_WINDOW = "zero-window"
    TLS_ALERT = "tls-alert"
    HTTP_ERROR = "http-error"
    TIMEOUT = "timeout"
    DUPLICATE_ACK = "duplicate-ack"
    OUT_OF_ORDER = "out-of-order"
    MALFORMED = "malformed"
    FRAGMENT = "fragment"
    CHECKSUM_ERROR = "checksum-error"
    SUSPICIOUS_FLAGS = "suspicious-flags"
    ICMP_ERROR = "icmp-error"


class StreamAnomaly(BaseModel):
    type: StreamAnomalyType
    count: int
    description: str
    packet_numbers: list[int] = Field(alias="packetNumbers")


class TcpStream(BaseModel):
    index: int
    source: str
    destination: str
    packet_count: int = Field(alias="packetCount")
    total_bytes: int = Field(alias="totalBytes")
    duration_seconds: float = Field(alias="durationSeconds")
    app_protocol: str | None = Field(default=None, alias="appProtocol")
    anomalies: list[StreamAnomaly] = Field(default_factory=list)
    anomaly_score: float = Field(default=0.0, alias="anomalyScore")
    capture_file_id: str = Field(alias="captureFileId")


# ─── Policy Types ──────────────────────────────────────────────────────

class PolicyCategory(str, Enum):
    ENCRYPTION = "encryption"
    NETWORK_SEGMENTATION = "network-segmentation"
    ACCESS_CONTROL = "access-control"
    PROTOCOL_COMPLIANCE = "protocol-compliance"
    AUTHENTICATION = "authentication"
    LOGGING = "logging"
    DATA_EXFILTRATION = "data-exfiltration"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ComparisonOp(str, Enum):
    EQUALS = "equals"
    NOT_EQUALS = "notEquals"
    GREATER_THAN = "greaterThan"
    LESS_THAN = "lessThan"
    CONTAINS = "contains"
    NOT_CONTAINS = "notContains"
    IN = "in"
    NOT_IN = "notIn"
    IN_ZONE = "inZone"
    MATCHES = "matches"


class RuleCondition(BaseModel):
    field: str
    operator: ComparisonOp
    value: Any


class PolicyRule(BaseModel):
    id: str
    name: str
    description: str
    category: PolicyCategory
    severity: Severity
    standard: str | None = None
    conditions: list[RuleCondition] = Field(default_factory=list)


class ParsedPolicy(BaseModel):
    policy_name: str = Field(alias="policyName")
    version: str | None = None
    effective_date: str | None = Field(default=None, alias="effectiveDate")
    framework: str | None = None
    source_format: str = Field(alias="sourceFormat")
    raw_text: str | None = Field(default=None, alias="rawText")
    rules: list[PolicyRule] = Field(default_factory=list)
    network_zones: dict[str, list[str]] | None = Field(default=None, alias="networkZones")
    authorized_servers: dict[str, list[str]] | None = Field(default=None, alias="authorizedServers")


# ─── Compliance / Finding Types ────────────────────────────────────────

class FindingStatus(str, Enum):
    VIOLATED = "violated"
    COMPLIANT = "compliant"
    SUSPICIOUS = "suspicious"


class ComplianceEvidence(BaseModel):
    stream_id: int | None = Field(default=None, alias="streamId")
    packet_range: str | None = Field(default=None, alias="packetRange")
    src_ip: str | None = Field(default=None, alias="srcIp")
    dst_ip: str | None = Field(default=None, alias="dstIp")
    dst_port: int | None = Field(default=None, alias="dstPort")
    protocol: str | None = None
    details: str


class ComplianceFinding(BaseModel):
    id: str
    rule_id: str = Field(alias="ruleId")
    rule_name: str = Field(alias="ruleName")
    rule_description: str = Field(alias="ruleDescription")
    category: PolicyCategory
    severity: Severity
    standard: str | None = None
    policy_context: str = Field(alias="policyContext")
    evidence_packet_numbers: list[int] = Field(alias="evidencePacketNumbers")
    description: str
    timestamp: str
    dismissed: bool = False
    user_note: str | None = Field(default=None, alias="userNote")
    confidence: float | None = None
    status: FindingStatus | None = None
    evidence: ComplianceEvidence | None = None
    reasoning: str | None = None


class ComplianceSummary(BaseModel):
    total_rules: int = Field(alias="totalRules")
    passed_rules: int = Field(alias="passedRules")
    failed_rules: int = Field(alias="failedRules")
    findings: list[ComplianceFinding] = Field(default_factory=list)
    pass_rate: float = Field(alias="passRate")
    average_confidence: float | None = Field(default=None, alias="averageConfidence")
    status_counts: dict | None = Field(default=None, alias="statusCounts")


# ─── LLM Provider Types ────────────────────────────────────────────────

class LLMProviderType(str, Enum):
    OLLAMA = "ollama"
    DEEPSEEK = "deepseek"
    OPENROUTER = "openrouter"
    OPENROUTER2 = "openrouter2"
    OPENAI = "openai"
    KIMI = "kimi"
    NVIDIA = "nvidia"


class LLMProviderConfig(BaseModel):
    type: LLMProviderType
    base_url: str | None = Field(default=None, alias="baseUrl")
    api_key: str | None = Field(default=None, alias="apiKey")
    model: str
    is_active: bool = Field(default=True, alias="isActive")


class LLMConfig(BaseModel):
    primary: LLMProviderConfig
    fallback: LLMProviderConfig | None = None
    secondary: LLMProviderConfig | None = None
    agent_providers: dict | None = Field(default=None, alias="agentProviders")
    token_budget: dict = Field(alias="tokenBudget")


# ─── Analysis Types ────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    session_id: str = Field(alias="sessionId")


class AgentMetadata(BaseModel):
    policy_rules_extracted: int = Field(alias="policyRulesExtracted")
    traffic_conversations_analyzed: int = Field(alias="trafficConversationsAnalyzed")
    traffic_anomalies_detected: int = Field(alias="trafficAnomaliesDetected")
    processing_time_ms: float = Field(alias="processingTimeMs")
    providers_used: dict | None = Field(default=None, alias="providersUsed")


class AnalyzeResponse(BaseModel):
    findings: list[ComplianceFinding] = Field(default_factory=list)
    summary: dict
    agent_metadata: AgentMetadata = Field(alias="agentMetadata")


# ─── NetworkAgent Types ────────────────────────────────────────────────

class NetworkAgentOutput(BaseModel):
    """Output from NetworkAgent pcap analysis."""
    conversations: list[TcpStream] = Field(default_factory=list)
    anomalies: list[StreamAnomaly] = Field(default_factory=list)
    protocol_insights: list[str] = Field(default_factory=list, alias="protocolInsights")
    syn_scan_indicators: list[str] = Field(default_factory=list, alias="synScanIndicators")
    brute_force_indicators: list[str] = Field(default_factory=list, alias="bruteForceIndicators")
    summary: CaptureSummary | None = None


# ─── PolicyAgent Types ─────────────────────────────────────────────────

class PolicyAgentOutput(BaseModel):
    """Output from PolicyAgent policy parsing."""
    rules: list[PolicyRule] = Field(default_factory=list)
    detection_logic: list[str] = Field(default_factory=list, alias="detectionLogic")
    evidence_required: list[str] = Field(default_factory=list, alias="evidenceRequired")
    policy: ParsedPolicy | None = None


# ─── RAGAS Eval Types ──────────────────────────────────────────────────

class RagasEvalRequest(BaseModel):
    session_id: str = Field(alias="sessionId")


class PerFindingScore(BaseModel):
    finding_id: str = Field(alias="findingId")
    rule_name: str = Field(alias="ruleName")
    faithfulness: float
    answer_relevancy: float = Field(alias="answerRelevancy")


class RagasEvalResult(BaseModel):
    session_id: str | None = Field(default=None, alias="sessionId")
    timestamp: str
    avg_faithfulness: float = Field(alias="avgFaithfulness")
    avg_answer_relevancy: float = Field(alias="avgAnswerRelevancy")
    per_finding_scores: list[PerFindingScore] = Field(default_factory=list, alias="perFindingScores")
    provider_used: str | None = Field(default=None, alias="providerUsed")
    heuristic_fallback: bool = Field(default=False, alias="heuristicFallback")
    error: str | None = None
