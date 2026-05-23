"""
ComplianceJudge — Agent 3 of the SACA Multi-Agent Architecture (port from TypeScript).

Uses LangGraph + LiteLLM to cross-reference structured policy rules against
traffic reports and produce verified compliance findings with confidence scores.

Port of backend/src/agents/complianceJudge.ts + complianceJudge-toolloop.ts
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Annotated, Any, Dict, List, Optional, Sequence, TypedDict

import pyshark
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages

logger = logging.getLogger(__name__)


# ─── Domain Types ───────────────────────────────────────────────────────────


@dataclass
class RuleMatch:
    confidence: float
    evidence_type: str  # "payload", "flow", "protocol"
    evidence: dict


@dataclass
class JudgeFinding:
    id: str
    rule_id: str
    rule_name: str
    rule_description: str
    category: str
    severity: str
    standard: str | None
    policy_context: str
    evidence_packet_numbers: list[int]
    description: str
    timestamp: str
    dismissed: bool = False
    confidence: float = 0.5
    status: str = "suspicious"  # violated | compliant | suspicious
    evidence: dict | None = None
    reasoning: str = ""


# ─── LangGraph State ────────────────────────────────────────────────────────


class JudgeState(TypedDict, total=False):
    """State that flows through the ComplianceJudge LangGraph nodes."""

    messages: Annotated[Sequence[dict], add_messages]
    policy_rules: list[dict]
    conversations: list[dict]
    anomalies: list[dict]
    syn_scans: list[dict]
    brute_force: list[dict]
    tls_versions: list[str]
    http_requests: int
    plaintext_auth_streams: int
    expert_warnings: int
    expert_errors: int
    capture_file_path: str
    llm_config: dict | None
    # Intermediate
    rule_findings: list[dict]
    anomaly_findings: list[dict]
    verified_findings: list[dict]
    tool_rounds: int
    # Output
    findings: list[dict]
    summary: dict


# ─── ComplianceJudge Class ───────────────────────────────────────────────────


class ComplianceJudge:
    """Cross-references policy rules against network traffic and produces findings."""

    VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
    VALID_CATEGORIES = {
        "encryption", "network-segmentation", "access-control",
        "protocol-compliance", "authentication", "logging", "data-exfiltration",
    }

    def __init__(self, llm_gateway=None):
        self.llm = llm_gateway
        self.capture_file_path: str = ""

    # ─── Public API ─────────────────────────────────────────────────────

    def evaluate(
        self,
        policy_rules: list[dict],
        network_output: dict,
        llm_config: dict | None = None,
        capture_file_path: str = "",
    ) -> dict:
        """
        Evaluate policy rules against network traffic.

        Args:
            policy_rules: List of rule dicts from PolicyAgent output
            network_output: Dict from NetworkAgent output with conversations, anomalies, etc.
            llm_config: Optional LLM provider config
            capture_file_path: Path to pcap for evidence extraction

        Returns: dict with 'findings' and 'summary'
        """
        self.capture_file_path = capture_file_path
        logger.info("ComplianceJudge evaluating %d rules against traffic", len(policy_rules))

        # Phase 1: Rule-based matching (deterministic)
        rule_findings = self._perform_rule_based_matching(
            policy_rules,
            network_output.get("conversations", []),
            network_output.get("anomalies", []),
            network_output.get("synScanIndicators", []),
            network_output.get("bruteForceIndicators", []),
            network_output.get("tlsVersions", []),
            network_output.get("httpRequests", 0),
            network_output.get("plaintextAuthStreams", 0),
        )

        # Phase 2: Anomaly-based findings (unmapped anomalies)
        anomaly_findings = self._create_anomaly_findings(
            network_output.get("anomalies", []),
            policy_rules,
        )

        # Phase 3: LLM-based judgment (LangGraph tool loop if llm available)
        llm_findings: list[dict] = []
        if self.llm:
            llm_findings = self._run_llm_judgment(
                policy_rules, network_output, rule_findings, llm_config
            )

        # Phase 4: Merge and deduplicate
        all_findings = self._merge_findings(rule_findings + anomaly_findings + llm_findings)

        # Phase 5: Build summary
        summary = self._build_summary(all_findings, len(policy_rules))

        return {"findings": all_findings, "summary": summary}

    # ─── Phase 1: Rule-Based Matching ───────────────────────────────────

    def _perform_rule_based_matching(
        self,
        rules: list[dict],
        conversations: list[dict],
        anomalies: list[dict],
        syn_scans: list[str],
        brute_force: list[str],
        tls_versions: list[str],
        http_requests: int,
        plaintext_auth_streams: int,
    ) -> list[dict]:
        findings: list[dict] = []

        for rule in rules:
            matches = self._match_rule_against_traffic(
                rule, conversations, anomalies, syn_scans, brute_force,
                tls_versions, http_requests, plaintext_auth_streams,
            )

            if matches:
                for match in matches:
                    flow_only = match.evidence_type == "flow"
                    allow_flow = self._rule_allows_flow_violation(rule) if isinstance(rule, dict) else False
                    status = "suspicious" if (flow_only and not allow_flow) else "violated"
                    adj_confidence = max(0.45, match.confidence - 0.2) if status == "suspicious" else match.confidence
                    findings.append(self._create_finding_dict(rule, match, status, adj_confidence))
            else:
                findings.append(self._create_finding_dict(rule, None, "compliant", 0.3))

        return findings

    def _match_rule_against_traffic(
        self,
        rule: dict,
        conversations: list[dict],
        anomalies: list[dict],
        syn_scans: list[str],
        brute_force: list[str],
        tls_versions: list[str],
        http_requests: int,
        plaintext_auth_streams: int,
    ) -> list[RuleMatch]:
        matches: list[RuleMatch] = []
        logic = (rule.get("detectionLogic", "") or "").lower()
        name = (rule.get("name", "") or "").lower()
        desc = (rule.get("description", "") or "").lower()
        category = (rule.get("category", "") or "").lower()

        # ── Encryption ──────────────────────────────────────────────
        if category == "encryption" or any(k in logic for k in ("tls", "ssl", "encrypt")):
            # Weak TLS
            weak = [v for v in tls_versions if v in ("TLS 1.0", "TLS 1.1")]
            if weak:
                matches.append(RuleMatch(
                    confidence=0.92, evidence_type="protocol",
                    evidence={"protocol": "tls", "details": f"Weak TLS: {', '.join(weak)}"},
                ))
            # Plaintext HTTP — take the single most-significant HTTP stream only
            if http_requests > 0:
                http_convs = sorted(
                    [c for c in conversations if c.get("protocol") == "http" or c.get("dstPort") == 80],
                    key=lambda c: c.get("packetCount", 0),
                    reverse=True,
                )
                if http_convs:
                    conv = http_convs[0]
                    matches.append(RuleMatch(
                        confidence=0.95, evidence_type="protocol",
                        evidence={
                            "streamId": conv.get("streamId"),
                            "srcIp": conv.get("srcIp"),
                            "dstIp": conv.get("dstIp"),
                            "dstPort": conv.get("dstPort"),
                            "protocol": "http",
                            "details": f"Plaintext HTTP: {conv.get('srcIp')} \u2192 {conv.get('dstIp')}:{conv.get('dstPort')}",
                        },
                    ))

        # ── Protocol Compliance ─────────────────────────────────────
        if category == "protocol-compliance" or "port" in logic or "protocol" in logic:
            forbidden_ports, allowed_ports = self._extract_ports_from_text(logic)
            for conv in conversations:
                dst_port = conv.get("dstPort")
                if dst_port is None:
                    continue
                # Check forbidden ports
                if forbidden_ports and dst_port in forbidden_ports:
                    matches.append(RuleMatch(
                        confidence=0.88, evidence_type="protocol",
                        evidence={
                            "streamId": conv.get("streamId"),
                            "srcIp": conv.get("srcIp"),
                            "dstIp": conv.get("dstIp"),
                            "dstPort": dst_port,
                            "protocol": conv.get("protocol"),
                            "details": f"Forbidden port {dst_port} on stream {conv.get('streamId')}",
                        },
                    ))
                # Check allowed ports (violation if NOT in allowed list)
                elif allowed_ports and dst_port not in allowed_ports:
                    matches.append(RuleMatch(
                        confidence=0.85, evidence_type="protocol",
                        evidence={
                            "streamId": conv.get("streamId"),
                            "srcIp": conv.get("srcIp"),
                            "dstIp": conv.get("dstIp"),
                            "dstPort": dst_port,
                            "protocol": conv.get("protocol"),
                            "details": f"Port {dst_port} not in allowed list {allowed_ports} on stream {conv.get('streamId')}",
                        },
                    ))

        # ── Attack Surface / SYN Scans ──────────────────────────────
        is_asr = any(k in logic or k in name for k in (
            "attack surface", "exposed", "unnecessary", "minimize"
        ))
        if is_asr and syn_scans:
            for scan in syn_scans[:5]:
                # syn_scans entries are description strings; extract src/dst if possible
                matches.append(RuleMatch(
                    confidence=0.85, evidence_type="flow",
                    evidence={"details": scan, "protocol": "tcp"},
                ))

        # ── Network Segmentation — cap at 2 to avoid noise ──────────
        if category == "network-segmentation" or "zone" in logic or "segment" in logic:
            cross_zone = [
                c for c in conversations
                if self._looks_external(c.get("srcIp", "")) and self._looks_internal(c.get("dstIp", ""))
            ]
            for conv in cross_zone[:2]:
                matches.append(RuleMatch(
                    confidence=0.75, evidence_type="flow",
                    evidence={
                        "streamId": conv.get("streamId"),
                        "srcIp": conv.get("srcIp"),
                        "dstIp": conv.get("dstIp"),
                        "dstPort": conv.get("dstPort"),
                        "protocol": conv.get("protocol"),
                        "details": f"Cross-zone traffic: external {conv.get('srcIp')} \u2192 internal {conv.get('dstIp')}",
                    },
                ))

        # ── Authentication — only if real credential streams detected ──
        if category in ("authentication", "access-control") or any(k in logic for k in ("auth", "mfa")):
            if plaintext_auth_streams > 0:
                # Pick the best single auth stream (most packets)
                auth_convs = sorted(
                    [c for c in conversations if c.get("protocol") in ("http", "ftp", "telnet")],
                    key=lambda c: c.get("packetCount", 0),
                    reverse=True,
                )
                if auth_convs:
                    conv = auth_convs[0]
                    matches.append(RuleMatch(
                        confidence=0.82, evidence_type="protocol",
                        evidence={
                            "streamId": conv.get("streamId"),
                            "srcIp": conv.get("srcIp"),
                            "dstIp": conv.get("dstIp"),
                            "dstPort": conv.get("dstPort"),
                            "protocol": conv.get("protocol"),
                            "details": f"Plaintext credential transmission on {conv.get('protocol')} stream {conv.get('streamId')}: {conv.get('srcIp')} \u2192 {conv.get('dstIp')}:{conv.get('dstPort')}",
                        },
                    ))

        # ── Password / Brute Force — structured evidence, 1 match per rule ──
        is_pw_rule = "password" in logic or "default" in logic or "password" in name or "default" in name
        if is_pw_rule and brute_force:
            # Sort: prefer SSH (port 22), then by attempt count
            sorted_bf = sorted(
                brute_force,
                key=lambda b: (
                    1 if (b.get("dstPort") == 22 if isinstance(b, dict) else 0) else 0,
                    b.get("attemptCount", 0) if isinstance(b, dict) else 0,
                ),
                reverse=True,
            )
            bf = sorted_bf[0]
            if isinstance(bf, dict):
                attempts = bf.get("attemptCount", "?")  
                src = bf.get("srcIp", "?")
                dst = bf.get("dstIp", "?")
                port = bf.get("dstPort", "?")
                bf_text = (
                    f"{attempts} brute-force attempts from {src} \u2192 {dst}:{port}. "
                    f"{'Credential spraying (multiple source ports).' if bf.get('uniqueSrcPorts', 0) > 5 else 'Repeated attempts suggest weak/default passwords.'}"
                )
                matches.append(RuleMatch(
                    confidence=min(0.96, 0.75 + (attempts if isinstance(attempts, int) else 0) * 0.002),
                    evidence_type="flow",
                    evidence={
                        "srcIp": src, "dstIp": dst, "dstPort": port,
                        "protocol": "tcp", "details": bf_text,
                    },
                ))
            else:
                matches.append(RuleMatch(
                    confidence=0.85, evidence_type="flow",
                    evidence={"details": str(bf), "protocol": "tcp"},
                ))

        # ── Data Exfiltration ───────────────────────────────────────
        if category == "data-exfiltration" or "exfil" in logic or "egress" in logic:
            for conv in conversations:
                if (
                    self._looks_internal(conv.get("srcIp", ""))
                    and self._looks_external(conv.get("dstIp", ""))
                    and conv.get("totalBytes", 0) > 100000
                ):
                    matches.append(RuleMatch(
                        confidence=0.70, evidence_type="flow",
                        evidence={
                            "streamId": conv.get("streamId"),
                            "srcIp": conv.get("srcIp"),
                            "dstIp": conv.get("dstIp"),
                            "dstPort": conv.get("dstPort"),
                            "protocol": conv.get("protocol"),
                            "details": f"Large outbound: {conv.get('totalBytes')} bytes from {conv.get('srcIp')} → {conv.get('dstIp')}",
                        },
                    ))

        return matches

    # ─── Phase 2: Anomaly Findings ──────────────────────────────────────

    # ── Anomaly type → ETSI clause category/keyword mapping ────────────
    _ANOMALY_CATEGORY_MAP: dict[str, str] = {
        # Input validation / web app attacks → 5.13
        "web_shell_execution": "input validation",
        "file_upload_exploitation": "input validation",
        "command_injection": "input validation",
        "directory_traversal": "input validation",
        "xss_attack": "input validation",
        "sqli_attack": "input validation",
        # Password / brute force → 5.1
        "ssh_brute_force": "password",
        "telnet_brute_force": "password",
        "rdp_brute_force": "password",
        "brute_force": "password",
        # Secure communication → 5.5
        "arp_spoofing": "secure communication",
        "dns_rogue_responder": "secure communication",
        "dns_hijacking": "secure communication",
        "dns_answer_inconsistency": "secure communication",
        "session_hijacking": "secure communication",
        "token_injection": "secure communication",
        # Software integrity → 5.7
        "mirai_botnet": "software integrity",
        "log4shell_exploitation": "software integrity",
        "log4shell_payload_fetch": "software integrity",
        # Attack surface → 5.6
        "syn_scan": "attack surface",
        "os_fingerprinting": "attack surface",
        # Availability / DoS → 5.9
        "udp_flood": "availability",
        "udp_burst_multi_target": "availability",
        # Data exfiltration → 5.10
        "data_exfiltration": "exfiltration",
    }

    def _create_anomaly_findings(
        self, anomalies: list[dict], rules: list[dict]
    ) -> list[dict]:
        findings: list[dict] = []
        for anom in anomalies:
            anom_type = anom.get("type", "")
            # Try to map to the most relevant rule using enhanced category hints
            mapped = self._map_anomaly_to_rule_enhanced(anom, rules)
            preserve = anom_type in ("session_hijacking", "dns_tunneling", "dns_tunnel", "token_injection")

            if mapped and anom.get("payloadEvidence"):
                existing = any(
                    f.get("ruleId") == mapped.get("id") and f.get("status") == "violated"
                    for f in findings
                )
                if not existing:
                    findings.append(self._create_anomaly_finding_dict(anom, mapped, "violated"))
            elif not mapped or preserve:
                # Standalone anomaly — create as suspicious with richer evidence
                findings.append(self._create_anomaly_finding_dict(anom, None, "suspicious"))

        return findings

    def _map_anomaly_to_rule_enhanced(self, anomaly: dict, rules: list[dict]) -> dict | None:
        """Map anomaly to the most relevant policy rule using category hints."""
        anom_type = anomaly.get("type", "")
        category_hint = self._ANOMALY_CATEGORY_MAP.get(anom_type, "")

        best_rule = None
        best_score = 0.0

        for rule in rules:
            score = self._score_rule_match(anomaly, rule)

            # Boost score strongly if the category hint matches the rule text
            if category_hint:
                rule_text = self._normalize_rule_text(rule).lower()
                if category_hint in rule_text:
                    score += 3.0

            if score > best_score:
                best_score = score
                best_rule = rule

        return best_rule if best_score >= 1.5 else None

    # ─── Phase 3: LLM Judgment (LangGraph) ─────────────────────────────

    def _run_llm_judgment(
        self,
        rules: list[dict],
        network_output: dict,
        rule_findings: list[dict],
        llm_config: dict | None,
    ) -> list[dict]:
        """Run LangGraph-based LLM tool loop for enhanced judgment."""
        if not self.llm:
            return []

        logger.info("ComplianceJudge: Starting LLM tool loop...")
        verified: list[dict] = []

        system_prompt = self._build_judge_system_prompt(rules, network_output)
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": "Review all rules. Use verifyViolation for each rule. Start with CRITICAL severity."},
        ]

        tool_defs = self._get_judge_tools()
        max_rounds = 15

        for round_num in range(1, max_rounds + 1):
            try:
                response = self.llm.chat(messages, config=llm_config, tools=tool_defs)

                tool_calls = response.get("tool_calls", []) if isinstance(response, dict) else getattr(response, "tool_calls", [])

                if not tool_calls:
                    # No more tools to call — finish
                    logger.info("ComplianceJudge: LLM completed after %d rounds", round_num)
                    break

                for tc in tool_calls:
                    name = tc.get("name") if isinstance(tc, dict) else tc.name
                    args = tc.get("arguments", {}) if isinstance(tc, dict) else getattr(tc, "arguments", {})
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except json.JSONDecodeError:
                            args = {}

                    logger.info("ComplianceJudge tool: %s", name)
                    result = self._execute_judge_tool(name, args)

                    if name == "verifyViolation":
                        verified.append(result.get("finding", {}))

                    # Add assistant message + tool result to history
                    messages.append({
                        "role": "assistant",
                        "content": response.get("content", "") if isinstance(response, dict) else getattr(response, "content", ""),
                        "tool_calls": [{"id": tc.get("id", str(uuid.uuid4())), "name": name, "arguments": args}],
                    })
                    messages.append({
                        "role": "tool",
                        "content": result.get("result", "")[:2000],
                        "tool_call_id": tc.get("id", str(uuid.uuid4())),
                    })

            except Exception as exc:
                logger.error("ComplianceJudge LLM round %d failed: %s", round_num, exc)
                break

        return verified

    def _build_judge_system_prompt(self, rules: list[dict], network_output: dict) -> str:
        top_rules = rules[:20]
        top_anomalies = network_output.get("anomalies", [])[:10]

        return f"""You are the Compliance Judge in a security audit system.
Review policy rules against network traffic and VERIFY violations using tools.

POLICY RULES:
{json.dumps(top_rules, indent=2)}

NETWORK SUMMARY:
- Conversations: {len(network_output.get('conversations', []))}
- Anomalies: {len(network_output.get('anomalies', []))}
- TLS: {', '.join(network_output.get('tlsVersions', []))}
- HTTP requests: {network_output.get('httpRequests', 0)}
- Plaintext auth: {network_output.get('plaintextAuthStreams', 0)}

TOP ANOMALIES:
{json.dumps(top_anomalies, indent=2)}

For each rule, call verifyViolation with:
- ruleId, violated (bool), confidence (0-1), evidence (string), packetNumbers (array)

Start with CRITICAL severity rules. Be thorough."""

    def _get_judge_tools(self) -> list[dict]:
        return [
            {
                "type": "function",
                "function": {
                    "name": "applyTsharkFilter",
                    "description": "Apply a Wireshark display filter to find matching packets",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "filter": {"type": "string", "description": "Wireshark display filter"},
                            "maxPackets": {"type": "number", "description": "Max packets (default: 50)"},
                        },
                        "required": ["filter"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "getPacketRange",
                    "description": "Fetch specific packet range by frame numbers",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "startFrame": {"type": "number"},
                            "endFrame": {"type": "number"},
                        },
                        "required": ["startFrame", "endFrame"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "getStreamDetail",
                    "description": "Get detailed analysis of a TCP stream",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "streamId": {"type": "number"},
                        },
                        "required": ["streamId"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "verifyViolation",
                    "description": "Mark a rule violation as verified with evidence",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "ruleId": {"type": "string"},
                            "violated": {"type": "boolean"},
                            "confidence": {"type": "number"},
                            "evidence": {"type": "string"},
                            "packetNumbers": {"type": "array", "items": {"type": "number"}},
                        },
                        "required": ["ruleId", "violated", "confidence", "evidence"],
                    },
                },
            },
        ]

    def _execute_judge_tool(self, name: str, args: dict) -> dict:
        if name == "applyTsharkFilter":
            return self._tool_apply_filter(args.get("filter", ""), args.get("maxPackets", 50))
        elif name == "getPacketRange":
            return self._tool_get_packet_range(args.get("startFrame", 1), args.get("endFrame", 100))
        elif name == "getStreamDetail":
            return self._tool_get_stream_detail(args.get("streamId", 0))
        elif name == "verifyViolation":
            return self._tool_verify_violation(args)
        return {"result": f"Unknown tool: {name}"}

    def _tool_apply_filter(self, display_filter: str, max_packets: int) -> dict:
        if not self.capture_file_path:
            return {"result": "No capture file available"}
        try:
            cap = pyshark.FileCapture(
                self.capture_file_path, keep_packets=False,
                display_filter=display_filter,
            )
            lines: list[str] = []
            for i, pkt in enumerate(cap):
                if i >= max_packets:
                    break
                try:
                    lines.append(
                        f"[{pkt.number}] {pkt.sniff_time} {pkt.ip.src} → {pkt.ip.dst} "
                        f"{pkt.highest_layer} {getattr(pkt, '_ws_col_Info', '')}"
                    )
                except (AttributeError, Exception):
                    lines.append(f"[{getattr(pkt, 'number', '?')}] (no IP layer)")
            cap.close()
            return {"result": "\n".join(lines) if lines else "(no matching packets)"}
        except Exception as exc:
            return {"result": f"Filter error: {exc}"}

    def _tool_get_packet_range(self, start: int, end: int) -> dict:
        if not self.capture_file_path:
            return {"result": "No capture file available"}
        end = min(end, start + 100)
        try:
            frame_filter = " || ".join(f"frame.number=={n}" for n in range(start, end + 1))
            cap = pyshark.FileCapture(
                self.capture_file_path, keep_packets=False,
                display_filter=frame_filter,
            )
            lines: list[str] = []
            for pkt in cap:
                try:
                    lines.append(
                        f"[{pkt.number}] {pkt.sniff_time} {pkt.ip.src}:{getattr(pkt, 'tcp', pkt).srcport if hasattr(pkt, 'tcp') else getattr(pkt, 'udp', pkt).srcport} "
                        f"→ {pkt.ip.dst}:{getattr(pkt, 'tcp', pkt).dstport if hasattr(pkt, 'tcp') else getattr(pkt, 'udp', pkt).dstport} "
                        f"{getattr(pkt, '_ws_col_Protocol', pkt.highest_layer)} {getattr(pkt, '_ws_col_Info', '')}"
                    )
                except Exception:
                    lines.append(f"[{getattr(pkt, 'number', '?')}]")
            cap.close()
            return {"result": "\n".join(lines) if lines else "(no packets in range)"}
        except Exception as exc:
            return {"result": f"Range error: {exc}"}

    def _tool_get_stream_detail(self, stream_id: int) -> dict:
        if not self.capture_file_path:
            return {"result": "No capture file available"}
        try:
            cap = pyshark.FileCapture(
                self.capture_file_path, keep_packets=False,
                display_filter=f"tcp.stream=={stream_id}",
            )
            lines: list[str] = [f"TCP Stream {stream_id}:"]
            for i, pkt in enumerate(cap):
                if i >= 80:
                    lines.append("... (truncated)")
                    break
                try:
                    lines.append(
                        f"[{pkt.number}] {pkt.ip.src}:{pkt.tcp.srcport} → "
                        f"{pkt.ip.dst}:{pkt.tcp.dstport} "
                        f"[{getattr(pkt.tcp, 'flags', '')}] "
                        f"len={pkt.length}"
                    )
                except Exception:
                    pass
            cap.close()
            return {"result": "\n".join(lines)}
        except Exception as exc:
            return {"result": f"Stream error: {exc}"}

    def _tool_verify_violation(self, args: dict) -> dict:
        finding = {
            "id": f"F-LLM-{uuid.uuid4().hex[:8]}",
            "ruleId": args.get("ruleId", ""),
            "ruleName": args.get("ruleId", ""),
            "ruleDescription": "",
            "category": "protocol-compliance",
            "severity": "medium",
            "standard": None,
            "policyContext": "",
            "evidencePacketNumbers": args.get("packetNumbers", []),
            "description": args.get("evidence", ""),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "dismissed": False,
            "confidence": args.get("confidence", 0.5),
            "status": "violated" if args.get("violated") else "compliant",
            "evidence": {"details": args.get("evidence", "")},
            "reasoning": args.get("evidence", ""),
        }
        return {"result": f"Verified: ruleId={args.get('ruleId')}", "finding": finding}

    # ─── Phase 4: Merge ────────────────────────────────────────────────

    def _merge_findings(self, findings: list[dict]) -> list[dict]:
        """Merge findings: best per ruleId, then demote duplicate-evidence violations."""
        # Step 1: Keep highest-confidence finding per ruleId
        by_rule: dict[str, dict] = {}
        for f in findings:
            rid = f.get("ruleId", "") or f.get("id", "")
            existing = by_rule.get(rid)
            if not existing or f.get("confidence", 0) > existing.get("confidence", 0):
                by_rule[rid] = f

        merged = list(by_rule.values())

        # Step 2: Demote violations that share the same evidence with a higher-confidence violation.
        # This prevents "Stream 5 cited by 12 rules" noise — only the most relevant rule stays violated.
        merged = self._demote_duplicate_evidence(merged)
        return merged

    def _demote_duplicate_evidence(self, findings: list[dict]) -> list[dict]:
        """If multiple VIOLATED findings share identical network evidence (stream/IPs/port/protocol),
        keep only the highest-confidence one as 'violated'. Demote the rest to 'suspicious'."""
        from collections import defaultdict

        # Group violated findings by their canonical evidence key
        evidence_groups: dict[tuple, list[dict]] = defaultdict(list)
        for f in findings:
            if f.get("status") != "violated":
                continue
            ev = f.get("evidence", {}) or {}
            key = (
                ev.get("streamId"),
                ev.get("srcIp"),
                ev.get("dstIp"),
                ev.get("dstPort"),
                ev.get("protocol"),
            )
            # Only group if the finding has at least some identifying network evidence
            if any(v is not None for v in key):
                evidence_groups[key].append(f)

        # For each group with >1 violation, keep highest-confidence, demote the rest
        demoted_ids: set[str] = set()
        for key, group in evidence_groups.items():
            if len(group) <= 1:
                continue
            group_sorted = sorted(group, key=lambda f: f.get("confidence", 0), reverse=True)
            for f in group_sorted[1:]:
                fid = f.get("id", "")
                if fid:
                    demoted_ids.add(fid)

        result = []
        for f in findings:
            if f.get("id") in demoted_ids:
                f = dict(f)  # copy
                f["status"] = "suspicious"
                f["confidence"] = round(max(0.45, f.get("confidence", 0.5) - 0.2), 3)
                f["reasoning"] = (
                    f.get("reasoning", "")
                    + " [Note: Same network observation cited by a higher-priority violation — "
                    "demoted to suspicious to reduce audit noise.]"
                )
            result.append(f)
        return result

    def _build_summary(self, findings: list[dict], total_rules: int) -> dict:
        violated = sum(1 for f in findings if f.get("status") == "violated")
        compliant = sum(1 for f in findings if f.get("status") == "compliant")
        suspicious = sum(1 for f in findings if f.get("status") == "suspicious")
        confidences = [f.get("confidence", 0) for f in findings]

        # Severity counts
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info")
            if sev in severity_counts:
                severity_counts[sev] += 1

        return {
            "totalRules": total_rules,
            "violated": violated,
            "compliant": compliant,
            "suspicious": suspicious,
            "criticalCount": severity_counts["critical"],
            "highCount": severity_counts["high"],
            "mediumCount": severity_counts["medium"],
            "lowCount": severity_counts["low"],
            "averageConfidence": round(sum(confidences) / max(len(confidences), 1), 3) if confidences else 0,
        }

    # ─── Helpers ────────────────────────────────────────────────────────

    def _create_finding_dict(
        self,
        rule: dict,
        match: RuleMatch | None,
        status: str,
        confidence: float,
    ) -> dict:
        finding_id = f"F-{rule.get('id', 'UNK')}-{uuid.uuid4().hex[:6]}"
        std = rule.get("standard", "")

        if match:
            ev = match.evidence
            details = ev.get("details", "network traffic observed")
            src = ev.get("srcIp", "")
            dst = ev.get("dstIp", "")
            port = ev.get("dstPort", "")
            proto = (ev.get("protocol") or "unknown").upper()
            stream = ev.get("streamId")
            flow_str = ""
            if src and dst:
                flow_str = f" Flow: {src} \u2192 {dst}{':{}'.format(port) if port else ''} ({proto})"
                if stream is not None:
                    flow_str += f" stream {stream}"
            desc = f"{std + ': ' if std else ''}{details}"
            reasoning = (
                f"Matched rule '{rule.get('name', '')}' with confidence {confidence:.2f}."
                f"{flow_str}. Observed: {details}."
            )
        else:
            detect_logic = rule.get("detectionLogic", "") or ""
            # Trim PDF boilerplate from detectionLogic (stop at first newline or after 120 chars)
            if "\n" in detect_logic:
                detect_logic = detect_logic.split("\n")[0].strip()
            detect_logic = detect_logic[:120]
            desc = "No violation detected" if status == "compliant" else "Inconclusive"
            reasoning = (
                f"No traffic matched rule '{rule.get('name', '')}'"
                f"{' (' + std + ')' if std else ''}."
                f"{' Detection criteria: ' + detect_logic + '.' if detect_logic else ''}"
                f" Status: {status}."
            )

        return {
            "id": finding_id,
            "ruleId": rule.get("id", ""),
            "ruleName": rule.get("name", ""),
            "ruleDescription": rule.get("description", ""),
            "category": rule.get("category", "protocol-compliance"),
            "severity": rule.get("severity", "medium"),
            "standard": rule.get("standard"),
            "policyContext": rule.get("description", ""),
            "evidencePacketNumbers": [],
            "description": desc,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "dismissed": False,
            "confidence": confidence,
            "status": status,
            "evidence": match.evidence if match else {"details": "No specific evidence"},
            "reasoning": reasoning,
        }

    def _create_anomaly_finding_dict(
        self, anomaly: dict, mapped_rule: dict | None, status: str
    ) -> dict:
        anom_type = anomaly.get("type", "unknown")
        src = anomaly.get("srcIp")
        dst = anomaly.get("dstIp")
        port = anomaly.get("dstPort")
        desc = anomaly.get("description", "")

        if mapped_rule:
            rule_id = mapped_rule.get("id", f"ANOMALY:{anom_type}")
            rule_name = mapped_rule.get("name", anom_type.replace("_", " ").title())
            category = mapped_rule.get("category", "protocol-compliance")
            severity = mapped_rule.get("severity", anomaly.get("severity", "medium"))
            std = mapped_rule.get("standard", "")
        else:
            rule_id = f"ANOMALY:{anom_type}"
            rule_name = anom_type.replace("_", " ").title()
            category = "protocol-compliance"
            severity = anomaly.get("severity", "medium")
            std = ""

        # Build structured evidence
        evidence = {"details": desc}
        if src:
            evidence["srcIp"] = src
        if dst:
            evidence["dstIp"] = dst
        if port:
            evidence["dstPort"] = port

        # Build grounded reasoning
        flow_str = ""
        if src and dst:
            flow_str = f" Flow: {src} → {dst}"
            if port:
                flow_str += f":{port}"
        reasoning = (
            f"Anomaly '{anom_type}' detected with confidence {anomaly.get('confidence', 0.55):.2f}.{flow_str} "
            f"Evidence: {desc[:200]}"
        )

        return {
            "id": f"F-ANOM-{uuid.uuid4().hex[:6]}",
            "ruleId": rule_id,
            "ruleName": rule_name,
            "ruleDescription": mapped_rule.get("description", "") if mapped_rule else "",
            "category": category,
            "severity": severity,
            "standard": std or None,
            "policyContext": mapped_rule.get("description", "Detected by NetworkAgent anomaly analysis") if mapped_rule else "Detected by NetworkAgent anomaly analysis",
            "evidencePacketNumbers": anomaly.get("packetNumbers", []),
            "description": desc,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "dismissed": False,
            "confidence": anomaly.get("confidence", 0.55),
            "status": status,
            "evidence": evidence,
            "reasoning": reasoning,
        }

    def _map_anomaly_to_rule(self, anomaly: dict, rules: list[dict]) -> dict | None:
        best_rule = None
        best_score = 0
        for rule in rules:
            score = self._score_rule_match(anomaly, rule)
            if score > best_score:
                best_score = score
                best_rule = rule
        return best_rule if best_score >= 2 else None

    def _score_rule_match(self, anomaly: dict, rule: dict) -> float:
        rule_text = self._normalize_rule_text(rule)
        anom_text = f"{anomaly.get('type', '')} {anomaly.get('description', '')}".lower()
        score = 0.0

        # Normative language boost
        if any(k in rule_text for k in ("shall", "must", "mandate", "required", "prohibit")):
            score += 0.5
        if anomaly.get("payloadEvidence"):
            score += 0.5

        anom_type_phrase = anomaly.get("type", "").replace("_", " ")
        if anom_type_phrase in rule_text:
            score += 1

        # Secure communication / integrity matches
        if any(k in rule_text for k in (
            "secure communication", "communication security", "in transit",
            "transport security", "confidentiality", "integrity",
        )) and any(k in anom_text for k in ("tls", "plaintext", "http", "arp", "dns", "spoof", "hijack", "mitm")):
            score += 1.5

        # Category-specific boosts
        cat = (rule.get("category", "") or "").lower()
        if cat == "authentication" and any(k in anom_text for k in ("brute", "credential", "password", "session")):
            score += 1
        if cat == "encryption" and any(k in anom_text for k in ("tls", "plaintext", "http", "https")):
            score += 1
        if "network" in cat and any(k in anom_text for k in ("dns", "arp", "spoof", "hijack", "poison", "mitm")):
            score += 1.5

        return score

    def _normalize_rule_text(self, rule: dict) -> str:
        return (
            f"{rule.get('name', '')} {rule.get('description', '')} "
            f"{rule.get('detectionLogic', '')} {rule.get('standard', '')}"
        ).lower()

    def _rule_allows_flow_violation(self, rule: dict) -> bool:
        text = self._normalize_rule_text(rule)
        flow_keywords = (
            "scan", "recon", "discovery", "syn", "probe", "flood", "dos", "ddos",
            "availability", "rate limit", "brute force", "credential spray",
            "attack surface", "exposed service",
        )
        cat = (rule.get("category", "") or "").lower()
        return any(k in text for k in flow_keywords) or "availability" in cat

    def _extract_ports_from_text(self, text: str) -> tuple[list[int], list[int]]:
        """Extract port numbers from rule text.
        
        Returns (forbidden_ports, allowed_ports).
        If text mentions 'only', 'allowed', 'permitted' → extracted ports are ALLOWED,
        and forbidden is empty (handled by checking against allowed list).
        If text mentions 'forbidden', 'prohibited', 'blocked' → extracted ports are FORBIDDEN.
        """
        ports = [int(m) for m in re.findall(r"\b(\d{2,5})\b", text) if 1 <= int(m) <= 65535]
        text_lower = text.lower()
        
        # If the rule specifies allowed ports (e.g., "Only ports 80, 443 are allowed")
        if any(k in text_lower for k in ("only", "allowed", "permitted", "authorized")):
            return [], ports  # Forbidden = empty, Allowed = extracted ports
        
        return ports, []  # Forbidden = extracted ports, Allowed = empty

    @staticmethod
    def _looks_internal(ip: str) -> bool:
        return ip.startswith(("10.", "172.16.", "192.168.", "127."))

    @staticmethod
    def _looks_external(ip: str) -> bool:
        if not ip:
            return False
        return not ComplianceJudge._looks_internal(ip)
