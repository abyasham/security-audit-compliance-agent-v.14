"""
PolicyAgent — Agent 1 of the SACA Multi-Agent Architecture (port from TypeScript).

Parses policy documents into structured, machine-readable rules using LiteLLM
with spaCy NLP enrichment and PolicyKnowledgeGraph context retrieval.

Port of backend/src/agents/policyAgent.ts
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional

from schema.models import (
    ComparisonOp,
    ParsedPolicy,
    PolicyCategory,
    PolicyRule,
    RuleCondition,
    Severity,
)
from services.policy_kg import PolicyKnowledgeGraph

logger = logging.getLogger(__name__)

# ─── AgentRule (internal, enriched with detection logic) ─────────────────────


class AgentRule:
    """Enriched PolicyRule with detectionLogic and evidenceRequired."""

    def __init__(
        self,
        rule_id: str,
        name: str,
        description: str,
        category: str,
        severity: str,
        detection_logic: str,
        evidence_required: List[str],
        standard: str | None = None,
        conditions: List[dict] | None = None,
    ):
        self.id = rule_id
        self.name = name
        self.description = description
        self.category = category
        self.severity = severity
        self.standard = standard
        self.conditions = conditions or []
        self.detection_logic = detection_logic
        self.evidence_required = evidence_required

    def to_policy_rule(self) -> PolicyRule:
        return PolicyRule(
            id=self.id,
            name=self.name,
            description=self.description,
            category=PolicyCategory(self.category),
            severity=Severity(self.severity),
            standard=self.standard,
            conditions=[
                RuleCondition(
                    field=c["field"],
                    operator=ComparisonOp(c.get("operator", "equals")),
                    value=c.get("value", ""),
                )
                for c in self.conditions
            ],
        )


# ─── Agent ──────────────────────────────────────────────────────────────────


class PolicyAgent:
    """Parses policy documents into structured rules using LLM + NLP."""

    VALID_CATEGORIES = {c.value for c in PolicyCategory}
    VALID_SEVERITIES = {s.value for s in Severity}
    VALID_OPS = {op.value for op in ComparisonOp}

    def __init__(self, llm_gateway=None, nlp_model=None):
        self.llm = llm_gateway
        self.nlp = nlp_model  # spaCy model injected at startup

    # ─── Public API ─────────────────────────────────────────────────────

    def analyze(
        self,
        parsed_policy: ParsedPolicy,
        llm_config: dict | None = None,
    ) -> dict:
        """
        Parse a policy document into structured rules.

        Returns: dict with policyName, version, framework, rules (list of dicts),
                 rawTextLength, ruleCount, categories, severities
        """
        raw_text = parsed_policy.raw_text or ""

        # If there's no raw text (e.g., already structured JSON/YAML),
        # enrich existing rules and return.
        if not raw_text.strip():
            enriched = self._enrich_rules(parsed_policy.rules or [])
            return self._build_output(parsed_policy, enriched)

        # LLM extraction  
        extracted = self._extract_rules_with_llm(raw_text, parsed_policy, llm_config)

        # Heuristic fallback when LLM produces nothing
        fallback = self._extract_rules_heuristically(raw_text, parsed_policy) if not extracted else []

        # Merge: existing from structured input + extracted + fallback
        all_rules = (
            self._enrich_rules(parsed_policy.rules or [])
            + extracted
            + fallback
        )

        # Deduplicate by semantic fingerprint
        seen: set[str] = set()
        deduped: list[AgentRule] = []
        for r in all_rules:
            fp = (
                f"{r.id}::{r.name.lower()}::"
                f"{(r.standard or '').lower()}::"
                f"{r.description.lower()[:200]}"
            )
            if fp in seen:
                continue
            seen.add(fp)
            deduped.append(r)

        return self._build_output(parsed_policy, deduped)

    # ─── LLM Extraction ─────────────────────────────────────────────────

    def _extract_rules_with_llm(
        self,
        raw_text: str,
        parsed_policy: ParsedPolicy,
        llm_config: dict | None = None,
    ) -> list[AgentRule]:
        """Call LLM to extract structured rules from unstructured policy text."""
        if not self.llm:
            logger.warning("No LLM gateway — falling back to heuristic extraction")
            return []

        # Build extraction context via PolicyKnowledgeGraph
        kg = PolicyKnowledgeGraph.from_policy_text(raw_text)
        extraction_ctx = kg.retrieve_clause_context(
            ["encryption", "access", "authentication", "logging", "protocol", "data", "control", "security"],
            max_nodes=80,
        )

        system_prompt = """You are the Policy Parser Agent for a network security compliance system.
Read a security policy document and extract a machine-readable list of rules.

Output STRICT JSON. No markdown, no explanations. ONLY a JSON array.

Each rule MUST have:
- id: short unique ID like "R001"
- name: concise rule title (max 80 chars)
- description: what the rule requires
- category: one of [encryption, network-segmentation, access-control, protocol-compliance, authentication, logging, data-exfiltration]
- severity: one of [critical, high, medium, low, info]
- standard: EXACT provision/clause/section number from the document (e.g., "ETSI EN 303 645 Provision 5.1")
- conditions: array of { field, operator, value } where operator is one of [equals, notEquals, greaterThan, lessThan, contains, notContains, in, notIn, inZone, matches]
- detectionLogic: plain-English description of what traffic pattern violates this rule
- evidenceRequired: array of evidence fields needed (e.g., ["packet_numbers", "src_ip", "dst_ip", "protocol", "port"])

CRITICAL: cite exact provision/clause numbers. For ETSI EN 303 645 use "Provision X.Y" format.
If no actionable network rules found, return []."""

        user_prompt = f"""Extract structured compliance rules from this policy document.

Policy name: {parsed_policy.policy_name}
Framework: {parsed_policy.framework or 'Unknown'}

---

{extraction_ctx[:22000]}

---

Return ONLY a JSON array of rules."""

        try:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ]
            response = self.llm.chat(messages, config=llm_config)
            content = response.get("content", "") if isinstance(response, dict) else response
            rules = self._parse_rules_from_llm(content)
            logger.info("PolicyAgent: extracted %d rules from LLM", len(rules))
            return rules
        except Exception as exc:
            logger.error("PolicyAgent LLM extraction failed: %s", exc)
            return []

    def _parse_rules_from_llm(self, content: str) -> list[AgentRule]:
        """Parse LLM JSON output into AgentRule list."""
        json_text = content.strip()

        fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", json_text)
        if fence:
            json_text = fence.group(1).strip()

        start = json_text.find("[")
        end = json_text.rfind("]")
        if start != -1 and end != -1 and end > start:
            json_text = json_text[start : end + 1]

        try:
            data = json.loads(json_text)
        except json.JSONDecodeError:
            logger.error("PolicyAgent: failed to parse LLM JSON")
            return []

        if not isinstance(data, list):
            data = data.get("rules", []) if isinstance(data, dict) else []

        return [self._normalize_rule(r, i) for i, r in enumerate(data)]

    def _normalize_rule(self, raw: dict, index: int) -> AgentRule:
        """Normalize a raw rule dict into a valid AgentRule."""
        combined = f"{raw.get('name', '')} {raw.get('description', '')} {raw.get('detectionLogic', raw.get('detection_logic', ''))}"
        category = raw.get("category") if raw.get("category") in self.VALID_CATEGORIES else self._infer_category(combined)
        severity = raw.get("severity") if raw.get("severity") in self.VALID_SEVERITIES else self._infer_severity(combined)

        conditions: list[dict] = []
        for c in raw.get("conditions", []):
            op = c.get("operator", "equals")
            conditions.append({
                "field": str(c.get("field", "")),
                "operator": op if op in self.VALID_OPS else "equals",
                "value": c.get("value", ""),
            })

        det_logic = raw.get("detectionLogic") or raw.get("detection_logic") or ""
        evidence = raw.get("evidenceRequired") or raw.get("evidence_required") or []

        rule = AgentRule(
            rule_id=raw.get("id") or f"R{index + 1:03d}",
            name=raw.get("name") or f"Rule {index + 1}",
            description=raw.get("description") or "",
            category=category,
            severity=severity,
            standard=raw.get("standard") or raw.get("clause") or raw.get("provision"),
            conditions=conditions,
            detection_logic=det_logic,
            evidence_required=evidence if isinstance(evidence, list) else [],
        )

        # Fill in missing detection logic / evidence
        if not rule.detection_logic or len(rule.detection_logic.strip()) < 10:
            rule.detection_logic = self._infer_detection_logic(rule)
        if not rule.evidence_required:
            rule.evidence_required = self._infer_evidence_required(rule)

        return rule

    # ─── Heuristic Extraction ───────────────────────────────────────────

    def _extract_rules_heuristically(
        self, raw_text: str, parsed_policy: ParsedPolicy
    ) -> list[AgentRule]:
        """Deterministic fallback: parse keyword-driven rules from text."""
        rules: list[AgentRule] = []
        
        # Try splitting by double newlines first, then by numbered/bulleted lines
        sections = raw_text.split("\n\n")
        if len(sections) == 1:
            # Try splitting by lines that start with numbers or bullets
            lines = raw_text.split("\n")
            sections = []
            current = ""
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                # Check if this line starts a new section (number, bullet, or clause)
                if re.match(r"^(\d+[.):\s]+|[-*•]\s+|(?:clause|provision|section|control|article)\s*\d+)", line, re.IGNORECASE):
                    if current:
                        sections.append(current.strip())
                    current = line
                else:
                    current += " " + line
            if current:
                sections.append(current.strip())
        
        # Filter out short sections
        sections = [s for s in sections if len(s.strip()) >= 20]

        for idx, section in enumerate(sections):
            section = section.strip()

            # Detect provision numbers
            prov_match = re.search(
                r"(?:provision|clause|control|section|article)\s*[:\s]*(\d[\d.]*)",
                section,
                re.IGNORECASE,
            )
            standard = prov_match.group(0) if prov_match else None
            
            # Extract a name from the first sentence
            name_match = re.match(r"^(?:\d+[.):\s]+)?\s*([^.{;]+)", section)
            name = name_match.group(1).strip() if name_match else f"Heuristic Rule {idx + 1}"
            if len(name) > 80:
                name = name[:77] + "..."

            category = self._infer_category(section)
            severity = self._infer_severity(section)
            det_logic = self._infer_detection_logic_from_text(section, category)
            evidence = ["packet_numbers", "src_ip", "dst_ip", "protocol"]

            rules.append(AgentRule(
                rule_id=f"H{idx + 1:03d}",
                name=name,
                description=section[:300],
                category=category,
                severity=severity,
                standard=standard,
                conditions=[],
                detection_logic=det_logic,
                evidence_required=evidence,
            ))

        return rules

    def _enrich_rules(self, rules: list[PolicyRule]) -> list[AgentRule]:
        """Add detectionLogic/evidenceRequired to existing structured rules."""
        enriched: list[AgentRule] = []
        for r in rules:
            agent_rule = AgentRule(
                rule_id=r.id,
                name=r.name,
                description=r.description,
                category=r.category.value,
                severity=r.severity.value,
                standard=r.standard,
                conditions=[
                    {"field": c.field, "operator": c.operator.value, "value": c.value}
                    for c in (r.conditions or [])
                ],
                detection_logic=self._infer_detection_logic_from_rule(r),
                evidence_required=self._infer_evidence_required_from_rule(r),
            )
            enriched.append(agent_rule)
        return enriched

    # ─── Inference Helpers ──────────────────────────────────────────────

    def _infer_category(self, text: str) -> str:
        t = text.lower()
        if re.search(r"(tls|ssl|https|encrypt|cipher|certificate|in transit|secure communication)", t):
            return "encryption"
        if re.search(r"(segment|zone|subnet|east-west|north-south|dmz)", t):
            return "network-segmentation"
        if re.search(r"(auth|password|mfa|credential|identity|session|login)", t):
            return "authentication"
        if re.search(r"(log|audit|retention|siem|monitor)", t):
            return "logging"
        if re.search(r"(exfil|egress|outbound|dlp|leak)", t):
            return "data-exfiltration"
        if re.search(r"(protocol|port|http|dns|arp|icmp|ftp|telnet|ssh)", t):
            return "protocol-compliance"
        return "access-control"

    def _infer_severity(self, text: str) -> str:
        t = text.lower()
        if re.search(r"(critical|immediately|must not|never|strictly prohibited|catastrophic)", t):
            return "critical"
        if re.search(r"(high|shall|must|required|mandatory)", t):
            return "high"
        if re.search(r"(should|recommended|important)", t):
            return "medium"
        if re.search(r"(may|optional|advisory)", t):
            return "low"
        return "medium"

    def _infer_detection_logic(self, rule: AgentRule) -> str:
        return self._infer_detection_logic_from_text(
            f"{rule.name} {rule.description}", rule.category
        )

    def _infer_detection_logic_from_text(self, text: str, category: str) -> str:
        """Generate detection logic from rule text.
        
        Preserves specific details (port numbers, IP ranges, protocol names) from the original text
        so the ComplianceJudge can extract them for deterministic matching.
        """
        t = text.lower()
        
        # For protocol-compliance, preserve port numbers and protocol names from the original text
        if category == "protocol-compliance":
            # Extract port numbers and protocol mentions from the text
            ports = re.findall(r"\b(\d{2,5})\b", text)
            protocols = re.findall(r"\b(tcp|udp|http|https|ssh|ftp|telnet|dns|smtp|tls|ssl)\b", t)
            if ports or protocols:
                preserved = text[:200]  # Preserve first 200 chars with specifics
                return f"{preserved}"
            return "Flag forbidden protocols, ports, or non-compliant traffic patterns."
        
        if category == "encryption":
            # Preserve TLS version requirements
            tls_match = re.search(r"tls\s*[\d.]+|ssl|https|plaintext", t)
            if tls_match:
                return f"{text[:180]}. Flag plaintext protocols or weak TLS/SSL."
            return "Flag plaintext protocols or weak TLS/SSL where encryption is required."
        if category == "network-segmentation":
            return "Flag unauthorized cross-zone traffic between restricted segments."
        if category == "authentication":
            return "Flag brute-force, plaintext credentials, and weak authentication."
        if category == "logging":
            return "Verify that audit logs capture required security events."
        if category == "data-exfiltration":
            # Preserve size thresholds
            size_match = re.search(r"(\d+)\s*(kb|mb|gb|bytes?)", t)
            if size_match:
                return f"{text[:180]}. Flag large outbound transfers."
            return "Flag large outbound transfers to unauthorized destinations."
        return "Inspect traffic for deviations from the defined rule."

    def _infer_detection_logic_from_rule(self, rule: PolicyRule) -> str:
        return self._infer_detection_logic_from_text(
            f"{rule.name} {rule.description}", rule.category.value
        )

    def _infer_evidence_required(self, rule: AgentRule) -> list[str]:
        base = ["packet_numbers", "src_ip", "dst_ip", "protocol"]
        if rule.category == "encryption":
            base.append("tls_version")
        if rule.category == "authentication":
            base.extend(["port", "attempt_count"])
        return base

    def _infer_evidence_required_from_rule(self, rule: PolicyRule) -> list[str]:
        base = ["packet_numbers", "src_ip", "dst_ip", "protocol"]
        if rule.category.value == "encryption":
            base.append("tls_version")
        if rule.category.value == "authentication":
            base.extend(["port", "attempt_count"])
        return base

    # ─── Output ─────────────────────────────────────────────────────────

    def _build_output(
        self, parsed_policy: ParsedPolicy, rules: list[AgentRule]
    ) -> dict:
        categories = list({r.category for r in rules})
        sevs: dict[str, int] = {s.value: 0 for s in Severity}
        for r in rules:
            sevs[r.severity] = sevs.get(r.severity, 0) + 1

        return {
            "policyName": parsed_policy.policy_name,
            "version": parsed_policy.version,
            "framework": parsed_policy.framework,
            "rules": [
                {
                    "id": r.id,
                    "name": r.name,
                    "description": r.description,
                    "category": r.category,
                    "severity": r.severity,
                    "standard": r.standard,
                    "conditions": r.conditions,
                    "detectionLogic": r.detection_logic,
                    "evidenceRequired": r.evidence_required,
                }
                for r in rules
            ],
            "rawTextLength": len(parsed_policy.raw_text or ""),
            "ruleCount": len(rules),
            "categories": categories,
            "severities": sevs,
        }
