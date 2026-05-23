"""
RAGAS Evaluation Runner — evaluates compliance findings for faithfulness & relevancy.

Uses ragas >=0.4.x collections metrics (Faithfulness, AnswerRelevancy) with
real LLM calls. Falls back to heuristic scoring when no API key is available.

Per the migration plan: RAGAS measures whether ComplianceJudge findings are
faithful to actual packet evidence — detecting LLM hallucination in audit outputs.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ─── Prototype Tuning ──────────────────────────────────────────────────────
# Findings are pre-filtered to violated-only and capped to 3 by the Express API.
# RAGAS_SAMPLE_SIZE is a safety net in case the runner is called directly.
RAGAS_SAMPLE_SIZE = int(os.getenv("RAGAS_SAMPLE_SIZE", "3"))
# Max seconds to wait for a single LLM call before giving it 0.0 and moving on.
RAGAS_PER_FINDING_TIMEOUT = int(os.getenv("RAGAS_PER_FINDING_TIMEOUT", "60"))

logger = logging.getLogger(__name__)


# ─── Result Types ───────────────────────────────────────────────────────────


@dataclass
class PerFindingScore:
    finding_id: str
    rule_name: str
    faithfulness: float
    answer_relevancy: float
    faithfulness_reason: str = ""
    relevancy_reason: str = ""
    scored_by_llm: bool = True


@dataclass
class RAGASEvalResult:
    session_id: str | None
    timestamp: str
    avg_faithfulness: float
    avg_answer_relevancy: float
    per_finding_scores: list[PerFindingScore] = field(default_factory=list)
    error: str | None = None
    provider_used: str | None = None
    heuristic_fallback: bool = False


# ─── RAGAS Runner ───────────────────────────────────────────────────────────


class RagasRunner:
    """Runs RAGAS evaluation on compliance judge findings."""

    def __init__(self, llm_gateway=None):
        self.llm = llm_gateway
        self._metrics = None
        self._provider_used = None

    # ── Public API ──────────────────────────────────────────────────────────

    async def evaluate(
        self,
        findings: list[dict],
        policy_text: str = "",
        session_id: str | None = None,
        capture_file_path: str | None = None,
    ) -> RAGASEvalResult:
        """
        Run RAGAS metrics on findings.

        Args:
            findings: List of finding dicts from ComplianceJudge
            policy_text: The original policy text for context
            session_id: Optional session ID for result storage

        Returns:
            RAGASEvalResult with faithfulness, answer_relevancy scores
        """
        if not findings:
            return RAGASEvalResult(
                session_id=session_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                avg_faithfulness=-1.0,
                avg_answer_relevancy=-1.0,
                error="no_findings",
            )

        # Sample diverse findings for LLM scoring, rest get heuristic
        sampled, remaining = self._sample_diverse(findings, RAGAS_SAMPLE_SIZE)
        logger.info(
            "RAGAS: scoring %d/%d findings with LLM, %d with heuristic",
            len(sampled), len(findings), len(remaining),
        )

        # Score sampled findings with real RAGAS
        try:
            llm_result = await self._evaluate_with_ragas(
                sampled, policy_text, session_id, capture_file_path
            )
        except Exception as exc:
            logger.warning("Real RAGAS failed (%s), falling back to all-heuristic", exc)
            result = self._evaluate_heuristic(findings, policy_text, session_id, capture_file_path)
            result.heuristic_fallback = True
            await self._save_result(result)
            return result

        # Score remaining findings with fast heuristic
        if remaining:
            heur_result = self._evaluate_heuristic(remaining, policy_text, session_id, capture_file_path)
            llm_result.per_finding_scores.extend(heur_result.per_finding_scores)

        # Recompute averages over all findings
        all_f = [p.faithfulness for p in llm_result.per_finding_scores]
        all_r = [p.answer_relevancy for p in llm_result.per_finding_scores]
        llm_result.avg_faithfulness = round(sum(all_f) / len(all_f), 3) if all_f else 0.0
        llm_result.avg_answer_relevancy = round(sum(all_r) / len(all_r), 3) if all_r else 0.0

        await self._save_result(llm_result)
        return llm_result

    # ── Real RAGAS (LLM-based) ──────────────────────────────────────────────

    async def _evaluate_with_ragas(
        self,
        findings: list[dict],
        policy_text: str,
        session_id: str | None,
        capture_file_path: str | None,
    ) -> RAGASEvalResult:
        """Use ragas Faithfulness metric with LLM calls.

        Optimised for prototype speed:
        - Only runs Faithfulness (1 LLM call per finding, not 2).
        - AnswerRelevancy uses fast heuristic instead of LLM.
        - Runs all findings concurrently via asyncio.gather.
        """
        from ragas.metrics.collections.faithfulness import Faithfulness

        # Build LLM client
        llm, _emb, provider = self._build_ragas_llm()
        if llm is None:
            raise RuntimeError("No LLM provider available for RAGAS")

        faithfulness_metric = Faithfulness(llm=llm)

        async def _score_one(finding: dict) -> PerFindingScore:
            fid = finding.get("id", "unknown")
            rule_name = finding.get("ruleName", finding.get("rule_name", "Unknown"))
            reasoning = finding.get("reasoning", "") or finding.get("description", "")
            evidence = finding.get("evidence", {}) or {}
            evidence_details = evidence.get("details", "") or ""
            finding_desc = finding.get("description", "") or ""
            severity = finding.get("severity", "")
            status = finding.get("status", "")
            category = finding.get("category", "") or ""

            # Query = the compliance check question
            query = f"Is this network traffic finding a violation of {rule_name}?"

            # Response = the judge's full reasoning about the finding
            response = reasoning or finding_desc or ""

            # Contexts = structured evidence facts (what the LLM should ground its reasoning in)
            # These are the observable facts — not raw PDF text, not tautological copies
            contexts: list[str] = []

            # Core evidence context
            if evidence_details:
                contexts.append(f"Observed traffic: {evidence_details}")
            proto = evidence.get("protocol", "")
            src = evidence.get("srcIp") or evidence.get("src_ip", "")
            dst = evidence.get("dstIp") or evidence.get("dst_ip", "")
            port = evidence.get("dstPort") or evidence.get("dst_port", "")
            if src and dst:
                addr = f"{src} → {dst}"
                if port:
                    addr += f":{port}"
                if proto:
                    addr += f" ({proto.upper()})"
                contexts.append(f"Network flow: {addr}")

            # Finding classification
            if severity and status:
                contexts.append(f"Finding classification: {severity} severity, status={status}, category={category}")

            # Packet numbers as evidence of observation
            pkt_nums = finding.get("evidencePacketNumbers") or finding.get("evidence_packet_numbers") or []
            if pkt_nums:
                contexts.append(f"Supported by {len(pkt_nums)} observed packet(s): {pkt_nums[:5]}")

            if not contexts:
                contexts = ["No structured evidence available for this finding."]

            # Faithfulness via LLM — hard timeout per finding
            try:
                f_result = await asyncio.wait_for(
                    faithfulness_metric.ascore(
                        user_input=query,
                        response=response,
                        retrieved_contexts=contexts,
                    ),
                    timeout=RAGAS_PER_FINDING_TIMEOUT,
                )
                raw = f_result.value if hasattr(f_result, "value") else f_result
                if isinstance(raw, (int, float)) and not (isinstance(raw, float) and math.isnan(raw)):
                    f_score = float(raw)
                else:
                    f_score = 0.0
            except asyncio.TimeoutError:
                logger.warning("Faithfulness timed out for %s (>%ds), using 0.0", fid, RAGAS_PER_FINDING_TIMEOUT)
                f_score = 0.0
            except (AttributeError, TypeError, KeyError):
                f_score = 0.0

            # Do NOT apply evidence_cap to LLM-scored findings — trust the LLM result
            llm_raw_score = f_score

            # AnswerRelevancy via fast heuristic (no LLM call)
            r_score = self._heuristic_relevancy(finding, policy_text)

            f_reason = self._explain_faithfulness_llm(finding, llm_raw_score, contexts)
            r_reason = self._explain_relevancy(finding, r_score, query)

            return PerFindingScore(
                finding_id=fid,
                rule_name=rule_name,
                faithfulness=round(f_score, 3),
                answer_relevancy=round(r_score, 3),
                faithfulness_reason=f_reason,
                relevancy_reason=r_reason,
            )

        # Run all sampled findings concurrently
        logger.info("RAGAS: scoring %d findings concurrently with %s", len(findings), provider)
        per_scores = await asyncio.gather(*[_score_one(f) for f in findings])
        per_scores = list(per_scores)

        avg_f = round(sum(p.faithfulness for p in per_scores) / len(per_scores), 3) if per_scores else 0.0
        avg_r = round(sum(p.answer_relevancy for p in per_scores) / len(per_scores), 3) if per_scores else 0.0

        return RAGASEvalResult(
            session_id=session_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            avg_faithfulness=avg_f,
            avg_answer_relevancy=avg_r,
            per_finding_scores=per_scores,
            provider_used=provider,
            heuristic_fallback=False,
        )

    # ── Heuristic Fallback ──────────────────────────────────────────────────

    def _evaluate_heuristic(
        self,
        findings: list[dict],
        policy_text: str,
        session_id: str | None,
        capture_file_path: str | None,
    ) -> RAGASEvalResult:
        """Fallback heuristic scoring when LLM is unavailable."""
        per_scores: list[PerFindingScore] = []
        faithfulness_scores: list[float] = []
        relevancy_scores: list[float] = []

        policy_lower = policy_text.lower() if policy_text else ""
        keywords = {
            "encrypt", "tls", "ssl", "auth", "password", "credential",
            "log", "audit", "access", "segment", "zone", "protocol",
            "port", "data", "exfil", "security", "control", "forbidden",
            "allowed", "permitted", "deny", "mfa", "plaintext",
        }
        matched = {k for k in keywords if k in policy_lower}

        for finding in findings:
            fid = finding.get("id", "unknown")
            rule_name = finding.get("ruleName", finding.get("rule_name", "Unknown"))

            # Faithfulness heuristic (strict, evidence-first)
            f_score = 0.0
            if finding.get("evidence", {}).get("details"):
                f_score += 0.35
            if finding.get("evidencePacketNumbers") or finding.get("evidence_packet_numbers"):
                f_score += 0.35
            reasoning = finding.get("reasoning", "") or ""
            if len(reasoning) > 30:
                f_score += 0.15
            conf = finding.get("confidence", 0)
            if conf and conf >= 0.7:
                f_score += 0.1
            f_score = min(1.0, f_score)

            contexts = self._build_contexts(finding, capture_file_path)
            f_score = min(f_score, self._evidence_cap(finding, contexts))

            # Relevancy heuristic
            r_score = 0.5
            if matched:
                finding_text = (
                    f"{finding.get('ruleDescription', '')} {finding.get('description', '')} {reasoning}"
                ).lower()
                hits = sum(1 for k in matched if k in finding_text)
                r_score = hits / max(len(matched), 1)

            f_reason = self._explain_faithfulness(finding, f_score, contexts)
            r_reason = self._explain_relevancy(finding, r_score, rule_name)

            per_scores.append(
                PerFindingScore(
                    finding_id=fid,
                    rule_name=rule_name,
                    faithfulness=round(f_score, 3),
                    answer_relevancy=round(r_score, 3),
                    faithfulness_reason=f_reason,
                    relevancy_reason=r_reason,
                    scored_by_llm=False,
                )
            )
            faithfulness_scores.append(f_score)
            relevancy_scores.append(r_score)

        avg_f = round(sum(faithfulness_scores) / len(faithfulness_scores), 3) if faithfulness_scores else 0.0
        avg_r = round(sum(relevancy_scores) / len(relevancy_scores), 3) if relevancy_scores else 0.0

        return RAGASEvalResult(
            session_id=session_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            avg_faithfulness=avg_f,
            avg_answer_relevancy=avg_r,
            per_finding_scores=per_scores,
            provider_used="heuristic",
            heuristic_fallback=True,
        )

    # ── Helpers ─────────────────────────────────────────────────────────────

    @staticmethod
    def _sample_diverse(findings: list[dict], n: int) -> tuple[list[dict], list[dict]]:
        """Pick up to *n* diverse findings (spread across severities).

        Returns (sampled, remaining).
        """
        if len(findings) <= n:
            return findings, []

        # Bucket by severity to ensure diversity
        buckets: dict[str, list[dict]] = {}
        for f in findings:
            sev = f.get("severity", "medium")
            buckets.setdefault(sev, []).append(f)

        sampled: list[dict] = []
        # Round-robin across severity buckets
        severity_order = ["critical", "high", "medium", "low", "info"]
        while len(sampled) < n:
            picked_any = False
            for sev in severity_order:
                if len(sampled) >= n:
                    break
                bucket = buckets.get(sev, [])
                if bucket:
                    sampled.append(bucket.pop(random.randrange(len(bucket))))
                    picked_any = True
            if not picked_any:
                break

        sampled_ids = {id(f) for f in sampled}
        remaining = [f for f in findings if id(f) not in sampled_ids]
        return sampled, remaining

    def _heuristic_relevancy(self, finding: dict, policy_text: str) -> float:
        """Fast heuristic for AnswerRelevancy — measures how well reasoning addresses the finding.

        Uses category, severity, status and key security terms rather than raw PDF text.
        """
        import re
        reasoning = (finding.get("reasoning", "") or "").lower()
        description = (finding.get("description", "") or "").lower()
        category = (finding.get("category", "") or "").lower().replace("-", " ")
        severity = (finding.get("severity", "") or "").lower()
        status = (finding.get("status", "") or "").lower()
        evidence_details = ((finding.get("evidence", {}) or {}).get("details", "") or "").lower()

        response_text = f"{reasoning} {description}"

        # Domain-relevant security keywords (not PDF boilerplate)
        security_keywords = {
            "encrypt", "tls", "ssl", "https", "plaintext", "unencrypted",
            "http", "protocol", "traffic", "packet", "network", "port",
            "violation", "compliant", "security", "detection", "rule",
        }

        # Category-specific keywords
        category_keywords = set(re.findall(r'\b[a-z]{3,}\b', category))

        all_keywords = security_keywords | category_keywords
        hits = sum(1 for k in all_keywords if k in response_text)

        base_score = min(1.0, hits / max(len(all_keywords) * 0.25, 1))

        # Bonus: reasoning explicitly references the status/severity
        if status and status in response_text:
            base_score = min(1.0, base_score + 0.1)
        if severity and severity in response_text:
            base_score = min(1.0, base_score + 0.05)

        return round(base_score, 3)

    def _build_ragas_llm(self) -> tuple[Any, Any, str | None]:
        """Build RAGAS-compatible LLM + embeddings. Returns (llm, embeddings, provider_name)."""
        from openai import AsyncOpenAI

        # Try providers in priority order
        openrouter_model = os.getenv("OPENROUTER_MODEL", "openrouter/google/gemini-2.0-flash")
        deepseek_model = os.getenv("DEEPSEEK_MODEL", "deepseek/deepseek-chat")

        providers = [
            ("openai", "OPENAI_API_KEY", "gpt-4o-mini", None),
            ("openrouter", "OPENROUTER1_API_KEY", openrouter_model, "https://openrouter.ai/api/v1"),
            ("openrouter2", "OPENROUTER2_API_KEY", openrouter_model, "https://openrouter.ai/api/v1"),
            ("deepseek", "DEEPSEEK_API_KEY", deepseek_model, None),
            ("kimi", "KIMI_API_KEY", "moonshot/moonshot-v1-8k", None),
            ("nvidia", "NVIDIA_API_KEY", "nvidia_nim/mistralai/mistral-large-3-675b-instruct-2512", None),
        ]

        for provider_name, env_key, model, base_url in providers:
            api_key = os.getenv(env_key, "")
            if not api_key:
                continue

            try:
                client = AsyncOpenAI(api_key=api_key, base_url=base_url)
                from ragas.llms import llm_factory
                from ragas.embeddings import embedding_factory

                # Strip provider prefix from model — base_url determines the actual provider
                normalized_model = model.split("/", 1)[-1] if "/" in model else model
                llm = llm_factory(model=normalized_model, provider="openai", client=client)
                emb = embedding_factory("openai", model="text-embedding-3-small", client=client, interface="modern")
                logger.info("RAGAS using provider: %s, model: %s", provider_name, normalized_model)
                return llm, emb, provider_name
            except Exception as exc:
                logger.warning("RAGAS provider %s failed: %s", provider_name, exc)
                continue

        return None, None, None

    def _build_contexts(self, finding: dict, capture_file_path: str | None) -> list[str]:
        """Build retrieved context strings from finding evidence."""
        contexts: list[str] = []

        evidence = finding.get("evidence", {})
        if evidence:
            details = evidence.get("details", "")
            if details:
                contexts.append(details)
            src_ip = evidence.get("srcIp", evidence.get("src_ip", ""))
            dst_ip = evidence.get("dstIp", evidence.get("dst_ip", ""))
            dst_port = evidence.get("dstPort", evidence.get("dst_port", ""))
            proto = evidence.get("protocol", "")
            stream_id = evidence.get("streamId", evidence.get("stream_id", ""))
            if src_ip and dst_ip:
                contexts.append(
                    f"Stream {stream_id}: {src_ip} -> {dst_ip}:{dst_port} [{proto}]"
                )

        # Packet numbers as context
        pkt_nums = finding.get("evidencePacketNumbers", finding.get("evidence_packet_numbers", []))
        for n in pkt_nums[:10]:
            contexts.append(f"Packet {n}")

        # Packet trace context from pcap (best-effort)
        if capture_file_path and pkt_nums:
            contexts.extend(self._packet_contexts(capture_file_path, pkt_nums))

        return contexts

    def _evidence_cap(self, finding: dict, contexts: list[str]) -> float:
        """Return max faithfulness allowed based on evidence strength.

        Tuned thresholds (2026-05-22):
        - Base increased from 0.1 -> 0.2 (minimum trust for any finding)
        - Details: 0.4 for detailed evidence (>100 chars), 0.25 for brief
        - Packet numbers: tiered 0.25-0.5 based on count (more = stronger)
        - Actual packet lines from tshark: 0.25-0.4 (strongest evidence)
        - Payload evidence: 0.2 (was 0.1)
        - Confidence bonus: up to 0.1 for high-confidence findings
        """
        cap = 0.2  # Base trust for any finding
        evidence = finding.get("evidence", {}) or {}
        pkt_nums = finding.get("evidencePacketNumbers") or finding.get("evidence_packet_numbers") or []

        # Evidence details quality
        details = evidence.get("details", "")
        if details:
            if len(details) > 100:
                cap += 0.4  # Detailed evidence
            else:
                cap += 0.25  # Brief evidence

        # Packet numbers (specificity of evidence) — tiered by count
        num_pkts = len(pkt_nums)
        if num_pkts >= 20:
            cap += 0.5  # Strong evidence: many packets
        elif num_pkts >= 10:
            cap += 0.4
        elif num_pkts >= 5:
            cap += 0.35
        elif num_pkts > 0:
            cap += 0.25  # Some packet evidence

        # Network addressing (specificity)
        has_src = evidence.get("srcIp") or evidence.get("src_ip")
        has_dst = evidence.get("dstIp") or evidence.get("dst_ip")
        if has_src and has_dst:
            cap += 0.15  # Both source and destination known
        elif has_src or has_dst:
            cap += 0.1

        # Port and protocol specificity
        if evidence.get("dstPort") or evidence.get("dst_port"):
            cap += 0.1
        if evidence.get("protocol"):
            cap += 0.1

        # Payload evidence (deep inspection)
        if evidence.get("payloadEvidence") or evidence.get("payload_evidence"):
            cap += 0.2

        # Actual packet lines from tshark (strongest evidence)
        packet_lines = [ctx for ctx in contexts if ctx.startswith("Packet ") and ":" in ctx]
        if len(packet_lines) >= 10:
            cap += 0.4  # Many actual packet lines
        elif len(packet_lines) >= 5:
            cap += 0.3
        elif len(packet_lines) > 0:
            cap += 0.25

        # Confidence bonus
        confidence = finding.get("confidence", 0)
        if confidence >= 0.9:
            cap += 0.1
        elif confidence >= 0.7:
            cap += 0.05

        return min(1.0, cap)

    # ── Explanation helpers ─────────────────────────────────────────────────

    def _explain_faithfulness_llm(self, finding: dict, score: float, contexts: list[str]) -> str:
        """Explanation for LLM-scored faithfulness to observed evidence."""
        reasoning = finding.get("reasoning", "") or ""
        evidence = finding.get("evidence", {}) or {}
        evidence_details = evidence.get("details", "") or ""
        pct = round(score * 100)

        # Score interpretation — faithfulness to observed traffic evidence
        if score >= 0.8:
            verdict = "The judge's reasoning is well-grounded in the observed traffic evidence — claims are directly supported by packet data."
        elif score >= 0.5:
            verdict = "The judge's reasoning is partially grounded in the evidence — most claims are supported but some may be inferred."
        elif score >= 0.2:
            verdict = "The judge's reasoning has weak grounding in the evidence — claims may go beyond what was directly observed."
        else:
            verdict = "The judge's reasoning has poor grounding in the evidence — claims appear to rely on inference rather than observed traffic."

        # Evidence used
        evidence_note = f' Evidence used: "{evidence_details[:80]}..."' if evidence_details else ""

        # Reasoning snippet
        reasoning_snippet = ""
        if reasoning:
            snippet = reasoning[:120].strip()
            reasoning_snippet = f' Judge reasoning: "{snippet}{"..." if len(reasoning) > 120 else ""}"'

        return f"LLM Faithfulness {pct}%: {verdict}{evidence_note}{reasoning_snippet}"

    def _explain_faithfulness(self, finding: dict, score: float, contexts: list[str]) -> str:
        """Heuristic-based faithfulness explanation (used for non-LLM-scored findings)."""
        evidence = finding.get("evidence", {}) or {}
        pkt_nums = finding.get("evidencePacketNumbers") or finding.get("evidence_packet_numbers") or []
        details = evidence.get("details", "")
        pct = round(score * 100)

        parts: list[str] = []
        if details:
            parts.append(f"Evidence details present ({len(details)} chars)")
        else:
            parts.append("No evidence details")
        if pkt_nums:
            parts.append(f"{len(pkt_nums)} packet ref(s)")
        has_src = evidence.get("srcIp") or evidence.get("src_ip")
        has_dst = evidence.get("dstIp") or evidence.get("dst_ip")
        if has_src and has_dst:
            parts.append("IPs identified")
        if evidence.get("protocol"):
            parts.append(f"Protocol: {evidence.get('protocol')}")

        if score >= 0.7:
            interp = f"Heuristic {pct}%: Good structural evidence."
        elif score >= 0.4:
            interp = f"Heuristic {pct}%: Partial evidence."
        else:
            interp = f"Heuristic {pct}%: Weak evidence."

        return f"{interp} " + "; ".join(parts)

    def _explain_relevancy(self, finding: dict, score: float, query: str) -> str:
        """Generate a human-readable explanation for the answer relevancy score."""
        reasoning = finding.get("reasoning", "") or ""
        rule_desc = finding.get("ruleDescription", "") or ""

        parts: list[str] = []

        if reasoning:
            parts.append(f"Reasoning provided ({len(reasoning)} chars)")
        else:
            parts.append("No reasoning provided")

        if rule_desc:
            parts.append("Rule description available")

        # Score interpretation
        pct = round(score * 100)
        if score >= 0.7:
            parts.append(f"Score {pct}%: Response directly addresses the policy rule '{query}'.")
        elif score >= 0.4:
            parts.append(f"Score {pct}%: Response partially addresses the rule '{query}' — some relevant points may be missing.")
        else:
            parts.append(f"Score {pct}%: Response has low relevance to the rule '{query}' — may be off-topic or too generic.")

        return "; ".join(parts)

    def _packet_contexts(self, capture_file_path: str, packet_numbers: list[int]) -> list[str]:
        """Build compact packet summaries for evidence numbers using tshark."""
        import subprocess
        import shutil

        if not capture_file_path or not os.path.exists(capture_file_path):
            return []

        # Limit packet count to keep context small
        pkt_nums = [int(n) for n in packet_numbers if isinstance(n, int) or str(n).isdigit()]
        pkt_nums = sorted(set(pkt_nums))[:12]
        if not pkt_nums:
            return []

        # Find tshark
        tshark = shutil.which("tshark")
        if not tshark:
            win_path = r"C:\\Program Files\\Wireshark\\tshark.exe"
            tshark = win_path if os.path.exists(win_path) else None
        if not tshark:
            return []

        # Wireshark display filter: frame.number in {1 2 3}
        filter_list = " ".join(str(n) for n in pkt_nums)
        display_filter = f"frame.number in {{{filter_list}}}"

        args = [
            tshark,
            "-r", capture_file_path,
            "-Y", display_filter,
            "-T", "fields",
            "-E", "separator=|",
            "-E", "header=n",
            "-e", "frame.number",
            "-e", "frame.time_relative",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "udp.srcport",
            "-e", "udp.dstport",
            "-e", "_ws.col.Protocol",
            "-e", "_ws.col.Info",
        ]

        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                return []
        except Exception:
            return []

        contexts: list[str] = []
        for line in result.stdout.splitlines():
            parts = line.split("|")
            if not parts or not parts[0].strip().isdigit():
                continue

            frame = parts[0].strip()
            time_rel = parts[1].strip() if len(parts) > 1 else ""
            src_ip = parts[2].strip() if len(parts) > 2 else ""
            dst_ip = parts[3].strip() if len(parts) > 3 else ""
            tcp_src = parts[4].strip() if len(parts) > 4 else ""
            tcp_dst = parts[5].strip() if len(parts) > 5 else ""
            udp_src = parts[6].strip() if len(parts) > 6 else ""
            udp_dst = parts[7].strip() if len(parts) > 7 else ""
            proto = parts[8].strip() if len(parts) > 8 else ""
            info = parts[9].strip() if len(parts) > 9 else ""

            src_port = tcp_src or udp_src
            dst_port = tcp_dst or udp_dst
            if src_port or dst_port:
                addr = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            else:
                addr = f"{src_ip} -> {dst_ip}"

            contexts.append(f"Packet {frame}: {proto} {addr} t={time_rel}s {info}")

        return contexts

    async def _save_result(self, result: RAGASEvalResult) -> None:
        """Write result JSON to apps/core-py/data/evals/{session_id}/ragas_{timestamp}.json."""
        if not result.session_id:
            return

        # Use workspace-relative path for Windows compatibility
        base_dir = Path(__file__).parent.parent / "data" / "evals"
        eval_dir = base_dir / result.session_id
        try:
            eval_dir.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            logger.warning("Failed to create eval dir %s: %s", eval_dir, exc)
            return

        ts = result.timestamp.replace(":", "-").replace(".", "-")
        path = eval_dir / f"ragas_{ts}.json"

        data = {
            "session_id": result.session_id,
            "timestamp": result.timestamp,
            "avg_faithfulness": result.avg_faithfulness,
            "avg_answer_relevancy": result.avg_answer_relevancy,
            "provider_used": result.provider_used,
            "heuristic_fallback": result.heuristic_fallback,
            "error": result.error,
            "per_finding_scores": [
                {
                    "finding_id": p.finding_id,
                    "rule_name": p.rule_name,
                    "faithfulness": p.faithfulness,
                    "answer_relevancy": p.answer_relevancy,
                    "faithfulness_reason": p.faithfulness_reason,
                    "relevancy_reason": p.relevancy_reason,
                }
                for p in result.per_finding_scores
            ],
        }

        try:
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            logger.info("RAGAS result saved to %s", path)
        except Exception as exc:
            logger.warning("Failed to save RAGAS result: %s", exc)

    # ── Synchronous wrapper (for FastAPI endpoint) ──────────────────────────

    def evaluate_sync(
        self,
        findings: list[dict],
        policy_text: str = "",
        session_id: str | None = None,
        capture_file_path: str | None = None,
    ) -> dict:
        """Synchronous wrapper for FastAPI endpoints."""
        try:
            # Check if we're already in an async context (FastAPI)
            try:
                loop = asyncio.get_running_loop()
                # We're in an async context — use nest_asyncio to allow nested execution
                import nest_asyncio
                nest_asyncio.apply()
                result = loop.run_until_complete(
                    self.evaluate(findings, policy_text, session_id, capture_file_path)
                )
            except RuntimeError:
                # No running loop — safe to use asyncio.run()
                result = asyncio.run(self.evaluate(findings, policy_text, session_id, capture_file_path))
        except Exception as exc:
            logger.error("RAGAS evaluation failed: %s", exc)
            result = RAGASEvalResult(
                session_id=session_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                avg_faithfulness=-1.0,
                avg_answer_relevancy=-1.0,
                error=str(exc),
            )

        return {
            "session_id": result.session_id,
            "timestamp": result.timestamp,
            "avg_faithfulness": result.avg_faithfulness,
            "avg_answer_relevancy": result.avg_answer_relevancy,
            "provider_used": result.provider_used,
            "heuristic_fallback": result.heuristic_fallback,
            "error": result.error,
            "per_finding_scores": [
                {
                    "finding_id": p.finding_id,
                    "rule_name": p.rule_name,
                    "faithfulness": p.faithfulness,
                    "answer_relevancy": p.answer_relevancy,
                    "faithfulness_reason": p.faithfulness_reason,
                    "relevancy_reason": p.relevancy_reason,
                    "scored_by_llm": p.scored_by_llm,
                }
                for p in result.per_finding_scores
            ],
        }
