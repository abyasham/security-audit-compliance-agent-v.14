"""
NetworkAgent — Agent 2 of the SACA Multi-Agent Architecture (port from TypeScript).

Analyzes pcap files using pyshark + LiteLLM and produces a structured traffic report.
5 core detectors: SYN scan, brute force, UDP floods, ARP spoofing, DNS hijacking/tunneling.
Plus: OS fingerprinting, Mirai signatures, session hijacking, Log4Shell, web app attacks.
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections import defaultdict
from typing import Any

import pyshark

from schema.models import (
    NetworkAgentOutput,
    StreamAnomaly,
    StreamAnomalyType,
    TcpStream,
    CaptureSummary,
    ExpertInfoSummary,
    ExpertInfoEntry,
    ExpertInfoSeverity,
)

logger = logging.getLogger(__name__)

# ─── Output dataclasses (lightweight, converted to Pydantic at boundary) ────

from dataclasses import dataclass, field


@dataclass
class SynScanIndicator:
    src_ip: str
    dst_ip: str
    dst_port: int
    syn_count: int
    retransmit_count: int
    packet_numbers: list[int]
    first_seen: float
    last_seen: float
    description: str


@dataclass
class BruteForceIndicator:
    src_ip: str
    dst_ip: str
    dst_port: int
    attempt_count: int
    packet_numbers: list[int]
    unique_src_ports: int
    first_seen: float
    last_seen: float
    description: str


@dataclass
class TrafficAnomaly:
    type: str
    packet_numbers: list[int] = field(default_factory=list)
    stream_id: int | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    description: str = ""
    severity: str = "medium"
    confidence: float = 0.7
    payload_evidence: bool = False


@dataclass
class TrafficConversation:
    streamId: int
    protocol: str
    srcIp: str
    dstIp: str
    srcPort: int = 0
    dstPort: int = 0
    packetRange: str = ""
    packetCount: int = 0
    totalBytes: int = 0
    notes: str = ""


@dataclass
class TrafficProtocolInsight:
    protocol: str
    packet_count: int
    percentage: float
    notes: str


# ─── Agent ──────────────────────────────────────────────────────────────────


class NetworkAgent:
    """Analyzes a pcap file with pyshark and returns NetworkAgentOutput."""

    # Known public DNS servers (for hijacking detection)
    KNOWN_PUBLIC_DNS: set[str] = {
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
        "9.9.9.9", "208.67.222.222", "208.67.220.220",
    }

    # Brute-force target ports
    BRUTE_FORCE_PORTS: list[int] = [22, 23, 80, 443, 3389, 5432, 3306, 9999, 1340]

    # Suspicious TLDs for DNS detection
    SUSPICIOUS_TLD_RE = re.compile(
        r"\.(wiki|xyz|top|club|win|click|space|site|online|store"
        r"|review|download|racing|loan|stream|ninja|zone|world"
        r"|today|press|rest|host|icu|casa|bar|uno|best|bid)\b",
        re.IGNORECASE,
    )

    def __init__(self, llm_gateway=None):
        self.llm = llm_gateway  # injected LiteLLM gateway

    # ─── Public API ─────────────────────────────────────────────────────

    def analyze(self, file_path: str, llm_config: dict | None = None) -> NetworkAgentOutput:
        """Run the full analysis pipeline and return structured output."""
        # pyshark needs its own event loop context when running in threads
        import asyncio
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        except RuntimeError:
            pass  # Already have a loop

        cap = pyshark.FileCapture(file_path, keep_packets=False)

        # Phase 1: Gather data
        summary = self._gather_summary(cap)
        conversations = self._gather_conversations(cap)
        expert_info = self._gather_expert_info(cap)
        protocol_insights = self._build_protocol_insights(summary)

        # Phase 1b: Detectors
        syn_scans = self._detect_syn_scans(cap)
        brute_force = self._detect_brute_force(cap)
        arp_spoofing = self._detect_arp_spoofing(cap)
        udp_floods = self._detect_udp_floods(cap)
        os_fingerprinting = self._detect_os_fingerprinting(cap)
        dns_hijacking = self._detect_dns_hijacking(cap)
        dns_tunneling = self._detect_dns_tunneling(cap)
        session_hijacking = self._detect_session_hijacking(cap)
        log4shell = self._detect_log4shell(cap)
        web_app_attacks = self._detect_web_app_attacks(cap)
        mirai = self._detect_mirai_signatures(syn_scans, brute_force, udp_floods)

        cap.close()

        # Phase 2: LLM anomaly detection (requires re-open with full payload)
        llm_anomalies = self._identify_anomalies_with_llm(
            file_path, conversations, expert_info, syn_scans, brute_force, llm_config
        )

        # Phase 3: TLS / HTTP counts
        tls_versions = self._detect_tls_versions(file_path)
        http_requests = self._count_http_requests(file_path)
        plaintext_auth = self._detect_plaintext_auth(file_path, conversations)

        # Merge all anomalies
        all_anomalies: list[TrafficAnomaly] = []
        all_anomalies.extend(self._syn_scans_to_anomalies(syn_scans))
        all_anomalies.extend(self._brute_force_to_anomalies(brute_force))
        all_anomalies.extend(arp_spoofing)
        all_anomalies.extend(udp_floods)
        all_anomalies.extend(os_fingerprinting)
        all_anomalies.extend(dns_hijacking)
        all_anomalies.extend(dns_tunneling)
        all_anomalies.extend(session_hijacking)
        all_anomalies.extend(log4shell)
        all_anomalies.extend(web_app_attacks)
        all_anomalies.extend(mirai)
        all_anomalies.extend(llm_anomalies)

        file_name = os.path.basename(file_path)

        return NetworkAgentOutput(
            conversations=[
                TcpStream(
                    index=getattr(c, "streamId", getattr(c, "stream_id", 0)),
                    source=getattr(c, "srcIp", getattr(c, "src_ip", "")),
                    destination=getattr(c, "dstIp", getattr(c, "dst_ip", "")),
                    packetCount=getattr(c, "packetCount", getattr(c, "packet_count", 0)),
                    totalBytes=getattr(c, "totalBytes", getattr(c, "total_bytes", 0)),
                    durationSeconds=0,
                    appProtocol=getattr(c, "protocol", ""),
                    anomalies=[],
                    anomalyScore=0,
                    captureFileId=file_name,
                )
                for c in conversations
            ],
            anomalies=[
                StreamAnomaly(
                    type=StreamAnomalyType(a.type) if a.type in StreamAnomalyType.__members__.values() else StreamAnomalyType.MALFORMED,
                    count=len(a.packet_numbers),
                    description=a.description,
                    packetNumbers=a.packet_numbers,
                )
                for a in all_anomalies
            ],
            protocolInsights=[insight.notes or insight.protocol for insight in protocol_insights],
            synScanIndicators=[s.description for s in syn_scans],
            bruteForceIndicators=[b.description for b in brute_force],
            summary=summary,
        )

    # ─── Phase 1: Data Gathering ────────────────────────────────────────

    def _gather_summary(self, cap) -> CaptureSummary:
        """Extract capture summary from pyshark capture."""
        packets = list(cap)
        if not packets:
            return CaptureSummary(
                totalPackets=0, durationSeconds=0, protocolBreakdown={},
                tcpStreamCount=0, udpStreamCount=0,
                startTime="", endTime="",
            )

        total = len(packets)
        proto_counts: dict[str, int] = defaultdict(int)
        tcp_count = udp_count = 0

        for pkt in packets:
            proto = pkt.highest_layer or "UNKNOWN"
            proto_counts[proto] += 1
            if hasattr(pkt, "tcp"):
                tcp_count += 1
            if hasattr(pkt, "udp"):
                udp_count += 1

        try:
            start_time = str(packets[0].sniff_time) if packets[0].sniff_time else ""
            end_time = str(packets[-1].sniff_time) if packets[-1].sniff_time else ""
            duration = (packets[-1].sniff_timestamp - packets[0].sniff_timestamp) if (
                hasattr(packets[-1], "sniff_timestamp") and hasattr(packets[0], "sniff_timestamp")
            ) else 0
        except Exception:
            start_time = end_time = ""
            duration = 0

        return CaptureSummary(
            totalPackets=total,
            durationSeconds=round(duration, 3),
            protocolBreakdown=dict(proto_counts),
            tcpStreamCount=tcp_count,
            udpStreamCount=udp_count,
            startTime=start_time,
            endTime=end_time,
        )

    def _gather_conversations(self, cap) -> list[TrafficConversation]:
        """Aggregate TCP/UDP conversations from pyshark packets."""
        # We do a simple aggregation; pyshark's FileCapture is single-pass so
        # we iterate once and bucket by (proto, src_ip, dst_ip, src_port, dst_port).
        agg: dict[str, dict] = defaultdict(lambda: {"count": 0, "bytes": 0})

        for pkt in cap:
            try:
                src = pkt.ip.src
                dst = pkt.ip.dst
            except AttributeError:
                continue

            proto: str = "tcp" if hasattr(pkt, "tcp") else "udp"
            try:
                src_port = int(getattr(pkt, proto).srcport)
                dst_port = int(getattr(pkt, proto).dstport)
            except Exception:
                continue

            key = f"{proto}:{src}:{src_port}->{dst}:{dst_port}"
            entry = agg[key]
            entry["count"] += 1
            try:
                entry["bytes"] += int(pkt.length)
            except Exception:
                pass
            entry.setdefault("proto", proto)
            entry.setdefault("src_ip", src)
            entry.setdefault("dst_ip", dst)
            entry.setdefault("src_port", src_port)
            entry.setdefault("dst_port", dst_port)

        results: list[TrafficConversation] = []
        for idx, (_, v) in enumerate(
            sorted(agg.items(), key=lambda kv: kv[1]["count"], reverse=True)[:300]
        ):
            results.append(TrafficConversation(
                streamId=idx,
                protocol=v["proto"],
                srcIp=v["src_ip"],
                dstIp=v["dst_ip"],
                srcPort=v["src_port"],
                dstPort=v["dst_port"],
                packetRange="",
                packetCount=v["count"],
                totalBytes=v["bytes"],
                notes="",
            ))
        return results

    def _gather_expert_info(self, cap) -> ExpertInfoSummary:
        """Count expert info levels from pyshark."""
        errors = warnings = notes = chats = 0
        entries: list[ExpertInfoEntry] = []

        for pkt in cap:
            # pyshark exposes expert info via _ws_expert fields when available
            try:
                severity = pkt._ws_expert_severity
                group = getattr(pkt, "_ws_expert_group", "")
                msg = getattr(pkt, "_ws_expert_message", "")
                proto = pkt.highest_layer or ""
                pkt_num = int(pkt.number)
            except AttributeError:
                continue

            sev_map = {
                "error": ExpertInfoSeverity.ERROR,
                "warn": ExpertInfoSeverity.WARNING,
                "note": ExpertInfoSeverity.NOTE,
                "chat": ExpertInfoSeverity.CHAT,
            }
            mapped = sev_map.get(severity, ExpertInfoSeverity.NOTE)
            if mapped == ExpertInfoSeverity.ERROR:
                errors += 1
            elif mapped == ExpertInfoSeverity.WARNING:
                warnings += 1
            elif mapped == ExpertInfoSeverity.NOTE:
                notes += 1
            else:
                chats += 1

            entries.append(ExpertInfoEntry(
                severity=mapped, group=group, message=msg,
                packetNumber=pkt_num, protocol=proto,
            ))

        return ExpertInfoSummary(
            errors=errors, warnings=warnings, notes=notes, chats=chats, details=entries,
        )

    def _build_protocol_insights(self, summary: CaptureSummary) -> list[TrafficProtocolInsight]:
        breakdown = summary.protocol_breakdown or {}
        total = summary.total_packets or 1
        entries = sorted(breakdown.items(), key=lambda x: x[1], reverse=True)[:10]
        insights: list[TrafficProtocolInsight] = []
        for proto, cnt in entries:
            pct = round((cnt / total) * 100, 1)
            note = ""
            if proto == "HTTP" and cnt > 0:
                note = "Plaintext HTTP detected"
            elif proto == "TELNET" and cnt > 0:
                note = "Insecure telnet detected"
            elif proto == "FTP" and cnt > 0:
                note = "Plaintext FTP detected"
            elif proto in ("TLS", "SSL") and cnt > 0:
                note = "Encrypted TLS traffic"
            insights.append(TrafficProtocolInsight(
                protocol=proto, packet_count=cnt, percentage=pct, notes=note,
            ))
        return insights

    # ─── Phase 1b: Detectors ────────────────────────────────────────────

    def _detect_syn_scans(self, cap) -> list[SynScanIndicator]:
        """Detect SYN scans (SYN without ACK, incomplete handshakes)."""
        syn_map: dict[str, dict] = defaultdict(lambda: {"count": 0, "frames": [], "src_ports": set()})

        for pkt in cap:
            try:
                if hasattr(pkt, "tcp") and pkt.tcp.flags_syn == "1" and pkt.tcp.flags_ack == "0":
                    src = pkt.ip.src
                    dst = pkt.ip.dst
                    dst_port = int(pkt.tcp.dstport)
                    src_port = int(pkt.tcp.srcport)
                    frame_num = int(pkt.number)
                else:
                    continue
            except (AttributeError, ValueError):
                continue

            key = f"{src}|{dst}|{dst_port}"
            entry = syn_map[key]
            entry["count"] += 1
            if len(entry["frames"]) < 20:
                entry["frames"].append(frame_num)
            entry["src_ports"].add(src_port)

        indicators: list[SynScanIndicator] = []
        for key_str, data in syn_map.items():
            if data["count"] < 3:
                continue
            src, dst, port_str = key_str.split("|")
            dst_port = int(port_str)
            frames = data["frames"]
            indicators.append(SynScanIndicator(
                src_ip=src, dst_ip=dst, dst_port=dst_port,
                syn_count=data["count"],
                retransmit_count=len(frames) - 1 if len(frames) > 1 else 0,
                packet_numbers=frames,
                first_seen=frames[0] if frames else 0,
                last_seen=frames[-1] if frames else 0,
                description=(
                    f"{data['count']} SYN packets (no handshake) from {src} to {dst}:{dst_port}. "
                    f"{'Multiple source ports suggest scanning.' if len(data['src_ports']) > 3 else 'Retransmissions suggest automated retry.'}"
                ),
            ))

        indicators.sort(key=lambda x: x.syn_count, reverse=True)
        logger.info("SYN scan detection: %d indicators", len(indicators))
        return indicators

    def _detect_brute_force(self, cap) -> list[BruteForceIndicator]:
        """Detect brute-force patterns via repeated SYN to auth ports."""
        all_indicators: list[BruteForceIndicator] = []

        for port in self.BRUTE_FORCE_PORTS:
            attempt_map: dict[str, dict] = defaultdict(
                lambda: {"count": 0, "frames": [], "src_ports": set()}
            )

            for pkt in cap:
                try:
                    if (
                        hasattr(pkt, "tcp")
                        and int(pkt.tcp.dstport) == port
                        and pkt.tcp.flags_syn == "1"
                    ):
                        src = pkt.ip.src
                        dst = pkt.ip.dst
                        src_port = int(pkt.tcp.srcport)
                        frame_num = int(pkt.number)
                    else:
                        continue
                except (AttributeError, ValueError):
                    continue

                key = f"{src}|{dst}|{port}"
                entry = attempt_map[key]
                entry["count"] += 1
                if len(entry["frames"]) < 20:
                    entry["frames"].append(frame_num)
                entry["src_ports"].add(src_port)

            for key_str, data in attempt_map.items():
                if data["count"] < 5:
                    continue
                src, dst, _ = key_str.split("|")
                frames = data["frames"]
                all_indicators.append(BruteForceIndicator(
                    src_ip=src, dst_ip=dst, dst_port=port,
                    attempt_count=data["count"],
                    packet_numbers=frames,
                    unique_src_ports=len(data["src_ports"]),
                    first_seen=frames[0] if frames else 0,
                    last_seen=frames[-1] if frames else 0,
                    description=(
                        f"{data['count']} attempts from {src} to {dst}:{port}. "
                        f"{'Many source ports indicate brute-force/spraying.' if len(data['src_ports']) > 5 else 'Repeated attempts indicate automated attack.'}"
                    ),
                ))

        all_indicators.sort(key=lambda x: x.attempt_count, reverse=True)
        logger.info("Brute force detection: %d indicators", len(all_indicators))
        return all_indicators

    def _syn_scans_to_anomalies(self, scans: list[SynScanIndicator]) -> list[TrafficAnomaly]:
        results: list[TrafficAnomaly] = []
        for s in scans:
            sev = "critical" if s.syn_count > 50 else "high" if s.syn_count > 20 else "medium"
            conf = min(0.95, 0.6 + s.syn_count * 0.01)
            results.append(TrafficAnomaly(
                type="syn_scan",
                src_ip=s.src_ip,
                dst_ip=s.dst_ip,
                dst_port=s.dst_port,
                packet_numbers=s.packet_numbers,
                description=s.description,
                severity=sev,
                confidence=conf,
            ))
        return results

    def _brute_force_to_anomalies(self, bfs: list[BruteForceIndicator]) -> list[TrafficAnomaly]:
        results: list[TrafficAnomaly] = []
        for b in bfs:
            type_map = {22: "ssh_brute_force", 23: "telnet_brute_force", 3389: "rdp_brute_force", 9999: "suspicious_port_scan"}
            atype = type_map.get(b.dst_port, "brute_force")
            sev = "critical" if b.attempt_count > 100 else "high" if b.attempt_count > 30 else "medium"
            conf = min(0.95, 0.65 + b.attempt_count * 0.003)
            results.append(TrafficAnomaly(
                type=atype,
                src_ip=b.src_ip,
                dst_ip=b.dst_ip,
                dst_port=b.dst_port,
                packet_numbers=b.packet_numbers,
                description=b.description,
                severity=sev,
                confidence=conf,
            ))
        return results

    def _detect_arp_spoofing(self, cap) -> list[TrafficAnomaly]:
        """Detect ARP spoofing: one IP mapped to multiple MACs."""
        ip_to_macs: dict[str, dict[str, list[int]]] = defaultdict(lambda: defaultdict(list))
        ip_reply_counts: dict[str, int] = defaultdict(int)

        for pkt in cap:
            try:
                if not hasattr(pkt, "arp"):
                    continue
                frame = int(pkt.number)
                opcode = pkt.arp.opcode
                src_ip = pkt.arp.src_proto_ipv4
                src_mac = pkt.arp.src_hw_mac.lower()
                dst_ip = getattr(pkt.arp, "dst_proto_ipv4", "")
                dst_mac = getattr(pkt.arp, "dst_hw_mac", "").lower()
            except (AttributeError, ValueError):
                continue

            if len(ip_to_macs[src_ip][src_mac]) < 20:
                ip_to_macs[src_ip][src_mac].append(frame)

            if opcode == "2":
                ip_reply_counts[src_ip] += 1
            if opcode == "2" and dst_ip and src_ip == dst_ip and dst_mac != "00:00:00:00:00:00":
                ip_reply_counts[src_ip] += 1

        anomalies: list[TrafficAnomaly] = []
        for ip_addr, mac_map in ip_to_macs.items():
            if len(mac_map) < 2:
                continue
            macs = list(mac_map.keys())
            packet_numbers = [f for frames in mac_map.values() for f in frames[:30]]
            replies = ip_reply_counts.get(ip_addr, 0)

            anomalies.append(TrafficAnomaly(
                type="arp_spoofing",
                src_ip=ip_addr,
                packet_numbers=packet_numbers[:30],
                description=(
                    f"ARP spoofing: IP {ip_addr} → multiple MACs ({', '.join(macs)}). "
                    f"{f'ARP replies: {replies}.' if replies else ''}"
                ).strip(),
                severity="critical" if replies > 20 else "high" if replies > 5 else "medium",
                confidence=0.9 if replies > 20 else 0.8 if replies > 5 else 0.7,
                payload_evidence=True,
            ))
        return anomalies

    def _detect_udp_floods(self, cap) -> list[TrafficAnomaly]:
        """Detect high-volume UDP floods (Mirai-style)."""
        buckets: dict[str, dict] = defaultdict(lambda: {"count": 0, "packets": []})
        by_source: dict[str, dict] = defaultdict(lambda: {"count": 0, "packets": [], "targets": set()})

        for pkt in cap:
            try:
                if not hasattr(pkt, "udp"):
                    continue
                src_ip = pkt.ip.src
                dst_ip = pkt.ip.dst
                src_port = pkt.udp.srcport
                dst_port = pkt.udp.dstport
                frame = int(pkt.number)
            except (AttributeError, ValueError):
                continue

            # Skip mDNS to avoid noise
            if dst_ip == "224.0.0.251" or dst_port == "5353" or src_port == "5353":
                continue

            key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            entry = buckets[key]
            entry["count"] += 1
            if len(entry["packets"]) < 50:
                entry["packets"].append(frame)

            src_agg = by_source[src_ip]
            src_agg["count"] += 1
            if len(src_agg["packets"]) < 80:
                src_agg["packets"].append(frame)
            src_agg["targets"].add(f"{dst_ip}:{dst_port}")

        anomalies: list[TrafficAnomaly] = []
        for key_str, entry in buckets.items():
            if entry["count"] < 120:
                continue
            src_part, dst_part = key_str.split("->")
            src_ip, src_port_str = src_part.rsplit(":", 1)
            dst_ip, dst_port_str = dst_part.rsplit(":", 1)
            anomalies.append(TrafficAnomaly(
                type="udp_flood",
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=int(dst_port_str) if dst_port_str.isdigit() else None,
                packet_numbers=entry["packets"],
                description=f"UDP flood: {entry['count']} packets {src_ip}:{src_port_str} → {dst_ip}:{dst_port_str}.",
                severity="critical" if entry["count"] > 1000 else "high",
                confidence=0.9 if entry["count"] > 1000 else 0.75,
            ))

        for src_ip, entry in by_source.items():
            if entry["count"] < 400 or len(entry["targets"]) < 8:
                continue
            anomalies.append(TrafficAnomaly(
                type="udp_burst_multi_target",
                src_ip=src_ip,
                packet_numbers=entry["packets"],
                description=f"UDP burst: {entry['count']} pkts → {len(entry['targets'])} targets from {src_ip}.",
                severity="critical" if entry["count"] > 1500 else "high",
                confidence=0.92 if entry["count"] > 1500 else 0.8,
            ))

        return anomalies

    def _detect_os_fingerprinting(self, cap) -> list[TrafficAnomaly]:
        """Detect OS fingerprinting via diverse SYN option signatures."""
        by_pair: dict[str, dict] = defaultdict(
            lambda: {"signatures": defaultdict(list), "ports": set(), "frames": []}
        )

        for pkt in cap:
            try:
                if not (hasattr(pkt, "tcp") and pkt.tcp.flags_syn == "1" and pkt.tcp.flags_ack == "0"):
                    continue
                src = pkt.ip.src
                dst = pkt.ip.dst
                frame = int(pkt.number)
                dst_port = pkt.tcp.dstport
                ttl = getattr(pkt.ip, "ttl", "")
                win = getattr(pkt.tcp, "window_size_value", "")
                mss = getattr(pkt.tcp.options, "mss_val", "")
                wscale = getattr(pkt.tcp.options, "wscale_shift", "")
                sack = "1" if getattr(pkt.tcp.options, "sack_perm", "0") == "1" else "0"
                ts = "1" if getattr(pkt.tcp.options, "timestamp", "") else "0"
            except (AttributeError, ValueError):
                continue

            sig = f"{ttl}|{win}|{mss}|{wscale}|{sack}|{ts}"
            key = f"{src}->{dst}"
            entry = by_pair[key]
            entry["ports"].add(dst_port)
            if len(entry["frames"]) < 60:
                entry["frames"].append(frame)
            sig_frames = entry["signatures"][sig]
            if len(sig_frames) < 10:
                sig_frames.append(frame)

        anomalies: list[TrafficAnomaly] = []
        for pair_str, entry in by_pair.items():
            if len(entry["signatures"]) < 4 or len(entry["ports"]) < 2:
                continue
            src, dst = pair_str.split("->")
            anomalies.append(TrafficAnomaly(
                type="os_fingerprinting",
                src_ip=src,
                dst_ip=dst,
                packet_numbers=entry["frames"],
                description=f"OS fingerprinting: {len(entry['signatures'])} signatures across {len(entry['ports'])} ports from {src} → {dst}.",
                severity="high" if len(entry["signatures"]) >= 6 else "medium",
                confidence=min(0.92, 0.65 + len(entry["signatures"]) * 0.04),
            ))
        return anomalies

    def _detect_dns_hijacking(self, cap) -> list[TrafficAnomaly]:
        """Detect DNS hijacking, rogue responders, NXDOMAIN spikes."""
        query_log: dict[str, dict] = defaultdict(lambda: {"responders": set(), "answers": defaultdict(list), "frames": []})
        responder_counts: dict[str, dict] = defaultdict(lambda: {"count": 0, "frames": []})
        device_responders: dict[str, dict] = defaultdict(lambda: {"count": 0, "frames": [], "targets": set(), "query_names": set()})
        mdnss_frames: list[int] = []
        suspicious_domains: list[str] = []
        nxdomain_frames: list[int] = []

        for pkt in cap:
            try:
                if not hasattr(pkt, "dns"):
                    continue
                frame = int(pkt.number)
                src_ip = pkt.ip.src
                dst_ip = pkt.ip.dst
                is_resp = getattr(pkt.dns, "flags_response", "0") == "1"
                rcode = int(getattr(pkt.dns, "flags_rcode", 0) or 0)
                qry_name = getattr(pkt.dns, "qry_name", "") or ""
                # DNS answers
                answers_raw = ""
                try:
                    if hasattr(pkt.dns, "a"):
                        answers_raw = pkt.dns.a
                except Exception:
                    pass
            except (AttributeError, ValueError):
                continue

            # mDNS
            if dst_ip == "224.0.0.251" or src_ip == "224.0.0.251":
                mdnss_frames.append(frame)
                continue

            # NXDOMAIN
            if is_resp and rcode != 0:
                nxdomain_frames.append(frame)

            # Suspicious TLDs
            if qry_name and self.SUSPICIOUS_TLD_RE.search(qry_name):
                suspicious_domains.append(qry_name)

            if is_resp and qry_name:
                rec = query_log[qry_name]
                rec["responders"].add(src_ip)
                rec["frames"].append(frame)
                ans_list = [a.strip() for a in answers_raw.split(",") if a.strip()] if answers_raw else []
                for ans in ans_list:
                    if len(rec["answers"][ans]) < 10:
                        rec["answers"][ans].append(frame)

            if is_resp:
                rc = responder_counts[src_ip]
                rc["count"] += 1
                if len(rc["frames"]) < 50:
                    rc["frames"].append(frame)

            if is_resp and src_ip != "192.168.137.1" and src_ip not in self.KNOWN_PUBLIC_DNS and not src_ip.startswith("224."):
                dr = device_responders[src_ip]
                dr["count"] += 1
                if len(dr["frames"]) < 50:
                    dr["frames"].append(frame)
                if dst_ip:
                    dr["targets"].add(dst_ip)
                if qry_name:
                    dr["query_names"].add(qry_name)

        anomalies: list[TrafficAnomaly] = []

        # 1) Rogue DNS servers (>=30 responses)
        for ip_addr, rec in responder_counts.items():
            if ip_addr in self.KNOWN_PUBLIC_DNS or ip_addr == "192.168.137.1" or ip_addr.startswith("224."):
                continue
            if rec["count"] < 30:
                continue
            anomalies.append(TrafficAnomaly(
                type="dns_rogue_responder",
                src_ip=ip_addr,
                packet_numbers=rec["frames"][:30],
                description=f"Rogue DNS: {ip_addr} sent {rec['count']} responses.",
                severity="critical" if rec["count"] > 100 else "high",
                confidence=min(0.92, 0.65 + rec["count"] * 0.001),
                payload_evidence=True,
            ))

        # 2) Device-level responders (>=5 responses)
        for ip_addr, rec in device_responders.items():
            if rec["count"] < 5:
                continue
            anomalies.append(TrafficAnomaly(
                type="dns_unauthorized_device_responder",
                src_ip=ip_addr,
                packet_numbers=rec["frames"][:30],
                description=f"Device {ip_addr} serving DNS to {len(rec['targets'])} targets, {len(rec['query_names'])} domains ({rec['count']} responses).",
                severity="critical" if rec["count"] > 20 else "high",
                confidence=min(0.88, 0.65 + rec["count"] * 0.005),
                payload_evidence=True,
            ))

        # 3) Inconsistent answers per query
        for qry_name, rec in query_log.items():
            if len(rec["responders"]) >= 2 and len(rec["answers"]) >= 2:
                ans_ips = list(rec["answers"].keys())[:10]
                anomalies.append(TrafficAnomaly(
                    type="dns_answer_inconsistency",
                    packet_numbers=rec["frames"][:20],
                    description=f"DNS inconsistency: '{qry_name}' answered by {len(rec['responders'])} sources with {len(rec['answers'])} IP sets ({', '.join(ans_ips)}).",
                    severity="high",
                    confidence=0.85,
                    payload_evidence=True,
                ))

        # 4) mDNS storm (>500)
        if len(mdnss_frames) > 500:
            anomalies.append(TrafficAnomaly(
                type="mdns_multicast_flood",
                packet_numbers=mdnss_frames[:30],
                description=f"mDNS flood: {len(mdnss_frames)} frames to 224.0.0.251.",
                severity="high" if len(mdnss_frames) > 2000 else "medium",
                confidence=min(0.85, 0.6 + len(mdnss_frames) * 0.00005),
            ))

        # 5) NXDOMAIN spike (>50)
        if len(nxdomain_frames) > 50:
            anomalies.append(TrafficAnomaly(
                type="dns_nxdomain_spike",
                packet_numbers=nxdomain_frames[:20],
                description=f"NXDOMAIN spike: {len(nxdomain_frames)} errors.",
                severity="high" if len(nxdomain_frames) > 100 else "medium",
                confidence=min(0.82, 0.55 + len(nxdomain_frames) * 0.001),
            ))

        # 6) Suspicious domains (>=8 unique)
        unique_sus = list(set(suspicious_domains))
        if len(unique_sus) >= 8:
            anomalies.append(TrafficAnomaly(
                type="dns_suspicious_domains",
                description=f"Suspicious domains: {', '.join(unique_sus[:15])}{'...' if len(unique_sus) > 15 else ''} ({len(unique_sus)} total).",
                severity="high" if len(unique_sus) > 15 else "medium",
                confidence=min(0.85, 0.55 + len(unique_sus) * 0.02),
                payload_evidence=True,
            ))

        logger.info("DNS hijacking: %d anomalies", len(anomalies))
        return anomalies

    def _detect_dns_tunneling(self, cap) -> list[TrafficAnomaly]:
        """Detect DNS tunneling via long queries, TXT records, subdomain diversity."""
        by_pair: dict[str, dict] = defaultdict(
            lambda: {"count": 0, "long_count": 0, "txt_count": 0, "frames": [], "base_domains": defaultdict(set)}
        )

        for pkt in cap:
            try:
                if not (hasattr(pkt, "dns") and getattr(pkt.dns, "flags_response", "0") == "0"):
                    continue
                frame = int(pkt.number)
                src = pkt.ip.src
                dst = pkt.ip.dst
                qry = (getattr(pkt.dns, "qry_name", "") or "").lower()
                qtype = getattr(pkt.dns, "qry_type", "") or ""
                qlen = int(getattr(pkt.dns, "qry_name_len", 0) or 0)
            except (AttributeError, ValueError):
                continue

            if not qry:
                continue

            labels = qry.split(".")
            base = ".".join(labels[-2:]) if len(labels) >= 2 else qry
            sub = ".".join(labels[:-2]) if len(labels) > 2 else ""

            key = f"{src}->{dst}"
            entry = by_pair[key]
            entry["count"] += 1
            if qlen >= 45:
                entry["long_count"] += 1
            if qtype == "16":
                entry["txt_count"] += 1
            if len(entry["frames"]) < 80:
                entry["frames"].append(frame)
            if sub:
                entry["base_domains"][base].add(sub)

        anomalies: list[TrafficAnomaly] = []
        for pair_str, entry in by_pair.items():
            src, dst = pair_str.split("->")
            suspicious_bases = sorted(
                [(b, len(s)) for b, s in entry["base_domains"].items() if len(s) >= 20],
                key=lambda x: x[1], reverse=True,
            )
            has_long = entry["count"] >= 80 and entry["long_count"] >= 30
            has_txt = entry["txt_count"] >= 15 and entry["count"] >= 40
            if not has_long and not has_txt and not suspicious_bases:
                continue

            top_base = suspicious_bases[0] if suspicious_bases else ("n/a", 0)
            anomalies.append(TrafficAnomaly(
                type="dns_tunneling",
                src_ip=src,
                dst_ip=dst,
                dst_port=53,
                packet_numbers=entry["frames"],
                description=(
                    f"DNS tunneling from {src} → {dst}: {entry['count']} queries, "
                    f"{entry['long_count']} long, {entry['txt_count']} TXT"
                    f"{f', {top_base[1]} subdomains under {top_base[0]}' if top_base[0] != 'n/a' else ''}."
                ),
                severity="high" if entry["count"] > 200 or (top_base[1] if top_base[0] != "n/a" else 0) > 50 else "medium",
                confidence=min(0.88, 0.55 + entry["long_count"] * 0.004 + (top_base[1] if top_base[0] != "n/a" else 0) * 0.006 + entry["txt_count"] * 0.003),
                payload_evidence=True,
            ))
        return anomalies

    def _detect_session_hijacking(self, cap) -> list[TrafficAnomaly]:
        """Detect session hijacking via token reuse across IPs."""
        token_usage: dict[str, dict] = defaultdict(lambda: {"src_ips": set(), "dst_ips": set(), "frames": [], "sample_uris": []})

        for pkt in cap:
            try:
                if not (hasattr(pkt, "http") and (hasattr(pkt.http, "cookie") or hasattr(pkt.http, "authorization"))):
                    continue
                frame = int(pkt.number)
                src = pkt.ip.src
                dst = pkt.ip.dst
                host = getattr(pkt.http, "host", "") or ""
                uri = getattr(pkt.http, "request_uri", "") or ""
                cookie = getattr(pkt.http, "cookie", "") or ""
                auth = getattr(pkt.http, "authorization", "") or ""
            except (AttributeError, ValueError):
                continue

            candidates: list[str] = []
            for m in re.finditer(r"(?:PHPSESSID|JSESSIONID|ASP\.NET_SessionId|sessionid|sid|token|auth_token)=([^;\s]+)", cookie):
                candidates.append(m.group(1))

            auth_match = re.match(r"^(Basic|Bearer)\s+([A-Za-z0-9+\/=._-]{12,})", auth, re.IGNORECASE)
            if auth_match:
                candidates.append(f"{auth_match.group(1).lower()}:{auth_match.group(2)}")

            for token in candidates:
                scoped = f"{host or dst}|{token}"
                tu = token_usage[scoped]
                tu["src_ips"].add(src)
                tu["dst_ips"].add(dst)
                if len(tu["frames"]) < 40:
                    tu["frames"].append(frame)
                if uri and len(tu["sample_uris"]) < 6:
                    tu["sample_uris"].append(uri)

        anomalies: list[TrafficAnomaly] = []
        for scoped, usage in token_usage.items():
            if len(usage["src_ips"]) < 2:
                continue
            scope, token_val = scoped.split("|", 1)
            srcs = list(usage["src_ips"])
            label = token_val[:36] + "..." if len(token_val) > 36 else token_val
            anomalies.append(TrafficAnomaly(
                type="session_hijacking",
                src_ip=srcs[0],
                dst_ip=list(usage["dst_ips"])[0],
                packet_numbers=usage["frames"],
                description=f"Session hijacking: token {label} reused by {', '.join(srcs)} against {scope}.",
                severity="critical" if len(usage["src_ips"]) >= 3 else "high",
                confidence=0.92 if len(usage["src_ips"]) >= 3 else 0.84,
                payload_evidence=True,
            ))
        return anomalies

    def _detect_log4shell(self, cap) -> list[TrafficAnomaly]:
        """Detect Log4Shell/JNDI exploitation patterns."""
        anomalies: list[TrafficAnomaly] = []

        for pkt in cap:
            try:
                frame = int(pkt.number)
            except (AttributeError, ValueError):
                continue

            # LDAP callback on port 1389
            try:
                if hasattr(pkt, "tcp") and int(pkt.tcp.dstport) == 1389:
                    anomalies.append(TrafficAnomaly(
                        type="log4shell_ldap_callback",
                        src_ip=pkt.ip.src,
                        dst_ip=pkt.ip.dst,
                        dst_port=1389,
                        packet_numbers=[frame],
                        description=f"Log4Shell: LDAP callback on port 1389 from {pkt.ip.src}.",
                        severity="critical",
                        confidence=0.95,
                        payload_evidence=True,
                    ))
                    continue
            except Exception:
                pass

            # JNDI patterns in HTTP URIs
            try:
                if hasattr(pkt, "http") and hasattr(pkt.http, "request_uri"):
                    uri = pkt.http.request_uri or ""
                    if "${jndi:" in uri.lower() or "${" in uri and "jndi" in uri.lower():
                        anomalies.append(TrafficAnomaly(
                            type="log4shell_jndi_injection",
                            src_ip=pkt.ip.src,
                            dst_ip=pkt.ip.dst,
                            packet_numbers=[frame],
                            description=f"Log4Shell: JNDI injection in URI: {uri[:200]}",
                            severity="critical",
                            confidence=0.98,
                            payload_evidence=True,
                        ))
            except Exception:
                pass

        return anomalies

    def _detect_web_app_attacks(self, cap) -> list[TrafficAnomaly]:
        """Detect directory traversal, XSS, SQLi in HTTP URIs."""
        anomalies: list[TrafficAnomaly] = []

        traversal_re = re.compile(r"\.\.%2[fF]|\.\.%5[cC]|\.\./|\.\.\\|/etc/passwd|/etc/shadow|/[cC]:\\")
        xss_re = re.compile(r"<script>|javascript:|%3Cscript%3E|alert\(|onerror=|onload=")
        sqli_re = re.compile(r"' OR |UNION SELECT|DROP TABLE|1=1--|admin'--|%27")

        for pkt in cap:
            try:
                if not hasattr(pkt, "http") or not hasattr(pkt.http, "request_uri"):
                    continue
                frame = int(pkt.number)
                uri = (pkt.http.request_uri or "").lower()
                src = pkt.ip.src
                dst = pkt.ip.dst
            except (AttributeError, ValueError):
                continue

            if traversal_re.search(uri):
                anomalies.append(TrafficAnomaly(
                    type="directory_traversal",
                    src_ip=src, dst_ip=dst,
                    packet_numbers=[frame],
                    description=f"Directory traversal in packet {frame}: {uri[:200]}",
                    severity="critical", confidence=0.95,
                ))
            elif xss_re.search(uri):
                anomalies.append(TrafficAnomaly(
                    type="xss_attack",
                    src_ip=src, dst_ip=dst,
                    packet_numbers=[frame],
                    description=f"XSS in packet {frame}: {uri[:200]}",
                    severity="critical", confidence=0.95,
                ))
            elif sqli_re.search(uri):
                anomalies.append(TrafficAnomaly(
                    type="sqli_attack",
                    src_ip=src, dst_ip=dst,
                    packet_numbers=[frame],
                    description=f"SQLi in packet {frame}: {uri[:200]}",
                    severity="critical", confidence=0.95,
                ))

        return anomalies

    def _detect_mirai_signatures(
        self,
        syn_scans: list[SynScanIndicator],
        brute_force: list[BruteForceIndicator],
        udp_floods: list[TrafficAnomaly],
    ) -> list[TrafficAnomaly]:
        """Correlate detectors for Mirai botnet signature."""
        telnet_ips = {b.src_ip for b in brute_force if b.dst_port in (23, 2323, 48101)}
        recon_ips = {s.src_ip for s in syn_scans if s.syn_count >= 20}
        udp_ips = {a.src_ip for a in udp_floods if a.type in ("udp_flood", "udp_burst_multi_target") and a.src_ip}

        candidates = set(telnet_ips) | set(udp_ips)
        anomalies: list[TrafficAnomaly] = []
        for ip_addr in candidates:
            has_telnet = ip_addr in telnet_ips
            has_udp = ip_addr in udp_ips
            has_recon = ip_addr in recon_ips
            score = sum([has_telnet, has_udp, has_recon])
            if score < 2:
                continue
            anomalies.append(TrafficAnomaly(
                type="mirai_botnet",
                src_ip=ip_addr,
                description=(
                    f"Mirai signature for {ip_addr}: "
                    f"{'telnet brute-force; ' if has_telnet else ''}"
                    f"{'SYN recon; ' if has_recon else ''}"
                    f"{'UDP flood' if has_udp else ''}"
                ).strip(),
                severity="critical" if score >= 3 else "high",
                confidence=0.93 if score >= 3 else 0.82,
            ))
        return anomalies

    # ─── Phase 2: LLM Anomaly Detection ────────────────────────────────

    def _identify_anomalies_with_llm(
        self,
        file_path: str,
        conversations: list[TrafficConversation],
        expert_info: ExpertInfoSummary,
        syn_scans: list[SynScanIndicator],
        brute_force: list[BruteForceIndicator],
        llm_config: dict | None = None,
    ) -> list[TrafficAnomaly]:
        """Use LLM to identify additional anomalies from packet context."""
        if not self.llm:
            logger.warning("No LLM gateway — skipping LLM anomaly detection")
            return []

        # Build packet context (simplified — HTTP URIs only via pyshark)
        packet_ctx = self._build_packet_context(file_path, conversations, syn_scans, brute_force)

        prompt_data = {
            "conversationCount": len(conversations),
            "topConversations": [
                {"protocol": c.protocol, "srcIp": c.srcIp, "dstIp": c.dstIp,
                 "dstPort": c.dstPort, "packetCount": c.packetCount, "notes": c.notes}
                for c in conversations[:15]
            ],
            "synScanCount": len(syn_scans),
            "topSynScans": [
                {"srcIp": s.src_ip, "dstIp": s.dst_ip, "dstPort": s.dst_port,
                 "synCount": s.syn_count}
                for s in syn_scans[:5]
            ],
            "bruteForceCount": len(brute_force),
            "topBruteForce": [
                {"srcIp": b.src_ip, "dstIp": b.dst_ip, "dstPort": b.dst_port,
                 "attemptCount": b.attempt_count}
                for b in brute_force[:5]
            ],
            "expertErrors": expert_info.errors,
            "expertWarnings": expert_info.warnings,
            "packetData": packet_ctx[:30000],
        }

        system_prompt = """You are a Network Analyzer Agent for security compliance.
Output STRICT JSON array of anomalies. No markdown.

Each anomaly: type, packetNumbers (array), srcIp, dstIp, dstPort, description (with evidence), severity (critical/high/medium/low/info), confidence (0.0-1.0).

ATTACK PATTERNS:
1. Directory Traversal: ../, ..%2F, /etc/passwd
2. XSS: <script>, javascript:, %3Cscript%3E
3. SQL Injection: ' OR, UNION SELECT, 1=1--
4. DNS rogue responders, hijacking, tunneling
5. Plaintext credentials, weak TLS
6. Data exfiltration, DGA domains
7. Command injection

If no anomalies found, return []."""

        user_prompt = f"""Identify anomalies from:

PACKET DATA:
{packet_ctx[:30000]}

TRAFFIC SUMMARY:
{json.dumps(prompt_data, indent=2)}

Return ONLY JSON array."""

        try:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ]
            response = self.llm.chat(messages, config=llm_config)
            return self._parse_llm_anomalies(response)
        except Exception as exc:
            logger.error("LLM anomaly detection failed: %s", exc)
            return []

    def _build_packet_context(
        self,
        file_path: str,
        conversations: list[TrafficConversation],
        syn_scans: list[SynScanIndicator],
        brute_force: list[BruteForceIndicator],
        max_packets: int = 300,
    ) -> str:
        """Build a context string of HTTP/DNS/suspicious packets for LLM."""
        sections: list[str] = []

        # Re-open capture for detailed inspection
        try:
            cap = pyshark.FileCapture(file_path, keep_packets=False,
                                      display_filter="http.request || dns")
            http_lines: list[str] = []
            dns_lines: list[str] = []

            for i, pkt in enumerate(cap):
                if i >= max_packets:
                    break
                try:
                    fn = pkt.number
                    src = pkt.ip.src
                    dst = pkt.ip.dst
                except AttributeError:
                    continue

                if hasattr(pkt, "http") and hasattr(pkt.http, "request_method"):
                    method = pkt.http.request_method
                    host = getattr(pkt.http, "host", "") or ""
                    uri = getattr(pkt.http, "request_uri", "") or ""
                    ua = getattr(pkt.http, "user_agent", "") or ""
                    http_lines.append(
                        f"[{fn}] {src} → {dst} | {method} {uri}"
                        f"{' | Host:' + host if host else ''}"
                        f"{' | UA:' + ua[:80] if ua else ''}"
                    )
                elif hasattr(pkt, "dns"):
                    qry = getattr(pkt.dns, "qry_name", "") or ""
                    is_resp = getattr(pkt.dns, "flags_response", "0") == "1"
                    a = getattr(pkt.dns, "a", "") or ""
                    dns_lines.append(
                        f"[{fn}] {'RESP' if is_resp else 'QUERY'} {src} → {dst} | Q:{qry}"
                        f"{' | A:' + a if a else ''}"
                    )

            cap.close()

            if http_lines:
                sections.append(f"=== HTTP REQUESTS ({len(http_lines)}) ===\n" + "\n".join(http_lines))
            if dns_lines:
                sections.append(f"=== DNS TRAFFIC ({len(dns_lines)}) ===\n" + "\n".join(dns_lines))
        except Exception as exc:
            logger.warning("Packet context build failed: %s", exc)

        return "\n\n".join(sections) if sections else "(No packet data available)"

    def _parse_llm_anomalies(self, content: str) -> list[TrafficAnomaly]:
        """Parse LLM JSON output into TrafficAnomaly list."""
        if isinstance(content, dict):
            content = content.get("content", "")
        json_text = content.strip()
        # Extract JSON array
        fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", json_text)
        if fence:
            json_text = fence.group(1).strip()
        start = json_text.find("[")
        end = json_text.rfind("]")
        if start != -1 and end != -1 and end > start:
            json_text = json_text[start:end + 1]

        try:
            data = json.loads(json_text)
            if not isinstance(data, list):
                return []
        except json.JSONDecodeError:
            return []

        results: list[TrafficAnomaly] = []
        for a in data:
            results.append(TrafficAnomaly(
                type=a.get("type", "unknown"),
                src_ip=a.get("srcIp", a.get("src_ip")),
                dst_ip=a.get("dstIp", a.get("dst_ip")),
                dst_port=a.get("dstPort", a.get("dst_port")),
                packet_numbers=a.get("packetNumbers", a.get("packet_numbers", [])),
                description=a.get("description", ""),
                severity=a.get("severity", "medium") if a.get("severity") in ("critical", "high", "medium", "low", "info") else "medium",
                confidence=min(1, max(0, a.get("confidence", 0.7))),
            ))
        return results

    # ─── Phase 3: TLS / HTTP Counts ─────────────────────────────────────

    def _detect_tls_versions(self, file_path: str) -> list[str]:
        """Detect TLS versions from handshake packets."""
        versions: set[str] = set()
        try:
            cap = pyshark.FileCapture(file_path, keep_packets=False, display_filter="tls.handshake.version")
            for pkt in cap:
                try:
                    ver = pkt.tls.handshake_version
                    ver_map = {
                        "0x0301": "TLS 1.0", "0x0302": "TLS 1.1",
                        "0x0303": "TLS 1.2", "0x0304": "TLS 1.3",
                    }
                    if ver in ver_map:
                        versions.add(ver_map[ver])
                except AttributeError:
                    pass
            cap.close()
        except Exception:
            pass
        return sorted(versions)

    def _count_http_requests(self, file_path: str) -> int:
        """Count HTTP request packets."""
        count = 0
        try:
            cap = pyshark.FileCapture(file_path, keep_packets=False, display_filter="http.request")
            count = sum(1 for _ in cap)
            cap.close()
        except Exception:
            pass
        return count

    def _detect_plaintext_auth(self, file_path: str, conversations) -> int:
        """Count streams with actual plaintext credential transmission.

        Only counts streams with:
        - HTTP Basic Authorization header, OR
        - HTTP POST to auth-related endpoints (login, signin, auth, password), OR
        - FTP/Telnet traffic (inherently plaintext auth protocols)

        Does NOT count general HTTP traffic or cookies — those are not auth evidence.
        """
        count = 0
        try:
            # Check for HTTP Basic Auth headers (explicit credential transmission)
            cap = pyshark.FileCapture(
                file_path, keep_packets=False,
                display_filter='http.authorization contains "Basic"'
            )
            streams: set[int] = set()
            for pkt in cap:
                try:
                    streams.add(int(pkt.tcp.stream))
                except (AttributeError, ValueError):
                    pass
            cap.close()

            # Check for HTTP POST to auth-related paths
            cap2 = pyshark.FileCapture(
                file_path, keep_packets=False,
                display_filter='http.request.method == "POST"'
            )
            for pkt in cap2:
                try:
                    uri = str(getattr(pkt.http, "request_uri", "")).lower()
                    if any(k in uri for k in ("login", "signin", "sign-in", "auth", "password", "passwd", "credential")):
                        streams.add(int(pkt.tcp.stream))
                except (AttributeError, ValueError):
                    pass
            cap2.close()

            count = len(streams)
        except Exception:
            pass
        return count
