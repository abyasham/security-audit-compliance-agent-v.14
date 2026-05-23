"""
Standalone runner for NetworkAgent — called as a subprocess to avoid asyncio conflicts.
Usage: python network_agent_runner.py <pcap_file_path>
Output: JSON to stdout
"""
import json
import sys
import os

# Add parent dir to path so imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No file path provided"}), file=sys.stderr)
        sys.exit(1)
    
    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        print(json.dumps({"error": f"File not found: {file_path}"}), file=sys.stderr)
        sys.exit(1)
    
    try:
        from agents.network_agent import NetworkAgent
        
        agent = NetworkAgent()
        result = agent.analyze(file_path)
        
        # Manual serialization to handle Pydantic models
        output = {
            "conversations": [
                {
                    "index": c.index,
                    "source": c.source,
                    "destination": c.destination,
                    "packetCount": c.packet_count,
                    "totalBytes": c.total_bytes,
                    "durationSeconds": c.duration_seconds,
                    "appProtocol": c.app_protocol,
                    "anomalies": [],
                    "anomalyScore": c.anomaly_score,
                    "captureFileId": c.capture_file_id,
                }
                for c in result.conversations
            ],
            "anomalies": [
                {
                    "type": a.type.value if hasattr(a.type, 'value') else str(a.type),
                    "count": a.count,
                    "description": a.description,
                    "packetNumbers": a.packet_numbers,
                }
                for a in result.anomalies
            ],
            "protocolInsights": result.protocol_insights,
            "synScanIndicators": result.syn_scan_indicators,
            "bruteForceIndicators": result.brute_force_indicators,
            "summary": {
                "totalPackets": result.summary.total_packets if result.summary else 0,
                "durationSeconds": result.summary.duration_seconds if result.summary else 0,
                "protocolBreakdown": result.summary.protocol_breakdown if result.summary else {},
                "tcpStreamCount": result.summary.tcp_stream_count if result.summary else 0,
                "udpStreamCount": result.summary.udp_stream_count if result.summary else 0,
                "startTime": result.summary.start_time if result.summary else "",
                "endTime": result.summary.end_time if result.summary else "",
            } if result.summary else None,
        }
        print(json.dumps(output))
    except Exception as e:
        import traceback
        print(json.dumps({"error": str(e), "traceback": traceback.format_exc()}), file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
