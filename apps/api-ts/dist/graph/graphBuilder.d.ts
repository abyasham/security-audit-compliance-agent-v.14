import { TsharkRunner } from '../services/tsharkRunner';
import { GraphStore } from './graphStore';
/**
 * GraphBuilder — Converts pcap file into a LightRAG property graph.
 *
 * Uses tshark to extract:
 *   - Conversations (TCP/UDP) → IP nodes + CONNECTS edges
 *   - Protocol hierarchy → Protocol nodes + USES_PROTOCOL edges
 *   - Endpoint list → Port nodes + USES_PORT edges
 *   - Sample packets → Packet nodes + BELONGS_TO edges
 */
export declare class GraphBuilder {
    private tshark;
    constructor(tshark: TsharkRunner);
    /**
     * Build a complete traffic graph from a pcap file.
     * This is the main entry point called after pcap upload.
     */
    buildFromPcap(filePath: string): Promise<GraphStore>;
    /**
     * Parse tshark conversation output into graph nodes and edges.
     * tshark -z conv,tcp output format:
     *   <-> 192.168.1.5:54321  <->  10.0.0.1:443    1234  2345  150.123  0.0012  42
     */
    private parseConversations;
    /** Attach protocol information to streams */
    private attachProtocols;
    /** Add sample packet nodes to the graph */
    private addSamplePackets;
    /** Parse packet range output into Packet nodes */
    private parsePacketBatch;
    /** Find a stream that matches a packet's src/dst/protocol */
    private findStreamForPacket;
    /** Split address:port string */
    private splitAddrPort;
    /** Infer network zone from IP address */
    private inferZone;
    /** Infer service name from port number */
    private inferService;
}
//# sourceMappingURL=graphBuilder.d.ts.map