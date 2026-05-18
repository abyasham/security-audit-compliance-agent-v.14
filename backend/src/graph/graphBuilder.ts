import { TsharkRunner } from '../services/tsharkRunner';
import { GraphStore } from './graphStore';
import { GraphNode, GraphEdge, NodeType, EdgeType } from './types';

/**
 * GraphBuilder — Converts pcap file into a LightRAG property graph.
 *
 * Uses tshark to extract:
 *   - Conversations (TCP/UDP) → IP nodes + CONNECTS edges
 *   - Protocol hierarchy → Protocol nodes + USES_PROTOCOL edges
 *   - Endpoint list → Port nodes + USES_PORT edges
 *   - Sample packets → Packet nodes + BELONGS_TO edges
 */
export class GraphBuilder {
  private tshark: TsharkRunner;

  constructor(tshark: TsharkRunner) {
    this.tshark = tshark;
  }

  /**
   * Build a complete traffic graph from a pcap file.
   * This is the main entry point called after pcap upload.
   */
  async buildFromPcap(filePath: string): Promise<GraphStore> {
    const store = new GraphStore();

    // Step 1: Get capture summary for metadata
    const summary = await this.tshark.getCaptureSummary(filePath);

    // Step 2: Build from TCP conversations
    const tcpConv = await this.tshark.getConversations(filePath, 'tcp');
    this.parseConversations(tcpConv, store, 'tcp');

    // Step 3: Build from UDP conversations
    const udpConv = await this.tshark.getConversations(filePath, 'udp');
    this.parseConversations(udpConv, store, 'udp');

    // Step 4: Build from IP conversations (catches ICMP, etc.)
    const ipConv = await this.tshark.getConversations(filePath, 'ip');
    this.parseConversations(ipConv, store, 'ip');

    // Step 5: Get protocol hierarchy and attach to streams
    const protoHierarchy = await this.tshark.getProtocolHierarchy(filePath);
    this.attachProtocols(store, protoHierarchy);

    // Step 6: Sample first N packets to build packet nodes
    await this.addSamplePackets(filePath, store, Math.min(summary.packetCount, 200));

    return store;
  }

  /**
   * Parse tshark conversation output into graph nodes and edges.
   * tshark -z conv,tcp output format:
   *   <-> 192.168.1.5:54321  <->  10.0.0.1:443    1234  2345  150.123  0.0012  42
   */
  private parseConversations(raw: string, store: GraphStore, protocol: string): void {
    const lines = raw.split('\n').map(l => l.replace(/\r$/, ''));
    let inTable = false;

    for (const line of lines) {
      // Detect table start/end
      if (line.includes('=======')) {
        inTable = !inTable;
        continue;
      }
      if (line.includes('Filter:') || line.includes('Conversations')) {
        inTable = true;
        continue;
      }
      if (!inTable) continue;
      if (line.trim() === '' || line.includes('Frames') || line.includes('Relative')) continue;

      // Parse conversation line using regex
      // Format: IP:PORT <-> IP:PORT framesA bytesA framesB bytesB totalFrames totalBytes start duration
      // Bytes may have units: kB, MB, bytes
      const match = line.match(/^(\S+:\d+)\s+<->\s+(\S+:\d+)\s+(.+)$/);
      if (!match) continue;

      const srcAddr = match[1].trim();
      const dstAddr = match[2].trim();
      const rest = match[3].trim();

      // Parse address:port
      const [srcIP, srcPort] = this.splitAddrPort(srcAddr);
      const [dstIP, dstPort] = this.splitAddrPort(dstAddr);

      // Parse the rest: extract all numbers, skipping unit words
      const tokens = rest.split(/\s+/);
      const numbers: number[] = [];
      for (let i = 0; i < tokens.length; i++) {
        const t = tokens[i];
        // Skip unit words
        if (t === 'kB' || t === 'MB' || t === 'bytes' || t === 'GB') continue;
        const n = parseFloat(t);
        if (!isNaN(n)) {
          numbers.push(n);
        }
      }

      // Expected: [framesA, bytesA, framesB, bytesB, totalFrames, totalBytes, start, duration]
      // But bytes may be merged with units, so we take what we can get
      const framesA = numbers[0] || 0;
      const bytesA = numbers[1] || 0;
      const framesB = numbers[2] || 0;
      const bytesB = numbers[3] || 0;
      const totalFrames = numbers[4] || (framesA + framesB);
      const totalBytes = numbers[5] || (bytesA + bytesB);
      const start = numbers[6] || 0;
      const duration = numbers[7] || 0;

      // Create IP nodes
      const srcNode: GraphNode = {
        id: `ip:${srcIP}`,
        type: 'ip',
        properties: { address: srcIP, zone: this.inferZone(srcIP) },
      };
      const dstNode: GraphNode = {
        id: `ip:${dstIP}`,
        type: 'ip',
        properties: { address: dstIP, zone: this.inferZone(dstIP) },
      };
      store.addNode(srcNode);
      store.addNode(dstNode);

      // Create Port nodes
      if (srcPort) {
        const srcPortNode: GraphNode = {
          id: `port:${srcPort}`,
          type: 'port',
          properties: { number: parseInt(srcPort), service: this.inferService(parseInt(srcPort)) },
        };
        store.addNode(srcPortNode);
      }
      if (dstPort) {
        const dstPortNode: GraphNode = {
          id: `port:${dstPort}`,
          type: 'port',
          properties: { number: parseInt(dstPort), service: this.inferService(parseInt(dstPort)) },
        };
        store.addNode(dstPortNode);
      }

      // Create Stream node
      const streamId = `stream:${protocol}:${srcIP}:${srcPort}-${dstIP}:${dstPort}`;
      const streamNode: GraphNode = {
        id: streamId,
        type: 'stream',
        properties: {
          protocol,
          srcIP,
          dstIP,
          srcPort: parseInt(srcPort) || 0,
          dstPort: parseInt(dstPort) || 0,
          packetCount: totalFrames,
          byteCount: totalBytes,
          duration,
          start,
        },
      };
      store.addNode(streamNode);

      // CONNECTS edge (IP to IP, via stream)
      const connectsEdge: GraphEdge = {
        id: `conn:${srcIP}-${dstIP}:${protocol}:${srcPort}-${dstPort}`,
        type: 'connects',
        source: srcNode.id,
        target: dstNode.id,
        properties: {
          protocol,
          srcPort: parseInt(srcPort) || 0,
          dstPort: parseInt(dstPort) || 0,
          packetCount: totalFrames,
          byteCount: totalBytes,
          duration,
          streamId,
        },
      };
      store.addEdge(connectsEdge);

      // USES_PORT edges (Stream → Port)
      if (srcPort) {
        store.addEdge({
          id: `uses_port:${streamId}:src:${srcPort}`,
          type: 'uses_port',
          source: streamId,
          target: `port:${srcPort}`,
          properties: { direction: 'src' },
        });
      }
      if (dstPort) {
        store.addEdge({
          id: `uses_port:${streamId}:dst:${dstPort}`,
          type: 'uses_port',
          source: streamId,
          target: `port:${dstPort}`,
          properties: { direction: 'dst' },
        });
      }

      // INITIATES edge (who started — heuristic: lower port is usually server, higher is client)
      // This is a weak heuristic; better to use packet timing
      store.addEdge({
        id: `initiates:${srcNode.id}:${streamId}`,
        type: 'initiates',
        source: srcNode.id,
        target: streamId,
        properties: {},
      });
    }
  }

  /** Attach protocol information to streams */
  private attachProtocols(store: GraphStore, protoHierarchy: string): void {
    const lines = protoHierarchy.split('\n').map(l => l.replace(/\r$/, ''));
    for (const line of lines) {
      if (!line.includes('Protocol') && !line.includes('├─') && !line.includes('└─')) continue;
      // Parse protocol hierarchy lines
      const match = line.match(/[├└]─\s*(\w+)\s+\d+/);
      if (match) {
        const protoName = match[1].toLowerCase();
        const protoNode: GraphNode = {
          id: `protocol:${protoName}`,
          type: 'protocol',
          properties: { name: protoName },
        };
        // Only add if not exists
        if (!store.getNode(protoNode.id)) {
          store.addNode(protoNode);
        }
      }
    }
  }

  /** Add sample packet nodes to the graph */
  private async addSamplePackets(filePath: string, store: GraphStore, count: number): Promise<void> {
    const batchSize = 100;
    for (let start = 1; start <= count; start += batchSize) {
      const end = Math.min(start + batchSize - 1, count);
      try {
        const raw = await this.tshark.getPacketRange(filePath, start, end);
        this.parsePacketBatch(raw, store);
      } catch {
        // Skip batch on error
      }
    }
  }

  /** Parse packet range output into Packet nodes */
  private parsePacketBatch(raw: string, store: GraphStore): void {
    const lines = raw.split('\n').map(l => l.replace(/\r$/, '')).filter(l => l.trim());
    for (const line of lines) {
      const parts = line.split('\t');
      if (parts.length < 6) continue;

      const frameNum = parts[0];
      const time = parts[1];
      const srcIP = parts[2];
      const dstIP = parts[3];
      const proto = parts[4];
      const info = parts.slice(5).join(' ');

      const packetId = `packet:${frameNum}`;
      const packetNode: GraphNode = {
        id: packetId,
        type: 'packet',
        properties: {
          frameNumber: parseInt(frameNum),
          timeRelative: parseFloat(time),
          srcIP,
          dstIP,
          protocol: proto,
          info,
        },
      };
      store.addNode(packetNode);

      // Link packet to stream (find stream by src/dst match)
      const streamId = this.findStreamForPacket(store, srcIP, dstIP, proto);
      if (streamId) {
        store.addEdge({
          id: `belongs_to:${packetId}:${streamId}`,
          type: 'belongs_to',
          source: packetId,
          target: streamId,
          properties: {},
        });
        store.addEdge({
          id: `has_packet:${streamId}:${packetId}`,
          type: 'has_packet',
          source: streamId,
          target: packetId,
          properties: {},
        });
      }
    }
  }

  /** Find a stream that matches a packet's src/dst/protocol */
  private findStreamForPacket(store: GraphStore, srcIP: string, dstIP: string, protocol: string): string | undefined {
    const streams = store.getNodesByType('stream');
    for (const stream of streams) {
      const p = stream.properties;
      if ((p.srcIP === srcIP && p.dstIP === dstIP) || (p.srcIP === dstIP && p.dstIP === srcIP)) {
        if (p.protocol === protocol || protocol.toLowerCase().includes(p.protocol)) {
          return stream.id;
        }
      }
    }
    return undefined;
  }

  /** Split address:port string */
  private splitAddrPort(addr: string): [string, string] {
    // Handle IPv6 brackets: [2001:db8::1]:443
    if (addr.startsWith('[')) {
      const match = addr.match(/\[(.+?)\]:(\d+)/);
      if (match) return [match[1], match[2]];
      return [addr, ''];
    }
    // IPv4: 192.168.1.1:443
    const lastColon = addr.lastIndexOf(':');
    if (lastColon > 0) {
      return [addr.substring(0, lastColon), addr.substring(lastColon + 1)];
    }
    return [addr, ''];
  }

  /** Infer network zone from IP address */
  private inferZone(ip: string): string {
    if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.match(/^172\.(1[6-9]|2\d|3[01])\./)) {
      return 'internal';
    }
    if (ip === '127.0.0.1' || ip === '::1') {
      return 'loopback';
    }
    if (ip.startsWith('0.') || ip === '0.0.0.0') {
      return 'unspecified';
    }
    // Check for multicast
    if (ip.startsWith('224.') || ip.startsWith('239.') || ip.startsWith('ff')) {
      return 'multicast';
    }
    return 'external';
  }

  /** Infer service name from port number */
  private inferService(port: number): string {
    const services: Record<number, string> = {
      20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet',
      25: 'smtp', 53: 'dns', 80: 'http', 110: 'pop3',
      143: 'imap', 443: 'https', 445: 'smb', 3306: 'mysql',
      3389: 'rdp', 5432: 'postgresql', 6379: 'redis',
      8080: 'http-alt', 8443: 'https-alt',
    };
    return services[port] || 'unknown';
  }
}
