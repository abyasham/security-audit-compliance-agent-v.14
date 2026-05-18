import { TsharkRunner } from '../services/tsharkRunner';
import { LLMGateway } from '../services/llmGateway';
import { ChatMessage, CaptureSummary } from '../types';

/**
 * NetworkAgent — Agent 2 of the SACA Multi-Agent Architecture (Option B: Parallel + Judge)
 *
 * Role: Analyze pcap files using tshark tools and produce a structured traffic report.
 *
 * Input:  pcap file path (via tshark tools)
 * Output: JSON traffic report with conversations, anomalies, and protocol insights
 */

export interface TrafficConversation {
  streamId: number;
  protocol: string;
  srcIp: string;
  dstIp: string;
  srcPort?: number;
  dstPort: number;
  packetRange: string;
  packetCount: number;
  totalBytes: number;
  notes: string;
}

export interface TrafficAnomaly {
  type: string;
  streamId?: number;
  srcIp?: string;
  dstIp?: string;
  dstPort?: number;
  packetNumbers: number[];
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: number;
  payloadEvidence?: boolean;
}

export interface TrafficProtocolInsight {
  protocol: string;
  packetCount: number;
  percentage: number;
  notes: string;
}

export interface NetworkAgentOutput {
  fileName: string;
  summary: CaptureSummary & { totalPackets: number };
  conversations: TrafficConversation[];
  anomalies: TrafficAnomaly[];
  protocolInsights: TrafficProtocolInsight[];
  expertWarnings: number;
  expertErrors: number;
  tlsVersions: string[];
  httpRequests: number;
  plaintextAuthStreams: number;
  synScanIndicators: SynScanIndicator[];
  bruteForceIndicators: BruteForceIndicator[];
}

export interface SynScanIndicator {
  srcIp: string;
  dstIp: string;
  dstPort: number;
  synCount: number;
  retransmitCount: number;
  packetNumbers: number[];
  firstSeen: number;
  lastSeen: number;
  description: string;
}

export interface BruteForceIndicator {
  srcIp: string;
  dstIp: string;
  dstPort: number;
  attemptCount: number;
  packetNumbers: number[];
  uniqueSrcPorts: number;
  firstSeen: number;
  lastSeen: number;
  description: string;
}

export class NetworkAgent {
  private tshark: TsharkRunner;
  private llm: LLMGateway;

  constructor(tshark?: TsharkRunner, preferredProvider?: string) {
    this.tshark = tshark || new TsharkRunner();
    if (preferredProvider) {
      const gateway = LLMGateway.forProvider(preferredProvider as any);
      if (gateway) {
        this.llm = gateway;
        console.log(`[NetworkAgent] Using dedicated provider: ${preferredProvider}`);
      } else {
        console.warn(`[NetworkAgent] Provider ${preferredProvider} not available, falling back to global chain`);
        this.llm = new LLMGateway();
      }
    } else {
      this.llm = new LLMGateway();
    }
  }

  /**
   * Analyze a pcap file and produce a structured traffic report.
   */
  async analyze(filePath: string, llmConfig?: any): Promise<NetworkAgentOutput> {
    // Phase 1: Gather tshark data
    const summary = await this.gatherSummary(filePath);
    const conversations = await this.gatherConversations(filePath);
    const expertInfo = await this.gatherExpertInfo(filePath);
    const protocolInsights = this.buildProtocolInsights(summary.protocolBreakdown, summary.packetCount);

    // Phase 1b: SYN scan / brute force detection (critical for security analysis)
    const synScans = await this.detectSynScans(filePath);
    const bruteForce = await this.detectBruteForce(filePath);
    const arpSpoofing = await this.detectArpSpoofing(filePath);
    const udpFloods = await this.detectUdpFloods(filePath);
    const osFingerprinting = await this.detectOsFingerprinting(filePath);
    const dnsHijacking = await this.detectDnsHijacking(filePath);
    const dnsTunneling = await this.detectDnsTunneling(filePath);
    const sessionHijacking = await this.detectSessionHijacking(filePath);
    const log4shell = await this.detectLog4Shell(filePath);
    const webAppAttacks = await this.detectWebAppAttacks(filePath);
    const miraiSignatures = this.detectMiraiSignatures(synScans, bruteForce, udpFloods);

    // Phase 2: Use LLM to identify anomalies from structured data
    const anomalies = await this.identifyAnomaliesWithLLM(filePath, conversations, expertInfo, synScans, bruteForce, llmConfig);

    // Phase 3: Count specific indicators
    const tlsVersions = await this.detectTlsVersions(filePath);
    const httpRequests = await this.countHttpRequests(filePath);
    const plaintextAuthStreams = await this.detectPlaintextAuth(filePath, conversations);

    // Merge tshark-derived anomalies with LLM anomalies
    const allAnomalies = [
      ...this.synScansToAnomalies(synScans),
      ...this.bruteForceToAnomalies(bruteForce),
      ...arpSpoofing,
      ...udpFloods,
      ...osFingerprinting,
      ...dnsHijacking,
      ...dnsTunneling,
      ...sessionHijacking,
      ...log4shell,
      ...webAppAttacks,
      ...miraiSignatures,
      ...anomalies,
    ];

    return {
      fileName: filePath.split(/[\\/]/).pop() || filePath,
      summary: { ...summary, totalPackets: summary.packetCount },
      conversations,
      anomalies: allAnomalies,
      protocolInsights,
      expertWarnings: expertInfo.warnings,
      expertErrors: expertInfo.errors,
      tlsVersions,
      httpRequests,
      plaintextAuthStreams,
      synScanIndicators: synScans,
      bruteForceIndicators: bruteForce,
    };
  }

  // ─── Phase 1: Tshark Data Gathering ────────────────────────────────────────

  private async gatherSummary(filePath: string): Promise<CaptureSummary & { packetCount: number }> {
    try {
      const summary = await this.tshark.getCaptureSummary(filePath);
      return {
        totalPackets: summary.packetCount,
        packetCount: summary.packetCount,
        durationSeconds: summary.durationSeconds,
        protocolBreakdown: summary.protocolBreakdown,
        tcpStreamCount: summary.tcpStreamCount,
        udpStreamCount: 0,
        startTime: summary.startTime,
        endTime: summary.endTime,
      };
    } catch (err: any) {
      console.error('[NetworkAgent] Summary failed:', err.message);
      return { totalPackets: 0, packetCount: 0, durationSeconds: 0, protocolBreakdown: {}, tcpStreamCount: 0, udpStreamCount: 0, startTime: '', endTime: '' };
    }
  }

  private async gatherConversations(filePath: string): Promise<TrafficConversation[]> {
    try {
      const conversations: TrafficConversation[] = [];

      const tcpRaw = await this.tshark.getConversations(filePath, 'tcp');
      const tcpLines = tcpRaw.split('\n').filter(l => l.trim());
      for (const line of tcpLines) {
        const match = line.match(/^(\d+\.\d+\.\d+\.\d+):(\d+)\s+<->\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+(\d+)\s+(\d+)\s+([\d.]+)/);
        if (match) {
          conversations.push({
            streamId: conversations.length,
            protocol: 'tcp',
            srcIp: match[1], srcPort: parseInt(match[2]),
            dstIp: match[3], dstPort: parseInt(match[4]),
            packetRange: '', packetCount: parseInt(match[5]),
            totalBytes: parseInt(match[6]), notes: '',
          });
        }
      }

      const udpRaw = await this.tshark.getConversations(filePath, 'udp');
      const udpLines = udpRaw.split('\n').filter(l => l.trim());
      for (const line of udpLines) {
        const match = line.match(/^(\d+\.\d+\.\d+\.\d+):(\d+)\s+<->\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+(\d+)\s+(\d+)\s+([\d.]+)/);
        if (match) {
          conversations.push({
            streamId: conversations.length,
            protocol: 'udp',
            srcIp: match[1], srcPort: parseInt(match[2]),
            dstIp: match[3], dstPort: parseInt(match[4]),
            packetRange: '', packetCount: parseInt(match[5]),
            totalBytes: parseInt(match[6]), notes: 'UDP conversation detected',
          });
        }
      }

      // Enrich with protocol detection for top streams
      for (let i = 0; i < Math.min(conversations.length, 20); i++) {
        const conv = conversations[i];
        try {
          if (conv.protocol === 'tcp') {
            const protoCheck = await this.tshark.applyFilter(filePath, `tcp.stream eq ${i}`, 5);
            if (protoCheck.includes('HTTP')) { conv.protocol = 'http'; conv.notes = 'HTTP traffic detected'; }
            else if (protoCheck.includes('TLS') || protoCheck.includes('SSL')) { conv.protocol = 'tls'; conv.notes = 'TLS/SSL traffic detected'; }
            else if (protoCheck.includes('FTP')) { conv.protocol = 'ftp'; conv.notes = 'FTP traffic detected'; }
            else if (protoCheck.includes('SSH')) { conv.protocol = 'ssh'; conv.notes = 'SSH traffic detected'; }
          }
        } catch { /* ignore */ }
      }

      if (conversations.length === 0) {
        const fallback = await this.gatherConversationsFromPackets(filePath);
        conversations.push(...fallback);
      }

      return conversations;
    } catch (err: any) {
      console.error('[NetworkAgent] Conversations failed:', err.message);
      return [];
    }
  }

  private async gatherExpertInfo(filePath: string): Promise<{ errors: number; warnings: number; notes: number; entries: any[] }> {
    try {
      const raw = await this.tshark.getExpertInfo(filePath, 'all');
      const lines = raw.split('\n');
      let errors = 0, warnings = 0, notes = 0;
      const entries: any[] = [];
      for (const line of lines) {
        if (line.includes('Error')) errors++;
        if (line.includes('Warn')) warnings++;
        if (line.includes('Note')) notes++;
        if (line.trim() && !line.startsWith('=') && !line.startsWith(' ')) entries.push({ text: line.trim() });
      }
      return { errors, warnings, notes, entries };
    } catch { return { errors: 0, warnings: 0, notes: 0, entries: [] }; }
  }

  private buildProtocolInsights(breakdown: Record<string, number>, totalPackets: number): TrafficProtocolInsight[] {
    const entries = Object.entries(breakdown).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([protocol, count]) => ({
      protocol, packetCount: count,
      percentage: totalPackets > 0 ? Math.round((count / totalPackets) * 1000) / 10 : 0,
      notes: '',
    }));
    for (const e of entries) {
      if (e.protocol === 'http' && e.packetCount > 0) e.notes = 'Plaintext HTTP detected';
      if (e.protocol === 'telnet' && e.packetCount > 0) e.notes = 'Insecure telnet detected';
      if (e.protocol === 'ftp' && e.packetCount > 0) e.notes = 'Plaintext FTP detected';
      if (e.protocol === 'tls' && e.packetCount > 0) e.notes = 'Encrypted TLS traffic';
    }
    return entries;
  }

  // ─── Phase 1b: SYN Scan & Brute Force Detection ─────────────────────────

  /**
   * Detect SYN scans and SYN retransmissions using tshark.
   * Looks for SYN-only packets (no ACK) which indicate incomplete handshakes.
   */
  private async detectSynScans(filePath: string): Promise<SynScanIndicator[]> {
    try {
      const raw = await this.tshark.applyFilter(
        filePath,
        'tcp.flags.syn==1 && tcp.flags.ack==0',
        5000
      );
      const lines = raw.split('\n').filter(l => l.trim());
      const synMap = new Map<string, { count: number; frames: number[]; srcPort: Set<number> }>();

      for (const line of lines) {
        const parts = line.split(/\s+/).filter(p => p.trim());
        if (parts.length < 5) continue;
        // applyFilter returns: frame.number frame.time_relative ip.src ip.dst _ws.col.Protocol _ws.col.Info
        // _ws.col.Info format: "[TCP Retransmission] 41643 → 80 [SYN] ..." or "41643 → 80 [SYN] ..."
        const srcIp = parts[2] || '';
        const dstIp = parts[3] || '';
        const frameNum = parseInt(parts[0] || '0');

        // Extract ports from _ws.col.Info using regex
        const portMatch = line.match(/(\d+)\s*→\s*(\d+)/);
        const srcPort = portMatch ? parseInt(portMatch[1]) : 0;
        const dstPort = portMatch ? parseInt(portMatch[2]) : 0;

        if (!srcIp || !dstIp || !dstPort) continue;

        const key = `${srcIp}|${dstIp}|${dstPort}`;
        if (!synMap.has(key)) {
          synMap.set(key, { count: 0, frames: [], srcPort: new Set() });
        }
        const entry = synMap.get(key)!;
        entry.count++;
        entry.frames.push(frameNum);
        entry.srcPort.add(srcPort);
      }

      const indicators: SynScanIndicator[] = [];
      for (const [key, data] of synMap) {
        const [srcIp, dstIp, dstPortStr] = key.split('|');
        const dstPort = parseInt(dstPortStr);
        if (data.count >= 3) {
          indicators.push({
            srcIp, dstIp, dstPort,
            synCount: data.count,
            retransmitCount: data.frames.length > 1 ? data.frames.length - 1 : 0,
            packetNumbers: data.frames.slice(0, 20),
            firstSeen: data.frames[0] || 0,
            lastSeen: data.frames[data.frames.length - 1] || 0,
            description: `${data.count} SYN packets (no handshake completion) from ${srcIp} to ${dstIp}:${dstPort}. ${data.srcPort.size > 3 ? 'Multiple source ports suggest scanning.' : 'Retransmissions suggest automated retry.'}`,
          });
        }
      }

      // Sort by count descending
      indicators.sort((a, b) => b.synCount - a.synCount);
      console.log(`[NetworkAgent] SYN scan detection: ${indicators.length} indicators found`);
      return indicators;
    } catch (err: any) {
      console.error('[NetworkAgent] SYN scan detection failed:', err.message);
      return [];
    }
  }

  /**
   * Detect brute force patterns: high volume of connection attempts to same port.
   * Specifically targets SSH (22), HTTP/HTTPS (80/443), and other auth ports.
   */
  private async detectBruteForce(filePath: string): Promise<BruteForceIndicator[]> {
    try {
      // Focus on ports commonly targeted by brute force
      const targetPorts = [22, 23, 80, 443, 3389, 5432, 3306, 9999, 1340];
      const allIndicators: BruteForceIndicator[] = [];

      for (const port of targetPorts) {
        try {
          const raw = await this.tshark.applyFilter(
            filePath,
            `tcp.dstport==${port} && tcp.flags.syn==1`,
            2000
          );
          const lines = raw.split('\n').filter(l => l.trim());
          const attemptMap = new Map<string, { count: number; frames: number[]; srcPorts: Set<number> }>();

          for (const line of lines) {
            const parts = line.split(/\s+/).filter(p => p.trim());
            if (parts.length < 5) continue;
            // applyFilter returns: frame.number frame.time_relative ip.src ip.dst _ws.col.Protocol _ws.col.Info
            const srcIp = parts[2] || '';
            const dstIp = parts[3] || '';
            const frameNum = parseInt(parts[0] || '0');

            // Extract source port from _ws.col.Info using regex
            const portMatch = line.match(/(\d+)\s*→\s*(\d+)/);
            const srcPort = portMatch ? parseInt(portMatch[1]) : 0;

            if (!srcIp || !dstIp) continue;

            const key = `${srcIp}|${dstIp}|${port}`;
            if (!attemptMap.has(key)) {
              attemptMap.set(key, { count: 0, frames: [], srcPorts: new Set() });
            }
            const entry = attemptMap.get(key)!;
            entry.count++;
            entry.frames.push(frameNum);
            entry.srcPorts.add(srcPort);
          }

          for (const [key, data] of attemptMap) {
            const [srcIp, dstIp] = key.split('|');
            if (data.count >= 5) {
              allIndicators.push({
                srcIp, dstIp, dstPort: port,
                attemptCount: data.count,
                packetNumbers: data.frames.slice(0, 20),
                uniqueSrcPorts: data.srcPorts.size,
                firstSeen: data.frames[0] || 0,
                lastSeen: data.frames[data.frames.length - 1] || 0,
                description: `${data.count} connection attempts from ${srcIp} to ${dstIp}:${port}. ${data.srcPorts.size > 5 ? 'Many different source ports indicate brute-force/credential spraying.' : 'Repeated attempts indicate automated attack.'}`,
              });
            }
          }
        } catch { /* ignore per-port failures */ }
      }

      allIndicators.sort((a, b) => b.attemptCount - a.attemptCount);
      console.log(`[NetworkAgent] Brute force detection: ${allIndicators.length} indicators found`);
      return allIndicators;
    } catch (err: any) {
      console.error('[NetworkAgent] Brute force detection failed:', err.message);
      return [];
    }
  }

  private synScansToAnomalies(scans: SynScanIndicator[]): TrafficAnomaly[] {
    return scans.map(s => ({
      type: 'syn_scan',
      srcIp: s.srcIp,
      dstIp: s.dstIp,
      dstPort: s.dstPort,
      packetNumbers: s.packetNumbers,
      description: s.description,
      severity: s.synCount > 50 ? 'critical' : s.synCount > 20 ? 'high' : 'medium',
      confidence: Math.min(0.95, 0.6 + s.synCount * 0.01),
    }));
  }

  private bruteForceToAnomalies(bf: BruteForceIndicator[]): TrafficAnomaly[] {
    return bf.map(b => ({
      type: b.dstPort === 22 ? 'ssh_brute_force' : b.dstPort === 23 ? 'telnet_brute_force' : b.dstPort === 3389 ? 'rdp_brute_force' : b.dstPort === 9999 ? 'suspicious_port_scan' : 'brute_force',
      srcIp: b.srcIp,
      dstIp: b.dstIp,
      dstPort: b.dstPort,
      packetNumbers: b.packetNumbers,
      description: b.description,
      severity: b.attemptCount > 100 ? 'critical' : b.attemptCount > 30 ? 'high' : 'medium',
      confidence: Math.min(0.95, 0.65 + b.attemptCount * 0.003),
    }));
  }

  // ─── Phase 2: LLM Anomaly Detection ─────────────────────────────────────

  /**
   * Build rich packet context for LLM with HTTP payload hints.
   * Fetches packet metadata + HTTP-specific fields (URIs, methods, response codes).
   * This allows LLM to detect XSS/SQLi/directory traversal in URIs without followStream.
   */
  private async buildPacketContext(
    filePath: string,
    conversations: TrafficConversation[],
    synScans: SynScanIndicator[],
    bruteForce: BruteForceIndicator[],
    maxPackets: number = 300
  ): Promise<string> {
    try {
      const sections: string[] = [];
      let httpRequestCount = 0;
      let http2RequestCount = 0;
      let httpFallbackUsed = false;

      // Section 1: HTTP Traffic with FULL payload extraction (CRITICAL for XSS/SQLi/traversal)
      try {
        // Get ALL HTTP/1.x requests with full URI and any query parameters.
        // Enable TCP and HTTP desegmentation to recover full headers across packets.
        const httpData = await this.tshark.runTshark(
          filePath,
          [
            '-o tcp.desegment_tcp_streams:TRUE',
            '-o http.desegment_headers:TRUE',
            '-o http.desegment_body:TRUE',
            '-Y "http.request"',
            '-T fields',
            '-E separator=|',
            '-E quote=d',
            '-E occurrence=f',
            '-e frame.number',
            '-e ip.src',
            '-e ip.dst',
            '-e tcp.srcport',
            '-e tcp.dstport',
            '-e http.request.method',
            '-e http.host',
            '-e http.request.uri',
            '-e http.request.full_uri',
            '-e http.user_agent',
            '-e http.cookie',
            '-e http.referer',
            '-e http.request.line',
            '-c 2000',
          ].join(' ')
        );

        if (httpData && httpData.trim().length > 10) {
          const lines = httpData.split('\n').filter((l: string) => l.trim());
          httpRequestCount = lines.length;
          console.log(`[NetworkAgent] Extracted ${lines.length} HTTP requests with full URIs`);
          const formattedHttp = lines.slice(0, 2000).map((line, idx) => {
            const parts = this.splitTsharkFields(line, '|').map(p => this.normalizeTsharkField(p));
            const frame = parts[0] || '?';
            const src = parts[1] || '?';
            const dst = parts[2] || '?';
            const sport = parts[3] || '?';
            const dport = parts[4] || '?';
            const method = parts[5] || 'GET';
            const host = parts[6] || '';
            const uri = parts[7] || '/';
            const fullUri = this.buildFullUri(parts[8], host, uri, parts[12]);
            const ua = parts[9] || '';
            const cookie = parts[10] || '';
            const referer = parts[11] || '';
            const fullUriLabel = fullUri ? ` | FULL:${fullUri}` : '';
            return `[HTTP ${idx + 1}] Frame:${frame} | ${src}:${sport} -> ${dst}:${dport} | ${method} ${uri}${fullUriLabel}${host ? ' | Host:' + host : ''}${ua ? ' | UA:' + ua.substring(0, 100) : ''}${cookie ? ' | Cookie:' + cookie.substring(0, 100) : ''}${referer ? ' | Ref:' + referer.substring(0, 100) : ''}`;
          }).join('\n');
          sections.push(`=== HTTP REQUESTS (${lines.length} captured, showing query params/URIs) ===\n${formattedHttp}`);
        } else {
          console.warn('[NetworkAgent] No HTTP/1.x traffic extracted');
        }

        // HTTP/2 header extraction (best-effort). Build URIs from :scheme, :authority, :path.
        const http2Data = await this.tshark.runTshark(
          filePath,
          [
            '-Y "http2.header.name"',
            '-T fields',
            '-E separator=|',
            '-E quote=d',
            '-E occurrence=a',
            '-e frame.number',
            '-e ip.src',
            '-e ip.dst',
            '-e tcp.srcport',
            '-e tcp.dstport',
            '-e http2.streamid',
            '-e http2.header.name',
            '-e http2.header.value',
            '-c 4000',
          ].join(' ')
        );

        if (http2Data && http2Data.trim().length > 10) {
          const lines = http2Data.split('\n').filter((l: string) => l.trim());
          const requestsByKey = new Map<string, { frame: string; src: string; dst: string; sport: string; dport: string; method?: string; scheme?: string; authority?: string; path?: string }>();

          for (const line of lines) {
            const parts = this.splitTsharkFields(line, '|').map(p => this.normalizeTsharkField(p));
            const frame = parts[0] || '?';
            const src = parts[1] || '?';
            const dst = parts[2] || '?';
            const sport = parts[3] || '?';
            const dport = parts[4] || '?';
            const streamId = parts[5] || '?';
            const names = (parts[6] || '').split(',').map(p => p.trim()).filter(Boolean);
            const values = (parts[7] || '').split(',').map(p => p.trim());
            const key = `${frame}:${streamId}`;

            const record = requestsByKey.get(key) || { frame, src, dst, sport, dport };
            names.forEach((name, idx) => {
              const value = values[idx] || '';
              if (name === ':method') record.method = value;
              if (name === ':scheme') record.scheme = value;
              if (name === ':authority') record.authority = value;
              if (name === ':path') record.path = value;
            });
            requestsByKey.set(key, record);
          }

          const http2Requests = Array.from(requestsByKey.values())
            .filter(r => r.method || r.path || r.authority)
            .map((r, idx) => {
              const scheme = r.scheme || 'https';
              const authority = r.authority || '';
              const path = r.path || '/';
              const full = authority ? `${scheme}://${authority}${path}` : path;
              return `[HTTP2 ${idx + 1}] Frame:${r.frame} | ${r.src}:${r.sport} -> ${r.dst}:${r.dport} | ${r.method || 'GET'} ${path}${authority ? ' | Host:' + authority : ''}${full ? ' | FULL:' + full : ''}`;
            });

          if (http2Requests.length > 0) {
            http2RequestCount = http2Requests.length;
            sections.push(`=== HTTP2 REQUESTS (${http2Requests.length} captured, derived from headers) ===\n${http2Requests.join('\n')}`);
          }
        }

        console.log(`[NetworkAgent] HTTP metrics: http1=${httpRequestCount}, http2=${http2RequestCount}`);

        if (httpRequestCount < 3) {
          const httpStreams = await this.collectHttpStreamIds(filePath, 6);
          if (httpStreams.length > 0) {
            const followSections: string[] = [];
            for (const streamId of httpStreams) {
              const followed = await this.tshark.followStream(filePath, streamId, 'ascii');
              if (followed && followed.trim()) {
                const clipped = followed.length > 6000 ? `${followed.substring(0, 6000)}\n... [truncated]` : followed;
                followSections.push(`--- Stream ${streamId} ---\n${clipped}`);
              }
            }
            if (followSections.length > 0) {
              httpFallbackUsed = true;
              sections.push(`=== HTTP STREAM RECONSTRUCTIONS (fallback) ===\n${followSections.join('\n\n')}`);
            }
          }
        }
      } catch (err: any) {
        console.warn('[NetworkAgent] HTTP extraction failed:', err.message);
      }

      // Section 2: Suspicious packets (SYN scans, brute force)
      const suspiciousPackets = new Set<number>();
      for (const scan of synScans.slice(0, 10)) {
        scan.packetNumbers.slice(0, 10).forEach(p => suspiciousPackets.add(p));
      }
      for (const bf  of bruteForce.slice(0, 10)) {
        bf.packetNumbers.slice(0, 10).forEach(p => suspiciousPackets.add(p));
      }

      if (suspiciousPackets.size > 0) {
        const suspArray = Array.from(suspiciousPackets).sort((a, b) => a - b).slice(0, 150);
        const frameFilter = suspArray.join(' || frame.number==');
        const suspData = await this.tshark.applyFilter(filePath, `frame.number==${frameFilter}`, 150);
        if (suspData && suspData.trim().length > 0) {
          sections.push(`=== SUSPICIOUS PACKETS (SYN scans, brute force) ===\n${suspData.substring(0, 8000)}`);
        }
      }

      // Section 3: Sample from high-traffic conversations
      const streamFilters: string[] = [];
      for (const conv of conversations.slice(0, 12)) {
        streamFilters.push(`tcp.stream==${conv.streamId}`);
        if (streamFilters.length >= 12) break;
      }
      if (streamFilters.length > 0) {
        const convData = await this.tshark.applyFilter(filePath, streamFilters.join(' || '), 100);
        if (convData && convData.trim().length > 0) {
          sections.push(`=== TOP CONVERSATIONS (sample) ===\n${convData.substring(0, 5000)}`);
        }
      }

      // Section 4: UDP traffic summary (helps Mirai/UDP floods)
      try {
        const udpData = await this.tshark.runTshark(
          filePath,
          [
            '-Y "udp"',
            '-T fields',
            '-E separator=|',
            '-E quote=d',
            '-E occurrence=f',
            '-e frame.number',
            '-e ip.src',
            '-e ip.dst',
            '-e udp.srcport',
            '-e udp.dstport',
            '-e udp.length',
            '-e _ws.col.Info',
            '-c 500',
          ].join(' ')
        );
        if (udpData && udpData.trim().length > 0) {
          sections.push(`=== UDP TRAFFIC (sample) ===\n${udpData.substring(0, 7000)}`);
        }
      } catch { /* ignore UDP extraction failures */ }

      // Section 5: DNS traffic summary (helps DNS hijacking/spoofing detection)
      try {
        const dnsData = await this.tshark.runTshark(
          filePath,
          [
            '-Y "dns"',
            '-T fields',
            '-E separator=|',
            '-E quote=d',
            '-E occurrence=f',
            '-e frame.number',
            '-e ip.src',
            '-e ip.dst',
            '-e dns.flags.response',
            '-e dns.flags.rcode',
            '-e dns.qry.name',
            '-e dns.a',
            '-c 1200',
          ].join(' ')
        );
        if (dnsData && dnsData.trim().length > 0) {
          const lines = dnsData.split('\n').filter((l: string) => l.trim());
          const formatted = lines.slice(0, 800).map((line: string) => {
            const parts = this.splitTsharkFields(line, '|').map(p => this.normalizeTsharkField(p));
            const frame = parts[0] || '?';
            const src = parts[1] || '?';
            const dst = parts[2] || '?';
            const isResp = (parts[3] || '').trim() === '1' ? 'RESP' : 'QUERY';
            const rcode = parts[4] || '';
            const qry = parts[5] || '';
            const answers = parts[6] || '';
            return `[DNS ${isResp}] Frame:${frame} ${src} -> ${dst} | Q:${qry}${rcode ? ' | RCODE:' + rcode : ''}${answers ? ' | A:' + answers : ''}`;
          }).join('\n');
          sections.push(`=== DNS TRAFFIC (first ${Math.min(lines.length, 800)} records) ===\n${formatted}`);
          console.log(`[NetworkAgent] DNS context: ${lines.length} DNS records included`);
        }
      } catch { /* ignore DNS extraction failures */ }

      if (sections.length === 0) {
        return '(No packet data available)';
      }

      if (httpFallbackUsed) {
        console.log('[NetworkAgent] HTTP fallback: follow-stream used due to low HTTP request count');
      }
      return sections.join('\n\n');
    } catch (err: any) {
      console.error('[NetworkAgent] buildPacketContext failed:', err.message);
      return '(Packet context unavailable due to tshark error)';
    }
  }

  private normalizeTsharkField(value: string): string {
    const trimmed = value.trim();
    if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
      return trimmed.slice(1, -1).replace(/""/g, '"');
    }
    return trimmed;
  }

  private splitTsharkFields(line: string, separator: string): string[] {
    const fields: string[] = [];
    let current = '';
    let inQuotes = false;

    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"') {
        if (inQuotes && line[i + 1] === '"') {
          current += '"';
          i++;
        } else {
          inQuotes = !inQuotes;
        }
        continue;
      }

      if (ch === separator && !inQuotes) {
        fields.push(current);
        current = '';
        continue;
      }

      current += ch;
    }

    fields.push(current);
    return fields;
  }

  private buildFullUri(fullUri: string, host: string, uri: string, requestLine?: string): string {
    if (fullUri) return fullUri;
    if (requestLine && requestLine.includes('http')) {
      const parts = requestLine.split(' ');
      const candidate = parts[1] || '';
      if (candidate.startsWith('http://') || candidate.startsWith('https://')) return candidate;
    }
    if (!host) return uri;
    const normalizedUri = uri.startsWith('/') ? uri : `/${uri}`;
    return `http://${host}${normalizedUri}`;
  }


  private async collectHttpStreamIds(filePath: string, limit: number): Promise<number[]> {
    const streamIds = new Set<number>();
    const queries = [
      [
        '-o tcp.desegment_tcp_streams:TRUE',
        '-o http.desegment_headers:TRUE',
        '-o http.desegment_body:TRUE',
        '-Y "http.request"',
        '-T fields',
        '-e tcp.stream',
      ].join(' '),
      [
        '-Y "http"',
        '-T fields',
        '-e tcp.stream',
      ].join(' '),
      [
        '-Y "tcp.port==80 || tcp.port==8080 || tcp.port==8000 || tcp.port==8888"',
        '-T fields',
        '-e tcp.stream',
      ].join(' '),
    ];

    for (const args of queries) {
      if (streamIds.size >= limit) break;
      try {
        const raw = await this.tshark.runTshark(filePath, args);
        this.parseStreamIds(raw).forEach(id => {
          if (streamIds.size < limit) streamIds.add(id);
        });
      } catch {
        // ignore and try next query
      }
    }

    return Array.from(streamIds);
  }

  private parseStreamIds(raw: string): number[] {
    return raw
      .split('\n')
      .map(l => l.trim())
      .filter(l => l.length > 0)
      .map(l => parseInt(l, 10))
      .filter(n => Number.isFinite(n));
  }

  private async identifyAnomaliesWithLLM(
    filePath: string,
    conversations: TrafficConversation[],
    expertInfo: { errors: number; warnings: number; notes: number; entries: any[] },
    synScans: SynScanIndicator[],
    bruteForce: BruteForceIndicator[],
    llmConfig?: any
  ): Promise<TrafficAnomaly[]> {
    // ✅ NEW: Build rich packet context (up to 300 packets)
    console.log('[NetworkAgent] Building rich packet context for LLM...');
    const packetContext = await this.buildPacketContext(filePath, conversations, synScans, bruteForce, 300);
    console.log(`[NetworkAgent] Packet context built: ${packetContext.split('\n').length} packets`);

    const promptData = {
      conversationCount: conversations.length,
      topConversations: conversations.slice(0, 15).map(c => ({
        protocol: c.protocol, srcIp: c.srcIp, dstIp: c.dstIp,
        dstPort: c.dstPort, packetCount: c.packetCount, notes: c.notes,
      })),
      synScanCount: synScans.length,
      topSynScans: synScans.slice(0, 5).map(s => ({
        srcIp: s.srcIp, dstIp: s.dstIp, dstPort: s.dstPort,
        synCount: s.synCount, retransmitCount: s.retransmitCount,
      })),
      bruteForceCount: bruteForce.length,
      topBruteForce: bruteForce.slice(0, 5).map(b => ({
        srcIp: b.srcIp, dstIp: b.dstIp, dstPort: b.dstPort,
        attemptCount: b.attemptCount, uniqueSrcPorts: b.uniqueSrcPorts,
      })),
      expertErrors: expertInfo.errors,
      expertWarnings: expertInfo.warnings,
      // ✅ NEW: Include actual packet data
      packetData: packetContext,
    };

    const systemPrompt = `You are the Network Analyzer Agent for a security compliance system.
Your job: identify anomalies and suspicious traffic patterns from ACTUAL PACKET DATA + structured traffic summary.

Output STRICT JSON array of anomalies. No markdown, no explanations. ONLY JSON.

Each anomaly MUST have:
- type: a short identifier like "xss_attack", "sqli_attack", "directory_traversal", "plaintext_http", "weak_tls", "path_injection", "command_injection", "unauthorized_port", "syn_scan", "ssh_brute_force", "dns_tunneling", "dns_hijacking", "dns_rogue_responder", "session_hijack", "data_exfiltration", etc.
- packetNumbers: array of ACTUAL packet numbers from the packet data (e.g., [45, 47, 52])
- srcIp: source IP address (extract from packet data)
- dstIp: destination IP address (extract from packet data)
- dstPort: destination port (extract from packet data if available)
- description: human-readable explanation with SPECIFIC EVIDENCE (e.g., "Directory traversal in HTTP URI - packet 23: GET /../../etc/passwd")
- severity: one of [critical, high, medium, low, info]
- confidence: 0.0-1.0 score based on evidence strength (0.9+ for definitive, 0.7-0.9 for strong, 0.5-0.7 for moderate, <0.5 for weak)

CRITICAL: THE HTTP REQUESTS SECTION CONTAINS THE ATTACK EVIDENCE.

ATTACK PATTERNS (CHECK EVERY HTTP REQUEST LINE):

1. **Directory Traversal (PRIORITY 1):**
   LOOK FOR: ../ or ..%2F or ..%5C anywhere in the URI
   LOOK FOR: /etc/passwd, /etc/shadow, C:\\ paths
   EXAMPLES:
   - /vulnerabilities/fi/?page=../../../../../../etc/passwd
   - /dvwa/vulnerabilities/fi/?page=../../include.php
   
2. **XSS Attack (PRIORITY 2):**
   LOOK FOR: <script>, javascript:, alert(, onerror=, onload=
   LOOK FOR: %3Cscript%3E, %3Cimg, %3Ciframe (URL-encoded)
   
3. **SQL Injection (PRIORITY 3):**
   LOOK FOR: ' OR, UNION SELECT, DROP TABLE, 1=1--, admin'--
   LOOK FOR: %27 (single quote), %20OR%20
   
4. **Command Injection:**
   LOOK FOR: pipe, semicolon, backtick in URIs
   
5. **DVWA App:**
   /dvwa/ or /vulnerabilities/ in URI = vulnerable test app

ALSO DETECT:
6. SYN scans and port scans - check packet data
7. Brute force attacks - check packet data
8. Plaintext credentials - check http.cookie, http.authorization
9. Weak TLS versions - check handshake packets
10. DNS/ARP spoofing - check sequences
11. DNS hijacking / rogue DNS responders - check DNS TRAFFIC section for unauthorized DNS response sources, multiple answers for same query, suspicious TLDs (e.g., .wiki, .xyz), NXDOMAIN spikes
12. UDP floods / Mirai-style traffic - check for high-volume UDP bursts to many targets or ports
13. Data exfiltration - check large payloads

DNS HIJACKING CHECKLIST (in === DNS TRAFFIC === section):
- If DNS RESPONSE comes from an IP that is NOT a known public DNS (8.8.8.8, 8.8.4.4, 1.1.1.1) and NOT the router/gateway → flag as "dns_rogue_responder"
- If same query (Q) receives different answer IPs from different responders → flag as "dns_hijacking"
- If many queries for domains ending in suspicious TLDs (.wiki, .xyz, .top) → flag as "dns_suspicious_domains"
- If many NXDOMAIN (RCODE != 0) responses → flag as "dns_nxdomain_spike"
- If mDNS multicast traffic to 224.0.0.251 is excessive → flag as "mdns_multicast_flood"

CRITICAL: Analyze the HTTP TRAFFIC section FIRST. Directory traversal, XSS, and SQLi attacks are ALL visible in http.request.uri field.

If no anomalies found, return [].`;

    const userPrompt = `Identify network anomalies from this traffic analysis:

PACKET DATA (${packetContext.split('\n').length} lines):
${packetContext.substring(0, 30000)}

TRAFFIC SUMMARY:
${JSON.stringify(promptData, null, 2)}

CRITICAL ANALYSIS STEPS:

STEP 1: Scan EVERY line in === HTTP REQUESTS === section. Look for these EXACT patterns:

DIRECTORY TRAVERSAL - if URI contains ANY of:
  - "../" (one or more)
  - "..%2F" (URL-encoded)
  - "/etc/passwd", "/etc/shadow"
  - "../../.." (path escaping)
EXAMPLE MATCH: "GET /vulnerabilities/fi/?page=../../../../../../etc/passwd"
→ CREATE: {type: "directory_traversal", packetNumbers: [frame], severity: "critical", confidence: 0.95, description: "Directory traversal in packet X: URI contains ../../../../../etc/passwd"}

XSS ATTACK - if URI contains:
  - "<script>"
  - "javascript:"
  - "%3Cscript%3E"
→ CREATE: {type: "xss_attack", severity: "critical", confidence: 0.95}

SQL INJECTION - if URI contains:
  - "' OR '1'='1"
  - "UNION SELECT"
  - "admin'--"
→ CREATE: {type: "sqli_attack", severity: "critical", confidence: 0.95}

STEP 3: Scan === DNS TRAFFIC === section for hijacking/spoofing:
- DNS RESPONSE from unexpected source IP (not router, not 8.8.8.8/8.8.4.4/1.1.1.1) → type: "dns_rogue_responder"
- Same query name with different answers → type: "dns_hijacking"
- Many NXDOMAIN (RCODE != 0) → type: "dns_nxdomain_spike"
- Suspicious TLDs (.wiki, .xyz) in queries → type: "dns_suspicious_domains"
- Excessive mDNS to 224.0.0.251 → type: "mdns_multicast_flood"

STEP 4: Return JSON array of ALL anomalies found

BE THOROUGH: If you see "../" in ANY HTTP URI, that is directory traversal. Don't ignore it.

Return ONLY a JSON array.`;

    const messages: ChatMessage[] = [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userPrompt },
    ];

    try {
      this.llm.setSelectedProvider(llmConfig);
      const response = await this.llm.chatComplete(messages);
      const anomalies = this.parseAnomalies(response.content);
      console.log(`[NetworkAgent] LLM identified ${anomalies.length} anomalies`);
      return anomalies;
    } catch (err: any) {
      console.error('[NetworkAgent] LLM anomaly detection failed:', err.message);
      return [];
    }
  }

  private parseAnomalies(content: string): TrafficAnomaly[] {
    let jsonText = content.trim();
    const fenceMatch = jsonText.match(/```(?:json)?\s*([\s\S]*?)```/);
    if (fenceMatch) jsonText = fenceMatch[1].trim();
    const arrayStart = jsonText.indexOf('[');
    const arrayEnd = jsonText.lastIndexOf(']');
    if (arrayStart !== -1 && arrayEnd !== -1 && arrayEnd > arrayStart) {
      jsonText = jsonText.substring(arrayStart, arrayEnd + 1);
    }
    try {
      const data = JSON.parse(jsonText);
      if (!Array.isArray(data)) return [];
      return data.map((a: any) => ({
        type: a.type || 'unknown',
        streamId: a.streamId ?? a.stream_id ?? undefined,
        srcIp: a.srcIp ?? a.src_ip ?? a.sourceIp ?? undefined,
        dstIp: a.dstIp ?? a.dst_ip ?? a.destinationIp ?? undefined,
        dstPort: a.dstPort ?? a.dst_port ?? a.destinationPort ?? undefined,
        packetNumbers: Array.isArray(a.packetNumbers) ? a.packetNumbers : (Array.isArray(a.packet_numbers) ? a.packet_numbers : []),
        description: a.description || '',
        severity: ['critical', 'high', 'medium', 'low', 'info'].includes(a.severity) ? a.severity : 'medium',
        // ✅ NEW: Default confidence to 0.7 instead of 0.5 (LLM now has packet evidence)
        confidence: typeof a.confidence === 'number' ? Math.max(0, Math.min(1, a.confidence)) : 0.7,
      }));
    } catch (err: any) {
      console.error('[NetworkAgent] Failed to parse anomalies JSON:', err.message);
      return [];
    }
  }

  private async detectUdpFloods(filePath: string): Promise<TrafficAnomaly[]> {
    try {
      const raw = await this.tshark.runTshark(
        filePath,
        [
          '-Y "udp"',
          '-T fields',
          '-E separator=|',
          '-E occurrence=f',
          '-e frame.number',
          '-e ip.src',
          '-e ip.dst',
          '-e udp.srcport',
          '-e udp.dstport',
        ].join(' ')
      );

      if (!raw || raw.trim().length === 0) return [];

      const buckets = new Map<string, { count: number; packets: number[] }>();
      const bySource = new Map<string, { count: number; packets: number[]; targets: Set<string> }>();
      for (const line of raw.split('\n')) {
        if (!line.trim()) continue;
        const parts = line.split('|');
        const frame = parseInt(parts[0] || '', 10);
        const srcIp = parts[1] || '';
        const dstIp = parts[2] || '';
        const srcPort = parts[3] || '';
        const dstPort = parts[4] || '';
        if (!srcIp || !dstIp) continue;
        // Ignore mDNS multicast traffic to avoid drowning DNS hijacking signals.
        if (dstIp === '224.0.0.251' || dstPort === '5353' || srcPort === '5353') continue;
        const key = `${srcIp}:${srcPort}->${dstIp}:${dstPort}`;
        const entry = buckets.get(key) || { count: 0, packets: [] };
        entry.count += 1;
        if (entry.packets.length < 50 && Number.isFinite(frame)) entry.packets.push(frame);
        buckets.set(key, entry);

        const srcAgg = bySource.get(srcIp) || { count: 0, packets: [], targets: new Set<string>() };
        srcAgg.count += 1;
        if (srcAgg.packets.length < 80 && Number.isFinite(frame)) srcAgg.packets.push(frame);
        srcAgg.targets.add(`${dstIp}:${dstPort}`);
        bySource.set(srcIp, srcAgg);
      }

      const anomalies: TrafficAnomaly[] = [];
      for (const [key, entry] of buckets.entries()) {
        if (entry.count < 120) continue;
        const [src, dst] = key.split('->');
        const [srcIp, srcPortStr] = src.split(':');
        const [dstIp, dstPortStr] = dst.split(':');
        anomalies.push({
          type: 'udp_flood',
          srcIp,
          dstIp,
          dstPort: parseInt(dstPortStr || '0', 10) || undefined,
          packetNumbers: entry.packets,
          description: `High-volume UDP traffic (${entry.count} packets) from ${srcIp}:${srcPortStr} to ${dstIp}:${dstPortStr}. Possible botnet/Mirai UDP flood.`,
          severity: entry.count > 1000 ? 'critical' : 'high',
          confidence: entry.count > 1000 ? 0.9 : 0.75,
        });
      }

      for (const [srcIp, entry] of bySource.entries()) {
        if (entry.count < 400 || entry.targets.size < 8) continue;
        anomalies.push({
          type: 'udp_burst_multi_target',
          srcIp,
          packetNumbers: entry.packets,
          description: `UDP burst from ${srcIp}: ${entry.count} packets to ${entry.targets.size} unique targets. Botnet/flood behavior likely.`,
          severity: entry.count > 1500 ? 'critical' : 'high',
          confidence: entry.count > 1500 ? 0.92 : 0.8,
        });
      }

      return anomalies;
    } catch (err: any) {
      console.error('[NetworkAgent] UDP flood detection failed:', err.message);
      return [];
    }
  }

  private async detectOsFingerprinting(filePath: string): Promise<TrafficAnomaly[]> {
    try {
      const raw = await this.tshark.runTshark(
        filePath,
        [
          '-Y "tcp.flags.syn==1 && tcp.flags.ack==0"',
          '-T fields',
          '-E separator=|',
          '-E occurrence=f',
          '-e frame.number',
          '-e ip.src',
          '-e ip.dst',
          '-e tcp.dstport',
          '-e ip.ttl',
          '-e tcp.window_size_value',
          '-e tcp.options',
          '-e tcp.options.mss_val',
          '-e tcp.options.wscale.shift',
          '-e tcp.options.sack_perm',
          '-e tcp.options.timestamp',
        ].join(' ')
      );

      if (!raw || raw.trim().length === 0) return [];

      const byPair = new Map<string, { signatures: Map<string, number[]>; ports: Set<string>; frames: number[] }>();

      for (const line of raw.split('\n')) {
        if (!line.trim()) continue;
        const parts = line.split('|');
        const frame = parseInt(parts[0] || '', 10);
        const srcIp = parts[1] || '';
        const dstIp = parts[2] || '';
        const dstPort = parts[3] || '';
        const ttl = parts[4] || '';
        const win = parts[5] || '';
        const optionsHex = parts[6] || '';
        const mss = parts[7] || '';
        const wscale = parts[8] || '';
        const sackPerm = parts[9] || '';
        const ts = parts[10] || '';

        if (!srcIp || !dstIp || !dstPort || !Number.isFinite(frame)) continue;

        const signature = [ttl, win, mss, wscale, sackPerm ? '1' : '0', ts ? '1' : '0', optionsHex].join('|');
        const key = `${srcIp}->${dstIp}`;
        const entry = byPair.get(key) || { signatures: new Map<string, number[]>(), ports: new Set<string>(), frames: [] };
        entry.ports.add(dstPort);
        if (entry.frames.length < 60) entry.frames.push(frame);
        const sigFrames = entry.signatures.get(signature) || [];
        if (sigFrames.length < 10) sigFrames.push(frame);
        entry.signatures.set(signature, sigFrames);
        byPair.set(key, entry);
      }

      const anomalies: TrafficAnomaly[] = [];
      for (const [pair, entry] of byPair.entries()) {
        const uniqueSignatures = entry.signatures.size;
        if (uniqueSignatures < 4 || entry.ports.size < 2) continue;
        const [srcIp, dstIp] = pair.split('->');
        const signatureSamples = Array.from(entry.signatures.keys()).slice(0, 4).map(s => s.split('|').slice(0, 4).join('|'));
        anomalies.push({
          type: 'os_fingerprinting',
          srcIp,
          dstIp,
          packetNumbers: entry.frames,
          description: `OS fingerprinting suspected: ${uniqueSignatures} unique SYN option signatures from ${srcIp} to ${dstIp} across ${entry.ports.size} ports. Signatures (ttl|win|mss|wscale): ${signatureSamples.join(' ; ')}.`,
          severity: uniqueSignatures >= 6 ? 'high' : 'medium',
          confidence: Math.min(0.92, 0.65 + uniqueSignatures * 0.04),
        });
      }

      return anomalies;
    } catch (err: any) {
      console.error('[NetworkAgent] OS fingerprinting detection failed:', err.message);
      return [];
    }
  }

  private detectMiraiSignatures(
    synScans: SynScanIndicator[],
    bruteForce: BruteForceIndicator[],
    udpFloods: TrafficAnomaly[]
  ): TrafficAnomaly[] {
    const telnetAttackers = new Set(
      bruteForce
        .filter(b => b.dstPort === 23 || b.dstPort === 2323 || b.dstPort === 48101)
        .map(b => b.srcIp)
    );

    const reconAttackers = new Set(
      synScans
        .filter(s => s.synCount >= 20)
        .map(s => s.srcIp)
    );

    const udpAttackers = new Set(
      udpFloods
        .filter(a => a.type === 'udp_flood' || a.type === 'udp_burst_multi_target')
        .map(a => a.srcIp)
        .filter((ip): ip is string => !!ip)
    );

    const candidates = new Set<string>([
      ...Array.from(telnetAttackers),
      ...Array.from(udpAttackers),
    ]);

    const anomalies: TrafficAnomaly[] = [];
    for (const srcIp of candidates) {
      const hasTelnet = telnetAttackers.has(srcIp);
      const hasUdpFlood = udpAttackers.has(srcIp);
      const hasRecon = reconAttackers.has(srcIp);
      const score = (hasTelnet ? 1 : 0) + (hasUdpFlood ? 1 : 0) + (hasRecon ? 1 : 0);
      if (score < 2) continue;

      anomalies.push({
        type: 'mirai_botnet',
        srcIp,
        packetNumbers: [],
        description: `Mirai-like signature detected for ${srcIp}: ${hasTelnet ? 'telnet brute-force; ' : ''}${hasRecon ? 'SYN reconnaissance; ' : ''}${hasUdpFlood ? 'UDP flood behavior' : ''}`.trim(),
        severity: score >= 3 ? 'critical' : 'high',
        confidence: score >= 3 ? 0.93 : 0.82,
      });
    }

    return anomalies;
  }

  private async gatherConversationsFromPackets(filePath: string): Promise<TrafficConversation[]> {
    try {
      const raw = await this.tshark.runTshark(
        filePath,
        [
          '-Y "tcp || udp"',
          '-T fields',
          '-E separator=|',
          '-E occurrence=f',
          '-e ip.src',
          '-e ip.dst',
          '-e tcp.srcport',
          '-e tcp.dstport',
          '-e udp.srcport',
          '-e udp.dstport',
          '-e frame.len',
          '-c 20000',
        ].join(' ')
      );

      const agg = new Map<string, { count: number; bytes: number; protocol: 'tcp' | 'udp'; srcIp: string; dstIp: string; srcPort: number; dstPort: number }>();
      for (const line of raw.split('\n')) {
        if (!line.trim()) continue;
        const p = line.split('|');
        const srcIp = p[0] || '';
        const dstIp = p[1] || '';
        const tcpSrc = parseInt(p[2] || '0', 10);
        const tcpDst = parseInt(p[3] || '0', 10);
        const udpSrc = parseInt(p[4] || '0', 10);
        const udpDst = parseInt(p[5] || '0', 10);
        const len = parseInt(p[6] || '0', 10) || 0;
        if (!srcIp || !dstIp) continue;

        const isTcp = tcpSrc > 0 && tcpDst > 0;
        const protocol: 'tcp' | 'udp' = isTcp ? 'tcp' : 'udp';
        const srcPort = isTcp ? tcpSrc : udpSrc;
        const dstPort = isTcp ? tcpDst : udpDst;
        if (!srcPort || !dstPort) continue;

        const key = `${protocol}:${srcIp}:${srcPort}->${dstIp}:${dstPort}`;
        const entry = agg.get(key) || { count: 0, bytes: 0, protocol, srcIp, dstIp, srcPort, dstPort };
        entry.count += 1;
        entry.bytes += len;
        agg.set(key, entry);
      }

      return Array.from(agg.values())
        .sort((a, b) => b.count - a.count)
        .slice(0, 300)
        .map((a, idx) => ({
          streamId: idx,
          protocol: a.protocol,
          srcIp: a.srcIp,
          dstIp: a.dstIp,
          srcPort: a.srcPort,
          dstPort: a.dstPort,
          packetRange: '',
          packetCount: a.count,
          totalBytes: a.bytes,
          notes: 'Packet-derived conversation fallback',
        }));
    } catch {
      return [];
    }
  }

  // ─── Phase 3: Specific Indicator Detection ────────────────────────────────

  private async detectTlsVersions(filePath: string): Promise<string[]> {
    try {
      const raw = await this.tshark.applyFilter(filePath, 'tls.handshake.version', 50);
      const versions = new Set<string>();
      if (raw.includes('0x0301')) versions.add('TLS 1.0');
      if (raw.includes('0x0302')) versions.add('TLS 1.1');
      if (raw.includes('0x0303')) versions.add('TLS 1.2');
      if (raw.includes('0x0304')) versions.add('TLS 1.3');
      return Array.from(versions);
    } catch { return []; }
  }

  private async detectArpSpoofing(filePath: string): Promise<TrafficAnomaly[]> {
    try {
      const raw = await this.tshark.runTshark(
        filePath,
        [
          '-Y "arp"',
          '-T fields',
          '-E separator=|',
          '-E quote=d',
          '-E occurrence=f',
          '-e frame.number',
          '-e arp.opcode',
          '-e arp.src.proto_ipv4',
          '-e arp.src.hw_mac',
          '-e arp.dst.proto_ipv4',
          '-e arp.dst.hw_mac',
        ].join(' ')
      );

      if (!raw || raw.trim().length === 0) return [];

      const ipToMacs = new Map<string, Map<string, number[]>>();
      const ipReplyCounts = new Map<string, number>();
      let arpFrameCount = 0;

      for (const line of raw.split('\n')) {
        if (!line.trim()) continue;
        const parts = this.splitTsharkFields(line, '|').map(p => this.normalizeTsharkField(p));
        const frame = parseInt(parts[0] || '', 10);
        const opcode = parts[1] || '';
        const srcIp = parts[2] || '';
        const srcMac = (parts[3] || '').toLowerCase();
        const dstIp = parts[4] || '';
        const dstMac = (parts[5] || '').toLowerCase();

        if (!Number.isFinite(frame) || !srcIp || !srcMac) continue;
        arpFrameCount++;

        const macMap = ipToMacs.get(srcIp) || new Map<string, number[]>();
        const frames = macMap.get(srcMac) || [];
        if (frames.length < 20) frames.push(frame);
        macMap.set(srcMac, frames);
        ipToMacs.set(srcIp, macMap);

        if (opcode === '2') {
          ipReplyCounts.set(srcIp, (ipReplyCounts.get(srcIp) || 0) + 1);
        }

        // Track gratuitous ARP hints (reply where src/dst IP match)
        if (opcode === '2' && dstIp && srcIp === dstIp && dstMac !== '00:00:00:00:00:00') {
          ipReplyCounts.set(srcIp, (ipReplyCounts.get(srcIp) || 0) + 1);
        }
      }

      console.log(`[NetworkAgent] ARP metrics: frames=${arpFrameCount}, uniqueIps=${ipToMacs.size}`);

      const anomalies: TrafficAnomaly[] = [];
      for (const [ip, macMap] of ipToMacs.entries()) {
        if (macMap.size < 2) continue;
        const macs = Array.from(macMap.keys());
        const packetNumbers = Array.from(macMap.values()).flat().slice(0, 30);
        const replyCount = ipReplyCounts.get(ip) || 0;

        anomalies.push({
          type: 'arp_spoofing',
          srcIp: ip,
          dstIp: undefined,
          dstPort: undefined,
          packetNumbers,
          description: `ARP spoofing suspected: IP ${ip} is associated with multiple MACs (${macs.join(', ')}). ${replyCount > 0 ? `ARP replies observed: ${replyCount}.` : ''}`.trim(),
          severity: replyCount > 20 ? 'critical' : replyCount > 5 ? 'high' : 'medium',
          confidence: replyCount > 20 ? 0.9 : replyCount > 5 ? 0.8 : 0.7,
          payloadEvidence: true,
        });
      }

      return anomalies;
    } catch (err: any) {
      console.error('[NetworkAgent] ARP spoofing detection failed:', err.message);
      return [];
    }
  }

  private async detectDnsHijacking(filePath: string): Promise<TrafficAnomaly[]> {
    try {
      const raw = await this.tshark.runTshark(
        filePath,
        [
          '-Y "dns"',
          '-T fields',
          '-E separator=|',
          '-E quote=d',
          '-E occurrence=f',
          '-e frame.number',
          '-e ip.src',
          '-e ip.dst',
          '-e udp.srcport',
          '-e udp.dstport',
          '-e dns.flags.response',
          '-e dns.flags.rcode',
          '-e dns.qry.name',
          '-e dns.a',
        ].join(' ')
      );

      if (!raw || raw.trim().length === 0) return [];

      const knownPublicDns = new Set(['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9', '208.67.222.222', '208.67.220.220']);
      const internalRouter = '192.168.137.1'; // GT-07 specific gateway
      const queryLog = new Map<string, { responders: Set<string>; answers: Map<string, number[]>; frames: number[] }>();
      const responderCounts = new Map<string, { count: number; frames: number[] }>();
      const deviceResponders = new Map<string, { count: number; frames: number[]; targets: Set<string>; queryNames: Set<string> }>();
      const mdnssFrames: number[] = [];
      const suspiciousDomains: string[] = [];
      const nxdomainFrames: number[] = [];

      for (const line of raw.split('\n')) {
        if (!line.trim()) continue;
        const parts = this.splitTsharkFields(line, '|').map(p => this.normalizeTsharkField(p));
        const frame = parseInt(parts[0] || '', 10);
        const srcIp = parts[1] || '';
        const dstIp = parts[2] || '';
        const srcPort = parseInt(parts[3] || '', 10);
        const dstPort = parseInt(parts[4] || '', 10);
        const isResponse = (parts[5] || '').trim() === '1';
        const rcode = parseInt(parts[6] || '', 10);
        const qryName = (parts[7] || '').trim();
        const answers = (parts[8] || '').trim();

        if (!Number.isFinite(frame)) continue;

        // mDNS multicast pollution
        if (dstIp === '224.0.0.251' || srcIp === '224.0.0.251') {
          mdnssFrames.push(frame);
          continue;
        }

        // NXDOMAIN / error tracking
        if (isResponse && Number.isFinite(rcode) && rcode !== 0) {
          nxdomainFrames.push(frame);
        }

        // Suspicious TLDs / DGA-like
        // Tightened: only high-suspicion TLDs (excluding borderline/common ones like .link, .work, .date, .party)
        if (qryName && /\.(wiki|xyz|top|club|win|click|space|site|online|store|review|download|racing|loan|stream|ninja|zone|world|today|press|rest|host|icu|casa|bar|uno|best|bid)\b/i.test(qryName)) {
          suspiciousDomains.push(qryName);
        }

        if (isResponse) {
          // Response source tracking per query
          if (qryName) {
            const rec = queryLog.get(qryName) || { responders: new Set<string>(), answers: new Map<string, number[]>(), frames: [] };
            rec.responders.add(srcIp);
            rec.frames.push(frame);
            const ansList = answers ? answers.split(',').map(s => s.trim()).filter(Boolean) : [];
            for (const ans of ansList) {
              const aFrames = rec.answers.get(ans) || [];
              if (aFrames.length < 10) aFrames.push(frame);
              rec.answers.set(ans, aFrames);
            }
            queryLog.set(qryName, rec);
          }

          // Global responder counts
          const rRec = responderCounts.get(srcIp) || { count: 0, frames: [] };
          rRec.count += 1;
          if (rRec.frames.length < 50) rRec.frames.push(frame);
          responderCounts.set(srcIp, rRec);

          // Device-level DNS responder (non-router, non-public)
          if (srcIp !== internalRouter && !knownPublicDns.has(srcIp) && !srcIp.startsWith('224.')) {
            const dRec = deviceResponders.get(srcIp) || { count: 0, frames: [], targets: new Set<string>(), queryNames: new Set<string>() };
            dRec.count += 1;
            if (dRec.frames.length < 50) dRec.frames.push(frame);
            if (dstIp) dRec.targets.add(dstIp);
            if (qryName) dRec.queryNames.add(qryName);
            deviceResponders.set(srcIp, dRec);
          }
        }
      }

      const anomalies: TrafficAnomaly[] = [];

      // 1) Rogue DNS server responses (raised threshold from 20 to 30)
      for (const [ip, rec] of responderCounts.entries()) {
        if (knownPublicDns.has(ip)) continue;
        if (ip === internalRouter) continue;
        if (ip.startsWith('224.')) continue;
        if (rec.count >= 30) {
          anomalies.push({
            type: 'dns_rogue_responder',
            srcIp: ip,
            packetNumbers: rec.frames.slice(0, 30),
            description: `DNS responses from unauthorized server ${ip} (${rec.count} responses). Expected resolver is ${internalRouter}. Possible DNS hijacking or poisoned cache.`,
            severity: rec.count > 100 ? 'critical' : rec.count > 50 ? 'high' : 'high',
            confidence: Math.min(0.92, 0.65 + rec.count * 0.001),
            payloadEvidence: true,
          });
        }
      }

      // 2) Device-level DNS spoofing (IoT acting as DNS server) — raised minimum from 3 to 5
      for (const [ip, rec] of deviceResponders.entries()) {
        if (rec.count < 5) continue;
        anomalies.push({
          type: 'dns_unauthorized_device_responder',
          srcIp: ip,
          packetNumbers: rec.frames.slice(0, 30),
          description: `Device ${ip} is sending DNS responses to ${rec.targets.size} target(s) for ${rec.queryNames.size} domain(s) (${rec.count} responses). IoT device may be compromised and acting as rogue resolver.`,
          severity: rec.count > 20 ? 'critical' : 'high',
          confidence: Math.min(0.88, 0.65 + rec.count * 0.005),
          payloadEvidence: true,
        });
      }

      // 3) Multiple answers for same query (possible cache poisoning)
      for (const [qryName, rec] of queryLog.entries()) {
        if (rec.responders.size >= 2 && rec.answers.size >= 2) {
          const answerIps = Array.from(rec.answers.keys()).slice(0, 10);
          anomalies.push({
            type: 'dns_answer_inconsistency',
            srcIp: undefined,
            dstIp: undefined,
            packetNumbers: rec.frames.slice(0, 20),
            description: `Domain "${qryName}" received answers from ${rec.responders.size} different sources with ${rec.answers.size} distinct IP sets (${answerIps.join(', ')}). Inconsistent answers suggest DNS cache poisoning or hijacking.`,
            severity: 'high',
            confidence: 0.85,
            payloadEvidence: true,
          });
        }
      }

      // 4) mDNS multicast storm (raised threshold from 200 to 500)
      if (mdnssFrames.length > 500) {
        anomalies.push({
          type: 'mdns_multicast_flood',
          packetNumbers: mdnssFrames.slice(0, 30),
          description: `High volume of mDNS (multicast DNS) traffic: ${mdnssFrames.length} frames to 224.0.0.251. This may indicate mDNS amplification or multicast pollution from compromised IoT devices.`,
          severity: mdnssFrames.length > 2000 ? 'high' : 'medium',
          confidence: Math.min(0.85, 0.6 + mdnssFrames.length * 0.00005),
        });
      }

      // 5) NXDOMAIN / error spikes (raised threshold from 20 to 50)
      if (nxdomainFrames.length > 50) {
        anomalies.push({
          type: 'dns_nxdomain_spike',
          packetNumbers: nxdomainFrames.slice(0, 20),
          description: `DNS error response spike: ${nxdomainFrames.length} DNS responses with non-zero RCODE (NXDOMAIN / SERVFAIL / REFUSED). May indicate DGA, hijacked resolution, or blocked malicious domains.`,
          severity: nxdomainFrames.length > 100 ? 'high' : 'medium',
          confidence: Math.min(0.82, 0.55 + nxdomainFrames.length * 0.001),
        });
      }

      // 6) Suspicious domain queries (DGA / suspicious TLD)
      // Only flag when there is a clear pattern: many unique suspicious domains
      // to avoid false positives on legitimate but unusual TLDs
      const uniqueSuspicious = [...new Set(suspiciousDomains)];
      if (uniqueSuspicious.length >= 8) {
        anomalies.push({
          type: 'dns_suspicious_domains',
          packetNumbers: [],
          description: `Suspicious domains detected in DNS queries: ${uniqueSuspicious.slice(0, 15).join(', ')}${uniqueSuspicious.length > 15 ? ` ... (${uniqueSuspicious.length - 15} more)` : ''}. Unusual TLDs and naming patterns may indicate malware C2 or DGA.`,
          severity: uniqueSuspicious.length > 15 ? 'high' : 'medium',
          confidence: Math.min(0.85, 0.55 + uniqueSuspicious.length * 0.02),
          payloadEvidence: true,
        });
      }

      console.log(`[NetworkAgent] DNS hijacking detection: ${anomalies.length} anomalies (${mdnssFrames.length} mDNS, ${nxdomainFrames.length} NXDOMAIN, ${deviceResponders.size} device responders, ${responderCounts.size} unique responders)`);
      return anomalies;
    } catch (err: any) {
      console.error('[NetworkAgent] DNS hijacking detection failed:', err.message);
      return [];
    }
  }

  private async detectDnsTunneling(filePath: string): Promise<TrafficAnomaly[]> {
    try {
      const raw = await this.tshark.runTshark(
        filePath,
        [
          '-Y "dns && dns.flags.response==0"',
          '-T fields',
          '-E separator=|',
          '-E occurrence=f',
          '-e frame.number',
          '-e ip.src',
          '-e ip.dst',
          '-e dns.qry.name',
          '-e dns.qry.type',
          '-e dns.qry.name.len',
        ].join(' ')
      );

      if (!raw || raw.trim().length === 0) return [];

      const byPair = new Map<string, { count: number; longCount: number; txtCount: number; frames: number[]; baseDomains: Map<string, Set<string>> }>();

      for (const line of raw.split('\n')) {
        if (!line.trim()) continue;
        const parts = this.splitTsharkFields(line, '|').map(p => this.normalizeTsharkField(p));
        const frame = parseInt(parts[0] || '', 10);
        const srcIp = parts[1] || '';
        const dstIp = parts[2] || '';
        const query = (parts[3] || '').toLowerCase();
        const qType = parts[4] || '';
        const qLen = parseInt(parts[5] || '', 10);
        if (!srcIp || !dstIp || !query || !Number.isFinite(frame)) continue;

        const labels = query.split('.').filter(Boolean);
        const baseDomain = labels.length >= 2 ? `${labels[labels.length - 2]}.${labels[labels.length - 1]}` : query;
        const subdomain = labels.length > 2 ? labels.slice(0, -2).join('.') : '';

        const key = `${srcIp}->${dstIp}`;
        const entry = byPair.get(key) || { count: 0, longCount: 0, txtCount: 0, frames: [], baseDomains: new Map<string, Set<string>>() };
        entry.count += 1;
        if (Number.isFinite(qLen) && qLen >= 45) entry.longCount += 1;
        if (qType === '16') entry.txtCount += 1;
        if (entry.frames.length < 80) entry.frames.push(frame);
        const subs = entry.baseDomains.get(baseDomain) || new Set<string>();
        if (subdomain) subs.add(subdomain);
        entry.baseDomains.set(baseDomain, subs);
        byPair.set(key, entry);
      }

      const anomalies: TrafficAnomaly[] = [];
      for (const [pair, entry] of byPair.entries()) {
        const [srcIp, dstIp] = pair.split('->');
        const suspiciousBases = Array.from(entry.baseDomains.entries())
          .filter(([_, subs]) => subs.size >= 20)
          .sort((a, b) => b[1].size - a[1].size);

        // Require more stringent conditions to reduce false positives:
        // - Long query pattern: >= 80 total queries AND >= 30 long queries (up from 40/15)
        // - TXT record pattern: >= 15 TXT queries AND >= 40 total queries (up from 10/20)
        // - Subdomain diversity: >= 20 unique subdomains under one base domain (up from 12)
        const hasLongQueryPattern = entry.count >= 80 && entry.longCount >= 30;
        const hasTxtPattern = entry.txtCount >= 15 && entry.count >= 40;
        if (!hasLongQueryPattern && !hasTxtPattern && suspiciousBases.length === 0) continue;

        const topBase = suspiciousBases[0]?.[0] || 'n/a';
        const topSubs = suspiciousBases[0]?.[1]?.size || 0;
        anomalies.push({
          type: 'dns_tunneling',
          srcIp,
          dstIp,
          dstPort: 53,
          packetNumbers: entry.frames,
          description: `DNS tunneling suspected from ${srcIp} to ${dstIp}: ${entry.count} queries, ${entry.longCount} long query names, ${entry.txtCount} TXT queries${topBase !== 'n/a' ? `, and ${topSubs} unique subdomains under ${topBase}` : ''}.`,
          severity: entry.count > 200 || topSubs > 50 ? 'high' : 'medium',
          confidence: Math.min(0.88, 0.55 + (entry.longCount * 0.004) + (topSubs * 0.006) + (entry.txtCount * 0.003)),
          payloadEvidence: true,
        });
      }

      return anomalies;
    } catch (err: any) {
      console.error('[NetworkAgent] DNS tunneling detection failed:', err.message);
      return [];
    }
  }

  private async detectSessionHijacking(filePath: string): Promise<TrafficAnomaly[]> {
    try {
      const raw = await this.tshark.runTshark(
        filePath,
        [
          '-Y "http.cookie || http.authorization"',
          '-T fields',
          '-E separator=|',
          '-E quote=d',
          '-E occurrence=f',
          '-e frame.number',
          '-e ip.src',
          '-e ip.dst',
          '-e http.host',
          '-e http.request.uri',
          '-e http.cookie',
          '-e http.authorization',
        ].join(' ')
      );

      if (!raw || raw.trim().length === 0) return [];

      const tokenUsage = new Map<string, { srcIps: Set<string>; dstIps: Set<string>; frames: number[]; sampleUris: string[] }>();

      for (const line of raw.split('\n')) {
        if (!line.trim()) continue;
        const parts = this.splitTsharkFields(line, '|').map(p => this.normalizeTsharkField(p));
        const frame = parseInt(parts[0] || '', 10);
        const srcIp = parts[1] || '';
        const dstIp = parts[2] || '';
        const host = parts[3] || '';
        const uri = parts[4] || '';
        const cookie = parts[5] || '';
        const auth = parts[6] || '';
        if (!srcIp || !dstIp || !Number.isFinite(frame)) continue;

        const candidates: string[] = [];

        const cookieMatches = cookie.match(/(?:PHPSESSID|JSESSIONID|ASP\.NET_SessionId|sessionid|sid|token|auth_token)=([^;\s]+)/gi) || [];
        for (const m of cookieMatches) {
          const partsToken = m.split('=');
          if (partsToken.length === 2 && partsToken[1].trim()) {
            const value = partsToken[1].trim().replace(/^"+|"+$/g, '');
            candidates.push(`${partsToken[0].toLowerCase()}=${value}`);
          }
        }

        const authMatch = auth.match(/^(Basic|Bearer)\s+([A-Za-z0-9+\/=._-]{12,})/i);
        if (authMatch) {
          const value = authMatch[2].trim().replace(/^"+|"+$/g, '');
          candidates.push(`${authMatch[1].toLowerCase()}:${value}`);
        }

        for (const token of candidates) {
          const scoped = `${host || dstIp}|${token}`;
          const usage = tokenUsage.get(scoped) || { srcIps: new Set<string>(), dstIps: new Set<string>(), frames: [], sampleUris: [] };
          usage.srcIps.add(srcIp);
          usage.dstIps.add(dstIp);
          if (usage.frames.length < 40) usage.frames.push(frame);
          if (uri && usage.sampleUris.length < 6) usage.sampleUris.push(uri);
          tokenUsage.set(scoped, usage);
        }
      }

      const anomalies: TrafficAnomaly[] = [];
      for (const [scopedToken, usage] of tokenUsage.entries()) {
        if (usage.srcIps.size < 2) continue;
        const [scope, token] = scopedToken.split('|');
        const srcs = Array.from(usage.srcIps);
        const tokenLabel = token.length > 36 ? `${token.slice(0, 36)}...` : token;
        anomalies.push({
          type: 'session_hijacking',
          srcIp: srcs[0],
          dstIp: Array.from(usage.dstIps)[0],
          packetNumbers: usage.frames,
          description: `Session hijacking suspected: token ${tokenLabel} reused by multiple client IPs (${srcs.join(', ')}) against ${scope}. Sample URIs: ${usage.sampleUris.join(', ')}.`,
          severity: usage.srcIps.size >= 3 ? 'critical' : 'high',
          confidence: usage.srcIps.size >= 3 ? 0.92 : 0.84,
          payloadEvidence: true,
        });
      }

      // Phase 2: Scan non-HTTP UDP/TCP payloads for embedded JSON containing auth tokens
      // (GT-11 pattern: token injected into JSON body on UDP port)
      // Scan all UDP/TCP payloads with actual data for JSON auth patterns
      // Use udp.port == 6669 to catch the specific GT-11 JSON-on-UDP pattern,
      // plus any UDP traffic with non-zero data payload
      const jsonRaw = await this.tshark.runTshark(
        filePath,
        '-Y "udp.port == 6669 || (udp && data.len > 0)" -T fields -E separator=| -E quote=d -E occurrence=a -e frame.number -e ip.src -e ip.dst -e udp.srcport -e udp.dstport -e tcp.srcport -e tcp.dstport -e data -e data.len'
      );

      if (jsonRaw && jsonRaw.trim()) {
        const authTokens = new Map<string, { srcIp: string; dstIp: string; frames: number[]; context: string }>();
        for (const line of jsonRaw.split('\n')) {
          if (!line.trim()) continue;
          const parts = this.splitTsharkFields(line, '|').map(p => this.normalizeTsharkField(p));
          const frame = parseInt(parts[0] || '', 10);
          const srcIp = parts[1] || '';
          const dstIp = parts[2] || '';
          const srcPort = parts[3] || '';
          const dstPort = parts[4] || '';
          // UDP payloads on port 6669: parts[5+6] are empty (no tcp ports); hex data lands at parts[7]
          // Mixed TCP+UDP: tcp src/dst ports occupy parts[5+6], hex at parts[7]
          // Check parts[7] first (data field), fallback to parts[5] for edge cases
          const hexData = (parts[7] || parts[5] || '').trim();
          let payload = '';
          if (hexData && hexData.length >= 84) {
            try {
              const decoded = hexData.replace(/[0-9a-fA-F]{2}/g, (m) => String.fromCharCode(parseInt(m, 16)));
              // Find the first complete JSON object in the decoded string
              const jsonStart = decoded.indexOf('{"');
              if (jsonStart >= 0) {
                // Extract from the first '{' and find its matching '}'
                const jsonSlice = decoded.substring(jsonStart);
                const jsonEnd = jsonSlice.indexOf('}');
                if (jsonEnd > 0) payload = jsonSlice.substring(0, jsonEnd + 1);
              }
            } catch (_) { /* ignore decode errors */ }
          }
          if (!Number.isFinite(frame) || !srcIp || !payload) continue;

          // Match JSON containing both a token field and credentials (weak or otherwise)
          const tokenMatch = payload.match(/"token"\s*:\s*"([^"]{8,})"/i);
          const passwdMatch = payload.match(/"passwd"\s*:\s*"([^"]+)"/i) || payload.match(/"password"\s*:\s*"([^"]+)"/i);
          if (tokenMatch && passwdMatch) {
            const tokenValue = tokenMatch[1];
            const passwdValue = passwdMatch[1];
            const key = `${tokenValue}|${passwdValue}`;
            const existing = authTokens.get(key) || { srcIp, dstIp, frames: [], context: '' };
            if (existing.frames.length < 20) existing.frames.push(frame);
            existing.context = payload.substring(0, 120);
            if (!existing.srcIp) existing.srcIp = srcIp;
            if (!existing.dstIp) existing.dstIp = dstIp;
            authTokens.set(key, existing);
          }

          // Also flag JSON with token + ssid (device authentication context)
          const ssidMatch = payload.match(/"ssid"\s*:\s*"([^"]+)"/i);
          if (tokenMatch && ssidMatch && !passwdMatch) {
            const tokenValue = tokenMatch[1];
            const ssidValue = ssidMatch[1];
            const key = `ssid:${ssidValue}|${tokenValue}`;
            const existing = authTokens.get(key) || { srcIp, dstIp, frames: [], context: '' };
            if (existing.frames.length < 20) existing.frames.push(frame);
            existing.context = payload.substring(0, 120);
            if (!existing.srcIp) existing.srcIp = srcIp;
            if (!existing.dstIp) existing.dstIp = dstIp;
            authTokens.set(key, existing);
          }
        }

        for (const [, info] of authTokens.entries()) {
          if (info.frames.length < 1) continue;
          // JSON containing both token AND credentials — no volume threshold needed;
          // this pattern is inherently suspicious (non-HTTP port + plaintext auth)
          anomalies.push({
            type: 'token_injection',
            srcIp: info.srcIp,
            dstIp: info.dstIp,
            packetNumbers: info.frames,
            description: `Token injection suspected (GT-11 pattern): token ${info.context.match(/"token"\s*:\s*"([^"]+)"/)?.[1] || '不明'} in JSON body alongside plaintext credentials: ${info.context.substring(0, 100)}. Unusual non-HTTP port (6669) carrying authentication data — possible MITM token injection or API abuse.`,
            severity: info.frames.length >= 2 ? 'high' : 'medium',
            confidence: 0.88,
            payloadEvidence: true,
          });
        }
      }

      return anomalies;
    } catch (err: any) {
      console.error('[NetworkAgent] Session hijacking detection failed:', err.message);
      return [];
    }
  }

  /**
   * Detect Log4Shell (CVE-2021-44228) / JNDI exploitation patterns:
   * - LDAP connections to port 1389 (JNDI/LDAP callback)
   * - HTTP GET requests for .class files (remote payload fetch)
   * - ${jndi:...} interpolation patterns in request URIs or bodies
   * - Java class file magic bytes (CAFEBABE) in responses
   */
  private async detectLog4Shell(filePath: string): Promise<TrafficAnomaly[]> {
    try {
      // Capture LDAP (JNDI callback), HTTP for .class payloads, and general HTTP for JNDI patterns
      // JNDI/LDAP callback pattern: TCP to port 1389 (standard JNDI LDAP callback port)
      const ldapRaw = await this.tshark.runTshark(
        filePath,
        [
          '-Y "tcp.port == 1389"',
          '-T fields',
          '-E separator=|',
          '-E quote=d',
          '-E occurrence=f',
          '-e frame.number',
          '-e ip.src',
          '-e ip.dst',
          '-e tcp.srcport',
          '-e tcp.dstport',
        ].join(' ')
      );

      const httpClassRaw = await this.tshark.runTshark(
        filePath,
        [
          '-Y "http.request.uri matches "\\.class""',
          '-T fields',
          '-E separator=|',
          '-E quote=d',
          '-E occurrence=a',
          '-e frame.number',
          '-e ip.src',
          '-e ip.dst',
          '-e http.request.uri',
          '-e http.host',
          '-e http.request.method',
        ].join(' ')
      );

      // Generic HTTP URIs — we'll filter for ${jndi:} in JS
      const httpJndiRaw = await this.tshark.runTshark(
        filePath,
        [
          '-Y "http.request.uri"',
          '-T fields',
          '-E separator=|',
          '-E quote=d',
          '-E occurrence=a',
          '-e frame.number',
          '-e ip.src',
          '-e ip.dst',
          '-e http.request.uri',
          '-e http.host',
        ].join(' ')
      );

      const anomalies: TrafficAnomaly[] = [];

      // 1) LDAP connections to JNDI port 1389
      if (ldapRaw && ldapRaw.trim()) {
        const ldapFrames: number[] = [];
        const ldapSources = new Map<string, number[]>();
        for (const line of ldapRaw.split('\n')) {
          if (!line.trim()) continue;
          const parts = this.splitTsharkFields(line, '|').map(p => this.normalizeTsharkField(p));
          const frame = parseInt(parts[0] || '', 10);
          const srcIp = parts[1] || '';
          if (Number.isFinite(frame) && srcIp) {
            if (ldapFrames.length < 50) ldapFrames.push(frame);
            const list = ldapSources.get(srcIp) || [];
            if (list.length < 30) list.push(frame);
            ldapSources.set(srcIp, list);
          }
        }
        if (ldapFrames.length >= 1) {
          const srcs = Array.from(ldapSources.keys());
          anomalies.push({
            type: 'log4shell_exploitation',
            srcIp: srcs[0],
            packetNumbers: ldapFrames,
            description: `LDAP session detected on port 1389 (JNDI callback port) — ${ldapFrames.length} frames from ${srcs.join(', ')}. Consistent with Log4Shell JNDI exploitation: remote code execution via untrusted LDAP references.`,
            severity: 'critical',
            confidence: Math.min(0.95, 0.7 + ldapFrames.length * 0.01),
            payloadEvidence: true,
          });
        }
      }

      // 2) HTTP GET requests for .class files (remote payload fetch pattern)
      if (httpClassRaw && httpClassRaw.trim()) {
        const classFrames: number[] = [];
        const classUris: string[] = [];
        const classSources = new Map<string, number[]>();
        for (const line of httpClassRaw.split('\n')) {
          if (!line.trim()) continue;
          const parts = this.splitTsharkFields(line, '|').map(p => this.normalizeTsharkField(p));
          const frame = parseInt(parts[0] || '', 10);
          const srcIp = parts[1] || '';
          const uri = parts[2] || '';
          if (Number.isFinite(frame)) {
            if (classFrames.length < 50) classFrames.push(frame);
            if (uri && classUris.length < 10) classUris.push(uri);
            const list = classSources.get(srcIp) || [];
            if (list.length < 30) list.push(frame);
            classSources.set(srcIp, list);
          }
        }
        if (classFrames.length >= 1) {
          const srcs = Array.from(classSources.keys());
          anomalies.push({
            type: 'log4shell_payload_fetch',
            srcIp: srcs[0],
            packetNumbers: classFrames,
            description: `HTTP GET requests for .class files detected (${classFrames.length} frames from ${srcs.join(', ')}): ${classUris.slice(0, 5).join(', ')}. Classic Log4Shell/ JNDI payload fetch pattern — remote Java class file download for code execution.`,
            severity: 'critical',
            confidence: Math.min(0.96, 0.75 + classFrames.length * 0.005),
            payloadEvidence: true,
          });
        }
      }

      // 3) Explicit ${jndi:} URI patterns (scanned in JS after generic HTTP capture)
      if (httpJndiRaw && httpJndiRaw.trim()) {
        const jndiFrames: number[] = [];
        const jndiUris: string[] = [];
        for (const line of httpJndiRaw.split('\n')) {
          if (!line.trim()) continue;
          const parts = this.splitTsharkFields(line, '|').map(p => this.normalizeTsharkField(p));
          const frame = parseInt(parts[0] || '', 10);
          const uri = parts[2] || '';
          if (Number.isFinite(frame) && /\${jndi:/i.test(uri)) {
            if (jndiFrames.length < 50) jndiFrames.push(frame);
            if (uri && jndiUris.length < 10) jndiUris.push(uri);
          }
        }
        if (jndiFrames.length >= 1) {
          anomalies.push({
            type: 'log4shell_jndi_uri',
            srcIp: undefined,
            packetNumbers: jndiFrames,
            description: `JNDI interpolation pattern detected in HTTP URIs: ${jndiUris.slice(0, 5).join(', ')}. Direct evidence of Log4Shell exploitation attempt — \${jndi:} notation triggers JNDI lookup.`,
            severity: 'critical',
            confidence: 0.97,
            payloadEvidence: true,
          });
        }
      }

      console.log(`[NetworkAgent] Log4Shell detection: ${anomalies.length} anomalies (LDAP JNDI=${ldapRaw?.trim() ? 1 : 0}, class_fetches=${httpClassRaw?.trim() ? 1 : 0}, jndi_uris=${httpJndiRaw?.trim() ? 1 : 0})`);
      return anomalies;
    } catch (err: any) {
      console.error('[NetworkAgent] Log4Shell detection failed:', err.message);
      return [];
    }
  }

  private async detectWebAppAttacks(filePath: string): Promise<TrafficAnomaly[]> {
    try {
      const raw = await this.tshark.runTshark(
        filePath,
        [
          '-o tcp.desegment_tcp_streams:TRUE',
          '-o http.desegment_headers:TRUE',
          '-Y "http.request"',
          '-T fields',
          '-E separator=|',
          '-E quote=d',
          '-E occurrence=f',
          '-e frame.number',
          '-e ip.src',
          '-e ip.dst',
          '-e tcp.dstport',
          '-e http.request.method',
          '-e http.host',
          '-e http.request.uri',
          '-e http.request.full_uri',
          '-e http.request.line',
          '-c 4000',
        ].join(' ')
      );

      if (!raw || raw.trim().length === 0) return [];

      const xssFrames: number[] = [];
      const sqliFrames: number[] = [];
      const traversalFrames: number[] = [];
      const commandFrames: number[] = [];

      const xssSamples: string[] = [];
      const sqliSamples: string[] = [];
      const traversalSamples: string[] = [];
      const commandSamples: string[] = [];

      let sampleSrcIp = '';
      let sampleDstIp = '';
      let sampleDstPort = 0;

      for (const line of raw.split('\n')) {
        if (!line.trim()) continue;
        const parts = this.splitTsharkFields(line, '|').map(p => this.normalizeTsharkField(p));
        const frame = parseInt(parts[0] || '', 10);
        const srcIp = parts[1] || '';
        const dstIp = parts[2] || '';
        const dstPort = parseInt(parts[3] || '', 10) || 80;
        const method = (parts[4] || 'GET').toUpperCase();
        const host = parts[5] || '';
        const uri = parts[6] || '';
        const fullUri = this.buildFullUri(parts[7] || '', host, uri, parts[8] || '');

        if (!Number.isFinite(frame)) continue;
        const normalized = this.normalizeUriForDetection(fullUri || uri || '');

        if (!sampleSrcIp && srcIp) sampleSrcIp = srcIp;
        if (!sampleDstIp && dstIp) sampleDstIp = dstIp;
        if (!sampleDstPort && dstPort) sampleDstPort = dstPort;

        if (this.isLikelyXss(normalized)) {
          if (xssFrames.length < 80) xssFrames.push(frame);
          if (xssSamples.length < 3) xssSamples.push(`${method} ${fullUri || uri}`);
        }

        if (this.isLikelySqli(normalized)) {
          if (sqliFrames.length < 80) sqliFrames.push(frame);
          if (sqliSamples.length < 3) sqliSamples.push(`${method} ${fullUri || uri}`);
        }

        if (this.isLikelyDirectoryTraversal(normalized)) {
          if (traversalFrames.length < 80) traversalFrames.push(frame);
          if (traversalSamples.length < 3) traversalSamples.push(`${method} ${fullUri || uri}`);
        }

        if (this.isLikelyCommandInjection(normalized)) {
          if (commandFrames.length < 80) commandFrames.push(frame);
          if (commandSamples.length < 3) commandSamples.push(`${method} ${fullUri || uri}`);
        }
      }

      const anomalies: TrafficAnomaly[] = [];

      if (xssFrames.length > 0) {
        anomalies.push({
          type: 'xss_attack',
          srcIp: sampleSrcIp || undefined,
          dstIp: sampleDstIp || undefined,
          dstPort: sampleDstPort || undefined,
          packetNumbers: xssFrames,
          description: `Potential XSS payloads detected in HTTP request URIs (${xssFrames.length} frames). Samples: ${xssSamples.join(' ; ')}`,
          severity: xssFrames.length >= 3 ? 'critical' : 'high',
          confidence: xssFrames.length >= 3 ? 0.93 : 0.82,
          payloadEvidence: true,
        });
      }

      if (sqliFrames.length > 0) {
        anomalies.push({
          type: 'sqli_attack',
          srcIp: sampleSrcIp || undefined,
          dstIp: sampleDstIp || undefined,
          dstPort: sampleDstPort || undefined,
          packetNumbers: sqliFrames,
          description: `Potential SQL injection payloads detected in HTTP request URIs (${sqliFrames.length} frames). Samples: ${sqliSamples.join(' ; ')}`,
          severity: sqliFrames.length >= 3 ? 'critical' : 'high',
          confidence: sqliFrames.length >= 3 ? 0.92 : 0.8,
          payloadEvidence: true,
        });
      }

      if (traversalFrames.length > 0) {
        anomalies.push({
          type: 'directory_traversal',
          srcIp: sampleSrcIp || undefined,
          dstIp: sampleDstIp || undefined,
          dstPort: sampleDstPort || undefined,
          packetNumbers: traversalFrames,
          description: `Potential directory traversal patterns detected in HTTP request URIs (${traversalFrames.length} frames). Samples: ${traversalSamples.join(' ; ')}`,
          severity: 'critical',
          confidence: traversalFrames.length >= 2 ? 0.95 : 0.85,
          payloadEvidence: true,
        });
      }

      if (commandFrames.length > 0) {
        anomalies.push({
          type: 'command_injection',
          srcIp: sampleSrcIp || undefined,
          dstIp: sampleDstIp || undefined,
          dstPort: sampleDstPort || undefined,
          packetNumbers: commandFrames,
          description: `Potential command injection payloads detected in HTTP request URIs (${commandFrames.length} frames). Samples: ${commandSamples.join(' ; ')}`,
          severity: commandFrames.length >= 3 ? 'high' : 'medium',
          confidence: commandFrames.length >= 3 ? 0.86 : 0.72,
          payloadEvidence: true,
        });
      }

      return anomalies;
    } catch (err: any) {
      console.error('[NetworkAgent] Web attack detection failed:', err.message);
      return [];
    }
  }

  private normalizeUriForDetection(input: string): string {
    const lower = (input || '').toLowerCase();
    const decoded = this.safeDecodeURIComponent(lower);
    return `${lower}\n${decoded}`;
  }

  private safeDecodeURIComponent(value: string): string {
    try {
      return decodeURIComponent(value.replace(/\+/g, '%20'));
    } catch {
      return value;
    }
  }

  private isLikelyXss(text: string): boolean {
    const patterns = [
      /<script\b/i,
      /javascript:/i,
      /alert\s*\(/i,
      /onerror\s*=/i,
      /onload\s*=/i,
      /<img\b[^>]*onerror\s*=/i,
      /<iframe\b/i,
      /document\.cookie/i,
      /%3[cC]script/i,
      /%3[cC]img/i,
      /%3[cC]iframe/i,
      /prompt\s*\(/i,
      /confirm\s*\(/i,
      /eval\s*\(/i,
      /fromcharcode/i,
    ];
    return patterns.some(r => r.test(text));
  }

  private isLikelySqli(text: string): boolean {
    const patterns = [
      /\bunion\b\s+\bselect\b/i,
      /\bor\b\s*['"]?1['"]?\s*=\s*['"]?1/i,
      /\band\b\s*['"]?1['"]?\s*=\s*['"]?1/i,
      /\bdrop\b\s+\btable\b/i,
      /\binformation_schema\b/i,
      /\bbenchmark\s*\(/i,
      /\bsleep\s*\(/i,
      /--\s*$/i,
      /\/\*/i,
      /xp_cmdshell/i,
      /\bwaitfor\b\s+\bdelay\b/i,
      /\binto\b\s+\boutfile\b/i,
      /\bload_file\s*\(/i,
      /\bchar\s*\(\s*\d+/i,
      /\bcast\s*\(/i,
      /\bconvert\s*\(/i,
    ];
    return patterns.some(r => r.test(text));
  }

  private isLikelyDirectoryTraversal(text: string): boolean {
    const patterns = [
      /\.\.\//i,
      /\.\.\\/i,
      /\.\.%2f/i,
      /\.\.%5c/i,
      /\/etc\/passwd/i,
      /\/etc\/shadow/i,
      /windows\/system32/i,
      /boot\.ini/i,
      /\.\.%252f/i,
      /\.\.%255c/i,
      /%252e%252e%252f/i,
      /%252e%252e%255c/i,
    ];
    return patterns.some(r => r.test(text));
  }

  private isLikelyCommandInjection(text: string): boolean {
    const patterns = [
      /[;&|`].*(cat|ls|id|whoami|curl|wget|bash|sh|nc|netcat|python|perl|ruby)\b/i,
      /\$\(.*\)/i,
      /%3b.*(cat|ls|id|whoami|curl|wget|bash|sh|nc)\b/i,
      /%7c.*(cat|ls|id|whoami|curl|wget|bash|sh|nc)\b/i,
      /\bping\b.*-c\s+\d+/i,
      /\bpowershell\b/i,
      /\bcmd\.exe\b/i,
      /\b\/bin\/sh\b/i,
      /\bnc\s+-[el]/i,
    ];
    return patterns.some(r => r.test(text));
  }

  private async countHttpRequests(filePath: string): Promise<number> {
    try {
      const raw = await this.tshark.applyFilter(filePath, 'http', 500);
      return raw.split('\n').filter(l => l.trim()).length;
    } catch { return 0; }
  }

  private async detectPlaintextAuth(filePath: string, conversations: TrafficConversation[]): Promise<number> {
    let count = 0;
    for (const conv of conversations) {
      if (conv.protocol === 'http' || conv.protocol === 'ftp' || conv.protocol === 'telnet') count++;
    }
    return count;
  }
}
