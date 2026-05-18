import { execSync, exec, spawnSync } from 'child_process';
import { existsSync } from 'fs';
import { config } from '../config';

/**
 * TsharkRunner — Ported from NetTrace Agentix's tsharkRunner.ts
 *
 * Manages tshark execution for pcap file parsing.
 * Converts binary pcap data into structured text for LLM analysis.
 */
export class TsharkRunner {
  private tsharkPath: string;
  private detected: boolean = false;

  constructor() {
    this.tsharkPath = config.tsharkPath || 'tshark';
  }

  /**
   * Detect and validate tshark installation.
   * Checks: 1) configured path, 2) PATH, 3) standard install locations
   */
  async detectTshark(): Promise<string | undefined> {
    if (this.detected) return this.tsharkPath;

    // Check configured path first
    if (config.tsharkPath && await this.validateTshark(config.tsharkPath)) {
      this.tsharkPath = config.tsharkPath;
      this.detected = true;
      return config.tsharkPath;
    }

    // Check PATH
    if (await this.validateTshark('tshark')) {
      this.tsharkPath = 'tshark';
      this.detected = true;
      return 'tshark';
    }

    // Check standard Windows install locations
    const standardPaths = [
      'C:\\Program Files\\Wireshark\\tshark.exe',
      'C:\\Program Files (x86)\\Wireshark\\tshark.exe',
    ];

    for (const p of standardPaths) {
      if (await this.validateTshark(p)) {
        this.tsharkPath = p;
        this.detected = true;
        return p;
      }
    }

    this.detected = true;
    return undefined;
  }

  /** Get tshark status info for the health endpoint */
  getStatus(): { available: boolean; path: string } {
    return {
      available: this.isAvailable(),
      path: this.tsharkPath,
    };
  }

  isAvailable(): boolean {
    try {
      execSync(`"${this.tsharkPath}" --version`, { timeout: 5000 });
      return true;
    } catch {
      return false;
    }
  }

  private async validateTshark(tsharkPath: string): Promise<boolean> {
    return new Promise((resolve) => {
      exec(`"${tsharkPath}" --version`, { timeout: 5000 }, (error) => {
        resolve(!error);
      });
    });
  }

  // ─── Capture Summary ─────────────────────────────────────────────────────

  async getCaptureSummary(filePath: string): Promise<any> {
    this.ensureFile(filePath);

    // Get packet count
    const packetCount = parseInt(
      this.execTshark(filePath, '-T fields -e frame.number').trim().split('\n').filter(l => l.trim()).pop() || '0'
    );

    // Get protocol hierarchy
    const phsRaw = this.execTshark(filePath, '-z io,phs -q');
    const protocolBreakdown: Record<string, number> = {};
    const phsLines = phsRaw.split('\n');
    for (const line of phsLines) {
      const match = line.match(/^\s*([a-z0-9-]+)\s+(\d+)\s+/i);
      if (match) {
        protocolBreakdown[match[1].toLowerCase()] = parseInt(match[2]);
      }
    }

    // Get time range — first and last packet timestamps
    const timeResult = this.execTshark(filePath, '-T fields -e frame.time_epoch').trim();
    const timeLines = timeResult.split('\n').filter(l => l.trim());
    const timeFirst = timeLines.length > 0 ? timeLines[0].trim() : '';
    const timeLast = timeLines.length > 1 ? timeLines[timeLines.length - 1].trim() : timeFirst;
    const startTime = timeFirst ? new Date(parseFloat(timeFirst) * 1000).toISOString() : '';
    const endTime = timeLast ? new Date(parseFloat(timeLast) * 1000).toISOString() : '';
    const durationSeconds = (timeFirst && timeLast) ? Math.abs(parseFloat(timeLast) - parseFloat(timeFirst)) : 0;

    // Get conversation counts
    const tcpConv = this.execTshark(filePath, '-z conv,tcp -q');
    const tcpStreamCount = (tcpConv.match(/^\s*\d+\.\d+\.\d+\.\d+/gm) || []).length;

    return {
      packetCount,
      durationSeconds: Math.round(durationSeconds * 1000) / 1000,
      protocolBreakdown,
      tcpStreamCount,
      startTime,
      endTime,
    };
  }

  // ─── Packet Range ────────────────────────────────────────────────────────

  async getPacketRange(filePath: string, startFrame: number, endFrame: number, filter?: string): Promise<string> {
    this.ensureFile(filePath);

    const maxRange = 500;
    const clampedEnd = Math.min(endFrame, startFrame + maxRange - 1);

    // Build display filter with -Y flag (takes filter as single argument)
    let displayFilter = `frame.number >= ${startFrame} && frame.number <= ${clampedEnd}`;
    if (filter) {
      displayFilter = `(${displayFilter}) && (${filter})`;
    }

    // Use -Y "filter" so the filter stays as one argument (splitArgs handles quotes)
    const tsharkArgs = `-T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e ip.proto -e _ws.col.Protocol -e _ws.col.Info -c 500 -Y "${displayFilter.replace(/"/g, '\\"')}"`;

    return this.execTshark(filePath, tsharkArgs);
  }

  // ─── Conversations ──────────────────────────────────────────────────────

  async getConversations(filePath: string, protocol: string = 'tcp'): Promise<string> {
    this.ensureFile(filePath);
    return this.execTshark(filePath, `-z conv,${protocol} -q`);
  }

  // ─── Expert Info ─────────────────────────────────────────────────────────

  async getExpertInfo(filePath: string, severity?: string): Promise<string> {
    this.ensureFile(filePath);

    let args = '-z expert,note -q';
    if (severity && severity !== 'all') {
      args = `-Y "expert.severity == ${severity}" ${args}`;
    }

    return this.execTshark(filePath, args);
  }

  // ─── Stream Detail ───────────────────────────────────────────────────────

  async getStreamDetail(filePath: string, streamIndex: number): Promise<string> {
    this.ensureFile(filePath);
    return this.execTshark(filePath, `-T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.flags -e tcp.seq -e tcp.ack -e tcp.len -e _ws.col.Info -Y "tcp.stream eq ${streamIndex}"`);
  }

  // ─── Follow Stream ───────────────────────────────────────────────────────

  async followStream(filePath: string, streamIndex: number, format: string = 'ascii'): Promise<string> {
    this.ensureFile(filePath);
    return this.execTshark(filePath, `-z follow,tcp,${format},${streamIndex} -q`);
  }

  // ─── Apply Filter ────────────────────────────────────────────────────────

  async applyFilter(filePath: string, filter: string, maxPackets: number = 100): Promise<string> {
    this.ensureFile(filePath);
    return this.execTshark(filePath, `-T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Protocol -e _ws.col.Info -Y "${filter.replace(/"/g, '\\"')}" -c ${maxPackets}`);
  }

  // ─── Run Custom Tshark ──────────────────────────────────────────────────

  async runTshark(filePath: string, args: string): Promise<string> {
    this.ensureFile(filePath);

    // Block write operations for safety
    if (/\s-w\s/.test(args) || /-w$/.test(args.trim())) {
      throw new Error('Write operations (-w) are not allowed');
    }

    return this.execTsharkRaw(`-r "${filePath}" ${args}`);
  }

  // ─── Protocol Hierarchy ─────────────────────────────────────────────────

  async getProtocolHierarchy(filePath: string): Promise<string> {
    this.ensureFile(filePath);
    return this.execTshark(filePath, '-z io,phs -q');
  }

  // ─── Helpers ─────────────────────────────────────────────────────────────

  private ensureFile(filePath: string): void {
    if (!existsSync(filePath)) {
      throw new Error(`Capture file not found: ${filePath}`);
    }
  }

  /**
   * Execute tshark using spawnSync for proper Windows path handling.
   * spawnSync handles file paths with spaces and special characters better than execSync.
   */
  private execTshark(filePath: string, args: string): string {
    console.log(`[tshark] File: ${filePath} (exists: ${existsSync(filePath)})`);

    // Split args string into array, respecting quoted strings
    const argArray = ['-r', filePath, ...splitArgs(args)];
    
    const result = spawnSync(this.tsharkPath, argArray, {
      timeout: 30000,
      encoding: 'utf-8',
      maxBuffer: 50 * 1024 * 1024,
      windowsHide: true,
    });

    if (result.error) {
      throw new Error(`tshark error: ${result.error.message}`);
    }

    // tshark sometimes exits with non-zero even on success (e.g., when no matches found)
    if (result.stdout) return result.stdout;

    if (result.stderr) {
      // Check if stderr is just informational (not an error)
      const stderr = result.stderr.toLowerCase();
      if (stderr.includes('error') || stderr.includes('not found') || stderr.includes('cannot find')) {
        throw new Error(`tshark error: ${result.stderr}`);
      }
      // Some tshark output goes to stderr but is informational
    }

    return result.stdout || '';
  }

  /**
   * Execute tshark with raw args string.
   */
  private execTsharkRaw(args: string): string {
    const argArray = splitArgs(args);
    
    const result = spawnSync(this.tsharkPath, argArray, {
      timeout: 30000,
      encoding: 'utf-8',
      maxBuffer: 50 * 1024 * 1024,
      windowsHide: true,
    });

    if (result.error) {
      throw new Error(`tshark error: ${result.error.message}`);
    }

    if (result.stdout) return result.stdout;

    const stderr = (result.stderr || '').toLowerCase();
    if (stderr.includes('error') || stderr.includes('not found')) {
      throw new Error(`tshark error: ${result.stderr}`);
    }

    return result.stdout || '';
  }
}

/**
 * Split a command-line args string into an array, respecting quoted strings.
 */
function splitArgs(input: string): string[] {
  const args: string[] = [];
  const re = /"([^"\\]*(?:\\.[^"\\]*)*)"|'([^'\\]*(?:\\.[^'\\]*)*)'|([^\s]+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(input)) !== null) {
    const token = m[1] ?? m[2] ?? m[3] ?? '';
    if (token) args.push(token);
  }
  return args;
}
