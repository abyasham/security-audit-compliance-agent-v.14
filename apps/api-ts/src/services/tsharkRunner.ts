/**
 * Minimal TsharkRunner stub — retained for capture route compatibility.
 *
 * In v14, all heavy pcap analysis is done by Python Core (pyshark).
 * This stub provides basic tshark CLI access for the capture route's
 * packet inspection / summary endpoints.
 */

import { execFile } from 'child_process';
import fs from 'fs';
import { config } from '../config';

function whichTshark(): string {
  if (config.tsharkPath && fs.existsSync(config.tsharkPath)) return config.tsharkPath;
  // Try PATH
  return 'tshark';
}

export class TsharkRunner {
  private detectedPath: string | null = null;
  private attempted = false;

  get tsharkPath(): string {
    if (!this.attempted) {
      this.detectedPath = this.detectSync();
      this.attempted = true;
    }
    return this.detectedPath || 'tshark';
  }

  isAvailable(): boolean {
    return this.tsharkPath !== 'tshark' || this.detectSync() !== null;
  }

  getStatus() {
    return { path: this.tsharkPath, available: this.isAvailable() };
  }

  async detectTshark(): Promise<string | null> {
    const path = this.detectSync();
    if (path) this.detectedPath = path;
    return path;
  }

  private detectSync(): string | null {
    if (config.tsharkPath && fs.existsSync(config.tsharkPath)) return config.tsharkPath;
    // Check common Windows paths
    const candidates = [
      'C:\\Program Files\\Wireshark\\tshark.exe',
    ];
    for (const c of candidates) {
      if (fs.existsSync(c)) return c;
    }
    return null;
  }

  async getCaptureSummary(filePath: string): Promise<any> {
    try {
      // Use tshark with frame count to get packet statistics
      // Output format: frame.number and frame.time for duration calculation
      const output = await this.runTshark(filePath, '-T fields -e frame.number -e frame.time');
      const lines = output.trim().split('\n').filter((line: string) => line.length > 0);
      
      const packetCount = lines.length;
      
      // Try to calculate duration
      let durationSeconds = 0;
      if (lines.length > 1) {
        const times = lines.map((line: string) => {
          const parts = line.split('\t');
          return parseFloat(parts[1]) || 0;
        }).filter((t: number) => t > 0);
        
        if (times.length > 1) {
          durationSeconds = Math.round(times[times.length - 1] - times[0]);
        }
      }

      // Get TCP stream count
      let tcpStreamCount = 0;
      try {
        const convOutput = await this.runTshark(filePath, '-q -z conv,tcp');
        const convLines = convOutput.trim().split('\n');
        // Count conversation lines (lines with packet counts)
        tcpStreamCount = Math.max(0, convLines.filter((line: string) => /\d+\s+\d+\s+bytes/.test(line)).length);
      } catch {
        tcpStreamCount = 0;
      }

      return {
        totalPackets: Math.max(0, packetCount),
        packetCount: Math.max(0, packetCount),
        tcpStreamCount: Math.max(0, tcpStreamCount),
        durationSeconds: Math.max(0, durationSeconds),
        protocolBreakdown: {},
        startTime: '',
        endTime: '',
      };
    } catch (err: any) {
      // Fallback: return basic structure
      return {
        totalPackets: 0,
        packetCount: 0,
        tcpStreamCount: 0,
        durationSeconds: 0,
        protocolBreakdown: {},
        startTime: '',
        endTime: '',
      };
    }
  }

  async getConversations(filePath: string, protocol: string): Promise<string> {
    return this.runTshark(filePath, `-q -z conv,${protocol}`);
  }

  async getPacketRange(filePath: string, start: number, end: number, filter?: string): Promise<string> {
    const count = Math.min(end - start + 1, 100);
    const f = filter ? `-Y "${filter}"` : '';
    return this.runTshark(
      filePath,
      `${f} -T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Protocol -e _ws.col.Info -c ${count}`
    );
  }

  async getExpertInfo(filePath: string, _severity: string): Promise<string> {
    return this.runTshark(filePath, '-z expert');
  }

  async applyFilter(filePath: string, displayFilter: string, maxPackets: number = 50): Promise<string> {
    return this.runTshark(
      filePath,
      `-Y "${displayFilter}" -T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Protocol -e _ws.col.Info -c ${maxPackets}`
    );
  }

  async followStream(filePath: string, streamId: number, _mode: string = 'ascii'): Promise<string> {
    return this.runTshark(filePath, `-q -z follow,tcp,ascii,${streamId}`);
  }

  async getStreamDetail(filePath: string, streamIndex: number): Promise<string> {
    return this.runTshark(filePath, `-q -z follow,tcp,ascii,${streamIndex}`);
  }

  async getProtocolHierarchy(filePath: string): Promise<string> {
    return this.runTshark(filePath, '-q -z io,phs');
  }

  async runTshark(filePath: string, extraArgs: string): Promise<string> {
    return new Promise((resolve, reject) => {
      // Properly parse arguments to avoid splitting quoted strings
      const args = ['-r', filePath];
      const parts = extraArgs.match(/(?:[^\s"]+|"[^"]*")+/g) || [];
      args.push(...parts.map(p => p.replace(/^"|"$/g, '')));
      
      execFile(this.tsharkPath, args, { maxBuffer: 10 * 1024 * 1024, timeout: 30000 }, (err, stdout) => {
        if (err) return reject(err);
        resolve(stdout);
      });
    });
  }
}
