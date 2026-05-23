"use strict";
/**
 * Minimal TsharkRunner stub — retained for capture route compatibility.
 *
 * In v14, all heavy pcap analysis is done by Python Core (pyshark).
 * This stub provides basic tshark CLI access for the capture route's
 * packet inspection / summary endpoints.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.TsharkRunner = void 0;
const child_process_1 = require("child_process");
const fs_1 = __importDefault(require("fs"));
const config_1 = require("../config");
function whichTshark() {
    if (config_1.config.tsharkPath && fs_1.default.existsSync(config_1.config.tsharkPath))
        return config_1.config.tsharkPath;
    // Try PATH
    return 'tshark';
}
class TsharkRunner {
    detectedPath = null;
    attempted = false;
    get tsharkPath() {
        if (!this.attempted) {
            this.detectedPath = this.detectSync();
            this.attempted = true;
        }
        return this.detectedPath || 'tshark';
    }
    isAvailable() {
        return this.tsharkPath !== 'tshark' || this.detectSync() !== null;
    }
    getStatus() {
        return { path: this.tsharkPath, available: this.isAvailable() };
    }
    async detectTshark() {
        const path = this.detectSync();
        if (path)
            this.detectedPath = path;
        return path;
    }
    detectSync() {
        if (config_1.config.tsharkPath && fs_1.default.existsSync(config_1.config.tsharkPath))
            return config_1.config.tsharkPath;
        // Check common Windows paths
        const candidates = [
            'C:\\Program Files\\Wireshark\\tshark.exe',
        ];
        for (const c of candidates) {
            if (fs_1.default.existsSync(c))
                return c;
        }
        return null;
    }
    async getCaptureSummary(filePath) {
        try {
            // Use tshark with frame count to get packet statistics
            // Output format: frame.number and frame.time for duration calculation
            const output = await this.runTshark(filePath, '-T fields -e frame.number -e frame.time');
            const lines = output.trim().split('\n').filter((line) => line.length > 0);
            const packetCount = lines.length;
            // Try to calculate duration
            let durationSeconds = 0;
            if (lines.length > 1) {
                const times = lines.map((line) => {
                    const parts = line.split('\t');
                    return parseFloat(parts[1]) || 0;
                }).filter((t) => t > 0);
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
                tcpStreamCount = Math.max(0, convLines.filter((line) => /\d+\s+\d+\s+bytes/.test(line)).length);
            }
            catch {
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
        }
        catch (err) {
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
    async getConversations(filePath, protocol) {
        return this.runTshark(filePath, `-q -z conv,${protocol}`);
    }
    async getPacketRange(filePath, start, end, filter) {
        const count = Math.min(end - start + 1, 100);
        const f = filter ? `-Y "${filter}"` : '';
        return this.runTshark(filePath, `${f} -T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Protocol -e _ws.col.Info -c ${count}`);
    }
    async getExpertInfo(filePath, _severity) {
        return this.runTshark(filePath, '-z expert');
    }
    async applyFilter(filePath, displayFilter, maxPackets = 50) {
        return this.runTshark(filePath, `-Y "${displayFilter}" -T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Protocol -e _ws.col.Info -c ${maxPackets}`);
    }
    async followStream(filePath, streamId, _mode = 'ascii') {
        return this.runTshark(filePath, `-q -z follow,tcp,ascii,${streamId}`);
    }
    async getStreamDetail(filePath, streamIndex) {
        return this.runTshark(filePath, `-q -z follow,tcp,ascii,${streamIndex}`);
    }
    async getProtocolHierarchy(filePath) {
        return this.runTshark(filePath, '-q -z io,phs');
    }
    async runTshark(filePath, extraArgs) {
        return new Promise((resolve, reject) => {
            // Properly parse arguments to avoid splitting quoted strings
            const args = ['-r', filePath];
            const parts = extraArgs.match(/(?:[^\s"]+|"[^"]*")+/g) || [];
            args.push(...parts.map(p => p.replace(/^"|"$/g, '')));
            (0, child_process_1.execFile)(this.tsharkPath, args, { maxBuffer: 10 * 1024 * 1024, timeout: 30000 }, (err, stdout) => {
                if (err)
                    return reject(err);
                resolve(stdout);
            });
        });
    }
}
exports.TsharkRunner = TsharkRunner;
//# sourceMappingURL=tsharkRunner.js.map