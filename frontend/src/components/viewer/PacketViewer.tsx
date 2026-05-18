import { useState, useEffect, useRef, useCallback } from 'react';
import { useStore } from '../../store';
import { getPacketRange } from '../../services/api';

interface ParsedPacket {
  number: string;
  time: string;
  source: string;
  dest: string;
  protocol: string;
  info: string;
}

function formatHexDump(data: string): string {
  if (!data) return '';
  const bytes: number[] = [];
  // Extract bytes from raw output
  for (let i = 0; i < Math.min(data.length, 512); i++) {
    bytes.push(data.charCodeAt(i));
  }

  let result = '';
  const cols = 16;
  for (let i = 0; i < bytes.length; i += cols) {
    const addr = i.toString(16).padStart(8, '0');
    const hex = bytes.slice(i, i + cols)
      .map(b => b.toString(16).padStart(2, '0')).join(' ').padEnd(cols * 3, ' ');
    const ascii = bytes.slice(i, i + cols)
      .map(b => b >= 32 && b <= 126 ? String.fromCharCode(b) : '.').join('');
    result += `${addr}  ${hex}  |${ascii}|\n`;
  }
  return result;
}

export function PacketViewer() {
  const { captureFile, findings } = useStore();
  const [packets, setPackets] = useState<ParsedPacket[]>([]);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState('');
  const [selectedPacketNum, setSelectedPacketNum] = useState<number | null>(null);
  const [packetDetail, setPacketDetail] = useState('');
  const [packetHex, setPacketHex] = useState('');
  const listRef = useRef<HTMLDivElement>(null);

  // Load packets on mount and when capture file changes
  useEffect(() => {
    if (!captureFile?.filePath) return;
    loadPackets();
  }, [captureFile?.filePath]);

  const loadPackets = async (applyFilter?: string) => {
    if (!captureFile?.filePath) return;
    setLoading(true);
    try {
      const f = applyFilter !== undefined ? applyFilter : filter;
      const maxPackets = 200; // Limit for performance
      const raw = await getPacketRange(captureFile.filePath, 1, maxPackets, f || undefined);
      const parsed = parsePacketOutput(raw);
      setPackets(parsed);

      // Auto-select first packet to show detail panes
      if (parsed.length > 0) {
        const firstNum = parseInt(parsed[0].number);
        handlePacketClick(firstNum, parsed);
      } else {
        setSelectedPacketNum(null);
        setPacketDetail('');
        setPacketHex('');
      }
    } catch (err) {
      console.error('Failed to load packets:', err);
    } finally {
      setLoading(false);
    }
  };

  const parsePacketOutput = (raw: string): ParsedPacket[] => {
    const lines = raw.split('\n').filter(l => l.trim());
    return lines.map(line => {
      const parts = line.split('\t');
      return {
        number: parts[0] || '',
        time: parts[1] || '',
        source: parts[2] || parts[4] || '',
        dest: parts[3] || parts[5] || '',
        protocol: parts[6] || parts[4] || '',
        info: parts.slice(7).join(' ') || parts.slice(6).join(' ') || '',
      };
    }).filter(p => p.number && !isNaN(parseInt(p.number)));
  };

  const handlePacketClick = async (pktNum: number, packetList?: ParsedPacket[]) => {
    setSelectedPacketNum(pktNum);
    if (!captureFile?.filePath) return;
    try {
      const detail = await getPacketRange(captureFile.filePath, pktNum, pktNum);
      setPacketDetail(detail);
      // Use the info field as hex content if available
      const pkt = (packetList || packets).find(p => parseInt(p.number) === pktNum);
      setPacketHex(formatHexDump(pkt?.info || detail));
    } catch {
      setPacketDetail('Failed to load packet detail');
      setPacketHex('');
    }
  };

  const handleFilterSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    loadPackets(filter);
  };

  const handleFilterClear = () => {
    setFilter('');
    loadPackets('');
  };

  const violationPackets = new Set<number>();
  findings.filter(f => f.status === 'violated').forEach(f => f.evidencePacketNumbers.forEach(n => violationPackets.add(n)));

  const getSeverityForPacket = (pktNum: number): string | null => {
    for (const f of findings.filter(f => f.status === 'violated')) {
      if (f.evidencePacketNumbers.includes(pktNum)) return f.severity;
    }
    return null;
  };

  const severityColors: Record<string, string> = {
    critical: 'bg-red-900/50 border-red-700',
    high: 'bg-orange-900/50 border-orange-700',
    medium: 'bg-yellow-900/30 border-yellow-700',
    low: 'bg-blue-900/30 border-blue-700',
  };

  if (!captureFile) return null;

  return (
    <div className="card mt-4 overflow-hidden">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">
          📡 Packet Viewer — {captureFile.name}
        </h3>
        <span className="text-xs text-gray-500">
          {packets.length} packets{filter ? ` (filtered)` : ''}
        </span>
      </div>

      {/* Filter Bar */}
      <form onSubmit={handleFilterSubmit} className="flex gap-2 mb-2">
        <input
          type="text"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Display filter (e.g., tcp.port==80, dns, http, tls)"
          className="input-field text-sm flex-1 font-mono"
        />
        <button type="submit" className="btn-secondary text-sm px-3">Apply</button>
        {filter && (
          <button type="button" onClick={handleFilterClear}
            className="btn-secondary text-sm px-2">✕</button>
        )}
      </form>

      {/* 3-Pane Layout — Always Visible */}
      <div className="border border-gray-800 rounded-lg overflow-hidden">
        {/* Top: Packet Table */}
        <div ref={listRef} className="overflow-auto" style={{ maxHeight: '200px' }}>
          {loading ? (
            <div className="p-4 text-center text-gray-500 text-sm">Loading packets...</div>
          ) : packets.length === 0 ? (
            <div className="p-4 text-center text-gray-500 text-sm">
              {filter ? `No packets match filter: "${filter}"` : 'No packets — upload a pcap file first'}
            </div>
          ) : (
            <table className="w-full text-xs">
              <thead className="bg-gray-800 sticky top-0">
                <tr className="text-gray-400">
                  <th className="px-2 py-1.5 text-left w-12">#</th>
                  <th className="px-2 py-1.5 text-left w-16">Time</th>
                  <th className="px-2 py-1.5 text-left">Source</th>
                  <th className="px-2 py-1.5 text-left">Dest</th>
                  <th className="px-2 py-1.5 text-left w-20">Protocol</th>
                  <th className="px-2 py-1.5 text-left">Info</th>
                  <th className="px-2 py-1.5 w-8"></th>
                </tr>
              </thead>
              <tbody>
                {packets.map((pkt) => {
                  const pktNum = parseInt(pkt.number);
                  const isSelected = selectedPacketNum === pktNum;
                  const severity = getSeverityForPacket(pktNum);
                  const isViolation = violationPackets.has(pktNum);

                  return (
                    <tr key={pkt.number}
                      onClick={() => handlePacketClick(pktNum)}
                      className={`cursor-pointer border-b border-gray-800/50 transition-colors ${
                        isSelected ? 'bg-saca-600/20' :
                        isViolation && severity ? severityColors[severity] || '' :
                        'hover:bg-gray-800/50'
                      }`}>
                      <td className="px-2 py-1 font-mono text-gray-400">{pkt.number}</td>
                      <td className="px-2 py-1 font-mono text-gray-500">{pkt.time}</td>
                      <td className="px-2 py-1 font-mono">{pkt.source}</td>
                      <td className="px-2 py-1 font-mono">{pkt.dest}</td>
                      <td className="px-2 py-1">
                        <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${
                          isViolation ? 'bg-red-700/50 text-red-200' : 'bg-gray-700 text-gray-300'
                        }`}>{pkt.protocol}</span>
                      </td>
                      <td className="px-2 py-1 text-gray-300 truncate max-w-xs">{pkt.info}</td>
                      <td className="px-2 py-1">{isViolation && <span className="text-red-400">⚠</span>}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* Bottom Panes: Protocol Tree + Hex Dump */}
        {selectedPacketNum && (
          <div className="border-t border-gray-800">
            <div className="flex items-center justify-between px-2 py-1 bg-gray-800/50">
              <span className="text-xs text-gray-400">Packet {selectedPacketNum}</span>
            </div>
            <div className="grid grid-cols-2 divide-x divide-gray-800" style={{ minHeight: '160px' }}>
              {/* Protocol Tree */}
              <div className="overflow-auto p-2 bg-gray-900/50">
                <div className="text-xs font-semibold text-gray-500 mb-1 uppercase tracking-wider">Protocol Tree</div>
                <pre className="text-xs font-mono text-gray-300 whitespace-pre-wrap leading-relaxed">
                  {packetDetail || 'Select a packet to see details'}
                </pre>
              </div>
              {/* Hex Dump */}
              <div className="overflow-auto p-2 bg-gray-900/50">
                <div className="text-xs font-semibold text-gray-500 mb-1 uppercase tracking-wider">Hex Dump</div>
                <pre className="text-xs font-mono text-green-300/80 whitespace-pre leading-relaxed">
                  {packetHex || 'Select a packet to see hex dump'}
                </pre>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
