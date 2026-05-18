import { useState, useEffect, useCallback } from 'react';
import { useStore } from '../../store';
import { getGraphStats } from '../../services/api';

interface GraphNode {
  id: string;
  type: string;
  properties: Record<string, any>;
}

interface GraphEdge {
  id: string;
  type: string;
  source: string;
  target: string;
  properties: Record<string, any>;
}

interface GraphQueryResult {
  nodes: GraphNode[];
  edges: GraphEdge[];
  paths: GraphNode[][];
}

interface GraphPanelProps {
  highlightIp?: string;
}

export function GraphPanel({ highlightIp }: GraphPanelProps) {
  const { sessionId, graphStats } = useStore();
  const [stats, setStats] = useState<any>(graphStats);
  const [queryResult, setQueryResult] = useState<GraphQueryResult | null>(null);
  const [queryType, setQueryType] = useState<'neighbors' | 'paths' | 'stats'>('stats');
  const [ipAddress, setIpAddress] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Fetch stats on mount / when graphStats changes
  useEffect(() => {
    if (graphStats) setStats(graphStats);
  }, [graphStats]);

  // Auto-query when highlightIp changes
  useEffect(() => {
    if (highlightIp) {
      setIpAddress(highlightIp);
      // Small delay to let state settle
      const t = setTimeout(() => {
        runQueryForIp(highlightIp);
      }, 100);
      return () => clearTimeout(t);
    }
  }, [highlightIp]);

  const fetchStats = useCallback(async () => {
    if (!sessionId) return;
    setLoading(true);
    setError(null);
    try {
      const s = await getGraphStats(sessionId);
      setStats(s);
      setQueryResult(null);
      setQueryType('stats');
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [sessionId]);

  const runQueryForIp = useCallback(async (ip: string) => {
    if (!sessionId || !ip) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/graph/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionId,
          query: {
            startNode: { type: 'ip', properties: { address: ip } },
            edgeType: 'connects',
            direction: 'both',
            limit: 50,
          },
        }),
      });
      const json = await res.json();
      if (!json.success) throw new Error(json.error);
      setQueryResult(json.data);
      setQueryType('neighbors');
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [sessionId]);

  const runQuery = useCallback(() => runQueryForIp(ipAddress), [runQueryForIp, ipAddress]);

  if (!stats && !sessionId) {
    return (
      <div className="p-6 text-center text-gray-500">
        <p className="text-lg mb-2">🕸️ Traffic Graph</p>
        <p className="text-sm">Upload a pcap file to build the network graph.</p>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="p-4 border-b border-gray-800">
        <h2 className="text-lg font-semibold flex items-center gap-2">
          🕸️ Traffic Graph
          {stats && (
            <span className="text-xs font-normal text-gray-400">
              {stats.nodeCount?.toLocaleString()} nodes · {stats.edgeCount?.toLocaleString()} edges
            </span>
          )}
        </h2>
      </div>

      {/* Controls */}
      <div className="p-4 border-b border-gray-800 space-y-3">
        <div className="flex gap-2">
          <button
            onClick={fetchStats}
            className={`px-3 py-1.5 rounded text-sm ${queryType === 'stats' ? 'bg-saca-600 text-white' : 'bg-gray-800 text-gray-300 hover:bg-gray-700'}`}
          >
            📊 Stats
          </button>
          <div className="flex gap-2 flex-1">
            <input
              type="text"
              value={ipAddress}
              onChange={e => setIpAddress(e.target.value)}
              placeholder="IP address (e.g. 192.168.1.1)"
              className="flex-1 bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-sm text-white placeholder-gray-600"
              onKeyDown={e => e.key === 'Enter' && runQuery()}
            />
            <button
              onClick={runQuery}
              disabled={!ipAddress || loading}
              className="px-3 py-1.5 bg-saca-600 text-white rounded text-sm hover:bg-saca-500 disabled:opacity-50"
            >
              {loading ? '...' : '🔍 Query'}
            </button>
          </div>
        </div>
        {error && <p className="text-red-400 text-xs">{error}</p>}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto p-4">
        {queryType === 'stats' && stats && <GraphStatsView stats={stats} />}
        {queryType === 'neighbors' && queryResult && <GraphVisualization data={queryResult} />}
      </div>
    </div>
  );
}

function GraphStatsView({ stats }: { stats: any }) {
  const nodeTypes = stats.nodeCountsByType || {};
  const edgeTypes = stats.edgeCountsByType || {};
  const topTalkers = stats.topTalkers || [];

  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-2 gap-3">
        <div className="bg-gray-900 rounded-lg p-3 border border-gray-800">
          <p className="text-xs text-gray-500 uppercase">Nodes</p>
          <p className="text-2xl font-bold text-saca-400">{stats.nodeCount?.toLocaleString()}</p>
        </div>
        <div className="bg-gray-900 rounded-lg p-3 border border-gray-800">
          <p className="text-xs text-gray-500 uppercase">Edges</p>
          <p className="text-2xl font-bold text-saca-400">{stats.edgeCount?.toLocaleString()}</p>
        </div>
      </div>

      {/* Node Types */}
      <div>
        <h3 className="text-sm font-semibold text-gray-300 mb-2">Node Types</h3>
        <div className="grid grid-cols-2 gap-2">
          {Object.entries(nodeTypes).map(([type, count]: [string, any]) => (
            <div key={type} className="flex justify-between bg-gray-900 rounded px-3 py-2 text-sm">
              <span className="text-gray-400 capitalize">{type}</span>
              <span className="text-white font-mono">{count}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Edge Types */}
      <div>
        <h3 className="text-sm font-semibold text-gray-300 mb-2">Edge Types</h3>
        <div className="grid grid-cols-2 gap-2">
          {Object.entries(edgeTypes).map(([type, count]: [string, any]) => (
            <div key={type} className="flex justify-between bg-gray-900 rounded px-3 py-2 text-sm">
              <span className="text-gray-400 capitalize">{type.replace(/_/g, ' ')}</span>
              <span className="text-white font-mono">{count}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Top Talkers */}
      {topTalkers.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-gray-300 mb-2">Top Talkers</h3>
          <div className="space-y-1">
            {topTalkers.slice(0, 10).map((t: any, i: number) => (
              <div key={i} className="flex justify-between bg-gray-900 rounded px-3 py-2 text-sm">
                <span className="text-gray-300 font-mono text-xs">{t.ip?.replace('ip:', '')}</span>
                <span className="text-gray-500 text-xs">{t.packetCount} pkts · {(t.byteCount / 1024).toFixed(1)} kB</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function GraphVisualization({ data }: { data: GraphQueryResult }) {
  const { nodes, edges } = data;
  if (nodes.length === 0) return <p className="text-gray-500 text-center">No results</p>;

  // Simple circular layout
  const centerX = 300;
  const centerY = 250;
  const radius = Math.min(200, nodes.length * 15);

  const nodePositions = new Map<string, { x: number; y: number }>();

  // Place first node at center
  if (nodes.length > 0) {
    nodePositions.set(nodes[0].id, { x: centerX, y: centerY });
  }

  // Place others in a circle
  const otherNodes = nodes.slice(1);
  otherNodes.forEach((node, i) => {
    const angle = (2 * Math.PI * i) / Math.max(otherNodes.length, 1);
    nodePositions.set(node.id, {
      x: centerX + radius * Math.cos(angle),
      y: centerY + radius * Math.sin(angle),
    });
  });

  const getNodeColor = (type: string) => {
    switch (type) {
      case 'ip': return '#60a5fa'; // blue
      case 'port': return '#f472b6'; // pink
      case 'stream': return '#a78bfa'; // purple
      case 'protocol': return '#34d399'; // green
      default: return '#9ca3af';
    }
  };

  return (
    <div className="space-y-3">
      <p className="text-xs text-gray-500">
        Showing {nodes.length} nodes, {edges.length} connections
      </p>

      <div className="bg-gray-900 rounded-lg border border-gray-800 overflow-auto">
        <svg width="600" height="500" viewBox="0 0 600 500">
          {/* Edges */}
          {edges.map(edge => {
            const src = nodePositions.get(edge.source);
            const tgt = nodePositions.get(edge.target);
            if (!src || !tgt) return null;
            return (
              <line
                key={edge.id}
                x1={src.x}
                y1={src.y}
                x2={tgt.x}
                y2={tgt.y}
                stroke="#4b5563"
                strokeWidth={1}
                opacity={0.6}
              />
            );
          })}

          {/* Nodes */}
          {nodes.map(node => {
            const pos = nodePositions.get(node.id);
            if (!pos) return null;
            const isCenter = node.id === nodes[0]?.id;
            const label = node.properties.address || node.properties.number || node.id.split(':').pop() || node.id;
            return (
              <g key={node.id}>
                <circle
                  cx={pos.x}
                  cy={pos.y}
                  r={isCenter ? 20 : 12}
                  fill={getNodeColor(node.type)}
                  opacity={0.9}
                  stroke="#1f2937"
                  strokeWidth={2}
                />
                <text
                  x={pos.x}
                  y={pos.y + (isCenter ? 32 : 22)}
                  textAnchor="middle"
                  fill="#d1d5db"
                  fontSize={isCenter ? 11 : 9}
                  fontFamily="monospace"
                >
                  {label}
                </text>
                <text
                  x={pos.x}
                  y={pos.y + (isCenter ? 44 : 32)}
                  textAnchor="middle"
                  fill="#6b7280"
                  fontSize={8}
                >
                  {node.type}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      {/* Edge details */}
      <div className="space-y-1 max-h-48 overflow-auto">
        {edges.slice(0, 20).map(edge => (
          <div key={edge.id} className="flex justify-between bg-gray-900 rounded px-3 py-1.5 text-xs">
            <span className="text-gray-400">
              {edge.properties.protocol?.toUpperCase()} {edge.properties.srcPort} → {edge.properties.dstPort}
            </span>
            <span className="text-gray-500">
              {edge.properties.packetCount} pkts
            </span>
          </div>
        ))}
        {edges.length > 20 && (
          <p className="text-gray-600 text-xs text-center">... and {edges.length - 20} more</p>
        )}
      </div>
    </div>
  );
}
