import { useState } from 'react';
import { ComplianceFinding } from '../../types';

interface FindingsPanelProps {
  findings: ComplianceFinding[];
  onDismiss: (findingId: string) => void;
  summary?: {
    totalRules: number;
    violated: number;
    compliant: number;
    suspicious: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    averageConfidence: number;
  } | null;
  isLoading?: boolean;
  onRequestGraphTab?: (ip?: string) => void;
  onRequestViewerTab?: (streamId?: number) => void;
}

function ConfidenceBadge({ confidence, status }: { confidence?: number; status?: string }) {
  if (status === 'compliant') {
    return <span className="px-2 py-0.5 rounded text-xs font-medium bg-green-900/60 text-green-300 border border-green-700">Compliant</span>;
  }
  if (status === 'suspicious') {
    return <span className="px-2 py-0.5 rounded text-xs font-medium bg-yellow-900/60 text-yellow-300 border border-yellow-700">Suspicious Activity</span>;
  }

  const c = confidence ?? 0;
  if (c >= 0.90) {
    return <span className="px-2 py-0.5 rounded text-xs font-bold bg-red-900/80 text-red-200 border border-red-600">{Math.round(c * 100)}%</span>;
  }
  if (c >= 0.70) {
    return <span className="px-2 py-0.5 rounded text-xs font-bold bg-orange-900/70 text-orange-200 border border-orange-600">{Math.round(c * 100)}%</span>;
  }
  if (c >= 0.40) {
    return <span className="px-2 py-0.5 rounded text-xs font-medium bg-yellow-900/60 text-yellow-300 border border-yellow-700">{Math.round(c * 100)}%</span>;
  }
  return <span className="px-2 py-0.5 rounded text-xs font-medium bg-gray-800 text-gray-400 border border-gray-700">{Math.round(c * 100)}%</span>;
}

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: 'bg-red-950 text-red-300 border-red-800',
    high: 'bg-orange-950 text-orange-300 border-orange-800',
    medium: 'bg-yellow-950 text-yellow-300 border-yellow-800',
    low: 'bg-blue-950 text-blue-300 border-blue-800',
    info: 'bg-gray-800 text-gray-400 border-gray-700',
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wide border ${colors[severity] || colors.info}`}>
      {severity}
    </span>
  );
}

export function FindingsPanel({ findings, onDismiss, summary, isLoading, onRequestGraphTab, onRequestViewerTab }: FindingsPanelProps) {
  const [filter, setFilter] = useState<'all' | 'violated' | 'compliant' | 'suspicious'>('all');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [dnsFirst, setDnsFirst] = useState(false);

  const isDnsFinding = (finding: ComplianceFinding) => {
    const haystack = `${finding.ruleId || ''} ${finding.ruleName || ''} ${finding.description || ''} ${finding.evidence?.details || ''}`.toLowerCase();
    return haystack.includes('dns_') || haystack.includes('dns ') || haystack.includes('mdns') || haystack.includes('resolver');
  };

  const filtered = findings.filter(f => {
    if (filter === 'all') return true;
    return f.status === filter;
  });

  const dnsCount = filtered.reduce((count, finding) => count + (isDnsFinding(finding) ? 1 : 0), 0);

  const ordered = dnsFirst
    ? [...filtered].sort((a, b) => Number(isDnsFinding(b)) - Number(isDnsFinding(a)))
    : filtered;

  if (isLoading) {
    return (
      <div className="card p-8 text-center">
        <div className="animate-spin w-8 h-8 border-2 border-saca-500 border-t-transparent rounded-full mx-auto mb-4" />
        <p className="text-gray-400">Running multi-agent analysis...</p>
        <p className="text-gray-600 text-sm mt-1">Policy Agent → Network Agent → Compliance Judge</p>
      </div>
    );
  }

  if (findings.length === 0) {
    return (
      <div className="card p-8 text-center text-gray-500">
        <p className="text-lg mb-2">🔍 No findings yet</p>
        <p className="text-sm">Upload a pcap and policy, then run analysis to see compliance results.</p>
        <p className="text-sm mt-2 text-saca-400">Tip: Click "Find all compliance violations" in the Chat tab to run the multi-agent pipeline.</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Summary Bar */}
      {summary && (
        <div className="card">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="bg-red-950/40 border border-red-900 rounded-lg p-3 text-center">
              <p className="text-2xl font-bold text-red-400">{summary.violated}</p>
              <p className="text-xs text-red-500 uppercase tracking-wide">Violations</p>
            </div>
            <div className="bg-green-950/40 border border-green-900 rounded-lg p-3 text-center">
              <p className="text-2xl font-bold text-green-400">{summary.compliant}</p>
              <p className="text-xs text-green-500 uppercase tracking-wide">Compliant</p>
            </div>
            <div className="bg-yellow-950/40 border border-yellow-900 rounded-lg p-3 text-center">
              <p className="text-2xl font-bold text-yellow-400">{summary.suspicious}</p>
              <p className="text-xs text-yellow-500 uppercase tracking-wide">Suspicious Activity</p>
            </div>
            <div className="bg-saca-950/40 border border-saca-900 rounded-lg p-3 text-center">
              <p className="text-2xl font-bold text-saca-400">{Math.round(summary.averageConfidence * 100)}%</p>
              <p className="text-xs text-saca-500 uppercase tracking-wide">Avg Confidence</p>
            </div>
          </div>
          <div className="mt-3 flex flex-wrap gap-2 text-xs text-gray-500">
            <span>🔴 Critical: {summary.criticalCount}</span>
            <span>🟠 High: {summary.highCount}</span>
            <span>🟡 Medium: {summary.mediumCount}</span>
            <span>🔵 Low: {summary.lowCount}</span>
            <span className="ml-auto">📜 Total Rules: {summary.totalRules}</span>
          </div>
        </div>
      )}

      {/* Filter Tabs */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex flex-1 gap-1 bg-gray-900 rounded-lg p-1">
          {(['all', 'violated', 'compliant', 'suspicious'] as const).map(f => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`flex-1 py-1.5 px-3 rounded-md text-xs font-medium transition-colors ${
                filter === f
                  ? 'bg-saca-700 text-white'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800'
              }`}
            >
              {f === 'all' ? `All (${findings.length})` : `${f.charAt(0).toUpperCase() + f.slice(1)} (${findings.filter(x => x.status === f).length})`}
            </button>
          ))}
        </div>
        <button
          onClick={() => setDnsFirst(prev => !prev)}
          aria-pressed={dnsFirst}
          className={`px-3 py-1.5 rounded-md text-xs font-medium border transition-colors ${
            dnsFirst
              ? 'bg-blue-900/50 text-blue-200 border-blue-700'
              : 'bg-gray-900 text-gray-400 border-gray-700 hover:text-gray-200 hover:border-gray-500'
          }`}
        >
          {dnsFirst ? `DNS first: On (${dnsCount})` : `DNS first (${dnsCount})`}
        </button>
      </div>

      {/* Findings List */}
      <div className="space-y-2 max-h-[600px] overflow-y-auto pr-1">
        {ordered.map(finding => (
          <div
            key={finding.id}
            className={`card p-4 transition-all ${
              finding.status === 'violated'
                ? 'border-l-4 border-l-red-600'
                : finding.status === 'compliant'
                ? 'border-l-4 border-l-green-600'
                : 'border-l-4 border-l-yellow-600'
            } ${finding.dismissed ? 'opacity-50' : ''}`}
          >
            <div className="flex items-start gap-3">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap mb-1">
                  <SeverityBadge severity={finding.severity} />
                  <ConfidenceBadge confidence={finding.confidence} status={finding.status} />
                  {finding.standard && (
                    <span className="text-xs text-gray-500">{finding.standard}</span>
                  )}
                </div>
                <h4 className="text-sm font-semibold text-gray-200 truncate">
                  {finding.ruleName}
                </h4>
                <p className="text-xs text-gray-400 mt-0.5">{finding.description}</p>

                {/* Evidence */}
                {finding.evidence && (
                  <div className="mt-2 text-xs text-gray-500 bg-gray-900/50 rounded p-2">
                    <div className="flex flex-wrap gap-x-3 gap-y-1">
                      {finding.evidence.streamId !== undefined && (
                        <span>📡 Stream {finding.evidence.streamId}</span>
                      )}
                      {finding.evidence.srcIp && (
                        <span>📤 {finding.evidence.srcIp}</span>
                      )}
                      {finding.evidence.dstIp && (
                        <span>📥 {finding.evidence.dstIp}{finding.evidence.dstPort ? `:${finding.evidence.dstPort}` : ''}</span>
                      )}
                      {finding.evidence.protocol && (
                        <span>🔌 {finding.evidence.protocol.toUpperCase()}</span>
                      )}
                    </div>
                    {finding.evidence.details && (
                      <p className="mt-1 text-gray-400">{finding.evidence.details}</p>
                    )}

                    {/* Traceability Actions */}
                    {(finding.evidence.streamId !== undefined || finding.evidence.srcIp || finding.evidence.dstIp || finding.evidencePacketNumbers.length > 0) && (
                      <div className="mt-2 flex gap-2">
                        {(finding.evidence.srcIp || finding.evidence.dstIp) && onRequestGraphTab && (
                          <button
                            onClick={() => onRequestGraphTab(finding.evidence!.srcIp || finding.evidence!.dstIp || undefined)}
                            className="px-2 py-1 rounded bg-saca-950/60 text-saca-400 hover:text-saca-300 hover:bg-saca-900/40 text-[10px] font-medium border border-saca-900 transition-colors"
                          >
                            🕸️ Trace in Graph
                          </button>
                        )}
                        {finding.evidencePacketNumbers.length > 0 && onRequestViewerTab && (
                          <button
                            onClick={() => onRequestViewerTab(finding.evidence!.streamId)}
                            className="px-2 py-1 rounded bg-blue-950/60 text-blue-400 hover:text-blue-300 hover:bg-blue-900/40 text-[10px] font-medium border border-blue-900 transition-colors"
                          >
                            📊 View Packets
                          </button>
                        )}
                      </div>
                    )}
                  </div>
                )}

                {/* Reasoning */}
                {finding.reasoning && (
                  <div className="mt-1">
                    <button
                      onClick={() => setExpandedId(expandedId === finding.id ? null : finding.id)}
                      className="text-xs text-saca-400 hover:text-saca-300"
                    >
                      {expandedId === finding.id ? '▾ Hide reasoning' : '▸ Show reasoning'}
                    </button>
                    {expandedId === finding.id && (
                      <p className="text-xs text-gray-500 mt-1 italic">{finding.reasoning}</p>
                    )}
                  </div>
                )}
              </div>

              <button
                onClick={() => onDismiss(finding.id)}
                className="text-gray-600 hover:text-gray-400 text-sm"
                title="Dismiss finding"
              >
                ✕
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
