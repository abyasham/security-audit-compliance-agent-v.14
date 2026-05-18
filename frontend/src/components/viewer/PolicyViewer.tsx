import { useState } from 'react';
import { useStore } from '../../store';

export function PolicyViewer() {
  const { policy } = useStore();
  const [expanded, setExpanded] = useState(false);
  const [selectedRule, setSelectedRule] = useState<string | null>(null);

  if (!policy) return null;

  const severityColors: Record<string, string> = {
    critical: 'badge-critical',
    high: 'badge-high',
    medium: 'badge-medium',
    low: 'badge-low',
    info: 'badge-info',
  };

  return (
    <div className="card mt-4 overflow-hidden">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">
          📋 Policy Viewer — {policy.policyName}
        </h3>
        <span className="text-xs text-gray-500">
          {policy.sourceFormat.toUpperCase()} · {policy.rules.length} rules
        </span>
      </div>

      {/* Policy Metadata */}
      <div className="flex flex-wrap gap-3 mb-3 text-xs text-gray-500">
        <span>📄 Format: {policy.sourceFormat.toUpperCase()}</span>
        {policy.version && <span>📌 v{policy.version}</span>}
      </div>

      {/* Rules List */}
      {policy.rules.length > 0 ? (
        <div className="space-y-2 max-h-64 overflow-y-auto">
          {policy.rules.map((rule) => (
            <div
              key={rule.id}
              onClick={() => setSelectedRule(selectedRule === rule.id ? null : rule.id)}
              className={`p-3 rounded-lg border cursor-pointer transition-colors ${
                selectedRule === rule.id
                  ? 'bg-saca-600/20 border-saca-600/50'
                  : 'bg-gray-800/50 border-gray-700 hover:border-gray-600'
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-gray-200">{rule.id}</span>
                  <span className="text-sm text-gray-300">{rule.name}</span>
                </div>
                <span className={severityColors[rule.severity] || 'badge-info'}>
                  {rule.severity.toUpperCase()}
                </span>
              </div>

              {selectedRule === rule.id && (
                <div className="mt-2 pt-2 border-t border-gray-700/50 text-xs text-gray-400 space-y-1">
                  <p>{rule.description}</p>
                  <p>🏷 Category: {rule.category}</p>
                  {rule.standard && <p>📏 Standard: {rule.standard}</p>}
                </div>
              )}
            </div>
          ))}
        </div>
      ) : (
        /* Raw policy text for PDF/DOCX (LLM will process) */
        <div className="bg-gray-800/30 border border-gray-700 rounded-lg">
          <button
            onClick={() => setExpanded(!expanded)}
            className="w-full px-3 py-2 text-left text-sm text-gray-400 hover:text-gray-300 flex items-center justify-between"
          >
            <span>📄 Policy Text ({policy.rawText?.length || 0} chars)</span>
            <span className={`transition-transform ${expanded ? 'rotate-180' : ''}`}>▼</span>
          </button>
          {expanded && policy.rawText && (
            <pre className="px-3 pb-3 text-xs font-mono text-gray-500 whitespace-pre-wrap max-h-48 overflow-y-auto leading-relaxed">
              {policy.rawText}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}
