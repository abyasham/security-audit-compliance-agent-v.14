import { useStore } from '../../store';

const STAGE_LABELS: Record<string, { label: string; icon: string; description: string }> = {
  policy: { label: 'Policy Agent', icon: '📜', description: 'Extracting rules from policy document' },
  network: { label: 'Network Agent', icon: '📡', description: 'Analyzing pcap traffic for anomalies' },
  judge: { label: 'Compliance Judge', icon: '⚖️', description: 'Cross-referencing rules against traffic' },
};

export function AnalysisProgress() {
  const { analysisProgress, isAnalyzing } = useStore();

  if (!isAnalyzing || !analysisProgress) return null;

  const { stages, error } = analysisProgress;

  return (
    <div className="card p-6 space-y-4">
      <h3 className="text-lg font-semibold text-saca-300 flex items-center gap-2">
        <span className="animate-spin w-5 h-5 border-2 border-saca-500 border-t-transparent rounded-full inline-block" />
        Running Multi-Agent Analysis
      </h3>

      <div className="space-y-3">
        {stages.map((stage) => {
          const info = STAGE_LABELS[stage.name] || { label: stage.name, icon: '🔹', description: '' };
          const isActive = stage.status === 'running';
          const isDone = stage.status === 'completed';
          const isFailed = stage.status === 'failed';

          return (
            <div
              key={stage.name}
              className={`flex items-center gap-3 p-3 rounded-lg border transition-all ${
                isActive
                  ? 'bg-saca-900/20 border-saca-600/50'
                  : isDone
                  ? 'bg-green-900/10 border-green-800/30'
                  : isFailed
                  ? 'bg-red-900/10 border-red-800/30'
                  : 'bg-gray-900/30 border-gray-800/30'
              }`}
            >
              <span className="text-xl">{info.icon}</span>
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <span className={`font-medium ${isFailed ? 'text-red-300' : 'text-gray-200'}`}>
                    {info.label}
                  </span>
                  {isActive && (
                    <span className="text-xs text-saca-400 animate-pulse">Running...</span>
                  )}
                  {isDone && <span className="text-xs text-green-400">✓ Done</span>}
                  {isFailed && <span className="text-xs text-red-400">✗ Failed</span>}
                </div>
                <p className="text-xs text-gray-500">{info.description}</p>
                {stage.result && (
                  <p className="text-xs text-gray-400 mt-1">
                    {stage.name === 'policy' && `${stage.result.ruleCount} rules extracted`}
                    {stage.name === 'network' && `${stage.result.conversationCount} conversations, ${stage.result.anomalyCount} anomalies`}
                    {stage.name === 'judge' && `${stage.result.findingCount} findings`}
                  </p>
                )}
                {stage.error && (
                  <p className="text-xs text-red-400 mt-1">{stage.error}</p>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {error && (
        <div className="bg-red-900/20 border border-red-800 rounded-lg p-3 text-sm text-red-300">
          ⚠️ {error}
        </div>
      )}
    </div>
  );
}
