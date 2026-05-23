import { useState, useEffect } from 'react';
import { useStore } from '../../store';
import { LLMProviderType } from '../../types';

const PROVIDER_INFO: Record<string, { label: string; color: string; icon: string }> = {
  ollama: { label: 'Ollama (Local)', color: 'text-yellow-400', icon: '🦙' },
  deepseek: { label: 'DeepSeek API', color: 'text-blue-400', icon: '🔵' },
  openrouter: { label: 'OpenRouter #1', color: 'text-purple-400', icon: '🟣' },
  openrouter2: { label: 'OpenRouter #2', color: 'text-indigo-400', icon: '🟪' },
  openai: { label: 'OpenAI API', color: 'text-green-400', icon: '🟢' },
  kimi: { label: 'Kimi (Moonshot)', color: 'text-pink-400', icon: '🌙' },
  nvidia: { label: 'NVIDIA NIM', color: 'text-lime-400', icon: '🟩' },
};

const AGENT_LABELS: Record<string, { label: string; icon: string; description: string }> = {
  policy: { label: 'Policy Agent', icon: '📜', description: 'Parses policy documents into structured rules' },
  network: { label: 'Network Agent', icon: '📡', description: 'Analyzes pcap files using tshark tools' },
  judge: { label: 'Compliance Judge', icon: '⚖️', description: 'Cross-references rules against traffic' },
};

export function LlmSettings() {
  const { llmConfig, setLlmConfig } = useStore();
  const [expanded, setExpanded] = useState(false);
  const [agentExpanded, setAgentExpanded] = useState(false);
  const [providerStatus, setProviderStatus] = useState<Array<{ type: string; model: string; configured: boolean }>>([]);

  // Fetch provider status from backend
  useEffect(() => {
    fetch('/api/chat/status')
      .then(r => r.json())
      .then(data => {
        if (data.success && data.data?.providers?.providers) {
          setProviderStatus(data.data.providers.providers);
        }
      })
      .catch(() => {});
  }, []);

  const availableProviders = providerStatus.filter(p => p.configured);

  const applyRecommendedSplit = async () => {
    const updated = { ...llmConfig };
    if (!updated.agentProviders) updated.agentProviders = {};

    const hasDeepseek = availableProviders.some(p => p.type === 'deepseek');
    const hasOpenai = availableProviders.some(p => p.type === 'openai');

    if (hasDeepseek) {
      updated.agentProviders.policy = 'deepseek';
      updated.agentProviders.judge = 'deepseek';
    }
    if (hasOpenai) {
      updated.agentProviders.network = 'openai';
    } else if (hasDeepseek) {
      updated.agentProviders.network = 'deepseek';
    }

    await setLlmConfig(updated);
  };

  const switchProvider = async (type: string) => {
    const provider = providerStatus.find(p => p.type === type);
    if (!provider) return;

    const updated = { ...llmConfig };
    updated.primary = {
      type: type as LLMProviderType,
      baseUrl: type === 'ollama' ? 'http://localhost:11434' : undefined,
      model: provider.model,
      isActive: true,
    };
    await setLlmConfig(updated);
  };

  const setAgentProvider = (agent: 'policy' | 'network' | 'judge', providerType: string | null) => {
    const updated = { ...llmConfig };
    if (!updated.agentProviders) updated.agentProviders = {};
    if (providerType === null) {
      delete updated.agentProviders[agent];
    } else {
      updated.agentProviders[agent] = providerType as LLMProviderType;
    }
    setLlmConfig(updated);
  };

  return (
    <div className="space-y-3">
      {/* Global Provider */}
      <div className="card">
        <button
          onClick={() => setExpanded(!expanded)}
          className="w-full flex items-center justify-between text-sm"
        >
          <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">
            🤖 Global LLM Provider
          </h3>
          <span className={`transition-transform ${expanded ? 'rotate-180' : ''}`}>▼</span>
        </button>

        <div className="mt-2 flex items-center gap-2 text-sm">
          <span className={PROVIDER_INFO[llmConfig.primary.type]?.color || 'text-gray-400'}>
            {PROVIDER_INFO[llmConfig.primary.type]?.icon} {PROVIDER_INFO[llmConfig.primary.type]?.label || llmConfig.primary.type}
          </span>
          <span className="text-green-400 text-xs">● Active</span>
        </div>

        {expanded && (
          <div className="mt-3 space-y-2 pt-3 border-t border-gray-800">
            <p className="text-xs text-gray-500 mb-2">Configured providers (from .env):</p>

            {availableProviders.length === 0 ? (
              <p className="text-xs text-yellow-400">No providers configured. Add API keys to backend/.env</p>
            ) : (
              <div className="space-y-1">
                {availableProviders.map((p) => (
                  <button
                    key={p.type}
                    onClick={() => switchProvider(p.type)}
                    className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-sm transition-colors ${
                      llmConfig.primary.type === p.type
                        ? 'bg-saca-600/20 border border-saca-600/50 text-saca-300'
                        : 'bg-gray-800 border border-gray-700 text-gray-400 hover:bg-gray-700'
                    }`}
                  >
                    <span>
                      {PROVIDER_INFO[p.type]?.icon} {PROVIDER_INFO[p.type]?.label || p.type}
                    </span>
                    <span className="text-xs text-gray-500">{p.model}</span>
                  </button>
                ))}
              </div>
            )}

            <p className="text-xs text-gray-600 mt-2">
              API keys are configured in backend/.env and never exposed to the browser.
            </p>
          </div>
        )}
      </div>

      {/* Per-Agent Provider Selection */}
      <div className="card">
        <button
          onClick={() => setAgentExpanded(!agentExpanded)}
          className="w-full flex items-center justify-between text-sm"
        >
          <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">
            🧩 Per-Agent Providers
          </h3>
          <span className={`transition-transform ${agentExpanded ? 'rotate-180' : ''}`}>▼</span>
        </button>

        <div className="mt-2 text-xs text-gray-500">
          Override which LLM each agent uses. Leave as "Global" to use the provider above.
        </div>

        {agentExpanded && (
          <div className="mt-3 space-y-3 pt-3 border-t border-gray-800">
            <div className="flex flex-wrap items-center gap-2">
              <button
                onClick={applyRecommendedSplit}
                className="px-3 py-1.5 rounded text-xs font-semibold border border-saca-600/60 text-saca-300 bg-saca-600/10 hover:bg-saca-600/20 transition-colors"
              >
                ✅ Apply Recommended Split
              </button>
              <span className="text-[11px] text-gray-500">
                Uses DeepSeek for Policy/Judge and OpenAI for Network when available.
              </span>
            </div>

            {(['policy', 'network', 'judge'] as const).map((agent) => {
              const current = llmConfig.agentProviders?.[agent];
              const info = AGENT_LABELS[agent];
              return (
                <div key={agent} className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm">{info.icon}</span>
                    <span className="text-sm font-medium text-gray-300">{info.label}</span>
                  </div>
                  <p className="text-xs text-gray-500 ml-6">{info.description}</p>
                  <div className="ml-6 flex flex-wrap gap-1 mt-1">
                    <button
                      onClick={() => setAgentProvider(agent, null)}
                      className={`px-2 py-1 rounded text-xs border transition-colors ${
                        !current
                          ? 'bg-saca-600/20 border-saca-600/50 text-saca-300'
                          : 'bg-gray-800 border-gray-700 text-gray-400 hover:bg-gray-700'
                      }`}
                    >
                      🌐 Global ({llmConfig.primary.type})
                    </button>
                    {availableProviders.map((p) => (
                      <button
                        key={p.type}
                        onClick={() => setAgentProvider(agent, p.type)}
                        className={`px-2 py-1 rounded text-xs border transition-colors ${
                          current === p.type
                            ? 'bg-saca-600/20 border-saca-600/50 text-saca-300'
                            : 'bg-gray-800 border-gray-700 text-gray-400 hover:bg-gray-700'
                        }`}
                      >
                        {PROVIDER_INFO[p.type]?.icon} {PROVIDER_INFO[p.type]?.label || p.type}
                      </button>
                    ))}
                  </div>
                </div>
              );
            })}

            <div className="bg-gray-900/50 rounded p-2 text-xs text-gray-500">
              <p className="font-medium text-gray-400 mb-1">💡 Recommended splits:</p>
              <ul className="space-y-0.5 ml-1">
                <li>• <strong>DeepSeek</strong> for Policy (structured extraction)</li>
                <li>• <strong>OpenAI GPT-4.1-mini</strong> for Network (tool-calling accuracy)</li>
                <li>• <strong>DeepSeek</strong> for Judge (consistent rule matching)</li>
              </ul>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
