import { useState, useEffect } from 'react';
import { useStore } from './store';
import { Header } from './components/layout/Header';
import { PcapUpload } from './components/upload/PcapUpload';
import { PolicyUpload } from './components/upload/PolicyUpload';
import { ChatPanel } from './components/chat/ChatPanel';
import { PacketViewer } from './components/viewer/PacketViewer';
import { PolicyViewer } from './components/viewer/PolicyViewer';
import { GraphPanel } from './components/graph/GraphPanel';
import { FindingsPanel } from './components/findings/FindingsPanel';
import { LlmSettings } from './components/settings/LlmSettings';
import { checkHealth } from './services/api';

export default function App() {
  const { step, setStep, captureFile, policy, error, clearError, initSession, findings, analysisSummary, analysisMetadata, isAnalyzing, dismissFinding, evaluateRagas, isEvaluatingRagas, ragasResult } = useStore();
  const [analysisTab, setAnalysisTab] = useState<'chat' | 'viewer' | 'graph' | 'policy' | 'findings'>('chat');
  const [highlightStreamId, setHighlightStreamId] = useState<number | undefined>(undefined);
  const [highlightIp, setHighlightIp] = useState<string | undefined>(undefined);

  const handleShowFindings = () => setAnalysisTab('findings');

  const handleTraceInGraph = (ip?: string) => {
    setHighlightIp(ip);
    setAnalysisTab('graph');
  };

  const handleViewPackets = (streamId?: number) => {
    setHighlightStreamId(streamId);
    setAnalysisTab('viewer');
  };

  useEffect(() => {
    // Validate backend connectivity
    checkHealth().catch(() => {
      // Will show in the UI
    });
    initSession();
  }, []);

  return (
    <div className="min-h-screen flex flex-col">
      <Header />

      {error && (
        <div className="fixed top-4 right-4 z-50 max-w-md">
          <div className="bg-red-900/90 border border-red-700 rounded-xl p-4 shadow-2xl">
            <div className="flex items-start gap-3">
              <span className="text-red-300 text-lg">⚠</span>
              <p className="text-red-200 text-sm flex-1">{error}</p>
              <button onClick={clearError} className="text-red-400 hover:text-red-200">✕</button>
            </div>
          </div>
        </div>
      )}

      <main className="flex-1 container mx-auto px-4 py-6 max-w-7xl">
        {/* Step indicator — 3 phases: Upload → Configure → Analyze */}
        <div className="flex items-center gap-2 mb-8 justify-center">
          {(['upload', 'configure', 'analyze'] as const).map((s, i) => (
            <div key={s} className="flex items-center gap-2">
              <button
                onClick={() => setStep(s)}
                className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium transition-colors ${
                  step === s
                    ? 'bg-saca-600 text-white'
                    : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                }`}
              >
                {i + 1}
              </button>
              <span className={`text-sm capitalize ${step === s ? 'text-saca-300' : 'text-gray-500'}`}>
                {s === 'analyze' ? 'Analyze' : s}
              </span>
              {i < 2 && <div className="w-12 h-px bg-gray-700 mx-1" />}
            </div>
          ))}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Sidebar */}
          <div className="lg:col-span-1 space-y-4">
            <div className="card">
              <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">Files</h3>
              <div className="space-y-2">
                <div className="flex items-center gap-2 text-sm">
                  <span className={`w-2 h-2 rounded-full ${captureFile ? 'bg-green-500' : 'bg-gray-600'}`} />
                  <span className={captureFile ? 'text-green-300' : 'text-gray-500'}>
                    {captureFile ? `📡 ${captureFile.name}` : 'No capture loaded'}
                  </span>
                </div>
                <div className="flex items-center gap-2 text-sm">
                  <span className={`w-2 h-2 rounded-full ${policy ? 'bg-green-500' : 'bg-gray-600'}`} />
                  <span className={policy ? 'text-green-300' : 'text-gray-500'}>
                    {policy ? `📋 ${policy.policyName}` : 'No policy loaded'}
                  </span>
                </div>
              </div>
              {captureFile?.summary && (
                <div className="mt-3 pt-3 border-t border-gray-800 text-xs text-gray-500 space-y-1">
                  <p>📦 {(captureFile.summary.packetCount ?? 0).toLocaleString()} packets</p>
                  <p>🔗 {captureFile.summary.tcpStreamCount ?? 0} TCP streams</p>
                  <p>⏱ {(captureFile.summary.durationSeconds ?? 0)}s duration</p>
                </div>
              )}
              {policy?.rules && policy.rules.length > 0 && (
                <div className="mt-3 pt-3 border-t border-gray-800 text-xs text-gray-500">
                  <p>📜 {policy.rules.length} policy rules</p>
                </div>
              )}
              {findings.length > 0 && (
                <div className="mt-3 pt-3 border-t border-gray-800 text-xs">
                  <p className="text-red-400">🛡️ {findings.filter(f => f.status === 'violated').length} violations</p>
                  <p className="text-green-400">✅ {findings.filter(f => f.status === 'compliant').length} compliant</p>
                </div>
              )}
            </div>

            <LlmSettings />
          </div>

          {/* Main Content */}
          <div className="lg:col-span-3">
            {step === 'upload' && (
              <div className="space-y-6">
                <PcapUpload />
                <PolicyUpload />
                {(captureFile || policy) && (
                  <div className="text-center space-y-2">
                    <button
                      onClick={() => setStep('analyze')}
                      className="btn-primary text-lg px-8 py-3"
                    >
                      Start Analysis →
                    </button>
                    {(!captureFile || !policy) && (
                      <p className="text-xs text-gray-500">
                        {!captureFile && !policy ? 'Upload both pcap and policy to run analysis' : !captureFile ? 'Upload a pcap file to continue' : 'Upload a policy document to continue'}
                      </p>
                    )}
                  </div>
                )}
              </div>
            )}
            {step === 'configure' && (
              <div className="card p-8 text-center text-gray-400">
                <p>Configuration step — will contain agent selection and report settings.</p>
              </div>
            )}
            {step === 'analyze' && (
              <div className="space-y-4">
                {analysisMetadata && (
                  <div className="card border-l-4 border-l-saca-500">
                    <div className="flex items-center justify-between gap-4 text-sm">
                      <div>
                        <p className="text-saca-300 font-semibold">Policy Conversion Status</p>
                        <p className="text-gray-400 mt-1">
                          Extracted <span className="text-white font-semibold">{analysisMetadata.policyRulesExtracted}</span> policy rule(s) before compliance judgment.
                        </p>
                      </div>
                      <div className="text-right text-xs text-gray-500">
                        <p>Conversations: {analysisMetadata.trafficConversationsAnalyzed}</p>
                        <p>Anomalies: {analysisMetadata.trafficAnomaliesDetected}</p>
                      </div>
                    </div>
                  </div>
                )}

                {/* Analysis Tabs */}
                <div className="flex gap-1 bg-gray-900 rounded-lg p-1">
                  {[
                    { id: 'chat', label: '💬 Chat' },
                    { id: 'findings', label: `🛡️ Findings${findings.length > 0 ? ` (${findings.filter(f => f.status === 'violated').length})` : ''}` },
                    { id: 'viewer', label: '📊 Packet Viewer' },
                    { id: 'graph', label: '🕸️ Traffic Graph' },
                    { id: 'policy', label: '📋 Policy' },
                  ].map(tab => (
                    <button
                      key={tab.id}
                      onClick={() => setAnalysisTab(tab.id as any)}
                      className={`flex-1 py-2 px-3 rounded-md text-sm font-medium transition-colors ${
                        analysisTab === tab.id
                          ? 'bg-saca-600 text-white'
                          : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800'
                      }`}
                    >
                      {tab.label}
                    </button>
                  ))}
                </div>

                {analysisTab === 'chat' && <ChatPanel onRequestFindingsTab={handleShowFindings} />}
                {analysisTab === 'findings' && (
                  <FindingsPanel
                    findings={findings}
                    onDismiss={dismissFinding}
                    summary={analysisSummary}
                    isLoading={isAnalyzing}
                    onRequestGraphTab={handleTraceInGraph}
                    onRequestViewerTab={handleViewPackets}
                    onEvaluateRagas={evaluateRagas}
                    isEvaluatingRagas={isEvaluatingRagas}
                    ragasResult={ragasResult}
                  />
                )}
                {analysisTab === 'viewer' && <PacketViewer />}
                {analysisTab === 'graph' && <GraphPanel highlightIp={highlightIp} />}
                {analysisTab === 'policy' && <PolicyViewer />}
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
