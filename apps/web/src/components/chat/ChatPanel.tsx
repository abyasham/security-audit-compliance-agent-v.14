import { useState, useRef, useEffect } from 'react';
import { useStore } from '../../store';
import { ChatMessage } from './ChatMessage';
import { ChatInput } from './ChatInput';
import { AnalysisProgress } from '../analysis/AnalysisProgress';

interface ChatPanelProps {
  onRequestFindingsTab?: () => void;
}

export function ChatPanel({ onRequestFindingsTab }: ChatPanelProps) {
  const {
    messages,
    isStreaming,
    sendMessage,
    captureFile,
    policy,
    runAnalysis,
    runAnalysisStep,
    isAnalyzing,
    findings,
    analysisSummary,
  } = useStore();

  const optionalPrompts = [
    {
      icon: '🔐',
      label: 'Check encryption compliance',
      action: 'chat' as const,
      prompt: 'Analyze all TLS/SSL connections. Are there any connections using deprecated protocols (TLS 1.0/1.1, SSL)? List all unencrypted connections.',
    },
    {
      icon: '🚪',
      label: 'Check network segmentation',
      action: 'chat' as const,
      prompt: 'Analyze network segmentation. Are there any connections from external IPs to internal services that should be blocked? Check database ports, SSH, RDP.',
    },
    {
      icon: '📋',
      label: 'Generate audit report',
      action: 'chat' as const,
      prompt: 'Generate a comprehensive compliance audit report based on this capture and the security policy. Include all violations, evidence, and recommendations.',
    },
  ];

  const handlePrimaryAnalysis = async () => {
    try {
      await runAnalysis();
      onRequestFindingsTab?.();
    } catch {
      // Error is already set in store, just don't crash
    }
  };

  const handleStep = async (step: 'policy' | 'network' | 'judge') => {
    try {
      await runAnalysisStep(step);
    } catch {
      // Error is already set in store, just don't crash
    }
  };

  const handleQuickAction = async (prompt: string) => {
    await sendMessage(prompt);
  };
  const handleGenerateReport = () => {
    const timestamp = new Date().toISOString();
    const safeStamp = timestamp.replace(/[:.]/g, '-');
    const reportName = `SACA_Report_${safeStamp}.md`;

    const violatedFindings = findings.filter(f => f.status === 'violated');
    const violationCount = violatedFindings.length;
    const summaryLines = analysisSummary
      ? [
        `Total rules: ${analysisSummary.totalRules}`,
        `Violated: ${analysisSummary.violated}`,
        `Compliant: ${analysisSummary.compliant}`,
        `Suspicious: ${analysisSummary.suspicious}`,
        `Critical: ${analysisSummary.criticalCount}`,
        `High: ${analysisSummary.highCount}`,
        `Medium: ${analysisSummary.mediumCount}`,
        `Low: ${analysisSummary.lowCount}`,
        `Average confidence: ${(analysisSummary.averageConfidence ?? 0).toFixed(2)}`,
      ]
      : [];

    const violationSection = violationCount === 0
      ? 'No compliance violations were detected in the current analysis.'
      : [
        '| Severity | Rule | Category | Status | Evidence | Description |',
        '| --- | --- | --- | --- | --- | --- |',
        ...violatedFindings.map((f) => {
          const evidence = [
            f.evidence?.srcIp ? `src=${f.evidence.srcIp}` : '',
            f.evidence?.dstIp ? `dst=${f.evidence.dstIp}` : '',
            f.evidence?.dstPort ? `port=${f.evidence.dstPort}` : '',
            f.evidence?.protocol ? `proto=${f.evidence.protocol}` : '',
            f.evidencePacketNumbers?.length ? `pkts=${f.evidencePacketNumbers.slice(0, 6).join(',')}` : '',
          ].filter(Boolean).join(' ');

          return `| ${f.severity} | ${f.ruleName} | ${f.category} | ${f.status || 'violated'} | ${evidence || 'n/a'} | ${f.description} |`;
        }),
      ].join('\n');

    const qaPairs = [] as string[];
    let pendingQuestion: string | null = null;
    for (const msg of messages) {
      if (msg.role === 'user') {
        pendingQuestion = msg.content;
        continue;
      }
      if (msg.role === 'assistant' && pendingQuestion) {
        qaPairs.push(`**Q:** ${pendingQuestion}\n\n**A:** ${msg.content}`);
        pendingQuestion = null;
      }
    }

    const qaSection = qaPairs.length > 0
      ? qaPairs.join('\n\n---\n\n')
      : 'No chat questions and answers available in this session.';

    const headerLines = [
      '# SACA Analysis Report',
      '',
      `Generated: ${timestamp}`,
      captureFile ? `Capture: ${captureFile.name}` : 'Capture: (none)',
      policy ? `Policy: ${policy.policyName}` : 'Policy: (none)',
    ];

    const summarySection = summaryLines.length > 0
      ? ['## Analysis Summary', '', ...summaryLines].join('\n')
      : '## Analysis Summary\n\nNo summary available. Run analysis to populate this section.';

    const report = [
      ...headerLines,
      '',
      summarySection,
      '',
      '## Violation Report',
      '',
      violationSection,
      '',
      '## Queries Answered',
      '',
      qaSection,
      '',
    ].join('\n');

    const blob = new Blob([report], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = reportName;
    link.click();
    URL.revokeObjectURL(url);
  };
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const hasData = captureFile && policy;

  return (
    <div className="card flex flex-col h-[600px]">
      {/* Header */}
      <div className="pb-3 border-b border-gray-800 mb-3 flex items-center justify-between gap-3">
        <h2 className="text-lg font-semibold flex items-center gap-2">
          💬 Security Audit Analysis
        </h2>
        <button
          onClick={handleGenerateReport}
          disabled={messages.length === 0 && findings.length === 0}
          className="px-3 py-2 text-xs font-semibold rounded-lg border border-saca-500/60 text-saca-200
                   hover:bg-saca-800/40 hover:border-saca-400 transition disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Generate Report
        </button>
        {!hasData && (
          <p className="text-sm text-yellow-400 mt-1">
            ⚠ Upload both a pcap capture and a security policy to start analysis.
          </p>
        )}
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto space-y-3 pr-2 scrollbar-thin">
        {messages.length === 0 && (
          <div className="text-center text-gray-500 mt-6 space-y-4">
            <div className="text-4xl">🔍</div>
            <p>Ask SACA to analyze the network capture</p>
            {hasData && (
              <div className="max-w-2xl mx-auto mt-4 space-y-4">
                <button
                  onClick={handlePrimaryAnalysis}
                  disabled={isStreaming || isAnalyzing}
                  className="w-full flex items-center justify-between gap-3 px-5 py-4 bg-saca-800/40 hover:bg-saca-700/50
                           border border-saca-500/50 hover:border-saca-400 rounded-xl text-left
                           transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <div className="flex items-center gap-3">
                    <span className="text-2xl">🔍</span>
                    <div>
                      <p className="text-sm font-semibold text-saca-200">Find all non-compliance (Primary)</p>
                      <p className="text-xs text-saca-300/80">Runs full multi-agent pipeline: Policy → Network → Judge</p>
                    </div>
                  </div>
                  <span className="text-[10px] uppercase tracking-wider text-saca-300 bg-saca-950/60 px-2 py-1 rounded">Default</span>
                </button>

                {/* Debug: Individual Agent Steps */}
                <div className="border border-gray-800 rounded-xl p-3 bg-gray-900/30">
                  <p className="text-xs uppercase tracking-wider text-gray-500 mb-2">Debug: Run Individual Steps</p>
                  <div className="grid grid-cols-3 gap-2">
                    <button
                      onClick={() => handleStep('policy')}
                      disabled={isStreaming || isAnalyzing}
                      className="flex flex-col items-center gap-1 px-3 py-3 bg-gray-800 hover:bg-gray-700
                               border border-gray-700 hover:border-blue-500 rounded-xl text-center
                               transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
                      title="Step 1: Extract rules from policy text"
                    >
                      <span className="text-xl">📜</span>
                      <span className="text-xs text-gray-300">Policy Agent</span>
                      <span className="text-[10px] text-gray-500">Extract Rules</span>
                    </button>
                    <button
                      onClick={() => handleStep('network')}
                      disabled={isStreaming || isAnalyzing}
                      className="flex flex-col items-center gap-1 px-3 py-3 bg-gray-800 hover:bg-gray-700
                               border border-gray-700 hover:border-green-500 rounded-xl text-center
                               transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
                      title="Step 2: Analyze network traffic"
                    >
                      <span className="text-xl">📡</span>
                      <span className="text-xs text-gray-300">Network Agent</span>
                      <span className="text-[10px] text-gray-500">Analyze Traffic</span>
                    </button>
                    <button
                      onClick={() => handleStep('judge')}
                      disabled={isStreaming || isAnalyzing}
                      className="flex flex-col items-center gap-1 px-3 py-3 bg-gray-800 hover:bg-gray-700
                               border border-gray-700 hover:border-purple-500 rounded-xl text-center
                               transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
                      title="Step 3: Cross-reference rules vs traffic"
                    >
                      <span className="text-xl">⚖️</span>
                      <span className="text-xs text-gray-300">Judge</span>
                      <span className="text-[10px] text-gray-500">Compliance Check</span>
                    </button>
                  </div>
                </div>

                <div className="border border-gray-800 rounded-xl p-3 bg-gray-900/30">
                  <p className="text-xs uppercase tracking-wider text-gray-500 mb-2">Optional focused prompts</p>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {optionalPrompts.map((action) => (
                      <button
                        key={action.prompt}
                        onClick={() => handleQuickAction(action.prompt)}
                        disabled={isStreaming || isAnalyzing}
                        className="flex items-center gap-3 px-4 py-3 bg-gray-800 hover:bg-gray-700
                                 border border-gray-700 hover:border-saca-500 rounded-xl text-left
                                 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed
                                 group"
                      >
                        <span className="text-xl">{action.icon}</span>
                        <span className="text-sm text-gray-300 group-hover:text-white transition-colors">
                          {action.label}
                        </span>
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            )}
            {!hasData && (
              <p className="text-sm text-yellow-400">
                ⚠ Upload a pcap capture and a security policy first
              </p>
            )}
          </div>
        )}

        {messages.map((msg, i) => (
          <ChatMessage key={i} message={msg} />
        ))}

        {isAnalyzing && (
          <div className="flex items-center gap-2 text-saca-400 text-sm pl-10">
            <div className="w-2 h-2 bg-saca-500 rounded-full animate-pulse" />
            Running multi-agent analysis (Policy → Network → Judge)...
          </div>
        )}
        {isStreaming && !isAnalyzing && (
          <div className="flex items-center gap-2 text-gray-500 text-sm pl-10">
            <div className="w-2 h-2 bg-saca-500 rounded-full animate-pulse" />
            Analyzing...
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <div className="pt-3 border-t border-gray-800 mt-3">
        <ChatInput disabled={!hasData || isStreaming} />
      </div>
    </div>
  );
}
