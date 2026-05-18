import { create } from 'zustand';
import {
  Session, CaptureFile, ParsedPolicy, ComplianceFinding,
  ChatMessage, LLMConfig, AppStep, LLMProviderType, AnalyzeResponse,
} from './types';
import * as api from './services/api';

interface AppState {
  // Session
  sessionId: string | null;
  session: Session | null;
  loading: boolean;
  error: string | null;

  // App step
  step: AppStep;

  // Files
  captureFile: CaptureFile | null;
  policy: ParsedPolicy | null;
  isParsing: boolean;

  // Chat
  messages: ChatMessage[];
  isStreaming: boolean;

  // Findings
  findings: ComplianceFinding[];
  analysisSummary: AnalyzeResponse['summary'] | null;
  analysisMetadata: AnalyzeResponse['agentMetadata'] | null;
  isAnalyzing: boolean;

  // Graph (LightRAG)
  graphStats: any | null;

  // LLM Config
  llmConfig: LLMConfig;

  // Actions
  initSession: () => Promise<void>;
  uploadAndParsePcap: (file: File) => Promise<void>;
  uploadAndParsePolicy: (file: File) => Promise<void>;
  setStep: (step: AppStep) => void;
  sendMessage: (message: string) => Promise<void>;
  setLlmConfig: (config: LLMConfig) => Promise<void>;
  dismissFinding: (findingId: string) => void;
  runAnalysis: () => Promise<void>;
  clearError: () => void;
  resetChatHistory: () => void;
  resetFindings: () => void;
}

const defaultLlmConfig: LLMConfig = {
  primary: { type: 'ollama', baseUrl: 'http://localhost:11434', model: 'deepseek-r1:14b', isActive: true },
  fallback: { type: 'deepseek', apiKey: '', model: 'deepseek-chat', isActive: false },
  secondary: { type: 'openrouter', apiKey: '', model: 'openai/gpt-4o', isActive: false },
};

export const useStore = create<AppState>((set, get) => ({
  sessionId: null,
  session: null,
  loading: false,
  error: null,
  step: 'upload',
  captureFile: null,
  policy: null,
  isParsing: false,
  messages: [],
  isStreaming: false,
  findings: [],
  analysisSummary: null,
  analysisMetadata: null,
  isAnalyzing: false,
  graphStats: null,
  llmConfig: defaultLlmConfig,

  clearError: () => set({ error: null }),

  initSession: async () => {
    set({ loading: true, error: null });
    try {
      const { sessionId } = await api.createSession();
      const session = await api.getSession(sessionId);
      set({ sessionId, session, loading: false, messages: [], findings: [] });
    } catch (err: any) {
      set({ error: err.message, loading: false });
    }
  },

  uploadAndParsePcap: async (file: File) => {
    set({ loading: true, isParsing: true, error: null });
    try {
      // Ensure session exists
      let { sessionId } = get();
      if (!sessionId) {
        const { sessionId: newId } = await api.createSession();
        sessionId = newId;
      }

      // Upload
      const captureFile = await api.uploadPcap(file);
      await api.linkCapture(sessionId!, captureFile);

      // Parse summary
      const summary = await api.parseCaptureSummary(captureFile.filePath);
      captureFile.summary = summary;
      captureFile.parsed = true;

      // Build LightRAG graph (async, non-blocking for UI)
      api.buildGraph(sessionId!, captureFile.filePath)
        .then(stats => {
          console.log('[SACA] Graph built:', stats);
          set({ graphStats: stats });
        })
        .catch(err => {
          console.warn('[SACA] Graph build failed:', err.message);
        });

      set({
        sessionId,
        captureFile,
        loading: false,
        isParsing: false,
        step: 'upload',
      });
    } catch (err: any) {
      set({ error: err.message, loading: false, isParsing: false });
    }
  },

  uploadAndParsePolicy: async (file: File) => {
    set({ loading: true, isParsing: true, error: null });
    try {
      let { sessionId } = get();
      if (!sessionId) {
        const { sessionId: newId } = await api.createSession();
        sessionId = newId;
      }

      // Upload
      const uploaded = await api.uploadPolicy(file);
      const policy = await api.parsePolicy(uploaded.filePath);
      await api.linkPolicy(sessionId!, policy);

      set({
        sessionId,
        policy,
        loading: false,
        isParsing: false,
      });
    } catch (err: any) {
      set({ error: err.message, loading: false, isParsing: false });
    }
  },

  setStep: (step: AppStep) => set({ step }),

  sendMessage: async (message: string) => {
    const { sessionId, messages } = get();
    if (!sessionId) return;

    const updatedMessages = [...messages, { role: 'user' as const, content: message }];
    set({ messages: updatedMessages, isStreaming: true, error: null });

    try {
      let assistantContent = '';
      const stream = api.streamChat(sessionId, message);

      for await (const chunk of stream) {
        assistantContent += chunk;
        set({
          messages: [
            ...updatedMessages,
            { role: 'assistant', content: assistantContent },
          ],
        });
      }

      set({ isStreaming: false });
    } catch (err: any) {
      set({
        error: err.message,
        isStreaming: false,
        messages: [
          ...updatedMessages,
          { role: 'assistant', content: `⚠️ Error: ${err.message}` },
        ],
      });
    }
  },

  setLlmConfig: async (llmConfig: LLMConfig) => {
    set({ llmConfig, loading: true });
    try {
      const { sessionId } = get();
      if (sessionId) {
        await api.updateLlmConfig(sessionId, llmConfig);
      }
      set({ loading: false });
    } catch (err: any) {
      set({ error: err.message, loading: false });
    }
  },

  dismissFinding: (findingId: string) => {
    const { findings } = get();
    set({
      findings: findings.map(f =>
        f.id === findingId ? { ...f, dismissed: true } : f
      ),
    });
  },

  runAnalysis: async () => {
    const { sessionId } = get();
    if (!sessionId) return;

    // Clear stale findings so failed runs cannot look like successful reruns.
    set({ isAnalyzing: true, error: null, findings: [], analysisSummary: null, analysisMetadata: null });
    try {
      const result = await api.runAnalysis(sessionId);
      set({
        findings: result.findings,
        analysisSummary: result.summary,
        analysisMetadata: result.agentMetadata,
        isAnalyzing: false,
      });
    } catch (err: any) {
      set({ error: err.message, isAnalyzing: false });
    }
  },

  resetChatHistory: () => {
    set({ messages: [] });
  },

  resetFindings: () => {
    set({ findings: [], analysisSummary: null, analysisMetadata: null });
  },
}));
