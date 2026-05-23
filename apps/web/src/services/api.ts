import { ApiResponse, Session, CaptureFile, ParsedPolicy, ComplianceFinding, AnalyzeResponse } from '../types';

const BASE = '/api';

async function parseApiResponse<T>(res: Response): Promise<ApiResponse<T>> {
  const raw = await res.text();
  if (!raw || raw.trim().length === 0) {
    throw new Error(
      `Server returned an empty response (${res.status} ${res.statusText}). ` +
      'Make sure backend is running on http://localhost:3001.'
    );
  }

  let json: ApiResponse<T>;
  try {
    json = JSON.parse(raw) as ApiResponse<T>;
  } catch {
    throw new Error(
      `Server returned non-JSON response (${res.status} ${res.statusText}). ` +
      'Check backend logs and Vite proxy settings.'
    );
  }

  return json;
}

async function request<T>(url: string, options?: RequestInit & { timeoutMs?: number }): Promise<T> {
  const { timeoutMs = 300_000, ...fetchOptions } = options || {};
  const res = await fetch(`${BASE}${url}`, {
    headers: { 'Content-Type': 'application/json', ...fetchOptions.headers },
    ...fetchOptions,
    signal: AbortSignal.timeout(timeoutMs),
  });
  const json = await parseApiResponse<T>(res);
  if (!json.success) throw new Error(json.error || 'Request failed');
  return json.data as T;
}

// ─── Health ────────────────────────────────────────────────────────────────

export async function checkHealth() {
  return request<{ status: string; version: string; logo: string }>('/health');
}

// ─── Session ───────────────────────────────────────────────────────────────

export async function createSession(): Promise<{ sessionId: string }> {
  return request<{ sessionId: string }>('/session', { method: 'POST' });
}

export async function getSession(id: string): Promise<Session> {
  return request<Session>(`/session/${id}`);
}

export async function updateLlmConfig(sessionId: string, llmConfig: any) {
  return request(`/session/${sessionId}/llm-config`, {
    method: 'PUT',
    body: JSON.stringify({ llmConfig }),
  });
}

// ─── Upload ────────────────────────────────────────────────────────────────

export async function uploadPcap(file: File): Promise<CaptureFile> {
  const form = new FormData();
  form.append('pcap', file);
  const res = await fetch(`${BASE}/upload/pcap`, { method: 'POST', body: form });
  const json = await parseApiResponse<CaptureFile>(res);
  if (!json.success) throw new Error(json.error || 'Upload failed');
  return json.data!;
}

export async function uploadPolicy(file: File): Promise<{ id: string; name: string; filePath: string }> {
  const form = new FormData();
  form.append('policy', file);
  const res = await fetch(`${BASE}/upload/policy`, { method: 'POST', body: form });
  const json = await parseApiResponse<{ id: string; name: string; filePath: string }>(res);
  if (!json.success) throw new Error(json.error || 'Upload failed');
  return json.data!;
}

export async function linkCapture(sessionId: string, captureFile: CaptureFile) {
  return request(`/session/${sessionId}/captures`, {
    method: 'POST',
    body: JSON.stringify({ captureFile }),
  });
}

export async function linkPolicy(sessionId: string, policy: ParsedPolicy) {
  return request(`/session/${sessionId}/policy`, {
    method: 'POST',
    body: JSON.stringify({ policy }),
  });
}

// ─── Parse ─────────────────────────────────────────────────────────────────

export async function parsePolicy(filePath: string): Promise<ParsedPolicy> {
  return request<ParsedPolicy>('/policy/parse', {
    method: 'POST',
    body: JSON.stringify({ filePath }),
  });
}

export async function parseCaptureSummary(filePath: string): Promise<CaptureFile['summary']> {
  return request('/capture/summary', {
    method: 'POST',
    body: JSON.stringify({ filePath }),
  });
}

// ─── Graph ─────────────────────────────────────────────────────────────────

export async function buildGraph(sessionId: string, filePath: string): Promise<any> {
  return request('/graph/build', {
    method: 'POST',
    body: JSON.stringify({ sessionId, filePath }),
  });
}

export async function getGraphStats(sessionId: string): Promise<any> {
  return request(`/graph/stats/${sessionId}`);
}

// ─── Chat ──────────────────────────────────────────────────────────────────

export async function* streamChat(sessionId: string, message: string): AsyncGenerator<string> {
  const res = await fetch(`${BASE}/chat/stream`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sessionId, message }),
  });

  if (!res.ok) throw new Error(`Chat request failed: ${res.statusText}`);
  if (!res.body) throw new Error('No response body');

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split('\n\n');
    buffer = lines.pop() || '';

    for (const line of lines) {
      if (line.startsWith('data: ')) {
        try {
          const parsed = JSON.parse(line.slice(6));
          if (parsed.type === 'chunk') yield parsed.content;
          if (parsed.type === 'done') return;
          if (parsed.type === 'error') throw new Error(parsed.error);
        } catch (e) {
          if (e instanceof SyntaxError) continue;
          throw e;
        }
      }
    }
  }
}

// ─── Capture Data (POST-based to avoid Windows path issues in URLs) ────────

export async function getPacketRange(
  filePath: string,
  start: number,
  end: number,
  filter?: string
): Promise<string> {
  return request<string>('/capture/packets', {
    method: 'POST',
    body: JSON.stringify({ filePath, startFrame: start, endFrame: end, filter }),
  });
}

export async function getConversations(filePath: string, protocol = 'tcp'): Promise<string> {
  return request<string>('/capture/conversations', {
    method: 'POST',
    body: JSON.stringify({ filePath, protocol }),
  });
}

export async function getExpertInfo(filePath: string, severity?: string): Promise<string> {
  return request<string>('/capture/expert-info', {
    method: 'POST',
    body: JSON.stringify({ filePath, severity }),
  });
}

export async function getCaptureSummary(filePath: string): Promise<CaptureFile['summary']> {
  return request('/capture/summary', {
    method: 'POST',
    body: JSON.stringify({ filePath }),
  });
}

// ─── Multi-Agent Analysis ─────────────────────────────────────────────────

export async function startAnalysis(sessionId: string): Promise<{ message: string; sessionId: string }> {
  return request('/analyze', {
    method: 'POST',
    body: JSON.stringify({ sessionId }),
  });
}

export async function getAnalysisProgress(sessionId: string): Promise<{
  sessionId: string;
  overallStatus: string;
  stages: Array<{
    name: string;
    status: string;
    startedAt?: string;
    completedAt?: string;
    error?: string;
    result?: any;
  }>;
  startedAt: string;
  completedAt?: string;
  error?: string;
  finalResult?: AnalyzeResponse;
}> {
  return request(`/analyze/progress/${sessionId}`);
}

export async function getAnalysisStatus(sessionId: string): Promise<{
  canAnalyze: boolean;
  missing: string[];
  captureFiles: number;
  hasPolicy: boolean;
  existingFindings: number;
}> {
  return request(`/analyze/status/${sessionId}`);
}

export async function runAnalysisStep(sessionId: string, step: 'policy' | 'network' | 'judge'): Promise<{ step: string; result: any }> {
  return request(`/analyze/step/${step}`, {
    method: 'POST',
    body: JSON.stringify({ sessionId }),
  });
}

// ─── RAGAS Evaluation ───────────────────────────────────────────────────────

export interface RagasEvalResult {
  sessionId: string | null;
  timestamp: string;
  avgFaithfulness: number;
  avgAnswerRelevancy: number;
  perFindingScores: Array<{
    findingId: string;
    ruleName: string;
    faithfulness: number;
    answerRelevancy: number;
    faithfulnessReason?: string;
    relevancyReason?: string;
    scoredByLlm?: boolean;
  }>;
  providerUsed: string | null;
  heuristicFallback: boolean;
  error: string | null;
  sampleSize?: number;
  totalFindings?: number;
}

export async function evaluateRagas(sessionId: string): Promise<RagasEvalResult> {
  return request<RagasEvalResult>('/analyze/evaluate', {
    method: 'POST',
    body: JSON.stringify({ sessionId }),
  });
}
