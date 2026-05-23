/**
 * PythonCoreClient — HTTP bridge from Express API → Python FastAPI Core.
 *
 * Replaces:
 *   - Direct agent imports (PolicyAgent, NetworkAgent, ComplianceJudge)
 *   - LLMGateway chat calls (→ streamChat)
 *   - RAGAS evaluation
 *
 * All LLM-heavy work lives in Python via LiteLLM.
 */

import { config } from '../config';
import type {
  AnalyzeResponse,
  ComplianceFinding,
  ParsedPolicy,
  PolicyRule,
  TcpStream,
} from '../types';

// NetworkAgent output shape from Python Core
export interface NetworkAgentOutput {
  conversations: TcpStream[];
  anomalies: any[];
  summary?: any;
}

const BASE_URL = config.pythonCoreUrl.replace(/\/+$/, '');

// ─── Helpers ───────────────────────────────────────────────────────────────

async function _post<T>(path: string, body: unknown, timeoutMs = 300_000): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`PythonCore ${path} → ${res.status}: ${text}`);
  }
  return res.json() as Promise<T>;
}

// ─── Public API ────────────────────────────────────────────────────────────

/** Check whether the Python core is reachable. */
export async function checkHealth(): Promise<boolean> {
  try {
    const res = await fetch(`${BASE_URL}/health`, { signal: AbortSignal.timeout(3000) });
    return res.ok;
  } catch {
    return false;
  }
}

/** Returns true once; throws after 30 s of retries. */
export async function waitForCore(retries = 30, delayMs = 1000): Promise<void> {
  for (let i = 0; i < retries; i++) {
    if (await checkHealth()) return;
    await new Promise(r => setTimeout(r, delayMs));
  }
  throw new Error('Python core did not become healthy');
}

// ── Agent endpoints ────────────────────────────────────────────────────────

export async function analyzeNetwork(
  sessionId: string,
  filePath: string,
): Promise<NetworkAgentOutput> {
  return _post<NetworkAgentOutput>('/analyze/network', { sessionId, filePath });
}

export async function analyzePolicy(
  sessionId: string,
  policyText: string,
  sourceFormat: string = 'text',
): Promise<{ rules: PolicyRule[]; policy: ParsedPolicy }> {
  return _post('/analyze/policy', { sessionId, policyText, sourceFormat });
}

export async function judgeCompliance(
  sessionId: string,
  rules: PolicyRule[],
  networkOutput: any,
): Promise<{ findings: ComplianceFinding[]; summary: any }> {
  return _post('/analyze/compliance', { sessionId, rules, networkOutput });
}

// ── Chat stream (SSE) ─────────────────────────────────────────────────────

export async function* streamChat(
  messages: Array<{ role: string; content: string }>,
  provider?: string,
): AsyncGenerator<{ delta: string; finish?: boolean }> {
  const res = await fetch(`${BASE_URL}/chat/stream`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ messages, provider }),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`PythonCore /chat/stream → ${res.status}: ${text}`);
  }

  const reader = res.body!.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    const lines = buffer.split('\n');
    buffer = lines.pop() || '';

    for (const line of lines) {
      if (line.startsWith('data: ')) {
        const payload = line.slice(6);
        if (payload === '[DONE]') return;
        try {
          yield JSON.parse(payload);
        } catch {
          // skip unparseable chunks
        }
      }
    }
  }
}

// ── RAGAS ──────────────────────────────────────────────────────────────────

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

export async function runRagas(
  sessionId: string,
  findings: unknown[],
  policyText: string,
  captureFilePath?: string,
): Promise<RagasEvalResult> {
  // 10-minute timeout: 3 findings × ~2 min worst-case each
  const raw = await _post<any>('/eval/ragas', { sessionId, findings, policyText, captureFilePath }, 600_000);
  // Python returns snake_case; map to camelCase for frontend
  return {
    sessionId: raw.session_id ?? null,
    timestamp: raw.timestamp ?? '',
    avgFaithfulness: raw.avg_faithfulness ?? 0,
    avgAnswerRelevancy: raw.avg_answer_relevancy ?? 0,
    providerUsed: raw.provider_used ?? null,
    heuristicFallback: raw.heuristic_fallback ?? false,
    error: raw.error ?? null,
    perFindingScores: (raw.per_finding_scores ?? []).map((p: any) => ({
      findingId: p.finding_id ?? '',
      ruleName: p.rule_name ?? '',
      faithfulness: p.faithfulness ?? 0,
      answerRelevancy: p.answer_relevancy ?? 0,
      faithfulnessReason: p.faithfulness_reason ?? '',
      relevancyReason: p.relevancy_reason ?? '',
      scoredByLlm: p.scored_by_llm ?? true,
    })),
  };
}
