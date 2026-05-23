"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.checkHealth = checkHealth;
exports.waitForCore = waitForCore;
exports.analyzeNetwork = analyzeNetwork;
exports.analyzePolicy = analyzePolicy;
exports.judgeCompliance = judgeCompliance;
exports.streamChat = streamChat;
exports.runRagas = runRagas;
const config_1 = require("../config");
const BASE_URL = config_1.config.pythonCoreUrl.replace(/\/+$/, '');
// ─── Helpers ───────────────────────────────────────────────────────────────
async function _post(path, body) {
    const res = await fetch(`${BASE_URL}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });
    if (!res.ok) {
        const text = await res.text();
        throw new Error(`PythonCore ${path} → ${res.status}: ${text}`);
    }
    return res.json();
}
// ─── Public API ────────────────────────────────────────────────────────────
/** Check whether the Python core is reachable. */
async function checkHealth() {
    try {
        const res = await fetch(`${BASE_URL}/health`, { signal: AbortSignal.timeout(3000) });
        return res.ok;
    }
    catch {
        return false;
    }
}
/** Returns true once; throws after 30 s of retries. */
async function waitForCore(retries = 30, delayMs = 1000) {
    for (let i = 0; i < retries; i++) {
        if (await checkHealth())
            return;
        await new Promise(r => setTimeout(r, delayMs));
    }
    throw new Error('Python core did not become healthy');
}
// ── Agent endpoints ────────────────────────────────────────────────────────
async function analyzeNetwork(sessionId, filePath) {
    return _post('/analyze/network', { sessionId, filePath });
}
async function analyzePolicy(sessionId, policyText, sourceFormat = 'text') {
    return _post('/analyze/policy', { sessionId, policyText, sourceFormat });
}
async function judgeCompliance(sessionId, rules, networkOutput) {
    return _post('/analyze/compliance', { sessionId, rules, networkOutput });
}
// ── Chat stream (SSE) ─────────────────────────────────────────────────────
async function* streamChat(messages, provider) {
    const res = await fetch(`${BASE_URL}/chat/stream`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ messages, provider }),
    });
    if (!res.ok) {
        const text = await res.text();
        throw new Error(`PythonCore /chat/stream → ${res.status}: ${text}`);
    }
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    while (true) {
        const { done, value } = await reader.read();
        if (done)
            break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';
        for (const line of lines) {
            if (line.startsWith('data: ')) {
                const payload = line.slice(6);
                if (payload === '[DONE]')
                    return;
                try {
                    yield JSON.parse(payload);
                }
                catch {
                    // skip unparseable chunks
                }
            }
        }
    }
}
async function runRagas(sessionId, findings, policyText) {
    return _post('/eval/ragas', { sessionId, findings, policyText });
}
//# sourceMappingURL=pythonCoreClient.js.map