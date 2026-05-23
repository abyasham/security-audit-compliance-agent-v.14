"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sessionRouter = void 0;
const express_1 = require("express");
const uuid_1 = require("uuid");
const sessionStore_1 = require("../storage/sessionStore");
exports.sessionRouter = (0, express_1.Router)();
const store = sessionStore_1.SessionStore.getInstance();
// ─── Create Session ─────────────────────────────────────────────────────────
exports.sessionRouter.post('/', (_req, res) => {
    const session = {
        id: (0, uuid_1.v4)(),
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        captureFiles: [],
        findings: [],
        chatHistory: [],
        llmConfig: {
            primary: { type: 'ollama', baseUrl: 'http://localhost:11434', model: 'deepseek-r1:14b', isActive: true },
            tokenBudget: { maxInputTokens: 900000, reserveForResponse: 100000 },
        },
    };
    store.createSession(session);
    res.json({ success: true, data: { sessionId: session.id } });
});
// ─── Get Session ────────────────────────────────────────────────────────────
exports.sessionRouter.get('/:id', (req, res) => {
    const session = store.getSession(req.params.id);
    if (!session) {
        return res.status(404).json({ success: false, error: 'Session not found' });
    }
    res.json({ success: true, data: session });
});
// ─── Update LLM Config ─────────────────────────────────────────────────────
exports.sessionRouter.put('/:id/llm-config', (req, res) => {
    const { id } = req.params;
    const { llmConfig } = req.body;
    const session = store.getSession(id);
    if (!session) {
        return res.status(404).json({ success: false, error: 'Session not found' });
    }
    session.llmConfig = { ...session.llmConfig, ...llmConfig };
    session.updatedAt = new Date().toISOString();
    store.updateSession(session);
    res.json({ success: true, data: session.llmConfig });
});
// ─── Link Capture to Session ────────────────────────────────────────────────
exports.sessionRouter.post('/:id/captures', (req, res) => {
    const { id } = req.params;
    const { captureFile } = req.body;
    const session = store.getSession(id);
    if (!session) {
        return res.status(404).json({ success: false, error: 'Session not found' });
    }
    session.captureFiles.push(captureFile);
    session.updatedAt = new Date().toISOString();
    store.updateSession(session);
    res.json({ success: true, data: session.captureFiles });
});
// ─── Link Policy to Session ─────────────────────────────────────────────────
exports.sessionRouter.post('/:id/policy', (req, res) => {
    const { id } = req.params;
    const { policy } = req.body;
    const session = store.getSession(id);
    if (!session) {
        return res.status(404).json({ success: false, error: 'Session not found' });
    }
    session.policy = policy;
    session.updatedAt = new Date().toISOString();
    store.updateSession(session);
    res.json({ success: true, data: session.policy });
});
// ─── Soft Reset — Clear all session memory (keeps server running) ───────────
exports.sessionRouter.post('/reset', (_req, res) => {
    const result = store.clearAll();
    console.log(`[Session] Soft reset complete — ${result.sessionsCleared} sessions, ${result.graphsCleared} graphs cleared`);
    res.json({
        success: true,
        data: {
            message: 'All session memory cleared. Server is still running — create a new session to start fresh.',
            ...result,
        },
    });
});
//# sourceMappingURL=session.js.map