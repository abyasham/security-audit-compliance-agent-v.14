"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.chatRouter = void 0;
const express_1 = require("express");
const sessionStore_1 = require("../storage/sessionStore");
const contextAssembler_1 = require("../services/contextAssembler");
const toolExecutor_1 = require("../services/toolExecutor");
const sharedTshark_1 = require("../services/sharedTshark");
const pythonCore = __importStar(require("../services/pythonCoreClient"));
exports.chatRouter = (0, express_1.Router)();
const store = sessionStore_1.SessionStore.getInstance();
const assembler = new contextAssembler_1.ContextAssembler();
const executor = new toolExecutor_1.ToolExecutor(sharedTshark_1.tsharkRunner);
// ─── Send Chat Message (SSE Stream with Tool Loop) ─────────────────────────
exports.chatRouter.post('/stream', async (req, res) => {
    try {
        const { sessionId, message } = req.body;
        if (!sessionId || !message) {
            return res.status(400).json({ success: false, error: 'sessionId and message are required' });
        }
        const session = store.getSession(sessionId);
        if (!session) {
            return res.status(404).json({ success: false, error: 'Session not found' });
        }
        // Check Python Core availability
        const coreAvailable = await pythonCore.checkHealth();
        if (!coreAvailable) {
            return res.status(400).json({
                success: false,
                error: 'Python Core is not available. Start the core-py service first.',
            });
        }
        // Set up SSE headers
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');
        res.flushHeaders();
        // ─── Set Preferences ──────────────────────────────────────────────────
        const agentProviders = session.llmConfig?.agentProviders || {};
        const preferredProvider = agentProviders.judge || undefined;
        // ─── Phase 1: Assemble Context ───────────────────────────────────────
        const systemPrompt = await assembler.assembleSystemPrompt(session);
        const userMessage = await assembler.assembleUserMessage(session, message);
        const messages = [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: userMessage },
        ];
        // Store user message
        session.chatHistory.push({ role: 'user', content: message });
        // ─── Phase 2: Stream from Python Core ────────────────────────────────
        let assistantContent = '';
        try {
            const stream = pythonCore.streamChat(messages, preferredProvider);
            for await (const chunk of stream) {
                if (chunk.delta) {
                    assistantContent += chunk.delta;
                    res.write(`data: ${JSON.stringify({ type: 'chunk', content: chunk.delta })}\n\n`);
                }
                if (chunk.finish)
                    break;
            }
            res.write(`data: ${JSON.stringify({ type: 'done' })}\n\n`);
        }
        catch (err) {
            console.error('[Chat] Stream failed:', err.message);
            assistantContent = `Analysis error: ${err.message}. Please try again or ask a different question.`;
            res.write(`data: ${JSON.stringify({ type: 'chunk', content: assistantContent })}\n\n`);
            res.write(`data: ${JSON.stringify({ type: 'done' })}\n\n`);
        }
        // Store assistant response
        session.chatHistory.push({ role: 'assistant', content: assistantContent || '(Analysis completed)' });
        session.updatedAt = new Date().toISOString();
        store.updateSession(session);
        res.end();
    }
    catch (err) {
        console.error('[Chat] Error:', err);
        try {
            res.write(`data: ${JSON.stringify({ type: 'error', error: err.message })}\n\n`);
            res.end();
        }
        catch {
            res.status(500).json({ success: false, error: err.message });
        }
    }
});
// ─── LLM Status ────────────────────────────────────────────────────────────
exports.chatRouter.get('/status', async (_req, res) => {
    const coreAvailable = await pythonCore.checkHealth();
    if (!coreAvailable) {
        return res.json({
            success: true,
            data: {
                available: false,
                providers: { providers: [] },
            },
        });
    }
    // Build provider list from config (mirrors v13 LLMGateway.getStatus format)
    const providers = [];
    // Read from env (same keys as .env at repo root)
    const cfg = (await Promise.resolve().then(() => __importStar(require('../config')))).config;
    for (const [type, info] of Object.entries(cfg.llmConfig)) {
        // info = { baseUrl? / apiKey?, model }
        const model = info.model || '';
        let configured = false;
        if (type === 'ollama') {
            configured = !!(info.baseUrl);
        }
        else {
            configured = !!(info.apiKey);
        }
        providers.push({ type, model, configured });
    }
    res.json({
        success: true,
        data: {
            available: true,
            providers: { providers },
        },
    });
});
//# sourceMappingURL=chat.js.map