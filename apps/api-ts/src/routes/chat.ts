import { Router, Request, Response } from 'express';
import { SessionStore } from '../storage/sessionStore';
import { ContextAssembler } from '../services/contextAssembler';
import { ToolExecutor } from '../services/toolExecutor';
import { ChatMessage } from '../types';
import { tsharkRunner } from '../services/sharedTshark';
import * as pythonCore from '../services/pythonCoreClient';

export const chatRouter = Router();
const store = SessionStore.getInstance();
const assembler = new ContextAssembler();
const executor = new ToolExecutor(tsharkRunner);

// ─── Send Chat Message (SSE Stream with Tool Loop) ─────────────────────────

chatRouter.post('/stream', async (req: Request, res: Response) => {
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

    // Build messages: system prompt + prior chat history + new user message
    // This gives the LLM full context: policy + capture + findings + conversation history
    const history = (session.chatHistory || []).slice(-20); // last 20 messages to stay in budget
    const messages: ChatMessage[] = [
      { role: 'system', content: systemPrompt },
      ...history,
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
        if (chunk.finish) break;
      }
      res.write(`data: ${JSON.stringify({ type: 'done' })}\n\n`);
    } catch (err: any) {
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
  } catch (err: any) {
    console.error('[Chat] Error:', err);
    try {
      res.write(`data: ${JSON.stringify({ type: 'error', error: err.message })}\n\n`);
      res.end();
    } catch {
      res.status(500).json({ success: false, error: err.message });
    }
  }
});

// ─── LLM Status ────────────────────────────────────────────────────────────

chatRouter.get('/status', async (_req: Request, res: Response) => {
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
  const providers: Array<{ type: string; model: string; configured: boolean }> = [];

  // Read from env (same keys as .env at repo root)
  const cfg = (await import('../config')).config;

  for (const [type, info] of Object.entries(cfg.llmConfig)) {
    // info = { baseUrl? / apiKey?, model }
    const model = (info as any).model || '';
    let configured = false;
    if (type === 'ollama') {
      configured = !!((info as any).baseUrl);
    } else {
      configured = !!((info as any).apiKey);
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
