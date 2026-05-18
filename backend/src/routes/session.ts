import { Router, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { SessionStore } from '../storage/sessionStore';

export const sessionRouter = Router();
const store = SessionStore.getInstance();

// ─── Create Session ─────────────────────────────────────────────────────────

sessionRouter.post('/', (_req: Request, res: Response) => {
  const session: import('../types').Session = {
    id: uuidv4(),
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

sessionRouter.get('/:id', (req: Request, res: Response) => {
  const session = store.getSession(req.params.id);
  if (!session) {
    return res.status(404).json({ success: false, error: 'Session not found' });
  }
  res.json({ success: true, data: session });
});

// ─── Update LLM Config ─────────────────────────────────────────────────────

sessionRouter.put('/:id/llm-config', (req: Request, res: Response) => {
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

sessionRouter.post('/:id/captures', (req: Request, res: Response) => {
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

sessionRouter.post('/:id/policy', (req: Request, res: Response) => {
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

sessionRouter.post('/reset', (_req: Request, res: Response) => {
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
