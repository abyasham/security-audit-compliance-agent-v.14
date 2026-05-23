import { Router, Request, Response } from 'express';
import { SessionStore } from '../storage/sessionStore';

export const sessionControlsRouter = Router();
const store = SessionStore.getInstance();

// ─── POST /api/session/reset — Clear session memory (chat, findings, graphs) ─

sessionControlsRouter.post('/reset/:sessionId', (req: Request, res: Response) => {
  try {
    const { sessionId } = req.params;
    const session = store.getSession(sessionId);

    if (!session) {
      return res.status(404).json({ success: false, error: 'Session not found' });
    }

    // Clear memory but preserve uploaded files and settings
    session.chatHistory = [];
    session.findings = [];
    // Note: graph is stored separately in GraphStore, not in Session
    session.updatedAt = new Date().toISOString();

    store.updateSession(session);

    console.log(`[SessionControls] Reset session ${sessionId} — cleared chat history, findings, and graph`);

    res.json({
      success: true,
      data: {
        message: 'Session memory cleared successfully',
        preserved: {
          captureFiles: session.captureFiles.length,
          hasPolicy: !!session.policy,
          llmConfig: !!session.llmConfig,
        },
      },
    });
  } catch (err: any) {
    console.error('[SessionControls] Reset error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── POST /api/session/clear — Full session clear (everything except ID) ────

sessionControlsRouter.post('/clear/:sessionId', (req: Request, res: Response) => {
  try {
    const { sessionId } = req.params;
    const session = store.getSession(sessionId);

    if (!session) {
      return res.status(404).json({ success: false, error: 'Session not found' });
    }

    // Clear everything
    session.chatHistory = [];
    session.findings = [];
    session.captureFiles = [];
    session.policy = undefined;
    session.updatedAt = new Date().toISOString();

    store.updateSession(session);

    console.log(`[SessionControls] Cleared session ${sessionId} completely`);

    res.json({
      success: true,
      data: {
        message: 'Session cleared successfully. Upload new files to start fresh.',
      },
    });
  } catch (err: any) {
    console.error('[SessionControls] Clear error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── DELETE /api/session/:sessionId — Delete session permanently ────────────

sessionControlsRouter.delete('/:sessionId', (req: Request, res: Response) => {
  try {
    const { sessionId } = req.params;
    const session = store.getSession(sessionId);

    if (!session) {
      return res.status(404).json({ success: false, error: 'Session not found' });
    }

    // Delete from store
    store.deleteSession(sessionId);

    console.log(`[SessionControls] Deleted session ${sessionId}`);

    res.json({
      success: true,
      data: {
        message: 'Session deleted successfully',
      },
    });
  } catch (err: any) {
    console.error('[SessionControls] Delete error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── GET /api/session/memory/:sessionId — Get memory usage stats ────────────

sessionControlsRouter.get('/memory/:sessionId', (req: Request, res: Response) => {
  try {
    const { sessionId } = req.params;
    const session = store.getSession(sessionId);

    if (!session) {
      return res.status(404).json({ success: false, error: 'Session not found' });
    }

    const chatHistorySize = JSON.stringify(session.chatHistory).length;
    const findingsSize = JSON.stringify(session.findings).length;
    const totalSize = chatHistorySize + findingsSize;

    res.json({
      success: true,
      data: {
        chatMessages: session.chatHistory.length,
        findings: session.findings.length,
        captureFiles: session.captureFiles.length,
        hasPolicy: !!session.policy,
        memoryUsage: {
          chatHistoryKB: Math.round(chatHistorySize / 1024),
          findingsKB: Math.round(findingsSize / 1024),
          totalKB: Math.round(totalSize / 1024),
        },
      },
    });
  } catch (err: any) {
    console.error('[SessionControls] Memory stats error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── POST /api/session/compact/:sessionId — Compact memory (keep last N msgs) ─

sessionControlsRouter.post('/compact/:sessionId', (req: Request, res: Response) => {
  try {
    const { sessionId } = req.params;
    const { keepLastMessages = 10 } = req.body;
    const session = store.getSession(sessionId);

    if (!session) {
      return res.status(404).json({ success: false, error: 'Session not found' });
    }

    const originalCount = session.chatHistory.length;

    // Keep only last N messages
    if (session.chatHistory.length > keepLastMessages) {
      session.chatHistory = session.chatHistory.slice(-keepLastMessages);
    }

    session.updatedAt = new Date().toISOString();
    store.updateSession(session);

    const removed = originalCount - session.chatHistory.length;

    console.log(`[SessionControls] Compacted session ${sessionId} — removed ${removed} old messages`);

    res.json({
      success: true,
      data: {
        message: `Compacted chat history: kept last ${session.chatHistory.length} messages`,
        removed,
        remaining: session.chatHistory.length,
      },
    });
  } catch (err: any) {
    console.error('[SessionControls] Compact error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});
