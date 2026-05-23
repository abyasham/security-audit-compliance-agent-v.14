import express from 'express';
import cors from 'cors';
import path from 'path';
import { config } from './config';
import { uploadRouter } from './routes/upload';
import { captureRouter } from './routes/capture';
import { policyRouter } from './routes/policy';
import { sessionRouter } from './routes/session';
import { sessionControlsRouter } from './routes/session-controls';
import { chatRouter } from './routes/chat';
import { graphRouter } from './routes/graph';
import { analyzeRouter } from './routes/analyze';
import { analyzeStubRouter } from './routes/analyze-stub';
import * as pythonCore from './services/pythonCoreClient';

const app = express();

// ─── Middleware ──────────────────────────────────────────────────────────────

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// ─── Static Files (Logo, Frontend build) ────────────────────────────────────

app.use('/static', express.static(path.resolve(__dirname, '..', 'public')));

// ─── Routes ─────────────────────────────────────────────────────────────────

app.use('/api/upload', uploadRouter);
app.use('/api/capture', captureRouter);
app.use('/api/policy', policyRouter);
app.use('/api/session', sessionRouter);
app.use('/api/session/controls', sessionControlsRouter);
app.use('/api/chat', chatRouter);
app.use('/api/graph', graphRouter);
// Use real analyzer (Python Core)
app.use('/api/analyze', analyzeRouter);

// ─── Health Check ───────────────────────────────────────────────────────────

app.get('/api/health', async (_req, res) => {
  const coreOk = await pythonCore.checkHealth().catch(() => false);
  res.json({
    success: true,
    data: {
      status: 'ok',
      version: '0.2.0',
      uptime: process.uptime(),
      logo: '/static/saca.jpg',
      pythonCore: coreOk ? 'connected' : 'unavailable',
      pythonCoreUrl: config.pythonCoreUrl,
    },
  });
});

// ─── Error Handler ──────────────────────────────────────────────────────────

app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error('[SACA] Unhandled error:', err);
  res.status(500).json({
    success: false,
    error: err.message || 'Internal server error',
  });
});

// ─── Server Control Endpoints ───────────────────────────────────────────────

app.post('/api/shutdown', (_req, res) => {
  res.json({ success: true, message: 'Shutting down...' });
  console.log('[SACA] Shutdown requested via API');
  setTimeout(() => process.exit(0), 500);
});

import fs from 'fs';

app.post('/api/admin/clear-all', async (_req, res) => {
  try {
    // Clear uploads
    const uploadFiles = fs.readdirSync(config.uploadDir);
    for (const file of uploadFiles) {
      fs.unlinkSync(path.join(config.uploadDir, file));
    }
    
    // Clear data
    const dataFiles = fs.readdirSync(config.dataDir);
    for (const file of dataFiles) {
      fs.unlinkSync(path.join(config.dataDir, file));
    }
    
    // Clear session memory
    const { SessionStore } = await import('./storage/sessionStore');
    const store = SessionStore.getInstance();
    const result = store.clearAll();
    
    res.json({
      success: true,
      message: 'All data cleared',
      uploadsCleared: uploadFiles.length,
      dataFilesCleared: dataFiles.length,
      sessionsCleared: result.sessionsCleared,
      graphsCleared: result.graphsCleared
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── Start Server ───────────────────────────────────────────────────────────

async function start() {
  // Check Python Core connectivity
  try {
    const coreOk = await pythonCore.checkHealth();
    console.log(`[SACA] Python Core: ${coreOk ? 'connected' : '❌ unreachable'}`);
  } catch {
    console.log('[SACA] Python Core: not checked');
  }

  app.listen(config.port, () => {
    console.log(`[SACA] ════════════════════════════════════════`);
    console.log(`[SACA]  SACA Server v0.2.0`);
    console.log(`[SACA]  http://localhost:${config.port}`);
    console.log(`[SACA]  Python Core: ${config.pythonCoreUrl}`);
    console.log(`[SACA] ════════════════════════════════════════`);
  });
}

start().catch(err => {
  console.error('[SACA] Failed to start:', err);
  process.exit(1);
});

export default app;
