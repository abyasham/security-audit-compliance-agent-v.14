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
import { tsharkRunner } from './services/sharedTshark';

const app = express();

// ─── Shared Tshark Runner ───────────────────────────────────────────────────
export { tsharkRunner };

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
app.use('/api/analyze', analyzeRouter);

// ─── Health Check ───────────────────────────────────────────────────────────

app.get('/api/health', (_req, res) => {
  res.json({
    success: true,
    data: {
      status: 'ok',
      version: '0.2.0',
      uptime: process.uptime(),
      logo: '/static/saca.jpg',
      tshark: tsharkRunner.getStatus(),
      tsharkHelp: tsharkRunner.isAvailable()
        ? undefined
        : 'tshark not found. Install Wireshark from https://www.wireshark.org/download.html or set TSHARK_PATH in .env',
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
  // Auto-detect tshark on startup
  const tsharkPath = await tsharkRunner.detectTshark();
  if (tsharkPath) {
    console.log(`[SACA] tshark detected: ${tsharkPath}`);
  } else {
    console.log('[SACA] ⚠ tshark not found. Install Wireshark from https://www.wireshark.org/download.html');
    console.log('[SACA]   Or set TSHARK_PATH in .env to point to tshark.exe');
  }

  app.listen(config.port, () => {
    console.log(`[SACA] ════════════════════════════════════════`);
    console.log(`[SACA]  SACA Server v0.2.0`);
    console.log(`[SACA]  http://localhost:${config.port}`);
    console.log(`[SACA]  Logo: /static/saca.jpg`);
    console.log(`[SACA]  tshark: ${tsharkRunner.getStatus().path || '(not found)'}`);
    console.log(`[SACA] ════════════════════════════════════════`);
    console.log(`[SACA] Upload directory: ${config.uploadDir}`);
    console.log(`[SACA] Data directory: ${config.dataDir}`);
  });
}

start().catch(err => {
  console.error('[SACA] Failed to start:', err);
  process.exit(1);
});

export default app;
