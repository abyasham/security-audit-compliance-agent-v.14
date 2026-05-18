import { Router, Request, Response } from 'express';
import { tsharkRunner } from '../services/sharedTshark';

export const captureRouter = Router();

// ─── Middleware: Check tshark availability ───────────────────────────────────

captureRouter.use((_req, res, next) => {
  if (!tsharkRunner.isAvailable()) {
    return res.status(400).json({
      success: false,
      error: 'tshark not found. Install Wireshark from https://www.wireshark.org/download.html or set TSHARK_PATH in .env',
      tsharkHelp: true,
    });
  }
  next();
});

// Helper to extract filePath from query or body
function getFilePath(req: Request): string {
  return req.body?.filePath || (req.query.filePath as string) || '';
}

// ─── Get Capture Summary ────────────────────────────────────────────────────

captureRouter.post('/summary', async (req: Request, res: Response) => {
  try {
    const filePath = getFilePath(req);
    if (!filePath) return res.status(400).json({ success: false, error: 'filePath required' });
    const summary = await tsharkRunner.getCaptureSummary(filePath);
    res.json({ success: true, data: summary });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── Get Packet Range ───────────────────────────────────────────────────────

captureRouter.post('/packets', async (req: Request, res: Response) => {
  try {
    const filePath = getFilePath(req);
    const startFrame = req.body?.startFrame || parseInt(req.query.start as string) || 1;
    const endFrame = req.body?.endFrame || parseInt(req.query.end as string) || 100;
    const filter = req.body?.filter || req.query.filter as string | undefined;

    if (!filePath) return res.status(400).json({ success: false, error: 'filePath required' });

    const packets = await tsharkRunner.getPacketRange(filePath, startFrame, endFrame, filter);
    res.json({ success: true, data: packets });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── Get Conversations ──────────────────────────────────────────────────────

captureRouter.post('/conversations', async (req: Request, res: Response) => {
  try {
    const filePath = getFilePath(req);
    const protocol = req.body?.protocol || req.query.protocol as string || 'tcp';
    if (!filePath) return res.status(400).json({ success: false, error: 'filePath required' });
    const conversations = await tsharkRunner.getConversations(filePath, protocol);
    res.json({ success: true, data: conversations });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── Get Expert Info ────────────────────────────────────────────────────────

captureRouter.post('/expert-info', async (req: Request, res: Response) => {
  try {
    const filePath = getFilePath(req);
    const severity = req.body?.severity || req.query.severity as string | undefined;
    if (!filePath) return res.status(400).json({ success: false, error: 'filePath required' });
    const info = await tsharkRunner.getExpertInfo(filePath, severity);
    res.json({ success: true, data: info });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── Get Stream Detail ──────────────────────────────────────────────────────

captureRouter.post('/stream-detail', async (req: Request, res: Response) => {
  try {
    const filePath = getFilePath(req);
    const streamIndex = req.body?.streamIndex;
    if (!filePath) return res.status(400).json({ success: false, error: 'filePath required' });
    if (streamIndex === undefined) return res.status(400).json({ success: false, error: 'streamIndex required' });
    const detail = await tsharkRunner.getStreamDetail(filePath, streamIndex);
    res.json({ success: true, data: detail });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── Apply Filter ───────────────────────────────────────────────────────────

captureRouter.post('/filter', async (req: Request, res: Response) => {
  try {
    const filePath = getFilePath(req);
    const filter = req.body?.filter || req.query.filter as string;
    const maxPackets = req.body?.maxPackets || parseInt(req.query.maxPackets as string) || 100;
    if (!filePath) return res.status(400).json({ success: false, error: 'filePath required' });
    if (!filter) return res.status(400).json({ success: false, error: 'Filter expression is required' });
    const packets = await tsharkRunner.applyFilter(filePath, filter, maxPackets);
    res.json({ success: true, data: packets });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});
