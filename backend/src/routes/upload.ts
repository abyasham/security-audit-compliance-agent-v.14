import { Router, Request, Response } from 'express';
import multer from 'multer';
import path from 'path';
import { config } from '../config';
import { v4 as uuidv4 } from 'uuid';

export const uploadRouter = Router();

// ─── Multer Configuration ───────────────────────────────────────────────────

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, config.uploadDir);
  },
  filename: (_req, file, cb) => {
    const uniqueName = `${uuidv4()}${path.extname(file.originalname)}`;
    cb(null, uniqueName);
  },
});

const fileFilter = (_req: Request, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
  const allowedPcap = ['.pcap', '.pcapng', '.cap', '.pcpap'];
  const allowedPolicy = ['.pdf', '.docx', '.doc', '.json', '.yaml', '.yml', '.txt'];
  const ext = path.extname(file.originalname).toLowerCase();

  if (file.fieldname === 'pcap' && allowedPcap.includes(ext)) {
    cb(null, true);
  } else if (file.fieldname === 'policy' && allowedPolicy.includes(ext)) {
    cb(null, true);
  } else {
    cb(new Error(`Unsupported file type: ${ext}. Allowed pcap: ${allowedPcap.join(', ')}. Allowed policy: ${allowedPolicy.join(', ')}`));
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: config.maxFileSize },
});

// ─── Upload PCAP ────────────────────────────────────────────────────────────

uploadRouter.post('/pcap', upload.single('pcap'), (req: Request, res: Response) => {
  if (!req.file) {
    return res.status(400).json({ success: false, error: 'No pcap file provided' });
  }

  const file = req.file;
  res.json({
    success: true,
    data: {
      id: path.basename(file.filename, path.extname(file.filename)),
      name: file.originalname,
      filePath: file.path,
      sizeBytes: file.size,
      mimeType: file.mimetype || 'application/octet-stream',
      parsed: false,
    },
  });
});

// ─── Upload Policy ──────────────────────────────────────────────────────────

uploadRouter.post('/policy', upload.single('policy'), (req: Request, res: Response) => {
  if (!req.file) {
    return res.status(400).json({ success: false, error: 'No policy file provided' });
  }

  const file = req.file;
  res.json({
    success: true,
    data: {
      id: path.basename(file.filename, path.extname(file.filename)),
      name: file.originalname,
      filePath: file.path,
      sizeBytes: file.size,
      mimeType: file.mimetype || 'application/octet-stream',
    },
  });
});

// ─── Error Handler for Multer ───────────────────────────────────────────────

uploadRouter.use((err: any, _req: Request, res: Response, _next: any) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({ success: false, error: `File too large. Max size: ${config.maxFileSize / 1024 / 1024}MB` });
    }
    return res.status(400).json({ success: false, error: err.message });
  }
  if (err) {
    return res.status(400).json({ success: false, error: err.message });
  }
  res.status(500).json({ success: false, error: 'Upload failed' });
});
