"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.uploadRouter = void 0;
const express_1 = require("express");
const multer_1 = __importDefault(require("multer"));
const path_1 = __importDefault(require("path"));
const config_1 = require("../config");
const uuid_1 = require("uuid");
exports.uploadRouter = (0, express_1.Router)();
// ─── Multer Configuration ───────────────────────────────────────────────────
const storage = multer_1.default.diskStorage({
    destination: (_req, _file, cb) => {
        cb(null, config_1.config.uploadDir);
    },
    filename: (_req, file, cb) => {
        const uniqueName = `${(0, uuid_1.v4)()}${path_1.default.extname(file.originalname)}`;
        cb(null, uniqueName);
    },
});
const fileFilter = (_req, file, cb) => {
    const allowedPcap = ['.pcap', '.pcapng', '.cap', '.pcpap'];
    const allowedPolicy = ['.pdf', '.docx', '.doc', '.json', '.yaml', '.yml', '.txt'];
    const ext = path_1.default.extname(file.originalname).toLowerCase();
    if (file.fieldname === 'pcap' && allowedPcap.includes(ext)) {
        cb(null, true);
    }
    else if (file.fieldname === 'policy' && allowedPolicy.includes(ext)) {
        cb(null, true);
    }
    else {
        cb(new Error(`Unsupported file type: ${ext}. Allowed pcap: ${allowedPcap.join(', ')}. Allowed policy: ${allowedPolicy.join(', ')}`));
    }
};
const upload = (0, multer_1.default)({
    storage,
    fileFilter,
    limits: { fileSize: config_1.config.maxFileSize },
});
// ─── Upload PCAP ────────────────────────────────────────────────────────────
exports.uploadRouter.post('/pcap', upload.single('pcap'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ success: false, error: 'No pcap file provided' });
    }
    const file = req.file;
    res.json({
        success: true,
        data: {
            id: path_1.default.basename(file.filename, path_1.default.extname(file.filename)),
            name: file.originalname,
            filePath: file.path,
            sizeBytes: file.size,
            mimeType: file.mimetype || 'application/octet-stream',
            parsed: false,
        },
    });
});
// ─── Upload Policy ──────────────────────────────────────────────────────────
exports.uploadRouter.post('/policy', upload.single('policy'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ success: false, error: 'No policy file provided' });
    }
    const file = req.file;
    res.json({
        success: true,
        data: {
            id: path_1.default.basename(file.filename, path_1.default.extname(file.filename)),
            name: file.originalname,
            filePath: file.path,
            sizeBytes: file.size,
            mimeType: file.mimetype || 'application/octet-stream',
        },
    });
});
// ─── Error Handler for Multer ───────────────────────────────────────────────
exports.uploadRouter.use((err, _req, res, _next) => {
    if (err instanceof multer_1.default.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(413).json({ success: false, error: `File too large. Max size: ${config_1.config.maxFileSize / 1024 / 1024}MB` });
        }
        return res.status(400).json({ success: false, error: err.message });
    }
    if (err) {
        return res.status(400).json({ success: false, error: err.message });
    }
    res.status(500).json({ success: false, error: 'Upload failed' });
});
//# sourceMappingURL=upload.js.map