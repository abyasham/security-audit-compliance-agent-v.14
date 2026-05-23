"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.captureRouter = void 0;
const express_1 = require("express");
const sharedTshark_1 = require("../services/sharedTshark");
exports.captureRouter = (0, express_1.Router)();
// ─── Middleware: Check tshark availability ───────────────────────────────────
exports.captureRouter.use((_req, res, next) => {
    if (!sharedTshark_1.tsharkRunner.isAvailable()) {
        return res.status(400).json({
            success: false,
            error: 'tshark not found. Install Wireshark from https://www.wireshark.org/download.html or set TSHARK_PATH in .env',
            tsharkHelp: true,
        });
    }
    next();
});
// Helper to extract filePath from query or body
function getFilePath(req) {
    return req.body?.filePath || req.query.filePath || '';
}
// ─── Get Capture Summary ────────────────────────────────────────────────────
exports.captureRouter.post('/summary', async (req, res) => {
    try {
        const filePath = getFilePath(req);
        if (!filePath)
            return res.status(400).json({ success: false, error: 'filePath required' });
        const summary = await sharedTshark_1.tsharkRunner.getCaptureSummary(filePath);
        res.json({ success: true, data: summary });
    }
    catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});
// ─── Get Packet Range ───────────────────────────────────────────────────────
exports.captureRouter.post('/packets', async (req, res) => {
    try {
        const filePath = getFilePath(req);
        const startFrame = req.body?.startFrame || parseInt(req.query.start) || 1;
        const endFrame = req.body?.endFrame || parseInt(req.query.end) || 100;
        const filter = req.body?.filter || req.query.filter;
        if (!filePath)
            return res.status(400).json({ success: false, error: 'filePath required' });
        const packets = await sharedTshark_1.tsharkRunner.getPacketRange(filePath, startFrame, endFrame, filter);
        res.json({ success: true, data: packets });
    }
    catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});
// ─── Get Conversations ──────────────────────────────────────────────────────
exports.captureRouter.post('/conversations', async (req, res) => {
    try {
        const filePath = getFilePath(req);
        const protocol = req.body?.protocol || req.query.protocol || 'tcp';
        if (!filePath)
            return res.status(400).json({ success: false, error: 'filePath required' });
        const conversations = await sharedTshark_1.tsharkRunner.getConversations(filePath, protocol);
        res.json({ success: true, data: conversations });
    }
    catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});
// ─── Get Expert Info ────────────────────────────────────────────────────────
exports.captureRouter.post('/expert-info', async (req, res) => {
    try {
        const filePath = getFilePath(req);
        const severity = req.body?.severity || req.query.severity;
        if (!filePath)
            return res.status(400).json({ success: false, error: 'filePath required' });
        const info = await sharedTshark_1.tsharkRunner.getExpertInfo(filePath, severity);
        res.json({ success: true, data: info });
    }
    catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});
// ─── Get Stream Detail ──────────────────────────────────────────────────────
exports.captureRouter.post('/stream-detail', async (req, res) => {
    try {
        const filePath = getFilePath(req);
        const streamIndex = req.body?.streamIndex;
        if (!filePath)
            return res.status(400).json({ success: false, error: 'filePath required' });
        if (streamIndex === undefined)
            return res.status(400).json({ success: false, error: 'streamIndex required' });
        const detail = await sharedTshark_1.tsharkRunner.getStreamDetail(filePath, streamIndex);
        res.json({ success: true, data: detail });
    }
    catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});
// ─── Apply Filter ───────────────────────────────────────────────────────────
exports.captureRouter.post('/filter', async (req, res) => {
    try {
        const filePath = getFilePath(req);
        const filter = req.body?.filter || req.query.filter;
        const maxPackets = req.body?.maxPackets || parseInt(req.query.maxPackets) || 100;
        if (!filePath)
            return res.status(400).json({ success: false, error: 'filePath required' });
        if (!filter)
            return res.status(400).json({ success: false, error: 'Filter expression is required' });
        const packets = await sharedTshark_1.tsharkRunner.applyFilter(filePath, filter, maxPackets);
        res.json({ success: true, data: packets });
    }
    catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});
//# sourceMappingURL=capture.js.map