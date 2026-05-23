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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const path_1 = __importDefault(require("path"));
const config_1 = require("./config");
const upload_1 = require("./routes/upload");
const capture_1 = require("./routes/capture");
const policy_1 = require("./routes/policy");
const session_1 = require("./routes/session");
const session_controls_1 = require("./routes/session-controls");
const chat_1 = require("./routes/chat");
const graph_1 = require("./routes/graph");
const analyze_1 = require("./routes/analyze");
const pythonCore = __importStar(require("./services/pythonCoreClient"));
const app = (0, express_1.default)();
// ─── Middleware ──────────────────────────────────────────────────────────────
app.use((0, cors_1.default)());
app.use(express_1.default.json({ limit: '50mb' }));
app.use(express_1.default.urlencoded({ extended: true, limit: '50mb' }));
// ─── Static Files (Logo, Frontend build) ────────────────────────────────────
app.use('/static', express_1.default.static(path_1.default.resolve(__dirname, '..', 'public')));
// ─── Routes ─────────────────────────────────────────────────────────────────
app.use('/api/upload', upload_1.uploadRouter);
app.use('/api/capture', capture_1.captureRouter);
app.use('/api/policy', policy_1.policyRouter);
app.use('/api/session', session_1.sessionRouter);
app.use('/api/session/controls', session_controls_1.sessionControlsRouter);
app.use('/api/chat', chat_1.chatRouter);
app.use('/api/graph', graph_1.graphRouter);
// Use real analyzer (Python Core)
app.use('/api/analyze', analyze_1.analyzeRouter);
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
            pythonCoreUrl: config_1.config.pythonCoreUrl,
        },
    });
});
// ─── Error Handler ──────────────────────────────────────────────────────────
app.use((err, _req, res, _next) => {
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
const fs_1 = __importDefault(require("fs"));
app.post('/api/admin/clear-all', async (_req, res) => {
    try {
        // Clear uploads
        const uploadFiles = fs_1.default.readdirSync(config_1.config.uploadDir);
        for (const file of uploadFiles) {
            fs_1.default.unlinkSync(path_1.default.join(config_1.config.uploadDir, file));
        }
        // Clear data
        const dataFiles = fs_1.default.readdirSync(config_1.config.dataDir);
        for (const file of dataFiles) {
            fs_1.default.unlinkSync(path_1.default.join(config_1.config.dataDir, file));
        }
        // Clear session memory
        const { SessionStore } = await Promise.resolve().then(() => __importStar(require('./storage/sessionStore')));
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
    }
    catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});
// ─── Start Server ───────────────────────────────────────────────────────────
async function start() {
    // Check Python Core connectivity
    try {
        const coreOk = await pythonCore.checkHealth();
        console.log(`[SACA] Python Core: ${coreOk ? 'connected' : '❌ unreachable'}`);
    }
    catch {
        console.log('[SACA] Python Core: not checked');
    }
    app.listen(config_1.config.port, () => {
        console.log(`[SACA] ════════════════════════════════════════`);
        console.log(`[SACA]  SACA Server v0.2.0`);
        console.log(`[SACA]  http://localhost:${config_1.config.port}`);
        console.log(`[SACA]  Python Core: ${config_1.config.pythonCoreUrl}`);
        console.log(`[SACA] ════════════════════════════════════════`);
    });
}
start().catch(err => {
    console.error('[SACA] Failed to start:', err);
    process.exit(1);
});
exports.default = app;
//# sourceMappingURL=index.js.map