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
Object.defineProperty(exports, "__esModule", { value: true });
exports.analyzeRouter = void 0;
const express_1 = require("express");
const sessionStore_1 = require("../storage/sessionStore");
const policyParser_1 = require("../services/policyParser");
const pythonCore = __importStar(require("../services/pythonCoreClient"));
const analysisProgress_1 = require("../storage/analysisProgress");
exports.analyzeRouter = (0, express_1.Router)();
const store = sessionStore_1.SessionStore.getInstance();
// ─── POST /api/analyze — Start Multi-Agent Analysis (async) ─────────────────
exports.analyzeRouter.post('/', async (req, res) => {
    try {
        const { sessionId } = req.body;
        if (!sessionId) {
            return res.status(400).json({ success: false, error: 'sessionId is required' });
        }
        const session = store.getSession(sessionId);
        if (!session) {
            return res.status(404).json({ success: false, error: 'Session not found' });
        }
        // Validate prerequisites
        const captureFile = session.captureFiles.find(f => f && f.filePath);
        const policy = session.policy;
        if (!captureFile) {
            return res.status(400).json({ success: false, error: 'No capture file loaded. Upload a pcap first.' });
        }
        if (!policy) {
            return res.status(400).json({ success: false, error: 'No policy loaded. Upload a policy document first.' });
        }
        // Check if analysis is already running
        const existing = analysisProgress_1.analysisProgressStore.get(sessionId);
        if (existing && existing.overallStatus === 'running') {
            return res.status(409).json({ success: false, error: 'Analysis already running for this session' });
        }
        // Start new analysis progress tracking
        analysisProgress_1.analysisProgressStore.start(sessionId);
        // Kick off analysis in background (don't await)
        runStagedAnalysis(sessionId, captureFile.filePath, policy).catch(err => {
            console.error('[Analyze] Background analysis error:', err);
            analysisProgress_1.analysisProgressStore.setFailed(sessionId, err.message || 'Analysis failed');
        });
        res.json({ success: true, data: { message: 'Analysis started', sessionId } });
    }
    catch (err) {
        console.error('[Analyze] Orchestrator error:', err);
        res.status(500).json({ success: false, error: err.message || 'Analysis failed' });
    }
});
// ─── GET /api/analyze/progress/:sessionId — Poll for progress ───────────────
exports.analyzeRouter.get('/progress/:sessionId', (req, res) => {
    const progress = analysisProgress_1.analysisProgressStore.get(req.params.sessionId);
    if (!progress) {
        return res.status(404).json({ success: false, error: 'No analysis found for this session' });
    }
    res.json({ success: true, data: progress });
});
// ─── GET /api/analyze/status — Check if analysis can run ────────────────────
exports.analyzeRouter.get('/status/:sessionId', (req, res) => {
    try {
        const session = store.getSession(req.params.sessionId);
        if (!session) {
            return res.status(404).json({ success: false, error: 'Session not found' });
        }
        const canAnalyze = session.captureFiles.length > 0 && !!session.policy;
        const missing = [];
        if (session.captureFiles.length === 0)
            missing.push('capture file');
        if (!session.policy)
            missing.push('policy document');
        res.json({
            success: true,
            data: {
                canAnalyze,
                missing,
                captureFiles: session.captureFiles.length,
                hasPolicy: !!session.policy,
                existingFindings: session.findings.length,
            },
        });
    }
    catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});
// ─── POST /api/analyze/step/:step — Run individual agent step ──────────────
exports.analyzeRouter.post('/step/:step', async (req, res) => {
    try {
        const { step } = req.params;
        const { sessionId } = req.body;
        if (!sessionId) {
            return res.status(400).json({ success: false, error: 'sessionId is required' });
        }
        if (!['policy', 'network', 'judge'].includes(step)) {
            return res.status(400).json({ success: false, error: 'Invalid step. Use: policy, network, judge' });
        }
        const session = store.getSession(sessionId);
        if (!session) {
            return res.status(404).json({ success: false, error: 'Session not found' });
        }
        const captureFile = session.captureFiles.find(f => f && f.filePath);
        const policy = session.policy;
        if (step === 'network' && !captureFile) {
            return res.status(400).json({ success: false, error: 'No capture file loaded' });
        }
        if ((step === 'policy' || step === 'judge') && !policy) {
            return res.status(400).json({ success: false, error: 'No policy loaded' });
        }
        if (step === 'judge' && (!session.policy?.rules || session.policy.rules.length === 0)) {
            return res.status(400).json({ success: false, error: 'Run policy step first to extract rules' });
        }
        let result;
        if (step === 'policy') {
            const policyData = policy;
            const parsedPolicy = policyData.rawText ? policyData : await new policyParser_1.PolicyParser().parse(policyData.filePath || '');
            result = await pythonCore.analyzePolicy(sessionId, parsedPolicy.rawText || '', parsedPolicy.sourceFormat || 'text');
            // Store rules on session
            session.policy = { ...session.policy, rules: result.rules };
            store.updateSession(session);
        }
        else if (step === 'network') {
            result = await pythonCore.analyzeNetwork(sessionId, captureFile.filePath);
            // Store network result on session for judge step
            session.networkOutput = result;
            store.updateSession(session);
        }
        else if (step === 'judge') {
            const rules = session.policy?.rules || [];
            const networkOutput = session.networkOutput || { conversations: [], anomalies: [] };
            result = await pythonCore.judgeCompliance(sessionId, rules, networkOutput);
            session.findings = result.findings || [];
            session.updatedAt = new Date().toISOString();
            store.updateSession(session);
            // Return in AnalyzeResponse format for frontend
            const findings = result.findings || [];
            const summary = result.summary || {
                totalRules: rules.length,
                violated: 0, compliant: 0, suspicious: 0,
                criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0,
                averageConfidence: 0,
            };
            result = { findings, summary, agentMetadata: {
                    policyRulesExtracted: rules.length,
                    trafficConversationsAnalyzed: networkOutput.conversations?.length || 0,
                    trafficAnomaliesDetected: networkOutput.anomalies?.length || 0,
                    processingTimeMs: 0,
                } };
        }
        res.json({ success: true, data: { step, result } });
    }
    catch (err) {
        console.error(`[Analyze] Step ${req.params.step} failed:`, err.message);
        res.status(500).json({ success: false, error: err.message });
    }
});
// ─── Background Analysis Runner ─────────────────────────────────────────────
async function runStagedAnalysis(sessionId, filePath, policy) {
    const startTime = Date.now();
    console.log(`[Analyze] Starting staged analysis for session ${sessionId}`);
    try {
        // ─── Resolve parsed policy ─────────────────────────────────────────────
        let parsedPolicy;
        const policyMeta = policy;
        if (policyMeta && (policyMeta.rawText || '').trim().length > 0) {
            parsedPolicy = policyMeta;
            console.log(`[Analyze] Using pre-parsed policy: ${parsedPolicy.policyName}, rawText length: ${(parsedPolicy.rawText || '').length}`);
        }
        else if (policyMeta && policyMeta.filePath) {
            const parser = new policyParser_1.PolicyParser();
            parsedPolicy = await parser.parse(policyMeta.filePath);
            console.log(`[Analyze] Parsed policy from file: ${parsedPolicy.policyName}`);
        }
        else {
            throw new Error('Policy has no rawText or filePath. Upload and parse a policy first.');
        }
        const session = store.getSession(sessionId);
        const agentProviders = session.llmConfig?.agentProviders || {};
        // ─── Stage 1: PolicyAgent ──────────────────────────────────────────────
        console.log(`[Analyze] Stage 1: PolicyAgent starting...`);
        analysisProgress_1.analysisProgressStore.setStageRunning(sessionId, 'policy');
        let policyResult;
        try {
            policyResult = await pythonCore.analyzePolicy(sessionId, parsedPolicy.rawText || '', parsedPolicy.sourceFormat || 'text');
            const ruleCount = policyResult.rules?.length || 0;
            console.log(`[Analyze] Stage 1: PolicyAgent complete — ${ruleCount} rules`);
            analysisProgress_1.analysisProgressStore.setStageCompleted(sessionId, 'policy', { ruleCount });
        }
        catch (err) {
            console.error('[Analyze] Stage 1: PolicyAgent failed:', err.message);
            analysisProgress_1.analysisProgressStore.setStageFailed(sessionId, 'policy', err.message);
            throw new Error(`Policy analysis failed: ${err.message}`);
        }
        // Quality gate
        const policyRules = policyResult.rules || [];
        if (policyRules.length === 0) {
            throw new Error('Policy extraction produced 0 actionable rules.');
        }
        // ─── Stage 2: NetworkAgent ─────────────────────────────────────────────
        console.log(`[Analyze] Stage 2: NetworkAgent starting...`);
        analysisProgress_1.analysisProgressStore.setStageRunning(sessionId, 'network');
        let networkResult;
        try {
            networkResult = await pythonCore.analyzeNetwork(sessionId, filePath);
            const convCount = networkResult.conversations?.length || 0;
            const anomalyCount = networkResult.anomalies?.length || 0;
            console.log(`[Analyze] Stage 2: NetworkAgent complete — ${convCount} conversations, ${anomalyCount} anomalies`);
            analysisProgress_1.analysisProgressStore.setStageCompleted(sessionId, 'network', { conversationCount: convCount, anomalyCount });
        }
        catch (err) {
            console.error('[Analyze] Stage 2: NetworkAgent failed:', err.message);
            analysisProgress_1.analysisProgressStore.setStageFailed(sessionId, 'network', err.message);
            throw new Error(`Network analysis failed: ${err.message}`);
        }
        // ─── Stage 3: ComplianceJudge ──────────────────────────────────────────
        console.log(`[Analyze] Stage 3: ComplianceJudge starting...`);
        analysisProgress_1.analysisProgressStore.setStageRunning(sessionId, 'judge');
        let judgeResult;
        try {
            judgeResult = await pythonCore.judgeCompliance(sessionId, policyRules, networkResult);
            const findingCount = judgeResult.findings?.length || 0;
            console.log(`[Analyze] Stage 3: ComplianceJudge complete — ${findingCount} findings`);
            analysisProgress_1.analysisProgressStore.setStageCompleted(sessionId, 'judge', { findingCount });
        }
        catch (err) {
            console.error('[Analyze] Stage 3: ComplianceJudge failed:', err.message);
            analysisProgress_1.analysisProgressStore.setStageFailed(sessionId, 'judge', err.message);
            throw new Error(`Compliance judgment failed: ${err.message}`);
        }
        // ─── Persist & Finalize ────────────────────────────────────────────────
        const findings = (judgeResult.findings || []).map((f) => ({
            ...f,
            confidence: f.confidence || 0,
            status: f.status || 'suspicious',
        }));
        session.findings = findings;
        session.updatedAt = new Date().toISOString();
        store.updateSession(session);
        const processingTimeMs = Date.now() - startTime;
        const response = {
            findings,
            summary: judgeResult.summary || {
                totalRules: policyRules.length,
                violated: 0, compliant: 0, suspicious: 0,
                criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0,
                averageConfidence: 0,
            },
            agentMetadata: {
                policyRulesExtracted: policyRules.length,
                trafficConversationsAnalyzed: networkResult.conversations?.length || 0,
                trafficAnomaliesDetected: networkResult.anomalies?.length || 0,
                processingTimeMs,
                providersUsed: {
                    policy: agentProviders.policy || 'global',
                    network: agentProviders.network || 'global',
                    judge: agentProviders.judge || 'global',
                },
            },
        };
        analysisProgress_1.analysisProgressStore.setCompleted(sessionId, response);
        console.log(`[Analyze] Analysis complete for session ${sessionId} — ${findings.length} findings`);
    }
    catch (err) {
        console.error('[Analyze] Staged analysis failed:', err.message);
        analysisProgress_1.analysisProgressStore.setFailed(sessionId, err.message);
    }
}
// ─── POST /api/analyze/evaluate — RAGAS evaluation ───────────────────────────
exports.analyzeRouter.post('/evaluate', async (req, res) => {
    try {
        const { sessionId } = req.body;
        if (!sessionId) {
            return res.status(400).json({ success: false, error: 'sessionId is required' });
        }
        const session = store.getSession(sessionId);
        if (!session) {
            return res.status(404).json({ success: false, error: 'Session not found' });
        }
        const findings = session.findings || [];
        const policyText = session.policy?.rawText || '';
        if (findings.length === 0) {
            return res.status(400).json({ success: false, error: 'No findings to evaluate. Run analysis first.' });
        }
        console.log(`[RAGAS] Evaluating ${findings.length} findings for session ${sessionId}`);
        const result = await pythonCore.runRagas(sessionId, findings, policyText);
        // Store RAGAS result on session
        session.ragasResult = result;
        session.updatedAt = new Date().toISOString();
        store.updateSession(session);
        res.json({ success: true, data: result });
    }
    catch (err) {
        console.error('[RAGAS] Evaluation failed:', err.message);
        res.status(500).json({ success: false, error: err.message });
    }
});
//# sourceMappingURL=analyze.js.map