import { Router, Request, Response } from 'express';
import { SessionStore } from '../storage/sessionStore';
import { PolicyParser } from '../services/policyParser';
import { AnalyzeResponse } from '../types';
import * as pythonCore from '../services/pythonCoreClient';
import { analysisProgressStore } from '../storage/analysisProgress';

export const analyzeRouter = Router();
const store = SessionStore.getInstance();

// ─── POST /api/analyze — Start Multi-Agent Analysis (async) ─────────────────

analyzeRouter.post('/', async (req: Request, res: Response) => {
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
    const existing = analysisProgressStore.get(sessionId);
    if (existing && existing.overallStatus === 'running') {
      return res.status(409).json({ success: false, error: 'Analysis already running for this session' });
    }

    // Start new analysis progress tracking
    analysisProgressStore.start(sessionId);

    // Kick off analysis in background (don't await)
    runStagedAnalysis(sessionId, captureFile.filePath, policy).catch(err => {
      console.error('[Analyze] Background analysis error:', err);
      analysisProgressStore.setFailed(sessionId, err.message || 'Analysis failed');
    });

    res.json({ success: true, data: { message: 'Analysis started', sessionId } });
  } catch (err: any) {
    console.error('[Analyze] Orchestrator error:', err);
    res.status(500).json({ success: false, error: err.message || 'Analysis failed' });
  }
});

// ─── GET /api/analyze/progress/:sessionId — Poll for progress ───────────────

analyzeRouter.get('/progress/:sessionId', (req: Request, res: Response) => {
  const progress = analysisProgressStore.get(req.params.sessionId);
  if (!progress) {
    return res.status(404).json({ success: false, error: 'No analysis found for this session' });
  }
  res.json({ success: true, data: progress });
});

// ─── GET /api/analyze/status — Check if analysis can run ────────────────────

analyzeRouter.get('/status/:sessionId', (req: Request, res: Response) => {
  try {
    const session = store.getSession(req.params.sessionId);
    if (!session) {
      return res.status(404).json({ success: false, error: 'Session not found' });
    }

    const canAnalyze = session.captureFiles.length > 0 && !!session.policy;
    const missing: string[] = [];
    if (session.captureFiles.length === 0) missing.push('capture file');
    if (!session.policy) missing.push('policy document');

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
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── POST /api/analyze/step/:step — Run individual agent step ──────────────

analyzeRouter.post('/step/:step', async (req: Request, res: Response) => {
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

    let result: any;
    if (step === 'policy') {
      const policyData = policy!;
      const parsedPolicy = policyData.rawText ? policyData : await new PolicyParser().parse((policyData as any).filePath || '');
      result = await pythonCore.analyzePolicy(sessionId, parsedPolicy.rawText || '', parsedPolicy.sourceFormat || 'text');
      // Store rules on session
      session.policy = { ...session.policy, rules: result.rules } as any;
      store.updateSession(session);
    } else if (step === 'network') {
      result = await pythonCore.analyzeNetwork(sessionId, captureFile!.filePath);
      // Store network result on session for judge step
      (session as any).networkOutput = result;
      store.updateSession(session);
    } else if (step === 'judge') {
      const rules = session.policy?.rules || [];
      const networkOutput = (session as any).networkOutput || { conversations: [], anomalies: [] };
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
      }};
    }

    res.json({ success: true, data: { step, result } });
  } catch (err: any) {
    console.error(`[Analyze] Step ${req.params.step} failed:`, err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── Background Analysis Runner ─────────────────────────────────────────────

async function runStagedAnalysis(sessionId: string, filePath: string, policy: any) {
  const startTime = Date.now();
  console.log(`[Analyze] Starting staged analysis for session ${sessionId}`);

  try {
    // ─── Resolve parsed policy ─────────────────────────────────────────────
    let parsedPolicy: import('../types').ParsedPolicy;
    const policyMeta = policy as any;

    if (policyMeta && (policyMeta.rawText || '').trim().length > 0) {
      parsedPolicy = policyMeta;
      console.log(`[Analyze] Using pre-parsed policy: ${parsedPolicy.policyName}, rawText length: ${(parsedPolicy.rawText || '').length}`);
    } else if (policyMeta && policyMeta.filePath) {
      const parser = new PolicyParser();
      parsedPolicy = await parser.parse(policyMeta.filePath);
      console.log(`[Analyze] Parsed policy from file: ${parsedPolicy.policyName}`);
    } else {
      throw new Error('Policy has no rawText or filePath. Upload and parse a policy first.');
    }

    const session = store.getSession(sessionId)!;
    const agentProviders = session.llmConfig?.agentProviders || {};

    // ─── Stage 1: PolicyAgent ──────────────────────────────────────────────
    console.log(`[Analyze] Stage 1: PolicyAgent starting...`);
    analysisProgressStore.setStageRunning(sessionId, 'policy');

    let policyResult: any;
    try {
      policyResult = await pythonCore.analyzePolicy(
        sessionId,
        parsedPolicy.rawText || '',
        parsedPolicy.sourceFormat || 'text',
      );
      const ruleCount = policyResult.rules?.length || 0;
      console.log(`[Analyze] Stage 1: PolicyAgent complete — ${ruleCount} rules`);
      analysisProgressStore.setStageCompleted(sessionId, 'policy', { ruleCount });
    } catch (err: any) {
      console.error('[Analyze] Stage 1: PolicyAgent failed:', err.message);
      analysisProgressStore.setStageFailed(sessionId, 'policy', err.message);
      throw new Error(`Policy analysis failed: ${err.message}`);
    }

    // Quality gate
    const policyRules = policyResult.rules || [];
    if (policyRules.length === 0) {
      throw new Error('Policy extraction produced 0 actionable rules.');
    }

    // ─── Stage 2: NetworkAgent ─────────────────────────────────────────────
    console.log(`[Analyze] Stage 2: NetworkAgent starting...`);
    analysisProgressStore.setStageRunning(sessionId, 'network');

    let networkResult: any;
    try {
      networkResult = await pythonCore.analyzeNetwork(sessionId, filePath);
      const convCount = networkResult.conversations?.length || 0;
      const anomalyCount = networkResult.anomalies?.length || 0;
      console.log(`[Analyze] Stage 2: NetworkAgent complete — ${convCount} conversations, ${anomalyCount} anomalies`);
      analysisProgressStore.setStageCompleted(sessionId, 'network', { conversationCount: convCount, anomalyCount });
    } catch (err: any) {
      console.error('[Analyze] Stage 2: NetworkAgent failed:', err.message);
      analysisProgressStore.setStageFailed(sessionId, 'network', err.message);
      throw new Error(`Network analysis failed: ${err.message}`);
    }

    // ─── Stage 3: ComplianceJudge ──────────────────────────────────────────
    console.log(`[Analyze] Stage 3: ComplianceJudge starting...`);
    analysisProgressStore.setStageRunning(sessionId, 'judge');

    let judgeResult: any;
    try {
      judgeResult = await pythonCore.judgeCompliance(
        sessionId,
        policyRules,
        networkResult,
      );
      const findingCount = judgeResult.findings?.length || 0;
      console.log(`[Analyze] Stage 3: ComplianceJudge complete — ${findingCount} findings`);
      analysisProgressStore.setStageCompleted(sessionId, 'judge', { findingCount });
    } catch (err: any) {
      console.error('[Analyze] Stage 3: ComplianceJudge failed:', err.message);
      analysisProgressStore.setStageFailed(sessionId, 'judge', err.message);
      throw new Error(`Compliance judgment failed: ${err.message}`);
    }

    // ─── Persist & Finalize ────────────────────────────────────────────────
    const findings = (judgeResult.findings || []).map((f: any) => ({
      ...f,
      confidence: f.confidence || 0,
      status: f.status || 'suspicious',
    }));

    session.findings = findings;
    session.updatedAt = new Date().toISOString();
    store.updateSession(session);

    const processingTimeMs = Date.now() - startTime;

    const response: AnalyzeResponse = {
      findings,
      summary: (judgeResult as any).summary || {
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

    analysisProgressStore.setCompleted(sessionId, response);
    console.log(`[Analyze] Analysis complete for session ${sessionId} — ${findings.length} findings`);

  } catch (err: any) {
    console.error('[Analyze] Staged analysis failed:', err.message);
    analysisProgressStore.setFailed(sessionId, err.message);
  }
}

// ─── POST /api/analyze/evaluate — RAGAS evaluation ───────────────────────────

analyzeRouter.post('/evaluate', async (req: Request, res: Response) => {
  try {
    const { sessionId } = req.body;
    if (!sessionId) {
      return res.status(400).json({ success: false, error: 'sessionId is required' });
    }

    const session = store.getSession(sessionId);
    if (!session) {
      return res.status(404).json({ success: false, error: 'Session not found' });
    }

    const allFindings = session.findings || [];
    const policyText = session.policy?.rawText || '';
    const captureFilePath = session.captureFiles.find(f => f && f.filePath)?.filePath;

    if (allFindings.length === 0) {
      return res.status(400).json({ success: false, error: 'No findings to evaluate. Run analysis first.' });
    }

    // Only send violated findings, capped at 3 — keeps RAGAS fast for prototype
    const RAGAS_MAX = 3;
    const violated = allFindings.filter((f: any) => f.status === 'violated');
    const sample = violated.length > 0
      ? violated.slice(0, RAGAS_MAX)
      : allFindings.slice(0, RAGAS_MAX);  // fallback if no violations

    console.log(`[RAGAS] Evaluating ${sample.length} findings (${violated.length} violated / ${allFindings.length} total) for session ${sessionId}`);
    const result = await pythonCore.runRagas(sessionId, sample, policyText, captureFilePath);

    // Annotate with sample info for UI
    const llmScored = result.perFindingScores.filter(p => p.scoredByLlm !== false).length;
    (result as any).sampleSize = llmScored;
    (result as any).totalFindings = allFindings.length;
    (result as any).violatedCount = violated.length;

    // Store RAGAS result on session
    (session as any).ragasResult = result;
    session.updatedAt = new Date().toISOString();
    store.updateSession(session);

    res.json({ success: true, data: result });
  } catch (err: any) {
    console.error('[RAGAS] Evaluation failed:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});
