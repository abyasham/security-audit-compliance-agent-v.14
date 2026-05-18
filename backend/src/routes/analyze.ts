import { Router, Request, Response } from 'express';
import { SessionStore } from '../storage/sessionStore';
import { PolicyAgent } from '../agents/policyAgent';
import { NetworkAgent } from '../agents/networkAgent';
import { ComplianceJudge } from '../agents/complianceJudge';
import { PolicyParser } from '../services/policyParser';
import { AnalyzeResponse } from '../types';
import { tsharkRunner } from '../services/sharedTshark';

export const analyzeRouter = Router();
const store = SessionStore.getInstance();

// ─── POST /api/analyze — Multi-Agent Orchestrator (Option B: Parallel + Judge) ─

analyzeRouter.post('/', async (req: Request, res: Response) => {
  const startTime = Date.now();

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
    const captureFile = session.captureFiles[0];
    const policy = session.policy;

    if (!captureFile) {
      return res.status(400).json({ success: false, error: 'No capture file loaded. Upload a pcap first.' });
    }
    if (!policy) {
      return res.status(400).json({ success: false, error: 'No policy loaded. Upload a policy document first.' });
    }

    console.log(`[Analyze] Starting multi-agent analysis for session ${sessionId}`);

    // ─── Resolve parsed policy ───────────────────────────────────────────────
    let parsedPolicy: import('../types').ParsedPolicy;
    const policyMeta = policy as any;

    if (policyMeta && (policyMeta.rawText || '').trim().length > 0) {
      // Frontend already linked a ParsedPolicy with rawText
      parsedPolicy = policyMeta;
      console.log(`[Analyze] Using pre-parsed policy: ${parsedPolicy.policyName}, rawText length: ${(parsedPolicy.rawText || '').length}`);
    } else if (policyMeta && policyMeta.filePath) {
      // Manual API usage: only metadata was linked, need to parse file
      try {
        const parser = new PolicyParser();
        parsedPolicy = await parser.parse(policyMeta.filePath);
        console.log(`[Analyze] Parsed policy from file: ${parsedPolicy.policyName}, rawText length: ${(parsedPolicy.rawText || '').length}`);
      } catch (err: any) {
        console.error('[Analyze] PolicyParser failed:', err.message);
        return res.status(500).json({ success: false, error: `Policy parsing failed: ${err.message}` });
      }
    } else {
      return res.status(400).json({ success: false, error: 'Policy has no rawText or filePath. Upload and parse a policy first.' });
    }

    // ─── Phase 1: Run Agent 1 (Policy) and Agent 2 (Network) IN PARALLEL ───
    // Read per-agent provider overrides from session config
    const agentProviders = session.llmConfig?.agentProviders || {};
    const policyProvider = agentProviders.policy;
    const networkProvider = agentProviders.network;
    const judgeProvider = agentProviders.judge;

    console.log(`[Analyze] Agent providers — Policy: ${policyProvider || 'global chain'}, Network: ${networkProvider || 'global chain'}, Judge: ${judgeProvider || 'global chain'}`);

    const policyAgent = new PolicyAgent(policyProvider);
    const networkAgent = new NetworkAgent(tsharkRunner, networkProvider);

    const [policyResult, networkResult] = await Promise.all([
      policyAgent.analyze(parsedPolicy, session.llmConfig).catch(err => {
        console.error('[Analyze] PolicyAgent failed:', err.message);
        return null;
      }),
      networkAgent.analyze(captureFile.filePath, session.llmConfig).catch(err => {
        console.error('[Analyze] NetworkAgent failed:', err.message);
        return null;
      }),
    ]);

    if (!policyResult) {
      return res.status(500).json({ success: false, error: 'Policy analysis failed. Check LLM connectivity.' });
    }
    if (!networkResult) {
      return res.status(500).json({ success: false, error: 'Network analysis failed. Check tshark connectivity.' });
    }

    // Quality gate: do not run compliance judgment when policy extraction failed.
    // Otherwise users only see generic anomaly findings (e.g., syn_scan) that are not
    // tied to uploaded policy clauses, which looks like "fixes not applied".
    const weakRuleCount = policyResult.rules.filter(r => !r.detectionLogic || r.detectionLogic.trim().length < 10).length;
    if (policyResult.ruleCount === 0) {
      return res.status(422).json({
        success: false,
        error: 'Policy extraction produced 0 actionable rules. Compliance analysis is blocked to avoid misleading anomaly-only output. Re-upload policy or try a clearer policy file format (TXT/DOCX/JSON), then run again.',
        data: {
          policyName: policyResult.policyName,
          rawTextLength: policyResult.rawTextLength,
          ruleCount: policyResult.ruleCount,
        },
      });
    }

    if (weakRuleCount === policyResult.ruleCount) {
      return res.status(422).json({
        success: false,
        error: 'Policy rules were extracted but detection logic is too weak for reliable compliance matching. Analysis blocked to prevent false confidence. Please refine policy text or upload structured JSON/YAML rules.',
        data: {
          policyName: policyResult.policyName,
          rawTextLength: policyResult.rawTextLength,
          ruleCount: policyResult.ruleCount,
          weakRuleCount,
        },
      });
    }

    console.log(`[Analyze] PolicyAgent: ${policyResult.ruleCount} rules | NetworkAgent: ${networkResult.conversations.length} conversations, ${networkResult.anomalies.length} anomalies`);

    // ─── Phase 2: Feed outputs to Agent 3 (Compliance Judge) ────────────────

    const judge = new ComplianceJudge(judgeProvider, tsharkRunner);
    const judgeResult = await judge.evaluate(policyResult, networkResult, session.llmConfig, captureFile.filePath);

    console.log(`[Analyze] Judge: ${judgeResult.summary.violated} violations, ${judgeResult.summary.compliant} compliant, ${judgeResult.summary.suspicious} suspicious`);

    // ─── Phase 3: Persist findings to session ───────────────────────────────

    const findings = judgeResult.findings.map(f => ({
      ...f,
      confidence: f.confidence,
      status: f.status,
      evidence: f.evidence,
      reasoning: f.reasoning,
    }));

    session.findings = findings;
    session.updatedAt = new Date().toISOString();
    store.updateSession(session);

    // ─── Phase 4: Build response ────────────────────────────────────────────

    const processingTimeMs = Date.now() - startTime;

    const response: AnalyzeResponse = {
      findings,
      summary: judgeResult.summary,
      agentMetadata: {
        policyRulesExtracted: policyResult.ruleCount,
        trafficConversationsAnalyzed: networkResult.conversations.length,
        trafficAnomaliesDetected: networkResult.anomalies.length,
        processingTimeMs,
        providersUsed: {
          policy: policyProvider || 'global chain',
          network: networkProvider || 'global chain',
          judge: judgeProvider || 'global chain',
        },
      },
    };

    res.json({ success: true, data: response });
  } catch (err: any) {
    console.error('[Analyze] Orchestrator error:', err);
    res.status(500).json({ success: false, error: err.message || 'Analysis failed' });
  }
});

// ─── GET /api/analyze/status — Check if analysis can run for a session ─────

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
