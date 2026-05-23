import { Router, Request, Response } from 'express';
import { PolicyParser } from '../services/policyParser';
import * as pythonCore from '../services/pythonCoreClient';

export const policyRouter = Router();

// ─── Parse Policy File ──────────────────────────────────────────────────────

policyRouter.post('/parse', async (req: Request, res: Response) => {
  try {
    const { filePath } = req.body;

    if (!filePath) {
      return res.status(400).json({ success: false, error: 'filePath is required' });
    }

    const parser = new PolicyParser();
    const result = await parser.parse(filePath);

    res.json({
      success: true,
      data: result,
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── Extract Rules from Policy Text (via PolicyAgent + LLM/Fallback) ─────────

policyRouter.post('/extract-rules', async (req: Request, res: Response) => {
  try {
    const { policyText, policyName, framework, llmConfig } = req.body;

    if (!policyText) {
      return res.status(400).json({ success: false, error: 'policyText is required' });
    }

    const parsedPolicy: import('../types').ParsedPolicy = {
      policyName: policyName || 'Inline Policy Text',
      framework,
      sourceFormat: 'text',
      rawText: String(policyText),
      rules: [],
    };

    const provider = llmConfig?.agentProviders?.policy;
    const result = await pythonCore.analyzePolicy(
      'extract-rules',  // dummy sessionId for standalone extraction
      String(policyText),
      'text',
    );

    const rules = result.rules || [];
    const categories = [...new Set(rules.map((r: any) => r.category).filter(Boolean))];
    const severities = [...new Set(rules.map((r: any) => r.severity).filter(Boolean))];

    res.json({
      success: true,
      data: {
        policyName: result.policy?.policyName || policyName,
        framework: result.policy?.framework || framework,
        rawTextLength: result.policy?.rawText?.length || 0,
        ruleCount: rules.length,
        categories,
        severities,
        rules,
      },
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── Validate Policy JSON ───────────────────────────────────────────────────

policyRouter.post('/validate', (req: Request, res: Response) => {
  try {
    const { policy } = req.body;

    if (!policy) {
      return res.status(400).json({ success: false, error: 'Policy object is required' });
    }

    const parser = new PolicyParser();
    const validation = parser.validateStructured(policy);

    res.json({
      success: true,
      data: validation,
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});
