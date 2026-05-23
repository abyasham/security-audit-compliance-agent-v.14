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
exports.policyRouter = void 0;
const express_1 = require("express");
const policyParser_1 = require("../services/policyParser");
const pythonCore = __importStar(require("../services/pythonCoreClient"));
exports.policyRouter = (0, express_1.Router)();
// ─── Parse Policy File ──────────────────────────────────────────────────────
exports.policyRouter.post('/parse', async (req, res) => {
    try {
        const { filePath } = req.body;
        if (!filePath) {
            return res.status(400).json({ success: false, error: 'filePath is required' });
        }
        const parser = new policyParser_1.PolicyParser();
        const result = await parser.parse(filePath);
        res.json({
            success: true,
            data: result,
        });
    }
    catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});
// ─── Extract Rules from Policy Text (via PolicyAgent + LLM/Fallback) ─────────
exports.policyRouter.post('/extract-rules', async (req, res) => {
    try {
        const { policyText, policyName, framework, llmConfig } = req.body;
        if (!policyText) {
            return res.status(400).json({ success: false, error: 'policyText is required' });
        }
        const parsedPolicy = {
            policyName: policyName || 'Inline Policy Text',
            framework,
            sourceFormat: 'text',
            rawText: String(policyText),
            rules: [],
        };
        const provider = llmConfig?.agentProviders?.policy;
        const result = await pythonCore.analyzePolicy('extract-rules', // dummy sessionId for standalone extraction
        String(policyText), 'text');
        const rules = result.rules || [];
        const categories = [...new Set(rules.map((r) => r.category).filter(Boolean))];
        const severities = [...new Set(rules.map((r) => r.severity).filter(Boolean))];
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
    }
    catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});
// ─── Validate Policy JSON ───────────────────────────────────────────────────
exports.policyRouter.post('/validate', (req, res) => {
    try {
        const { policy } = req.body;
        if (!policy) {
            return res.status(400).json({ success: false, error: 'Policy object is required' });
        }
        const parser = new policyParser_1.PolicyParser();
        const validation = parser.validateStructured(policy);
        res.json({
            success: true,
            data: validation,
        });
    }
    catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});
//# sourceMappingURL=policy.js.map