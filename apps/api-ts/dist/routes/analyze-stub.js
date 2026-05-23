"use strict";
/**
 * Stub Analyzer — Returns realistic mock findings for end-to-end testing.
 * Use while debugging Python Core issues.
 *
 * Disable by removing from index.ts or setting USE_STUB=false in .env
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.analyzeStubRouter = void 0;
const express_1 = require("express");
const sessionStore_1 = require("../storage/sessionStore");
const uuid_1 = require("uuid");
exports.analyzeStubRouter = (0, express_1.Router)();
const store = sessionStore_1.SessionStore.getInstance();
// Mock findings for testing UI without Python Core
function generateMockFindings(sessionId, ruleCount) {
    const findings = [];
    const mockData = [
        {
            ruleName: 'Unencrypted HTTP Traffic',
            description: 'Detected HTTP connections without TLS encryption',
            severity: 'high',
            status: 'violated',
            confidence: 0.92,
            srcIp: '192.168.137.163',
            dstIp: '120.76.210.199',
            dstPort: 80,
        },
        {
            ruleName: 'Suspicious Port 22 Access',
            description: 'SSH connection from unusual source IP',
            severity: 'medium',
            status: 'suspicious',
            confidence: 0.65,
            srcIp: '203.0.113.45',
            dstIp: '10.0.0.5',
            dstPort: 22,
        },
        {
            ruleName: 'DNS Resolution Compliance',
            description: 'DNS queries to non-authoritative resolver',
            severity: 'low',
            status: 'suspicious',
            confidence: 0.48,
            srcIp: '192.168.137.163',
            dstIp: '8.8.8.8',
            dstPort: 53,
        },
        {
            ruleName: 'TLS 1.2+ Compliance',
            description: 'HTTPS connection using TLS 1.2 - compliant',
            severity: 'info',
            status: 'compliant',
            confidence: 0.99,
            srcIp: '192.168.137.163',
            dstIp: '93.184.216.34',
            dstPort: 443,
        },
        {
            ruleName: 'Internal Network Segmentation',
            description: 'Traffic between expected internal subnets',
            severity: 'low',
            status: 'compliant',
            confidence: 0.98,
            srcIp: '10.0.0.1',
            dstIp: '10.0.0.5',
            dstPort: 3306,
        },
    ];
    mockData.slice(0, Math.min(5, ruleCount + 2)).forEach((data, idx) => {
        findings.push({
            id: (0, uuid_1.v4)(),
            ruleId: `rule-${idx}`,
            ruleName: data.ruleName,
            ruleDescription: data.description,
            category: 'encryption',
            severity: data.severity,
            standard: 'NIST-800-53',
            policyContext: 'Internal security policy v2.1',
            evidencePacketNumbers: [42, 43, 44, 45, 46],
            description: data.description,
            timestamp: new Date().toISOString(),
            dismissed: false,
            confidence: data.confidence,
            status: data.status,
            evidence: {
                srcIp: data.srcIp,
                dstIp: data.dstIp,
                dstPort: data.dstPort,
                protocol: data.dstPort === 443 ? 'TLS' : data.dstPort === 22 ? 'SSH' : data.dstPort === 53 ? 'DNS' : 'TCP',
                details: `Traffic detected from ${data.srcIp} to ${data.dstIp}:${data.dstPort}`,
            },
            reasoning: `This finding was detected based on packet analysis showing ${data.description.toLowerCase()}`,
        });
    });
    return findings;
}
exports.analyzeStubRouter.get('/status/:sessionId', (req, res) => {
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
exports.analyzeStubRouter.post('/', async (req, res) => {
    try {
        const { sessionId } = req.body;
        if (!sessionId) {
            return res.status(400).json({ success: false, error: 'sessionId is required' });
        }
        const session = store.getSession(sessionId);
        if (!session) {
            return res.status(404).json({ success: false, error: 'Session not found' });
        }
        console.log(`[AnalyzeStub] Generating mock findings for session ${sessionId}`);
        // Generate mock findings
        const findings = generateMockFindings(sessionId, 5);
        // Calculate summary
        const summary = {
            totalRules: 5,
            violated: findings.filter(f => f.status === 'violated').length,
            compliant: findings.filter(f => f.status === 'compliant').length,
            suspicious: findings.filter(f => f.status === 'suspicious').length,
            criticalCount: findings.filter(f => f.severity === 'critical').length,
            highCount: findings.filter(f => f.severity === 'high').length,
            mediumCount: findings.filter(f => f.severity === 'medium').length,
            lowCount: findings.filter(f => f.severity === 'low').length,
            averageConfidence: findings.reduce((sum, f) => sum + (f.confidence || 0), 0) / findings.length,
        };
        // Persist
        session.findings = findings;
        session.updatedAt = new Date().toISOString();
        store.updateSession(session);
        res.json({
            success: true,
            data: {
                findings,
                summary,
                agentMetadata: {
                    policyRulesExtracted: 5,
                    trafficConversationsAnalyzed: 12,
                    trafficAnomaliesDetected: 3,
                    processingTimeMs: 2500,
                    providersUsed: {
                        policy: 'mock',
                        network: 'mock',
                        judge: 'mock',
                    },
                },
            },
        });
    }
    catch (err) {
        console.error('[AnalyzeStub] Error:', err);
        res.status(500).json({ success: false, error: err.message || 'Analysis failed' });
    }
});
//# sourceMappingURL=analyze-stub.js.map