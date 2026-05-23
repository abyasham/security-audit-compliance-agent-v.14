/**
 * PythonCoreClient — HTTP bridge from Express API → Python FastAPI Core.
 *
 * Replaces:
 *   - Direct agent imports (PolicyAgent, NetworkAgent, ComplianceJudge)
 *   - LLMGateway chat calls (→ streamChat)
 *   - RAGAS evaluation
 *
 * All LLM-heavy work lives in Python via LiteLLM.
 */
import type { ComplianceFinding, ParsedPolicy, PolicyRule, TcpStream } from '../types';
export interface NetworkAgentOutput {
    conversations: TcpStream[];
    anomalies: any[];
    summary?: any;
}
/** Check whether the Python core is reachable. */
export declare function checkHealth(): Promise<boolean>;
/** Returns true once; throws after 30 s of retries. */
export declare function waitForCore(retries?: number, delayMs?: number): Promise<void>;
export declare function analyzeNetwork(sessionId: string, filePath: string): Promise<NetworkAgentOutput>;
export declare function analyzePolicy(sessionId: string, policyText: string, sourceFormat?: string): Promise<{
    rules: PolicyRule[];
    policy: ParsedPolicy;
}>;
export declare function judgeCompliance(sessionId: string, rules: PolicyRule[], networkOutput: any): Promise<{
    findings: ComplianceFinding[];
    summary: any;
}>;
export declare function streamChat(messages: Array<{
    role: string;
    content: string;
}>, provider?: string): AsyncGenerator<{
    delta: string;
    finish?: boolean;
}>;
export interface RagasEvalResult {
    sessionId: string | null;
    timestamp: string;
    avgFaithfulness: number;
    avgAnswerRelevancy: number;
    perFindingScores: Array<{
        findingId: string;
        ruleName: string;
        faithfulness: number;
        answerRelevancy: number;
    }>;
    providerUsed: string | null;
    heuristicFallback: boolean;
    error: string | null;
}
export declare function runRagas(sessionId: string, findings: unknown[], policyText: string): Promise<RagasEvalResult>;
//# sourceMappingURL=pythonCoreClient.d.ts.map