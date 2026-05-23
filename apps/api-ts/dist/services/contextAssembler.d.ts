import { Session } from '../types';
/**
 * ContextAssembler — builds the prompt for the LLM.
 *
 * Ported from NetTrace Agentix's contextAssembler.ts, adapted for SACA:
 * - Policy-violating packets get HIGHEST priority in context
 * - Anomalous packets get second priority
 * - Policy text is injected alongside packet data
 * - Context is limited to uploaded artifacts (policy + capture)
 */
export declare class ContextAssembler {
    private static readonly CHARS_PER_TOKEN;
    /**
     * Build the complete system prompt for compliance auditing.
     */
    assembleSystemPrompt(session: Session): Promise<string>;
    /**
     * Build the user message with packet data context.
     */
    assembleUserMessage(session: Session, userQuery: string): Promise<string>;
    /**
     * Estimate token count for budget management.
     */
    countTokens(text: string): number;
    /**
     * Check if content fits within budget.
     */
    fitsInBudget(text: string, budget: number): boolean;
    private getBaseSystemPrompt;
    private getAgentPrompt;
    private getPolicyContext;
    private getCaptureSummary;
}
//# sourceMappingURL=contextAssembler.d.ts.map