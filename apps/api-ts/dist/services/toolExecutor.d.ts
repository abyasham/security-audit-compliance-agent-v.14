import { TsharkRunner } from './tsharkRunner';
import { ToolCall, ToolResult } from '../types';
/**
 * ToolExecutor — handles LLM tool calls during analysis.
 *
 * Manages the tool loop: LLM calls tool → executor runs it → result goes back to LLM.
 * Max 25 rounds per turn to prevent infinite loops.
 */
export declare class ToolExecutor {
    private tshark;
    private store;
    private static readonly MAX_ROUNDS;
    constructor(tshark: TsharkRunner);
    /**
     * Get tool definitions in OpenAI-compatible format.
     * captureFileId is optional — defaults to the first capture in the session.
     */
    getToolDefinitions(): any[];
    /**
     * Resolve the capture file path from args or session.
     */
    private resolveCaptureFile;
    /**
     * Execute a single tool call.
     */
    executeTool(toolCall: ToolCall, sessionId: string): Promise<ToolResult>;
    getMaxRounds(): number;
}
//# sourceMappingURL=toolExecutor.d.ts.map