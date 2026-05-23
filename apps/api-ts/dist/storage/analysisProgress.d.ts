/**
 * AnalysisProgress — In-memory progress tracking for multi-agent analysis.
 *
 * Tracks each stage: policy → network → judge
 * so the frontend can poll for progress updates.
 */
export interface AnalysisStage {
    name: string;
    status: 'pending' | 'running' | 'completed' | 'failed';
    startedAt?: string;
    completedAt?: string;
    error?: string;
    result?: any;
}
export interface AnalysisProgress {
    sessionId: string;
    overallStatus: 'idle' | 'running' | 'completed' | 'failed';
    stages: AnalysisStage[];
    startedAt: string;
    completedAt?: string;
    error?: string;
    finalResult?: any;
}
declare class AnalysisProgressStore {
    private progress;
    start(sessionId: string): AnalysisProgress;
    get(sessionId: string): AnalysisProgress | undefined;
    setStageRunning(sessionId: string, stageName: string): void;
    setStageCompleted(sessionId: string, stageName: string, result?: any): void;
    setStageFailed(sessionId: string, stageName: string, error: string): void;
    setCompleted(sessionId: string, finalResult: any): void;
    setFailed(sessionId: string, error: string): void;
    clear(sessionId: string): void;
}
export declare const analysisProgressStore: AnalysisProgressStore;
export {};
//# sourceMappingURL=analysisProgress.d.ts.map