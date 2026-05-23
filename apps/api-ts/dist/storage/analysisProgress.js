"use strict";
/**
 * AnalysisProgress — In-memory progress tracking for multi-agent analysis.
 *
 * Tracks each stage: policy → network → judge
 * so the frontend can poll for progress updates.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.analysisProgressStore = void 0;
class AnalysisProgressStore {
    progress = new Map();
    start(sessionId) {
        const progress = {
            sessionId,
            overallStatus: 'running',
            stages: [
                { name: 'policy', status: 'pending' },
                { name: 'network', status: 'pending' },
                { name: 'judge', status: 'pending' },
            ],
            startedAt: new Date().toISOString(),
        };
        this.progress.set(sessionId, progress);
        return progress;
    }
    get(sessionId) {
        return this.progress.get(sessionId);
    }
    setStageRunning(sessionId, stageName) {
        const p = this.progress.get(sessionId);
        if (!p)
            return;
        const stage = p.stages.find(s => s.name === stageName);
        if (stage) {
            stage.status = 'running';
            stage.startedAt = new Date().toISOString();
        }
    }
    setStageCompleted(sessionId, stageName, result) {
        const p = this.progress.get(sessionId);
        if (!p)
            return;
        const stage = p.stages.find(s => s.name === stageName);
        if (stage) {
            stage.status = 'completed';
            stage.completedAt = new Date().toISOString();
            stage.result = result;
        }
    }
    setStageFailed(sessionId, stageName, error) {
        const p = this.progress.get(sessionId);
        if (!p)
            return;
        const stage = p.stages.find(s => s.name === stageName);
        if (stage) {
            stage.status = 'failed';
            stage.completedAt = new Date().toISOString();
            stage.error = error;
        }
        p.overallStatus = 'failed';
        p.error = error;
    }
    setCompleted(sessionId, finalResult) {
        const p = this.progress.get(sessionId);
        if (!p)
            return;
        p.overallStatus = 'completed';
        p.completedAt = new Date().toISOString();
        p.finalResult = finalResult;
    }
    setFailed(sessionId, error) {
        const p = this.progress.get(sessionId);
        if (!p)
            return;
        p.overallStatus = 'failed';
        p.error = error;
        p.completedAt = new Date().toISOString();
    }
    clear(sessionId) {
        this.progress.delete(sessionId);
    }
}
exports.analysisProgressStore = new AnalysisProgressStore();
//# sourceMappingURL=analysisProgress.js.map