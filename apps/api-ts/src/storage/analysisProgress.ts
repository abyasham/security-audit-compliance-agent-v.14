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

class AnalysisProgressStore {
  private progress = new Map<string, AnalysisProgress>();

  start(sessionId: string): AnalysisProgress {
    const progress: AnalysisProgress = {
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

  get(sessionId: string): AnalysisProgress | undefined {
    return this.progress.get(sessionId);
  }

  setStageRunning(sessionId: string, stageName: string) {
    const p = this.progress.get(sessionId);
    if (!p) return;
    const stage = p.stages.find(s => s.name === stageName);
    if (stage) {
      stage.status = 'running';
      stage.startedAt = new Date().toISOString();
    }
  }

  setStageCompleted(sessionId: string, stageName: string, result?: any) {
    const p = this.progress.get(sessionId);
    if (!p) return;
    const stage = p.stages.find(s => s.name === stageName);
    if (stage) {
      stage.status = 'completed';
      stage.completedAt = new Date().toISOString();
      stage.result = result;
    }
  }

  setStageFailed(sessionId: string, stageName: string, error: string) {
    const p = this.progress.get(sessionId);
    if (!p) return;
    const stage = p.stages.find(s => s.name === stageName);
    if (stage) {
      stage.status = 'failed';
      stage.completedAt = new Date().toISOString();
      stage.error = error;
    }
    p.overallStatus = 'failed';
    p.error = error;
  }

  setCompleted(sessionId: string, finalResult: any) {
    const p = this.progress.get(sessionId);
    if (!p) return;
    p.overallStatus = 'completed';
    p.completedAt = new Date().toISOString();
    p.finalResult = finalResult;
  }

  setFailed(sessionId: string, error: string) {
    const p = this.progress.get(sessionId);
    if (!p) return;
    p.overallStatus = 'failed';
    p.error = error;
    p.completedAt = new Date().toISOString();
  }

  clear(sessionId: string) {
    this.progress.delete(sessionId);
  }
}

export const analysisProgressStore = new AnalysisProgressStore();
