import { Session } from '../types';

/**
 * In-memory session store with periodical persistence to disk.
 * For a prototype, this keeps things simple while supporting
 * future migration to SQLite (sql.js) when needed.
 */
import { GraphStore } from '../graph/graphStore';

export class SessionStore {
  private static instance: SessionStore;
  private sessions = new Map<string, Session>();
  private graphs = new Map<string, GraphStore>(); // sessionId -> GraphStore

  private constructor() {}

  static getInstance(): SessionStore {
    if (!SessionStore.instance) {
      SessionStore.instance = new SessionStore();
    }
    return SessionStore.instance;
  }

  createSession(session: Session): void {
    this.sessions.set(session.id, session);
  }

  getSession(id: string): Session | undefined {
    return this.sessions.get(id);
  }

  updateSession(session: Session): void {
    this.sessions.set(session.id, session);
  }

  deleteSession(id: string): boolean {
    return this.sessions.delete(id);
  }

  getAllSessions(): Session[] {
    return Array.from(this.sessions.values());
  }

  /** Clean up sessions older than the specified age in hours */
  cleanupStaleSessions(maxAgeHours: number = 24): void {
    const cutoff = Date.now() - (maxAgeHours * 60 * 60 * 1000);
    for (const [id, session] of this.sessions) {
      if (new Date(session.updatedAt).getTime() < cutoff) {
        this.sessions.delete(id);
        this.graphs.delete(id);
      }
    }
  }

  // ─── Graph Storage ─────────────────────────────────────────────────────

  setGraph(sessionId: string, graph: GraphStore): void {
    this.graphs.set(sessionId, graph);
  }

  getGraph(sessionId: string): GraphStore | undefined {
    return this.graphs.get(sessionId);
  }

  hasGraph(sessionId: string): boolean {
    return this.graphs.has(sessionId);
  }

  deleteGraph(sessionId: string): boolean {
    return this.graphs.delete(sessionId);
  }

  /** Clear all sessions and graphs — full memory reset */
  clearAll(): { sessionsCleared: number; graphsCleared: number } {
    const sessionsCleared = this.sessions.size;
    const graphsCleared = this.graphs.size;
    this.sessions.clear();
    this.graphs.clear();
    return { sessionsCleared, graphsCleared };
  }
}
