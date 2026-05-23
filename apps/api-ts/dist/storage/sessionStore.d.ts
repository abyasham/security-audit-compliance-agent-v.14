import { Session } from '../types';
/**
 * In-memory session store with periodical persistence to disk.
 * For a prototype, this keeps things simple while supporting
 * future migration to SQLite (sql.js) when needed.
 */
import { GraphStore } from '../graph/graphStore';
export declare class SessionStore {
    private static instance;
    private sessions;
    private graphs;
    private constructor();
    static getInstance(): SessionStore;
    createSession(session: Session): void;
    getSession(id: string): Session | undefined;
    updateSession(session: Session): void;
    deleteSession(id: string): boolean;
    getAllSessions(): Session[];
    /** Clean up sessions older than the specified age in hours */
    cleanupStaleSessions(maxAgeHours?: number): void;
    setGraph(sessionId: string, graph: GraphStore): void;
    getGraph(sessionId: string): GraphStore | undefined;
    hasGraph(sessionId: string): boolean;
    deleteGraph(sessionId: string): boolean;
    /** Clear all sessions and graphs — full memory reset */
    clearAll(): {
        sessionsCleared: number;
        graphsCleared: number;
    };
}
//# sourceMappingURL=sessionStore.d.ts.map