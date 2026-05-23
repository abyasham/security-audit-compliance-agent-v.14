"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SessionStore = void 0;
class SessionStore {
    static instance;
    sessions = new Map();
    graphs = new Map(); // sessionId -> GraphStore
    constructor() { }
    static getInstance() {
        if (!SessionStore.instance) {
            SessionStore.instance = new SessionStore();
        }
        return SessionStore.instance;
    }
    createSession(session) {
        this.sessions.set(session.id, session);
    }
    getSession(id) {
        return this.sessions.get(id);
    }
    updateSession(session) {
        this.sessions.set(session.id, session);
    }
    deleteSession(id) {
        return this.sessions.delete(id);
    }
    getAllSessions() {
        return Array.from(this.sessions.values());
    }
    /** Clean up sessions older than the specified age in hours */
    cleanupStaleSessions(maxAgeHours = 24) {
        const cutoff = Date.now() - (maxAgeHours * 60 * 60 * 1000);
        for (const [id, session] of this.sessions) {
            if (new Date(session.updatedAt).getTime() < cutoff) {
                this.sessions.delete(id);
                this.graphs.delete(id);
            }
        }
    }
    // ─── Graph Storage ─────────────────────────────────────────────────────
    setGraph(sessionId, graph) {
        this.graphs.set(sessionId, graph);
    }
    getGraph(sessionId) {
        return this.graphs.get(sessionId);
    }
    hasGraph(sessionId) {
        return this.graphs.has(sessionId);
    }
    deleteGraph(sessionId) {
        return this.graphs.delete(sessionId);
    }
    /** Clear all sessions and graphs — full memory reset */
    clearAll() {
        const sessionsCleared = this.sessions.size;
        const graphsCleared = this.graphs.size;
        this.sessions.clear();
        this.graphs.clear();
        return { sessionsCleared, graphsCleared };
    }
}
exports.SessionStore = SessionStore;
//# sourceMappingURL=sessionStore.js.map