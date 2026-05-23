"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.graphRouter = void 0;
const express_1 = require("express");
const sharedTshark_1 = require("../services/sharedTshark");
const graphBuilder_1 = require("../graph/graphBuilder");
const sessionStore_1 = require("../storage/sessionStore");
exports.graphRouter = (0, express_1.Router)();
const sessionStore = sessionStore_1.SessionStore.getInstance();
// ─── Build Graph from PCAP ──────────────────────────────────────────────────
exports.graphRouter.post('/build', async (req, res) => {
    try {
        const { sessionId, filePath } = req.body;
        if (!sessionId)
            return res.status(400).json({ success: false, error: 'sessionId required' });
        if (!filePath)
            return res.status(400).json({ success: false, error: 'filePath required' });
        const builder = new graphBuilder_1.GraphBuilder(sharedTshark_1.tsharkRunner);
        const graph = await builder.buildFromPcap(filePath);
        sessionStore.setGraph(sessionId, graph);
        const stats = graph.getStats();
        res.json({
            success: true,
            data: {
                nodeCount: stats.nodeCount,
                edgeCount: stats.edgeCount,
                nodeCountsByType: stats.nodeCountsByType,
                edgeCountsByType: stats.edgeCountsByType,
                topTalkers: stats.topTalkers.slice(0, 5),
                protocolBreakdown: stats.protocolBreakdown,
            },
        });
    }
    catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});
// ─── Get Graph Stats ────────────────────────────────────────────────────────
exports.graphRouter.get('/stats/:sessionId', (req, res) => {
    const graph = sessionStore.getGraph(req.params.sessionId);
    if (!graph) {
        return res.status(404).json({ success: false, error: 'No graph found for this session' });
    }
    const stats = graph.getStats();
    res.json({ success: true, data: stats });
});
// ─── Query Graph ────────────────────────────────────────────────────────────
exports.graphRouter.post('/query', (req, res) => {
    const { sessionId, query } = req.body;
    if (!sessionId)
        return res.status(400).json({ success: false, error: 'sessionId required' });
    const graph = sessionStore.getGraph(sessionId);
    if (!graph) {
        return res.status(404).json({ success: false, error: 'No graph found for this session. Upload a pcap first.' });
    }
    try {
        const result = graph.query(query);
        res.json({
            success: true,
            data: {
                nodes: result.nodes.map(n => ({ id: n.id, type: n.type, properties: n.properties })),
                edges: result.edges.map(e => ({ id: e.id, type: e.type, source: e.source, target: e.target, properties: e.properties })),
                paths: result.paths.map(path => path.map(n => ({ id: n.id, type: n.type, properties: n.properties }))),
            },
        });
    }
    catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});
// ─── Get Node Neighbors ───────────────────────────────────────────────────
exports.graphRouter.get('/neighbors/:sessionId/:nodeId', (req, res) => {
    const { sessionId, nodeId } = req.params;
    const graph = sessionStore.getGraph(sessionId);
    if (!graph) {
        return res.status(404).json({ success: false, error: 'No graph found for this session' });
    }
    const edges = graph.getEdgesForNode(nodeId);
    const nodeIds = new Set();
    for (const e of edges) {
        nodeIds.add(e.source === nodeId ? e.target : e.source);
    }
    const nodes = Array.from(nodeIds).map(id => graph.getNode(id)).filter(Boolean);
    res.json({
        success: true,
        data: {
            centerNode: graph.getNode(nodeId),
            neighbors: nodes,
            edges,
        },
    });
});
//# sourceMappingURL=graph.js.map