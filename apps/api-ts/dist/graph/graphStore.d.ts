import { GraphNode, GraphEdge, NodeType, EdgeType, GraphStats, GraphQuery, GraphQueryResult } from './types';
/**
 * GraphStore — In-memory property graph with indexes.
 *
 * LightRAG-style: no external DB needed. Pure TypeScript Map-based storage.
 * Persists to JSON for session recovery.
 */
export declare class GraphStore {
    private graph;
    constructor();
    /** Add or update a node */
    addNode(node: GraphNode): void;
    /** Add an edge (undirected for CONNECTS, directed for others) */
    addEdge(edge: GraphEdge): void;
    /** Get node by ID */
    getNode(id: string): GraphNode | undefined;
    /** Get edge by ID */
    getEdge(id: string): GraphEdge | undefined;
    /** Get all edges from a node (outgoing + incoming) */
    getEdgesForNode(nodeId: string): GraphEdge[];
    /** Get outgoing edges from a node */
    getOutgoingEdges(nodeId: string, type?: EdgeType): GraphEdge[];
    /** Get incoming edges to a node */
    getIncomingEdges(nodeId: string, type?: EdgeType): GraphEdge[];
    /** Get all nodes of a type */
    getNodesByType(type: NodeType): GraphNode[];
    /** Get all edges of a type */
    getEdgesByType(type: EdgeType): GraphEdge[];
    /**
     * Query the graph using a simple filter-based DSL.
     * Supports: node type filtering, property matching, edge traversal, path finding.
     */
    query(q: GraphQuery): GraphQueryResult;
    /** Find all paths between two node patterns (BFS, limited hops) */
    private findPaths;
    /** Find an edge between two nodes */
    private findEdgeBetween;
    /** Match nodes against a pattern */
    private matchNodes;
    /** Check if a node matches a pattern */
    private matchesNode;
    /** Get graph statistics */
    getStats(): GraphStats;
    /** Export to JSON for persistence */
    toJSON(): object;
    /** Import from JSON */
    static fromJSON(data: {
        nodes: GraphNode[];
        edges: GraphEdge[];
    }): GraphStore;
    /** Clear all data */
    clear(): void;
}
//# sourceMappingURL=graphStore.d.ts.map