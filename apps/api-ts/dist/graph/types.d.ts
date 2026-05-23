/**
 * LightRAG Graph Types for SACA
 *
 * Network traffic represented as a property graph:
 * - Nodes: IP, Port, Protocol, Stream, Host, Packet
 * - Edges: CONNECTS, USES_PORT, USES_PROTOCOL, BELONGS_TO, RESOLVES
 */
export type NodeType = 'ip' | 'port' | 'protocol' | 'stream' | 'host' | 'packet' | 'tls';
export interface GraphNode {
    id: string;
    type: NodeType;
    properties: Record<string, any>;
}
export type EdgeType = 'connects' | 'uses_port' | 'uses_protocol' | 'belongs_to' | 'has_packet' | 'resolves' | 'initiates' | 'has_tls' | 'violates';
export interface GraphEdge {
    id: string;
    type: EdgeType;
    source: string;
    target: string;
    properties: Record<string, any>;
}
export interface TrafficGraph {
    nodes: Map<string, GraphNode>;
    edges: Map<string, GraphEdge>;
    nodeIndexByType: Map<NodeType, Set<string>>;
    edgeIndexBySource: Map<string, Set<string>>;
    edgeIndexByTarget: Map<string, Set<string>>;
    edgeIndexByType: Map<EdgeType, Set<string>>;
}
export interface GraphQueryResult {
    nodes: GraphNode[];
    edges: GraphEdge[];
    paths: GraphNode[][];
}
export interface GraphQuery {
    startNode?: {
        type?: NodeType;
        properties?: Record<string, any>;
    };
    edgeType?: EdgeType;
    endNode?: {
        type?: NodeType;
        properties?: Record<string, any>;
    };
    direction?: 'out' | 'in' | 'both';
    limit?: number;
    pathFrom?: {
        type?: NodeType;
        properties?: Record<string, any>;
    };
    pathTo?: {
        type?: NodeType;
        properties?: Record<string, any>;
    };
    maxHops?: number;
}
export interface GraphStats {
    nodeCount: number;
    edgeCount: number;
    nodeCountsByType: Record<NodeType, number>;
    edgeCountsByType: Record<string, number>;
    topTalkers: {
        ip: string;
        packetCount: number;
        byteCount: number;
    }[];
    protocolBreakdown: Record<string, number>;
}
//# sourceMappingURL=types.d.ts.map