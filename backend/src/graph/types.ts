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

export type EdgeType = 
  | 'connects'        // IP → IP (a conversation/connection)
  | 'uses_port'       // IP → Port or Stream → Port
  | 'uses_protocol'   // Stream → Protocol
  | 'belongs_to'      // Packet → Stream
  | 'has_packet'      // Stream → Packet
  | 'resolves'        // Host → IP
  | 'initiates'       // IP → Stream (who started it)
  | 'has_tls'         // Stream → TLS
  | 'violates'        // Stream|Packet → PolicyRule
  ;

export interface GraphEdge {
  id: string;
  type: EdgeType;
  source: string;     // node id
  target: string;     // node id
  properties: Record<string, any>;
}

export interface TrafficGraph {
  nodes: Map<string, GraphNode>;
  edges: Map<string, GraphEdge>;
  // Indexes for fast lookup
  nodeIndexByType: Map<NodeType, Set<string>>;
  edgeIndexBySource: Map<string, Set<string>>;
  edgeIndexByTarget: Map<string, Set<string>>;
  edgeIndexByType: Map<EdgeType, Set<string>>;
}

export interface GraphQueryResult {
  nodes: GraphNode[];
  edges: GraphEdge[];
  paths: GraphNode[][];  // For path queries
}

export interface GraphQuery {
  // Simple query DSL (Cypher-like but lightweight)
  startNode?: { type?: NodeType; properties?: Record<string, any> };
  edgeType?: EdgeType;
  endNode?: { type?: NodeType; properties?: Record<string, any> };
  direction?: 'out' | 'in' | 'both';
  limit?: number;
  // Path query: find paths between two nodes
  pathFrom?: { type?: NodeType; properties?: Record<string, any> };
  pathTo?: { type?: NodeType; properties?: Record<string, any> };
  maxHops?: number;
}

export interface GraphStats {
  nodeCount: number;
  edgeCount: number;
  nodeCountsByType: Record<NodeType, number>;
  edgeCountsByType: Record<string, number>;
  topTalkers: { ip: string; packetCount: number; byteCount: number }[];
  protocolBreakdown: Record<string, number>;
}
