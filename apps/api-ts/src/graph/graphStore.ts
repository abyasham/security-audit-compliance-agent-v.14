import { GraphNode, GraphEdge, TrafficGraph, NodeType, EdgeType, GraphStats, GraphQuery, GraphQueryResult } from './types';

/**
 * GraphStore — In-memory property graph with indexes.
 * 
 * LightRAG-style: no external DB needed. Pure TypeScript Map-based storage.
 * Persists to JSON for session recovery.
 */
export class GraphStore {
  private graph: TrafficGraph;

  constructor() {
    this.graph = {
      nodes: new Map(),
      edges: new Map(),
      nodeIndexByType: new Map(),
      edgeIndexBySource: new Map(),
      edgeIndexByTarget: new Map(),
      edgeIndexByType: new Map(),
    };
  }

  /** Add or update a node */
  addNode(node: GraphNode): void {
    this.graph.nodes.set(node.id, node);
    // Index by type
    if (!this.graph.nodeIndexByType.has(node.type)) {
      this.graph.nodeIndexByType.set(node.type, new Set());
    }
    this.graph.nodeIndexByType.get(node.type)!.add(node.id);
  }

  /** Add an edge (undirected for CONNECTS, directed for others) */
  addEdge(edge: GraphEdge): void {
    this.graph.edges.set(edge.id, edge);
    // Source index
    if (!this.graph.edgeIndexBySource.has(edge.source)) {
      this.graph.edgeIndexBySource.set(edge.source, new Set());
    }
    this.graph.edgeIndexBySource.get(edge.source)!.add(edge.id);
    // Target index
    if (!this.graph.edgeIndexByTarget.has(edge.target)) {
      this.graph.edgeIndexByTarget.set(edge.target, new Set());
    }
    this.graph.edgeIndexByTarget.get(edge.target)!.add(edge.id);
    // Type index
    if (!this.graph.edgeIndexByType.has(edge.type)) {
      this.graph.edgeIndexByType.set(edge.type, new Set());
    }
    this.graph.edgeIndexByType.get(edge.type)!.add(edge.id);
  }

  /** Get node by ID */
  getNode(id: string): GraphNode | undefined {
    return this.graph.nodes.get(id);
  }

  /** Get edge by ID */
  getEdge(id: string): GraphEdge | undefined {
    return this.graph.edges.get(id);
  }

  /** Get all edges from a node (outgoing + incoming) */
  getEdgesForNode(nodeId: string): GraphEdge[] {
    const out = this.graph.edgeIndexBySource.get(nodeId) || new Set();
    const inc = this.graph.edgeIndexByTarget.get(nodeId) || new Set();
    const all = new Set([...out, ...inc]);
    return Array.from(all).map(id => this.graph.edges.get(id)!).filter(Boolean);
  }

  /** Get outgoing edges from a node */
  getOutgoingEdges(nodeId: string, type?: EdgeType): GraphEdge[] {
    const ids = this.graph.edgeIndexBySource.get(nodeId) || new Set();
    return Array.from(ids)
      .map(id => this.graph.edges.get(id)!)
      .filter(e => !type || e.type === type);
  }

  /** Get incoming edges to a node */
  getIncomingEdges(nodeId: string, type?: EdgeType): GraphEdge[] {
    const ids = this.graph.edgeIndexByTarget.get(nodeId) || new Set();
    return Array.from(ids)
      .map(id => this.graph.edges.get(id)!)
      .filter(e => !type || e.type === type);
  }

  /** Get all nodes of a type */
  getNodesByType(type: NodeType): GraphNode[] {
    const ids = this.graph.nodeIndexByType.get(type) || new Set();
    return Array.from(ids).map(id => this.graph.nodes.get(id)!).filter(Boolean);
  }

  /** Get all edges of a type */
  getEdgesByType(type: EdgeType): GraphEdge[] {
    const ids = this.graph.edgeIndexByType.get(type) || new Set();
    return Array.from(ids).map(id => this.graph.edges.get(id)!).filter(Boolean);
  }

  /**
   * Query the graph using a simple filter-based DSL.
   * Supports: node type filtering, property matching, edge traversal, path finding.
   */
  query(q: GraphQuery): GraphQueryResult {
    const result: GraphQueryResult = { nodes: [], edges: [], paths: [] };

    // Path query: find paths between two node patterns
    if (q.pathFrom && q.pathTo) {
      result.paths = this.findPaths(q.pathFrom, q.pathTo, q.maxHops || 4);
      // Flatten paths into nodes/edges for easy consumption
      const nodeIds = new Set<string>();
      const edgeIds = new Set<string>();
      for (const path of result.paths) {
        for (let i = 0; i < path.length; i++) {
          nodeIds.add(path[i].id);
          if (i < path.length - 1) {
            // Find the edge connecting these two nodes
            const e = this.findEdgeBetween(path[i].id, path[i + 1].id);
            if (e) edgeIds.add(e.id);
          }
        }
      }
      result.nodes = Array.from(nodeIds).map(id => this.graph.nodes.get(id)!).filter(Boolean);
      result.edges = Array.from(edgeIds).map(id => this.graph.edges.get(id)!).filter(Boolean);
      return result;
    }

    // Simple traversal query: start node → edge type → end node
    if (q.startNode) {
      let startNodes = this.matchNodes(q.startNode);
      for (const start of startNodes) {
        const edges = q.direction === 'in'
          ? this.getIncomingEdges(start.id, q.edgeType)
          : q.direction === 'out'
            ? this.getOutgoingEdges(start.id, q.edgeType)
            : this.getEdgesForNode(start.id).filter(e => !q.edgeType || e.type === q.edgeType);

        for (const edge of edges) {
          const otherId = edge.source === start.id ? edge.target : edge.source;
          const other = this.graph.nodes.get(otherId);
          if (!other) continue;
          if (q.endNode && !this.matchesNode(other, q.endNode)) continue;
          
          result.nodes.push(start, other);
          result.edges.push(edge);
        }
      }
    }

    // Deduplicate
    const nodeIds = new Set(result.nodes.map(n => n.id));
    const edgeIds = new Set(result.edges.map(e => e.id));
    result.nodes = Array.from(nodeIds).map(id => this.graph.nodes.get(id)!).filter(Boolean);
    result.edges = Array.from(edgeIds).map(id => this.graph.edges.get(id)!).filter(Boolean);

    if (q.limit) {
      result.nodes = result.nodes.slice(0, q.limit);
      result.edges = result.edges.slice(0, q.limit);
    }

    return result;
  }

  /** Find all paths between two node patterns (BFS, limited hops) */
  private findPaths(
    from: { type?: NodeType; properties?: Record<string, any> },
    to: { type?: NodeType; properties?: Record<string, any> },
    maxHops: number
  ): GraphNode[][] {
    const startNodes = this.matchNodes(from);
    const endNodes = this.matchNodes(to);
    const endIds = new Set(endNodes.map(n => n.id));
    const paths: GraphNode[][] = [];

    for (const start of startNodes) {
      const visited = new Set<string>();
      const queue: { node: GraphNode; path: GraphNode[] }[] = [{ node: start, path: [start] }];
      
      while (queue.length > 0) {
        const { node, path } = queue.shift()!;
        if (path.length > maxHops + 1) continue;
        
        if (endIds.has(node.id) && path.length > 1) {
          paths.push([...path]);
          if (paths.length >= 10) return paths; // Limit results
          continue;
        }
        
        visited.add(node.id);
        const edges = this.getEdgesForNode(node.id);
        for (const edge of edges) {
          const nextId = edge.source === node.id ? edge.target : edge.source;
          if (visited.has(nextId)) continue;
          const next = this.graph.nodes.get(nextId);
          if (!next) continue;
          queue.push({ node: next, path: [...path, next] });
        }
      }
    }
    return paths;
  }

  /** Find an edge between two nodes */
  private findEdgeBetween(a: string, b: string): GraphEdge | undefined {
    const out = this.getOutgoingEdges(a);
    return out.find(e => e.target === b || e.source === b);
  }

  /** Match nodes against a pattern */
  private matchNodes(pattern: { type?: NodeType; properties?: Record<string, any> }): GraphNode[] {
    let candidates: GraphNode[];
    if (pattern.type) {
      candidates = this.getNodesByType(pattern.type);
    } else {
      candidates = Array.from(this.graph.nodes.values());
    }
    if (!pattern.properties) return candidates;
    return candidates.filter(n => this.matchesNode(n, pattern));
  }

  /** Check if a node matches a pattern */
  private matchesNode(node: GraphNode, pattern: { type?: NodeType; properties?: Record<string, any> }): boolean {
    if (pattern.type && node.type !== pattern.type) return false;
    if (pattern.properties) {
      for (const [key, val] of Object.entries(pattern.properties)) {
        if (node.properties[key] !== val) return false;
      }
    }
    return true;
  }

  /** Get graph statistics */
  getStats(): GraphStats {
    const nodeCountsByType: Record<string, number> = {};
    const edgeCountsByType: Record<string, number> = {};
    const talkers = new Map<string, { packetCount: number; byteCount: number }>();
    const protocols = new Map<string, number>();

    for (const [type, ids] of this.graph.nodeIndexByType) {
      nodeCountsByType[type] = ids.size;
    }
    for (const [type, ids] of this.graph.edgeIndexByType) {
      edgeCountsByType[type] = ids.size;
    }

    // Count packets per IP
    for (const edge of this.getEdgesByType('connects')) {
      const src = edge.source;
      const existing = talkers.get(src) || { packetCount: 0, byteCount: 0 };
      existing.packetCount += edge.properties.packetCount || 0;
      existing.byteCount += edge.properties.byteCount || 0;
      talkers.set(src, existing);
    }

    // Protocol breakdown
    for (const edge of this.getEdgesByType('uses_protocol')) {
      const proto = this.graph.nodes.get(edge.target);
      if (proto) {
        const name = proto.properties.name || 'unknown';
        protocols.set(name, (protocols.get(name) || 0) + 1);
      }
    }

    const topTalkers = Array.from(talkers.entries())
      .map(([ip, stats]) => ({ ip, ...stats }))
      .sort((a, b) => b.byteCount - a.byteCount)
      .slice(0, 10);

    return {
      nodeCount: this.graph.nodes.size,
      edgeCount: this.graph.edges.size,
      nodeCountsByType: nodeCountsByType as any,
      edgeCountsByType,
      topTalkers,
      protocolBreakdown: Object.fromEntries(protocols),
    };
  }

  /** Export to JSON for persistence */
  toJSON(): object {
    return {
      nodes: Array.from(this.graph.nodes.values()),
      edges: Array.from(this.graph.edges.values()),
    };
  }

  /** Import from JSON */
  static fromJSON(data: { nodes: GraphNode[]; edges: GraphEdge[] }): GraphStore {
    const store = new GraphStore();
    for (const node of data.nodes) store.addNode(node);
    for (const edge of data.edges) store.addEdge(edge);
    return store;
  }

  /** Clear all data */
  clear(): void {
    this.graph.nodes.clear();
    this.graph.edges.clear();
    this.graph.nodeIndexByType.clear();
    this.graph.edgeIndexBySource.clear();
    this.graph.edgeIndexByTarget.clear();
    this.graph.edgeIndexByType.clear();
  }
}
