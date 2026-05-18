type PolicyEdgeType = 'sequence' | 'section' | 'keyword';

interface PolicyClauseNode {
  id: string;
  text: string;
  line: number;
  section?: string;
  keywords: string[];
  normativeScore: number;
}

interface PolicyEdge {
  from: string;
  to: string;
  type: PolicyEdgeType;
  weight: number;
}

/**
 * PolicyKnowledgeGraph
 *
 * Builds a lightweight graph from policy text and retrieves high-signal
 * clause neighborhoods for LLM extraction context.
 */
export class PolicyKnowledgeGraph {
  private nodes = new Map<string, PolicyClauseNode>();
  private edgesByNode = new Map<string, PolicyEdge[]>();

  private static readonly STOPWORDS = new Set([
    'the', 'a', 'an', 'and', 'or', 'to', 'of', 'in', 'on', 'for', 'with', 'is', 'are', 'be',
    'this', 'that', 'these', 'those', 'by', 'as', 'at', 'from', 'it', 'its', 'their', 'there',
    'will', 'can', 'may', 'should', 'could', 'would', 'than', 'then', 'into', 'such', 'any',
    'all', 'not', 'no', 'do', 'does', 'did', 'if', 'when', 'while', 'where', 'who', 'which',
    'have', 'has', 'had', 'must', 'shall', 'required', 'requirement',
  ]);

  static fromPolicyText(rawText: string): PolicyKnowledgeGraph {
    const graph = new PolicyKnowledgeGraph();
    graph.build(rawText);
    return graph;
  }

  getNodeCount(): number {
    return this.nodes.size;
  }

  retrieveClauseContext(queryKeywords: string[], maxNodes: number = 80): string {
    const seeds = this.rankSeedNodes(queryKeywords).slice(0, Math.max(10, Math.floor(maxNodes / 2)));
    const selected = new Set<string>();

    for (const seed of seeds) {
      selected.add(seed.id);
      const neighbors = this.getTopNeighbors(seed.id, 2);
      for (const n of neighbors) {
        if (selected.size >= maxNodes) break;
        selected.add(n);
      }
      if (selected.size >= maxNodes) break;
    }

    const clauses = Array.from(selected)
      .map(id => this.nodes.get(id))
      .filter((n): n is PolicyClauseNode => !!n)
      .sort((a, b) => a.line - b.line)
      .map(n => {
        const section = n.section ? ` [Section ${n.section}]` : '';
        return `L${n.line}${section}: ${n.text}`;
      });

    return clauses.join('\n');
  }

  private build(rawText: string): void {
    const lines = rawText
      .replace(/\r/g, '\n')
      .split('\n')
      .map((l, idx) => ({ text: l.trim(), line: idx + 1 }))
      .filter(x => x.text.length >= 20);

    const candidates = lines.filter(x => this.isClauseCandidate(x.text));

    for (const c of candidates) {
      const id = `c:${c.line}`;
      const section = this.extractSectionId(c.text);
      const keywords = this.extractKeywords(c.text);
      const node: PolicyClauseNode = {
        id,
        text: c.text,
        line: c.line,
        section,
        keywords,
        normativeScore: this.getNormativeScore(c.text),
      };
      this.nodes.set(id, node);
      this.edgesByNode.set(id, []);
    }

    const ordered = Array.from(this.nodes.values()).sort((a, b) => a.line - b.line);

    // Sequence edges for locality context.
    for (let i = 0; i < ordered.length - 1; i++) {
      this.addUndirectedEdge(ordered[i].id, ordered[i + 1].id, 'sequence', 0.5);
    }

    // Section edges tie clauses under same numbered provision.
    const bySection = new Map<string, PolicyClauseNode[]>();
    for (const node of ordered) {
      if (!node.section) continue;
      const arr = bySection.get(node.section) || [];
      arr.push(node);
      bySection.set(node.section, arr);
    }
    for (const group of bySection.values()) {
      for (let i = 0; i < group.length; i++) {
        for (let j = i + 1; j < group.length; j++) {
          this.addUndirectedEdge(group[i].id, group[j].id, 'section', 0.9);
        }
      }
    }

    // Keyword edges for semantic linkage.
    for (let i = 0; i < ordered.length; i++) {
      for (let j = i + 1; j < ordered.length; j++) {
        const overlap = this.keywordOverlap(ordered[i].keywords, ordered[j].keywords);
        if (overlap >= 2) {
          this.addUndirectedEdge(ordered[i].id, ordered[j].id, 'keyword', Math.min(1.5, 0.4 + overlap * 0.2));
        }
      }
    }
  }

  private isClauseCandidate(text: string): boolean {
    return /(\bshall\b|\bmust\b|\brequired\b|\bmandatory\b|\bmust not\b|\bprohibited\b|\bshould\b|\bcontrol\b|\bclause\b|\bsection\b)/i.test(text);
  }

  private extractSectionId(text: string): string | undefined {
    const match = text.match(/(?:clause|section|provision|control)?\s*(\d+(?:\.\d+)+|[A-Z]-\d+(?:\.\d+)*)/i);
    return match?.[1];
  }

  private getNormativeScore(text: string): number {
    let score = 0;
    if (/\bmust not\b|\bprohibited\b/i.test(text)) score += 3;
    if (/\bmust\b|\bshall\b|\brequired\b|\bmandatory\b/i.test(text)) score += 2;
    if (/\bshould\b/i.test(text)) score += 1;
    if (/\bsecurity\b|\bencrypt\b|\bauth\b|\baccess\b|\bintegrity\b|\bconfidentiality\b/i.test(text)) score += 1;
    return score;
  }

  private extractKeywords(text: string): string[] {
    const tokens = text
      .toLowerCase()
      .replace(/[^a-z0-9\s-]/g, ' ')
      .split(/\s+/)
      .map(t => t.trim())
      .filter(t => t.length >= 3)
      .filter(t => !PolicyKnowledgeGraph.STOPWORDS.has(t));
    return Array.from(new Set(tokens)).slice(0, 24);
  }

  private keywordOverlap(a: string[], b: string[]): number {
    const setA = new Set(a);
    let overlap = 0;
    for (const k of b) {
      if (setA.has(k)) overlap++;
    }
    return overlap;
  }

  private addUndirectedEdge(from: string, to: string, type: PolicyEdgeType, weight: number): void {
    const a: PolicyEdge = { from, to, type, weight };
    const b: PolicyEdge = { from: to, to: from, type, weight };
    this.edgesByNode.get(from)?.push(a);
    this.edgesByNode.get(to)?.push(b);
  }

  private rankSeedNodes(queryKeywords: string[]): PolicyClauseNode[] {
    const q = new Set(queryKeywords.map(k => k.toLowerCase()));
    const scored = Array.from(this.nodes.values()).map(node => {
      let overlap = 0;
      for (const k of node.keywords) {
        if (q.has(k)) overlap++;
      }
      const score = node.normativeScore + overlap * 1.2;
      return { node, score };
    });

    return scored
      .sort((a, b) => b.score - a.score || a.node.line - b.node.line)
      .map(s => s.node);
  }

  private getTopNeighbors(nodeId: string, hops: number): string[] {
    const seen = new Set<string>([nodeId]);
    let frontier: Array<{ id: string; score: number }> = [{ id: nodeId, score: 0 }];

    for (let h = 0; h < hops; h++) {
      const next: Array<{ id: string; score: number }> = [];
      for (const item of frontier) {
        const edges = this.edgesByNode.get(item.id) || [];
        const ranked = [...edges].sort((a, b) => b.weight - a.weight).slice(0, 6);
        for (const e of ranked) {
          if (seen.has(e.to)) continue;
          seen.add(e.to);
          next.push({ id: e.to, score: item.score + e.weight });
        }
      }
      frontier = next;
      if (frontier.length === 0) break;
    }

    return Array.from(seen).filter(id => id !== nodeId);
  }
}
