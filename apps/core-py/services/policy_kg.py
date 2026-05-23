"""
PolicyKnowledgeGraph — lightweight knowledge graph from policy text using NetworkX.

Builds clause nodes with edges (sequence, section, keyword) and retrieves
high-signal clause neighborhoods for LLM extraction context.

Port of backend/src/services/policyKnowledgeGraph.ts
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set

import networkx as nx


class PolicyKnowledgeGraph:
    """Builds a lightweight graph from policy text."""

    STOPWORDS: Set[str] = {
        "the", "a", "an", "and", "or", "to", "of", "in", "on", "for", "with",
        "is", "are", "be", "this", "that", "these", "those", "by", "as", "at",
        "from", "it", "its", "their", "there", "will", "can", "may", "should",
        "could", "would", "than", "then", "into", "such", "any", "all", "not",
        "no", "do", "does", "did", "if", "when", "while", "where", "who",
        "which", "have", "has", "had", "must", "shall", "required", "requirement",
    }

    CLAUSE_CANDIDATE_RE = re.compile(
        r"(\bshall\b|\bmust\b|\brequired\b|\bmandatory\b|"
        r"\bmust not\b|\bprohibited\b|\bshould\b|\bcontrol\b|"
        r"\bclause\b|\bsection\b)",
        re.IGNORECASE,
    )

    SECTION_ID_RE = re.compile(
        r"(?:clause|section|provision|control)?\s*(\d+(?:\.\d+)+|[A-Z]-\d+(?:\.\d+)*)",
        re.IGNORECASE,
    )

    def __init__(self) -> None:
        self.graph = nx.Graph()
        self.nodes: Dict[str, dict] = {}

    @classmethod
    def from_policy_text(cls, raw_text: str) -> "PolicyKnowledgeGraph":
        graph = cls()
        graph._build(raw_text)
        return graph

    # ── Public API ─────────────────────────────────────────────────────

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    def retrieve_clause_context(self, query_keywords: List[str], max_nodes: int = 80) -> str:
        """Return relevant clause text for LLM extraction context."""
        seeds = self._rank_seed_nodes(query_keywords)[: max(max_nodes // 2, 10)]
        selected: Set[str] = set()

        for seed in seeds:
            selected.add(seed["id"])
            for neighbor in self._get_top_neighbors(seed["id"], hops=2):
                if len(selected) >= max_nodes:
                    break
                selected.add(neighbor)
            if len(selected) >= max_nodes:
                break

        clauses = sorted(
            [self.nodes[nid] for nid in selected if nid in self.nodes],
            key=lambda n: n["line"],
        )

        lines: list[str] = []
        for n in clauses:
            section = f" [Section {n['section']}]" if n.get("section") else ""
            lines.append(f"L{n['line']}{section}: {n['text']}")
        return "\n".join(lines)

    # ── Build ───────────────────────────────────────────────────────────

    def _build(self, raw_text: str) -> None:
        lines = [
            {"text": line.strip(), "line": idx + 1}
            for idx, line in enumerate(raw_text.replace("\r", "\n").split("\n"))
        ]
        lines = [l for l in lines if len(l["text"]) >= 20]

        # Extract clause candidates
        candidates = [l for l in lines if self.CLAUSE_CANDIDATE_RE.search(l["text"])]

        for c in candidates:
            node_id = f"c:{c['line']}"
            section = self._extract_section_id(c["text"])
            keywords = self._extract_keywords(c["text"])
            node = {
                "id": node_id,
                "text": c["text"],
                "line": c["line"],
                "section": section,
                "keywords": keywords,
                "normative_score": self._normative_score(c["text"]),
            }
            self.nodes[node_id] = node
            self.graph.add_node(node_id, **node)

        ordered = sorted(self.nodes.values(), key=lambda n: n["line"])

        # Sequence edges
        for i in range(len(ordered) - 1):
            self._add_undirected_edge(
                ordered[i]["id"], ordered[i + 1]["id"], "sequence", 0.5
            )

        # Section edges
        by_section: Dict[str, list] = {}
        for node in ordered:
            sec = node.get("section")
            if not sec:
                continue
            by_section.setdefault(sec, []).append(node)

        for group in by_section.values():
            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    self._add_undirected_edge(
                        group[i]["id"], group[j]["id"], "section", 0.9
                    )

        # Keyword edges
        for i in range(len(ordered)):
            kw_i = set(ordered[i]["keywords"])
            for j in range(i + 1, len(ordered)):
                kw_j = set(ordered[j]["keywords"])
                overlap = len(kw_i & kw_j)
                if overlap >= 2:
                    weight = min(1.5, 0.4 + overlap * 0.2)
                    self._add_undirected_edge(
                        ordered[i]["id"], ordered[j]["id"], "keyword", weight
                    )

    def _extract_section_id(self, text: str) -> Optional[str]:
        m = self.SECTION_ID_RE.search(text)
        return m.group(1) if m else None

    def _normative_score(self, text: str) -> int:
        score = 0
        if re.search(r"\bmust not\b|\bprohibited\b", text, re.IGNORECASE):
            score += 3
        if re.search(r"\bmust\b|\bshall\b|\brequired\b|\bmandatory\b", text, re.IGNORECASE):
            score += 2
        if re.search(r"\bshould\b", text, re.IGNORECASE):
            score += 1
        if re.search(
            r"\bsecurity\b|\bencrypt\b|\bauth\b|\baccess\b|\bintegrity\b|\bconfidentiality\b",
            text,
            re.IGNORECASE,
        ):
            score += 1
        return score

    def _extract_keywords(self, text: str) -> List[str]:
        tokens = re.sub(r"[^a-z0-9\s-]", " ", text.lower()).split()
        tokens = [t.strip() for t in tokens if len(t) >= 3 and t not in self.STOPWORDS]
        return list(dict.fromkeys(tokens))[:24]

    def _add_undirected_edge(
        self, src: str, dst: str, etype: str, weight: float
    ) -> None:
        self.graph.add_edge(src, dst, type=etype, weight=weight)

    # ── Query ───────────────────────────────────────────────────────────

    def _rank_seed_nodes(self, query_keywords: List[str]) -> list:
        q = {k.lower() for k in query_keywords}
        scored = [
            {
                **node,
                "score": node["normative_score"]
                + len(q & set(node["keywords"])) * 1.2,
            }
            for node in self.nodes.values()
        ]
        return sorted(scored, key=lambda n: (-n["score"], n["line"]))

    def _get_top_neighbors(self, node_id: str, hops: int = 2) -> List[str]:
        """BFS from node_id up to `hops` away, sorted by edge weight."""
        seen: Set[str] = {node_id}
        frontier = [(node_id, 0.0)]
        result: List[str] = []

        for _ in range(hops):
            if not frontier:
                break
            next_frontier = []
            for current, score in frontier:
                for neighbor in self.graph.neighbors(current):
                    if neighbor in seen:
                        continue
                    seen.add(neighbor)
                    edge_weight = self.graph[current][neighbor].get("weight", 0.5)
                    next_frontier.append((neighbor, score + edge_weight))
                    result.append(neighbor)
            frontier = sorted(next_frontier, key=lambda x: -x[1])[:6]

        return result
