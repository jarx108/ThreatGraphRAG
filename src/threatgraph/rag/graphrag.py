"""System B: ThreatGraph. Semantic chunk retrieval + Named Entity
Disambiguation + question-focused multi-hop graph traversal + GDS signals,
combined into one evidence-grounded, provenance-tracked context.

Pipeline:
  1. Vector search over Chunk embeddings (same call as System A).
  2. NED: entity mentions in the question ("Cozy Bear", "T1055", "Mimikatz")
     are linked to canonical graph nodes (threatgraph.entity_resolution).
  3. Question analysis: which entity type is being asked for ("which
     mitigations ..." -> Mitigation).
  4. Multi-hop traversal along the typed path from the linked entities to
     the asked-for type (graph.traversal.focused_facts), e.g. Software
     -USES-> Technique <-MITIGATES- Mitigation. Every fact keeps its edge
     provenance (STIX relationship id, source, last-modified, confidence).
     Unrecognized shapes fall back to a bounded neighbourhood expansion.
  5. GDS outputs (PageRank rank, Louvain community, mitigation coverage;
     see graph.analytics) are added as a quantitative section.
  6. The text + graph + analytics evidence is passed to the same generation
     prompt System A uses.
"""
from __future__ import annotations

import re
import time
from functools import lru_cache

from threatgraph.config import RETRIEVAL
from threatgraph.embeddings import Embedder, get_embedder
from threatgraph.entity_resolution import EntityResolver
from threatgraph.graph.neo4j_client import Neo4jClient
from threatgraph.graph.traversal import (
    bounded_neighborhood,
    focused_facts,
    graph_analytics_context,
    group_technique_mitigation_path,
    vector_search,
)
from threatgraph.rag.common import (
    GraphFact,
    RAGResult,
    RetrievedChunk,
    generate_answer,
    result_from_generation,
)
from threatgraph.rag.llm_provider import LLMProvider

# Words that name an entity type, in the order they are tried.
_TYPE_WORDS = [
    ("Mitigation", r"mitigations?|defen[cs]es?|countermeasures?|controls?"),
    ("Technique", r"techniques?|sub-?techniques?|ttps?|behaviou?rs?"),
    ("Software", r"software|malware|tools?|implants?|backdoors?"),
    ("ThreatGroup", r"groups?|actors?|adversar(?:y|ies)|apts?"),
    ("Campaign", r"campaigns?|operations?"),
]


def asked_entity_type(question: str) -> str | None:
    """The entity type a question asks for: the type word right after
    "which/what" (allowing a few modifiers such as "ATT&CK"), else the
    first type word in the question."""
    q = question.lower()
    m = re.search(r"\b(?:which|what|list|name)\b((?:\s+[\w&.-]+){1,4})", q)
    if m:
        for word in m.group(1).split():
            for label, pat in _TYPE_WORDS:
                if re.fullmatch(pat, word):
                    return label
    first = None
    for label, pat in _TYPE_WORDS:
        hit = re.search(rf"\b(?:{pat})\b", q)
        if hit and (first is None or hit.start() < first[0]):
            first = (hit.start(), label)
    return first[1] if first else None


@lru_cache(maxsize=1)
def get_resolver() -> EntityResolver:
    from threatgraph.ingestion.stix_loader import load_parsed_bundle
    return EntityResolver(load_parsed_bundle().entities)


def _fact(row: dict) -> GraphFact:
    return GraphFact(
        src_id=row.get("src_id") or row.get("src"), src_name=row.get("src_name"), src_type=row.get("src_type"),
        predicate=row.get("predicate"),
        tgt_id=row.get("tgt_id") or row.get("tgt"), tgt_name=row.get("tgt_name"), tgt_type=row.get("tgt_type"),
        source=row.get("source"), stix_relationship_id=row.get("stix_relationship_id"),
        modified=row.get("modified"), confidence=row.get("confidence"),
    )


def format_analytics(analytics: dict) -> str:
    lines = []
    for s in analytics.get("seeds", []):
        lines.append(f"{s['attack_id']} {s['name']} ({s['label']}): PageRank {s['pagerank']:.2f}, "
                     f"rank {s['rank']} of {s['of_label']} {s['label']} nodes, degree {int(s['degree'] or 0)}, "
                     f"Louvain community {s['community']} ({s['community_size']} nodes)")
    for c in analytics.get("coverage", []):
        lines.append(f"Mitigation coverage: {c['attack_id']} {c['name']} mitigates {c['covered']} "
                     f"of the {c['total']} techniques used by the named entities")
    return "\n".join(lines)


class ThreatGraphRAG:
    def __init__(self, client: Neo4jClient | None = None, embedder: Embedder | None = None,
                 provider: LLMProvider | None = None, top_k: int = RETRIEVAL.top_k_chunks,
                 max_hops: int = RETRIEVAL.max_hops, resolver: EntityResolver | None = None):
        self._client = client or Neo4jClient()
        self._embedder = embedder or get_embedder()
        self._provider = provider
        self._top_k = top_k
        self._max_hops = max_hops
        self._resolver = resolver
        self._owns_client = client is None

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def link_entities(self, question: str) -> list[dict]:
        resolver = self._resolver or get_resolver()
        seen, out = set(), []
        for m in resolver.find_mentions(question):
            if m.attack_id in seen:
                continue
            seen.add(m.attack_id)
            out.append({"mention": m.text, "attack_id": m.attack_id, "name": m.canonical_name,
                        "type": m.entity_type, "method": m.method})
        return out

    def _fallback_facts(self, seeds: list[str]) -> list[GraphFact]:
        facts, seen = [], set()
        for seed in seeds:
            rows = []
            if seed.startswith("G"):
                for row in group_technique_mitigation_path(self._client, seed):
                    rows.append({"src_id": row["group_id"], "src_name": row["group_name"], "src_type": "ThreatGroup",
                                 "predicate": "USES", "tgt_id": row["technique_id"],
                                 "tgt_name": row["technique_name"], "tgt_type": "Technique"})
                    rows += [{"src_id": m["attack_id"], "src_name": m["name"], "src_type": "Mitigation",
                              "predicate": "MITIGATES", "tgt_id": row["technique_id"],
                              "tgt_name": row["technique_name"], "tgt_type": "Technique"}
                             for m in row.get("mitigations") or [] if m.get("attack_id")]
            else:
                rows = bounded_neighborhood(self._client, seed, max_hops=self._max_hops)
            for row in rows:
                f = _fact(row)
                key = (f.src_id, f.predicate, f.tgt_id)
                if f.src_id and f.tgt_id and key not in seen:
                    seen.add(key)
                    facts.append(f)
            if len(facts) >= RETRIEVAL.neighborhood_facts:
                break
        return facts[:RETRIEVAL.neighborhood_facts]

    def retrieve_graph(self, question: str, chunks: list[RetrievedChunk]) -> dict:
        """NED + typed multi-hop traversal + GDS context (no LLM)."""
        linked = self.link_entities(question)
        target = asked_entity_type(question)
        seeds: dict[str, list[str]] = {}
        for e in linked:
            seeds.setdefault(e["type"], []).append(e["attack_id"])
        rows = focused_facts(self._client, seeds, target) if linked else []
        if rows:
            facts = [_fact(r) for r in rows]
        else:
            # Unrecognized question shape (or no linked entity): bounded
            # neighbourhood around the linked entities, else the entities the
            # top retrieved chunks describe.
            seed_ids = [e["attack_id"] for e in linked] or list(dict.fromkeys(
                c.entity_attack_id for c in chunks[:3] if c.entity_attack_id))
            facts = self._fallback_facts(seed_ids)
        coverage_for = (seeds.get("ThreatGroup", []) + seeds.get("Software", [])) \
            if target == "Mitigation" and not seeds.get("Technique") else []
        analytics = graph_analytics_context(self._client, [e["attack_id"] for e in linked], coverage_for)
        return {"linked": linked, "target": target, "facts": facts, "analytics": analytics}

    def retrieve(self, question: str) -> tuple[list[RetrievedChunk], list[GraphFact], str, float]:
        chunks, graph, context, latency = self._retrieve(question)
        return chunks, graph["facts"], context, latency

    def _retrieve(self, question: str):
        t0 = time.time()
        query_vector = self._embedder.embed_one(question)
        chunks = [
            RetrievedChunk(chunk_id=r["chunk_id"], text=r["text"], entity_name=r.get("entity_name"),
                           entity_attack_id=r.get("entity_attack_id"), score=r["score"])
            for r in vector_search(self._client, query_vector, k=self._top_k)
        ]
        graph = self.retrieve_graph(question, chunks)
        latency = time.time() - t0

        text_context = "\n\n".join(
            f"[{c.entity_attack_id or '?'}] {c.entity_name or ''}: {c.text}" for c in chunks)
        graph_context = "\n".join(
            f"({f.src_id} {f.src_name}:{f.src_type}) -{f.predicate}-> ({f.tgt_id} {f.tgt_name}:{f.tgt_type})"
            for f in graph["facts"])
        linked = ", ".join(f"\"{e['mention']}\" = {e['attack_id']} {e['name']} ({e['type']})"
                           for e in graph["linked"]) or "none"
        context = (f"LINKED ENTITIES:\n{linked}\n\nTEXT EVIDENCE:\n{text_context}\n\n"
                   f"GRAPH RELATIONSHIPS (MITRE ATT&CK v19.2):\n{graph_context}")
        analytics_text = format_analytics(graph["analytics"])
        if analytics_text:
            context += f"\n\nGRAPH ANALYTICS (Neo4j GDS):\n{analytics_text}"
        return chunks, graph, context, latency

    def answer(self, question: str) -> RAGResult:
        t_start = time.time()
        chunks: list[RetrievedChunk] = []
        graph = {"facts": [], "linked": [], "target": None, "analytics": {}}
        retrieval_latency = 0.0
        context = ""
        try:
            chunks, graph, context, retrieval_latency = self._retrieve(question)
            provider = self._provider or LLMProvider()
            gen = generate_answer(provider, question, context)
            return result_from_generation(
                "threatgraph", question, gen, chunks, graph["facts"], retrieval_latency, t_start, context,
                extra={"linked_entities": graph["linked"], "target_type": graph["target"],
                       "analytics": graph["analytics"]})
        except Exception as exc:
            # Keep whatever retrieval already succeeded instead of discarding it.
            return RAGResult(
                system="threatgraph", question=question, answer="",
                retrieved_chunks=chunks, graph_facts=graph["facts"],
                retrieval_latency_seconds=retrieval_latency, context_chars=len(context),
                total_latency_seconds=time.time() - t_start, error=str(exc),
                linked_entities=graph["linked"], target_type=graph["target"], analytics=graph["analytics"],
            )
