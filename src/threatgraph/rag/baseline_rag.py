"""System A: traditional text-only RAG. Exact semantic (cosine) chunk
retrieval over Neo4j chunk embeddings, no graph traversal of any kind. This is the control condition
against which System B (ThreatGraph) is compared; the only intended
difference between the two systems is the addition of graph retrieval.
"""
from __future__ import annotations

import time

from threatgraph.config import RETRIEVAL
from threatgraph.embeddings import Embedder, get_embedder
from threatgraph.graph.neo4j_client import Neo4jClient
from threatgraph.graph.traversal import vector_search
from threatgraph.rag.common import RAGResult, RetrievedChunk, generate_answer, result_from_generation
from threatgraph.rag.llm_provider import LLMProvider


class BaselineRAG:
    def __init__(self, client: Neo4jClient | None = None, embedder: Embedder | None = None,
                 provider: LLMProvider | None = None, top_k: int = RETRIEVAL.top_k_chunks):
        self._client = client or Neo4jClient()
        self._embedder = embedder or get_embedder()
        self._provider = provider
        self._top_k = top_k
        self._owns_client = client is None

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def retrieve(self, question: str) -> tuple[list[RetrievedChunk], list, str, float]:
        """Retrieval only (no LLM): (chunks, graph_facts=[], context, latency)."""
        t0 = time.time()
        query_vector = self._embedder.embed_one(question)
        rows = vector_search(self._client, query_vector, k=self._top_k)
        chunks = [
            RetrievedChunk(
                chunk_id=r["chunk_id"], text=r["text"],
                entity_name=r.get("entity_name"), entity_attack_id=r.get("entity_attack_id"),
                score=r["score"],
            )
            for r in rows
        ]
        context = "\n\n".join(
            f"[{c.entity_attack_id or '?'}] {c.entity_name or ''}: {c.text}" for c in chunks
        )
        return chunks, [], context, time.time() - t0

    def answer(self, question: str) -> RAGResult:
        t_start = time.time()
        chunks: list[RetrievedChunk] = []
        retrieval_latency = 0.0
        context = ""
        try:
            chunks, _, context, retrieval_latency = self.retrieve(question)
            provider = self._provider or LLMProvider()
            gen = generate_answer(provider, question, context)
            return result_from_generation("baseline", question, gen, chunks, [],
                                          retrieval_latency, t_start, context)
        except Exception as exc:
            # Preserve whatever retrieval already succeeded (e.g. a
            # generation-time failure after successful retrieval) instead of
            # silently discarding it.
            return RAGResult(
                system="baseline", question=question, answer="",
                retrieved_chunks=chunks, retrieval_latency_seconds=retrieval_latency,
                context_chars=len(context),
                total_latency_seconds=time.time() - t_start, error=str(exc),
            )
