"""Shared types and helpers for both RAG systems, so System A and System B
are directly comparable (same retrieved-chunk schema, same generation call
shape, same instrumentation fields)."""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Optional

from threatgraph.rag.llm_provider import LLMProvider

ANSWER_SYSTEM_PROMPT = (
    "You are a cyber threat intelligence analyst assistant. Answer the user's "
    "question using ONLY the evidence provided in the context below. Cite "
    "MITRE ATT&CK IDs (e.g. G0016, T1055, M1040) for every entity you name. "
    "When the question asks for a list (for example all mitigations or all "
    "techniques), include every item the evidence supports. If the context "
    "does not contain enough information to answer, say so explicitly "
    "instead of guessing."
)

# Recognizes "ThreatGroup (G0016)" style ATT&CK ID mentions in a question so
# the GraphRAG system can seed graph traversal from a resolved entity.
ATTACK_ID_RE = re.compile(r"\b([GTSMC]\d{4}(?:\.\d{3})?)\b")


@dataclass
class RetrievedChunk:
    chunk_id: str
    text: str
    entity_name: Optional[str]
    entity_attack_id: Optional[str]
    score: float


@dataclass
class GraphFact:
    src_id: Optional[str]
    src_name: Optional[str]
    src_type: Optional[str]
    predicate: Optional[str]
    tgt_id: Optional[str]
    tgt_name: Optional[str]
    tgt_type: Optional[str]
    # Edge provenance (see graph.populate): who asserted the fact and when.
    source: Optional[str] = None
    stix_relationship_id: Optional[str] = None
    modified: Optional[str] = None
    confidence: Optional[float] = None


@dataclass
class RAGResult:
    system: str  # "baseline" | "threatgraph"
    question: str
    answer: str
    retrieved_chunks: list[RetrievedChunk] = field(default_factory=list)
    graph_facts: list[GraphFact] = field(default_factory=list)
    retrieval_latency_seconds: float = 0.0
    generation_latency_seconds: float = 0.0
    total_latency_seconds: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost_usd: Optional[float] = None
    context_chars: int = 0
    error: Optional[str] = None
    # Answer reused from threatgraph.llm_cache (identical prompt answered
    # before); generation latency/tokens/cost are the originally measured ones.
    generation_cached: bool = False
    generation_cached_at: Optional[str] = None
    # GraphRAG only: entities linked by NED, the entity type the question
    # asks for, and the GDS signals added to the prompt.
    linked_entities: list = field(default_factory=list)
    target_type: Optional[str] = None
    analytics: dict = field(default_factory=dict)


def extract_attack_ids(question: str) -> list[str]:
    return ATTACK_ID_RE.findall(question)


def build_user_prompt(question: str, context: str) -> str:
    return f"CONTEXT:\n{context}\n\nQUESTION:\n{question}"


@dataclass
class Generation:
    text: str
    input_tokens: int
    output_tokens: int
    latency_seconds: float      # measured now, or the original measurement if cached
    estimated_cost_usd: Optional[float]
    cached: bool
    cached_at: Optional[str]
    wall_seconds: float         # time this call actually took (≈0 for a cache hit)


def generate_answer(provider: LLMProvider, question: str, context: str) -> Generation:
    t0 = time.time()
    resp = provider.complete(system=ANSWER_SYSTEM_PROMPT, user=build_user_prompt(question, context))
    wall = time.time() - t0
    return Generation(
        text=resp.text, input_tokens=resp.input_tokens, output_tokens=resp.output_tokens,
        latency_seconds=resp.latency_seconds if resp.cached else wall,
        estimated_cost_usd=resp.estimated_cost_usd, cached=resp.cached, cached_at=resp.cached_at,
        wall_seconds=wall,
    )


def result_from_generation(system: str, question: str, gen: Generation, chunks: list, facts: list,
                           retrieval_latency: float, t_start: float, context: str,
                           extra: Optional[dict] = None) -> RAGResult:
    # A cache hit costs ~0 s; report the originally measured generation time
    # instead so total latency stays comparable with freshly generated answers.
    total = time.time() - t_start - gen.wall_seconds + gen.latency_seconds
    return RAGResult(
        system=system, question=question, answer=gen.text,
        retrieved_chunks=chunks, graph_facts=facts,
        retrieval_latency_seconds=retrieval_latency, generation_latency_seconds=gen.latency_seconds,
        total_latency_seconds=total, input_tokens=gen.input_tokens, output_tokens=gen.output_tokens,
        estimated_cost_usd=gen.estimated_cost_usd, context_chars=len(context),
        generation_cached=gen.cached, generation_cached_at=gen.cached_at,
        **(extra or {}),
    )
