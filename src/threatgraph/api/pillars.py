"""API for the five-tab web UI, one section per rubric pillar:

  /api/overview                  problem statement numbers + headline results
  /api/ingestion                 schema, sources, edge provenance (pillar 1)
  /api/analytics[/run]           Neo4j GDS results (pillar 2)
  /api/extraction-ned, /api/extract, /api/ned
                                 Pydantic/Ollama extraction + NED (pillar 3)
  /api/graphrag/ask, /api/graphrag/benchmark[/run]
                                 GraphRAG vs text-only RAG (pillar 4)

Everything shown is read from Neo4j or from result files written by the
pipeline scripts; nothing is hardcoded here.
"""
from __future__ import annotations

import json
import threading
from functools import lru_cache
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from threatgraph.config import ATTACK_STIX_VERSION, EMBEDDING, LLM, RETRIEVAL
from threatgraph.eval import answer_metrics, ned_eval, ui_eval
from threatgraph.graph import analytics as gds_analytics
from threatgraph.ingestion import text_ingest

router = APIRouter(prefix="/api")
_lock = threading.Lock()


def _systems():
    from threatgraph.api.app import get_systems
    return get_systems()


def _client():
    return _systems()[1]._client


def _bench_items() -> dict[str, dict]:
    return {q["id"]: q for q in ui_eval.load_benchmark()}


# --------------------------------------------------------------------------
# Overview
# --------------------------------------------------------------------------

@router.get("/overview")
def overview():
    c = _client()
    nodes = c.run("MATCH (n) RETURN labels(n)[0] AS label, count(*) AS n ORDER BY n DESC")
    edges = c.run("MATCH ()-[r]->() RETURN coalesce(r.source, 'structural') AS source, count(*) AS n ORDER BY n DESC")
    bench = graphrag_benchmark()
    ned = ned_eval.load()
    ana = gds_analytics.load()
    return {
        "attack_version": ATTACK_STIX_VERSION,
        "llm": {"provider": LLM.provider, "model": LLM.model},
        "embedding": EMBEDDING.model_name,
        "nodes": nodes, "edges_by_source": edges,
        "headline": {
            "benchmark": bench.get("summary") if bench.get("available") else None,
            "n_questions": bench.get("n_questions"),
            "ned_accuracy": ned["threatgraph_ned"]["overall"]["accuracy"] if ned else None,
            "ned_baseline_accuracy": ned["baseline_exact_name"]["overall"]["accuracy"] if ned else None,
            "communities": ana["louvain"]["communities"] if ana else None,
        },
    }


# --------------------------------------------------------------------------
# Pillar 1: schema & ingestion
# --------------------------------------------------------------------------

@router.get("/ingestion")
def ingestion():
    c = _client()
    labels = c.run("""
        MATCH (n) WITH labels(n)[0] AS label, n
        WITH label, count(*) AS n, collect(keys(n))[0..50] AS key_lists
        RETURN label, n, reduce(a = [], k IN key_lists | a + [x IN k WHERE NOT x IN a]) AS keys
        ORDER BY n DESC
    """)
    rels = c.run("""
        MATCH (s)-[r]->(t)
        RETURN labels(s)[0] AS src, type(r) AS rel, labels(t)[0] AS tgt,
               coalesce(r.source, 'structural') AS source, count(*) AS n
        ORDER BY source, n DESC
    """)
    sample = c.run("""
        MATCH (g:ThreatGroup {attack_id: 'G0016'})-[r:USES]->(t:Technique {attack_id: 'T1059.001'})
        WHERE r.source = 'mitre_attack_stix'
        RETURN g.attack_id + ' ' + g.name AS subject, type(r) AS predicate, t.attack_id + ' ' + t.name AS object,
               r.source AS source, r.source_version AS source_version, r.stix_relationship_id AS stix_relationship_id,
               toString(r.created) AS created, toString(r.modified) AS modified, r.confidence AS confidence,
               r.evidence_text AS evidence_text
    """)
    llm_samples = c.run("""
        MATCH (s)-[r]->(t) WHERE r.source = 'llm_extraction'
        RETURN s.attack_id + ' ' + s.name AS subject, type(r) AS predicate, t.attack_id + ' ' + t.name AS object,
               r.confidence AS confidence, r.verified AS verified, r.model AS model, r.evidence_text AS evidence_text,
               r.source_entity AS source_document, r.subject_ned AS subject_ned, r.object_ned AS object_ned
        ORDER BY r.verified DESC, r.confidence DESC, subject, object LIMIT 12
    """)
    from threatgraph.ingestion.stix_loader import STIX_TYPE_TO_ENTITY_TYPE
    mapping = [{"stix_type": k, "label": v.value} for k, v in STIX_TYPE_TO_ENTITY_TYPE.items()]
    return {"labels": labels, "relationships": rels, "stix_edge_example": sample[0] if sample else None,
            "stix_mapping": mapping,
            "text_ingestion": text_ingest.load(), "llm_edge_examples": llm_samples,
            "attack_version": ATTACK_STIX_VERSION}


# --------------------------------------------------------------------------
# Pillar 2: graph analytics
# --------------------------------------------------------------------------

@router.get("/analytics")
def analytics():
    data = gds_analytics.load()
    return {"available": data is not None, **(data or {})}


@router.post("/analytics/run")
def analytics_run():
    with _lock:
        try:
            gds_analytics.run(_client())
        except RuntimeError as exc:
            raise HTTPException(400, str(exc))
    return analytics()


# --------------------------------------------------------------------------
# Pillar 3: extraction & NED
# --------------------------------------------------------------------------

SAMPLE_ENTITIES = ["G1054", "C0040", "S1097"]  # MirrorFace, APT41 DUST, HUI Loader: several entities each


@lru_cache(maxsize=1)
def _bundle():
    from threatgraph.ingestion.stix_loader import load_parsed_bundle
    return load_parsed_bundle()


@lru_cache(maxsize=1)
def _resolver():
    from threatgraph.embeddings import get_embedder
    from threatgraph.entity_resolution import EntityResolver
    return EntityResolver(_bundle().entities, embedder=get_embedder())


@router.get("/extraction-ned")
def extraction_ned():
    ev = ui_eval.extraction_evaluation()
    extraction = None
    if ev is not None:
        m = ev.pop("metrics")
        extraction = {**ev, "metrics": m.to_dict()}
    by_id = {pe.entity.attack_id: pe for pe in _bundle().entities.values()}
    samples = [{"attack_id": a, "name": by_id[a].entity.name, "text": by_id[a].description[:900]}
               for a in SAMPLE_ENTITIES if a in by_id]
    return {"extraction": extraction, "ned": ned_eval.load(), "samples": samples,
            "model": LLM.extraction_model, "provider": LLM.provider}


class TextRequest(BaseModel):
    text: str = Field(min_length=1, max_length=6000)


@router.post("/ned")
def ned(req: TextRequest):
    return {"mentions": [m.__dict__ for m in _resolver().find_mentions(req.text)]}


@router.post("/extract")
def extract_text(req: TextRequest):
    from threatgraph.extraction.extractor import ExtractionError, extract
    from threatgraph.rag.llm_provider import LLMProvider

    try:
        res = extract(req.text, provider=LLMProvider(), resolver=_resolver())
    except ExtractionError as exc:
        raise HTTPException(422, str(exc))
    except RuntimeError as exc:
        raise HTTPException(503, str(exc))
    entities = []
    for e in res.extraction.entities:
        r = res.resolutions.get(e.name)
        entities.append({"mention": e.name, "type": e.entity_type.value, "llm_attack_id": e.attack_id,
                         "confidence": e.confidence_score, "resolved": bool(r and r.matched),
                         "attack_id": r.attack_id if r else None, "canonical_name": r.canonical_name if r else None,
                         "method": r.method if r else None, "similarity": r.similarity if r else None})
    rels, c = [], _client()
    for rel in res.extraction.relationships:
        s, t = res.resolutions.get(rel.source), res.resolutions.get(rel.target)
        ok = bool(s and s.matched and t and t.matched)
        verified = None
        if ok:
            verified = bool(c.run(
                "MATCH (a {attack_id: $s})-[r]->(b {attack_id: $t}) WHERE type(r) = $p AND r.source = 'mitre_attack_stix' "
                "RETURN count(r) > 0 AS v", {"s": s.attack_id, "t": t.attack_id, "p": rel.predicate.value})[0]["v"])
        rels.append({"source": rel.source, "predicate": rel.predicate.value, "target": rel.target,
                     "source_id": s.attack_id if ok else None, "target_id": t.attack_id if ok else None,
                     "confidence": rel.confidence_score, "evidence_text": rel.evidence_text, "verified": verified})
    return {"entities": entities, "relationships": rels, "rejected": res.rejected,
            "latency_seconds": res.llm_response.latency_seconds, "cached": res.llm_response.cached,
            "model": res.llm_response.model, "schema_enforced": LLM.provider == "ollama"}


# --------------------------------------------------------------------------
# Pillar 4: GraphRAG
# --------------------------------------------------------------------------

class AskRequest(BaseModel):
    question: str = Field(min_length=1, max_length=4000)


def _run_view(run: dict, item: Optional[dict]) -> dict:
    return {**{k: run.get(k) for k in (
        "system", "answer", "error", "retrieval_latency_seconds", "generation_latency_seconds",
        "total_latency_seconds", "generation_cached", "retrieved_chunks", "graph_facts",
        "linked_entities", "target_type", "analytics")},
        "scores": answer_metrics.score(run, item) if item else None}


@router.post("/graphrag/ask")
def graphrag_ask(req: AskRequest):
    baseline, graphrag = _systems()
    item = ui_eval.match_benchmark(req.question, ui_eval.load_benchmark())
    out = {}
    for key, system in (("baseline", baseline), ("threatgraph", graphrag)):
        run = ui_eval.new_run(system.answer(req.question), item)
        out[key] = _run_view(run, item)
    return {"question": req.question, "benchmark_id": item["id"] if item else None,
            "gold": sorted(answer_metrics.gold_ids(item)) if item else None, "runs": out}


def _latest_finished():
    benches = [b for b in ui_eval.load_store()["benchmarks"] if b.get("finished_at")]
    return benches[-1] if benches else None


@router.get("/graphrag/benchmark")
def graphrag_benchmark():
    from threatgraph.api.app import _benchmark_jobs
    running = next((bid for bid, j in _benchmark_jobs.items() if j["running"]), None)
    progress = None
    if running:
        b = ui_eval.get_benchmark(running)
        progress = {"id": running, "done": len(b["items"]), "total": len(b["question_ids"])}
    bench = _latest_finished()
    if bench is None:
        return {"available": False, "running": progress}
    store, items = ui_eval.load_store(), _bench_items()
    rows, scores = [], {"baseline": [], "threatgraph": []}
    for qid, it in sorted(bench["items"].items()):
        row = {"question_id": qid, "question": it["question"], "category": it.get("category"),
               "hops": it.get("required_hops"), "scores": {}}
        for s in scores:
            run = store["runs"].get(it[s])
            if run:
                sc = answer_metrics.score(run, items[qid])
                scores[s].append(sc)
                row["scores"][s] = sc
        rows.append(row)
    by_category: dict[str, dict] = {}
    for cat in sorted({r["category"] for r in rows}):
        by_category[cat] = {s: answer_metrics.summarize([r["scores"][s] for r in rows
                                                         if r["category"] == cat and s in r["scores"]])
                            for s in scores}
    return {"available": True, "id": bench["id"], "finished_at": bench["finished_at"],
            "n_questions": len(rows), "metrics": [{"key": k, "label": l, "higher_is_better": h}
                                                   for k, l, h in answer_metrics.METRICS],
            "summary": {s: answer_metrics.summarize(v) for s, v in scores.items()},
            "by_category": by_category, "rows": rows, "running": progress,
            "config": {"llm": next((r["llm"] for r in store["runs"].values() if r.get("benchmark_id") == bench["id"]
                                    and r.get("llm")), "not recorded"),
                       "top_k_chunks": RETRIEVAL.top_k_chunks,
                       "max_graph_facts": RETRIEVAL.max_graph_facts}}


@router.post("/graphrag/benchmark/run")
def graphrag_benchmark_run():
    from threatgraph.api.app import BenchmarkRequest, start_benchmark
    return start_benchmark(BenchmarkRequest(n_questions=len(ui_eval.load_benchmark()), with_ragas=False))
