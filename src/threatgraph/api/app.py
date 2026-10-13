"""HTTP API behind the ThreatGraph web frontend (frontend/).

A thin layer over the same modules the Streamlit app uses: both RAG systems
(threatgraph.rag) for answering, and threatgraph.eval.ui_eval for RAGAS,
human ratings, benchmark runs, extraction metrics and persistence
(results/ui_evaluations.json). No metric is computed here.

Long-running work (benchmark runs, extraction evaluation) runs in a
background thread so the browser can poll progress and survive a refresh.

Run:  uvicorn threatgraph.api.app:app --port 8000   (or: make app)
When frontend/dist exists (make frontend), the built UI is served at /.
"""
from __future__ import annotations

import os
import threading
from contextlib import nullcontext
import time
import uuid
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from threatgraph import llm_cache
from threatgraph.config import EMBEDDING, LLM, REPO_ROOT
from threatgraph.eval import ui_eval
from threatgraph.eval.ui_eval import HUMAN_METRICS, RAGAS_METRICS, SYSTEMS

app = FastAPI(title="ThreatGraph API")

SystemKey = Literal["baseline", "threatgraph"]
METRIC_KEYS = [k for k, _ in RAGAS_METRICS] + [k for k, _ in HUMAN_METRICS] + ["total_latency_seconds"]
RUBRIC = {
    "factuality": "Are the claims accurate per MITRE ATT&CK, with no fabricated techniques, groups, "
                  "mitigations or relationships? 1 = mostly fabricated, 5 = fully accurate.",
    "completeness": "Does the answer cover everything the question needs (e.g. all mitigations, not "
                    "just one)? 1 = missing most required facts, 5 = fully complete.",
    "coherence": "Is the answer well-organized and readable, independent of correctness? "
                 "1 = incoherent, 5 = clear and well-structured.",
}

# --------------------------------------------------------------------------
# Shared state
# --------------------------------------------------------------------------

_systems_lock = threading.Lock()
_systems: Optional[tuple] = None
_jobs_lock = threading.Lock()
_benchmark_jobs: dict[str, dict] = {}   # bench_id -> {"current": qid, "error": str|None, "running": bool}
_extraction_job: dict = {"running": False, "error": None, "note": None}


def get_systems():
    """Both RAG systems, sharing one Neo4j driver and embedder (built once)."""
    global _systems
    with _systems_lock:
        if _systems is None:
            from threatgraph.embeddings import get_embedder
            from threatgraph.graph.neo4j_client import Neo4jClient
            from threatgraph.rag.baseline_rag import BaselineRAG
            from threatgraph.rag.graphrag import ThreatGraphRAG

            client = Neo4jClient()
            if not client.verify_connectivity():
                client.close()
                raise HTTPException(503, "Cannot connect to Neo4j. Check NEO4J_URI / NEO4J_USER / "
                                         "NEO4J_PASSWORD and that the database is running and populated.")
            embedder = get_embedder()
            _systems = (BaselineRAG(client=client, embedder=embedder),
                        ThreatGraphRAG(client=client, embedder=embedder))
        return _systems


def _system_map() -> dict:
    baseline, graphrag = get_systems()
    return {"baseline": baseline, "threatgraph": graphrag}


def present(run: dict) -> dict:
    return {**run, "metrics": {k: ui_eval.metric_value(run, k) for k in METRIC_KEYS}}


def _runs_or_404(run_ids: list[str]) -> list[dict]:
    store = ui_eval.load_store()
    missing = [i for i in run_ids if i not in store["runs"]]
    if missing:
        raise HTTPException(404, f"Unknown run id(s): {', '.join(missing)}")
    return [store["runs"][i] for i in run_ids]


# --------------------------------------------------------------------------
# Meta / health
# --------------------------------------------------------------------------

@app.get("/api/meta")
def meta():
    neo4j_ok = True
    try:
        get_systems()
    except HTTPException:
        neo4j_ok = False
    return {
        "neo4j_connected": neo4j_ok,
        "llm": {"provider": LLM.provider, "model": LLM.model},
        "judge": {"provider": os.environ.get("RAGAS_JUDGE_PROVIDER", LLM.provider),
                  "model": os.environ.get("RAGAS_JUDGE_MODEL", LLM.judge_model)},
        "embedding": {"model": EMBEDDING.model_name, "revision": EMBEDDING.revision},
        "ragas_env": ui_eval.RAGAS_PYTHON.exists(),
        "cache": {"enabled": llm_cache.enabled(), **llm_cache.stats()},
        "systems": [{"key": k, "label": label} for k, label in SYSTEMS],
        "ragas_metrics": [{"key": k, "label": label} for k, label in RAGAS_METRICS],
        "human_metrics": [{"key": k, "label": label, "rubric": RUBRIC[k]} for k, label in HUMAN_METRICS],
    }


@app.get("/api/benchmark/questions")
def benchmark_questions():
    return [{"id": q["id"], "question": q["question"], "category": q.get("category"),
             "required_hops": q.get("required_hops")} for q in ui_eval.load_benchmark()]


# --------------------------------------------------------------------------
# Ask + per-answer evaluation
# --------------------------------------------------------------------------

class AskRequest(BaseModel):
    question: str = Field(min_length=1, max_length=4000)
    systems: list[SystemKey] = Field(min_length=1, max_length=2)
    ragas: bool = False
    use_cache: bool = True   # False = force fresh LLM calls (the new answers are still cached)


@app.post("/api/ask")
def ask(req: AskRequest):
    question = req.question.strip()
    if not question:
        raise HTTPException(422, "Question is empty.")
    systems = _system_map()
    bench_item = ui_eval.match_benchmark(question)
    group_id = uuid.uuid4().hex[:12]
    runs = []
    for key in dict.fromkeys(req.systems):
        t0 = time.time()
        with (nullcontext() if req.use_cache else llm_cache.bypass()):
            result = systems[key].answer(question)
        run = ui_eval.new_run(result, bench_item)
        run["wall_clock_seconds"] = time.time() - t0
        run["group_id"] = group_id
        runs.append(run)
    ui_eval.save_runs(*runs)

    ragas_error = None
    if req.ragas:
        try:
            ui_eval.run_ragas(runs)
            ui_eval.save_runs(*runs)
        except ui_eval.EvaluationError as exc:
            ragas_error = str(exc)
    return {"runs": [present(r) for r in runs], "ragas_error": ragas_error}


class RagasRequest(BaseModel):
    run_ids: list[str] = Field(min_length=1, max_length=2)


@app.post("/api/ragas")
def ragas(req: RagasRequest):
    runs = _runs_or_404(req.run_ids)
    try:
        ui_eval.run_ragas(runs)  # one call: identical judge config for every run
    except ui_eval.EvaluationError as exc:
        raise HTTPException(502, str(exc)) from exc
    ui_eval.save_runs(*runs)
    return {"runs": [present(r) for r in runs]}


class Ratings(BaseModel):
    factuality: Optional[int] = Field(default=None, ge=1, le=5)
    completeness: Optional[int] = Field(default=None, ge=1, le=5)
    coherence: Optional[int] = Field(default=None, ge=1, le=5)


@app.put("/api/runs/{run_id}/ratings")
def save_ratings(run_id: str, ratings: Ratings):
    try:
        ui_eval.save_human_ratings(run_id, ratings.model_dump())
    except KeyError as exc:
        raise HTTPException(404, f"Unknown run id: {run_id}") from exc
    return present(ui_eval.get_run(run_id))


@app.get("/api/runs")
def get_runs(ids: str):
    return [present(r) for r in _runs_or_404([i for i in ids.split(",") if i])]


@app.get("/api/evaluations")
def saved_evaluations():
    """Individual (non-benchmark) evaluations, newest first, grouped by Ask."""
    groups: dict[str, list[dict]] = {}
    for r in sorted(ui_eval.load_store()["runs"].values(), key=lambda r: r["created_at"], reverse=True):
        if r.get("benchmark_id") is None:
            groups.setdefault(r.get("group_id") or r["id"], []).append(r)
    return [{
        "group_id": gid,
        "created_at": rs[0]["created_at"],
        "question": rs[0]["question"],
        "question_id": rs[0].get("question_id"),
        "systems": [r["system"] for r in rs],
        "run_ids": [r["id"] for r in rs],
        "evaluated": all(r.get("ragas") is not None for r in rs),
        "rated": all(any(v is not None for v in (r.get("human") or {}).values()) for r in rs),
    } for gid, rs in groups.items()]


# --------------------------------------------------------------------------
# Benchmark
# --------------------------------------------------------------------------

def _benchmark_worker(bench_id: str) -> None:
    def on_progress(done, total, qid, _item):
        with _jobs_lock:
            _benchmark_jobs[bench_id]["current"] = qid
    try:
        baseline, graphrag = get_systems()
        ui_eval.run_benchmark(bench_id, baseline, graphrag, on_progress)
    except Exception as exc:  # surfaced to the UI via /api/benchmarks/{id}
        with _jobs_lock:
            _benchmark_jobs[bench_id]["error"] = str(exc)
        ui_eval.finish_benchmark(bench_id, f"Stopped by an error: {exc}")
    finally:
        with _jobs_lock:
            _benchmark_jobs[bench_id]["running"] = False


def _start_benchmark_thread(bench_id: str) -> None:
    get_systems()  # fail fast (503) before registering the job
    with _jobs_lock:
        if any(j["running"] for j in _benchmark_jobs.values()):
            raise HTTPException(409, "A benchmark is already running.")
        _benchmark_jobs[bench_id] = {"running": True, "current": None, "error": None}
    threading.Thread(target=_benchmark_worker, args=(bench_id,), daemon=True).start()


def _job(bench_id: str) -> dict:
    with _jobs_lock:
        return dict(_benchmark_jobs.get(bench_id, {"running": False, "current": None, "error": None}))


def _benchmark_summary(b: dict) -> dict:
    job = _job(b["id"])
    return {
        "id": b["id"], "started_at": b["started_at"], "finished_at": b.get("finished_at"),
        "with_ragas": b["with_ragas"], "n_total": len(b["question_ids"]), "n_done": len(b["items"]),
        "stopped_reason": b.get("stopped_reason"), "running": job["running"],
        "current_question": job["current"], "error": job["error"],
    }


class BenchmarkRequest(BaseModel):
    n_questions: int = Field(ge=1)
    with_ragas: bool = True


@app.get("/api/benchmarks")
def list_benchmarks():
    return [_benchmark_summary(b) for b in reversed(ui_eval.load_store()["benchmarks"])]


@app.post("/api/benchmarks")
def start_benchmark(req: BenchmarkRequest):
    questions = ui_eval.load_benchmark()
    if not questions:
        raise HTTPException(400, "No benchmark found. Run `make benchmarks` first.")
    get_systems()
    with _jobs_lock:
        if any(j["running"] for j in _benchmark_jobs.values()):
            raise HTTPException(409, "A benchmark is already running.")
    bench = ui_eval.start_benchmark([q["id"] for q in questions[: req.n_questions]], req.with_ragas)
    _start_benchmark_thread(bench["id"])
    return _benchmark_summary(ui_eval.get_benchmark(bench["id"]))


@app.post("/api/benchmarks/{bench_id}/resume")
def resume_benchmark(bench_id: str):
    bench = ui_eval.get_benchmark(bench_id)
    if bench is None:
        raise HTTPException(404, "Unknown benchmark.")
    if bench.get("finished_at"):
        raise HTTPException(400, "This benchmark already finished.")
    _start_benchmark_thread(bench_id)
    return _benchmark_summary(ui_eval.get_benchmark(bench_id))


@app.get("/api/benchmarks/{bench_id}")
def benchmark_detail(bench_id: str):
    store = ui_eval.load_store()
    bench = next((b for b in store["benchmarks"] if b["id"] == bench_id), None)
    if bench is None:
        raise HTTPException(404, "Unknown benchmark.")
    runs_by_sys = ui_eval.benchmark_runs(bench, store)
    averages = {s: {k: ui_eval.summarize(runs_by_sys[s], k) for k in METRIC_KEYS} for s, _ in SYSTEMS}
    items = []
    for item in bench["items"].values():
        runs = {}
        for s, _ in SYSTEMS:
            run = store["runs"].get(item[s])
            runs[s] = None if run is None else {
                "id": run["id"], "error": run.get("error"),
                "metrics": {k: ui_eval.metric_value(run, k) for k in METRIC_KEYS},
            }
        items.append({k: item.get(k) for k in ("question_id", "question", "category", "required_hops",
                                                "ragas_error")} | {"runs": runs})
    metas = [r["ragas_meta"] for r in runs_by_sys["baseline"] if r.get("ragas_meta")]
    return {
        **_benchmark_summary(bench),
        "averages": averages,
        "items": items,
        "ragas_meta": ({k: metas[0].get(k) for k in ("ragas_version", "judge_provider", "judge_model",
                                                      "embedding_model")}
                       | {"total_evaluation_seconds": round(sum(m["evaluation_seconds"] for m in metas), 1)})
        if metas else None,
    }


# --------------------------------------------------------------------------
# Knowledge extraction
# --------------------------------------------------------------------------

@app.get("/api/extraction")
def extraction():
    ev = ui_eval.extraction_evaluation()
    job = dict(_extraction_job)
    if ev is None:
        return {"available": False, "job": job}
    m = ev.pop("metrics")
    return {"available": True, "job": job, **ev, "metrics": m.to_dict(),
            "false_positive_triples": m.fp_triples, "false_negative_triples": m.fn_triples}


class ExtractionRequest(BaseModel):
    sample_size: int = Field(default=30, ge=1, le=500)


def _extraction_worker(sample_size: int) -> None:
    from threatgraph.eval.run_extraction_eval import run as run_extraction
    try:
        out = run_extraction(sample_size=sample_size)
        _extraction_job["note"] = out.get("note")
    except Exception as exc:
        _extraction_job["error"] = str(exc)
    finally:
        _extraction_job["running"] = False


@app.post("/api/extraction/run")
def run_extraction(req: ExtractionRequest):
    if _extraction_job["running"]:
        raise HTTPException(409, "An extraction evaluation is already running.")
    _extraction_job.update(running=True, error=None, note=None)
    threading.Thread(target=_extraction_worker, args=(req.sample_size,), daemon=True).start()
    return {"job": dict(_extraction_job)}


# --------------------------------------------------------------------------
# Built frontend
# --------------------------------------------------------------------------

from threatgraph.api.pillars import router as pillars_router  # noqa: E402

app.include_router(pillars_router)

_DIST = REPO_ROOT / "frontend" / "dist"
if _DIST.exists():
    app.mount("/", StaticFiles(directory=_DIST, html=True), name="frontend")
