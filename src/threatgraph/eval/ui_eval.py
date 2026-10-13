"""Evaluation backend for the Streamlit UI (app/streamlit_app.py).

Everything the UI shows under "Evaluation Metrics", "Benchmark" and
"Knowledge Extraction Evaluation" is calculated here from real runs:

  - RAGAS (Faithfulness, Answer Relevance, Context Precision, Context
    Recall): scored by threatgraph.eval.ragas_worker in the isolated
    .venv-ragas interpreter, with the same judge LLM, embedding model and
    RAGAS version for both systems. Context Precision/Recall need a verified
    reference answer, which only exists when the question matches a record in
    data/eval_queries.json (built from MITRE ATT&CK STIX by
    scripts/build_benchmarks.py); otherwise they are None ("N/A").
  - Human ratings (Factuality, Completeness, Coherence, 1-5): only ever what
    the user enters in the UI; None until rated.
  - Latency: the RAG system's own measured answer latency. RAGAS evaluation
    time is recorded separately and never added to it.

Runs, ratings and benchmark progress persist to results/ui_evaluations.json
so a page refresh does not lose completed evaluations.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import statistics
import subprocess
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from threatgraph import llm_cache
from threatgraph.config import DATA_DIR, LLM, REPO_ROOT, RESULTS_DIR
from threatgraph.eval.build_ragas_records import build_contexts, render_reference
from threatgraph.eval.run_experiments import _result_to_record
from threatgraph.rag.common import RAGResult

STORE_PATH = RESULTS_DIR / "ui_evaluations.json"
RAGAS_PYTHON = REPO_ROOT / ".venv-ragas" / "bin" / "python"
RAGAS_TIMEOUT_SECONDS = int(os.environ.get("UI_RAGAS_SUBPROCESS_TIMEOUT", "3600"))

RAGAS_METRICS = [
    ("faithfulness", "Faithfulness"),
    ("answer_relevancy", "Answer Relevance"),
    ("context_precision", "Context Precision"),
    ("context_recall", "Context Recall"),
]
HUMAN_METRICS = [
    ("factuality", "Factuality"),
    ("completeness", "Completeness"),
    ("coherence", "Coherence"),
]
SYSTEMS = [("baseline", "Traditional RAG"), ("threatgraph", "GraphRAG")]

_store_lock = threading.Lock()


class EvaluationError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------
# Benchmark matching
# --------------------------------------------------------------------------

def normalize_question(q: str) -> str:
    return re.sub(r"\s+", " ", q.strip().lower()).rstrip(" ?.!")


def load_benchmark() -> list[dict]:
    path = DATA_DIR / "eval_queries.json"
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def match_benchmark(question: str, benchmark: Optional[list[dict]] = None) -> Optional[dict]:
    """Exact (whitespace/case/trailing-punctuation-insensitive) match only:
    a reference answer is attached only when the question really is the
    benchmark question, never by fuzzy similarity."""
    target = normalize_question(question)
    for q in benchmark if benchmark is not None else load_benchmark():
        if normalize_question(q["question"]) == target:
            return q
    return None


def reference_for(bench_item: Optional[dict]) -> Optional[str]:
    if not bench_item or not bench_item.get("expected_answer"):
        return None
    return render_reference(bench_item.get("category", ""), bench_item["expected_answer"])


# --------------------------------------------------------------------------
# Runs
# --------------------------------------------------------------------------

def new_run(result: RAGResult, bench_item: Optional[dict] = None,
            benchmark_id: Optional[str] = None) -> dict:
    rec = _result_to_record(result)
    return {
        "id": uuid.uuid4().hex[:12],
        "created_at": _now(),
        "benchmark_id": benchmark_id,
        "system": result.system,
        "question": result.question,
        "question_id": bench_item["id"] if bench_item else None,
        "llm": f"{LLM.provider}/{LLM.model}",
        "reference": reference_for(bench_item),
        "answer": result.answer,
        "error": result.error,
        "retrieval_latency_seconds": result.retrieval_latency_seconds,
        "generation_latency_seconds": result.generation_latency_seconds,
        "total_latency_seconds": result.total_latency_seconds,
        "estimated_cost_usd": result.estimated_cost_usd,
        "generation_cached": result.generation_cached,
        "generation_cached_at": result.generation_cached_at,
        "retrieved_chunks": rec["retrieved_chunks"],
        "graph_facts": rec["graph_facts"],
        "linked_entities": rec.get("linked_entities", []),
        "target_type": rec.get("target_type"),
        "analytics": rec.get("analytics", {}),
        "ragas": None,       # None = not evaluated yet; dict of metric -> float|None once evaluated
        "ragas_meta": None,
        "human": {k: None for k, _ in HUMAN_METRICS},
    }


def _parse_job_errors(stderr: str) -> list[str]:
    errors = []
    for m in re.finditer(r"Exception raised in Job\[\d+\]: (.+)", stderr):
        msg = m.group(1).strip()[:300]
        if msg not in errors:
            errors.append(msg)
    return errors


def _judge_config() -> dict:
    """Everything that determines a RAGAS score besides the record itself."""
    ragas_pins = (REPO_ROOT / "requirements-ragas.txt")
    return {
        "judge_provider": os.environ.get("RAGAS_JUDGE_PROVIDER", os.environ.get("LLM_PROVIDER", "anthropic")),
        "judge_model": os.environ.get("RAGAS_JUDGE_MODEL", os.environ.get("LLM_MODEL", "claude-sonnet-5")),
        "embedding_provider": os.environ.get("RAGAS_EMBEDDING_PROVIDER", "local"),
        "embedding_model": os.environ.get("EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2"),
        "embedding_revision": os.environ.get("EMBEDDING_MODEL_REVISION", ""),
        "ragas_pins_sha256": hashlib.sha256(ragas_pins.read_bytes()).hexdigest() if ragas_pins.exists() else None,
    }


def _ragas_key(record: dict, judge: dict) -> str:
    return llm_cache.make_key("ragas", {"record": record, "judge": judge})


def _expected_metrics(record: dict) -> list[str]:
    keys = ["faithfulness", "answer_relevancy"]
    return keys + (["context_precision", "context_recall"] if record.get("reference") else [])


def run_ragas(runs: list[dict]) -> dict:
    """Score `runs` (mutated in place) in one RAGAS subprocess call, so
    every run in the call is judged by the identical judge configuration.
    Records already scored with the same judge configuration are served from
    threatgraph.llm_cache instead of calling the judge again.
    Returns the shared metadata (judge, timing, errors)."""
    if not RAGAS_PYTHON.exists():
        raise EvaluationError(
            "RAGAS environment not found (.venv-ragas). Create it once with: "
            "scripts/run_ragas_eval.sh, or python3 -m venv .venv-ragas && "
            ".venv-ragas/bin/pip install -r requirements-ragas.txt && "
            ".venv-ragas/bin/pip install -e . --no-deps"
        )

    to_score = [r for r in runs if not r.get("error") and r.get("answer")]
    records = []
    for r in to_score:
        contexts = build_contexts(r)
        records.append({
            "user_input": r["question"], "response": r["answer"],
            "retrieved_contexts": contexts, "reference": r.get("reference"),
        })

    judge = _judge_config()
    keys = [_ragas_key(rec, judge) for rec in records]
    cached = [llm_cache.get(k) for k in keys]
    todo = [i for i, hit in enumerate(cached) if hit is None]

    t0 = time.time()
    meta: dict = {"evaluated_at": _now(), "errors": [], "cached_records": len(records) - len(todo)}
    worker_out: dict = {"scores": []}
    if todo:
        with tempfile.TemporaryDirectory() as tmp:
            in_path, out_path = Path(tmp) / "in.json", Path(tmp) / "out.json"
            in_path.write_text(json.dumps([records[i] for i in todo]), encoding="utf-8")
            try:
                proc = subprocess.run(
                    [str(RAGAS_PYTHON), "-m", "threatgraph.eval.ragas_worker", str(in_path), str(out_path)],
                    cwd=REPO_ROOT, capture_output=True, text=True, timeout=RAGAS_TIMEOUT_SECONDS,
                )
            except subprocess.TimeoutExpired as exc:
                raise EvaluationError(f"RAGAS evaluation timed out after {RAGAS_TIMEOUT_SECONDS}s") from exc
            if proc.returncode != 0 or not out_path.exists():
                tail = "\n".join((proc.stderr or proc.stdout).strip().splitlines()[-8:])
                raise EvaluationError(f"RAGAS evaluation failed:\n{tail}")
            worker_out = json.loads(out_path.read_text(encoding="utf-8"))
            meta["errors"] = _parse_job_errors(proc.stderr)
    meta["evaluation_seconds"] = round(time.time() - t0, 2)
    any_hit = next((h for h in cached if h is not None), None)
    for k in ("judge_provider", "judge_model", "embedding_model", "ragas_version"):
        meta[k] = worker_out.get(k) or (any_hit or {}).get("meta", {}).get(k)

    scores: list[dict] = [hit["scores"] if hit else {} for hit in cached]
    for i, fresh in zip(todo, worker_out["scores"]):
        scores[i] = fresh
        # Cache only complete score sets; a failed judge call should be retried.
        if all(fresh.get(m) is not None for m in _expected_metrics(records[i])):
            llm_cache.put(keys[i], "ragas", {"scores": fresh, "meta": {
                k: worker_out.get(k) for k in ("judge_provider", "judge_model", "embedding_model", "ragas_version")}})
    scored = dict(zip((r["id"] for r in to_score), scores))
    for r in runs:
        r["ragas"] = scored.get(r["id"], {k: None for k, _ in RAGAS_METRICS})
        r["ragas_meta"] = dict(meta, note=None if r["id"] in scored else "No answer to evaluate (generation failed).")
    return meta


# --------------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------------

def _load_unlocked() -> dict:
    if STORE_PATH.exists():
        try:
            data = json.loads(STORE_PATH.read_text(encoding="utf-8"))
            data.setdefault("runs", {})
            data.setdefault("benchmarks", [])
            return data
        except json.JSONDecodeError:
            # Keep the unreadable file for inspection rather than overwriting it.
            STORE_PATH.rename(STORE_PATH.with_suffix(f".corrupt-{int(time.time())}.json"))
    return {"runs": {}, "benchmarks": []}


def _save_unlocked(store: dict) -> None:
    STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = STORE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(store, indent=2, default=str), encoding="utf-8")
    os.replace(tmp, STORE_PATH)


def load_store() -> dict:
    with _store_lock:
        return _load_unlocked()


def _modify(fn: Callable[[dict], object]):
    with _store_lock:
        store = _load_unlocked()
        out = fn(store)
        _save_unlocked(store)
        return out


def save_runs(*runs: dict) -> None:
    def fn(store):
        for r in runs:
            store["runs"][r["id"]] = r
    _modify(fn)


def get_run(run_id: str) -> Optional[dict]:
    return load_store()["runs"].get(run_id)


def save_human_ratings(run_id: str, ratings: dict) -> None:
    for k, v in ratings.items():
        if k not in dict(HUMAN_METRICS) or (v is not None and v not in (1, 2, 3, 4, 5)):
            raise ValueError(f"Invalid rating {k}={v!r}")

    def fn(store):
        run = store["runs"].get(run_id)
        if run is None:
            raise KeyError(run_id)
        run["human"] = {k: ratings.get(k) for k, _ in HUMAN_METRICS}
        run["human_rated_at"] = _now()
    _modify(fn)


# --------------------------------------------------------------------------
# Benchmark
# --------------------------------------------------------------------------

def start_benchmark(question_ids: list[str], with_ragas: bool) -> dict:
    bench = {
        "id": uuid.uuid4().hex[:12], "started_at": _now(), "finished_at": None,
        "with_ragas": with_ragas, "question_ids": question_ids, "items": {}, "stopped_reason": None,
    }
    _modify(lambda store: store["benchmarks"].append(bench))
    return bench


def get_benchmark(bench_id: str) -> Optional[dict]:
    return next((b for b in load_store()["benchmarks"] if b["id"] == bench_id), None)


def latest_benchmark() -> Optional[dict]:
    benches = load_store()["benchmarks"]
    return benches[-1] if benches else None


def _is_quota_error(err: Optional[str]) -> bool:
    return bool(err) and any(s in err for s in ("RESOURCE_EXHAUSTED", "429", "quota"))


def run_benchmark_question(bench_id: str, q: dict, baseline, graphrag, with_ragas: bool) -> dict:
    """Answer one benchmark question with both systems (expected_answer is
    never shown to either system; it only becomes the RAGAS reference
    afterwards), optionally score with RAGAS, and persist."""
    b_run = new_run(baseline.answer(q["question"]), q, benchmark_id=bench_id)
    g_run = new_run(graphrag.answer(q["question"]), q, benchmark_id=bench_id)
    save_runs(b_run, g_run)  # keep answers even if evaluation fails below

    ragas_error = None
    if with_ragas:
        try:
            run_ragas([b_run, g_run])
            save_runs(b_run, g_run)
        except EvaluationError as exc:
            ragas_error = str(exc)

    item = {
        "question_id": q["id"], "question": q["question"], "category": q.get("category"),
        "required_hops": q.get("required_hops"), "baseline": b_run["id"], "threatgraph": g_run["id"],
        "ragas_error": ragas_error,
        "quota_error": _is_quota_error(b_run["error"]) or _is_quota_error(g_run["error"]),
    }

    def fn(store):
        bench = next(b for b in store["benchmarks"] if b["id"] == bench_id)
        bench["items"][q["id"]] = item
    _modify(fn)
    return item


def finish_benchmark(bench_id: str, stopped_reason: Optional[str] = None) -> None:
    def fn(store):
        bench = next(b for b in store["benchmarks"] if b["id"] == bench_id)
        bench["stopped_reason"] = stopped_reason
        if not stopped_reason and len(bench["items"]) >= len(bench["question_ids"]):
            bench["finished_at"] = _now()
    _modify(fn)


def run_benchmark(bench_id: str, baseline, graphrag,
                  on_progress: Optional[Callable[[int, int, Optional[str], Optional[dict]], None]] = None) -> Optional[str]:
    """Run every not-yet-completed question of a benchmark (so the same call
    also resumes an interrupted one). on_progress(done, total, current_qid,
    last_item) is called before each question and after the last. Returns the
    stop reason, or None if the benchmark completed."""
    bench = get_benchmark(bench_id)
    by_id = {q["id"]: q for q in load_benchmark()}
    pending = [qid for qid in bench["question_ids"] if qid not in bench["items"] and qid in by_id]
    total = len(bench["question_ids"])
    done = len(bench["items"])
    stopped, consecutive_quota, item = None, 0, None
    for qid in pending:
        if on_progress:
            on_progress(done, total, qid, item)
        item = run_benchmark_question(bench_id, by_id[qid], baseline, graphrag, bench["with_ragas"])
        done += 1
        consecutive_quota = consecutive_quota + 1 if item["quota_error"] else 0
        if consecutive_quota >= 2:
            stopped = "Stopped early: the LLM provider quota appears exhausted. Resume later."
            break
    finish_benchmark(bench_id, stopped)
    if on_progress:
        on_progress(done, total, None, item)
    return stopped


def benchmark_runs(bench: dict, store: Optional[dict] = None) -> dict[str, list[dict]]:
    store = store or load_store()
    out: dict[str, list[dict]] = {k: [] for k, _ in SYSTEMS}
    for item in bench["items"].values():
        for key, _ in SYSTEMS:
            run = store["runs"].get(item[key])
            if run:
                out[key].append(run)
    return out


# --------------------------------------------------------------------------
# Metric extraction / aggregation
# --------------------------------------------------------------------------

def metric_value(run: dict, key: str) -> Optional[float]:
    if key == "total_latency_seconds":
        return None if run.get("error") else run.get("total_latency_seconds")
    if key in dict(HUMAN_METRICS):
        return (run.get("human") or {}).get(key)
    return (run.get("ragas") or {}).get(key)


def summarize(runs: list[dict], key: str) -> dict:
    values = [v for v in (metric_value(r, key) for r in runs) if v is not None]
    if not values:
        return {"mean": None, "std": None, "n": 0}
    return {
        "mean": statistics.fmean(values),
        "std": statistics.stdev(values) if len(values) > 1 else None,
        "n": len(values),
    }


# --------------------------------------------------------------------------
# Knowledge extraction
# --------------------------------------------------------------------------

def extraction_evaluation() -> Optional[dict]:
    """Recompute Precision/Recall/F1 from the triples the extraction run
    actually produced (results/extraction_metrics.json, written by
    threatgraph.eval.run_extraction_eval) against the current
    data/gold_triples.json. predicted = TP + FP, where TP = gold - FN."""
    from threatgraph.eval.extraction_metrics import load_gold_triples, score_extractions

    path = RESULTS_DIR / "extraction_metrics.json"
    gold_path = DATA_DIR / "gold_triples.json"
    if not path.exists() or not gold_path.exists():
        return None
    summary = json.loads(path.read_text(encoding="utf-8"))
    gold = load_gold_triples(gold_path)
    fp = {tuple(t) for t in summary.get("false_positive_triples", [])}
    fn = {tuple(t) for t in summary.get("false_negative_triples", [])}
    predicted = fp | (gold - fn)
    metrics = score_extractions(gold, predicted)
    stored = summary.get("metrics", {})
    consistent = all(
        stored.get(k) == getattr(metrics, k)
        for k in ("true_positives", "false_positives", "false_negatives", "n_gold", "n_predicted")
    )
    return {
        "metrics": metrics,
        "consistent_with_saved_run": consistent,
        "model": summary.get("model"),
        "sample_size_succeeded": summary.get("sample_size_succeeded"),
        "sample_size_requested": summary.get("sample_size_requested"),
        "false_positive_breakdown": summary.get("false_positive_breakdown"),
        "errors": summary.get("errors", []),
        "computed_at": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(timespec="seconds"),
    }
