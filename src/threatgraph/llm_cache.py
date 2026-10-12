"""Persistent cache of LLM responses and RAGAS judge scores.

Why: generation and judging are the slow, rate-limited, paid steps. Asking
the same question again (in the UI, a resumed benchmark, a re-run
extraction evaluation) should not call the provider again when the request
is byte-for-byte the same as one already answered.

What counts as "the same request" (the cache key):
  - LLM responses:  provider, model, system prompt, user prompt, temperature,
    max_tokens. The user prompt contains the full retrieved context, so a
    cached answer is only reused when retrieval returned exactly the same
    evidence. LLM_SEED is deliberately not part of the key: it is a
    best-effort hint providers may ignore, and at temperature 0 it does not
    change what is being asked.
  - RAGAS scores:   question, answer, retrieved contexts, reference answer,
    and the judge configuration (provider, model, embeddings, RAGAS pins).
    Only complete score sets are cached, so failed judge calls are retried.

Honesty for the paper: a cache hit is flagged (LLMResponse.cached,
RAGResult.generation_cached) and carries the latency, token counts and cost
that were measured when the response was really generated, so latency
statistics are never polluted with ~0 s cache reads.

Disable entirely with LLM_CACHE=0; bypass reads for one block of code with
`with llm_cache.bypass(): ...` (fresh call, result still stored).
Storage: data/cache/llm_responses.sqlite (gitignored, like the STIX cache).

CLI:
  python -m threatgraph.llm_cache stats
  python -m threatgraph.llm_cache import-experiments   # reuse results/raw_experiment_results.json
  python -m threatgraph.llm_cache clear [--namespace llm|ragas]
"""
from __future__ import annotations

import contextvars
import hashlib
import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator, Optional

from threatgraph.config import CACHE_DIR

CACHE_PATH = CACHE_DIR / "llm_responses.sqlite"
_bypass: contextvars.ContextVar[bool] = contextvars.ContextVar("llm_cache_bypass", default=False)
_init_lock = threading.Lock()
_initialized_paths: set[str] = set()


def enabled() -> bool:
    return os.environ.get("LLM_CACHE", "1") != "0"


def reads_enabled() -> bool:
    return enabled() and not _bypass.get()


@contextmanager
def bypass() -> Iterator[None]:
    """Force fresh calls inside this block (results are still cached)."""
    token = _bypass.set(True)
    try:
        yield
    finally:
        _bypass.reset(token)


def make_key(namespace: str, payload: dict) -> str:
    canonical = json.dumps({"ns": namespace, **payload}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _connect() -> sqlite3.Connection:
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(CACHE_PATH, timeout=30)
    path = str(CACHE_PATH)
    if path not in _initialized_paths:
        with _init_lock:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS entries ("
                " key TEXT PRIMARY KEY, namespace TEXT NOT NULL, created_at TEXT NOT NULL,"
                " source TEXT NOT NULL, payload TEXT NOT NULL)"
            )
            conn.commit()
            _initialized_paths.add(path)
    return conn


def get(key: str) -> Optional[dict]:
    if not reads_enabled():
        return None
    with _connect() as conn:
        row = conn.execute("SELECT payload, created_at, source FROM entries WHERE key = ?", (key,)).fetchone()
    if row is None:
        return None
    return {**json.loads(row[0]), "_created_at": row[1], "_source": row[2]}


def put(key: str, namespace: str, payload: dict, source: str = "live",
        created_at: Optional[str] = None, overwrite: bool = True) -> None:
    if not enabled():
        return
    created_at = created_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
    verb = "INSERT OR REPLACE" if overwrite else "INSERT OR IGNORE"
    with _connect() as conn:
        conn.execute(f"{verb} INTO entries (key, namespace, created_at, source, payload) VALUES (?, ?, ?, ?, ?)",
                     (key, namespace, created_at, source, json.dumps(payload, ensure_ascii=False)))


def stats() -> dict:
    if not CACHE_PATH.exists():
        return {"path": str(CACHE_PATH), "entries": 0, "by_namespace_and_source": {}}
    with _connect() as conn:
        rows = conn.execute("SELECT namespace, source, COUNT(*) FROM entries GROUP BY namespace, source "
                            "ORDER BY namespace, source").fetchall()
    return {"path": str(CACHE_PATH), "entries": sum(r[2] for r in rows),
            "by_namespace_and_source": {f"{ns}/{src}": n for ns, src, n in rows}}


def clear(namespace: Optional[str] = None) -> int:
    if not CACHE_PATH.exists():
        return 0
    with _connect() as conn:
        cur = conn.execute("DELETE FROM entries" + (" WHERE namespace = ?" if namespace else ""),
                           (namespace,) if namespace else ())
        return cur.rowcount


# --------------------------------------------------------------------------
# LLM responses
# --------------------------------------------------------------------------

def llm_key(provider: str, model: str, system: str, user: str, max_tokens: int, temperature: float,
            json_schema: dict | None = None) -> str:
    payload = {"provider": provider, "model": model, "system": system, "user": user,
               "max_tokens": max_tokens, "temperature": temperature}
    if json_schema is not None:  # only when used, so existing keys stay valid
        payload["json_schema"] = json_schema
    return make_key("llm", payload)


# --------------------------------------------------------------------------
# Import earlier experiment answers
# --------------------------------------------------------------------------

def import_experiments(raw_path=None, config_path=None) -> dict:
    """Seed the cache with answers from results/raw_experiment_results.json.

    An answer is imported only if re-running today's retrieval (no LLM) for
    that question and system yields exactly the evidence the stored answer
    was generated from (same chunk ids in order, same graph facts in order),
    and the run used the same provider/model/temperature/max_tokens as the
    current configuration. Then today's prompt is identical to the one that
    produced the stored answer, so reusing it is equivalent to a cache hit.
    Everything else is skipped and reported, never approximated.
    """
    from threatgraph.config import LLM, RESULTS_DIR
    from threatgraph.embeddings import get_embedder
    from threatgraph.graph.neo4j_client import Neo4jClient
    from threatgraph.rag.baseline_rag import BaselineRAG
    from threatgraph.rag.common import ANSWER_SYSTEM_PROMPT, build_user_prompt
    from threatgraph.rag.graphrag import ThreatGraphRAG

    raw_path = raw_path or RESULTS_DIR / "raw_experiment_results.json"
    config_path = config_path or RESULTS_DIR / "experiment_config.json"
    records = json.loads(raw_path.read_text(encoding="utf-8"))
    cfg = json.loads(config_path.read_text(encoding="utf-8"))["llm"]
    current = {"provider": LLM.provider, "generation_model": LLM.model,
               "max_tokens": LLM.max_tokens, "temperature": LLM.temperature}
    mismatched = {k: (cfg.get(k), v) for k, v in current.items() if cfg.get(k) != v}
    if mismatched:
        return {"imported": 0, "skipped": len(records) * 2,
                "reason": f"experiment config differs from current config: {mismatched}"}
    created_at = datetime.fromtimestamp(raw_path.stat().st_mtime, timezone.utc).isoformat(timespec="seconds")

    client = Neo4jClient()
    if not client.verify_connectivity():
        raise RuntimeError("Neo4j is required to re-run retrieval for the import.")
    embedder = get_embedder()
    systems = {"baseline": BaselineRAG(client=client, embedder=embedder),
               "threatgraph": ThreatGraphRAG(client=client, embedder=embedder)}
    report = {"imported": 0, "already_cached": 0, "skipped_failed_answer": 0,
              "skipped_retrieval_changed": 0, "details": []}
    try:
        for rec in records:
            for sys_key, system in systems.items():
                stored = rec[sys_key]
                answer = rec.get(f"{sys_key}_answer") or stored.get("answer")
                if stored.get("error") or not answer:
                    report["skipped_failed_answer"] += 1
                    continue
                chunks, facts, context, _ = system.retrieve(rec["question"])
                same = ([c.chunk_id for c in chunks] == [c["chunk_id"] for c in stored["retrieved_chunks"]]
                        and [(f.src_id, f.predicate, f.tgt_id) for f in facts]
                        == [(f["src_id"], f["predicate"], f["tgt_id"]) for f in stored.get("graph_facts", [])])
                if not same:
                    report["skipped_retrieval_changed"] += 1
                    report["details"].append(f"{rec['question_id']}/{sys_key}: retrieval differs today")
                    continue
                key = llm_key(LLM.provider, LLM.model, ANSWER_SYSTEM_PROMPT,
                              build_user_prompt(rec["question"], context), LLM.max_tokens, LLM.temperature)
                with _connect() as conn:
                    exists = conn.execute("SELECT 1 FROM entries WHERE key = ?", (key,)).fetchone()
                if exists:
                    report["already_cached"] += 1
                    continue
                put(key, "llm", {
                    "text": answer,
                    "input_tokens": stored.get("input_tokens", 0),
                    "output_tokens": stored.get("output_tokens", 0),
                    "latency_seconds": stored.get("generation_latency_seconds", 0.0),
                    "estimated_cost_usd": stored.get("estimated_cost_usd"),
                    "model": LLM.model,
                }, source="import:raw_experiment_results", created_at=created_at, overwrite=False)
                report["imported"] += 1
    finally:
        client.close()
    return report


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Manage the LLM / RAGAS response cache.")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("stats")
    sub.add_parser("import-experiments")
    c = sub.add_parser("clear")
    c.add_argument("--namespace", choices=["llm", "ragas"])
    args = p.parse_args()
    if args.cmd == "stats":
        print(json.dumps(stats(), indent=2))
    elif args.cmd == "import-experiments":
        out = import_experiments()
        details = out.pop("details", [])
        print(json.dumps(out, indent=2))
        for d in details:
            print("  -", d)
    else:
        print(f"Removed {clear(args.namespace)} entries.")
