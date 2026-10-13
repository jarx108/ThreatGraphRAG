"""Write results/experiment_config.json: a record of the exact configuration
used for a run (models, chunking/retrieval parameters, dataset sizes, STIX
version), so results are reproducible and auditable independent of whether
the run itself used real or dry-run generation."""
from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
from datetime import datetime, timezone

from threatgraph.config import (
    ATTACK_STIX_SHA256,
    ATTACK_STIX_URL,
    ATTACK_STIX_VERSION,
    CHUNKING,
    DATA_DIR,
    EMBEDDING,
    LLM,
    REPO_ROOT,
    RESULTS_DIR,
    RETRIEVAL,
)


def _git_commit() -> str | None:
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True)
        dirty = subprocess.run(["git", "status", "--porcelain"], cwd=REPO_ROOT, capture_output=True, text=True)
    except OSError:
        return None
    if out.returncode != 0:
        return None
    return out.stdout.strip() + ("-dirty" if dirty.stdout.strip() else "")


def _sha256_file(path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None


def build_config() -> dict:
    gold = json.loads((DATA_DIR / "gold_triples.json").read_text(encoding="utf-8"))
    queries = json.loads((DATA_DIR / "eval_queries.json").read_text(encoding="utf-8"))
    by_category = {}
    for q in queries:
        by_category[q.get("category", "unknown")] = by_category.get(q.get("category", "unknown"), 0) + 1

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "git_commit": _git_commit(),
        "requirements_lock_sha256": _sha256_file(REPO_ROOT / "requirements.lock"),
        "dataset": {
            "source": "MITRE ATT&CK Enterprise STIX",
            "pinned_version": ATTACK_STIX_VERSION,
            "source_url": ATTACK_STIX_URL,
            "content_sha256": ATTACK_STIX_SHA256,
            "n_gold_triples": len(gold),
            "n_eval_queries": len(queries),
            "eval_queries_by_category": by_category,
        },
        "llm": {
            "provider": LLM.provider,
            "generation_model": LLM.model,
            "extraction_model": LLM.extraction_model,
            "ragas_judge_model": LLM.judge_model,
            "max_tokens": LLM.max_tokens,
            "temperature": LLM.temperature,
            "seed": LLM.seed,
            "ragas_judge_provider": os.environ.get("RAGAS_JUDGE_PROVIDER", LLM.provider),
        },
        "embedding": {
            "provider": EMBEDDING.provider,
            "model": EMBEDDING.model_name,
            "revision": EMBEDDING.revision,
            "dimensions": EMBEDDING.dimensions,
        },
        "chunking": {
            "chunk_size_chars": CHUNKING.chunk_size,
            "chunk_overlap_chars": CHUNKING.chunk_overlap,
            "method": "character-based sliding window (not token-based)",
        },
        "retrieval": {
            "top_k_chunks": RETRIEVAL.top_k_chunks,
            "max_hops": RETRIEVAL.max_hops,
            "max_graph_facts": RETRIEVAL.max_graph_facts,
        },
    }


if __name__ == "__main__":
    RESULTS_DIR.mkdir(exist_ok=True)
    cfg = build_config()
    (RESULTS_DIR / "experiment_config.json").write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    print(json.dumps(cfg, indent=2))
