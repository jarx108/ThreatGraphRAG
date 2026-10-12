"""Reproducibility verification: fingerprint every deterministic stage of the
pipeline and compare it against the committed manifest
(reproducibility/manifest.json).

Stages checked (everything upstream of the LLM):
  1. STIX input       canonical content hash == pinned ATTACK_STIX_SHA256
  2. Benchmark files  data/gold_triples.json, data/eval_queries.json bytes
  3. Parsing          entity/relationship sets parsed from STIX
  4. Chunking         every chunk id + text
  5. Embeddings       probe sentences embedded with the pinned model revision
                      (compared with a float tolerance, since BLAS kernels
                      differ slightly across CPUs/OSes)
  6. Graph (Neo4j)    node counts, relationship counts, full edge list hash,
                      and stored chunk embeddings re-computed from chunk text
  7. Retrieval        vector search must equal a brute-force NumPy k-NN for
                      every benchmark question; then both systems' retrieval
                      (vector search + GraphRAG seed
                      selection + graph traversal) for every benchmark
                      question, run twice to also prove run-to-run stability

LLM generation is deliberately not fingerprinted: hosted LLMs are only
best-effort deterministic even at temperature 0 with a seed, so answers are
recorded per run (results/) rather than asserted to be identical.

Usage:
  python -m threatgraph.repro            # verify against the manifest
  python -m threatgraph.repro --write    # (re)generate the manifest
  python -m threatgraph.repro --no-graph # skip the Neo4j-dependent stages
Exit code is 1 if any check fails.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from pathlib import Path
from typing import Callable

from threatgraph.config import ATTACK_STIX_SHA256, DATA_DIR, EMBEDDING, REPO_ROOT, RETRIEVAL

MANIFEST_PATH = REPO_ROOT / "reproducibility" / "manifest.json"
FLOAT_TOLERANCE = 1e-4
EMBEDDING_PROBES = [
    "Which mitigations address Process Injection (T1055)?",
    "APT29 uses spearphishing attachments for initial access.",
    "Network Intrusion Prevention can detect steganographic command and control traffic.",
]
N_CHUNK_EMBEDDING_SAMPLES = 25


def _sha256(obj) -> str:
    data = obj if isinstance(obj, bytes) else json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------
# Fingerprints
# --------------------------------------------------------------------------

def fingerprint_offline() -> dict:
    from threatgraph.embeddings import get_embedder
    from threatgraph.ingestion.chunking import chunk_all
    from threatgraph.ingestion.stix_loader import bundle_sha256, fetch_bundle, parse_bundle

    bundle = fetch_bundle()  # raises if the content hash does not match the pin
    pb = parse_bundle(bundle)
    entities = sorted((pe.entity.attack_id, pe.entity.entity_type.value, pe.entity.name)
                      for pe in pb.entities.values())
    relationships = sorted((r.source_stix_id, r.predicate, r.target_stix_id) for r in pb.relationships)
    by_type: dict[str, int] = {}
    for _, etype, _ in entities:
        by_type[etype] = by_type.get(etype, 0) + 1
    chunks = sorted((c.chunk_id, c.text) for c in chunk_all(pb.entities))

    embedder = get_embedder()
    probes = [[round(x, 6) for x in v] for v in embedder.embed(EMBEDDING_PROBES)]

    return {
        "stix": {"content_sha256": bundle_sha256(bundle)},
        "benchmark_files": {
            name: _sha256((DATA_DIR / name).read_bytes())
            for name in ("gold_triples.json", "eval_queries.json")
        },
        "parsed_bundle": {
            "n_entities": len(entities), "n_relationships": len(relationships),
            "entities_by_type": dict(sorted(by_type.items())),
            "entities_sha256": _sha256(entities), "relationships_sha256": _sha256(relationships),
        },
        "chunks": {"n_chunks": len(chunks), "sha256": _sha256(chunks)},
        "embeddings": {"model": EMBEDDING.model_name, "revision": EMBEDDING.revision,
                       "dimensions": len(probes[0]), "probe_vectors": probes},
    }


def fingerprint_graph() -> dict:
    from threatgraph.embeddings import get_embedder
    from threatgraph.graph.neo4j_client import Neo4jClient
    from threatgraph.rag.graphrag import ThreatGraphRAG

    client = Neo4jClient()
    if not client.verify_connectivity():
        raise RuntimeError("Cannot connect to Neo4j (check NEO4J_* in .env and that the database is running).")
    try:
        node_counts = {r["label"]: r["n"] for r in client.run(
            "MATCH (n) RETURN labels(n)[0] AS label, count(*) AS n ORDER BY label")}
        # LLM-extracted edges (source='llm_extraction', make ingest-text) depend
        # on model output, so only the deterministic graph is fingerprinted:
        # the STIX facts with their provenance, plus the structural edges.
        rel_counts = {r["type"]: r["n"] for r in client.run(
            "MATCH ()-[r]->() WHERE coalesce(r.source, '') <> 'llm_extraction' "
            "RETURN type(r) AS type, count(*) AS n ORDER BY type")}
        edges = [tuple(r.values()) for r in client.run(
            "MATCH (a)-[r]->(b) WHERE coalesce(r.source, '') <> 'llm_extraction' "
            "WITH coalesce(a.attack_id, a.chunk_id, a.document_id) AS s, type(r) AS p, "
            "     coalesce(b.attack_id, b.chunk_id, b.document_id) AS o, "
            "     r.stix_relationship_id AS rid, toString(r.modified) AS modified, r.confidence AS conf "
            "RETURN s, p, o, rid, modified, conf ORDER BY s, p, o, rid")]
        gds = _gds_fingerprint(client)

        # Stored chunk embeddings must equal the pinned model applied to the
        # stored text (checks the graph was built with the same model).
        embedder = get_embedder()
        all_ids = [r["id"] for r in client.run("MATCH (c:Chunk) RETURN c.chunk_id AS id ORDER BY id")]
        step = max(1, len(all_ids) // N_CHUNK_EMBEDDING_SAMPLES)
        sample_ids = all_ids[::step][:N_CHUNK_EMBEDDING_SAMPLES]
        rows = client.run("UNWIND $ids AS id MATCH (c:Chunk {chunk_id: id}) "
                          "RETURN c.chunk_id AS id, c.text AS text, c.embedding AS emb ORDER BY id",
                          {"ids": sample_ids})
        fresh = embedder.embed([r["text"] for r in rows])
        max_diff = max((abs(a - b) for r, f in zip(rows, fresh) for a, b in zip(r["emb"], f)), default=0.0)

        retrieval_runs = [_retrieval_fingerprint(ThreatGraphRAG(client=client, embedder=embedder))
                          for _ in range(2)]
        n_exact = _count_exact_vector_search(client, embedder)
    finally:
        client.close()

    return {
        "graph": {"node_counts": node_counts, "relationship_counts": rel_counts,
                  "n_edges": len(edges), "edges_sha256": _sha256(edges),
                  "stored_vs_recomputed_chunk_embedding_max_abs_diff": max_diff,
                  "n_chunk_embeddings_checked": len(rows)},
        **({"gds": gds} if gds else {}),
        "retrieval": retrieval_runs[0],
        "_retrieval_repeat_identical": _retrieval_equal(retrieval_runs[0], retrieval_runs[1]),
        "_vector_search_exact": n_exact,
    }


def _count_exact_vector_search(client, embedder) -> tuple[int, int]:
    """(questions whose retrieved top-k equals the brute-force NumPy top-k, total)."""
    import numpy as np

    from threatgraph.graph.traversal import vector_search

    rows = client.run("MATCH (c:Chunk) RETURN c.chunk_id AS id, c.embedding AS v ORDER BY id")
    ids = [r["id"] for r in rows]
    m = np.array([r["v"] for r in rows], dtype=float)
    m /= np.linalg.norm(m, axis=1, keepdims=True)
    questions = json.loads((DATA_DIR / "eval_queries.json").read_text(encoding="utf-8"))
    n_ok = 0
    for q in questions:
        v = np.array(embedder.embed_one(q["question"]), dtype=float)
        sims = m @ (v / np.linalg.norm(v))
        exact = {ids[i] for i in np.argsort(-sims)[:RETRIEVAL.top_k_chunks]}
        got = {r["chunk_id"] for r in vector_search(client, v.tolist(), k=RETRIEVAL.top_k_chunks)}
        n_ok += got == exact
    return n_ok, len(questions)


def _gds_fingerprint(client) -> dict | None:
    """Results of `make analytics` (None when it has not been run).
    PageRank is independent of node order and compared exactly (rounded);
    Louvain's partition can depend on internal node order, so only its
    community count and modularity are compared, with a tolerance."""
    rows = client.run("MATCH (n) WHERE n.pagerank IS NOT NULL "
                      "RETURN n.attack_id AS id, round(n.pagerank, 4) AS pr, n.degree AS deg, n.component AS comp "
                      "ORDER BY id")
    if not rows:
        return None
    from threatgraph.graph import analytics
    summary = analytics.load() or {}
    return {
        "n_nodes": len(rows),
        "pagerank_degree_sha256": _sha256([(r["id"], r["pr"], r["deg"]) for r in rows]),
        "components": len({r["comp"] for r in rows}),
        "louvain_communities": summary.get("louvain", {}).get("communities"),
        "louvain_modularity": summary.get("louvain", {}).get("modularity"),
    }


def _retrieval_fingerprint(graphrag) -> list[dict]:
    """Exactly the retrieval steps of both systems (System A's retrieval is
    the vector-search step System B also starts with), without the LLM."""
    from threatgraph.graph.traversal import vector_search
    from threatgraph.rag.common import RetrievedChunk

    out = []
    for q in json.loads((DATA_DIR / "eval_queries.json").read_text(encoding="utf-8")):
        rows = vector_search(graphrag._client, graphrag._embedder.embed_one(q["question"]), k=RETRIEVAL.top_k_chunks)
        chunks = [RetrievedChunk(r["chunk_id"], r["text"], r.get("entity_name"), r.get("entity_attack_id"), r["score"])
                  for r in rows]
        graph = graphrag.retrieve_graph(q["question"], chunks)
        out.append({
            "question_id": q["id"],
            "chunk_ids": [c.chunk_id for c in chunks],
            "chunk_scores": [round(c.score, 6) for c in chunks],
            "seeds": [e["attack_id"] for e in graph["linked"]],
            "target": graph["target"],
            "graph_facts": [[f.src_id, f.predicate, f.tgt_id] for f in graph["facts"]],
        })
    return out


def _retrieval_equal(a: list[dict], b: list[dict]) -> bool:
    strip = lambda rs: [{k: v for k, v in r.items() if k != "chunk_scores"} for r in rs]  # noqa: E731
    scores_close = all(abs(x - y) <= FLOAT_TOLERANCE
                       for ra, rb in zip(a, b) for x, y in zip(ra["chunk_scores"], rb["chunk_scores"]))
    return strip(a) == strip(b) and scores_close


# --------------------------------------------------------------------------
# Comparison
# --------------------------------------------------------------------------

def _max_vec_diff(a: list[list[float]], b: list[list[float]]) -> float:
    if len(a) != len(b) or any(len(x) != len(y) for x, y in zip(a, b)):
        return float("inf")
    return max(abs(x - y) for va, vb in zip(a, b) for x, y in zip(va, vb))


def compare(expected: dict, actual: dict) -> list[tuple[str, str, str]]:
    """Return [(check, status, detail)] with status PASS / FAIL / SKIP."""
    results: list[tuple[str, str, str]] = []

    def check(name: str, section: str, fn: Callable[[dict, dict], tuple[bool, str]]):
        if section not in actual:
            results.append((name, "SKIP", f"{section} not computed in this run"))
        elif section not in expected:
            results.append((name, "SKIP", f"{section} missing from manifest"))
        else:
            ok, detail = fn(expected[section], actual[section])
            results.append((name, "PASS" if ok else "FAIL", detail))

    check("STIX content hash", "stix", lambda e, a: (
        a["content_sha256"] == e["content_sha256"] == ATTACK_STIX_SHA256, a["content_sha256"][:16]))
    check("Benchmark files", "benchmark_files", lambda e, a: (
        a == e, ", ".join(f"{k}={v[:12]}" for k, v in a.items())))
    check("Parsed entities/relationships", "parsed_bundle", lambda e, a: (
        a == e, f"{a['n_entities']} entities, {a['n_relationships']} relationships"))
    check("Chunks", "chunks", lambda e, a: (a == e, f"{a['n_chunks']} chunks"))

    def emb(e, a):
        same_model = (a["model"], a["revision"], a["dimensions"]) == (e["model"], e["revision"], e["dimensions"])
        diff = _max_vec_diff(e["probe_vectors"], a["probe_vectors"])
        return same_model and diff <= FLOAT_TOLERANCE, f"{a['model']}@{a['revision'][:10]}, max |diff| {diff:.2e}"
    check("Embeddings", "embeddings", emb)

    def graph(e, a):
        same = all(a[k] == e[k] for k in ("node_counts", "relationship_counts", "n_edges", "edges_sha256"))
        emb_ok = a["stored_vs_recomputed_chunk_embedding_max_abs_diff"] <= FLOAT_TOLERANCE
        return same and emb_ok, (f"{sum(a['node_counts'].values())} nodes, {a['n_edges']} edges, stored chunk "
                                 f"embeddings max |diff| {a['stored_vs_recomputed_chunk_embedding_max_abs_diff']:.2e}")
    check("Neo4j graph", "graph", graph)

    def gds(e, a):
        ok = (a["n_nodes"] == e["n_nodes"] and a["pagerank_degree_sha256"] == e["pagerank_degree_sha256"]
              and a["components"] == e["components"]
              and abs((a["louvain_communities"] or 0) - (e["louvain_communities"] or 0)) <= 1
              and abs((a["louvain_modularity"] or 0) - (e["louvain_modularity"] or 0)) <= 0.01)
        return ok, (f"PageRank/degree of {a['n_nodes']} nodes, {a['components']} component(s), "
                    f"{a['louvain_communities']} communities (modularity {a['louvain_modularity']})")
    if "gds" in actual or "gds" in expected:
        check("GDS analytics", "gds", gds)

    check("Retrieval vs manifest", "retrieval", lambda e, a: (
        _retrieval_equal(e, a), f"{len(a)} benchmark questions, both systems' retrieval"))
    if "_vector_search_exact" in actual:
        ok_n, total = actual["_vector_search_exact"]
        results.append(("Vector search exactness", "PASS" if ok_n == total else "FAIL",
                        f"top-{RETRIEVAL.top_k_chunks} equals brute-force k-NN for {ok_n}/{total} questions"))
    if "_retrieval_repeat_identical" in actual:
        ok = actual["_retrieval_repeat_identical"]
        results.append(("Retrieval run-to-run", "PASS" if ok else "FAIL", "same process, two passes"))
    return results


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--write", action="store_true", help="write the manifest instead of verifying")
    p.add_argument("--no-graph", action="store_true", help="skip Neo4j-dependent checks")
    args = p.parse_args(argv)

    print("Fingerprinting ingestion, chunking and embeddings...")
    actual = fingerprint_offline()
    if not args.no_graph:
        print("Fingerprinting Neo4j graph and retrieval...")
        actual.update(fingerprint_graph())

    if args.write:
        if not args.no_graph and not actual["_retrieval_repeat_identical"]:
            print("Refusing to write: retrieval differed between two identical passes.")
            return 1
        manifest = {k: v for k, v in actual.items() if not k.startswith("_")}
        manifest["_generated_with"] = {"python": platform.python_version(), "platform": platform.platform()}
        MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
        MANIFEST_PATH.write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
        print(f"Wrote {MANIFEST_PATH.relative_to(REPO_ROOT)}")
        return 0

    if not MANIFEST_PATH.exists():
        print(f"No manifest at {MANIFEST_PATH}; run with --write first.")
        return 1
    expected = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    results = compare(expected, actual)
    width = max(len(n) for n, _, _ in results)
    for name, status, detail in results:
        print(f"  [{status}] {name.ljust(width)}  {detail}")
    gen = expected.get("_generated_with", {})
    print(f"Manifest generated on Python {gen.get('python')} / {gen.get('platform')}; "
          f"this run: Python {platform.python_version()} / {platform.platform()}")
    failed = [n for n, s, _ in results if s == "FAIL"]
    print("REPRODUCIBLE" if not failed else f"NOT REPRODUCIBLE: {', '.join(failed)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
