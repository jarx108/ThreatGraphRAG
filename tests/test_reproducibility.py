import json
import re

from threatgraph import repro
from threatgraph.config import ATTACK_STIX_SHA256, EMBEDDING
from threatgraph.graph import traversal
from threatgraph.ingestion.chunking import split_text
from threatgraph.ingestion.stix_loader import bundle_sha256


def test_bundle_hash_ignores_formatting_and_key_order():
    a = {"type": "bundle", "objects": [{"id": "x", "name": "Axiom"}]}
    b = json.loads(json.dumps({"objects": [{"name": "Axiom", "id": "x"}], "type": "bundle"}, indent=4))
    assert bundle_sha256(a) == bundle_sha256(b)
    assert bundle_sha256(a) != bundle_sha256({**a, "type": "other"})


def test_pins_are_exact():
    assert re.fullmatch(r"[0-9a-f]{64}", ATTACK_STIX_SHA256)
    assert re.fullmatch(r"[0-9a-f]{40}", EMBEDDING.revision)  # a commit, not a branch like "main"


def test_every_limited_graph_query_is_ordered():
    # LIMIT / slicing without ORDER BY returns storage-order-dependent rows,
    # i.e. different GraphRAG evidence on different Neo4j instances.
    for name in ("VECTOR_SEARCH_QUERY", "GROUP_TECHNIQUE_MITIGATION_QUERY",
                 "BOUNDED_NEIGHBORHOOD_QUERY", "GENERIC_BOUNDED_PATHS_QUERY"):
        q = getattr(traversal, name)
        if "LIMIT" in q or "collect(" in q:
            assert "ORDER BY" in q, name
    assert traversal.GENERIC_BOUNDED_PATHS_QUERY.count("ORDER BY") == 2  # one per collect()


def test_chunking_is_deterministic():
    text = "Lorem ipsum dolor sit amet. " * 200
    assert split_text(text, 750, 100) == split_text(text, 750, 100)


def _manifest():
    return {
        "stix": {"content_sha256": ATTACK_STIX_SHA256},
        "chunks": {"n_chunks": 2, "sha256": "abc"},
        "embeddings": {"model": "m", "revision": "r", "dimensions": 2, "probe_vectors": [[0.1, 0.2]]},
        "retrieval": [{"question_id": "Q01", "chunk_ids": ["a", "b"], "chunk_scores": [0.9, 0.8],
                       "seeds": ["G0001"], "graph_facts": [["G0001", "USES", "T1001"]]}],
    }


def test_compare_passes_identical_and_tolerates_float_noise():
    expected = _manifest()
    actual = json.loads(json.dumps(expected))
    actual["embeddings"]["probe_vectors"] = [[0.10003, 0.2]]
    actual["retrieval"][0]["chunk_scores"] = [0.90004, 0.8]
    results = {name: status for name, status, _ in repro.compare(expected, actual)}
    assert results["STIX content hash"] == "PASS"
    assert results["Embeddings"] == "PASS"
    assert results["Retrieval vs manifest"] == "PASS"
    assert results["Neo4j graph"] == "SKIP"  # not computed -> skipped, not silently passed


def test_compare_detects_real_drift():
    expected = _manifest()
    actual = json.loads(json.dumps(expected))
    actual["chunks"]["sha256"] = "different"
    actual["embeddings"]["probe_vectors"] = [[0.2, 0.2]]
    actual["retrieval"][0]["graph_facts"] = [["G0001", "USES", "T9999"]]
    results = {name: status for name, status, _ in repro.compare(expected, actual)}
    assert results["Chunks"] == "FAIL"
    assert results["Embeddings"] == "FAIL"
    assert results["Retrieval vs manifest"] == "FAIL"


def test_committed_manifest_matches_pinned_config():
    manifest = json.loads(repro.MANIFEST_PATH.read_text(encoding="utf-8"))
    assert manifest["stix"]["content_sha256"] == ATTACK_STIX_SHA256
    assert manifest["embeddings"]["revision"] == EMBEDDING.revision
    assert manifest["embeddings"]["model"] == EMBEDDING.model_name
