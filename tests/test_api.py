"""API tests that need no Neo4j or LLM: persistence-backed endpoints only."""
import pytest
from fastapi.testclient import TestClient

from threatgraph.api import app as api_module
from threatgraph.eval import ui_eval
from threatgraph.rag.common import RAGResult, RetrievedChunk

client = TestClient(api_module.app)


@pytest.fixture(autouse=True)
def tmp_store(tmp_path, monkeypatch):
    monkeypatch.setattr(ui_eval, "STORE_PATH", tmp_path / "ui_evaluations.json")


def _saved_run(system="baseline", group="g1"):
    run = ui_eval.new_run(RAGResult(
        system=system, question="What is T1055?", answer="Process Injection.",
        retrieved_chunks=[RetrievedChunk("c1", "text", "Process Injection", "T1055", 0.9)],
        total_latency_seconds=1.5,
    ))
    run["group_id"] = group
    ui_eval.save_runs(run)
    return run


def test_runs_include_computed_metrics_with_na_as_null():
    run = _saved_run()
    body = client.get(f"/api/runs?ids={run['id']}").json()
    assert body[0]["metrics"]["total_latency_seconds"] == 1.5
    assert body[0]["metrics"]["faithfulness"] is None
    assert body[0]["metrics"]["factuality"] is None


def test_unknown_run_is_404():
    assert client.get("/api/runs?ids=doesnotexist").status_code == 404


def test_ratings_round_trip_and_validation():
    run = _saved_run()
    res = client.put(f"/api/runs/{run['id']}/ratings", json={"factuality": 5, "completeness": 2})
    assert res.status_code == 200
    assert res.json()["metrics"]["factuality"] == 5
    assert res.json()["human"]["coherence"] is None
    assert client.put(f"/api/runs/{run['id']}/ratings", json={"factuality": 6}).status_code == 422
    assert client.put("/api/runs/nope/ratings", json={"factuality": 3}).status_code == 404


def test_saved_evaluations_group_compare_runs():
    _saved_run("baseline", group="g1")
    _saved_run("threatgraph", group="g1")
    groups = client.get("/api/evaluations").json()
    assert len(groups) == 1
    assert sorted(groups[0]["systems"]) == ["baseline", "threatgraph"]
    assert groups[0]["evaluated"] is False and groups[0]["rated"] is False


def test_benchmark_detail_averages_exclude_missing_values():
    bench = ui_eval.start_benchmark(["Q01"], with_ragas=False)
    b, g = _saved_run("baseline"), _saved_run("threatgraph")

    def fn(store):
        store["benchmarks"][0]["items"]["Q01"] = {
            "question_id": "Q01", "question": "q", "category": None, "required_hops": 2,
            "baseline": b["id"], "threatgraph": g["id"], "ragas_error": None, "quota_error": False}
    ui_eval._modify(fn)
    detail = client.get(f"/api/benchmarks/{bench['id']}").json()
    assert detail["n_done"] == 1
    assert detail["averages"]["baseline"]["total_latency_seconds"] == {"mean": 1.5, "std": None, "n": 1}
    assert detail["averages"]["threatgraph"]["faithfulness"] == {"mean": None, "std": None, "n": 0}
    assert client.get("/api/benchmarks/nope").status_code == 404


def test_ask_validates_input():
    assert client.post("/api/ask", json={"question": "", "systems": ["baseline"]}).status_code == 422
    assert client.post("/api/ask", json={"question": "q", "systems": ["gpt"]}).status_code == 422
