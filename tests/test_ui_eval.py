import json

import pytest

from threatgraph.eval import ui_eval
from threatgraph.rag.common import GraphFact, RAGResult, RetrievedChunk

BENCH = [{
    "id": "Q01", "category": "group_technique_mitigation", "required_hops": 2,
    "question": "Which mitigations address the ATT&CK technique Steganography (T1001.002) used by Axiom (G0001)?",
    "expected_answer": {
        "threat_group": {"attack_id": "G0001", "name": "Axiom"},
        "technique": {"attack_id": "T1001.002", "name": "Steganography"},
        "mitigations": [{"attack_id": "M1031", "name": "Network Intrusion Prevention"}],
    },
}]


@pytest.fixture(autouse=True)
def tmp_store(tmp_path, monkeypatch):
    monkeypatch.setattr(ui_eval, "STORE_PATH", tmp_path / "ui_evaluations.json")


def _result(system="baseline", question=BENCH[0]["question"], error=None):
    return RAGResult(
        system=system, question=question, answer="" if error else "M1031 Network Intrusion Prevention.",
        retrieved_chunks=[RetrievedChunk("c1", "Axiom used steganography.", "Axiom", "G0001", 0.9)],
        graph_facts=[GraphFact("M1031", "Network Intrusion Prevention", "Mitigation", "MITIGATES",
                               "T1001.002", "Steganography", "Technique")],
        retrieval_latency_seconds=0.1, generation_latency_seconds=1.0, total_latency_seconds=1.2, error=error,
    )


def test_match_benchmark_is_exact_modulo_case_whitespace_and_trailing_punctuation():
    q = BENCH[0]["question"]
    assert ui_eval.match_benchmark("  " + q.upper().rstrip("?") + "  ", BENCH)["id"] == "Q01"
    # A different (if similar) question must not borrow the reference answer.
    assert ui_eval.match_benchmark(q.replace("Axiom", "APT29"), BENCH) is None


def test_reference_comes_only_from_benchmark():
    run = ui_eval.new_run(_result(), ui_eval.match_benchmark(BENCH[0]["question"], BENCH))
    assert "Network Intrusion Prevention (M1031)" in run["reference"]
    assert ui_eval.new_run(_result(question="What is T1055?"), None)["reference"] is None


def test_unevaluated_and_unrated_metrics_are_none():
    run = ui_eval.new_run(_result(), None)
    for key, _ in ui_eval.RAGAS_METRICS + ui_eval.HUMAN_METRICS:
        assert ui_eval.metric_value(run, key) is None
    assert ui_eval.metric_value(run, "total_latency_seconds") == 1.2


def test_failed_answer_latency_excluded_from_metrics():
    run = ui_eval.new_run(_result(error="boom"), None)
    assert ui_eval.metric_value(run, "total_latency_seconds") is None


def test_run_ragas_maps_scores_by_run_and_skips_failed(monkeypatch):
    ok = ui_eval.new_run(_result(), BENCH[0])
    failed = ui_eval.new_run(_result(system="threatgraph", error="boom"), BENCH[0])
    sent = {}

    def fake_subprocess_run(cmd, **kwargs):
        records = json.loads(open(cmd[-2]).read())
        sent["records"] = records
        out = {"judge_provider": "openai", "judge_model": "judge-x", "embedding_model": "e", "ragas_version": "0.2.15",
               "scores": [{"faithfulness": 0.5, "answer_relevancy": 0.25,
                           "context_precision": None, "context_recall": 1.0}]}
        open(cmd[-1], "w").write(json.dumps(out))

        class P:
            returncode = 0
            stderr = "Exception raised in Job[2]: TimeoutError()\n"
            stdout = ""
        return P()

    monkeypatch.setattr(ui_eval.subprocess, "run", fake_subprocess_run)
    monkeypatch.setattr(ui_eval, "RAGAS_PYTHON", ui_eval.Path(__file__))  # any existing path
    meta = ui_eval.run_ragas([ok, failed])

    assert len(sent["records"]) == 1 and sent["records"][0]["reference"] == ok["reference"]
    assert any("Steganography" in c for c in sent["records"][0]["retrieved_contexts"])
    assert ok["ragas"]["faithfulness"] == 0.5 and ok["ragas"]["context_precision"] is None
    assert all(v is None for v in failed["ragas"].values())
    assert meta["judge_model"] == "judge-x" and meta["errors"] == ["TimeoutError()"]


def test_summarize_excludes_na_instead_of_zero():
    runs = [{"ragas": {"faithfulness": 1.0}}, {"ragas": {"faithfulness": None}}, {"ragas": {"faithfulness": 0.5}}]
    s = ui_eval.summarize(runs, "faithfulness")
    assert s["mean"] == 0.75 and s["n"] == 2
    assert ui_eval.summarize([{"ragas": None}], "faithfulness") == {"mean": None, "std": None, "n": 0}


def test_store_persists_runs_and_human_ratings():
    run = ui_eval.new_run(_result(), None)
    ui_eval.save_runs(run)
    ui_eval.save_human_ratings(run["id"], {"factuality": 4, "completeness": 3, "coherence": None})
    stored = ui_eval.get_run(run["id"])
    assert stored["human"] == {"factuality": 4, "completeness": 3, "coherence": None}
    with pytest.raises(ValueError):
        ui_eval.save_human_ratings(run["id"], {"factuality": 6})


def test_benchmark_items_persist_and_resume(monkeypatch):
    class FakeSystem:
        def __init__(self, name):
            self.name = name

        def answer(self, question):
            return _result(system=self.name, question=question)

    bench = ui_eval.start_benchmark(["Q01", "Q02"], with_ragas=False)
    ui_eval.run_benchmark_question(bench["id"], BENCH[0], FakeSystem("baseline"), FakeSystem("threatgraph"), False)
    ui_eval.finish_benchmark(bench["id"])
    saved = ui_eval.get_benchmark(bench["id"])
    assert list(saved["items"]) == ["Q01"] and saved["finished_at"] is None  # 1 of 2 done -> resumable
    runs = ui_eval.benchmark_runs(saved)
    assert [r["system"] for r in runs["baseline"]] == ["baseline"]
    assert runs["threatgraph"][0]["benchmark_id"] == bench["id"]


def test_extraction_evaluation_recomputes_saved_run():
    ev = ui_eval.extraction_evaluation()
    if ev is None:
        pytest.skip("no saved extraction run")
    m = ev["metrics"]
    assert ev["consistent_with_saved_run"]
    assert m.precision == pytest.approx(m.true_positives / m.n_predicted if m.n_predicted else 0.0)
    assert m.recall == pytest.approx(m.true_positives / m.n_gold)
