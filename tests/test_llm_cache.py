import json
import time

from threatgraph import llm_cache
from threatgraph.eval import ui_eval
from threatgraph.rag.common import Generation, generate_answer, result_from_generation
from threatgraph.rag.llm_provider import LLMProvider, LLMResponse


class CountingProvider(LLMProvider):
    """LLMProvider with the network call replaced (no API key needed)."""

    def __init__(self):  # noqa: D401 - skip the real client setup
        self.provider, self.model, self.calls = "gemini", "test-model", 0

    def _complete_with_retries(self, system, user, max_tokens, temperature, max_retries):
        self.calls += 1
        return LLMResponse(text=f"answer #{self.calls}", input_tokens=10, output_tokens=5,
                           latency_seconds=42.0, model=self.model, estimated_cost_usd=0.001)


def test_identical_request_is_served_from_cache_with_original_measurements():
    p = CountingProvider()
    first = p.complete("sys", "user prompt")
    second = p.complete("sys", "user prompt")
    assert p.calls == 1
    assert not first.cached and second.cached and second.cached_at
    assert second.text == "answer #1"
    assert second.latency_seconds == 42.0 and second.input_tokens == 10 and second.estimated_cost_usd == 0.001


def test_any_difference_in_the_request_misses():
    p = CountingProvider()
    p.complete("sys", "user prompt")
    p.complete("sys", "user prompt with different evidence")
    p.complete("other system prompt", "user prompt")
    p.complete("sys", "user prompt", temperature=0.7)
    p.complete("sys", "user prompt", max_tokens=17)
    assert p.calls == 5


def test_bypass_forces_a_fresh_call_and_refreshes_the_entry():
    p = CountingProvider()
    p.complete("sys", "u")
    with llm_cache.bypass():
        fresh = p.complete("sys", "u")
    assert p.calls == 2 and not fresh.cached
    assert p.complete("sys", "u").text == "answer #2"


def test_cache_can_be_disabled(monkeypatch):
    monkeypatch.setenv("LLM_CACHE", "0")
    p = CountingProvider()
    p.complete("sys", "u")
    p.complete("sys", "u")
    assert p.calls == 2


def test_cached_generation_reports_original_latency_not_cache_read_time():
    p = CountingProvider()
    generate_answer(p, "q", "ctx")
    gen = generate_answer(p, "q", "ctx")
    assert gen.cached and gen.latency_seconds == 42.0 and gen.wall_seconds < 1
    t_start = time.time() - 0.5 - gen.wall_seconds  # 0.5 s of retrieval already elapsed
    result = result_from_generation("baseline", "q", gen, [], [], 0.5, t_start, "ctx")
    assert result.generation_cached
    assert result.generation_latency_seconds == 42.0
    assert 42.4 < result.total_latency_seconds < 43.5  # retrieval 0.5 + original generation 42


def test_fresh_generation_latency_is_the_measured_wall_time():
    gen = Generation("a", 1, 1, latency_seconds=3.0, estimated_cost_usd=None, cached=False,
                     cached_at=None, wall_seconds=3.0)
    t_start = time.time() - 3.5
    r = result_from_generation("baseline", "q", gen, [], [], 0.5, t_start, "ctx")
    assert 3.4 < r.total_latency_seconds < 3.7 and not r.generation_cached


def _run(question="Which mitigations address T1055?", reference="M1040 Behavior Prevention."):
    return {"id": f"r{abs(hash(question)) % 10**6}", "question": question, "answer": "M1040.",
            "error": None, "reference": reference,
            "retrieved_chunks": [{"chunk_id": "c", "entity_attack_id": "T1055", "entity_name": "PI", "text": "t"}],
            "graph_facts": []}


def _fake_worker(monkeypatch, scores, calls):
    def fake_run(cmd, **kwargs):
        calls.append(json.loads(open(cmd[-2]).read()))
        out = {"judge_provider": "openai", "judge_model": "judge", "embedding_model": "e", "ragas_version": "0.2.15",
               "scores": scores[: len(calls[-1])]}
        open(cmd[-1], "w").write(json.dumps(out))

        class P:
            returncode, stderr, stdout = 0, "", ""
        return P()
    monkeypatch.setattr(ui_eval.subprocess, "run", fake_run)
    monkeypatch.setattr(ui_eval, "RAGAS_PYTHON", ui_eval.Path(__file__))


def test_ragas_scores_are_reused_for_identical_records(monkeypatch):
    calls: list = []
    full = {"faithfulness": 1.0, "answer_relevancy": 0.8, "context_precision": 0.5, "context_recall": 1.0}
    _fake_worker(monkeypatch, [full], calls)
    a, b = _run(), _run()
    ui_eval.run_ragas([a])
    meta = ui_eval.run_ragas([b])
    assert len(calls) == 1                      # second evaluation never invoked the judge
    assert b["ragas"] == full and meta["cached_records"] == 1 and meta["judge_model"] == "judge"


def test_incomplete_ragas_scores_are_not_cached(monkeypatch):
    calls: list = []
    partial = {"faithfulness": 1.0, "answer_relevancy": None, "context_precision": 0.5, "context_recall": 1.0}
    _fake_worker(monkeypatch, [partial], calls)
    ui_eval.run_ragas([_run()])
    ui_eval.run_ragas([_run()])
    assert len(calls) == 2                      # failed judge call is retried, not frozen in the cache
