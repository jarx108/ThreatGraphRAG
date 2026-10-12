import pytest

from threatgraph import llm_cache


@pytest.fixture(autouse=True)
def isolated_llm_cache(tmp_path, monkeypatch):
    """Never read or write the real data/cache/llm_responses.sqlite in tests."""
    monkeypatch.setattr(llm_cache, "CACHE_PATH", tmp_path / "llm_cache.sqlite")
    monkeypatch.delenv("LLM_CACHE", raising=False)
