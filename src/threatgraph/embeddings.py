"""Embedding provider abstraction.

Default: sentence-transformers/all-MiniLM-L6-v2, run locally (384 dims, no
API key, no per-call cost, fully reproducible). Set EMBEDDING_PROVIDER=openai
with an OPENAI_API_KEY to use a hosted embedding model instead (see
threatgraph.config.EmbeddingConfig).

Documented choice: a small local model was preferred over a hosted one so
retrieval/indexing/benchmark construction do not depend on a paid API key —
only answer *generation* does. This keeps the extraction-metric and
retrieval parts of the pipeline runnable in any environment.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Protocol

from threatgraph.config import EMBEDDING


class Embedder(Protocol):
    dimensions: int

    def embed(self, texts: list[str]) -> list[list[float]]: ...
    def embed_one(self, text: str) -> list[float]: ...


class SentenceTransformerEmbedder:
    def __init__(self, model_name: str = EMBEDDING.model_name, revision: str = EMBEDDING.revision):
        from sentence_transformers import SentenceTransformer
        # Pinned Hugging Face commit: identical weights in every environment.
        self._model = SentenceTransformer(model_name, revision=revision)
        get_dim = getattr(self._model, "get_embedding_dimension", None) or self._model.get_sentence_embedding_dimension
        self.dimensions = get_dim()

    def embed(self, texts: list[str]) -> list[list[float]]:
        return self._model.encode(texts, show_progress_bar=False, convert_to_numpy=True).tolist()

    def embed_one(self, text: str) -> list[float]:
        return self.embed([text])[0]


class OpenAIEmbedder:
    def __init__(self, model_name: str = "text-embedding-3-small"):
        import openai

        from threatgraph.config import LLM
        api_key = LLM.api_key if LLM.provider == "openai" else None
        import os
        api_key = os.environ.get("OPENAI_API_KEY", api_key)
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY is required for EMBEDDING_PROVIDER=openai")
        self._client = openai.OpenAI(api_key=api_key)
        self._model_name = model_name
        self.dimensions = 1536

    def embed(self, texts: list[str]) -> list[list[float]]:
        resp = self._client.embeddings.create(model=self._model_name, input=texts)
        return [d.embedding for d in resp.data]

    def embed_one(self, text: str) -> list[float]:
        return self.embed([text])[0]


@lru_cache(maxsize=1)
def get_embedder() -> Embedder:
    if EMBEDDING.provider == "openai":
        return OpenAIEmbedder()
    return SentenceTransformerEmbedder()
