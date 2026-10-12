"""Central configuration loaded from environment variables.

No API keys or credentials are hardcoded anywhere in this project. Copy
`.env.example` to `.env` and fill in real values, or export the variables
directly in your shell. `.env` is excluded from version control.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = REPO_ROOT / "data"
CACHE_DIR = DATA_DIR / "cache"
CHUNKS_DIR = DATA_DIR / "chunks"
RESULTS_DIR = REPO_ROOT / "results"


@dataclass(frozen=True)
class Neo4jConfig:
    uri: str = field(default_factory=lambda: os.environ.get("NEO4J_URI", "bolt://localhost:7687"))
    user: str = field(default_factory=lambda: os.environ.get("NEO4J_USER", "neo4j"))
    password: str = field(default_factory=lambda: os.environ.get("NEO4J_PASSWORD", ""))
    database: str = field(default_factory=lambda: os.environ.get("NEO4J_DATABASE", "neo4j"))


@dataclass(frozen=True)
class LLMConfig:
    provider: str = field(default_factory=lambda: os.environ.get("LLM_PROVIDER", "ollama"))
    model: str = field(default_factory=lambda: os.environ.get(
        "LLM_MODEL", "llama3.1:8b"))
    extraction_model: str = field(default_factory=lambda: os.environ.get(
        "LLM_EXTRACTION_MODEL", os.environ.get("LLM_MODEL", "llama3.1:8b")))
    judge_model: str = field(default_factory=lambda: os.environ.get(
        "RAGAS_JUDGE_MODEL", os.environ.get("LLM_MODEL", "claude-sonnet-5")))
    max_tokens: int = field(default_factory=lambda: int(os.environ.get("LLM_MAX_TOKENS", "1024")))
    temperature: float = field(default_factory=lambda: float(os.environ.get("LLM_TEMPERATURE", "0.0")))
    # Sent to providers that accept a sampling seed (OpenAI, Gemini); Anthropic
    # has no seed parameter and relies on temperature=0 alone. Even with a
    # seed, hosted LLMs are best-effort deterministic, not bit-exact.
    seed: int = field(default_factory=lambda: int(os.environ.get("LLM_SEED", "13")))
    # Local Ollama server (LLM_PROVIDER=ollama): no API key needed. num_ctx is
    # set explicitly because Ollama's small default context window would
    # silently truncate long GraphRAG prompts.
    ollama_host: str = field(default_factory=lambda: os.environ.get("OLLAMA_HOST", "http://localhost:11434"))
    ollama_num_ctx: int = field(default_factory=lambda: int(os.environ.get("OLLAMA_NUM_CTX", "16384")))

    @property
    def api_key(self) -> str | None:
        if self.provider == "anthropic":
            return os.environ.get("ANTHROPIC_API_KEY")
        if self.provider == "openai":
            return os.environ.get("OPENAI_API_KEY")
        if self.provider == "gemini":
            return os.environ.get("GEMINI_API_KEY")
        return None


DEFAULT_EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
DEFAULT_EMBEDDING_REVISION = "1110a243fdf4706b3f48f1d95db1a4f5529b4d41"


@dataclass(frozen=True)
class EmbeddingConfig:
    # Local, free, reproducible by default so retrieval/indexing need no API key.
    # Set EMBEDDING_PROVIDER=openai to use a hosted embedding model instead.
    provider: str = field(default_factory=lambda: os.environ.get("EMBEDDING_PROVIDER", "sentence-transformers"))
    model_name: str = field(default_factory=lambda: os.environ.get(
        "EMBEDDING_MODEL", DEFAULT_EMBEDDING_MODEL))
    dimensions: int = field(default_factory=lambda: int(os.environ.get("EMBEDDING_DIM", "384")))
    # Exact Hugging Face commit of the embedding model, so every environment
    # downloads identical weights. The default pins all-MiniLM-L6-v2; set
    # EMBEDDING_MODEL_REVISION (or "main") when changing EMBEDDING_MODEL.
    revision: str = field(default_factory=lambda: os.environ.get(
        "EMBEDDING_MODEL_REVISION", DEFAULT_EMBEDDING_REVISION
        if os.environ.get("EMBEDDING_MODEL", DEFAULT_EMBEDDING_MODEL) == DEFAULT_EMBEDDING_MODEL else "main"))


@dataclass(frozen=True)
class ChunkConfig:
    chunk_size: int = field(default_factory=lambda: int(os.environ.get("CHUNK_SIZE", "750")))
    chunk_overlap: int = field(default_factory=lambda: int(os.environ.get("CHUNK_OVERLAP", "100")))


@dataclass(frozen=True)
class RetrievalConfig:
    top_k_chunks: int = field(default_factory=lambda: int(os.environ.get("TOP_K_CHUNKS", "5")))
    max_hops: int = field(default_factory=lambda: int(os.environ.get("MAX_HOPS", "3")))
    # Upper bound on graph facts in a GraphRAG prompt. Question-focused
    # retrieval (traversal.focused_facts) returns only facts on the asked-for
    # path, so this is a safety cap rather than a budget to fill.
    max_graph_facts: int = field(default_factory=lambda: int(os.environ.get("MAX_GRAPH_FACTS", "150")))
    # Fact budget for the generic bounded-neighbourhood fallback.
    neighborhood_facts: int = field(default_factory=lambda: int(os.environ.get("NEIGHBORHOOD_FACTS", "15")))
    use_apoc: bool = field(default_factory=lambda: os.environ.get("GRAPH_TRAVERSAL_USE_APOC", "0") == "1")


NEO4J = Neo4jConfig()
LLM = LLMConfig()
EMBEDDING = EmbeddingConfig()
CHUNKING = ChunkConfig()
RETRIEVAL = RetrievalConfig()

ATTACK_STIX_VERSION = "19.2"
# SHA-256 of the bundle's canonical JSON (sorted keys, compact separators),
# so the check is independent of whitespace/formatting of the cached copy.
# Verified against a fresh download of the URL below on 2026-10-12. The URL
# points at the repo's master branch, so this hash is what guarantees every
# environment ingests byte-identical ATT&CK content.
ATTACK_STIX_SHA256 = "6227cd8ff0e21fc6355dc871dcad6a354b0d36570d2c3b783667577320378730"
ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    f"master/enterprise-attack/enterprise-attack-{ATTACK_STIX_VERSION}.json"
)
