"""RAGAS evaluation wrapper.

IMPORTANT - environment isolation: ragas 0.2.15 (the version pinned here)
and its langchain dependency chain conflict with this project's main
dependencies in a single environment (ragas unconditionally imports
langchain_community.chat_models.vertexai, which was removed in current
langchain-community releases; resolving that forces a pre-1.0 langchain
stack incompatible with other packages this project uses). This is a known,
reproducible upstream packaging break in ragas as of the version available
when this project was built, not a bug in this code.

Fix: RAGAS runs in a dedicated virtualenv (.venv-ragas/, built from
requirements-ragas.txt) that does NOT share site-packages with the main
project environment. This module is invoked via that venv's interpreter
(see scripts/run_ragas_eval.sh), reading/writing only JSON files so it has
no import-time dependency on threatgraph.graph (which requires the neo4j
driver, not installed in .venv-ragas). sentence-transformers IS installed in
.venv-ragas (separately from the main environment) so the judge embedding
model below can run locally, with no API key required for it specifically.

Metrics computed (ragas==0.2.15 semantics):
  - Faithfulness:     reference-free. Fraction of claims in the generated
                       answer that are supported by the retrieved context.
                       Does NOT use the gold reference answer.
  - Answer Relevancy:  reference-free. How directly the answer addresses the
                       question, via generated-question / original-question
                       embedding similarity. Does NOT use retrieved context
                       or the gold reference answer.
  - Context Precision: reference-based (uses `reference` field). Whether
                       relevant retrieved chunks are ranked near the top.
  - Context Recall:    reference-based (uses `reference` field). Whether the
                       retrieved context contains the information needed to
                       support the reference answer.

Context Precision and Context Recall require the gold reference answer and
are therefore computed only for scoring, never exposed to the RAG systems
being evaluated (see data/eval_queries.json / benchmark-leakage note in
scripts/build_benchmarks.py and the top-level README).
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

try:
    from dotenv import load_dotenv
    # Deliberately not importing threatgraph.config here (see module
    # docstring: this module must stay importable without neo4j/
    # sentence-transformers), so .env needs its own explicit load.
    load_dotenv(Path(__file__).resolve().parents[3] / ".env")
except ImportError:
    pass

from datasets import Dataset
from ragas import evaluate
from ragas.embeddings import LangchainEmbeddingsWrapper
from ragas.llms import LangchainLLMWrapper
from ragas.metrics import AnswerRelevancy, ContextPrecision, ContextRecall, Faithfulness


def _judge_llm():
    # RAGAS_JUDGE_PROVIDER is deliberately separate from LLM_PROVIDER (used
    # by extraction/generation): judging fans out into many more LLM calls
    # per item than a single answer does, so it's common to want a
    # different, cheaper, or separately-quota'd provider just for judging.
    provider = os.environ.get("RAGAS_JUDGE_PROVIDER", os.environ.get("LLM_PROVIDER", "anthropic"))
    model = os.environ.get("RAGAS_JUDGE_MODEL", os.environ.get("LLM_MODEL", "claude-sonnet-5"))
    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise RuntimeError("ANTHROPIC_API_KEY is required to run RAGAS evaluation.")
        return LangchainLLMWrapper(ChatAnthropic(model=model, temperature=0))
    if provider == "gemini":
        from langchain_google_genai import ChatGoogleGenerativeAI
        if not os.environ.get("GEMINI_API_KEY"):
            raise RuntimeError("GEMINI_API_KEY is required to run RAGAS evaluation.")
        return LangchainLLMWrapper(ChatGoogleGenerativeAI(
            model=model, temperature=0, google_api_key=os.environ["GEMINI_API_KEY"]))
    from langchain_openai import ChatOpenAI
    if not os.environ.get("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY is required to run RAGAS evaluation.")
    return LangchainLLMWrapper(ChatOpenAI(model=model, temperature=0))


def _judge_embeddings():
    # Default: the same local sentence-transformers model the rest of this
    # project uses for retrieval, via langchain_community's wrapper -- so
    # RAGAS's answer_relevancy metric needs no API key at all. Set
    # RAGAS_EMBEDDING_PROVIDER=openai to use a hosted embedding model
    # instead (then OPENAI_API_KEY is required, independent of which
    # LLM_PROVIDER judges faithfulness/relevancy text).
    provider = os.environ.get("RAGAS_EMBEDDING_PROVIDER", "local")
    if provider == "openai":
        from langchain_openai import OpenAIEmbeddings
        if not os.environ.get("OPENAI_API_KEY"):
            raise RuntimeError(
                "OPENAI_API_KEY is required when RAGAS_EMBEDDING_PROVIDER=openai."
            )
        return LangchainEmbeddingsWrapper(OpenAIEmbeddings(model="text-embedding-3-small"))

    from langchain_community.embeddings import HuggingFaceEmbeddings
    default_model = "sentence-transformers/all-MiniLM-L6-v2"
    model_name = os.environ.get("EMBEDDING_MODEL", default_model)
    # Same pinned weights as threatgraph.config.EmbeddingConfig.revision
    # (duplicated because this module must not import threatgraph.config).
    revision = os.environ.get("EMBEDDING_MODEL_REVISION",
                              "1110a243fdf4706b3f48f1d95db1a4f5529b4d41" if model_name == default_model else "main")
    return LangchainEmbeddingsWrapper(HuggingFaceEmbeddings(model_name=model_name,
                                                            model_kwargs={"revision": revision}))


def run_ragas(records_path: str, output_path: str) -> dict:
    """records_path: JSON list of
        {"user_input", "response", "retrieved_contexts": [str, ...], "reference": str}
    (ragas 0.2.x's SingleTurnSample column names) one per evaluated (system,
    query) pair, built by threatgraph.eval.build_ragas_records (which runs in
    the main venv, from run_experiments.py's raw output).
    """
    records = json.loads(Path(records_path).read_text(encoding="utf-8"))
    dataset = Dataset.from_list(records)

    llm = _judge_llm()
    embeddings = _judge_embeddings()
    metrics = [
        Faithfulness(llm=llm),
        AnswerRelevancy(llm=llm, embeddings=embeddings),
        ContextPrecision(llm=llm),
        ContextRecall(llm=llm),
    ]
    # RAGAS defaults to max_workers=16 concurrent judge calls, which
    # massively exceeds Gemini's free-tier per-minute rate limit (15
    # req/min for gemini-3.1-flash-lite) and causes most calls to time out
    # rather than queue -- an initial run with the default config only got
    # usable scores for 3-19 of 60 records per metric. A low worker count
    # paces requests within the actual provider limit instead.
    from ragas.run_config import RunConfig
    run_config = RunConfig(
        max_workers=int(os.environ.get("RAGAS_MAX_WORKERS", "2")),
        timeout=int(os.environ.get("RAGAS_TIMEOUT_SECONDS", "300")),
        max_retries=int(os.environ.get("RAGAS_MAX_RETRIES", "15")),
        max_wait=int(os.environ.get("RAGAS_MAX_WAIT_SECONDS", "90")),
    )
    result = evaluate(dataset, metrics=metrics, run_config=run_config)
    df = result.to_pandas()

    metric_cols = ("faithfulness", "answer_relevancy", "context_precision", "context_recall")
    summary = {
        "n_records": len(records),
        "judge_model": os.environ.get("RAGAS_JUDGE_MODEL", os.environ.get("LLM_MODEL", "claude-sonnet-5")),
        "ragas_version": __import__("ragas").__version__,
        "run_config": {"max_workers": run_config.max_workers, "timeout": run_config.timeout,
                        "max_retries": run_config.max_retries, "max_wait": run_config.max_wait},
        # n_successful/n_failed are reported per metric (not just a pooled
        # mean) because RAGAS silently scores a failed judge call as NaN --
        # a mean computed over a small surviving subset is not the same
        # claim as a mean over all n_records, and reporting only the mean
        # would obscure how much data actually went into it.
        "mean_scores": {col: round(float(df[col].mean()), 4) for col in metric_cols if col in df.columns},
        "n_successful": {col: int(df[col].notna().sum()) for col in metric_cols if col in df.columns},
        "n_failed": {col: int(df[col].isna().sum()) for col in metric_cols if col in df.columns},
    }
    Path(output_path).write_text(json.dumps(summary, indent=2), encoding="utf-8")
    df.to_csv(Path(output_path).with_suffix(".per_record.csv"), index=False)
    return summary


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("records_json")
    p.add_argument("output_json")
    args = p.parse_args()
    out = run_ragas(args.records_json, args.output_json)
    print(json.dumps(out, indent=2))
