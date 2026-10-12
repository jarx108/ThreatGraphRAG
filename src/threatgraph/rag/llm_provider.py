"""Pluggable LLM provider for extraction, RAG generation, and RAGAS judging.

Supports "ollama" (local, the default: no API key, no cost), "anthropic",
"openai", and "gemini" via LLM_PROVIDER. No API key is
ever hardcoded; each provider reads its key from the environment
(ANTHROPIC_API_KEY / OPENAI_API_KEY / GEMINI_API_KEY) through
threatgraph.config.LLM.

Cost estimates are approximate. Per-token prices live in
config/pricing.json (editable, NOT hardcoded in this file) because list
prices change over time and vary by account/region; verify against the
provider's current pricing page before citing estimated costs in any
report. If a model is missing from pricing.json, cost is reported as null
rather than guessed.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

_RETRY_DELAY_RE = re.compile(r"retry in (\d+(?:\.\d+)?)s|'retryDelay':\s*'(\d+(?:\.\d+)?)s'", re.IGNORECASE)


def _parse_retry_delay_seconds(exc_text: str) -> Optional[float]:
    """Best-effort extraction of a provider-suggested retry delay (Gemini
    puts this in its 429 body, e.g. "Please retry in 35.8s" / retryDelay:
    '35s'). Returns None if no delay could be parsed."""
    m = _RETRY_DELAY_RE.search(exc_text)
    if not m:
        return None
    return float(m.group(1) or m.group(2))

from threatgraph.config import LLM, REPO_ROOT

PRICING_PATH = REPO_ROOT / "config" / "pricing.json"


@dataclass
class LLMResponse:
    text: str
    input_tokens: int
    output_tokens: int
    latency_seconds: float
    model: str
    estimated_cost_usd: Optional[float]
    # True when served from threatgraph.llm_cache; latency/tokens/cost are
    # then the values measured when the response was originally generated.
    cached: bool = False
    cached_at: Optional[str] = None


def _load_pricing() -> dict:
    if PRICING_PATH.exists():
        return json.loads(PRICING_PATH.read_text(encoding="utf-8"))
    return {}


def _estimate_cost(model: str, input_tokens: int, output_tokens: int) -> Optional[float]:
    pricing = _load_pricing()
    rates = pricing.get(model)
    if not rates:
        return None
    return round(
        input_tokens / 1_000_000 * rates["input_per_mtok_usd"]
        + output_tokens / 1_000_000 * rates["output_per_mtok_usd"],
        6,
    )


class LLMProvider:
    def __init__(self, model: Optional[str] = None):
        self.model = model or LLM.model
        self.provider = LLM.provider
        if self.provider == "ollama":
            self._client = None  # plain HTTP to LLM.ollama_host, see _ollama_chat
            return
        if not LLM.api_key:
            key_var = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY",
                       "gemini": "GEMINI_API_KEY"}.get(self.provider, "? (unknown provider)")
            raise RuntimeError(f"No API key found for provider={self.provider!r}. Export {key_var}.")
        if self.provider == "anthropic":
            import anthropic
            self._client = anthropic.Anthropic(api_key=LLM.api_key)
        elif self.provider == "openai":
            import openai
            self._client = openai.OpenAI(api_key=LLM.api_key)
        elif self.provider == "gemini":
            from google import genai
            self._client = genai.Client(api_key=LLM.api_key)
        else:
            raise ValueError(f"Unsupported LLM_PROVIDER: {self.provider}")

    # A quota/rate-limit error can mean "wait 35 seconds" (per-minute limit)
    # or "wait 20 hours" (daily cap) -- those need very different handling.
    # Above this, retrying isn't practical; the caller gets the exception so
    # it can give up and save partial results instead of blocking for hours.
    MAX_RETRY_DELAY_SECONDS = 120

    def complete(self, system: str, user: str, max_tokens: int = LLM.max_tokens,
                 temperature: float = LLM.temperature, max_retries: int = 5,
                 json_schema: dict | None = None) -> LLMResponse:
        """Cached completion: an identical request (see threatgraph.llm_cache)
        returns the stored response instead of calling the provider.

        `json_schema` (a JSON Schema, e.g. a Pydantic model's
        model_json_schema()) asks the provider to constrain decoding to that
        schema. Ollama enforces it natively; other providers ignore it and
        rely on the caller's validation."""
        from threatgraph import llm_cache

        self._json_schema = json_schema
        key = llm_cache.llm_key(self.provider, self.model, system, user, max_tokens, temperature,
                                json_schema if self.provider == "ollama" else None)
        hit = llm_cache.get(key)
        if hit is not None:
            return LLMResponse(
                text=hit["text"], input_tokens=hit["input_tokens"], output_tokens=hit["output_tokens"],
                latency_seconds=hit["latency_seconds"], model=hit.get("model", self.model),
                estimated_cost_usd=hit.get("estimated_cost_usd"), cached=True, cached_at=hit["_created_at"],
            )
        resp = self._complete_with_retries(system, user, max_tokens, temperature, max_retries)
        llm_cache.put(key, "llm", {
            "text": resp.text, "input_tokens": resp.input_tokens, "output_tokens": resp.output_tokens,
            "latency_seconds": resp.latency_seconds, "estimated_cost_usd": resp.estimated_cost_usd,
            "model": resp.model,
        })
        return resp

    def _complete_with_retries(self, system: str, user: str, max_tokens: int,
                               temperature: float, max_retries: int) -> LLMResponse:
        t0 = time.time()
        attempt = 0
        while True:
            try:
                return self._complete_once(system, user, max_tokens, temperature, t0)
            except Exception as exc:
                exc_text = str(exc)
                attempt += 1
                is_server_overload = any(s in exc_text for s in ("503", "UNAVAILABLE", "overloaded"))
                is_rate_limit = any(s in exc_text for s in ("429", "RESOURCE_EXHAUSTED", "rate_limit"))

                if is_server_overload:
                    if attempt > max_retries:
                        raise
                    time.sleep(min(2 ** attempt, 30))
                    continue

                if is_rate_limit:
                    delay = _parse_retry_delay_seconds(exc_text)
                    # No parseable delay -> treat conservatively as a short
                    # rate limit, not an hours-long quota, and use backoff.
                    effective_delay = delay if delay is not None else min(2 ** attempt, 30)
                    if effective_delay > self.MAX_RETRY_DELAY_SECONDS or attempt > max_retries:
                        raise
                    time.sleep(effective_delay + 1)  # +1s buffer past the provider's own estimate
                    continue

                raise

    def _ollama_chat(self, system: str, user: str, max_tokens: int, temperature: float) -> tuple[str, int, int]:
        import urllib.error
        import urllib.request

        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "stream": False,
            "options": {"temperature": temperature, "seed": LLM.seed, "num_predict": max_tokens,
                        "num_ctx": LLM.ollama_num_ctx},
        }
        if getattr(self, "_json_schema", None) is not None:
            body["format"] = self._json_schema
        req = urllib.request.Request(f"{LLM.ollama_host.rstrip('/')}/api/chat", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=900) as r:
                data = json.loads(r.read())
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"Ollama error {exc.code}: {exc.read().decode(errors='replace')[:300]}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(
                f"Cannot reach Ollama at {LLM.ollama_host} ({exc.reason}). Start it with `ollama serve` "
                f"and pull the model with `ollama pull {self.model}`.") from exc
        return data["message"]["content"], data.get("prompt_eval_count", 0), data.get("eval_count", 0)

    def _complete_once(self, system: str, user: str, max_tokens: int, temperature: float, t0: float) -> LLMResponse:
        if self.provider == "ollama":
            text, in_tok, out_tok = self._ollama_chat(system, user, max_tokens, temperature)
        elif self.provider == "anthropic":
            resp = self._client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                temperature=temperature,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
            text = "".join(block.text for block in resp.content if block.type == "text")
            in_tok, out_tok = resp.usage.input_tokens, resp.usage.output_tokens
        elif self.provider == "gemini":
            from google.genai import types
            resp = self._client.models.generate_content(
                model=self.model,
                contents=user,
                config=types.GenerateContentConfig(
                    system_instruction=system,
                    max_output_tokens=max_tokens,
                    temperature=temperature,
                    seed=LLM.seed,
                    # Disabled: this project's tasks (strict-JSON extraction,
                    # short grounded answers) don't need extended reasoning,
                    # and leaving it on silently ate most of max_output_tokens
                    # as "thinking" tokens, truncating JSON output mid-string.
                    thinking_config=types.ThinkingConfig(thinking_budget=0),
                ),
            )
            text = resp.text or ""
            usage = resp.usage_metadata
            in_tok = usage.prompt_token_count or 0
            # candidates_token_count excludes "thinking" tokens; include them
            # in output-token accounting since they are billed output tokens.
            out_tok = (usage.candidates_token_count or 0) + (usage.thoughts_token_count or 0)
        else:
            resp = self._client.chat.completions.create(
                model=self.model,
                max_tokens=max_tokens,
                temperature=temperature,
                seed=LLM.seed,
                messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            )
            text = resp.choices[0].message.content or ""
            in_tok = resp.usage.prompt_tokens
            out_tok = resp.usage.completion_tokens

        latency = time.time() - t0
        return LLMResponse(
            text=text, input_tokens=in_tok, output_tokens=out_tok,
            latency_seconds=latency, model=self.model,
            estimated_cost_usd=_estimate_cost(self.model, in_tok, out_tok),
        )
