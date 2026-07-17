"""
LLM client for triage enrichment.

Thin async wrapper around the Google GenAI SDK with schema-constrained output
and exponential-backoff retry for free-tier / transient rate limits. The LLM
is used ONLY for reasoning about a detection GuardDuty has already made — it
never selects the concrete resource a containment action targets (those come
from the parsed finding), so a prompt-injection payload in telemetry cannot
redirect an action onto an attacker-chosen resource.

Provider is isolated here; swapping to Anthropic/OpenAI is a change to this one
class.
"""

from __future__ import annotations

import asyncio
import os
import random
from typing import Awaitable, Callable, Optional, TypeVar

from google import genai
from google.genai import errors, types
from pydantic import BaseModel

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

T = TypeVar("T", bound=BaseModel)

MODEL = "gemini-3.5-flash"
MAX_RETRIES = 5          # for 429 / 5xx — routine and expected on the free tier
MAX_TIMEOUT_RETRIES = 1  # for a full-duration hang — a much stronger stall signal;
                          # retrying it 5x at full duration each would block the
                          # sequential pipeline for minutes on one finding
BASE_BACKOFF = 2.0
MAX_BACKOFF = 60.0

# Per-call ceiling. Two layers, deliberately redundant: HttpOptions.timeout is
# passed to the SDK's own HTTP client (best case — a clean transport-level
# timeout), and asyncio.wait_for is an outer guard that forces the coroutine
# to raise even if the SDK's timeout only covers connect (not a stalled read
# with no response ever arriving). Without this, a single stalled request
# blocks the entire sequential pipeline indefinitely — this is not
# hypothetical, it happened in testing: near-zero CPU, no retry log lines, no
# progress for minutes, because nothing had raised yet for the retry loop to
# catch.
REQUEST_TIMEOUT_MS = 45_000
REQUEST_TIMEOUT_SECONDS = REQUEST_TIMEOUT_MS / 1000 + 5  # outer guard, slack for the SDK's own timeout to fire first


async def _with_backoff(factory: Callable[[], Awaitable[T]], *, label: str) -> T:
    attempt = 0
    timeout_attempt = 0
    while True:
        try:
            return await asyncio.wait_for(factory(), timeout=REQUEST_TIMEOUT_SECONDS)
        except (errors.APIError, asyncio.TimeoutError) as exc:
            if isinstance(exc, asyncio.TimeoutError):
                timeout_attempt += 1
                if timeout_attempt > MAX_TIMEOUT_RETRIES:
                    raise
                delay = BASE_BACKOFF
            else:
                status = getattr(exc, "code", None)
                # A daily-quota 429 (free-tier "requests per day") will not clear
                # within any inline backoff — the quota resets on a 24h boundary.
                # Retrying it just delays the inevitable fallback by ~75s per
                # finding. Detect it via the stable `PerDay` quotaId token and
                # fall back immediately; only retry transient per-minute limits.
                if status == 429 and "PerDay" in str(exc):
                    raise
                retryable = status == 429 or (isinstance(status, int) and 500 <= status < 600)
                attempt += 1
                if not retryable or attempt > MAX_RETRIES:
                    raise
                delay = min(BASE_BACKOFF * (2 ** (attempt - 1)), MAX_BACKOFF)
            delay += random.uniform(0, delay * 0.25)
            await asyncio.sleep(delay)


class LLMUnavailableError(RuntimeError):
    """Raised when triage enrichment cannot be produced by the model."""


class GeminiTriageClient:
    def __init__(self, api_key: Optional[str] = None) -> None:
        key = api_key or os.getenv("GEMINI_API_KEY")
        if not key:
            raise LLMUnavailableError("GEMINI_API_KEY is not set")
        self._client = genai.Client(api_key=key)

    async def structured(self, *, system: str, prompt: str, schema: type[T]) -> T:
        config = types.GenerateContentConfig(
            system_instruction=system,
            response_mime_type="application/json",
            response_schema=schema,
            temperature=0.1,
            http_options=types.HttpOptions(timeout=REQUEST_TIMEOUT_MS),
        )
        response = await _with_backoff(
            lambda: self._client.aio.models.generate_content(
                model=MODEL, contents=prompt, config=config
            ),
            label="triage",
        )
        parsed = response.parsed
        if isinstance(parsed, schema):
            return parsed
        if response.text:
            return schema.model_validate_json(response.text)
        raise LLMUnavailableError("model returned no parseable structured output")
