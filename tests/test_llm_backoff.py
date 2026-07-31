"""
LLM retry/backoff decision logic -- pure, no network. Every constant is
monkeypatched to near-zero so these tests run in milliseconds regardless of
the real production backoff schedule (BASE_BACKOFF=2s, MAX_BACKOFF=60s).
"""

from __future__ import annotations

import asyncio

import pytest
from google.genai import errors

from kronagent import llm as llm_module
from kronagent.llm import _with_backoff


class FakeApiError(errors.APIError):
    """Bypasses the real constructor (which wants a response object) -- tests
    only need `.code` and a str() representation, matching how the real SDK
    error was driven in earlier live testing this session."""

    def __init__(self, code: int, message: str = "") -> None:
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return self.message


@pytest.fixture(autouse=True)
def fast_backoff(monkeypatch):
    """Every test in this module gets near-zero delays."""
    monkeypatch.setattr(llm_module, "BASE_BACKOFF", 0.001)
    monkeypatch.setattr(llm_module, "MAX_BACKOFF", 0.01)
    monkeypatch.setattr(llm_module, "REQUEST_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr(llm_module, "MAX_RETRIES", 3)
    monkeypatch.setattr(llm_module, "MAX_TIMEOUT_RETRIES", 2)


async def test_success_on_first_try_makes_one_call() -> None:
    calls = {"n": 0}

    async def factory():
        calls["n"] += 1
        return "ok"

    result = await _with_backoff(factory, label="test")
    assert result == "ok"
    assert calls["n"] == 1


async def test_429_is_retried_until_max_retries_then_raises() -> None:
    calls = {"n": 0}

    async def factory():
        calls["n"] += 1
        raise FakeApiError(429, "rate limited")

    with pytest.raises(FakeApiError):
        await _with_backoff(factory, label="test")

    # MAX_RETRIES=3 -> 1 initial + 3 retries = 4 total attempts
    assert calls["n"] == 4


async def test_5xx_is_retried_like_429() -> None:
    calls = {"n": 0}

    async def factory():
        calls["n"] += 1
        if calls["n"] < 3:
            raise FakeApiError(503, "overloaded")
        return "recovered"

    result = await _with_backoff(factory, label="test")
    assert result == "recovered"
    assert calls["n"] == 3


async def test_400_is_not_retried() -> None:
    calls = {"n": 0}

    async def factory():
        calls["n"] += 1
        raise FakeApiError(400, "bad request")

    with pytest.raises(FakeApiError):
        await _with_backoff(factory, label="test")

    assert calls["n"] == 1  # no retry for a non-retryable client error


async def test_daily_quota_429_fails_fast_with_no_retry() -> None:
    """A per-day quota error will not clear within any inline backoff -- must
    raise immediately, not burn ~75s of retries before falling back."""
    calls = {"n": 0}

    async def factory():
        calls["n"] += 1
        raise FakeApiError(429, "Quota exceeded ... quotaId: GenerateRequestsPerDayPerProjectPerModel-FreeTier")

    with pytest.raises(FakeApiError):
        await _with_backoff(factory, label="test")

    assert calls["n"] == 1  # short-circuited -- no retry attempted


async def test_per_minute_429_without_perday_token_is_retried() -> None:
    calls = {"n": 0}

    async def factory():
        calls["n"] += 1
        if calls["n"] < 2:
            raise FakeApiError(429, "Quota exceeded, retry in 5s (per-minute limit)")
        return "ok"

    result = await _with_backoff(factory, label="test")
    assert result == "ok"
    assert calls["n"] == 2


async def test_timeout_is_retried_up_to_max_timeout_retries() -> None:
    calls = {"n": 0}

    async def factory():
        calls["n"] += 1
        await asyncio.sleep(10)  # always exceeds the patched 0.05s timeout

    with pytest.raises(asyncio.TimeoutError):
        await _with_backoff(factory, label="test")

    # MAX_TIMEOUT_RETRIES=2 -> 1 initial + 2 retries = 3 total attempts
    assert calls["n"] == 3


async def test_timeout_then_recovery_succeeds() -> None:
    calls = {"n": 0}

    async def factory():
        calls["n"] += 1
        if calls["n"] == 1:
            await asyncio.sleep(10)  # times out once
        return "recovered"

    result = await _with_backoff(factory, label="test")
    assert result == "recovered"
    assert calls["n"] == 2
