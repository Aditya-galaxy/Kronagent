#!/usr/bin/env python3
"""
Gemini-Powered Incident Response Pipeline
=========================================

An asynchronous, multi-agent incident-response pipeline wired to the official
Google GenAI SDK (`google-genai`). Security telemetry is dropped into an
in-memory asyncio.Queue and processed sequentially through three LLM agents:

    Ingestion -> Triage -> Isolation -> Remediation

Each agent is a `gemini-3.5-flash` call constrained to emit strict, schema-valid
JSON (Pydantic v2 enforcement via `response_schema`). The structured output of
each stage is injected into the prompt of the next, forming a context chain.

Free-tier rate limits (15 RPM) are respected two ways:
  * the ingestion loop emits one incident every 10 seconds, and
  * every model call is wrapped in a custom async exponential-backoff retry
    handler that honors HTTP 429 (RESOURCE_EXHAUSTED) responses.

Requirements: Python 3.12+, pydantic v2, google-genai.
Auth: set the GEMINI_API_KEY environment variable (never hardcode it).
"""

from __future__ import annotations

import asyncio
import os
import random
import sys
import uuid
from datetime import datetime, timezone
from typing import Awaitable, Callable, TypeVar

from google import genai
from google.genai import errors, types
from pydantic import BaseModel, Field

try:
    # Load GEMINI_API_KEY (and any other vars) from a local .env file if present.
    # Optional dependency: if python-dotenv isn't installed, fall back to the
    # process environment only.
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

MODEL = "gemini-3.5-flash"
INGESTION_INTERVAL_SECONDS = 10.0  # one incident / 10s -> 6 RPM, under the 15 RPM cap

# Exponential-backoff tuning for the free-tier 429 handler.
MAX_RETRIES = 5
BASE_BACKOFF_SECONDS = 2.0
MAX_BACKOFF_SECONDS = 60.0

T = TypeVar("T", bound=BaseModel)


# --------------------------------------------------------------------------- #
# Structured logging helper
# --------------------------------------------------------------------------- #

def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3] + "Z"


def log(stage: str, message: str) -> None:
    """Structured, timestamped stdout line: `<time> [STAGE] message`."""
    print(f"{_ts()} [{stage}] {message}", flush=True)


# --------------------------------------------------------------------------- #
# Pydantic schemas — the strict contracts Gemini must satisfy
# --------------------------------------------------------------------------- #

class SecurityLog(BaseModel):
    """A raw security event dropped onto the ingestion queue."""

    incident_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: str = Field(default_factory=_ts)
    source: str
    event_type: str
    raw_event: str


class TriageResult(BaseModel):
    """Triage Agent output schema."""

    is_threat: bool
    threat_category: str
    confidence_score: float = Field(ge=0.0, le=1.0)
    justification: str


class IsolationResult(BaseModel):
    """Isolation Agent output schema."""

    containment_strategy: str
    target_resource: str
    bash_commands: list[str]


class RemediationResult(BaseModel):
    """Remediation Agent output schema."""

    remediation_plan: str
    restoration_steps: list[str]
    verification_check: str


# --------------------------------------------------------------------------- #
# Async exponential-backoff retry wrapper
# --------------------------------------------------------------------------- #

async def with_backoff(
    coro_factory: Callable[[], Awaitable[T]],
    *,
    label: str,
    max_retries: int = MAX_RETRIES,
    base_delay: float = BASE_BACKOFF_SECONDS,
    max_delay: float = MAX_BACKOFF_SECONDS,
) -> T:
    """Invoke an async callable with exponential backoff + jitter.

    Retries on transient failures — specifically HTTP 429 (free-tier rate
    limit / RESOURCE_EXHAUSTED) and 5xx server errors. Non-retryable client
    errors (4xx other than 429) are raised immediately. `coro_factory` must
    return a *fresh* awaitable on each call, since an awaitable can only be
    consumed once.
    """
    attempt = 0
    while True:
        try:
            return await coro_factory()
        except errors.APIError as exc:
            status = getattr(exc, "code", None)
            retryable = status == 429 or (isinstance(status, int) and 500 <= status < 600)
            attempt += 1
            if not retryable or attempt > max_retries:
                raise

            delay = min(base_delay * (2 ** (attempt - 1)), max_delay)
            delay += random.uniform(0, delay * 0.25)  # jitter to avoid thundering herd
            reason = "rate limited (429)" if status == 429 else f"server error ({status})"
            log(
                "RETRY",
                f"{label}: {reason} — backing off {delay:.1f}s "
                f"(attempt {attempt}/{max_retries})",
            )
            await asyncio.sleep(delay)


# --------------------------------------------------------------------------- #
# Agents — each is a structured-output Gemini call
# --------------------------------------------------------------------------- #

class GeminiAgent:
    """Base agent: issues one schema-constrained Gemini call and returns the
    parsed, validated Pydantic instance."""

    def __init__(self, client: genai.Client, *, stage: str, schema: type[T]) -> None:
        self._client = client
        self._stage = stage
        self._schema = schema

    async def _generate(self, prompt: str, system_instruction: str) -> T:
        config = types.GenerateContentConfig(
            system_instruction=system_instruction,
            response_mime_type="application/json",
            response_schema=self._schema,
            temperature=0.2,
        )

        response = await with_backoff(
            lambda: self._client.aio.models.generate_content(
                model=MODEL,
                contents=prompt,
                config=config,
            ),
            label=self._stage,
        )

        # `.parsed` is the SDK-validated Pydantic instance when response_schema
        # is supplied. Guard against an empty/blocked response and re-validate
        # defensively so a malformed payload can never propagate downstream.
        parsed = response.parsed
        if isinstance(parsed, self._schema):
            return parsed
        if response.text:
            return self._schema.model_validate_json(response.text)
        raise errors.UnknownApiResponseError(
            f"{self._stage}: model returned no parseable structured output"
        )


class TriageAgent(GeminiAgent):
    SYSTEM = (
        "You are a senior SOC triage analyst. You receive a raw security log and "
        "assess whether it represents a genuine active threat. Be precise and "
        "conservative: assign a high confidence_score only when the evidence is "
        "unambiguous. Respond ONLY with the required JSON object."
    )

    def __init__(self, client: genai.Client) -> None:
        super().__init__(client, stage="TRIAGE", schema=TriageResult)

    async def run(self, log_event: SecurityLog) -> TriageResult:
        prompt = (
            "Assess the following security log for threat activity.\n\n"
            f"Incident ID: {log_event.incident_id}\n"
            f"Source: {log_event.source}\n"
            f"Event type: {log_event.event_type}\n"
            f"Raw event: {log_event.raw_event}\n"
        )
        return await self._generate(prompt, self.SYSTEM)


class IsolationAgent(GeminiAgent):
    SYSTEM = (
        "You are an infrastructure containment specialist. Given a confirmed "
        "threat and its triage assessment, produce a precise containment plan: "
        "the strategy, the exact target resource, and the concrete bash commands "
        "(AWS CLI / kubectl / iptables as appropriate) to isolate it immediately. "
        "Respond ONLY with the required JSON object."
    )

    def __init__(self, client: genai.Client) -> None:
        super().__init__(client, stage="ISOLATION", schema=IsolationResult)

    async def run(self, log_event: SecurityLog, triage: TriageResult) -> IsolationResult:
        # Triage's structured output is injected verbatim into the context.
        prompt = (
            "A threat has been CONFIRMED and must be contained now.\n\n"
            "=== Original security log ===\n"
            f"Source: {log_event.source}\n"
            f"Event type: {log_event.event_type}\n"
            f"Raw event: {log_event.raw_event}\n\n"
            "=== Triage assessment (upstream agent output) ===\n"
            f"{triage.model_dump_json(indent=2)}\n\n"
            "Produce the containment plan."
        )
        return await self._generate(prompt, self.SYSTEM)


class RemediationAgent(GeminiAgent):
    SYSTEM = (
        "You are a systems recovery engineer. Given a confirmed threat, its "
        "containment actions, and the affected resource, produce a remediation "
        "plan to restore the system to a healthy, verified state: the plan, the "
        "ordered restoration steps, and a single concrete verification check to "
        "confirm recovery. Respond ONLY with the required JSON object."
    )

    def __init__(self, client: genai.Client) -> None:
        super().__init__(client, stage="REMEDIATION", schema=RemediationResult)

    async def run(
        self,
        log_event: SecurityLog,
        triage: TriageResult,
        isolation: IsolationResult,
    ) -> RemediationResult:
        # Both upstream agents' structured outputs feed the remediation context.
        prompt = (
            "The threat has been contained. Produce the recovery plan.\n\n"
            "=== Original security log ===\n"
            f"Source: {log_event.source}\n"
            f"Raw event: {log_event.raw_event}\n\n"
            "=== Triage assessment ===\n"
            f"{triage.model_dump_json(indent=2)}\n\n"
            "=== Containment actions taken (upstream agent output) ===\n"
            f"{isolation.model_dump_json(indent=2)}\n\n"
            "Produce the remediation plan to restore and verify the resource."
        )
        return await self._generate(prompt, self.SYSTEM)


# --------------------------------------------------------------------------- #
# Async ingestion
# --------------------------------------------------------------------------- #

_INCIDENT_TEMPLATES: list[dict[str, str]] = [
    {
        "source": "aws-cloudtrail",
        "event_type": "credential_exfiltration",
        "raw_event": (
            "GetSecretValue + 412 sequential S3 GetObject calls from IAM user "
            "'svc-backup' originating at 185.220.101.7 (Tor exit node); "
            "ListBuckets immediately preceded the burst."
        ),
    },
    {
        "source": "kubernetes-audit",
        "event_type": "privilege_escalation",
        "raw_event": (
            "pods/exec into 'payments-api-7f9c8d' by ServiceAccount "
            "'default:anonymous'; container mounted /var/run/docker.sock and "
            "spawned a shell writing to a hostPath volume."
        ),
    },
    {
        "source": "endpoint-edr",
        "event_type": "malware_execution",
        "raw_event": (
            "mimikatz.exe launched by powershell.exe (encoded command) on "
            "WIN-ENDPOINT-14; LSASS memory read detected, followed by outbound "
            "SMB to 10.0.9.3."
        ),
    },
    {
        "source": "aws-guardduty",
        "event_type": "crypto_mining",
        "raw_event": (
            "EC2 instance i-0a1b2c3d4e5f60789 resolving known XMRig pool domains; "
            "sustained 98% CPU and outbound traffic to a stratum port."
        ),
    },
    {
        "source": "kubernetes-audit",
        "event_type": "secret_access",
        "raw_event": (
            "Anomalous `get secrets` across all namespaces by token tied to a "
            "deleted CI job; exploited CVE-2024-3400 on the ingress gateway."
        ),
    },
]


async def ingestion_loop(
    queue: asyncio.Queue[SecurityLog],
    stop_event: asyncio.Event,
    *,
    interval: float = INGESTION_INTERVAL_SECONDS,
) -> None:
    """Drop one realistic security log onto the queue every `interval` seconds
    until `stop_event` is set. The interval paces the pipeline under the
    free-tier 15 RPM ceiling."""
    while not stop_event.is_set():
        template = random.choice(_INCIDENT_TEMPLATES)
        event = SecurityLog(**template)
        await queue.put(event)
        log(
            "INGEST",
            f"Incident {event.incident_id} queued — source={event.source} "
            f"type={event.event_type}",
        )
        # Sleep in an interruptible way so shutdown is prompt.
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass

    log("INGEST", "Ingestion loop stopped")


# --------------------------------------------------------------------------- #
# Sequential orchestrator
# --------------------------------------------------------------------------- #

class IncidentResponseOrchestrator:
    """Consumes security logs from the queue and drives each one, sequentially,
    through Triage -> Isolation -> Remediation, chaining each agent's structured
    output into the next agent's context."""

    def __init__(self, client: genai.Client, queue: asyncio.Queue[SecurityLog]) -> None:
        self._queue = queue
        self._triage = TriageAgent(client)
        self._isolation = IsolationAgent(client)
        self._remediation = RemediationAgent(client)
        self._processed = 0

    @property
    def processed(self) -> int:
        return self._processed

    async def _process_one(self, event: SecurityLog) -> None:
        log("PIPELINE", f"--- Processing incident {event.incident_id} ---")

        # Stage 1: Triage
        triage = await self._triage.run(event)
        log(
            "TRIAGE",
            f"{event.incident_id}: is_threat={triage.is_threat} "
            f"category='{triage.threat_category}' "
            f"confidence={triage.confidence_score:.2f}",
        )
        log("TRIAGE", f"{event.incident_id}: justification — {triage.justification}")

        if not triage.is_threat:
            log(
                "PIPELINE",
                f"{event.incident_id}: benign per triage — no containment required. "
                f"--- Complete ---",
            )
            self._processed += 1
            return

        # Stage 2: Isolation (Triage JSON injected into context)
        isolation = await self._isolation.run(event, triage)
        log(
            "ISOLATION",
            f"{event.incident_id}: strategy='{isolation.containment_strategy}' "
            f"target='{isolation.target_resource}'",
        )
        for i, cmd in enumerate(isolation.bash_commands, start=1):
            log("ISOLATION", f"{event.incident_id}: cmd[{i}] $ {cmd}")

        # Stage 3: Remediation (Triage + Isolation JSON injected into context)
        remediation = await self._remediation.run(event, triage, isolation)
        log("REMEDIATION", f"{event.incident_id}: plan — {remediation.remediation_plan}")
        for i, step in enumerate(remediation.restoration_steps, start=1):
            log("REMEDIATION", f"{event.incident_id}: step[{i}] {step}")
        log(
            "REMEDIATION",
            f"{event.incident_id}: verification — {remediation.verification_check}",
        )

        log("PIPELINE", f"{event.incident_id}: --- Complete (fully remediated) ---")
        self._processed += 1

    async def run(self, ingestion_done: asyncio.Event) -> None:
        """Process queued incidents sequentially until ingestion has finished
        and the queue is drained."""
        while not (ingestion_done.is_set() and self._queue.empty()):
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

            try:
                await self._process_one(event)
            except errors.APIError as exc:
                log(
                    "ERROR",
                    f"{event.incident_id}: pipeline aborted — Gemini API error "
                    f"(code={getattr(exc, 'code', 'n/a')}): {exc}",
                )
            except Exception as exc:  # noqa: BLE001 - one bad incident must not stop the queue
                log("ERROR", f"{event.incident_id}: pipeline aborted — {type(exc).__name__}: {exc}")
            finally:
                self._queue.task_done()

        log("PIPELINE", "Orchestrator drained — no more incidents")


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

async def main(run_seconds: float) -> int:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        log("FATAL", "GEMINI_API_KEY is not set. Export it and retry:")
        log("FATAL", "  export GEMINI_API_KEY=your-key-here")
        return 1

    client = genai.Client(api_key=api_key)

    queue: asyncio.Queue[SecurityLog] = asyncio.Queue(maxsize=64)
    stop_event = asyncio.Event()
    ingestion_done = asyncio.Event()
    orchestrator = IncidentResponseOrchestrator(client, queue)

    log("BOOT", f"=== Gemini Incident Response Pipeline starting (model={MODEL}, "
                f"window={run_seconds:.0f}s, ingest every {INGESTION_INTERVAL_SECONDS:.0f}s) ===")

    producer = asyncio.create_task(ingestion_loop(queue, stop_event))
    consumer = asyncio.create_task(orchestrator.run(ingestion_done))

    try:
        await asyncio.sleep(run_seconds)
    finally:
        stop_event.set()
        await producer            # producer fully drained (incl. any final put)
        ingestion_done.set()      # only now may the consumer exit on an empty queue
        await consumer

    log("BOOT", f"=== Pipeline stopped. Incidents processed: {orchestrator.processed} ===")
    return 0


if __name__ == "__main__":
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else 35.0
    try:
        raise SystemExit(asyncio.run(main(duration)))
    except KeyboardInterrupt:
        log("BOOT", "Interrupted — shutting down.")
