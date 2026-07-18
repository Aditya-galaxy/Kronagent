"""
Finding ingestion.

Two sources behind one async interface, both yielding `QueuedFinding` envelopes
onto the shared work queue:

  * FileReplaySource — reads real-schema GuardDuty finding JSON from disk. Lets
                       the whole pipeline run and be tested with no AWS account.
  * SqsFindingSource — the production path: GuardDuty -> EventBridge -> (optional
                       SNS) -> SQS. Long-polls the queue, unwraps the envelope(s),
                       yields findings, and deletes each message ONLY after the
                       orchestrator has fully processed and audited it.

Delivery semantics (SQS): at-least-once with ack-after-process. A message stays
invisible for the queue's visibility timeout while in flight; it is deleted only
when `QueuedFinding.ack()` runs, which the orchestrator calls after the finding
is handled and audited. If the process crashes mid-processing, the message
reappears after the visibility timeout and is re-processed — a security finding
is never silently lost. This is the deliberate trade: a possible double-response
(idempotent + approval-gated, so safe) over a dropped threat.

Operational requirements for the SQS queue (see deploy/README.md):
  * visibility timeout > max expected per-finding processing time (LLM triage +
    containment). 60s is a safe default for this pipeline.
  * a redrive policy to a dead-letter queue (maxReceiveCount ~5): messages that
    fail to parse are left in place (not deleted) so SQS moves them to the DLQ
    rather than looping forever. Without a DLQ, a poison message redelivers
    every visibility-timeout window.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional

from pydantic import ValidationError

from .model import Finding

# A normalizer turns one native event dict into a provider-neutral Finding.
# Provided by the caller (from aegis.providers.NORMALIZERS), so ingestion is
# transport-only and knows nothing about any provider's wire schema.
Normalizer = Callable[[dict], Finding]


@dataclass
class QueuedFinding:
    """A finding on the internal work queue, plus the ack that retires it from
    the upstream source. `ack()` is called by the orchestrator exactly once,
    after processing + auditing completes."""

    finding: Finding
    _ack: Callable[[], Awaitable[None]]

    async def ack(self) -> None:
        await self._ack()


async def _noop_ack() -> None:
    return None


class FileReplaySource:
    def __init__(self, path: str, normalizer: Normalizer, *, interval: float = 1.0) -> None:
        self._path = path
        self._normalizer = normalizer
        self._interval = interval

    async def stream(self, queue: "asyncio.Queue[QueuedFinding]", stop: asyncio.Event) -> None:
        with open(self._path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        events = raw if isinstance(raw, list) else [raw]

        for item in events:
            if stop.is_set():
                break
            try:
                finding = self._normalizer(item)
            except (ValidationError, KeyError, ValueError) as exc:
                print(f"[INGEST] skipping malformed event: {exc}", flush=True)
                continue
            # File replay has nothing to retire upstream — ack is a no-op.
            await queue.put(QueuedFinding(finding=finding, _ack=_noop_ack))
            try:
                await asyncio.wait_for(stop.wait(), timeout=self._interval)
            except asyncio.TimeoutError:
                pass


class SqsFindingSource:
    """Production ingestion: long-poll an SQS queue fed by EventBridge (optionally
    via SNS). boto3 is imported lazily so importing this module never requires AWS.

    Messages are deleted only via `QueuedFinding.ack()` after full processing —
    see the module docstring for the at-least-once rationale.
    """

    # Backoff bounds for transient SQS/receive errors (throttling, network).
    _RECEIVE_BASE_BACKOFF = 1.0
    _RECEIVE_MAX_BACKOFF = 30.0

    def __init__(self, queue_url: str, normalizer: Normalizer, *, region: str,
                 wait_seconds: int = 20) -> None:
        self._queue_url = queue_url
        self._normalizer = normalizer
        self._region = region
        self._wait_seconds = wait_seconds
        self._sqs = None

    def _client(self):
        if self._sqs is None:
            import boto3  # local import: module stays importable without AWS
            self._sqs = boto3.client("sqs", region_name=self._region)
        return self._sqs

    async def stream(self, queue: "asyncio.Queue[QueuedFinding]", stop: asyncio.Event) -> None:
        sqs = self._client()
        backoff = self._RECEIVE_BASE_BACKOFF

        while not stop.is_set():
            try:
                resp = await asyncio.to_thread(
                    sqs.receive_message,
                    QueueUrl=self._queue_url,
                    MaxNumberOfMessages=10,
                    WaitTimeSeconds=self._wait_seconds,
                    AttributeNames=["ApproximateReceiveCount"],
                )
                backoff = self._RECEIVE_BASE_BACKOFF  # reset after a clean poll
            except Exception as exc:  # noqa: BLE001 - a receive error must not kill ingestion
                print(f"[INGEST] SQS receive failed, backing off {backoff:.0f}s: "
                      f"{type(exc).__name__}: {exc}", flush=True)
                await self._interruptible_sleep(stop, backoff)
                backoff = min(backoff * 2, self._RECEIVE_MAX_BACKOFF)
                continue

            for msg in resp.get("Messages", []):
                receipt = msg["ReceiptHandle"]
                finding = self._unwrap(msg.get("Body", ""), self._normalizer)

                if finding is None:
                    # Poison message: leave it for DLQ redrive rather than delete
                    # (deleting would silently lose it). SQS moves it to the DLQ
                    # once ApproximateReceiveCount exceeds the redrive maxReceiveCount.
                    recv = msg.get("Attributes", {}).get("ApproximateReceiveCount", "?")
                    print(f"[INGEST] unparseable message left for DLQ redrive "
                          f"(receive count {recv})", flush=True)
                    continue

                await queue.put(QueuedFinding(
                    finding=finding,
                    _ack=self._make_ack(receipt),
                ))

    def _make_ack(self, receipt_handle: str) -> Callable[[], Awaitable[None]]:
        async def _ack() -> None:
            await asyncio.to_thread(
                self._client().delete_message,
                QueueUrl=self._queue_url,
                ReceiptHandle=receipt_handle,
            )
        return _ack

    @staticmethod
    async def _interruptible_sleep(stop: asyncio.Event, seconds: float) -> None:
        try:
            await asyncio.wait_for(stop.wait(), timeout=seconds)
        except asyncio.TimeoutError:
            pass

    @staticmethod
    def _unwrap(body: str, normalizer: Normalizer) -> Optional[Finding]:
        """Unwrap the native event from an SQS message body and normalize it.

        Handles both delivery topologies:
          * EventBridge -> SQS:        {"detail-type": ..., "detail": <event>}
          * EventBridge -> SNS -> SQS: {"Type": "Notification",
                                        "Message": "<stringified EventBridge JSON>"}
        and a bare event (defensive). The provider's normalizer does the final
        native-event -> Finding conversion.
        """
        try:
            envelope = json.loads(body)
        except json.JSONDecodeError as exc:
            print(f"[INGEST] message body is not JSON: {exc}", flush=True)
            return None

        # SNS notification wraps the real payload as a JSON string under "Message".
        if isinstance(envelope, dict) and envelope.get("Type") == "Notification" \
                and isinstance(envelope.get("Message"), str):
            try:
                envelope = json.loads(envelope["Message"])
            except json.JSONDecodeError as exc:
                print(f"[INGEST] SNS Message is not JSON: {exc}", flush=True)
                return None

        # EventBridge wraps the event under "detail"; otherwise treat as bare.
        detail = envelope.get("detail", envelope) if isinstance(envelope, dict) else envelope

        try:
            return normalizer(detail)
        except (ValidationError, KeyError, ValueError) as exc:
            print(f"[INGEST] payload did not normalize to a Finding: {exc}", flush=True)
            return None
