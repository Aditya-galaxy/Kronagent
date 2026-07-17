"""
Finding ingestion.

Two sources behind one async interface:

  * FileReplaySource   — reads real-schema GuardDuty finding JSON from disk.
                         Lets the whole pipeline run and be tested with no AWS
                         account, against captured/synthetic real findings.
  * SqsFindingSource   — the production path: GuardDuty -> EventBridge -> SQS.
                         Long-polls the queue, unwraps the EventBridge envelope,
                         yields findings, and deletes messages after handoff.

Both yield validated `GuardDutyFinding` objects onto the shared queue.
"""

from __future__ import annotations

import asyncio
import json
from typing import Optional

from pydantic import ValidationError

from .schemas import GuardDutyFinding


class FileReplaySource:
    def __init__(self, path: str, *, interval: float = 1.0) -> None:
        self._path = path
        self._interval = interval

    async def stream(self, queue: "asyncio.Queue[GuardDutyFinding]", stop: asyncio.Event) -> None:
        with open(self._path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        findings = raw if isinstance(raw, list) else [raw]

        for item in findings:
            if stop.is_set():
                break
            try:
                finding = GuardDutyFinding.model_validate(item)
            except ValidationError as exc:
                print(f"[INGEST] skipping malformed finding: {exc.errors()[:1]}", flush=True)
                continue
            await queue.put(finding)
            try:
                await asyncio.wait_for(stop.wait(), timeout=self._interval)
            except asyncio.TimeoutError:
                pass


class SqsFindingSource:
    """Production ingestion: long-poll an SQS queue fed by EventBridge.

    boto3 is imported lazily so importing this module never requires AWS.
    """

    def __init__(self, queue_url: str, *, region: str, wait_seconds: int = 20) -> None:
        self._queue_url = queue_url
        self._region = region
        self._wait_seconds = wait_seconds

    def _client(self):
        import boto3
        return boto3.client("sqs", region_name=self._region)

    async def stream(self, queue: "asyncio.Queue[GuardDutyFinding]", stop: asyncio.Event) -> None:
        sqs = self._client()
        while not stop.is_set():
            resp = await asyncio.to_thread(
                sqs.receive_message,
                QueueUrl=self._queue_url,
                MaxNumberOfMessages=10,
                WaitTimeSeconds=self._wait_seconds,
            )
            for msg in resp.get("Messages", []):
                finding = self._unwrap(msg["Body"])
                if finding is not None:
                    await queue.put(finding)
                # Delete only after successful handoff to the queue.
                await asyncio.to_thread(
                    sqs.delete_message,
                    QueueUrl=self._queue_url,
                    ReceiptHandle=msg["ReceiptHandle"],
                )

    @staticmethod
    def _unwrap(body: str) -> Optional[GuardDutyFinding]:
        try:
            envelope = json.loads(body)
            # EventBridge wraps the finding under "detail".
            detail = envelope.get("detail", envelope)
            return GuardDutyFinding.model_validate(detail)
        except (json.JSONDecodeError, ValidationError) as exc:
            print(f"[INGEST] dropping unparseable SQS message: {exc}", flush=True)
            return None
