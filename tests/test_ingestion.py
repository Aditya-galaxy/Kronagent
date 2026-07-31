"""
Ingestion sources. FileReplaySource is tested against real fixture files.
SqsFindingSource is tested against a fake SQS client (no boto3, no network) --
formalizing the ack-after-process / poison-message / envelope-unwrapping
behavior that was previously validated only via ad hoc scripts.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from kronagent.ingestion import FileReplaySource, QueuedFinding, SqsFindingSource
from kronagent.model import Finding
from kronagent.providers.aws import normalize_guardduty

MINIMAL_FINDING = {
    "Id": "f-1", "Type": "UnauthorizedAccess:IAMUser/X", "Severity": 8.0,
    "Resource": {"ResourceType": "AccessKey",
                 "AccessKeyDetails": {"AccessKeyId": "AKIA1", "UserName": "u"}},
}


# --------------------------------------------------------------------------- #
# FileReplaySource
# --------------------------------------------------------------------------- #

async def test_file_replay_streams_every_finding(guardduty_findings, tmp_path) -> None:
    path = tmp_path / "findings.json"
    path.write_text(json.dumps(guardduty_findings))
    queue: "asyncio.Queue[QueuedFinding]" = asyncio.Queue()
    stop = asyncio.Event()

    await FileReplaySource(str(path), normalize_guardduty, interval=0.0).stream(queue, stop)

    items = []
    while not queue.empty():
        items.append(queue.get_nowait())
    assert len(items) == len(guardduty_findings)
    assert {i.finding.finding_id for i in items} == {f["Id"] for f in guardduty_findings}


async def test_file_replay_skips_malformed_events(tmp_path) -> None:
    good = MINIMAL_FINDING
    bad = {"not_a_valid_guardduty_finding": True}  # missing required Id/Type/Severity
    path = tmp_path / "mixed.json"
    path.write_text(json.dumps([good, bad, good]))
    queue: "asyncio.Queue[QueuedFinding]" = asyncio.Queue()
    stop = asyncio.Event()

    await FileReplaySource(str(path), normalize_guardduty, interval=0.0).stream(queue, stop)

    items = []
    while not queue.empty():
        items.append(queue.get_nowait())
    assert len(items) == 2  # the malformed one was skipped, not crashed on


async def test_file_replay_single_object_not_wrapped_in_list(tmp_path) -> None:
    path = tmp_path / "single.json"
    path.write_text(json.dumps(MINIMAL_FINDING))
    queue: "asyncio.Queue[QueuedFinding]" = asyncio.Queue()
    await FileReplaySource(str(path), normalize_guardduty, interval=0.0).stream(queue, asyncio.Event())
    assert queue.qsize() == 1


async def test_file_replay_ack_is_a_noop(tmp_path) -> None:
    path = tmp_path / "single.json"
    path.write_text(json.dumps(MINIMAL_FINDING))
    queue: "asyncio.Queue[QueuedFinding]" = asyncio.Queue()
    await FileReplaySource(str(path), normalize_guardduty, interval=0.0).stream(queue, asyncio.Event())
    item = queue.get_nowait()
    await item.ack()  # must not raise -- nothing upstream to retire


# --------------------------------------------------------------------------- #
# SqsFindingSource -- fake client, no boto3/network
# --------------------------------------------------------------------------- #

class FakeSqsClient:
    """Serves a fixed batch of messages once, then empty responses forever.
    Records delete_message calls so tests can assert on ack timing."""

    def __init__(self, messages: list[dict], *, fail_first_n_receives: int = 0) -> None:
        self._messages = messages
        self._served = False
        self._fail_remaining = fail_first_n_receives
        self.deleted: list[str] = []

    def receive_message(self, **kwargs) -> dict[str, Any]:
        if self._fail_remaining > 0:
            self._fail_remaining -= 1
            raise ConnectionError("simulated transient SQS failure")
        if self._served:
            return {}
        self._served = True
        return {"Messages": self._messages}

    def delete_message(self, *, QueueUrl: str, ReceiptHandle: str) -> None:
        self.deleted.append(ReceiptHandle)


def _make_source(fake_client: FakeSqsClient) -> SqsFindingSource:
    src = SqsFindingSource.__new__(SqsFindingSource)
    src._queue_url = "http://fake-queue"
    src._normalizer = normalize_guardduty
    src._region = "us-east-1"
    src._wait_seconds = 0
    src._sqs = fake_client
    return src


async def _run_briefly(src: SqsFindingSource, queue) -> None:
    stop = asyncio.Event()
    task = asyncio.create_task(src.stream(queue, stop))
    await asyncio.sleep(0.15)
    stop.set()
    try:
        await asyncio.wait_for(task, timeout=2)
    except asyncio.TimeoutError:
        task.cancel()


@pytest.mark.parametrize(
    "body,should_normalize",
    [
        (json.dumps({"detail-type": "GuardDuty Finding", "detail": MINIMAL_FINDING}), True),
        (json.dumps({"Type": "Notification", "Message": json.dumps({"detail": MINIMAL_FINDING})}), True),
        (json.dumps(MINIMAL_FINDING), True),  # bare, defensive path
        ("{not valid json", False),
        (json.dumps({"hello": "world"}), False),  # valid JSON, not a finding
    ],
)
def test_unwrap_envelope_shapes(body: str, should_normalize: bool) -> None:
    result = SqsFindingSource._unwrap(body, normalize_guardduty)
    if should_normalize:
        assert isinstance(result, Finding)
        assert result.finding_id == "f-1"
    else:
        assert result is None


async def test_good_message_is_queued_and_not_deleted_before_ack() -> None:
    fake = FakeSqsClient([{"ReceiptHandle": "rh-good",
                            "Body": json.dumps({"detail": MINIMAL_FINDING}),
                            "Attributes": {}}])
    src = _make_source(fake)
    queue: "asyncio.Queue[QueuedFinding]" = asyncio.Queue()

    await _run_briefly(src, queue)

    assert queue.qsize() == 1
    assert fake.deleted == []  # not deleted yet -- ack-after-process


async def test_ack_deletes_exactly_the_right_message() -> None:
    fake = FakeSqsClient([{"ReceiptHandle": "rh-good",
                            "Body": json.dumps({"detail": MINIMAL_FINDING}),
                            "Attributes": {}}])
    src = _make_source(fake)
    queue: "asyncio.Queue[QueuedFinding]" = asyncio.Queue()
    await _run_briefly(src, queue)
    item = queue.get_nowait()

    await item.ack()

    assert fake.deleted == ["rh-good"]


async def test_poison_message_is_left_for_dlq_not_deleted() -> None:
    fake = FakeSqsClient([{"ReceiptHandle": "rh-poison",
                            "Body": "{not valid json",
                            "Attributes": {"ApproximateReceiveCount": "3"}}])
    src = _make_source(fake)
    queue: "asyncio.Queue[QueuedFinding]" = asyncio.Queue()

    await _run_briefly(src, queue)

    assert queue.qsize() == 0  # never queued
    assert fake.deleted == []  # and critically: never deleted either


async def test_good_and_poison_in_same_batch_only_good_is_queued() -> None:
    fake = FakeSqsClient([
        {"ReceiptHandle": "rh-good", "Body": json.dumps({"detail": MINIMAL_FINDING}), "Attributes": {}},
        {"ReceiptHandle": "rh-poison", "Body": "garbage", "Attributes": {}},
    ])
    src = _make_source(fake)
    queue: "asyncio.Queue[QueuedFinding]" = asyncio.Queue()

    await _run_briefly(src, queue)

    assert queue.qsize() == 1
    assert fake.deleted == []


async def test_receive_errors_do_not_kill_the_loop() -> None:
    """A transient receive_message failure must be retried (with backoff), not
    propagate and stop ingestion."""
    fake = FakeSqsClient(
        [{"ReceiptHandle": "rh-good", "Body": json.dumps({"detail": MINIMAL_FINDING}), "Attributes": {}}],
        fail_first_n_receives=1,
    )
    src = _make_source(fake)
    src._RECEIVE_BASE_BACKOFF = 0.01  # keep the test fast
    src._RECEIVE_MAX_BACKOFF = 0.05
    queue: "asyncio.Queue[QueuedFinding]" = asyncio.Queue()

    await _run_briefly(src, queue)

    assert queue.qsize() == 1  # recovered after the transient failure
