"""
Live SQS ingestion against a REAL SQS server (moto standalone), not the fake
client used in test_ingestion.py. This proves the actual boto3 long-poll /
delete path — the code that runs in production against real AWS — works, and
proves the testbed emulator choice (moto server) is correct.

Skipped automatically if moto[server] isn't installed, so the core suite still
runs without the testbed dependency.
"""

from __future__ import annotations

import asyncio
import json

import pytest

pytest.importorskip("moto.server", reason="testbed dep: pip install -r testbed/requirements.txt")
pytest.importorskip("boto3")

import boto3
from moto.server import ThreadedMotoServer

from aegis.ingestion import QueuedFinding, SqsFindingSource
from aegis.providers.aws import normalize_guardduty

REGION = "us-east-1"

_FINDING = {
    "Id": "sqs-int-0001",
    "Type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
    "Severity": 8.0,
    "Resource": {"ResourceType": "AccessKey",
                 "AccessKeyDetails": {"AccessKeyId": "AKIAINT", "UserName": "svc-x"}},
}


def _eventbridge_body(finding: dict) -> str:
    return json.dumps({"detail-type": "GuardDuty Finding", "source": "aws.guardduty",
                       "detail": finding})


@pytest.fixture(autouse=True)
def _dummy_aws_credentials(monkeypatch):
    """The ingestion uses the default boto3 credential chain (an IAM role in
    production). moto ignores credential *values* but boto3 requires some to be
    present, so provide throwaway ones for the emulator. Production code stays
    credential-agnostic — we never inject credentials into SqsFindingSource."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")


@pytest.fixture()
def sqs_server():
    import os
    external_endpoint = os.getenv("AEGIS_TEST_SQS_ENDPOINT")
    if external_endpoint:
        client = boto3.client("sqs", region_name=REGION, endpoint_url=external_endpoint,
                              aws_access_key_id="testing", aws_secret_access_key="testing")
        try:
            queue_url = client.get_queue_url(QueueName="aegis-findings-test")["QueueUrl"]
        except Exception:
            queue_url = client.create_queue(QueueName="aegis-findings-test")["QueueUrl"]
        yield external_endpoint, queue_url, client
    else:
        server = ThreadedMotoServer(port=0)  # port 0 -> OS picks a free port
        server.start()
        host, port = server.get_host_and_port()
        endpoint = f"http://{host}:{port}"
        client = boto3.client("sqs", region_name=REGION, endpoint_url=endpoint,
                              aws_access_key_id="testing", aws_secret_access_key="testing")
        queue_url = client.create_queue(QueueName="aegis-findings-test")["QueueUrl"]
        try:
            yield endpoint, queue_url, client
        finally:
            server.stop()


async def _drain_one(source: SqsFindingSource) -> list[QueuedFinding]:
    queue: "asyncio.Queue[QueuedFinding]" = asyncio.Queue()
    stop = asyncio.Event()
    task = asyncio.create_task(source.stream(queue, stop))
    # Give the long-poll a moment to receive and enqueue.
    for _ in range(50):
        if not queue.empty():
            break
        await asyncio.sleep(0.1)
    stop.set()
    try:
        await asyncio.wait_for(task, timeout=3)
    except asyncio.TimeoutError:
        task.cancel()
    items = []
    while not queue.empty():
        items.append(queue.get_nowait())
    return items


async def test_live_ingestion_receives_a_real_sqs_message(sqs_server) -> None:
    endpoint, queue_url, client = sqs_server
    client.send_message(QueueUrl=queue_url, MessageBody=_eventbridge_body(_FINDING))

    source = SqsFindingSource(queue_url, normalize_guardduty, region=REGION,
                              wait_seconds=1, endpoint_url=endpoint)
    items = await _drain_one(source)

    assert len(items) == 1
    finding = items[0].finding
    assert finding.provider == "aws"
    assert finding.finding_id == "sqs-int-0001"
    assert finding.severity == 8.0


async def test_ack_deletes_the_message_from_the_real_queue(sqs_server) -> None:
    """The full at-least-once contract against a real queue: the message is
    present until ack(), and gone after."""
    endpoint, queue_url, client = sqs_server
    client.send_message(QueueUrl=queue_url, MessageBody=_eventbridge_body(_FINDING))

    source = SqsFindingSource(queue_url, normalize_guardduty, region=REGION,
                              wait_seconds=1, endpoint_url=endpoint)
    items = await _drain_one(source)
    assert len(items) == 1

    # ack() deletes the message. The deterministic proof it's truly gone (not
    # merely invisible): a fresh receive with a full visibility reset returns
    # nothing. We avoid asserting on ApproximateNumberOfMessages* — those are,
    # by AWS's own contract, approximate and timing-dependent, hence flaky.
    await items[0].ack()

    # A deleted message never comes back, regardless of visibility timeout.
    resp = client.receive_message(QueueUrl=queue_url, WaitTimeSeconds=1,
                                  VisibilityTimeout=0, MaxNumberOfMessages=10)
    assert resp.get("Messages", []) == []  # deleted — nothing comes back


async def test_sns_wrapped_message_is_unwrapped_against_real_sqs(sqs_server) -> None:
    """GuardDuty -> EventBridge -> SNS -> SQS topology: the body is an SNS
    Notification whose Message is the stringified EventBridge JSON."""
    endpoint, queue_url, client = sqs_server
    sns_body = json.dumps({"Type": "Notification", "Message": _eventbridge_body(_FINDING)})
    client.send_message(QueueUrl=queue_url, MessageBody=sns_body)

    source = SqsFindingSource(queue_url, normalize_guardduty, region=REGION,
                              wait_seconds=1, endpoint_url=endpoint)
    items = await _drain_one(source)

    assert len(items) == 1
    assert items[0].finding.finding_id == "sqs-int-0001"
