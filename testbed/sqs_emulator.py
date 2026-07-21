#!/usr/bin/env python3
"""
Aegis testbed — local SQS emulator + async finding stream.

Stands up a REAL SQS endpoint locally (via moto's standalone server) and streams
GuardDuty findings into it wrapped in EventBridge envelopes, exactly as the live
GuardDuty -> EventBridge -> SQS path delivers them. This lets the *live*
ingestion path (aegis.ingestion.SqsFindingSource, boto3 long-polling) run
end-to-end with no AWS account, no credentials, and no Docker.

Why moto server and not LocalStack:
  LocalStack's Community Edition went proprietary + auth-token-gated in March
  2026. moto's standalone server is pip-installable, zero-auth, pure Python
  (matches the Aegis stack), and exposes a real SQS endpoint — including the
  ReceiveMessage long-polling and DeleteMessage calls the ingestion uses — that
  a *separate* long-running process can point boto3 at via endpoint_url. For
  higher-fidelity or multi-language testing, ElasticMQ (docker-compose.yml here)
  is the documented alternative; moto is the default because it actually runs
  anywhere with one `pip install`.

Two modes:
  * `serve`  — start the SQS emulator, create the queue, print the endpoint +
               queue URL, and block. Point run_slice.py at it in another shell.
  * `stream` — (used by serve, or standalone) push findings from a sample file
               into the queue on a cadence, simulating an async alert stream.

Usage:
  python3 testbed/sqs_emulator.py serve                 # emulator + one-shot enqueue of the default samples
  python3 testbed/sqs_emulator.py serve --interval 3    # re-inject every 3s (continuous stream)
  AEGIS_SQS_ENDPOINT_URL=... plus AEGIS_SQS_QUEUE_URL=...  (printed on serve) -> run_slice.py ingests live
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

# boto3/moto are testbed-only deps; import lazily with a helpful message.
try:
    import boto3
    from moto.server import ThreadedMotoServer
except ImportError:
    sys.stderr.write(
        "testbed needs boto3 + moto[server]:\n"
        "  python3 -m pip install -r testbed/requirements.txt\n"
    )
    raise SystemExit(2)

REGION = os.getenv("AWS_REGION", "us-east-1")
QUEUE_NAME = "aegis-findings"
DEFAULT_SAMPLES = [
    ("aws", "samples/guardduty_findings.json"),
    ("aws", "samples/campaign_aws.json"),
]

REPO = Path(__file__).resolve().parent.parent


def _eventbridge_envelope(finding: dict) -> str:
    """Wrap a raw GuardDuty finding the way EventBridge delivers it to SQS."""
    return json.dumps({
        "version": "0",
        "id": finding.get("Id", "evt"),
        "detail-type": "GuardDuty Finding",
        "source": "aws.guardduty",
        "account": finding.get("AccountId", "123456789012"),
        "region": REGION,
        "resources": [],
        "detail": finding,
    })


def _load_findings(sample_paths: list[str]) -> list[dict]:
    findings: list[dict] = []
    for rel in sample_paths:
        raw = json.loads((REPO / rel).read_text())
        findings.extend(raw if isinstance(raw, list) else [raw])
    return findings


def _make_client(endpoint_url: str):
    # moto ignores credentials but boto3 still requires *some* to be present.
    return boto3.client(
        "sqs", region_name=REGION, endpoint_url=endpoint_url,
        aws_access_key_id="testing", aws_secret_access_key="testing",
    )


def _enqueue(client, queue_url: str, findings: list[dict]) -> None:
    for f in findings:
        client.send_message(QueueUrl=queue_url, MessageBody=_eventbridge_envelope(f))
        print(f"  [enqueue] {f.get('Id', '?')}  ({f.get('Type', '?')})", flush=True)


def cmd_enqueue(args: argparse.Namespace) -> int:
    """Push findings into an ALREADY-RUNNING external SQS endpoint (ElasticMQ,
    LocalStack, or real AWS) — the Docker path, where the emulator isn't ours."""
    client = _make_client(args.endpoint_url)
    queue_url = args.queue_url
    if not queue_url:
        queue_url = client.create_queue(QueueName=QUEUE_NAME)["QueueUrl"]
        print(f"  created queue: {queue_url}", flush=True)
    findings = _load_findings(args.samples)
    if args.interval > 0:
        print(f"streaming {len(findings)} finding(s) every {args.interval}s "
              f"(Ctrl-C to stop)…\n", flush=True)
        try:
            while True:
                _enqueue(client, queue_url, findings)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\nstopped.", flush=True)
    else:
        _enqueue(client, queue_url, findings)
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    server = ThreadedMotoServer(port=args.port)
    server.start()
    endpoint = f"http://localhost:{args.port}"
    client = _make_client(endpoint)
    queue_url = client.create_queue(
        QueueName=QUEUE_NAME,
        Attributes={"VisibilityTimeout": "60", "ReceiveMessageWaitTimeSeconds": "5"},
    )["QueueUrl"]

    # moto returns a queue URL with an internal host; the endpoint override on
    # the client side is what actually routes calls, so the queue URL only needs
    # to carry the right path. Normalize it to the local endpoint for clarity.
    print("\n=== Aegis SQS testbed ready ===", flush=True)
    print(f"  SQS endpoint : {endpoint}", flush=True)
    print(f"  Queue URL    : {queue_url}", flush=True)
    print("\nPoint the live ingestion at it in another shell:", flush=True)
    print(f"  export AEGIS_SQS_ENDPOINT_URL={endpoint}", flush=True)
    print(f"  export AEGIS_SQS_QUEUE_URL={queue_url}", flush=True)
    print("  python3 run_slice.py\n", flush=True)

    findings = _load_findings(args.samples)
    try:
        if args.interval > 0:
            print(f"streaming {len(findings)} finding(s) every {args.interval}s "
                  f"(Ctrl-C to stop)…\n", flush=True)
            while True:
                _enqueue(client, queue_url, findings)
                time.sleep(args.interval)
        else:
            print(f"enqueuing {len(findings)} finding(s) once, then holding the "
                  f"endpoint open (Ctrl-C to stop)…\n", flush=True)
            _enqueue(client, queue_url, findings)
            while True:
                time.sleep(3600)
    except KeyboardInterrupt:
        print("\nshutting down testbed.", flush=True)
    finally:
        server.stop()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Aegis local SQS testbed")
    sub = parser.add_subparsers(dest="command", required=True)

    p_serve = sub.add_parser("serve", help="start the SQS emulator and stream findings into it")
    p_serve.add_argument("--port", type=int, default=int(os.getenv("AEGIS_TESTBED_PORT", "5001")))
    p_serve.add_argument("--interval", type=float, default=0.0,
                         help="seconds between re-injecting the sample set; 0 = enqueue once")
    p_serve.add_argument("--samples", nargs="+",
                         default=[p for _, p in DEFAULT_SAMPLES],
                         help="finding sample files to stream")

    p_enq = sub.add_parser("enqueue", help="push findings into an external SQS endpoint (ElasticMQ/AWS)")
    p_enq.add_argument("--endpoint-url", default=os.getenv("AEGIS_SQS_ENDPOINT_URL", ""),
                       help="SQS endpoint (e.g. http://localhost:9324 for ElasticMQ)")
    p_enq.add_argument("--queue-url", default=os.getenv("AEGIS_SQS_QUEUE_URL", ""),
                       help="queue URL; if omitted, a queue named 'aegis-findings' is created")
    p_enq.add_argument("--interval", type=float, default=0.0,
                       help="seconds between re-injecting the sample set; 0 = enqueue once")
    p_enq.add_argument("--samples", nargs="+", default=[p for _, p in DEFAULT_SAMPLES],
                       help="finding sample files to stream")

    args = parser.parse_args()
    if args.command == "serve":
        return cmd_serve(args)
    if args.command == "enqueue":
        return cmd_enqueue(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
