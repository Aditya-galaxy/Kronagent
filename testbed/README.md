# Aegis Testbed — local cloud-alert-stream simulation

Runs the **live ingestion path** (GuardDuty → EventBridge → SQS, long-polled by
`aegis.ingestion.SqsFindingSource`) end-to-end with **no AWS account, no
credentials, and no Docker** — so you can exercise the real async streaming code
that runs in production, not just the file-replay path.

## Which emulator — and why not LocalStack

The brief proposed **Docker + LocalStack**. Research (July 2026) changed the
recommendation:

> **LocalStack's Community Edition went proprietary and auth-token-gated in
> March 2026** ([the repo was archived](https://codenote.net/en/posts/localstack-archived-oss-alternatives-comparison/);
> the free image now [requires a Hobby token](https://dev.to/peytongreen_dev/localstack-killed-its-free-tier-heres-how-to-test-aws-in-python-for-free-in-2026-12me)).
> For a zero-friction, runs-anywhere testbed that's the wrong dependency now.

Aegis ingests **only SQS**, and the stack is pure-Python with a "runs anywhere,
no heavy deps" ethos (lazy `boto3`, graceful degradation). So:

| Option | Setup | Auth | Fidelity | Verdict for Aegis |
|---|---|---|---|---|
| **moto server** (default) | `pip install` | none | real SQS endpoint, long-poll + delete | ✅ default — pure-Python, zero-auth, no Docker |
| **ElasticMQ** (Docker) | `docker compose up` | none | SQS-native, production-like | ✅ documented alt for higher fidelity / non-Python producers |
| LocalStack | Docker + token | **token** | broad AWS | ❌ went proprietary/auth-gated Mar 2026 |
| **moto in-process (`@mock_aws`)** | `pip install` | none | in-process only | ✅ Used in `tests/test_provider_containment_moto.py` to verify boto3 API state changes (NACLs, IAM) without real AWS credentials |

Sources: [OSS alternatives comparison](https://codenote.net/en/posts/localstack-archived-oss-alternatives-comparison/) ·
[Testing AWS in Python without LocalStack (2026)](https://dev.to/peytongreen_dev/localstack-killed-its-free-tier-heres-how-to-test-aws-in-python-for-free-in-2026-12me) ·
[Floci vs Moto vs Testcontainers](https://dev.to/peytongreen_dev/localstack-is-gone-floci-vs-moto-vs-testcontainers-which-one-replaces-it-c7c)

## The one code change that makes this possible

`Settings.sqs_endpoint_url` (env `AEGIS_SQS_ENDPOINT_URL`) overrides the SQS
endpoint. Empty = real AWS. This is not test-only plumbing — the same knob
points production ingestion at a VPC/PrivateLink SQS endpoint. Production code
stays **credential-agnostic**: it uses the default boto3 credential chain (an
IAM role in prod); the testbed just supplies throwaway credentials moto ignores.

## Default path (moto — no Docker)

```bash
python3 -m pip install -r testbed/requirements.txt

# Shell A — stand up the emulator + stream the sample findings in:
python3 testbed/sqs_emulator.py serve                 # enqueue once
python3 testbed/sqs_emulator.py serve --interval 5    # continuous async stream

# It prints the two env vars to export. Then Shell B — live ingestion:
export AEGIS_SQS_ENDPOINT_URL=http://localhost:5001
export AEGIS_SQS_QUEUE_URL=<printed queue URL>
python3 run_slice.py
```

`run_slice.py` will long-poll the queue and drive every finding through the full
agent pipeline (triage → policy → containment → audit), in dry-run.

## Docker path (ElasticMQ — higher fidelity)

```bash
docker compose -f testbed/docker-compose.yml up -d
export AEGIS_SQS_ENDPOINT_URL=http://localhost:9324
python3 testbed/sqs_emulator.py enqueue        # creates the queue, streams findings
# export the queue URL it prints, then in another shell:
python3 run_slice.py
docker compose -f testbed/docker-compose.yml down
```

## Verification

`tests/test_sqs_integration.py` runs the ingestion against a **real** moto SQS
server (not the fake client used elsewhere): receive → normalize → deliver →
ack-deletes-from-the-real-queue, plus SNS-envelope unwrapping. It's skipped
automatically if `moto[server]` isn't installed, so the core suite is unaffected.

```bash
python3 -m pytest tests/test_sqs_integration.py -q
```
