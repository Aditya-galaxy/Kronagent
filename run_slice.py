#!/usr/bin/env python3
"""
Aegis — AWS GuardDuty threat-defense vertical slice (runnable entry point).

Wires the real pipeline end to end:

    GuardDuty findings  ->  Triage (deterministic + LLM)  ->  Policy (graduated
    autonomy)  ->  Containment (dry-run by default)  ->  hash-chained audit log

Ingestion defaults to replaying real-schema findings from samples/ so the whole
system runs locally with no AWS account. Point it at a live SQS queue (fed by
GuardDuty -> EventBridge) and flip AEGIS_DRY_RUN=false + grow
AEGIS_AUTO_EXECUTE_ALLOWLIST to graduate it toward autonomy.

Safety posture (all overridable via env, all default safe):
    AEGIS_DRY_RUN=true                 # plan only; nothing is executed
    AEGIS_KILL_SWITCH=false            # global halt of all containment
    AEGIS_AUTO_EXECUTE_ALLOWLIST=""    # empty => every action needs approval
    AEGIS_MIN_SEVERITY=4.0             # below this: alert only
    AEGIS_QUARANTINE_SG_ID=            # required for real instance isolation
    GEMINI_API_KEY=...                 # triage enrichment (optional; degrades)

Usage:
    python3 run_slice.py [path-to-findings.json]
"""

from __future__ import annotations

import asyncio
import sys

import os

from aegis.approvals import ApprovalStore
from aegis.audit import AuditLog
from aegis.config import Settings
from aegis.containment import ContainmentExecutor
from aegis.ingestion import FileReplaySource, QueuedFinding, SqsFindingSource
from aegis.llm import GeminiTriageClient, LLMUnavailableError
from aegis.orchestrator import Orchestrator, _log
from aegis.policy import PolicyEngine
from aegis.triage import TriageEngine


async def main(findings_path: str) -> int:
    settings = Settings.from_env()

    # Triage LLM is optional — the pipeline degrades to deterministic triage.
    try:
        llm: GeminiTriageClient | None = GeminiTriageClient()
        llm_status = "Gemini triage enabled"
    except LLMUnavailableError as exc:
        llm = None
        llm_status = f"LLM disabled ({exc}) — deterministic triage only"

    triage = TriageEngine(llm)
    policy = PolicyEngine(settings)
    containment = ContainmentExecutor(settings)
    audit = AuditLog(settings.audit_log_path)
    approvals = ApprovalStore(settings.approval_store_path)
    orchestrator = Orchestrator(
        settings, triage=triage, policy=policy, containment=containment,
        audit=audit, approvals=approvals,
    )

    _log("BOOT", "=== Aegis GuardDuty threat-defense slice starting ===")
    _log("BOOT", f"mode: {'DRY-RUN (no execution)' if settings.dry_run else 'LIVE EXECUTION'}"
                 f" | kill_switch={settings.kill_switch}")
    _log("BOOT", f"auto-execute allowlist: {sorted(settings.auto_execute_allowlist) or 'EMPTY (all actions need approval)'}")
    _log("BOOT", f"triage: {llm_status}")

    queue: "asyncio.Queue[QueuedFinding]" = asyncio.Queue(maxsize=256)
    stop = asyncio.Event()
    ingestion_done = asyncio.Event()

    # Source selection: SQS if AEGIS_SQS_QUEUE_URL is set (live GuardDuty ->
    # EventBridge -> SQS), else replay findings from disk. The SQS source runs
    # until interrupted (Ctrl-C); the file source finishes on its own.
    sqs_url = os.getenv("AEGIS_SQS_QUEUE_URL")
    if sqs_url:
        _log("BOOT", f"ingestion: SQS long-poll {sqs_url} (region {settings.aws_region})")
        source = SqsFindingSource(sqs_url, region=settings.aws_region, wait_seconds=20)
        live = True
    else:
        _log("BOOT", f"ingestion: file replay {findings_path}")
        source = FileReplaySource(findings_path, interval=0.5)
        live = False

    producer = asyncio.create_task(source.stream(queue, stop))
    consumer = asyncio.create_task(orchestrator.run(queue, ingestion_done))

    try:
        if live:
            # Live mode: run until Ctrl-C, then drain gracefully.
            await producer
        else:
            await producer        # replay source finishes on its own
    except (KeyboardInterrupt, asyncio.CancelledError):
        _log("BOOT", "shutdown requested — draining in-flight findings")
    finally:
        stop.set()
        if not producer.done():
            await producer
        ingestion_done.set()      # only now may the consumer exit on an empty queue
        await consumer

    ok, broken = AuditLog.verify(settings.audit_log_path)
    _log("AUDIT", f"chain verification: {'OK' if ok else f'BROKEN at line {broken}'} "
                  f"({settings.audit_log_path})")

    pending = approvals.list(status="pending")
    if pending:
        _log("APPROVAL", f"{len(pending)} action(s) awaiting human approval:")
        for r in pending:
            _log("APPROVAL", f"  {r.request_id}  {r.action_class.value} on {r.target}  "
                            f"(finding {r.finding_id}, severity {r.severity})")
        _log("APPROVAL", "Review with:  python3 approve.py list")
        _log("APPROVAL", "Authorize with:  python3 approve.py approve <id> --by <you> --reason <why>")

    _log("BOOT", f"=== stopped. findings processed: {orchestrator.processed} ===")
    return 0


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "samples/guardduty_findings.json"
    try:
        raise SystemExit(asyncio.run(main(path)))
    except KeyboardInterrupt:
        # Ctrl-C during startup/teardown outside the drained window.
        _log("BOOT", "interrupted.")
        raise SystemExit(130)
