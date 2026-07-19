#!/usr/bin/env python3
"""
Aegis — AWS GuardDuty threat-defense vertical slice (runnable entry point).

Wires the real pipeline end to end:

    GuardDuty findings  ->  Triage (deterministic + LLM)  ->  Policy (graduated
    autonomy)  ->  Containment (dry-run by default)  ->  hash-chained audit log

Ingestion defaults to replaying real-schema findings from samples/ so the whole
system runs locally with no AWS account. Point it at a live SQS queue (fed by
GuardDuty -> EventBridge) and flip AEGIS_DRY_RUN=false + promote an action
class with promote.py to graduate it toward autonomy.

Safety posture (all overridable via env, all default safe):
    AEGIS_DRY_RUN=true                 # plan only; nothing is executed
    AEGIS_KILL_SWITCH=false            # global halt of all containment
    AEGIS_MIN_SEVERITY=4.0             # below this: alert only
    AEGIS_QUARANTINE_SG_ID=            # required for real instance isolation
    GEMINI_API_KEY=...                 # triage enrichment (optional; degrades)

The auto-execute allowlist is NOT an env var — it's an audited, persisted
store. Empty until an operator runs `promote.py add <action_class>`. See
allowlist.py.

Usage:
    python3 run_slice.py [path-to-findings.json]
"""

from __future__ import annotations

import asyncio
import os
import sys

from aegis.allowlist import AllowlistStore
from aegis.approvals import ApprovalStore
from aegis.audit import AuditLog
from aegis.config import Settings
from aegis.containment import ContainmentExecutor
from aegis.ingestion import FileReplaySource, QueuedFinding, SqsFindingSource
from aegis.intel import ThreatIntelAgent
from aegis.llm import GeminiTriageClient, LLMUnavailableError
from aegis.orchestrator import Orchestrator, _log
from aegis.policy import PolicyEngine
from aegis.providers import NORMALIZERS, build_containment_adapters
from aegis.triage import TriageEngine

# Default file-replay set — one sample per provider, to exercise the whole
# multi-provider pipeline in one local run with no cloud/cluster.
_DEFAULT_REPLAY: list[tuple[str, str]] = [
    ("aws", "samples/guardduty_findings.json"),
    ("kubernetes", "samples/k8s_audit_events.json"),
]


async def _replay_files(sources, queue, stop) -> None:
    """Stream several file sources into the queue in order, then return."""
    for provider, path in sources:
        normalizer = NORMALIZERS[provider]
        await FileReplaySource(path, normalizer, interval=0.5).stream(queue, stop)
        if stop.is_set():
            return


async def main(replay: list[tuple[str, str]]) -> int:
    settings = Settings.from_env()

    # Triage LLM is optional — the pipeline degrades to deterministic triage.
    try:
        llm: GeminiTriageClient | None = GeminiTriageClient()
        llm_status = "Gemini triage enabled"
    except LLMUnavailableError as exc:
        llm = None
        llm_status = f"LLM disabled ({exc}) — deterministic triage only"

    audit = AuditLog(settings.audit_log_path)
    allowlist = AllowlistStore(settings.allowlist_store_path, seed=settings.auto_execute_allowlist)
    triage = TriageEngine(llm)
    threat_intel = ThreatIntelAgent(llm)  # same LLM client; degrades if unavailable
    policy = PolicyEngine(settings, allowlist)
    containment = ContainmentExecutor(settings, build_containment_adapters(settings))
    approvals = ApprovalStore(settings.approval_store_path)
    orchestrator = Orchestrator(
        settings, triage=triage, policy=policy, containment=containment,
        audit=audit, approvals=approvals, threat_intel=threat_intel,
    )

    allowed = sorted(e.action_class for e in allowlist.list())
    _log("BOOT", "=== Aegis autonomous threat-defense platform starting ===")
    _log("BOOT", f"mode: {'DRY-RUN (no execution)' if settings.dry_run else 'LIVE EXECUTION'}"
                 f" | kill_switch={settings.kill_switch}")
    _log("BOOT", f"auto-execute allowlist: {allowed or 'EMPTY (all actions need approval)'}")
    _log("BOOT", f"triage + threat-intel: {llm_status}")
    _log("BOOT", "agents: Triage, Threat Intelligence (MITRE ATT&CK)")

    queue: "asyncio.Queue[QueuedFinding]" = asyncio.Queue(maxsize=256)
    stop = asyncio.Event()
    ingestion_done = asyncio.Event()

    # Source selection: SQS if AEGIS_SQS_QUEUE_URL is set (live source, runs
    # until Ctrl-C), else replay sample events from disk across all providers.
    sqs_url = os.getenv("AEGIS_SQS_QUEUE_URL")
    if sqs_url:
        sqs_provider = os.getenv("AEGIS_SQS_PROVIDER", "aws")
        _log("BOOT", f"ingestion: SQS long-poll {sqs_url} (provider={sqs_provider}, "
                     f"region {settings.aws_region})")
        source = SqsFindingSource(
            sqs_url, NORMALIZERS[sqs_provider], region=settings.aws_region, wait_seconds=20
        )
        producer = asyncio.create_task(source.stream(queue, stop))
        live = True
    else:
        _log("BOOT", f"ingestion: file replay {[p for _, p in replay]} "
                     f"(providers: {sorted({pr for pr, _ in replay})})")
        producer = asyncio.create_task(_replay_files(replay, queue, stop))
        live = False

    consumer = asyncio.create_task(orchestrator.run(queue, ingestion_done))

    try:
        await producer            # live: until Ctrl-C; replay: finishes on its own
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
    # Usage:
    #   run_slice.py                         -> replay every provider's sample set
    #   run_slice.py <provider> <path.json>  -> replay one file as that provider
    if len(sys.argv) >= 3:
        prov = sys.argv[1]
        if prov not in NORMALIZERS:
            _log("BOOT", f"unknown provider '{prov}'. Known: {sorted(NORMALIZERS)}")
            raise SystemExit(2)
        replay = [(prov, sys.argv[2])]
    elif len(sys.argv) == 2:
        # Back-compat: a bare path is replayed as AWS/GuardDuty.
        replay = [("aws", sys.argv[1])]
    else:
        replay = _DEFAULT_REPLAY
    try:
        raise SystemExit(asyncio.run(main(replay)))
    except KeyboardInterrupt:
        # Ctrl-C during startup/teardown outside the drained window.
        _log("BOOT", "interrupted.")
        raise SystemExit(130)
