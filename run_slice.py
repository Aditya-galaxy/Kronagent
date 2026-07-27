#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com
"""
Kronagent — AWS GuardDuty threat-defense vertical slice (runnable entry point).

Wires the real pipeline end to end:

    GuardDuty findings  ->  Triage (deterministic + LLM)  ->  Policy (graduated
    autonomy)  ->  Containment (dry-run by default)  ->  hash-chained audit log

Ingestion defaults to replaying real-schema findings from samples/ so the whole
system runs locally with no AWS account. Point it at a live SQS queue (fed by
GuardDuty -> EventBridge) and flip KRONAGENT_DRY_RUN=false + promote an action
class with promote.py to graduate it toward autonomy.

Safety posture (all overridable via env, all default safe):
    KRONAGENT_DRY_RUN=true                 # plan only; nothing is executed
    KRONAGENT_KILL_SWITCH=false            # global halt of all containment
    KRONAGENT_MIN_SEVERITY=4.0             # below this: alert only
    KRONAGENT_QUARANTINE_SG_ID=            # required for real instance isolation
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

from kronagent.allowlist import AllowlistStore
from kronagent.approvals import ApprovalStore
from kronagent.audit import AuditLog
from kronagent.config import Settings
from kronagent.commander import IncidentCommanderAgent
from kronagent.containment import ContainmentExecutor
from kronagent.correlation import CorrelationAgent
from kronagent.forensics import ForensicsAgent
from kronagent.ingestion import FileReplaySource, QueuedFinding, SqsFindingSource
from kronagent.intel import ThreatIntelAgent
from kronagent.llm import GeminiTriageClient, LLMUnavailableError
from kronagent.orchestrator import Orchestrator, _log
from kronagent.policy import PolicyEngine
from kronagent.providers import NORMALIZERS, build_containment_adapters
from kronagent.triage import TriageEngine

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
    from kronagent.crypto import get_signer
    signer = get_signer(settings)
    triage = TriageEngine(llm, signer)
    threat_intel = ThreatIntelAgent(llm)  # same LLM client; degrades if unavailable
    correlation = CorrelationAgent(llm)   # campaign correlation across the finding window
    commander = IncidentCommanderAgent(llm)  # synthesis + escalation (advisory)
    forensics = ForensicsAgent(settings)     # deterministic evidence + chain of custody
    policy = PolicyEngine(settings, allowlist)
    containment = ContainmentExecutor(settings, build_containment_adapters(settings))
    approvals = ApprovalStore(settings.approval_store_path)
    trajectory = None
    if settings.trajectory_guard_enabled:
        from kronagent.trajectory import TrajectoryConfig, TrajectoryGuard
        trajectory = TrajectoryGuard(TrajectoryConfig(
            window_seconds=settings.trajectory_window_seconds,
            max_auto_executions=settings.trajectory_max_auto_executions,
            max_scope_violations=settings.trajectory_max_scope_violations,
            enforce_scope=settings.trajectory_enforce_scope,
        ))
    orchestrator = Orchestrator(
        settings, triage=triage, policy=policy, containment=containment,
        audit=audit, approvals=approvals, threat_intel=threat_intel,
        correlation=correlation, commander=commander, forensics=forensics,
        trajectory=trajectory,
    )

    allowed = sorted(e.action_class for e in allowlist.list())
    _log("BOOT", "=== Kronagent autonomous threat-defense platform starting ===")
    _log("BOOT", f"mode: {'DRY-RUN (no execution)' if settings.dry_run else 'LIVE EXECUTION'}"
                 f" | kill_switch={settings.kill_switch}")
    _log("BOOT", f"auto-execute allowlist: {allowed or 'EMPTY (all actions need approval)'}")
    _log("BOOT", f"LLM agents (triage + threat-intel + correlation + commander): {llm_status}")
    _log("BOOT", "deterministic agents: forensics (evidence + chain of custody)")
    if trajectory is not None:
        _log("BOOT", f"trajectory guard: ARMED — scope_enforce={settings.trajectory_enforce_scope}, "
                     f"max_auto={settings.trajectory_max_auto_executions}/"
                     f"{settings.trajectory_window_seconds:.0f}s, "
                     f"max_scope_violations={settings.trajectory_max_scope_violations}")
    else:
        _log("BOOT", "trajectory guard: DISABLED")

    queue: "asyncio.Queue[QueuedFinding]" = asyncio.Queue(maxsize=256)
    stop = asyncio.Event()
    ingestion_done = asyncio.Event()

    # Source selection: SQS if KRONAGENT_SQS_QUEUE_URL is set (live source, runs
    # until Ctrl-C), else replay sample events from disk across all providers.
    sqs_url = os.getenv("KRONAGENT_SQS_QUEUE_URL")
    if sqs_url:
        sqs_provider = os.getenv("KRONAGENT_SQS_PROVIDER", "aws")
        _log("BOOT", f"ingestion: SQS long-poll {sqs_url} (provider={sqs_provider}, "
                     f"region {settings.aws_region})")
        source = SqsFindingSource(
            sqs_url, NORMALIZERS[sqs_provider], region=settings.aws_region,
            wait_seconds=settings.sqs_wait_seconds, endpoint_url=settings.sqs_endpoint_url,
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
