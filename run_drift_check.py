#!/usr/bin/env python3
"""
CLI tool to run a synthetic benign threat drift check to validate pipeline health.
"""

from __future__ import annotations

import asyncio
import sys
import uuid

from kronagent.allowlist import AllowlistStore
from kronagent.approvals import ApprovalStore
from kronagent.audit import AuditLog
from kronagent.commander import IncidentCommanderAgent
from kronagent.config import Settings
from kronagent.containment import ContainmentExecutor
from kronagent.correlation import CorrelationAgent
from kronagent.forensics import ForensicsAgent
from kronagent.ingestion import QueuedFinding
from kronagent.intel import ThreatIntelAgent
from kronagent.orchestrator import Orchestrator
from kronagent.policy import PolicyEngine
from kronagent.providers import build_containment_adapters
from kronagent.simulation import DriftSimulationEngine
from kronagent.triage import TriageEngine


async def run_check() -> int:
    print(">>> Initializing Kronagent components for Drift Validation...")
    import dataclasses
    settings = dataclasses.replace(Settings.from_env(), dry_run=True)

    audit = AuditLog(settings.audit_log_path)
    allowlist = AllowlistStore(settings.allowlist_store_path, seed=settings.auto_execute_allowlist)
    from kronagent.crypto import get_signer
    signer = get_signer(settings)
    triage = TriageEngine(None, signer)  # deterministic fallback
    threat_intel = ThreatIntelAgent(None)
    correlation = CorrelationAgent(None)
    commander = IncidentCommanderAgent(None)
    forensics = ForensicsAgent(settings)
    policy = PolicyEngine(settings, allowlist)
    containment = ContainmentExecutor(settings, build_containment_adapters(settings))
    approvals = ApprovalStore(settings.approval_store_path)

    orchestrator = Orchestrator(
        settings,
        triage=triage,
        policy=policy,
        containment=containment,
        audit=audit,
        approvals=approvals,
        threat_intel=threat_intel,
        correlation=correlation,
        commander=commander,
        forensics=forensics,
    )

    # 1. Generate synthetic finding
    simulation = DriftSimulationEngine()
    finding_id = f"f-drift-{uuid.uuid4().hex[:8]}"
    finding = simulation.generate_finding(finding_id)
    print(f">>> Generated synthetic drift finding: {finding_id}")

    # 2. Setup ingestion queue
    queue: asyncio.Queue[QueuedFinding] = asyncio.Queue()

    async def mock_ack():
        pass

    await queue.put(QueuedFinding(finding=finding, _ack=mock_ack))

    ingestion_done = asyncio.Event()
    ingestion_done.set()  # No more incoming items

    # 3. Process the queue
    print(">>> Running orchestrator check loop...")
    await orchestrator.run(queue, ingestion_done)

    # 4. Verify pipeline health
    print(">>> Verifying audit logs for drift validation...")
    ok = simulation.verify_pipeline_health(settings.audit_log_path, finding_id)
    if ok:
        print(">>> SUCCESS: Pipeline health check completed successfully. Triage recorded.")
        return 0
    else:
        print(">>> FAILURE: Triage record missing from audit log. Pipeline health compromised.")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(run_check()))
