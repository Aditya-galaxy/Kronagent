"""
Tests for drift simulation engine and synthetic monitoring validations.
"""

from __future__ import annotations

import asyncio
import os
import pytest

from kronagent.audit import AuditLog
from kronagent.config import Settings
from kronagent.containment import ContainmentExecutor
from kronagent.ingestion import QueuedFinding
from kronagent.orchestrator import Orchestrator
from kronagent.simulation import DriftSimulationEngine
from kronagent.triage import TriageEngine
from kronagent.schemas import PolicyDecision, ProposedAction, BlastRadius


class FakePolicyEngine:
    def decide(self, action: ProposedAction, *, severity: float) -> PolicyDecision:
        return PolicyDecision(
            action_class=action.action_class,
            disposition="auto_execute",
            reversible=True,
            blast_radius=BlastRadius.SINGLE_RESOURCE,
            reason="Fake policy logic.",
        )


def test_drift_simulation_finding_generation() -> None:
    engine = DriftSimulationEngine()
    finding = engine.generate_finding("f-drift-test")

    assert finding.finding_id == "f-drift-test"
    assert finding.finding_type == "Kronagent:Simulation/DriftCheck"
    assert finding.severity == 3.0
    assert finding.provider == "aws"
    assert finding.raw.get("is_simulation") is True


@pytest.mark.asyncio
async def test_drift_pipeline_validation_loop(tmp_path) -> None:
    log_path = str(tmp_path / "kronagent_audit.jsonl")
    settings = Settings(
        max_workers=1,
        audit_log_path=log_path,
        dry_run=True,
    )

    audit = AuditLog(log_path)
    triage = TriageEngine(None)
    policy = FakePolicyEngine()
    containment = ContainmentExecutor(settings, adapters={})

    orchestrator = Orchestrator(
        settings,
        triage=triage,
        policy=policy,
        containment=containment,
        audit=audit,
    )

    engine = DriftSimulationEngine()
    finding_id = "f-drift-test-loop"
    finding = engine.generate_finding(finding_id)

    queue: asyncio.Queue[QueuedFinding] = asyncio.Queue()

    async def mock_ack() -> None:
        pass

    item = QueuedFinding(finding=finding, _ack=mock_ack)
    await queue.put(item)

    ingestion_done = asyncio.Event()
    ingestion_done.set()

    # 1. Assert health check returns False before processing
    assert engine.verify_pipeline_health(log_path, finding_id) is False

    # 2. Run the orchestrator
    await orchestrator.run(queue, ingestion_done)

    # 3. Assert health check returns True post-processing
    assert engine.verify_pipeline_health(log_path, finding_id) is True

    # 4. Assert it returns False for different finding IDs
    assert engine.verify_pipeline_health(log_path, "f-different-id") is False
