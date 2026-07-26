"""
Tests for concurrent processing and audit integrity under Distributed Worker Architecture.
"""

from __future__ import annotations

import asyncio

import pytest

from kronagent.audit import AuditLog
from kronagent.config import Settings
from kronagent.containment import ContainmentExecutor
from kronagent.ingestion import QueuedFinding
from kronagent.model import Finding
from kronagent.orchestrator import Orchestrator
from kronagent.schemas import BlastRadius, PolicyDecision, ProposedAction, TriageVerdict


class AsyncMockTriage:
    async def assess(self, finding: Finding) -> tuple[TriageVerdict, list[ProposedAction]]:
        # Simulate slight async delay to allow concurrent workers to overlap
        await asyncio.sleep(0.05)
        verdict = TriageVerdict(
            finding_id=finding.finding_id,
            is_actionable_threat=True,
            threat_category="Suspicious Activity",
            confidence=0.9,
            severity=5.0,
            justification="Triage assessment completed.",
            correlated_signals=[],
        )
        return verdict, []


class FakePolicyEngine:
    def decide(self, action: ProposedAction, *, severity: float) -> PolicyDecision:
        return PolicyDecision(
            action_class=action.action_class,
            disposition="auto_execute",
            reversible=True,
            blast_radius=BlastRadius.SINGLE_RESOURCE,
            reason="Fake policy logic.",
        )


@pytest.mark.asyncio
async def test_parallel_worker_processing(tmp_path) -> None:
    # 1. Setup paths
    log_path = str(tmp_path / "kronagent_audit.jsonl")

    settings = Settings(
        max_workers=5,
        audit_log_path=log_path,
        dry_run=True,
    )

    # 2. Mock adapters
    audit = AuditLog(log_path)
    triage = AsyncMockTriage()
    policy = FakePolicyEngine()
    containment = ContainmentExecutor(settings, adapters={})

    orchestrator = Orchestrator(
        settings,
        triage=triage,
        policy=policy,
        containment=containment,
        audit=audit,
    )

    # 3. Create a queue and enqueue 15 findings
    queue: asyncio.Queue[QueuedFinding] = asyncio.Queue()
    for i in range(15):
        finding = Finding(
            provider="aws",
            finding_id=f"f-parallel-{i}",
            finding_type="UnauthorizedAccess",
            severity=5.0,
        )

        # Mock QueuedFinding with no-op ack
        async def mock_ack() -> None:
            pass

        item = QueuedFinding(finding=finding, _ack=mock_ack)
        await queue.put(item)

    ingestion_done = asyncio.Event()
    ingestion_done.set()  # no more incoming items

    # 4. Run the orchestrator concurrent worker pool
    await orchestrator.run(queue, ingestion_done)

    # 5. Assertions
    assert orchestrator.processed == 15

    # 6. Cryptographic Chain Integrity Check
    ok, err_line = AuditLog.verify(log_path)
    assert ok is True, f"Audit log chain integrity broken at line {err_line}"
