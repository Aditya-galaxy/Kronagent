"""
Orchestrator — sequencing, audit completeness, approval creation, and the
at-least-once ack contract. Uses fakes for triage/policy so each test controls
exactly one variable (the triage verdict, or the policy disposition) without
depending on LLM calls or severity-threshold arithmetic.
"""

from __future__ import annotations

import asyncio
import json
from typing import Callable

import pytest

from aegis.approvals import ApprovalStore
from aegis.audit import AuditLog
from aegis.containment import ContainmentExecutor
from aegis.ingestion import QueuedFinding
from aegis.model import Finding
from aegis.orchestrator import Orchestrator
from aegis.schemas import ActionClass, PolicyDecision, ProposedAction, TriageVerdict

from .conftest import FakeContainmentAdapter, make_decision


class FakeTriageEngine:
    """Returns a pre-scripted (verdict, candidates) pair -- no LLM, no network."""

    def __init__(self, verdict: TriageVerdict, candidates: list[ProposedAction]) -> None:
        self._verdict = verdict
        self._candidates = candidates
        self.assess_calls = 0

    async def assess(self, finding: Finding) -> tuple[TriageVerdict, list[ProposedAction]]:
        self.assess_calls += 1
        return self._verdict, self._candidates


class RaisingTriageEngine:
    async def assess(self, finding: Finding):
        raise RuntimeError("triage exploded")


class FakePolicyEngine:
    """Returns a fixed disposition for every action, regardless of severity."""

    def __init__(self, disposition: str) -> None:
        self._disposition = disposition
        self.decide_calls: list[ProposedAction] = []

    def decide(self, action: ProposedAction, *, severity: float) -> PolicyDecision:
        self.decide_calls.append(action)
        return make_decision(action_class=action.action_class, disposition=self._disposition)


class FakeThreatIntel:
    """Records how many findings it was asked to enrich, and returns a fixed
    assessment with MITRE techniques."""

    def __init__(self) -> None:
        self.assess_calls: list[str] = []

    async def assess(self, finding: Finding):
        from aegis.intel import MitreTechnique, ThreatIntelAssessment
        self.assess_calls.append(finding.finding_id)
        return ThreatIntelAssessment(
            finding_id=finding.finding_id, available=True,
            mitre_techniques=[MitreTechnique(technique_id="T1552.004",
                                             technique_name="Private Keys", tactic="Credential Access")],
            attack_lifecycle_stage="Exfiltration",
            intel_summary="scripted intel summary",
        )


def _finding(provider: str = "kubernetes", finding_id: str = "f-1", severity: float = 8.0) -> Finding:
    return Finding(provider=provider, finding_id=finding_id, finding_type="k8s:test", severity=severity)


def _verdict(finding_id: str, actionable: bool, severity: float = 8.0) -> TriageVerdict:
    return TriageVerdict(
        finding_id=finding_id, is_actionable_threat=actionable, threat_category="Test",
        confidence=0.9, severity=severity, justification="test justification",
    )


def _action(provider: str, action_class: ActionClass, target: str) -> ProposedAction:
    return ProposedAction(provider=provider, action_class=action_class, target=target, rationale="r")


def _queued(finding: Finding) -> tuple[QueuedFinding, Callable[[], int]]:
    """A QueuedFinding whose ack() call count is observable from the test."""
    state = {"acked": 0}

    async def ack() -> None:
        state["acked"] += 1

    return QueuedFinding(finding=finding, _ack=ack), lambda: state["acked"]


def _orchestrator(settings, triage, policy, *, approvals=None, threat_intel=None) -> tuple[Orchestrator, AuditLog]:
    audit = AuditLog(settings.audit_log_path)
    adapter = FakeContainmentAdapter(provider="kubernetes")
    containment = ContainmentExecutor(settings, {"kubernetes": adapter, "aws": adapter})
    orch = Orchestrator(settings, triage=triage, policy=policy, containment=containment,
                         audit=audit, approvals=approvals, threat_intel=threat_intel)
    return orch, audit


async def _drain(orch: Orchestrator, items: list[QueuedFinding]) -> None:
    queue: "asyncio.Queue[QueuedFinding]" = asyncio.Queue()
    for item in items:
        await queue.put(item)
    done = asyncio.Event()
    done.set()  # everything is already enqueued
    await orch.run(queue, done)


async def test_non_actionable_finding_skips_policy_and_containment(settings) -> None:
    triage = FakeTriageEngine(_verdict("f-1", actionable=False), candidates=[])
    policy = FakePolicyEngine(disposition="auto_execute")
    orch, _ = _orchestrator(settings, triage, policy)
    item, acked = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    assert orch.processed == 1
    assert policy.decide_calls == []
    assert acked() == 1


async def test_actionable_with_no_candidates_still_completes(settings) -> None:
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[])
    policy = FakePolicyEngine(disposition="auto_execute")
    orch, _ = _orchestrator(settings, triage, policy)
    item, acked = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    assert orch.processed == 1
    assert policy.decide_calls == []
    assert acked() == 1


async def test_requires_approval_creates_approval_request_with_correct_provider(settings) -> None:
    """End-to-end regression for the provider round-trip bug: an action
    proposed by the Kubernetes provider that requires approval must produce an
    ApprovalRequest whose provider/action_class/target survive to disk."""
    candidate = _action("kubernetes", ActionClass.ISOLATE_POD, "payments-api-7f9c8d")
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[candidate])
    policy = FakePolicyEngine(disposition="requires_approval")
    approvals = ApprovalStore(settings.approval_store_path)
    orch, _ = _orchestrator(settings, triage, policy, approvals=approvals)
    item, acked = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    pending = approvals.list(status="pending")
    assert len(pending) == 1
    assert pending[0].provider == "kubernetes"
    assert pending[0].action_class == ActionClass.ISOLATE_POD
    assert pending[0].target == "payments-api-7f9c8d"
    assert pending[0].to_proposed_action().provider == "kubernetes"
    assert acked() == 1


async def test_auto_execute_does_not_create_an_approval(settings) -> None:
    candidate = _action("kubernetes", ActionClass.ISOLATE_POD, "pod-1")
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[candidate])
    policy = FakePolicyEngine(disposition="auto_execute")
    approvals = ApprovalStore(settings.approval_store_path)
    orch, _ = _orchestrator(settings, triage, policy, approvals=approvals)
    item, acked = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    assert approvals.list() == []
    assert acked() == 1


async def test_blocked_does_not_create_an_approval(settings) -> None:
    candidate = _action("kubernetes", ActionClass.DELETE_POD, "pod-1")
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[candidate])
    policy = FakePolicyEngine(disposition="blocked")
    approvals = ApprovalStore(settings.approval_store_path)
    orch, _ = _orchestrator(settings, triage, policy, approvals=approvals)
    item, acked = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    assert approvals.list() == []
    assert acked() == 1


async def test_multiple_candidates_each_get_a_policy_decision(settings) -> None:
    candidates = [
        _action("kubernetes", ActionClass.ISOLATE_POD, "pod-1"),
        _action("kubernetes", ActionClass.DELETE_POD, "pod-1"),
        _action("kubernetes", ActionClass.CORDON_NODE, "node-1"),
    ]
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=candidates)
    policy = FakePolicyEngine(disposition="requires_approval")
    approvals = ApprovalStore(settings.approval_store_path)
    orch, _ = _orchestrator(settings, triage, policy, approvals=approvals)
    item, acked = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    assert len(policy.decide_calls) == 3
    assert len(approvals.list()) == 3
    assert acked() == 1


async def test_audit_records_every_stage_in_order(settings) -> None:
    candidate = _action("kubernetes", ActionClass.ISOLATE_POD, "pod-1")
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[candidate])
    policy = FakePolicyEngine(disposition="requires_approval")
    orch, audit = _orchestrator(settings, triage, policy)
    item, _ = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    records = [json.loads(l)["record"] for l in open(settings.audit_log_path) if l.strip()]
    stages = [r["stage"] for r in records]
    assert stages == ["triage", "policy", "containment"]
    ok, broken = AuditLog.verify(settings.audit_log_path)
    assert ok is True and broken is None


async def test_error_in_triage_is_caught_audited_and_still_acked(settings) -> None:
    """A single bad finding must not crash the loop, and the message must
    still be acked (the finding was fully handled -- as an error -- not lost
    and not silently redelivered forever)."""
    orch, audit = _orchestrator(settings, RaisingTriageEngine(), FakePolicyEngine("auto_execute"))
    item, acked = _queued(_finding(finding_id="f-bad"))

    await _drain(orch, [item])

    records = [json.loads(l)["record"] for l in open(settings.audit_log_path) if l.strip()]
    assert any(r["stage"] == "error" for r in records)
    assert acked() == 1
    # processed is NOT incremented on error -- _handle raised before reaching
    # the increment, which is correct: this finding did not complete normally.
    assert orch.processed == 0


async def test_error_on_one_finding_does_not_block_the_next(settings) -> None:
    good_verdict = _verdict("f-good", actionable=False)
    good_triage = FakeTriageEngine(good_verdict, candidates=[])

    class MixedTriage:
        def __init__(self) -> None:
            self.calls = 0

        async def assess(self, finding: Finding):
            self.calls += 1
            if finding.finding_id == "f-bad":
                raise RuntimeError("boom")
            return good_verdict, []

    orch, _ = _orchestrator(settings, MixedTriage(), FakePolicyEngine("auto_execute"))
    bad_item, bad_acked = _queued(_finding(finding_id="f-bad"))
    good_item, good_acked = _queued(_finding(finding_id="f-good"))

    await _drain(orch, [bad_item, good_item])

    assert bad_acked() == 1
    assert good_acked() == 1
    assert orch.processed == 1  # only the good finding completed successfully


async def test_threat_intel_enriches_actionable_finding_and_is_audited(settings) -> None:
    candidate = _action("aws", ActionClass.DISABLE_ACCESS_KEY, "AKIA1")
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[candidate])
    policy = FakePolicyEngine(disposition="requires_approval")
    approvals = ApprovalStore(settings.approval_store_path)
    intel = FakeThreatIntel()
    orch, _ = _orchestrator(settings, triage, policy, approvals=approvals, threat_intel=intel)
    item, _acked = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    # Intel ran and was audited.
    assert intel.assess_calls == ["f-1"]
    records = [json.loads(l)["record"] for l in open(settings.audit_log_path) if l.strip()]
    assert any(r["stage"] == "threat_intel" for r in records)

    # And the MITRE context reached the approval request the human will see.
    pending = approvals.list(status="pending")
    assert pending[0].mitre_techniques == ["T1552.004"]
    assert pending[0].threat_intel_summary == "scripted intel summary"


async def test_threat_intel_not_called_for_non_actionable_finding(settings) -> None:
    """Cost discipline: intel must not run on noise. A non-actionable finding
    returns before the enrichment step."""
    triage = FakeTriageEngine(_verdict("f-1", actionable=False), candidates=[])
    intel = FakeThreatIntel()
    orch, _ = _orchestrator(settings, triage, FakePolicyEngine("auto_execute"),
                            threat_intel=intel)
    item, _acked = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    assert intel.assess_calls == []  # never invoked


async def test_threat_intel_not_called_when_no_candidate_actions(settings) -> None:
    """Actionable but no containment action available -> no approval to enrich,
    so intel is skipped (same cost-scoping rationale)."""
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[])
    intel = FakeThreatIntel()
    orch, _ = _orchestrator(settings, triage, FakePolicyEngine("auto_execute"),
                            threat_intel=intel)
    item, _acked = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    assert intel.assess_calls == []


async def test_pipeline_works_without_a_threat_intel_agent(settings) -> None:
    """threat_intel is optional -- the orchestrator must run identically when
    it's None (backward compatible with pre-agent deployments)."""
    candidate = _action("aws", ActionClass.DISABLE_ACCESS_KEY, "AKIA1")
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[candidate])
    approvals = ApprovalStore(settings.approval_store_path)
    orch, _ = _orchestrator(settings, triage, FakePolicyEngine("requires_approval"),
                            approvals=approvals, threat_intel=None)
    item, _acked = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    pending = approvals.list(status="pending")
    assert len(pending) == 1
    assert pending[0].mitre_techniques == []  # no intel, empty advisory fields
    records = [json.loads(l)["record"] for l in open(settings.audit_log_path) if l.strip()]
    assert not any(r["stage"] == "threat_intel" for r in records)


async def test_ack_failure_is_logged_not_raised(settings) -> None:
    triage = FakeTriageEngine(_verdict("f-1", actionable=False), candidates=[])
    orch, audit = _orchestrator(settings, triage, FakePolicyEngine("auto_execute"))

    async def failing_ack() -> None:
        raise ConnectionError("SQS unreachable")

    item = QueuedFinding(finding=_finding(finding_id="f-1"), _ack=failing_ack)

    # Must not raise -- a failed ack means "will redeliver," not "crash the pipeline."
    await _drain(orch, [item])
    assert orch.processed == 1
