"""
Orchestrator: wire ingestion -> triage -> policy -> containment -> audit.

Each finding flows through sequentially and deterministically. Every stage
writes an immutable audit record before the next runs, so the log is a complete
decision trail even if a later stage fails. Containment is gated by the policy
engine and the global dry_run / kill_switch controls.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from .approvals import ApprovalRequest, ApprovalStore
from .audit import AuditLog
from .config import Settings
from .containment import ContainmentExecutor
from .ingestion import QueuedFinding
from .intel import ThreatIntelAgent, ThreatIntelAssessment
from .model import Finding
from .policy import PolicyEngine
from .schemas import AuditRecord
from .triage import TriageEngine


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3] + "Z"


def _log(stage: str, msg: str) -> None:
    print(f"{_ts()} [{stage}] {msg}", flush=True)


class Orchestrator:
    def __init__(
        self,
        settings: Settings,
        *,
        triage: TriageEngine,
        policy: PolicyEngine,
        containment: ContainmentExecutor,
        audit: AuditLog,
        approvals: ApprovalStore | None = None,
        threat_intel: ThreatIntelAgent | None = None,
    ) -> None:
        self._settings = settings
        self._triage = triage
        self._policy = policy
        self._containment = containment
        self._audit = audit
        self._approvals = approvals
        self._threat_intel = threat_intel
        self._processed = 0

    @property
    def processed(self) -> int:
        return self._processed

    async def _handle(self, finding: Finding) -> None:
        _log("INCIDENT", f"--- [{finding.provider}] {finding.finding_id} | "
                         f"{finding.finding_type} | severity={finding.severity} ---")

        # 1. Triage (deterministic detection + LLM enrichment)
        verdict, candidates = await self._triage.assess(finding)
        _log(
            "TRIAGE",
            f"{finding.finding_id}: actionable={verdict.is_actionable_threat} "
            f"category='{verdict.threat_category}' confidence={verdict.confidence:.2f}",
        )
        _log("TRIAGE", f"{finding.finding_id}: {verdict.justification}")
        await self._audit.record(AuditRecord(
            finding_id=finding.finding_id, stage="triage", payload=verdict.model_dump()
        ))

        if not verdict.is_actionable_threat:
            _log("INCIDENT", f"{finding.finding_id}: triaged non-actionable — monitoring only. --- done ---")
            self._processed += 1
            return

        if not candidates:
            _log("INCIDENT", f"{finding.finding_id}: no containment action available for this resource type. --- done ---")
            self._processed += 1
            return

        # 1b. Threat Intelligence enrichment (advisory). Runs only for actionable
        # findings with candidate actions — i.e. the ones heading toward a human
        # decision, where MITRE mapping + IOC assessment enriches the record and
        # the approval context. Never affects the policy decision.
        intel = ThreatIntelAssessment(finding_id=finding.finding_id, available=False)
        if self._threat_intel is not None:
            intel = await self._threat_intel.assess(finding)
            await self._audit.record(AuditRecord(
                finding_id=finding.finding_id, stage="threat_intel", payload=intel.model_dump()
            ))
            if intel.available:
                techniques = ", ".join(
                    f"{t.technique_id} ({t.tactic})" for t in intel.mitre_techniques if t.technique_id
                ) or "none mapped"
                _log("INTEL", f"{finding.finding_id}: ATT&CK: {techniques} | stage: "
                              f"{intel.attack_lifecycle_stage or 'n/a'}")
                _log("INTEL", f"{finding.finding_id}: {intel.intel_summary}")

        # 2 + 3. Policy decision and containment, per candidate action.
        for action in candidates:
            decision = self._policy.decide(action, severity=verdict.severity)
            await self._audit.record(AuditRecord(
                finding_id=finding.finding_id, stage="policy",
                payload={"action": action.model_dump(), "decision": decision.model_dump()},
            ))

            outcome = await self._containment.execute(action, decision)
            await self._audit.record(AuditRecord(
                finding_id=finding.finding_id, stage="containment", payload=outcome.model_dump(),
            ))

            marker = {
                "auto_execute": "AUTO",
                "requires_approval": "APPROVAL",
                "blocked": "BLOCKED",
            }[decision.disposition]
            _log(
                "POLICY",
                f"{finding.finding_id}: {action.action_class.value} -> {marker} "
                f"(reversible={decision.reversible}, blast={decision.blast_radius.value})",
            )

            # Persist approval-gated actions so an operator can authorize them.
            if decision.disposition == "requires_approval" and self._approvals is not None:
                req = self._approvals.add(ApprovalRequest(
                    finding_id=finding.finding_id,
                    finding_type=finding.finding_type,
                    severity=verdict.severity,
                    provider=action.provider,
                    action_class=action.action_class,
                    target=action.target,
                    rationale=action.rationale,
                    parameters=action.parameters,
                    policy_reason=decision.reason,
                    reversible=decision.reversible,
                    blast_radius=decision.blast_radius.value,
                    planned_api_calls=outcome.api_calls,
                    rollback_hint=outcome.rollback_hint,
                    mitre_techniques=intel.technique_ids(),
                    threat_intel_summary=intel.intel_summary,
                ))
                _log("CONTAIN", f"{finding.finding_id}: {outcome.detail}  [approval id: {req.request_id}]")
            else:
                _log("CONTAIN", f"{finding.finding_id}: {outcome.detail}")

            for call in outcome.api_calls:
                _log("CONTAIN", f"{finding.finding_id}:   plan $ {call}")
            _log("CONTAIN", f"{finding.finding_id}:   rollback: {outcome.rollback_hint}")

        _log("INCIDENT", f"{finding.finding_id}: --- response complete ---")
        self._processed += 1

    async def run(self, queue: "asyncio.Queue[QueuedFinding]", ingestion_done: asyncio.Event) -> None:
        while not (ingestion_done.is_set() and queue.empty()):
            try:
                item = await asyncio.wait_for(queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            finding = item.finding
            try:
                await self._handle(finding)
            except Exception as exc:  # noqa: BLE001 - one bad finding must not stop the pipeline
                _log("ERROR", f"{finding.finding_id}: pipeline error — {type(exc).__name__}: {exc}")
                await self._audit.record(AuditRecord(
                    finding_id=finding.finding_id, stage="error", payload={"error": str(exc)}
                ))
            finally:
                # Retire the message from the upstream source only after it has
                # been fully processed and audited (at-least-once). A failed ack
                # is logged, not raised — the message will simply redeliver.
                try:
                    await item.ack()
                except Exception as exc:  # noqa: BLE001
                    _log("ERROR", f"{finding.finding_id}: ack failed (will redeliver) — "
                                  f"{type(exc).__name__}: {exc}")
                queue.task_done()
