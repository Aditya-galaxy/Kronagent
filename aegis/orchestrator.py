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

from .allowlist import AllowlistStore
from .approvals import ApprovalRequest, ApprovalStore
from .audit import AuditLog
from .commander import IncidentAssessment, IncidentCommanderAgent
from .config import Settings
from .containment import ContainmentExecutor
from .correlation import CorrelationAgent, CorrelationAssessment, CorrelationMemory
from .forensics import ForensicsAgent, ForensicsResult
from .ingestion import QueuedFinding
from .intel import ThreatIntelAgent, ThreatIntelAssessment
from .model import Finding
from .policy import PolicyEngine
from .schemas import AuditRecord
from .triage import TriageEngine


import os


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3] + "Z"


def _log(stage: str, msg: str) -> None:
    print(f"{_ts()} [{stage}] {msg}", flush=True)


def get_tenant_path(base_path: str, tenant_id: str) -> str:
    if not base_path:
        return ""
    if not tenant_id or tenant_id == "default":
        return base_path
    root, ext = os.path.splitext(base_path)
    return f"{root}_{tenant_id}{ext}"


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
        correlation: CorrelationAgent | None = None,
        commander: IncidentCommanderAgent | None = None,
        forensics: ForensicsAgent | None = None,
    ) -> None:
        self._settings = settings
        self._triage = triage
        self._policy = policy
        self._containment = containment
        self._audit = audit
        self._approvals = approvals
        self._threat_intel = threat_intel
        self._correlation = correlation
        self._commander = commander
        self._forensics = forensics
        # Session-scoped campaign memory cache per tenant
        self._tenant_memories: dict[str, CorrelationMemory] = {}
        # Session-scoped campaign memory: only maintained when a correlation
        # agent is present. Every finding is recorded (incl. non-actionable
        # noise, which is often a campaign's first stage).
        self._memory = CorrelationMemory(settings.db_path) if correlation is not None else None
        self._processed = 0

    @property
    def processed(self) -> int:
        return self._processed

    async def _handle(self, finding: Finding) -> None:
        _log("INCIDENT", f"--- [{finding.provider}] {finding.finding_id} | "
                         f"{finding.finding_type} | severity={finding.severity} | tenant={finding.tenant_id} ---")

        # Dynamically resolve tenant-specific stores
        if not finding.tenant_id or finding.tenant_id == "default":
            tenant_audit = self._audit
            tenant_allowlist = self._policy._allowlist if hasattr(self._policy, "_allowlist") else AllowlistStore(self._settings.allowlist_store_path)
            tenant_approvals = self._approvals
            tenant_memory = self._memory
        else:
            tenant_audit_path = get_tenant_path(self._settings.audit_log_path, finding.tenant_id)
            audit_class = self._audit.__class__ if self._audit else AuditLog
            tenant_audit = audit_class(tenant_audit_path)

            tenant_allowlist_path = get_tenant_path(self._settings.allowlist_store_path, finding.tenant_id)
            allowlist_class = self._policy._allowlist.__class__ if hasattr(self._policy, "_allowlist") else AllowlistStore
            tenant_allowlist = allowlist_class(tenant_allowlist_path)

            tenant_approvals = None
            if self._approvals is not None:
                tenant_approvals_path = get_tenant_path(self._settings.approval_store_path, finding.tenant_id)
                approvals_class = self._approvals.__class__
                tenant_approvals = approvals_class(tenant_approvals_path)

            tenant_memory = None
            if self._correlation is not None:
                if finding.tenant_id not in self._tenant_memories:
                    tenant_db_path = get_tenant_path(self._settings.db_path, finding.tenant_id) if self._settings.db_path else None
                    self._tenant_memories[finding.tenant_id] = CorrelationMemory(tenant_db_path)
                tenant_memory = self._tenant_memories[finding.tenant_id]

        # Record into campaign memory BEFORE triage's early-returns
        prior = []
        if tenant_memory is not None:
            prior = tenant_memory.prior_to(finding.finding_id)
            from .sanitization import sanitize_finding
            tenant_memory.add(sanitize_finding(finding))

        # 1. Triage (deterministic detection + LLM enrichment)
        verdict, candidates = await self._triage.assess(finding)

        # Verify agent signature if required
        if self._settings.require_agent_signatures:
            from .crypto import get_signer
            signer = get_signer(self._settings)
            if not verdict.verify_signature(signer):
                _log("SECURITY_ALERT", f"{finding.finding_id}: triage verdict signature validation FAILED!")
                await tenant_audit.record(AuditRecord(
                    finding_id=finding.finding_id,
                    stage="security_alert",
                    payload={"detail": "Triage verdict signature validation failed. Possible tampering."}
                ))
                raise ValueError(f"Triage verdict signature verification failed for finding {finding.finding_id}")

        _log(
            "TRIAGE",
            f"{finding.finding_id}: actionable={verdict.is_actionable_threat} "
            f"category='{verdict.threat_category}' confidence={verdict.confidence:.2f}",
        )
        _log("TRIAGE", f"{finding.finding_id}: {verdict.justification}")
        await tenant_audit.record(AuditRecord(
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

        # 1b. Threat Intelligence enrichment (advisory)
        intel = ThreatIntelAssessment(finding_id=finding.finding_id, available=False)
        if self._threat_intel is not None:
            intel = await self._threat_intel.assess(finding)
            await tenant_audit.record(AuditRecord(
                finding_id=finding.finding_id, stage="threat_intel", payload=intel.model_dump()
            ))
            if intel.available:
                techniques = ", ".join(
                    f"{t.technique_id} ({t.tactic})" for t in intel.mitre_techniques if t.technique_id
                ) or "none mapped"
                _log("INTEL", f"{finding.finding_id}: ATT&CK: {techniques} | stage: "
                              f"{intel.attack_lifecycle_stage or 'n/a'}")
                _log("INTEL", f"{finding.finding_id}: {intel.intel_summary}")

        # 1c. Investigation / Correlation (advisory)
        correlation = CorrelationAssessment(finding_id=finding.finding_id, available=False)
        if self._correlation is not None:
            correlation = await self._correlation.assess(finding, prior)
            await tenant_audit.record(AuditRecord(
                finding_id=finding.finding_id, stage="correlation", payload=correlation.model_dump()
            ))
            if correlation.available and correlation.part_of_campaign:
                _log("CORRELATE", f"{finding.finding_id}: CAMPAIGN — related to "
                                  f"{correlation.related_finding_ids}")
                _log("CORRELATE", f"{finding.finding_id}: {correlation.correlation_summary}")
            elif correlation.available:
                _log("CORRELATE", f"{finding.finding_id}: no campaign link found "
                                  f"across {len(prior)} prior finding(s)")

        # 1d. Incident Commander (advisory synthesis)
        command = IncidentAssessment(finding_id=finding.finding_id, available=False)
        if self._commander is not None:
            command = await self._commander.assess(finding, verdict, intel, correlation)
            await tenant_audit.record(AuditRecord(
                finding_id=finding.finding_id, stage="command", payload=command.model_dump()
            ))
            if command.available:
                flag = "⚠ ESCALATE NOW" if command.escalate_to_human_now else "queued"
                _log("COMMAND", f"{finding.finding_id}: priority={command.priority or 'n/a'} "
                                f"[{flag}] — {command.escalation_reason}")
                _log("COMMAND", f"{finding.finding_id}: {command.incident_narrative}")

        # 1e. Forensics (deterministic)
        forensics = ForensicsResult(finding_id=finding.finding_id, provider=finding.provider)
        if self._forensics is not None:
            forensics = await self._forensics.collect(finding, tenant_audit)
            if forensics.items:
                _log("FORENSICS", f"{finding.finding_id}: preserved {len(forensics.items)} "
                                  f"evidence item(s): {forensics.evidence_kinds()}")
                for it in forensics.items:
                    _log("FORENSICS", f"{finding.finding_id}:   {it.kind} custody={it.custody_sha256[:12]}…")

        # 2 + 3. Policy decision and containment, per candidate action.
        for action in candidates:
            import inspect
            sig = inspect.signature(self._policy.decide)
            if "allowlist" in sig.parameters:
                decision = self._policy.decide(action, severity=verdict.severity, allowlist=tenant_allowlist)
            else:
                decision = self._policy.decide(action, severity=verdict.severity)
            await tenant_audit.record(AuditRecord(
                finding_id=finding.finding_id, stage="policy",
                payload={"action": action.model_dump(), "decision": decision.model_dump()},
            ))

            outcome = await self._containment.execute(action, decision)
            await tenant_audit.record(AuditRecord(
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
            if decision.disposition == "requires_approval" and tenant_approvals is not None:
                req = tenant_approvals.add(ApprovalRequest(
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
                    related_finding_ids=correlation.related_finding_ids,
                    correlation_summary=correlation.correlation_summary,
                    incident_priority=command.priority,
                    escalated=command.escalate_to_human_now,
                    incident_narrative=command.incident_narrative,
                    evidence_collected=forensics.evidence_kinds(),
                ))
                _log("CONTAIN", f"{finding.finding_id}: {outcome.detail}  [approval id: {req.request_id}]")
                
                # Trigger interactive Slack notification card in a background thread executor
                from .chatops import ChatOpsNotifier
                import asyncio
                
                ts = await asyncio.to_thread(
                    ChatOpsNotifier.send_approval_notification,
                    self._settings,
                    req
                )
                if ts:
                    req.slack_ts = ts
                    tenant_approvals.update(req)
            else:
                _log("CONTAIN", f"{finding.finding_id}: {outcome.detail}")

            for call in outcome.api_calls:
                _log("CONTAIN", f"{finding.finding_id}:   plan $ {call}")
            _log("CONTAIN", f"{finding.finding_id}:   rollback: {outcome.rollback_hint}")

        _log("INCIDENT", f"{finding.finding_id}: --- response complete ---")
        self._processed += 1

    async def _worker(self, queue: "asyncio.Queue[QueuedFinding]", ingestion_done: asyncio.Event) -> None:
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
                if not finding.tenant_id or finding.tenant_id == "default":
                    tenant_audit = self._audit
                else:
                    tenant_audit_path = get_tenant_path(self._settings.audit_log_path, finding.tenant_id)
                    audit_class = self._audit.__class__ if self._audit else AuditLog
                    tenant_audit = audit_class(tenant_audit_path)
                await tenant_audit.record(AuditRecord(
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

    async def run(self, queue: "asyncio.Queue[QueuedFinding]", ingestion_done: asyncio.Event) -> None:
        max_workers = getattr(self._settings, "max_workers", 1)
        if max_workers <= 1:
            await self._worker(queue, ingestion_done)
        else:
            _log("ORCHESTRATOR", f"Starting parallel execution with {max_workers} worker tasks")
            workers = [
                asyncio.create_task(self._worker(queue, ingestion_done))
                for _ in range(max_workers)
            ]
            await asyncio.gather(*workers)
