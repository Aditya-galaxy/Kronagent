"""
Human-approval workflow for containment actions.

The policy engine routes any action that isn't cleared for autonomy to a human.
This module is where those actions wait, and how an operator authorizes or
rejects them. It closes the earn-trust loop: an APPROVAL-gated action is
persisted with everything needed to execute it later, an operator decides
(with attribution and a reason), and only on approval does containment run.

Separation of concerns:
  * The audit log (audit.py) is the IMMUTABLE forensic trail — append-only,
    hash-chained. It records that an approval was requested/granted/executed.
  * This ApprovalStore is MUTABLE operational state — the current status of
    each pending request. It is the work queue an operator acts on.

The local store is a single JSON file rewritten under a lock. That is correct
for a single-operator slice; production needs a real datastore with row-level
locking and multi-operator concurrency (noted, not faked).
"""

from __future__ import annotations

import json
import os
import tempfile
import uuid
from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, Field

from .schemas import ActionClass, ProposedAction, utcnow_iso


class ApprovalRequest(BaseModel):
    request_id: str = Field(default_factory=lambda: "apr-" + uuid.uuid4().hex[:12])
    created_at: str = Field(default_factory=utcnow_iso)

    # Context needed to execute the action later, and to explain it to a human.
    finding_id: str
    finding_type: str
    severity: float
    provider: str = "aws"         # which containment adapter owns this action
    action_class: ActionClass
    target: str
    rationale: str
    parameters: dict = Field(default_factory=dict)
    policy_reason: str            # why the policy engine required approval
    reversible: bool
    blast_radius: str
    planned_api_calls: list[str] = Field(default_factory=list)
    rollback_hint: str = ""

    # Advisory threat-intel context (from the Threat Intelligence Agent), shown
    # to the human at approval time. Purely informational — never affects the
    # decision the policy engine already made.
    mitre_techniques: list[str] = Field(default_factory=list)
    threat_intel_summary: str = ""

    # Advisory correlation context (from the Investigation / Correlation Agent):
    # prior findings this one appears related to, and the campaign summary. Also
    # purely informational — tells the human "this isn't an isolated alert."
    related_finding_ids: list[str] = Field(default_factory=list)
    correlation_summary: str = ""

    # Advisory incident-command context (from the Incident Commander Agent): the
    # synthesized priority and whether this was flagged for immediate paging.
    # Advisory only — it prioritizes the human's queue, never the policy decision.
    incident_priority: str = ""
    escalated: bool = False
    incident_narrative: str = ""

    # Chain-of-custody evidence collected for this finding before containment
    # (from the Forensics Agent), by evidence kind. Tells the human what forensic
    # record was preserved.
    evidence_collected: list[str] = Field(default_factory=list)

    # Decision state (mutated by an operator).
    status: Literal["pending", "approved", "denied", "executed", "failed"] = "pending"
    decided_by: Optional[str] = None
    decided_at: Optional[str] = None
    decision_reason: Optional[str] = None
    execution_detail: Optional[str] = None

    def to_proposed_action(self) -> ProposedAction:
        return ProposedAction(
            provider=self.provider,
            action_class=self.action_class,
            target=self.target,
            rationale=self.rationale,
            parameters=self.parameters,
        )


class ApprovalStore:
    def __init__(self, path: str) -> None:
        self._path = path
        self._is_db = path.endswith(".db")
        if self._is_db:
            import sqlite3
            conn = sqlite3.connect(self._path)
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS approvals (
                        request_id TEXT PRIMARY KEY,
                        created_at TEXT NOT NULL,
                        finding_id TEXT NOT NULL,
                        finding_type TEXT NOT NULL,
                        severity REAL NOT NULL,
                        provider TEXT NOT NULL,
                        action_class TEXT NOT NULL,
                        target TEXT NOT NULL,
                        rationale TEXT NOT NULL,
                        parameters TEXT NOT NULL, -- JSON dict
                        policy_reason TEXT NOT NULL,
                        reversible INTEGER NOT NULL, -- 0 or 1
                        blast_radius TEXT NOT NULL,
                        planned_api_calls TEXT NOT NULL, -- JSON list
                        rollback_hint TEXT NOT NULL,
                        mitre_techniques TEXT NOT NULL, -- JSON list
                        threat_intel_summary TEXT NOT NULL,
                        related_finding_ids TEXT NOT NULL, -- JSON list
                        correlation_summary TEXT NOT NULL,
                        incident_priority TEXT NOT NULL,
                        escalated INTEGER NOT NULL, -- 0 or 1
                        incident_narrative TEXT NOT NULL,
                        evidence_collected TEXT NOT NULL, -- JSON list
                        status TEXT NOT NULL,
                        decided_by TEXT,
                        decided_at TEXT,
                        decision_reason TEXT,
                        execution_detail TEXT
                    )
                """)
                conn.commit()
            finally:
                conn.close()

    def _read_all(self) -> dict[str, dict]:
        if not os.path.exists(self._path):
            return {}
        with open(self._path, "r", encoding="utf-8") as fh:
            try:
                return json.load(fh)
            except json.JSONDecodeError:
                return {}

    def _write_all(self, data: dict[str, dict]) -> None:
        # Atomic replace: write to a temp file in the same dir, then rename, so
        # a crash mid-write can never corrupt the store.
        directory = os.path.dirname(os.path.abspath(self._path)) or "."
        fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._path)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    def add(self, request: ApprovalRequest) -> ApprovalRequest:
        if not self._is_db:
            data = self._read_all()
            data[request.request_id] = request.model_dump()
            self._write_all(data)
            return request

        import sqlite3
        conn = sqlite3.connect(self._path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO approvals (
                    request_id, created_at, finding_id, finding_type, severity,
                    provider, action_class, target, rationale, parameters,
                    policy_reason, reversible, blast_radius, planned_api_calls,
                    rollback_hint, mitre_techniques, threat_intel_summary,
                    related_finding_ids, correlation_summary, incident_priority,
                    escalated, incident_narrative, evidence_collected, status,
                    decided_by, decided_at, decision_reason, execution_detail
                ) VALUES (
                    ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?, ?
                )
                """,
                (
                    request.request_id,
                    request.created_at,
                    request.finding_id,
                    request.finding_type,
                    request.severity,
                    request.provider,
                    request.action_class.value,
                    request.target,
                    request.rationale,
                    json.dumps(request.parameters),
                    request.policy_reason,
                    1 if request.reversible else 0,
                    request.blast_radius,
                    json.dumps(request.planned_api_calls),
                    request.rollback_hint,
                    json.dumps(request.mitre_techniques),
                    request.threat_intel_summary,
                    json.dumps(request.related_finding_ids),
                    request.correlation_summary,
                    request.incident_priority,
                    1 if request.escalated else 0,
                    request.incident_narrative,
                    json.dumps(request.evidence_collected),
                    request.status,
                    request.decided_by,
                    request.decided_at,
                    request.decision_reason,
                    request.execution_detail,
                )
            )
            conn.commit()
            return request
        finally:
            conn.close()

    def get(self, request_id: str) -> Optional[ApprovalRequest]:
        if not self._is_db:
            data = self._read_all()
            raw = data.get(request_id)
            return ApprovalRequest.model_validate(raw) if raw else None

        import sqlite3
        conn = sqlite3.connect(self._path)
        try:
            cursor = conn.cursor()
            columns = [
                "request_id", "created_at", "finding_id", "finding_type", "severity",
                "provider", "action_class", "target", "rationale", "parameters",
                "policy_reason", "reversible", "blast_radius", "planned_api_calls",
                "rollback_hint", "mitre_techniques", "threat_intel_summary",
                "related_finding_ids", "correlation_summary", "incident_priority",
                "escalated", "incident_narrative", "evidence_collected", "status",
                "decided_by", "decided_at", "decision_reason", "execution_detail"
            ]
            cursor.execute(f"SELECT {','.join(columns)} FROM approvals WHERE request_id = ?", (request_id,))
            row = cursor.fetchone()
            if not row:
                return None
            
            data = dict(zip(columns, row))
            data["parameters"] = json.loads(data["parameters"])
            data["reversible"] = bool(data["reversible"])
            data["planned_api_calls"] = json.loads(data["planned_api_calls"])
            data["mitre_techniques"] = json.loads(data["mitre_techniques"])
            data["related_finding_ids"] = json.loads(data["related_finding_ids"])
            data["escalated"] = bool(data["escalated"])
            data["evidence_collected"] = json.loads(data["evidence_collected"])
            return ApprovalRequest.model_validate(data)
        finally:
            conn.close()

    def list(self, *, status: Optional[str] = None) -> list[ApprovalRequest]:
        if not self._is_db:
            data = self._read_all()
            items = [ApprovalRequest.model_validate(v) for v in data.values()]
            if status:
                items = [i for i in items if i.status == status]
            return sorted(items, key=lambda r: r.created_at)

        import sqlite3
        conn = sqlite3.connect(self._path)
        try:
            cursor = conn.cursor()
            columns = [
                "request_id", "created_at", "finding_id", "finding_type", "severity",
                "provider", "action_class", "target", "rationale", "parameters",
                "policy_reason", "reversible", "blast_radius", "planned_api_calls",
                "rollback_hint", "mitre_techniques", "threat_intel_summary",
                "related_finding_ids", "correlation_summary", "incident_priority",
                "escalated", "incident_narrative", "evidence_collected", "status",
                "decided_by", "decided_at", "decision_reason", "execution_detail"
            ]
            if status:
                cursor.execute(f"SELECT {','.join(columns)} FROM approvals WHERE status = ? ORDER BY created_at ASC", (status,))
            else:
                cursor.execute(f"SELECT {','.join(columns)} FROM approvals ORDER BY created_at ASC")
            
            rows = cursor.fetchall()
            items = []
            for row in rows:
                data = dict(zip(columns, row))
                data["parameters"] = json.loads(data["parameters"])
                data["reversible"] = bool(data["reversible"])
                data["planned_api_calls"] = json.loads(data["planned_api_calls"])
                data["mitre_techniques"] = json.loads(data["mitre_techniques"])
                data["related_finding_ids"] = json.loads(data["related_finding_ids"])
                data["escalated"] = bool(data["escalated"])
                data["evidence_collected"] = json.loads(data["evidence_collected"])
                items.append(ApprovalRequest.model_validate(data))
            return items
        finally:
            conn.close()

    def update(self, request: ApprovalRequest) -> None:
        if not self._is_db:
            data = self._read_all()
            if request.request_id not in data:
                raise KeyError(request.request_id)
            data[request.request_id] = request.model_dump()
            self._write_all(data)
            return

        import sqlite3
        conn = sqlite3.connect(self._path)
        try:
            cursor = conn.cursor()
            # Verify request exists
            cursor.execute("SELECT 1 FROM approvals WHERE request_id = ?", (request.request_id,))
            if not cursor.fetchone():
                raise KeyError(request.request_id)
            
            cursor.execute(
                """
                UPDATE approvals SET
                    created_at = ?, finding_id = ?, finding_type = ?, severity = ?,
                    provider = ?, action_class = ?, target = ?, rationale = ?, parameters = ?,
                    policy_reason = ?, reversible = ?, blast_radius = ?, planned_api_calls = ?,
                    rollback_hint = ?, mitre_techniques = ?, threat_intel_summary = ?,
                    related_finding_ids = ?, correlation_summary = ?, incident_priority = ?,
                    escalated = ?, incident_narrative = ?, evidence_collected = ?, status = ?,
                    decided_by = ?, decided_at = ?, decision_reason = ?, execution_detail = ?
                WHERE request_id = ?
                """,
                (
                    request.created_at,
                    request.finding_id,
                    request.finding_type,
                    request.severity,
                    request.provider,
                    request.action_class.value,
                    request.target,
                    request.rationale,
                    json.dumps(request.parameters),
                    request.policy_reason,
                    1 if request.reversible else 0,
                    request.blast_radius,
                    json.dumps(request.planned_api_calls),
                    request.rollback_hint,
                    json.dumps(request.mitre_techniques),
                    request.threat_intel_summary,
                    json.dumps(request.related_finding_ids),
                    request.correlation_summary,
                    request.incident_priority,
                    1 if request.escalated else 0,
                    request.incident_narrative,
                    json.dumps(request.evidence_collected),
                    request.status,
                    request.decided_by,
                    request.decided_at,
                    request.decision_reason,
                    request.execution_detail,
                    request.request_id,
                )
            )
            conn.commit()
        finally:
            conn.close()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
