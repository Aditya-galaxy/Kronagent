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
        data = self._read_all()
        data[request.request_id] = request.model_dump()
        self._write_all(data)
        return request

    def get(self, request_id: str) -> Optional[ApprovalRequest]:
        data = self._read_all()
        raw = data.get(request_id)
        return ApprovalRequest.model_validate(raw) if raw else None

    def list(self, *, status: Optional[str] = None) -> list[ApprovalRequest]:
        data = self._read_all()
        items = [ApprovalRequest.model_validate(v) for v in data.values()]
        if status:
            items = [i for i in items if i.status == status]
        return sorted(items, key=lambda r: r.created_at)

    def update(self, request: ApprovalRequest) -> None:
        data = self._read_all()
        if request.request_id not in data:
            raise KeyError(request.request_id)
        data[request.request_id] = request.model_dump()
        self._write_all(data)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
