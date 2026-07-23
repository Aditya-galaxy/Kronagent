"""
The earn-trust dial, made real and audited.

Before this module, "graduating" an action class to autonomous execution meant
editing AEGIS_AUTO_EXECUTE_ALLOWLIST and restarting the process — a change with
zero record of who made it or why. For a platform whose entire safety case
rests on "nothing executes unattended until a human decided it should," that
gap was the biggest inconsistency in the system: the single most consequential
decision it makes had no audit trail.

AllowlistStore fixes that:
  * persisted to disk (JSON, atomic write) so it survives restarts without
    redeploying a new env var,
  * every add/remove is written to the hash-chained AuditLog as a "governance"
    stage record — the same forensic backbone containment and approval
    decisions already use,
  * read live by PolicyEngine on every decision — promoting or demoting an
    action class takes effect immediately, no restart.

Seeded on first use from AEGIS_AUTO_EXECUTE_ALLOWLIST (if set) so existing
deployments aren't silently reset to empty.
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Optional

from pydantic import BaseModel, Field

from .audit import AuditLog
from .schemas import ActionClass, AuditRecord, utcnow_iso


class AllowlistEntry(BaseModel):
    action_class: str
    added_by: str
    added_at: str = Field(default_factory=utcnow_iso)
    reason: str


class AllowlistStore:
    def __init__(self, path: str, *, seed: frozenset[str] = frozenset()) -> None:
        self._path = path
        if not os.path.exists(self._path) and seed:
            self._write_all({
                ac: AllowlistEntry(
                    action_class=ac, added_by="system", reason="seeded from AEGIS_AUTO_EXECUTE_ALLOWLIST"
                ).model_dump()
                for ac in seed
            })

    # --- persistence (same atomic-replace pattern as ApprovalStore) ---
    def _read_all(self) -> dict[str, dict]:
        if not os.path.exists(self._path):
            return {}
        with open(self._path, "r", encoding="utf-8") as fh:
            try:
                return json.load(fh)
            except json.JSONDecodeError:
                return {}

    def _write_all(self, data: dict[str, dict]) -> None:
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

    # --- read path used by PolicyEngine on every decision ---
    def is_allowed(self, action_class: ActionClass) -> bool:
        return action_class.value in self._read_all()

    def list(self) -> list[AllowlistEntry]:
        return sorted(
            (AllowlistEntry.model_validate(v) for v in self._read_all().values()),
            key=lambda e: e.action_class,
        )

    # --- write path: operator-driven, always audited ---
    async def add(
        self, action_class: ActionClass, *, by: str, reason: str, audit: AuditLog,
        actor_fields: Optional[dict] = None,
    ) -> AllowlistEntry:
        entry = AllowlistEntry(action_class=action_class.value, added_by=by, reason=reason)
        data = self._read_all()
        already_present = action_class.value in data
        data[action_class.value] = entry.model_dump()
        self._write_all(data)
        await audit.record(AuditRecord(
            finding_id="_governance", stage="governance",
            payload={
                "decision": "allowlist_add", "action_class": action_class.value,
                "by": by, "reason": reason, "already_present": already_present,
                **(actor_fields or {}),
            },
        ))
        return entry

    async def remove(
        self, action_class: ActionClass, *, by: str, reason: str, audit: AuditLog,
        actor_fields: Optional[dict] = None,
    ) -> bool:
        data = self._read_all()
        existed = data.pop(action_class.value, None) is not None
        if existed:
            self._write_all(data)
        await audit.record(AuditRecord(
            finding_id="_governance", stage="governance",
            payload={
                "decision": "allowlist_remove", "action_class": action_class.value,
                "by": by, "reason": reason, "existed": existed,
                **(actor_fields or {}),
            },
        ))
        return existed
