"""
Behavioral-trajectory guard — the automatic kill switch for a runaway or
redirected containment pipeline.

Kronagent is itself an autonomous multi-agent system that, in live mode, holds
production write-credentials — it can revoke IAM, delete pods, block IPs. The
2026 agent-security incidents (e.g. the OpenAI GPT-5.6 Sol sandbox escape, where
an agent reward-hacked its way out of containment to reach a production
database) are not only a threat to defend *against*; they describe what an Kronagent
agent could *become* under prompt injection or misalignment. The lesson those
post-mortems converge on: **"single-call security monitoring is all but useless"
— you must watch behavioral trajectories across actions and back them with an
automatic kill switch.**

Kronagent's existing controls are strong on the single-action axis (the policy
engine gates each action; LLM agents are advisory and cannot emit a target).
The gap this module fills is the *trajectory* axis — two deterministic controls
over the stream of actions:

  1. **Scope integrity (stateless, per action).** Every containment action must
     target a resource actually implicated by its finding (a normalized resource
     id, or the finding's remote IP for IP-blocking actions). An action aimed at
     anything else is, by construction, a redirection — the exact
     prompt-injection-to-wrong-resource failure — and is blocked outright.
  2. **Runaway rate (stateful, across actions).** A burst of autonomous
     executions, or repeated scope violations, within a short window is the
     machine-speed-runaway signal. Crossing the threshold latches an automatic
     halt that blocks all further containment until a human clears it.

Deterministic by design: no LLM, so the safety backstop itself cannot be
prompt-injected. Session-scoped state (a real multi-replica deployment shares it
via the datastore); the docstring says so rather than implying more.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import json
import os
import tempfile
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Deque, Optional

from pydantic import BaseModel, Field


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

from .model import Finding
from .schemas import ProposedAction


@dataclass(frozen=True)
class TrajectoryConfig:
    window_seconds: float = 60.0
    # A burst of autonomous executions beyond this within the window latches the
    # halt. Normal earn-trust operation auto-executes rarely (few allowlisted
    # classes), so this ceiling is far above healthy behavior.
    max_auto_executions: int = 25
    # Any repeated out-of-scope targeting is alarming — a low ceiling.
    max_scope_violations: int = 3
    enforce_scope: bool = True

    @classmethod
    def from_env(cls) -> "TrajectoryConfig":
        return cls(
            window_seconds=float(os.getenv("KRONAGENT_TRAJECTORY_WINDOW_SECONDS", "60")),
            max_auto_executions=int(os.getenv("KRONAGENT_TRAJECTORY_MAX_AUTO", "25")),
            max_scope_violations=int(os.getenv("KRONAGENT_TRAJECTORY_MAX_SCOPE_VIOLATIONS", "3")),
            enforce_scope=os.getenv("KRONAGENT_TRAJECTORY_ENFORCE_SCOPE", "true").strip().lower()
            in {"1", "true", "yes", "on"},
        )


class TrajectoryEvent(BaseModel):
    """A guard finding, written to the audit log. `halted` marks the event that
    tripped (or occurred after) the automatic kill switch."""

    kind: str            # "scope_violation" | "runaway_halt"
    reason: str
    action_class: str = ""
    target: str = ""
    finding_id: str = ""
    halted: bool = False


def legitimate_targets(finding: Finding) -> set[str]:
    """The only resource identifiers a containment action for this finding may
    target: the finding's normalized resources, plus its remote IP (for
    IP-blocking actions). The provider planners only ever produce these, so any
    other target is an out-of-scope redirection."""
    targets = {r.id for r in finding.resources}
    if finding.remote_ip:
        targets.add(finding.remote_ip)
    return targets


class HaltRecord(BaseModel):
    """A latched halt, as persisted. Its presence in the store IS the halt."""

    reason: str
    engaged_at: str = Field(default_factory=_utc_now)
    kind: str = "automatic"      # "automatic" (guard-tripped) | "manual" (operator)
    engaged_by: str = "kronagent-trajectory-guard"
    finding_id: str = ""
    action_class: str = ""


class TrajectoryStateStore:
    """Persistence for the latched halt.

    Two problems are solved by writing the halt to disk rather than holding it
    only in memory:

      1. **A restart must not silently release the kill switch.** An in-memory
         latch is cleared by any process restart — including one triggered by
         the very incident that tripped it. That turns a safety control into a
         suggestion. A halt is meant to persist until a human clears it, so it
         has to outlive the process.
      2. **An operator needs a way to clear it.** The guard lives inside a
         running orchestrator; `halt.py` is a separate process and cannot reach
         into its memory. A shared file is the seam.

    Read on every action, exactly like `AllowlistStore.is_allowed`, so an
    operator's `halt.py clear` takes effect immediately with no restart.
    """

    def __init__(self, path: str) -> None:
        self._path = path

    # --- persistence (same atomic-replace pattern as AllowlistStore) ---
    def read(self) -> Optional[HaltRecord]:
        """The current halt, or None when containment is running normally."""
        if not self._path or not os.path.exists(self._path):
            return None
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError):
            # An unreadable state file must not be read as "not halted" — that
            # would fail open. Report a halt and say why.
            return HaltRecord(
                reason=f"trajectory state file {self._path!r} is unreadable — failing safe",
                engaged_at=_utc_now(), kind="automatic",
            )
        if not data:
            return None
        try:
            return HaltRecord.model_validate(data)
        except Exception:  # noqa: BLE001 - malformed state also fails safe
            return HaltRecord(
                reason=f"trajectory state file {self._path!r} is malformed — failing safe",
                engaged_at=_utc_now(), kind="automatic",
            )

    def _write(self, data: Optional[dict]) -> None:
        if not self._path:
            return
        directory = os.path.dirname(os.path.abspath(self._path)) or "."
        fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data or {}, fh, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._path)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    def engage(self, record: HaltRecord) -> HaltRecord:
        """Persist a halt. The FIRST halt wins — a later trigger must not
        overwrite the reason the operator needs to investigate."""
        existing = self.read()
        if existing is not None:
            return existing
        self._write(record.model_dump())
        return record

    def clear(self) -> Optional[HaltRecord]:
        """Release the halt. Returns what was cleared (for the audit record),
        or None if nothing was halted."""
        existing = self.read()
        self._write(None)
        return existing


class TrajectoryGuard:
    def __init__(self, config: Optional[TrajectoryConfig] = None,
                 store: Optional[TrajectoryStateStore] = None) -> None:
        self._cfg = config or TrajectoryConfig()
        self._store = store
        self._commits: Deque[float] = deque()
        self._scope_violations: Deque[float] = deque()
        self._halted = False
        self._halt_reason = ""

    @property
    def halted(self) -> bool:
        # The store is authoritative when present: it carries halts engaged by
        # a previous process or by an operator, and it reflects a `halt.py
        # clear` immediately.
        if self._store is not None:
            record = self._store.read()
            if record is not None:
                self._halted = True
                self._halt_reason = record.reason
                return True
            if self._halted:
                # Cleared out from under us by an operator — adopt that.
                self._halted = False
                self._halt_reason = ""
            return False
        return self._halted

    @property
    def halt_reason(self) -> str:
        if self._store is not None:
            record = self._store.read()
            return record.reason if record else ""
        return self._halt_reason

    def _prune(self, dq: Deque[float], now: float) -> None:
        cutoff = now - self._cfg.window_seconds
        while dq and dq[0] < cutoff:
            dq.popleft()

    def _engage_halt(self, reason: str, *, finding_id: str = "",
                     action_class: str = "") -> None:
        if not self._halted:
            self._halted = True
            self._halt_reason = reason
        if self._store is not None:
            self._store.engage(HaltRecord(
                reason=reason, engaged_at=_utc_now(), kind="automatic",
                finding_id=finding_id, action_class=action_class,
            ))

    def check_scope(self, action: ProposedAction, finding: Finding,
                    *, now: Optional[float] = None) -> Optional[TrajectoryEvent]:
        """Return a violation event if the action targets a resource not
        implicated by its finding; None if the action is in scope. Repeated
        violations latch the automatic halt."""
        if not self._cfg.enforce_scope:
            return None
        if action.target in legitimate_targets(finding):
            return None

        now = time.monotonic() if now is None else now
        self._scope_violations.append(now)
        self._prune(self._scope_violations, now)

        tripped = len(self._scope_violations) >= self._cfg.max_scope_violations
        if tripped:
            self._engage_halt(
                f"{len(self._scope_violations)} out-of-scope containment targets within "
                f"{self._cfg.window_seconds:.0f}s — possible action-redirection attack",
                finding_id=finding.finding_id,
                action_class=action.action_class.value,
            )
        return TrajectoryEvent(
            kind="scope_violation",
            reason=(f"action targets '{action.target}', not a resource implicated by finding "
                    f"'{finding.finding_id}' (legitimate: {sorted(legitimate_targets(finding))})"),
            action_class=action.action_class.value,
            target=action.target,
            finding_id=finding.finding_id,
            halted=self._halted,
        )

    def note_auto_execution(self, action: ProposedAction, finding: Finding,
                            *, now: Optional[float] = None) -> Optional[TrajectoryEvent]:
        """Record an action the pipeline decided to execute autonomously. A burst
        beyond the window ceiling latches the automatic halt; returns the halt
        event when it trips (else None)."""
        now = time.monotonic() if now is None else now
        self._commits.append(now)
        self._prune(self._commits, now)

        if len(self._commits) > self._cfg.max_auto_executions and not self._halted:
            self._engage_halt(
                f"{len(self._commits)} autonomous executions within "
                f"{self._cfg.window_seconds:.0f}s exceeds the safe ceiling "
                f"({self._cfg.max_auto_executions}) — runaway containment halted",
                finding_id=finding.finding_id,
                action_class=action.action_class.value,
            )
            return TrajectoryEvent(
                kind="runaway_halt", reason=self._halt_reason,
                action_class=action.action_class.value, target=action.target,
                finding_id=finding.finding_id, halted=True,
            )
        return None

    def engage_manual(self, reason: str, *, by: str) -> HaltRecord:
        """Trip the kill switch by hand — the operator-initiated counterpart to
        an automatic halt. Unlike the `kill_switch` setting this needs no
        restart, and unlike that setting it is attributed and audited."""
        record = HaltRecord(reason=reason, engaged_at=_utc_now(), kind="manual", engaged_by=by)
        self._halted = True
        self._halt_reason = reason
        if self._store is not None:
            return self._store.engage(record)
        return record

    def reset(self) -> str:
        """Clear the latched halt and counters — an explicit operator action
        after investigating. Returns the reason that was cleared (for auditing)."""
        cleared = self._halt_reason
        if self._store is not None:
            record = self._store.clear()
            if record is not None:
                cleared = record.reason
        self._halted = False
        self._halt_reason = ""
        self._commits.clear()
        self._scope_violations.clear()
        return cleared
