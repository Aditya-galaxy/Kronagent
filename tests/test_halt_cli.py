"""
Persisted trajectory halt + the operator kill-switch CLI (`halt.py`).

Two properties matter most here, and neither held before this store existed:

  1. **A halt outlives the process.** An in-memory-only latch is released by any
     restart — including a restart caused by the very incident that tripped it.
     That silently converts the kill switch into a suggestion, so it is tested
     as a security property, not a convenience.
  2. **An operator can release it, without a restart.** The guard runs inside
     the orchestrator; `halt.py` is a separate process. The shared state file is
     the seam, and a live guard must observe a clear on its next check.

Unreadable or malformed state must **fail safe** (report halted), never fail
open — a corrupt file is not evidence that containment is safe to resume.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from kronagent.identity import hash_token
from kronagent.model import Finding, ResourceRef
from kronagent.schemas import ActionClass, ProposedAction
from kronagent.trajectory import (
    HaltRecord,
    TrajectoryConfig,
    TrajectoryGuard,
    TrajectoryStateStore,
    _utc_now,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def _finding() -> Finding:
    return Finding(
        provider="aws", finding_id="f-halt-1", finding_type="test:finding", severity=8.0,
        resources=[ResourceRef(kind="aws.ec2.instance", id="i-legit", attributes={})],
    )


def _out_of_scope_action() -> ProposedAction:
    return ProposedAction(
        provider="aws", action_class=ActionClass.TERMINATE_INSTANCE,
        target="i-prod-database", rationale="redirected",
    )


# --------------------------------------------------------------------------- #
# The store
# --------------------------------------------------------------------------- #

def test_store_is_empty_before_any_halt(tmp_path) -> None:
    assert TrajectoryStateStore(str(tmp_path / "h.json")).read() is None


def test_store_round_trips_a_halt(tmp_path) -> None:
    store = TrajectoryStateStore(str(tmp_path / "h.json"))
    store.engage(HaltRecord(reason="runaway", engaged_at=_utc_now(), finding_id="f-9"))

    record = store.read()
    assert record is not None
    assert record.reason == "runaway"
    assert record.finding_id == "f-9"


def test_store_clear_returns_what_it_cleared(tmp_path) -> None:
    store = TrajectoryStateStore(str(tmp_path / "h.json"))
    store.engage(HaltRecord(reason="runaway", engaged_at=_utc_now()))

    cleared = store.clear()
    assert cleared is not None and cleared.reason == "runaway"
    assert store.read() is None
    assert store.clear() is None  # clearing twice is harmless


def test_first_halt_wins(tmp_path) -> None:
    """The operator investigates the reason the switch tripped. A later trigger
    must not overwrite it."""
    store = TrajectoryStateStore(str(tmp_path / "h.json"))
    store.engage(HaltRecord(reason="FIRST — the one being investigated", engaged_at=_utc_now()))
    store.engage(HaltRecord(reason="second", engaged_at=_utc_now()))

    assert store.read().reason == "FIRST — the one being investigated"


@pytest.mark.parametrize("contents", ["{ this is not json", '{"reason": 12345}'])
def test_corrupt_state_fails_safe_not_open(tmp_path, contents) -> None:
    """A state file that cannot be parsed must read as HALTED. Treating it as
    'not halted' would let a corrupted file silently re-enable containment."""
    path = tmp_path / "h.json"
    path.write_text(contents)

    record = TrajectoryStateStore(str(path)).read()
    assert record is not None
    assert "failing safe" in record.reason


def test_empty_state_file_is_not_a_halt(tmp_path) -> None:
    """`clear` writes `{}`; that is the normal running state, not a halt."""
    path = tmp_path / "h.json"
    path.write_text("{}")
    assert TrajectoryStateStore(str(path)).read() is None


# --------------------------------------------------------------------------- #
# Guard + store integration
# --------------------------------------------------------------------------- #

def test_automatic_halt_is_persisted(tmp_path) -> None:
    store = TrajectoryStateStore(str(tmp_path / "h.json"))
    guard = TrajectoryGuard(TrajectoryConfig(max_scope_violations=1), store=store)

    guard.check_scope(_out_of_scope_action(), _finding())

    record = store.read()
    assert record is not None
    assert record.kind == "automatic"
    assert record.finding_id == "f-halt-1"
    assert record.action_class == "terminate_instance"


def test_halt_survives_a_restart(tmp_path) -> None:
    """THE security property: a fresh guard against the same state file is still
    halted. Restarting the process must not release the kill switch."""
    path = str(tmp_path / "h.json")
    first = TrajectoryGuard(TrajectoryConfig(max_scope_violations=1),
                            store=TrajectoryStateStore(path))
    first.check_scope(_out_of_scope_action(), _finding())
    assert first.halted

    restarted = TrajectoryGuard(TrajectoryConfig(max_scope_violations=1),
                                store=TrajectoryStateStore(path))
    assert restarted.halted
    assert "out-of-scope" in restarted.halt_reason


def test_operator_clear_is_observed_by_a_live_guard(tmp_path) -> None:
    """A running orchestrator must pick up `halt.py clear` on its next check,
    with no restart — the same live-reload property the allowlist has."""
    path = str(tmp_path / "h.json")
    guard = TrajectoryGuard(TrajectoryConfig(max_scope_violations=1),
                            store=TrajectoryStateStore(path))
    guard.check_scope(_out_of_scope_action(), _finding())
    assert guard.halted

    TrajectoryStateStore(path).clear()  # a separate process
    assert not guard.halted
    assert guard.halt_reason == ""


def test_reset_clears_the_persisted_state(tmp_path) -> None:
    path = str(tmp_path / "h.json")
    store = TrajectoryStateStore(path)
    guard = TrajectoryGuard(TrajectoryConfig(max_scope_violations=1), store=store)
    guard.check_scope(_out_of_scope_action(), _finding())

    cleared = guard.reset()
    assert "out-of-scope" in cleared
    assert store.read() is None
    assert not guard.halted


def test_engage_manual_persists_attribution(tmp_path) -> None:
    store = TrajectoryStateStore(str(tmp_path / "h.json"))
    guard = TrajectoryGuard(store=store)

    guard.engage_manual("stopping everything pending investigation", by="alice")

    assert guard.halted
    record = store.read()
    assert record.kind == "manual"
    assert record.engaged_by == "alice"


def test_guard_without_a_store_keeps_in_memory_behaviour(tmp_path) -> None:
    """Backwards compatibility: store is optional, and omitting it leaves the
    original semantics untouched."""
    guard = TrajectoryGuard(TrajectoryConfig(max_scope_violations=1))
    guard.check_scope(_out_of_scope_action(), _finding())
    assert guard.halted
    assert guard.reset()
    assert not guard.halted


# --------------------------------------------------------------------------- #
# The CLI, driven as a real subprocess
# --------------------------------------------------------------------------- #

def _run(args: list[str], tmp_path, registry: str = "") -> subprocess.CompletedProcess:
    env = {
        **os.environ,
        "KRONAGENT_TRAJECTORY_STATE_PATH": str(tmp_path / "halt.json"),
        "KRONAGENT_AUDIT_PATH": str(tmp_path / "audit.jsonl"),
        "KRONAGENT_OPERATOR_REGISTRY": registry,
    }
    env.pop("KRONAGENT_OPERATOR_TOKEN", None)
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "halt.py"), *args],
        capture_output=True, text=True, env=env, cwd=str(REPO_ROOT),
    )


def _audit_stages(tmp_path) -> list[dict]:
    path = tmp_path / "audit.jsonl"
    if not path.exists():
        return []
    return [json.loads(line)["record"] for line in path.read_text().splitlines() if line.strip()]


def test_cli_status_when_running(tmp_path) -> None:
    result = _run(["status"], tmp_path)
    assert result.returncode == 0
    assert "not halted" in result.stdout


def test_cli_status_exit_code_signals_halted(tmp_path) -> None:
    """Non-zero on halted so monitoring can alert without parsing text."""
    _run(["engage", "--by", "alice", "--reason", "manual stop"], tmp_path)
    result = _run(["status"], tmp_path)
    assert result.returncode == 1
    assert "HALTED" in result.stdout


def test_cli_engage_then_clear_round_trip(tmp_path) -> None:
    engaged = _run(["engage", "--by", "alice", "--reason", "suspected compromise"], tmp_path)
    assert engaged.returncode == 0
    assert "ENGAGED" in engaged.stdout

    cleared = _run(["clear", "--by", "alice", "--reason", "investigated, source fixed"], tmp_path)
    assert cleared.returncode == 0
    assert "CLEARED" in cleared.stdout
    assert _run(["status"], tmp_path).returncode == 0


def test_cli_clear_is_audited_with_both_reasons(tmp_path) -> None:
    """The audit must record BOTH why it halted and why a human released it —
    that pairing is the artifact an auditor actually needs."""
    _run(["engage", "--by", "alice", "--reason", "HALT REASON"], tmp_path)
    _run(["clear", "--by", "bob", "--reason", "CLEAR REASON"], tmp_path)

    governance = [r for r in _audit_stages(tmp_path) if r["stage"] == "governance"]
    cleared = [r for r in governance if r["payload"]["decision"] == "trajectory_halt_cleared"]
    assert len(cleared) == 1
    payload = cleared[0]["payload"]
    assert payload["halt_reason"] == "HALT REASON"
    assert payload["cleared_reason"] == "CLEAR REASON"
    assert payload["operator_id"] == "bob"


def test_cli_clear_when_not_halted_is_a_noop(tmp_path) -> None:
    result = _run(["clear", "--by", "alice", "--reason", "nothing to do"], tmp_path)
    assert result.returncode == 0
    assert "nothing to clear" in result.stdout
    assert not [r for r in _audit_stages(tmp_path)
                if r["payload"].get("decision") == "trajectory_halt_cleared"]


def test_cli_engage_does_not_overwrite_an_existing_halt(tmp_path) -> None:
    _run(["engage", "--by", "alice", "--reason", "FIRST"], tmp_path)
    second = _run(["engage", "--by", "bob", "--reason", "SECOND"], tmp_path)

    assert "already halted" in second.stdout
    assert "FIRST" in _run(["status"], tmp_path).stdout


def test_cli_requires_a_reason(tmp_path) -> None:
    assert _run(["clear", "--by", "alice"], tmp_path).returncode != 0


# --- RBAC: clearing a platform-wide halt is admin-only --------------------- #

def _registry(tmp_path, **ops) -> str:
    data = {
        oid: {"display_name": oid.title(), "roles": roles,
              "token_sha256": hash_token(token), "active": True}
        for oid, (roles, token) in ops.items()
    }
    path = tmp_path / "ops.json"
    path.write_text(json.dumps(data))
    return str(path)


def test_cli_clear_denied_without_promote_permission(tmp_path) -> None:
    """An approver may authorize a single action but must not be able to
    release the platform-wide kill switch."""
    registry = _registry(tmp_path, carol=(["approver"], "carol-token"))
    _run(["engage", "--as", "carol", "--token", "carol-token", "--reason", "x"], tmp_path)

    result = _run(["clear", "--as", "carol", "--token", "carol-token",
                   "--reason", "let me out"], tmp_path, registry=registry)
    assert result.returncode == 4
    assert "ACCESS DENIED" in result.stderr
    assert any(r["stage"] == "access_denied" for r in _audit_stages(tmp_path))


def test_cli_clear_allowed_for_admin_and_records_verified_identity(tmp_path) -> None:
    registry = _registry(tmp_path, dave=(["admin"], "dave-token"))
    _run(["engage", "--as", "dave", "--token", "dave-token", "--reason", "halt"],
         tmp_path, registry=registry)

    result = _run(["clear", "--as", "dave", "--token", "dave-token",
                   "--reason", "investigated"], tmp_path, registry=registry)
    assert result.returncode == 0

    cleared = [r for r in _audit_stages(tmp_path)
               if r["payload"].get("decision") == "trajectory_halt_cleared"]
    assert cleared[0]["payload"]["identity_verified"] is True


def test_cli_clear_rejects_a_bad_token(tmp_path) -> None:
    registry = _registry(tmp_path, dave=(["admin"], "dave-token"))
    result = _run(["clear", "--as", "dave", "--token", "wrong-token",
                   "--reason", "x"], tmp_path, registry=registry)
    assert result.returncode == 4
