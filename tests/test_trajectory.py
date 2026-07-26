"""
Behavioral-trajectory guard — the automatic kill switch over Kronagent's OWN
action stream.

These tests pin the three properties the guard exists to guarantee:

  1. Scope integrity — an action targeting a resource NOT implicated by its
     finding (the action-redirection / prompt-injection-to-wrong-resource
     failure) is reported as a violation; a legitimately-targeted action is not.
  2. Runaway rate — a burst of autonomous executions beyond the window ceiling
     latches an automatic halt that then blocks everything.
  3. The halt is LATCHED and only an explicit reset() (a human action) clears
     it — the guard never un-halts itself just because the window drained.

The guard is deterministic and time-injectable (`now=`), so every window/rate
property is tested with exact synthetic clocks, not sleeps.
"""

from __future__ import annotations

from kronagent.model import Finding, ResourceRef
from kronagent.schemas import ActionClass
from kronagent.trajectory import (
    TrajectoryConfig,
    TrajectoryEvent,
    TrajectoryGuard,
    legitimate_targets,
)

from .conftest import make_action


def _finding(*, resources=None, remote_ip=None) -> Finding:
    return Finding(
        provider="aws",
        finding_id="f-0001",
        finding_type="test:finding",
        severity=8.0,
        resources=resources or [],
        remote_ip=remote_ip,
    )


def _instance_finding() -> Finding:
    return _finding(
        resources=[ResourceRef(kind="aws.ec2.instance", id="i-0abc", attributes={})],
        remote_ip="185.220.101.7",
    )


# --------------------------------------------------------------------------- #
# legitimate_targets — the definition of "in scope"
# --------------------------------------------------------------------------- #

def test_legitimate_targets_are_resource_ids_plus_remote_ip() -> None:
    finding = _finding(
        resources=[
            ResourceRef(kind="aws.iam.access_key", id="AKIA123", attributes={}),
            ResourceRef(kind="aws.iam.user", id="svc-backup", attributes={}),
        ],
        remote_ip="203.0.113.9",
    )
    assert legitimate_targets(finding) == {"AKIA123", "svc-backup", "203.0.113.9"}


def test_legitimate_targets_without_remote_ip() -> None:
    finding = _finding(resources=[ResourceRef(kind="aws.ec2.instance", id="i-1", attributes={})])
    assert legitimate_targets(finding) == {"i-1"}


# --------------------------------------------------------------------------- #
# Scope integrity
# --------------------------------------------------------------------------- #

def test_in_scope_action_passes_clean() -> None:
    guard = TrajectoryGuard()
    finding = _instance_finding()
    action = make_action(provider="aws", action_class=ActionClass.ISOLATE_INSTANCE_SG, target="i-0abc")
    assert guard.check_scope(action, finding) is None
    assert not guard.halted


def test_ip_block_targeting_the_findings_remote_ip_is_in_scope() -> None:
    guard = TrajectoryGuard()
    finding = _instance_finding()
    action = make_action(provider="aws", action_class=ActionClass.BLOCK_IP, target="185.220.101.7")
    assert guard.check_scope(action, finding) is None


def test_out_of_scope_action_is_reported() -> None:
    guard = TrajectoryGuard()
    finding = _instance_finding()
    # Redirected onto an instance the finding never mentioned — the exact
    # prompt-injection-to-wrong-resource failure.
    action = make_action(provider="aws", action_class=ActionClass.TERMINATE_INSTANCE,
                         target="i-victim-prod-db")
    event = guard.check_scope(action, finding)
    assert event is not None
    assert event.kind == "scope_violation"
    assert event.target == "i-victim-prod-db"
    assert event.finding_id == "f-0001"
    assert not guard.halted  # one violation is reported but doesn't yet latch


def test_scope_check_is_a_noop_when_enforcement_disabled() -> None:
    guard = TrajectoryGuard(TrajectoryConfig(enforce_scope=False))
    finding = _instance_finding()
    action = make_action(provider="aws", action_class=ActionClass.TERMINATE_INSTANCE, target="anything")
    assert guard.check_scope(action, finding) is None
    assert not guard.halted


def test_repeated_scope_violations_latch_the_halt() -> None:
    guard = TrajectoryGuard(TrajectoryConfig(max_scope_violations=3, window_seconds=60))
    finding = _instance_finding()
    action = make_action(provider="aws", action_class=ActionClass.TERMINATE_INSTANCE, target="i-evil")

    e1 = guard.check_scope(action, finding, now=0.0)
    e2 = guard.check_scope(action, finding, now=1.0)
    assert not guard.halted
    assert e1.halted is False and e2.halted is False

    e3 = guard.check_scope(action, finding, now=2.0)  # third within the window → latch
    assert guard.halted
    assert e3.halted is True
    assert "out-of-scope" in guard.halt_reason


def test_scope_violations_outside_the_window_do_not_accumulate() -> None:
    guard = TrajectoryGuard(TrajectoryConfig(max_scope_violations=3, window_seconds=60))
    finding = _instance_finding()
    action = make_action(provider="aws", action_class=ActionClass.TERMINATE_INSTANCE, target="i-evil")

    guard.check_scope(action, finding, now=0.0)
    guard.check_scope(action, finding, now=1.0)
    # Third violation is >60s after the first — the first has aged out, so the
    # live count is only 2 and the halt must NOT trip.
    guard.check_scope(action, finding, now=120.0)
    assert not guard.halted


# --------------------------------------------------------------------------- #
# Runaway rate
# --------------------------------------------------------------------------- #

def test_auto_executions_under_the_ceiling_do_not_halt() -> None:
    guard = TrajectoryGuard(TrajectoryConfig(max_auto_executions=25, window_seconds=60))
    finding = _instance_finding()
    action = make_action(provider="aws", action_class=ActionClass.ISOLATE_INSTANCE_SG, target="i-0abc")
    for i in range(25):
        assert guard.note_auto_execution(action, finding, now=float(i)) is None
    assert not guard.halted


def test_auto_execution_flood_latches_the_halt() -> None:
    guard = TrajectoryGuard(TrajectoryConfig(max_auto_executions=25, window_seconds=60))
    finding = _instance_finding()
    action = make_action(provider="aws", action_class=ActionClass.ISOLATE_INSTANCE_SG, target="i-0abc")

    halt_event = None
    for i in range(40):
        ev = guard.note_auto_execution(action, finding, now=float(i) * 0.1)  # all within 60s
        if ev is not None:
            halt_event = ev
            break
    assert guard.halted
    assert isinstance(halt_event, TrajectoryEvent)
    assert halt_event.kind == "runaway_halt"
    assert halt_event.halted is True
    assert "runaway" in guard.halt_reason


def test_auto_executions_spread_beyond_the_window_never_halt() -> None:
    guard = TrajectoryGuard(TrajectoryConfig(max_auto_executions=25, window_seconds=60))
    finding = _instance_finding()
    action = make_action(provider="aws", action_class=ActionClass.ISOLATE_INSTANCE_SG, target="i-0abc")
    # One execution every 10s → at most ~7 ever coexist in a 60s window.
    for i in range(100):
        assert guard.note_auto_execution(action, finding, now=float(i) * 10.0) is None
    assert not guard.halted


# --------------------------------------------------------------------------- #
# Latching + reset
# --------------------------------------------------------------------------- #

def test_halt_is_latched_and_only_reset_clears_it() -> None:
    guard = TrajectoryGuard(TrajectoryConfig(max_scope_violations=1))
    finding = _instance_finding()
    action = make_action(provider="aws", action_class=ActionClass.TERMINATE_INSTANCE, target="i-evil")

    guard.check_scope(action, finding, now=0.0)
    assert guard.halted
    reason = guard.halt_reason
    assert reason

    cleared = guard.reset()
    assert cleared == reason
    assert not guard.halted
    assert guard.halt_reason == ""

    # After reset, a fresh in-scope action is clean again.
    ok = make_action(provider="aws", action_class=ActionClass.ISOLATE_INSTANCE_SG, target="i-0abc")
    assert guard.check_scope(ok, finding) is None


def test_first_halt_reason_is_preserved_not_overwritten() -> None:
    """Once latched, a later trigger must not rewrite the halt_reason — the
    operator needs to see what first tripped the switch."""
    guard = TrajectoryGuard(TrajectoryConfig(max_scope_violations=1, max_auto_executions=1))
    finding = _instance_finding()
    bad = make_action(provider="aws", action_class=ActionClass.TERMINATE_INSTANCE, target="i-evil")

    guard.check_scope(bad, finding, now=0.0)
    first_reason = guard.halt_reason
    assert "out-of-scope" in first_reason

    good = make_action(provider="aws", action_class=ActionClass.ISOLATE_INSTANCE_SG, target="i-0abc")
    guard.note_auto_execution(good, finding, now=1.0)
    guard.note_auto_execution(good, finding, now=2.0)
    assert guard.halt_reason == first_reason  # unchanged


# --------------------------------------------------------------------------- #
# Mutation check: the guard must actually count, not rubber-stamp. If the scope
# comparison were inverted (block in-scope / allow out-of-scope), or the ceiling
# comparison flipped, these expectations fail.
# --------------------------------------------------------------------------- #

def test_guard_discriminates_in_scope_from_out_of_scope() -> None:
    guard = TrajectoryGuard()
    finding = _instance_finding()
    in_scope = make_action(provider="aws", action_class=ActionClass.ISOLATE_INSTANCE_SG, target="i-0abc")
    out_scope = make_action(provider="aws", action_class=ActionClass.ISOLATE_INSTANCE_SG, target="i-elsewhere")
    assert guard.check_scope(in_scope, finding) is None
    assert guard.check_scope(out_scope, finding) is not None
