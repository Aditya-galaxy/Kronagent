"""
ApprovalStore — the human side of the earn-trust loop.

`to_proposed_action()` is the specific regression target here: it's the exact
round-trip (ProposedAction -> ApprovalRequest -> JSON -> ApprovalRequest ->
ProposedAction) that silently dropped the `provider` field before it was
fixed, breaking every approval-gated action for the Kubernetes rollout.
"""

from __future__ import annotations

import pytest

from kronagent.approvals import ApprovalRequest, ApprovalStore
from kronagent.schemas import ActionClass


@pytest.fixture
def store(tmp_path) -> ApprovalStore:
    return ApprovalStore(str(tmp_path / "approvals.json"))


def _make_request(**overrides) -> ApprovalRequest:
    defaults = dict(
        finding_id="f-1", finding_type="test:type", severity=8.0,
        provider="kubernetes", action_class=ActionClass.ISOLATE_POD,
        target="payments-api-7f9c8d", rationale="contain it",
        parameters={"namespace": "payments"},
        policy_reason="not yet allowlisted", reversible=True,
        blast_radius="single_resource",
    )
    defaults.update(overrides)
    return ApprovalRequest(**defaults)


def test_add_and_get_round_trip(store: ApprovalStore) -> None:
    req = _make_request()
    store.add(req)
    fetched = store.get(req.request_id)
    assert fetched is not None
    assert fetched.provider == "kubernetes"
    assert fetched.action_class == ActionClass.ISOLATE_POD
    assert fetched.target == "payments-api-7f9c8d"
    assert fetched.parameters == {"namespace": "payments"}


def test_provider_survives_the_full_json_round_trip(store: ApprovalStore) -> None:
    """The regression test for the bug that broke approval-gated execution:
    provider must come back out of ProposedAction -> store -> disk -> store ->
    ProposedAction unchanged, for every provider, not just the default."""
    for provider, ac, target in [
        ("aws", ActionClass.DISABLE_ACCESS_KEY, "AKIA123"),
        ("kubernetes", ActionClass.CORDON_NODE, "node-1"),
    ]:
        req = _make_request(provider=provider, action_class=ac, target=target,
                             finding_id=f"f-{provider}")
        store.add(req)
        reloaded = store.get(req.request_id)
        assert reloaded is not None
        action = reloaded.to_proposed_action()
        assert action.provider == provider
        assert action.action_class == ac
        assert action.target == target


def test_get_missing_returns_none(store: ApprovalStore) -> None:
    assert store.get("apr-does-not-exist") is None


def test_list_filters_by_status(store: ApprovalStore) -> None:
    a = _make_request(finding_id="f-a")
    b = _make_request(finding_id="f-b")
    b.status = "approved"
    store.add(a)
    store.add(b)

    pending = store.list(status="pending")
    approved = store.list(status="approved")
    everything = store.list()

    assert [r.finding_id for r in pending] == ["f-a"]
    assert [r.finding_id for r in approved] == ["f-b"]
    assert len(everything) == 2


def test_update_persists_decision(store: ApprovalStore) -> None:
    req = _make_request()
    store.add(req)
    req.status = "approved"
    req.decided_by = "alice"
    req.decision_reason = "confirmed malicious"
    store.update(req)

    reloaded = store.get(req.request_id)
    assert reloaded.status == "approved"
    assert reloaded.decided_by == "alice"
    assert reloaded.decision_reason == "confirmed malicious"


def test_update_unknown_request_raises(store: ApprovalStore) -> None:
    ghost = _make_request()
    with pytest.raises(KeyError):
        store.update(ghost)


def test_atomic_write_survives_process_restart(tmp_path) -> None:
    """A fresh ApprovalStore pointed at the same path sees prior writes --
    proves persistence isn't an in-memory illusion."""
    path = str(tmp_path / "approvals.json")
    store1 = ApprovalStore(path)
    req = _make_request()
    store1.add(req)

    store2 = ApprovalStore(path)
    reloaded = store2.get(req.request_id)
    assert reloaded is not None
    assert reloaded.target == req.target
