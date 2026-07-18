"""
AllowlistStore — the earn-trust dial. Every write must be audited, and reads
must reflect the store's live state (no restart needed).
"""

from __future__ import annotations

import json

import pytest

from aegis.allowlist import AllowlistStore
from aegis.audit import AuditLog
from aegis.schemas import ActionClass


@pytest.fixture
def store(tmp_path) -> AllowlistStore:
    return AllowlistStore(str(tmp_path / "allowlist.json"))


def test_fresh_store_is_empty(store: AllowlistStore) -> None:
    assert store.list() == []
    assert store.is_allowed(ActionClass.DISABLE_ACCESS_KEY) is False


async def test_add_makes_action_allowed(store: AllowlistStore, audit_log: AuditLog) -> None:
    await store.add(ActionClass.DISABLE_ACCESS_KEY, by="alice", reason="proven safe", audit=audit_log)
    assert store.is_allowed(ActionClass.DISABLE_ACCESS_KEY) is True
    entries = store.list()
    assert len(entries) == 1
    assert entries[0].added_by == "alice"
    assert entries[0].reason == "proven safe"


async def test_add_writes_governance_audit_record(store: AllowlistStore, audit_log: AuditLog) -> None:
    await store.add(ActionClass.ISOLATE_POD, by="bob", reason="k8s netpol validated", audit=audit_log)
    lines = audit_log._path
    records = [json.loads(l)["record"] for l in open(lines) if l.strip()]
    gov = [r for r in records if r["stage"] == "governance"]
    assert len(gov) == 1
    assert gov[0]["payload"]["decision"] == "allowlist_add"
    assert gov[0]["payload"]["action_class"] == "isolate_pod"
    assert gov[0]["payload"]["by"] == "bob"
    assert gov[0]["payload"]["reason"] == "k8s netpol validated"
    assert gov[0]["payload"]["already_present"] is False


async def test_duplicate_add_flags_already_present(store: AllowlistStore, audit_log: AuditLog) -> None:
    await store.add(ActionClass.BLOCK_IP, by="a", reason="r1", audit=audit_log)
    await store.add(ActionClass.BLOCK_IP, by="a", reason="r2 (re-confirm)", audit=audit_log)
    records = [json.loads(l)["record"] for l in open(audit_log._path) if l.strip()]
    gov = [r for r in records if r["stage"] == "governance"]
    assert gov[0]["payload"]["already_present"] is False
    assert gov[1]["payload"]["already_present"] is True
    # Second add wins on content (last-write, not append-only for the live entry).
    assert store.list()[0].reason == "r2 (re-confirm)"


async def test_remove_revokes_autonomy(store: AllowlistStore, audit_log: AuditLog) -> None:
    await store.add(ActionClass.CORDON_NODE, by="a", reason="r", audit=audit_log)
    assert store.is_allowed(ActionClass.CORDON_NODE) is True
    existed = await store.remove(ActionClass.CORDON_NODE, by="a", reason="demoting", audit=audit_log)
    assert existed is True
    assert store.is_allowed(ActionClass.CORDON_NODE) is False


async def test_remove_nonexistent_is_noop_but_still_audited(store: AllowlistStore, audit_log: AuditLog) -> None:
    existed = await store.remove(ActionClass.BLOCK_IP, by="a", reason="testing no-op", audit=audit_log)
    assert existed is False
    records = [json.loads(l)["record"] for l in open(audit_log._path) if l.strip()]
    gov = [r for r in records if r["stage"] == "governance"]
    assert len(gov) == 1
    assert gov[0]["payload"]["decision"] == "allowlist_remove"
    assert gov[0]["payload"]["existed"] is False


def test_seed_applies_only_on_first_creation(tmp_path) -> None:
    path = str(tmp_path / "allowlist.json")
    seeded = AllowlistStore(path, seed=frozenset({"disable_access_key"}))
    assert seeded.is_allowed(ActionClass.DISABLE_ACCESS_KEY) is True

    # A second store pointed at the same (now-existing) file must NOT be
    # reseeded, even with a different seed -- that would silently clobber
    # live governance state on every restart.
    reopened = AllowlistStore(path, seed=frozenset({"block_ip"}))
    assert reopened.is_allowed(ActionClass.DISABLE_ACCESS_KEY) is True
    assert reopened.is_allowed(ActionClass.BLOCK_IP) is False


def test_no_seed_leaves_store_unwritten(tmp_path) -> None:
    import os
    path = str(tmp_path / "allowlist.json")
    AllowlistStore(path, seed=frozenset())
    assert not os.path.exists(path)
