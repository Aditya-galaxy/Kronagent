"""
Account binding — autonomy earned in one AWS account does not follow a tenant
into another.

A tenant's AWS containment runs in whichever account its connection names, or,
with no connection, on the process's own ambient credentials. Before binding,
an allowlist entry said nothing about which. A team could run shadow mode
against staging, promote `isolate_instance_sg` after a quiet month, reconnect
the tenant to production, and the promotion would carry straight across:
unattended changes in an account where the entry's evidence was never gathered.

What is pinned here:
  * every promotion records the account each bindable provider in its scope
    runs in, including "no connection";
  * the gate refuses an entry whose tenant now points elsewhere, per tenant,
    with no sweep in the loop, and entries for other providers are unaffected;
  * the sweep latches it once; reconnecting the original account does not undo
    it, a reassignment does not lift it, and only a renewal — which re-binds to
    where the actions run now — does;
  * an unreadable connection store refuses autonomy and blocks promotion but
    latches nothing;
  * entries from before binding are not refused, and review flags them;
  * every production promotion path passes the environment.
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from kronagent.allowlist import SUSPENDED_ENVIRONMENT_CHANGED, AllowlistStore
from kronagent.audit import AuditLog
from kronagent.config import Settings
from kronagent.connect import ConnectionStore, tenant_environment
from kronagent.policy import PolicyEngine
from kronagent.schemas import ActionClass, ProposedAction

REPO_ROOT = Path(__file__).resolve().parent.parent
STAGING, PRODUCTION = "111111111111", "222222222222"


def _connect(path: Path, account: str, tenant: str = "default") -> None:
    store = ConnectionStore(str(path))
    store.delete(tenant)
    store.create(tenant_id=tenant, account_id=account, region="us-east-1")


def _settings(tmp_path) -> Settings:
    return Settings(dry_run=True, allowlist_store_path=str(tmp_path / "allowlist.json"),
                    audit_log_path=str(tmp_path / "audit.jsonl"),
                    approval_store_path=str(tmp_path / "approvals.json"),
                    connection_store_path=str(tmp_path / "connections.json"))


def _env(settings: Settings, tenant: str = "default"):
    return lambda: tenant_environment(settings.connection_store_path, tenant)


def _isolate(tenant: str = "default") -> ProposedAction:
    return ProposedAction(provider="aws", tenant_id=tenant,
                          action_class=ActionClass.ISOLATE_INSTANCE_SG,
                          target="i-0abc", rationale="r")


async def _promote(settings: Settings, action_class=ActionClass.ISOLATE_INSTANCE_SG,
                   tenant: str = "default", **kwargs) -> AllowlistStore:
    store = AllowlistStore(settings.allowlist_store_path)
    await store.add(action_class, by="alice", reason="quiet month", **kwargs,
                    audit=AuditLog(settings.audit_log_path),
                    environment=tenant_environment(settings.connection_store_path, tenant))
    return store


# --------------------------------------------------------------------------- #
# What an environment is
# --------------------------------------------------------------------------- #

def test_the_environment_names_the_account_or_its_absence(tmp_path) -> None:
    path = tmp_path / "connections.json"
    assert tenant_environment("", "default") == {"aws": None}
    assert tenant_environment(str(path), "default") == {"aws": None}
    _connect(path, STAGING)
    assert tenant_environment(str(path), "default") == {"aws": STAGING}
    assert tenant_environment(str(path), "tenant-b") == {"aws": None}

    path.write_text("{truncated")
    with pytest.raises(RuntimeError):
        tenant_environment(str(path), "default")


async def test_a_promotion_binds_only_the_bindable_providers_in_its_scope(tmp_path) -> None:
    settings = _settings(tmp_path)
    _connect(tmp_path / "connections.json", STAGING)
    store = await _promote(settings, ActionClass.BLOCK_IP, providers=["aws", "cloudflare"])
    await store.add(ActionClass.ISOLATE_POD, by="alice", reason="r",
                    audit=AuditLog(settings.audit_log_path), environment={"aws": STAGING})
    bound = {e.action_class: e.environment for e in store.list()}
    assert bound == {"block_ip": {"aws": STAGING}, "isolate_pod": {}}


# --------------------------------------------------------------------------- #
# The gate
# --------------------------------------------------------------------------- #

async def test_staging_autonomy_does_not_follow_the_tenant_into_production(tmp_path) -> None:
    settings = _settings(tmp_path)
    _connect(tmp_path / "connections.json", STAGING)
    store = await _promote(settings)
    engine = PolicyEngine(settings, store)
    assert engine.decide(_isolate(), severity=8.0).disposition == "auto_execute"

    _connect(tmp_path / "connections.json", PRODUCTION)
    decision = engine.decide(_isolate(), severity=8.0)
    assert decision.disposition == "requires_approval"
    assert f"account {STAGING}" in decision.reason and f"account {PRODUCTION}" in decision.reason


async def test_autonomy_earned_on_ambient_credentials_does_not_carry_into_a_connection(
        tmp_path) -> None:
    """Promoting before any customer account is connected, then connecting one,
    is the same move as staging to production."""
    settings = _settings(tmp_path)
    store = await _promote(settings)
    engine = PolicyEngine(settings, store)
    assert engine.decide(_isolate(), severity=8.0).disposition == "auto_execute"

    _connect(tmp_path / "connections.json", PRODUCTION)
    decision = engine.decide(_isolate(), severity=8.0)
    assert decision.disposition == "requires_approval"
    assert "ambient process credentials" in decision.reason


async def test_binding_is_judged_in_the_actions_tenant(tmp_path) -> None:
    settings = _settings(tmp_path)
    connections = tmp_path / "connections.json"
    _connect(connections, STAGING, tenant="tenant-a")
    store = await _promote(settings, tenant="tenant-a")
    engine = PolicyEngine(settings, store)
    assert engine.decide(_isolate("tenant-a"), severity=8.0).disposition == "auto_execute"
    # Same store, an action for a tenant with no connection: a different account.
    assert engine.decide(_isolate("tenant-b"), severity=8.0).disposition == "requires_approval"


async def test_an_entry_with_nothing_bindable_ignores_account_changes(tmp_path) -> None:
    settings = _settings(tmp_path)
    store = await _promote(settings, ActionClass.ISOLATE_POD)
    _connect(tmp_path / "connections.json", PRODUCTION)
    pod = ProposedAction(provider="kubernetes", action_class=ActionClass.ISOLATE_POD,
                         target="pod-1", rationale="r")
    assert PolicyEngine(settings, store).decide(pod, severity=8.0).disposition == "auto_execute"


async def test_an_unreadable_connection_store_refuses_at_the_gate_and_latches_nothing(
        tmp_path) -> None:
    settings = _settings(tmp_path)
    connections = tmp_path / "connections.json"
    _connect(connections, STAGING)
    store = await _promote(settings)
    audit = AuditLog(settings.audit_log_path)
    original = connections.read_text()
    connections.write_text("{truncated")

    allowed, why = store.evaluate(ActionClass.ISOLATE_INSTANCE_SG, provider="aws",
                                  environment=_env(settings))
    assert allowed is False and "cannot be determined" in why
    assert await store.suspend_environment_changed(audit=audit, environment=_env(settings)) == []

    connections.write_text(original)
    assert store.is_allowed(ActionClass.ISOLATE_INSTANCE_SG, environment=_env(settings))


# --------------------------------------------------------------------------- #
# The sweep and the way back
# --------------------------------------------------------------------------- #

def _suspensions(audit: AuditLog) -> list[dict]:
    return [r for r in audit.records()
            if r["payload"].get("decision") == "allowlist_suspended"]


async def test_the_sweep_latches_once_and_reconnecting_does_not_undo_it(tmp_path) -> None:
    settings = _settings(tmp_path)
    connections = tmp_path / "connections.json"
    _connect(connections, STAGING)
    store = await _promote(settings)
    audit = AuditLog(settings.audit_log_path)
    _connect(connections, PRODUCTION)

    swept = await store.suspend_environment_changed(audit=audit, environment=_env(settings))
    assert [e.action_class for e, _ in swept] == ["isolate_instance_sg"]
    assert await store.suspend_environment_changed(audit=audit, environment=_env(settings)) == []

    records = _suspensions(audit)
    assert len(records) == 1
    payload = records[0]["payload"]
    assert payload["trigger"] == SUSPENDED_ENVIRONMENT_CHANGED
    assert payload["pinned_environment"] == {"aws": STAGING}
    assert payload["current_environment"] == {"aws": PRODUCTION}

    _connect(connections, STAGING)
    assert store.is_allowed(ActionClass.ISOLATE_INSTANCE_SG, environment=_env(settings)) is False


async def test_a_reassignment_does_not_lift_it_and_a_renewal_rebinds(tmp_path) -> None:
    settings = _settings(tmp_path)
    connections = tmp_path / "connections.json"
    _connect(connections, STAGING)
    store = await _promote(settings)
    audit = AuditLog(settings.audit_log_path)
    _connect(connections, PRODUCTION)
    await store.suspend_environment_changed(audit=audit, environment=_env(settings))

    await store.set_owner(ActionClass.ISOLATE_INSTANCE_SG, owner="dana", by="alice",
                          reason="r", audit=audit)
    assert store.list()[0].is_suspended is True

    await _promote(settings)   # a decision about production, made in production
    entry = store.list()[0]
    assert entry.is_suspended is False
    assert entry.environment == {"aws": PRODUCTION}
    assert store.is_allowed(ActionClass.ISOLATE_INSTANCE_SG, environment=_env(settings))


async def test_an_entry_from_before_binding_is_not_refused(tmp_path) -> None:
    settings = _settings(tmp_path)
    store = AllowlistStore(settings.allowlist_store_path)
    store._write_all({"isolate_instance_sg": {
        "action_class": "isolate_instance_sg", "added_by": "alice", "reason": "r",
        "added_at": "2026-01-01T00:00:00+00:00",
    }})
    _connect(tmp_path / "connections.json", PRODUCTION)
    assert store.is_allowed(ActionClass.ISOLATE_INSTANCE_SG, environment=_env(settings))


async def test_the_pipeline_records_the_suspension_before_the_decision(tmp_path) -> None:
    from kronagent.containment import ContainmentExecutor
    from kronagent.orchestrator import Orchestrator

    from .conftest import FakeContainmentAdapter
    from .test_orchestrator import FakeTriageEngine, _drain, _queued, _verdict
    from kronagent.model import Finding

    settings = _settings(tmp_path)
    connections = tmp_path / "connections.json"
    _connect(connections, STAGING)
    store = await _promote(settings)
    _connect(connections, PRODUCTION)
    audit = AuditLog(settings.audit_log_path)

    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[_isolate()])
    adapter = FakeContainmentAdapter(provider="aws")
    orch = Orchestrator(settings, triage=triage, policy=PolicyEngine(settings, store),
                        containment=ContainmentExecutor(settings, {"aws": adapter}),
                        audit=audit)
    finding = Finding(provider="aws", finding_id="f-1", finding_type="t", severity=8.0)
    await _drain(orch, [_queued(finding)[0]])

    records = audit.records()
    suspended_at = next(i for i, r in enumerate(records)
                        if r["payload"].get("trigger") == SUSPENDED_ENVIRONMENT_CHANGED)
    policy_at = next(i for i, r in enumerate(records) if r["stage"] == "policy")
    assert suspended_at < policy_at
    assert records[policy_at]["payload"]["decision"]["disposition"] == "requires_approval"


# --------------------------------------------------------------------------- #
# Write paths
# --------------------------------------------------------------------------- #

def test_every_production_promotion_passes_the_environment() -> None:
    """The store binds only when handed an environment, so a promotion path
    that forgot one would write an entry that follows its tenant anywhere."""
    sources = [REPO_ROOT / "promote.py", *sorted((REPO_ROOT / "kronagent").glob("*.py"))]
    calls, missing = 0, []
    for path in sources:
        if path.name == "allowlist.py":
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "add"
                    and {"reason", "audit"} <= {k.arg for k in node.keywords}):
                calls += 1
                if "environment" not in {k.arg for k in node.keywords}:
                    missing.append(f"{path.name}:{node.lineno}")
    assert calls >= 2, f"scanner found only {calls} promotions — it has gone blind"
    assert missing == [], f"promotions without environment: {missing}"


def _cli(args: list[str], tmp_path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "promote.py"), *args],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
        env={**os.environ, "KRONAGENT_ALLOWLIST_PATH": str(tmp_path / "allowlist.json"),
             "KRONAGENT_AUDIT_PATH": str(tmp_path / "audit.jsonl"),
             "KRONAGENT_CONNECTION_PATH": str(tmp_path / "connections.json")},
    )


def test_cli_binds_flags_and_suspends(tmp_path) -> None:
    connections = tmp_path / "connections.json"
    _connect(connections, STAGING)
    added = _cli(["add", "isolate_instance_sg", "--by", "alice", "--reason", "r"], tmp_path)
    assert added.returncode == 0, added.stderr
    assert f"Bound: aws actions run in account {STAGING}" in added.stdout

    _connect(connections, PRODUCTION)
    listed = _cli(["list"], tmp_path)
    assert "SUSPENDED: isolate_instance_sg" in listed.stderr
    assert f"account {PRODUCTION}" in listed.stdout

    AllowlistStore(str(tmp_path / "allowlist.json"))._write_all({"disable_access_key": {
        "action_class": "disable_access_key", "added_by": "alice", "reason": "r",
        "added_at": "2026-01-01T00:00:00+00:00",
    }})
    review = _cli(["review", "--by", "carol"], tmp_path)
    assert "not bound to an account — renew to bind it" in review.stdout

    connections.write_text("{truncated")
    refused = _cli(["add", "disable_access_key", "--by", "alice", "--reason", "r"], tmp_path)
    assert refused.returncode == 2
    assert "account" in refused.stderr


def test_web_promote_binds_and_refuses_when_the_account_is_unknown(tmp_path) -> None:
    from fastapi.testclient import TestClient

    from kronagent import web
    from kronagent.identity import hash_token

    registry = tmp_path / "operators.json"
    registry.write_text(json.dumps({"alice": {
        "display_name": "Alice", "roles": ["admin"], "token_sha256": hash_token("secret"),
    }}))
    connections = tmp_path / "connections.json"
    _connect(connections, STAGING)
    original = (web.settings, web.allowlist_store, web.audit_log)
    web.settings = Settings(**{**_settings(tmp_path).__dict__,
                               "operator_registry_path": str(registry)})
    web.allowlist_store = AllowlistStore(web.settings.allowlist_store_path)
    web.audit_log = AuditLog(web.settings.audit_log_path)
    try:
        client = TestClient(web.app)
        body = {"action_class": "isolate_instance_sg", "operator_id": "alice",
                "token": "secret", "reason": "r"}
        assert client.post("/api/allowlist/promote", json=body).status_code == 200
        assert web.allowlist_store.list()[0].environment == {"aws": STAGING}

        _connect(connections, PRODUCTION)
        review = client.get("/api/allowlist/review").json()[0]
        assert PRODUCTION in review["environment_drift"]

        connections.write_text("{truncated")
        assert client.post("/api/allowlist/promote", json=body).status_code == 409
    finally:
        web.settings, web.allowlist_store, web.audit_log = original
