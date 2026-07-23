"""
Unit and integration tests for the Aegis Analyst Console Web Server.
"""

from __future__ import annotations

import json
import os
import tempfile
import pytest

from fastapi.testclient import TestClient

from aegis.web import app
from aegis.approvals import ApprovalStore, ApprovalRequest
from aegis.allowlist import AllowlistStore
from aegis.audit import AuditLog
from aegis.schemas import ActionClass, AuditRecord


@pytest.fixture
def test_env():
    """Setup temporary files for the store paths to avoid modifying local workspace state."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_approval_path = os.path.join(temp_dir, "test_approvals.json")
        temp_allowlist_path = os.path.join(temp_dir, "test_allowlist.json")
        temp_audit_path = os.path.join(temp_dir, "test_audit.jsonl")
        temp_registry_path = os.path.join(temp_dir, "test_registry.json")
        
        # Write dummy registry
        from aegis.identity import hash_token
        registry_data = {
            "alice": {
                "display_name": "Alice Admin",
                "roles": ["admin"],
                "token_sha256": hash_token("secret"),
                "active": True
            },
            "bob": {
                "display_name": "Bob Viewer",
                "roles": ["viewer"],
                "token_sha256": hash_token("password"),
                "active": True
            }
        }
        with open(temp_registry_path, "w", encoding="utf-8") as f:
            json.dump(registry_data, f)

        # Import modules to override
        from aegis import web
        from aegis.config import Settings
        
        test_settings = Settings(
            dry_run=True,
            approval_store_path=temp_approval_path,
            allowlist_store_path=temp_allowlist_path,
            audit_log_path=temp_audit_path,
            operator_registry_path=temp_registry_path
        )
        
        # Backup original web components
        orig_settings = web.settings
        orig_approval = web.approval_store
        orig_allowlist = web.allowlist_store
        orig_audit = web.audit_log
        
        # Override web components
        web.settings = test_settings
        web.approval_store = ApprovalStore(temp_approval_path)
        web.allowlist_store = AllowlistStore(temp_allowlist_path)
        web.audit_log = AuditLog(temp_audit_path)
        
        client = TestClient(app)
        try:
            yield client, web.approval_store, web.allowlist_store, web.audit_log
        finally:
            # Restore original web components
            web.settings = orig_settings
            web.approval_store = orig_approval
            web.allowlist_store = orig_allowlist
            web.audit_log = orig_audit


def test_read_index(test_env) -> None:
    client, _, _, _ = test_env
    res = client.get("/")
    assert res.status_code == 200
    assert "Aegis Analyst Console" in res.text


def test_get_status(test_env) -> None:
    client, _, _, _ = test_env
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.json()
    assert "dry_run" in data
    assert "kill_switch" in data
    assert "integrity_verified" in data


def test_get_approvals_empty(test_env) -> None:
    client, _, _, _ = test_env
    res = client.get("/api/approvals")
    assert res.status_code == 200
    assert res.json() == []


def test_get_allowlist_empty(test_env) -> None:
    client, _, _, _ = test_env
    res = client.get("/api/allowlist")
    assert res.status_code == 200
    assert res.json() == []


def test_get_metrics_empty(test_env) -> None:
    client, _, _, _ = test_env
    res = client.get("/api/metrics")
    assert res.status_code == 200
    data = res.json()
    assert data["total_findings"] == 0
    assert data["total_pending"] == 0


@pytest.mark.asyncio
async def test_execute_approval_action_unauthorized(test_env) -> None:
    client, store, _, _ = test_env
    
    # 1. Add a pending approval request
    req = ApprovalRequest(
        finding_id="f-1",
        finding_type="aws:iam_abuse",
        severity=7.5,
        action_class=ActionClass.DISABLE_ACCESS_KEY,
        target="AKIA123",
        rationale="compromised keys",
        policy_reason="approval required",
        reversible=True,
        blast_radius="single_resource"
    )
    store.add(req)
    
    # 2. Deny action with invalid credentials (bob is only a viewer, lacks approve)
    res = client.post(
        f"/api/approvals/{req.request_id}/action",
        json={
            "action": "deny",
            "operator_id": "bob",
            "token": "password",
            "reason": "compromised keys"
        }
    )
    assert res.status_code == 403
    assert "lacks the 'approve' permission" in res.json()["detail"]


@pytest.mark.asyncio
async def test_execute_approval_action_success(test_env) -> None:
    client, store, _, audit = test_env
    
    # 1. Add a pending approval request
    req = ApprovalRequest(
        finding_id="f-1",
        finding_type="aws:iam_abuse",
        severity=7.5,
        action_class=ActionClass.DISABLE_ACCESS_KEY,
        target="AKIA123",
        rationale="compromised keys",
        policy_reason="approval required",
        reversible=True,
        blast_radius="single_resource"
    )
    store.add(req)
    
    # 2. Approve action with valid credentials (alice is admin)
    res = client.post(
        f"/api/approvals/{req.request_id}/action",
        json={
            "action": "approve",
            "operator_id": "alice",
            "token": "secret",
            "reason": "approved for incident mitigation"
        }
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] in {"approved", "executed"}
    
    # Verify request status in database
    updated_req = store.get(req.request_id)
    assert updated_req is not None
    assert updated_req.status in {"approved", "executed"}
    assert updated_req.decided_by == "alice"


def test_promote_allowlist_success(test_env) -> None:
    client, _, allowlist, _ = test_env
    
    # Promote action class with valid credentials (alice is admin)
    res = client.post(
        "/api/allowlist/promote",
        json={
            "action_class": "isolate_pod",
            "operator_id": "alice",
            "token": "secret",
            "reason": "promote isolate_pod for fast mitigation"
        }
    )
    assert res.status_code == 200
    assert res.json()["status"] == "success"
    
    # Verify allowlist state in database
    assert "isolate_pod" in [entry.action_class for entry in allowlist.list()]


@pytest.mark.asyncio
async def test_demote_allowlist_success(test_env) -> None:
    client, _, allowlist, audit = test_env
    
    await allowlist.add(
        ActionClass.ISOLATE_POD,
        by="alice",
        reason="test setup",
        audit=audit
    )
    
    # Demote action class with valid credentials (alice is admin)
    res = client.post(
        "/api/allowlist/demote",
        json={
            "action_class": "isolate_pod",
            "operator_id": "alice",
            "token": "secret",
            "reason": "demote isolate_pod"
        }
    )
    assert res.status_code == 200
    assert res.json()["status"] == "success"
    
    # Verify allowlist state in database
    assert "isolate_pod" not in [entry.action_class for entry in allowlist.list()]
