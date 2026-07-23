"""
Unit and integration tests for the Aegis ChatOps Slack integration.
"""

from __future__ import annotations

import hmac
import hashlib
import json
import os
import tempfile
import urllib.parse
import pytest
from unittest.mock import patch, MagicMock

from fastapi.testclient import TestClient

from aegis.web import app
from aegis.chatops import verify_slack_signature, ChatOpsNotifier
from aegis.approvals import ApprovalStore, ApprovalRequest
from aegis.allowlist import AllowlistStore
from aegis.audit import AuditLog
from aegis.schemas import ActionClass


@pytest.fixture
def test_env():
    """Setup temporary files and configure Settings to test webhook execution."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_approval_path = os.path.join(temp_dir, "test_approvals.json")
        temp_allowlist_path = os.path.join(temp_dir, "test_allowlist.json")
        temp_audit_path = os.path.join(temp_dir, "test_audit.jsonl")
        temp_registry_path = os.path.join(temp_dir, "test_registry.json")

        from aegis.identity import hash_token
        registry_data = {
            "alice": {
                "display_name": "Alice Admin",
                "roles": ["admin"],
                "token_sha256": hash_token("secret"),
                "active": True
            }
        }
        with open(temp_registry_path, "w", encoding="utf-8") as f:
            json.dump(registry_data, f)

        from aegis import web
        from aegis.config import Settings

        test_settings = Settings(
            dry_run=True,
            approval_store_path=temp_approval_path,
            allowlist_store_path=temp_allowlist_path,
            audit_log_path=temp_audit_path,
            operator_registry_path=temp_registry_path,
            slack_signing_secret="test_secret",
            slack_user_mapping={"U12345": "alice"}
        )

        orig_settings = web.settings
        orig_approval = web.approval_store
        orig_allowlist = web.allowlist_store
        orig_audit = web.audit_log

        web.settings = test_settings
        web.approval_store = ApprovalStore(temp_approval_path)
        web.allowlist_store = AllowlistStore(temp_allowlist_path)
        web.audit_log = AuditLog(temp_audit_path)

        client = TestClient(app)
        try:
            yield client, web.approval_store, web.audit_log, test_settings
        finally:
            web.settings = orig_settings
            web.approval_store = orig_approval
            web.allowlist_store = orig_allowlist
            web.audit_log = orig_audit


def test_signature_verification() -> None:
    secret = "my_secret"
    body = b"payload=%7B%22type%22%3A%22block_actions%22%7D"
    timestamp = "123456789"
    
    basestring = b"v0:" + timestamp.encode("utf-8") + b":" + body
    computed = "v0=" + hmac.new(secret.encode("utf-8"), basestring, hashlib.sha256).hexdigest()

    assert verify_slack_signature(secret, body, timestamp, computed) is True
    assert verify_slack_signature(secret, body, timestamp, "invalid") is False
    assert verify_slack_signature("", body, timestamp, computed) is False


def test_build_blocks_pending() -> None:
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
    blocks = ChatOpsNotifier.build_slack_blocks(req)
    assert len(blocks) >= 3
    # Check that it contains the Actions block with buttons
    actions = [b for b in blocks if b.get("type") == "actions"]
    assert len(actions) == 1
    elements = actions[0]["elements"]
    assert elements[0]["action_id"] == "approve_action"
    assert elements[1]["action_id"] == "deny_action"


def test_build_blocks_resolved() -> None:
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
    blocks = ChatOpsNotifier.build_slack_blocks(req, "Approved by @alice")
    actions = [b for b in blocks if b.get("type") == "actions"]
    assert len(actions) == 0
    verdict = [b for b in blocks if b.get("type") == "section" and "Verdict" in b.get("text", {}).get("text", "")]
    assert len(verdict) == 1


def test_webhook_invalid_signature(test_env) -> None:
    client, _, _, _ = test_env
    res = client.post(
        "/api/slack/interactive",
        content="payload=%7B%7D",
        headers={
            "X-Slack-Signature": "invalid",
            "X-Slack-Request-Timestamp": "12345678"
        }
    )
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_webhook_approve_success(test_env) -> None:
    client, store, _, settings = test_env

    # 1. Create a pending request
    req = ApprovalRequest(
        finding_id="f-1",
        finding_type="aws:iam_abuse",
        severity=8.2,
        action_class=ActionClass.DISABLE_ACCESS_KEY,
        target="AKIA123",
        rationale="compromised keys",
        policy_reason="approval required",
        reversible=True,
        blast_radius="single_resource"
    )
    store.add(req)

    # 2. Build mock interactive payload
    payload = {
        "type": "block_actions",
        "user": {
            "id": "U12345",
            "username": "alice_slack"
        },
        "actions": [
            {
                "action_id": "approve_action",
                "value": req.request_id
            }
        ]
    }

    body = f"payload={urllib.parse.quote(json.dumps(payload))}"
    timestamp = "123456789"
    basestring = b"v0:" + timestamp.encode("utf-8") + b":" + body.encode("utf-8")
    signature = "v0=" + hmac.new(settings.slack_signing_secret.encode("utf-8"), basestring, hashlib.sha256).hexdigest()

    # 3. Post to the webhook
    res = client.post(
        "/api/slack/interactive",
        content=body,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Slack-Signature": signature,
            "X-Slack-Request-Timestamp": timestamp
        }
    )
    assert res.status_code == 200
    data = res.json()
    assert data.get("replace_original") is True
    assert "Approved" in data.get("text")

    # Verify request status is updated in store
    updated = store.get(req.request_id)
    assert updated.status in {"approved", "executed"}
    assert updated.decided_by == "alice"


@pytest.mark.asyncio
async def test_webhook_deny_success(test_env) -> None:
    client, store, _, settings = test_env

    # 1. Create a pending request
    req = ApprovalRequest(
        finding_id="f-1",
        finding_type="aws:iam_abuse",
        severity=8.2,
        action_class=ActionClass.DISABLE_ACCESS_KEY,
        target="AKIA123",
        rationale="compromised keys",
        policy_reason="approval required",
        reversible=True,
        blast_radius="single_resource"
    )
    store.add(req)

    # 2. Build mock interactive payload
    payload = {
        "type": "block_actions",
        "user": {
            "id": "U12345",
            "username": "alice_slack"
        },
        "actions": [
            {
                "action_id": "deny_action",
                "value": req.request_id
            }
        ]
    }

    body = f"payload={urllib.parse.quote(json.dumps(payload))}"
    timestamp = "123456789"
    basestring = b"v0:" + timestamp.encode("utf-8") + b":" + body.encode("utf-8")
    signature = "v0=" + hmac.new(settings.slack_signing_secret.encode("utf-8"), basestring, hashlib.sha256).hexdigest()

    # 3. Post to the webhook
    res = client.post(
        "/api/slack/interactive",
        content=body,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Slack-Signature": signature,
            "X-Slack-Request-Timestamp": timestamp
        }
    )
    assert res.status_code == 200
    data = res.json()
    assert data.get("replace_original") is True
    assert "Rejected" in data.get("text")

    # Verify request status in store
    updated = store.get(req.request_id)
    assert updated.status == "denied"
    assert updated.decided_by == "alice"
