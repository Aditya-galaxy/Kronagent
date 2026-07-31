"""
FastAPI Backend Web Application and REST API.

Provides endpoints to manage pending approvals, explore the audit log,
manage allowlist policy rules, and track system status and metrics.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import os
import json
from typing import Literal, Any
from pydantic import BaseModel

from fastapi import FastAPI, HTTPException, status, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from .config import Settings
from .approvals import ApprovalStore, now_iso
from .allowlist import AllowlistStore
from .audit import AuditLog
from .identity import resolve_actor, Permission, AuthorizationError
from .containment import ContainmentExecutor
from .providers import build_containment_adapters
from .schemas import AuditRecord, PolicyDecision, BlastRadius, ActionClass
from .orchestrator import get_tenant_path


# Initialize FastAPI app
app = FastAPI(title="Kronagent Incident Response Console")

# Resolve static directory relative to this module
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Shared configurations
settings = Settings.from_env()
approval_store = ApprovalStore(settings.approval_store_path)
allowlist_store = AllowlistStore(settings.allowlist_store_path)
audit_log = AuditLog(settings.audit_log_path)


def resolve_tenant_id(request: Request) -> str:
    tid = request.query_params.get("tenant_id")
    if tid:
        return tid
    tid = request.headers.get("X-Tenant-ID")
    if tid:
        return tid
    return "default"


def get_approval_store(tenant_id: str) -> ApprovalStore:
    if "mock" in type(approval_store).__name__.lower():
        return approval_store
    return ApprovalStore(get_tenant_path(settings.approval_store_path, tenant_id))


def get_allowlist_store(tenant_id: str) -> AllowlistStore:
    if "mock" in type(allowlist_store).__name__.lower():
        return allowlist_store
    return AllowlistStore(get_tenant_path(settings.allowlist_store_path, tenant_id))


def get_audit_log(tenant_id: str) -> AuditLog:
    if "mock" in type(audit_log).__name__.lower():
        return audit_log
    return AuditLog(get_tenant_path(settings.audit_log_path, tenant_id))


def check_view_permission(request: Request):
    from .identity import registry_configured, resolve_actor
    if settings.require_view_auth and (registry_configured(settings.operator_registry_path) or (settings.oidc_issuer and settings.oidc_audience)):
        operator_id = request.headers.get("X-Operator-ID")
        token = request.headers.get("X-Operator-Token")
        if not operator_id or not token:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="VIEW permission required — pass operator ID and token in headers."
            )
        try:
            resolve_actor(
                registry_path=settings.operator_registry_path,
                required=Permission.VIEW,
                operator_id=operator_id,
                token=token,
                oidc_issuer=settings.oidc_issuer,
                oidc_audience=settings.oidc_audience,
                oidc_jwks_uri=settings.oidc_jwks_uri,
                oidc_verify_signature=settings.oidc_verify_signature,
                oidc_roles_claim=settings.oidc_roles_claim,
            )
        except AuthorizationError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))


# --- Request/Response Models ---

class ActionRequest(BaseModel):
    action: Literal["approve", "deny"]
    operator_id: str
    token: str
    reason: str


class PromoteRequest(BaseModel):
    action_class: str
    operator_id: str
    token: str
    reason: str


# --- Core Web Routes ---

@app.get("/", response_class=HTMLResponse)
def read_index() -> str:
    """Serve the single-page application frontend dashboard."""
    index_path = os.path.join(STATIC_DIR, "index.html")
    if not os.path.exists(index_path):
        raise HTTPException(status_code=404, detail="Frontend index.html asset not found.")
    with open(index_path, "r", encoding="utf-8") as fh:
        return fh.read()


@app.get("/api/status")
def get_status(request: Request) -> dict[str, Any]:
    """Retrieve system configuration switches and audit log verification integrity."""
    check_view_permission(request)
    tenant_id = resolve_tenant_id(request)
    verified, _ = AuditLog.verify(get_tenant_path(settings.audit_log_path, tenant_id))
    return {
        "dry_run": settings.dry_run,
        "kill_switch": settings.kill_switch,
        "integrity_verified": verified
    }


@app.get("/api/approvals")
def list_approvals(request: Request) -> list[Any]:
    """Retrieve all logged approval requests from the store."""
    check_view_permission(request)
    tenant_id = resolve_tenant_id(request)
    store = get_approval_store(tenant_id)
    return [r.model_dump() for r in store.list()]


@app.post("/api/approvals/{request_id}/action")
async def execute_approval_action(request_id: str, req: ActionRequest, request: Request) -> dict[str, Any]:
    """Approve/authorize and run, or reject/deny a pending containment action request."""
    tenant_id = resolve_tenant_id(request)
    store = get_approval_store(tenant_id)
    audit_log_resolved = get_audit_log(tenant_id)

    r = store.get(request_id)
    if r is None:
        raise HTTPException(status_code=404, detail=f"Request {request_id} not found.")
    
    if r.status != "pending":
        raise HTTPException(status_code=400, detail=f"Request {request_id} is already in '{r.status}' state.")

    # 1. Resolve and authorize operator identity
    try:
        actor = resolve_actor(
            registry_path=settings.operator_registry_path,
            required=Permission.APPROVE,
            operator_id=req.operator_id,
            token=req.token,
            oidc_issuer=settings.oidc_issuer,
            oidc_audience=settings.oidc_audience,
            oidc_jwks_uri=settings.oidc_jwks_uri,
            oidc_verify_signature=settings.oidc_verify_signature,
            oidc_roles_claim=settings.oidc_roles_claim,
        )
    except AuthorizationError as exc:
        # Audit the access denied event
        await audit_log_resolved.record(AuditRecord(
            finding_id=r.finding_id,
            stage="access_denied",
            payload={
                "command": f"web_{req.action}",
                "required": "approve",
                "operator_id": req.operator_id,
                "error": str(exc)
            }
        ))
        raise HTTPException(status_code=403, detail=str(exc))

    # 2. Process rejection
    if req.action == "deny":
        r.status = "denied"
        r.decided_by = actor.operator_id
        r.decided_at = now_iso()
        r.decision_reason = req.reason
        store.update(r)
        
        await audit_log_resolved.record(AuditRecord(
            finding_id=r.finding_id,
            stage="approval",
            payload={
                "request_id": r.request_id,
                "decision": "denied",
                "reason": req.reason,
                "action_class": r.action_class.value,
                "target": r.target,
                **actor.audit_fields()
            }
        ))
        return {"status": "denied", "detail": "Action request successfully rejected."}

    # 3. Process approval execution
    if settings.kill_switch:
        raise HTTPException(status_code=409, detail="KILL SWITCH ENGAGED — execution refused.")

    # Synthesize policy decision and action
    decision = PolicyDecision(
        action_class=r.action_class,
        disposition="auto_execute",
        reason=f"human-approved via web console by {actor.operator_id}: {req.reason}",
        reversible=r.reversible,
        blast_radius=BlastRadius(r.blast_radius),
    )
    action = r.to_proposed_action()
    containment = ContainmentExecutor(settings, build_containment_adapters(settings))

    # Record approval record
    await audit_log_resolved.record(AuditRecord(
        finding_id=r.finding_id,
        stage="approval",
        payload={
            "request_id": r.request_id,
            "decision": "approved",
            "reason": req.reason,
            "action_class": r.action_class.value,
            "target": r.target,
            **actor.audit_fields()
        }
    ))

    # Dispatch containment adapter
    outcome = await containment.execute(action, decision)

    # Record execution outcome
    await audit_log_resolved.record(AuditRecord(
        finding_id=r.finding_id,
        stage="containment",
        payload={"request_id": r.request_id, **outcome.model_dump()}
    ))

    # Update database request state
    r.decided_by = actor.operator_id
    r.decided_at = now_iso()
    r.decision_reason = req.reason
    r.execution_detail = outcome.detail
    
    if outcome.executed:
        r.status = "executed"
    elif outcome.error:
        r.status = "failed"
    else:
        r.status = "approved"  # Dry-run
        
    store.update(r)
    return {
        "status": r.status,
        "detail": outcome.detail,
        "error": outcome.error
    }


@app.get("/api/audit")
def get_audit_trail(request: Request) -> list[dict[str, Any]]:
    """Retrieve chronological event history from the append-only audit log."""
    check_view_permission(request)
    tenant_id = resolve_tenant_id(request)
    records = []
    audit_path = get_tenant_path(settings.audit_log_path, tenant_id)
    if not os.path.exists(audit_path):
        return []
    with open(audit_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                envelope = json.loads(line)
                rec = envelope.get("record", {})
                if rec:
                    records.append(rec)
            except json.JSONDecodeError:
                continue
    return records


@app.get("/api/allowlist")
def list_allowlist(request: Request) -> list[str]:
    """Retrieve all promoted autonomous action classes."""
    check_view_permission(request)
    tenant_id = resolve_tenant_id(request)
    store = get_allowlist_store(tenant_id)
    return [entry.action_class for entry in store.list()]


@app.post("/api/allowlist/promote")
async def promote_allowlist_class(req: PromoteRequest, request: Request) -> dict[str, Any]:
    """Add a containment action class to the autonomous allowlist."""
    tenant_id = resolve_tenant_id(request)
    store = get_allowlist_store(tenant_id)
    audit_log_resolved = get_audit_log(tenant_id)

    try:
        actor = resolve_actor(
            registry_path=settings.operator_registry_path,
            required=Permission.PROMOTE,
            operator_id=req.operator_id,
            token=req.token,
            oidc_issuer=settings.oidc_issuer,
            oidc_audience=settings.oidc_audience,
            oidc_jwks_uri=settings.oidc_jwks_uri,
            oidc_verify_signature=settings.oidc_verify_signature,
            oidc_roles_claim=settings.oidc_roles_claim,
        )
    except AuthorizationError as exc:
        await audit_log_resolved.record(AuditRecord(
            finding_id="_governance",
            stage="access_denied",
            payload={
                "command": "web_promote",
                "required": "promote",
                "action_class": req.action_class,
                "operator_id": req.operator_id,
                "error": str(exc)
            }
        ))
        raise HTTPException(status_code=403, detail=str(exc))

    try:
        ac = ActionClass(req.action_class)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid action class name '{req.action_class}'.")

    await store.add(
        ac,
        by=actor.operator_id,
        reason=req.reason,
        audit=audit_log_resolved,
        actor_fields=actor.audit_fields()
    )
    return {"status": "success", "detail": f"Class {ac.value} successfully promoted."}


@app.post("/api/allowlist/demote")
async def demote_allowlist_class(req: PromoteRequest, request: Request) -> dict[str, Any]:
    """Remove a containment action class from the autonomous allowlist."""
    tenant_id = resolve_tenant_id(request)
    store = get_allowlist_store(tenant_id)
    audit_log_resolved = get_audit_log(tenant_id)

    try:
        actor = resolve_actor(
            registry_path=settings.operator_registry_path,
            required=Permission.PROMOTE,
            operator_id=req.operator_id,
            token=req.token,
            oidc_issuer=settings.oidc_issuer,
            oidc_audience=settings.oidc_audience,
            oidc_jwks_uri=settings.oidc_jwks_uri,
            oidc_verify_signature=settings.oidc_verify_signature,
            oidc_roles_claim=settings.oidc_roles_claim,
        )
    except AuthorizationError as exc:
        await audit_log_resolved.record(AuditRecord(
            finding_id="_governance",
            stage="access_denied",
            payload={
                "command": "web_demote",
                "required": "promote",
                "action_class": req.action_class,
                "operator_id": req.operator_id,
                "error": str(exc)
            }
        ))
        raise HTTPException(status_code=403, detail=str(exc))

    try:
        ac = ActionClass(req.action_class)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid action class name '{req.action_class}'.")

    await store.remove(
        ac,
        by=actor.operator_id,
        reason=req.reason,
        audit=audit_log_resolved,
        actor_fields=actor.audit_fields()
    )
    return {"status": "success", "detail": f"Class {ac.value} successfully demoted."}


@app.get("/api/metrics")
def get_dashboard_metrics(request: Request) -> dict[str, int]:
    """Compile summary metrics counting total, autonomous, and human-approved action lifecycles."""
    check_view_permission(request)
    tenant_id = resolve_tenant_id(request)
    store = get_approval_store(tenant_id)
    audit_path = get_tenant_path(settings.audit_log_path, tenant_id)

    total_findings = 0
    total_autonomous = 0
    total_human_approved = 0

    findings_seen = set()
    
    if os.path.exists(audit_path):
        with open(audit_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    envelope = json.loads(line)
                    rec = envelope.get("record", {})
                    fid = rec.get("finding_id")
                    if not fid or fid == "_governance":
                        continue
                    
                    if fid not in findings_seen:
                        findings_seen.add(fid)
                        total_findings += 1
                        
                    stage = rec.get("stage")
                    payload = rec.get("payload", {})
                    
                    if stage == "policy":
                        decision = payload.get("decision", {})
                        if decision.get("disposition") == "auto_execute":
                            total_autonomous += 1
                    elif stage == "approval":
                        decision = payload.get("decision")
                        if decision == "approved":
                            total_human_approved += 1
                except json.JSONDecodeError:
                    continue

    pending_list = store.list(status="pending")

    return {
        "total_findings": total_findings,
        "total_pending": len(pending_list),
        "total_autonomous_actions": total_autonomous,
        "total_human_overridden_actions": total_human_approved
    }


@app.post("/api/slack/interactive")
async def slack_interactive(request: Request) -> dict[str, Any]:
    """
    Handle interactive button clicks from Slack approval messages.
    """
    body_bytes = await request.body()
    headers = request.headers
    signature = headers.get("X-Slack-Signature", "")
    timestamp = headers.get("X-Slack-Request-Timestamp", "")

    # 1. Verify Slack request signature (HMAC-SHA256)
    if settings.slack_signing_secret:
        from .chatops import verify_slack_signature
        if not verify_slack_signature(settings.slack_signing_secret, body_bytes, timestamp, signature):
            raise HTTPException(status_code=401, detail="Invalid Slack signature.")

    # 2. Parse form-url-encoded payload
    import urllib.parse
    form_data = urllib.parse.parse_qs(body_bytes.decode("utf-8"))
    payload_str_list = form_data.get("payload")
    if not payload_str_list:
        raise HTTPException(status_code=400, detail="Missing interactive payload.")

    try:
        payload = json.loads(payload_str_list[0])
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Malformed interactive JSON payload.")

    # 3. Extract operator details
    slack_user_id = payload.get("user", {}).get("id", "")
    slack_username = payload.get("user", {}).get("name", "") or payload.get("user", {}).get("username", "unknown")
    operator_id = settings.slack_user_mapping.get(slack_user_id, slack_user_id)

    # 4. Resolve local identity permissions
    from .identity import LocalIdentityProvider, Permission, Operator, AuthContext
    
    operator = None
    if settings.operator_registry_path:
        provider = LocalIdentityProvider(settings.operator_registry_path)
        operator = provider.get_operator(operator_id)
        if operator is None:
            return {
                "response_type": "ephemeral",
                "text": f"❌ Authentication failed: Slack user mapping '{operator_id}' not found in operator registry."
            }
        if not operator.active:
            return {
                "response_type": "ephemeral",
                "text": f"❌ Authentication failed: Operator '{operator_id}' is marked inactive."
            }
        if Permission.APPROVE not in operator.permissions():
            return {
                "response_type": "ephemeral",
                "text": f"❌ Authorization failed: Operator '{operator_id}' lacks approval permissions."
            }
        identity_verified = True
    else:
        # Default unauthenticated/fallback mode: map Slack operator with administrator role
        operator = Operator(
            operator_id=operator_id,
            display_name=slack_username,
            roles=["admin"],
            active=True
        )
        identity_verified = False

    actor = AuthContext(
        operator_id=operator.operator_id,
        display_name=operator.display_name,
        roles=operator.roles,
        identity_verified=identity_verified,
        auth_method="slack_sso"
    )

    # 5. Extract action decision
    actions = payload.get("actions", [])
    if not actions:
        raise HTTPException(status_code=400, detail="No action element found.")

    action_element = actions[0]
    action_id = action_element.get("action_id")
    request_id = action_element.get("value")

    # Locate request_id across all tenant stores
    tenant_id = "default"
    r = get_approval_store("default").get(request_id)
    if r is None:
        import glob
        directory = os.path.dirname(os.path.abspath(settings.approval_store_path)) or "."
        pattern = os.path.join(directory, "kronagent_approvals_*.json")
        for filepath in glob.glob(pattern):
            filename = os.path.basename(filepath)
            base_filename = os.path.basename(settings.approval_store_path)
            root, ext = os.path.splitext(base_filename)
            prefix = f"{root}_"
            if filename.startswith(prefix) and filename.endswith(ext):
                tid = filename[len(prefix):-len(ext)]
                candidate_store = get_approval_store(tid)
                candidate_r = candidate_store.get(request_id)
                if candidate_r is not None:
                    r = candidate_r
                    tenant_id = tid
                    break

    if r is None:
        return {
            "response_type": "ephemeral",
            "text": f"❌ Request ID '{request_id}' not found in any approval store."
        }

    # Dynamically resolve stores for the selected tenant
    store = get_approval_store(tenant_id)
    audit_log_resolved = get_audit_log(tenant_id)

    if r.status != "pending":
        return {
            "response_type": "ephemeral",
            "text": f"⚠️ Request is already processed: status is '{r.status}'."
        }

    action_type = "approve" if action_id == "approve_action" else "deny"

    # 6. Execute decision flow
    if action_type == "deny":
        r.status = "denied"
        r.decided_by = actor.operator_id
        r.decided_at = now_iso()
        r.decision_reason = "Rejected via Slack ChatOps"
        store.update(r)

        await audit_log_resolved.record(AuditRecord(
            finding_id=r.finding_id,
            stage="approval",
            payload={
                "request_id": r.request_id,
                "decision": "denied",
                "reason": "Rejected via Slack ChatOps",
                "action_class": r.action_class.value,
                "target": r.target,
                **actor.audit_fields()
            }
        ))
        status_text = f"Rejected via Slack by @{slack_username}"
    else:
        if settings.kill_switch:
            return {
                "response_type": "ephemeral",
                "text": "❌ Command execution aborted: global Kronagent KILL SWITCH is ENGAGED."
            }

        # Setup decision context
        decision = PolicyDecision(
            action_class=r.action_class,
            disposition="auto_execute",
            reason=f"approved via Slack ChatOps by @{slack_username}",
            reversible=r.reversible,
            blast_radius=BlastRadius(r.blast_radius),
        )
        action = r.to_proposed_action()
        containment = ContainmentExecutor(settings, build_containment_adapters(settings))

        # Record approval event
        await audit_log_resolved.record(AuditRecord(
            finding_id=r.finding_id,
            stage="approval",
            payload={
                "request_id": r.request_id,
                "decision": "approved",
                "reason": "Approved via Slack ChatOps",
                "action_class": r.action_class.value,
                "target": r.target,
                **actor.audit_fields()
            }
        ))

        # Execute containment
        outcome = await containment.execute(action, decision)

        # Record containment audit event
        await audit_log_resolved.record(AuditRecord(
            finding_id=r.finding_id,
            stage="containment",
            payload={"request_id": r.request_id, **outcome.model_dump()}
        ))

        r.decided_by = actor.operator_id
        r.decided_at = now_iso()
        r.decision_reason = "Approved via Slack ChatOps"
        r.execution_detail = outcome.detail

        if outcome.executed:
            r.status = "executed"
        elif outcome.error:
            r.status = "failed"
        else:
            r.status = "approved"  # Dry-run

        store.update(r)
        status_text = f"Approved & {r.status} via Slack by @{slack_username} ({outcome.detail})"

    # 7. Format updated message blocks
    from .chatops import ChatOpsNotifier
    updated_blocks = ChatOpsNotifier.build_slack_blocks(r, status_text)

    return {
        "replace_original": True,
        "text": f"Kronagent Approval Request Updated: {status_text}",
        "blocks": updated_blocks
    }
