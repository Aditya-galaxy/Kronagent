"""
GCP provider: GCP Security Command Center (SCC) normalization + IAM/Compute containment.

Owns everything vendor-specific about Google Cloud Platform:
  * the GCP SCC finding wire schema (tolerant of unmodeled fields),
  * normalize_gcp_scc(): SCC finding dict -> provider-neutral Finding,
  * plan_gcp_actions(): Finding -> candidate ProposedActions (targets read from
    the finding, never from the LLM),
  * GcpContainmentAdapter: ProposedAction -> concrete GCP API plan / execution.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import asyncio
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict

from ..model import Finding, ResourceRef
from ..schemas import ActionClass, ProposedAction

PROVIDER = "gcp"

_SEVERITY_MAP: dict[str, float] = {
    "CRITICAL": 9.0,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 2.5,
}


# --------------------------------------------------------------------------- #
# GCP SCC wire schema
# --------------------------------------------------------------------------- #

class GcpSccFindingDetail(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: Optional[str] = None           # e.g. "organizations/123/sources/456/findings/789"
    resourceName: Optional[str] = None   # e.g. "//compute.googleapis.com/projects/p/zones/z/instances/i"
    category: Optional[str] = None       # e.g. "Persistence: IAM Anomalous Grant"
    severity: Optional[str] = None       # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    eventTime: Optional[str] = None
    description: Optional[str] = None
    sourceProperties: Optional[dict[str, Any]] = None


class GcpSccPayload(BaseModel):
    """Outer wrapper for GCP SCC notifications or raw finding dictionary."""

    model_config = ConfigDict(extra="allow")
    finding: Optional[GcpSccFindingDetail] = None


def normalize_gcp_scc(payload: dict) -> Finding:
    # Accept either nested {"finding": {...}} or flat finding dict
    if "finding" in payload and isinstance(payload["finding"], dict):
        detail = GcpSccFindingDetail.model_validate(payload["finding"])
    else:
        detail = GcpSccFindingDetail.model_validate(payload)

    fid = detail.name.split("/")[-1] if detail.name else "gcp-finding-unknown"
    sev = _SEVERITY_MAP.get((detail.severity or "").upper(), 5.0)
    category = detail.category or "GCP Threat Detected"

    source_props = detail.sourceProperties or {}
    remote_ip = source_props.get("callerIp") or source_props.get("remoteIp")

    resources: list[ResourceRef] = []
    res_name = detail.resourceName or ""

    # Parse compute instance URI
    if "instances/" in res_name:
        parts = res_name.split("/")
        inst_id = parts[-1]
        zone = parts[parts.index("zones") + 1] if "zones" in parts else ""
        proj = parts[parts.index("projects") + 1] if "projects" in parts else ""
        resources.append(ResourceRef(
            kind="gcp.instance",
            id=inst_id,
            attributes={"project": proj, "zone": zone}
        ))

    # Parse service account key URI
    if "keys/" in res_name:
        parts = res_name.split("/")
        key_id = parts[-1]
        sa_email = parts[parts.index("serviceAccounts") + 1] if "serviceAccounts" in parts else ""
        proj = parts[parts.index("projects") + 1] if "projects" in parts else ""
        resources.append(ResourceRef(
            kind="gcp.service_account_key",
            id=key_id,
            attributes={"project": proj, "service_account": sa_email}
        ))

    # Parse service account URI or sourceProperties
    sa_email_prop = source_props.get("serviceAccountEmail") or source_props.get("service_account")
    if "serviceAccounts/" in res_name and not any(r.kind == "gcp.service_account" for r in resources):
        parts = res_name.split("/")
        sa_email = parts[parts.index("serviceAccounts") + 1]
        proj = parts[parts.index("projects") + 1] if "projects" in parts else ""
        resources.append(ResourceRef(
            kind="gcp.service_account",
            id=sa_email,
            attributes={"project": proj}
        ))
    elif sa_email_prop and not any(r.kind == "gcp.service_account" for r in resources):
        resources.append(ResourceRef(
            kind="gcp.service_account",
            id=sa_email_prop,
            attributes={}
        ))

    sa_key_prop = source_props.get("serviceAccountKeyId") or source_props.get("key_id")
    if sa_key_prop and not any(r.kind == "gcp.service_account_key" for r in resources):
        resources.append(ResourceRef(
            kind="gcp.service_account_key",
            id=sa_key_prop,
            attributes={"service_account": sa_email_prop or ""}
        ))

    return Finding(
        finding_id=fid,
        provider=PROVIDER,
        finding_type=category,
        severity=sev,
        title=f"GCP SCC: {category}",
        description=detail.description or f"GCP Security Command Center alert for resource {res_name}",
        remote_ip=remote_ip,
        resources=resources,
        raw=payload,  # field is `raw` — `raw_payload` was silently dropped, losing the SCC payload for audit
    )


# --------------------------------------------------------------------------- #
# Action Planner
# --------------------------------------------------------------------------- #

def plan_gcp_actions(finding: Finding) -> list[ProposedAction]:
    actions: list[ProposedAction] = []

    for res in finding.resources:
        if res.kind == "gcp.service_account_key":
            # target MUST be the bare resource id. A decorated string like
            # "key-id (sa@project)" is not a member of the finding's resource
            # set, so the trajectory guard correctly rejects it as an
            # out-of-scope redirection — which silently broke this containment
            # path. Context belongs in parameters, exactly as AWS carries
            # user_name for DISABLE_ACCESS_KEY.
            actions.append(ProposedAction(
                action_class=ActionClass.DISABLE_SERVICE_ACCOUNT_KEY,
                target=res.id,
                provider=PROVIDER,
                parameters={"service_account": res.attributes.get("service_account", "")},
                rationale=f"Disable compromised GCP service account key '{res.id}' implicated in {finding.finding_type}."
            ))

        elif res.kind == "gcp.service_account":
            actions.append(ProposedAction(
                action_class=ActionClass.DISABLE_SERVICE_ACCOUNT,
                target=res.id,
                provider=PROVIDER,
                rationale=f"Disable compromised GCP service account '{res.id}' implicated in {finding.finding_type}."
            ))

        elif res.kind == "gcp.instance":
            actions.append(ProposedAction(
                action_class=ActionClass.STOP_VM_INSTANCE,
                target=res.id,
                provider=PROVIDER,
                rationale=f"Stop compromised GCP Compute instance '{res.id}' implicated in {finding.finding_type}."
            ))

    if finding.remote_ip:
        actions.append(ProposedAction(
            action_class=ActionClass.BLOCK_IP,
            target=finding.remote_ip,
            provider=PROVIDER,
            rationale=f"Block malicious remote IP {finding.remote_ip} implicated in GCP alert {finding.finding_type}."
        ))

    return actions


# --------------------------------------------------------------------------- #
# Containment Adapter
# --------------------------------------------------------------------------- #

class GcpContainmentAdapter:
    """Plans GCP IAM / Compute containment. Live execution is NOT implemented.

    `perform()` used to update an in-memory set and return a success string
    without calling GCP at all. In live mode the executor saw no exception and
    recorded `executed=True` with "EXECUTED — service account key ... set to
    disabled" into the hash-chained audit log — so a compromised credential
    stayed active while the platform certified, in signed compliance evidence,
    that it had been revoked. A false containment guarantee is worse than an
    absent one: an absent one gets noticed.

    Live execution now refuses instead, matching what every other provider does
    for an unimplemented action. `simulate=True` restores the in-memory
    behaviour for tests, and must never be set in a deployment — hence
    `build_containment_adapters` leaving it at the default.

    Planning is unaffected: `plan()` is pure and honest, so dry-run continues to
    show exactly the API calls a real implementation would make.
    """

    provider = PROVIDER

    def __init__(self, project_id: str = "", *, simulate: bool = False) -> None:
        self.project_id = project_id
        self._simulate = simulate
        # State tracking for simulated test mode execution
        self.disabled_keys: set[str] = set()
        self.disabled_accounts: set[str] = set()
        self.stopped_instances: set[str] = set()
        self.blocked_ips: set[str] = set()

    def plan(self, action: ProposedAction) -> tuple[list[str], str, str]:
        if action.action_class == ActionClass.DISABLE_SERVICE_ACCOUNT_KEY:
            calls = [f"gcp.iam.serviceAccountKeys.disable(keyId='{action.target}')"]
            rollback = f"gcp.iam.serviceAccountKeys.enable(keyId='{action.target}')"
            detail = f"Disable GCP service account key '{action.target}'"

        elif action.action_class == ActionClass.DISABLE_SERVICE_ACCOUNT:
            calls = [f"gcp.iam.serviceAccounts.disable(name='{action.target}')"]
            rollback = f"gcp.iam.serviceAccounts.enable(name='{action.target}')"
            detail = f"Disable GCP service account '{action.target}'"

        elif action.action_class == ActionClass.STOP_VM_INSTANCE:
            calls = [f"gcp.compute.instances.stop(instance='{action.target}')"]
            rollback = f"gcp.compute.instances.start(instance='{action.target}')"
            detail = f"Stop GCP Compute Engine instance '{action.target}'"

        elif action.action_class == ActionClass.BLOCK_IP:
            calls = [f"gcp.compute.firewalls.insert(deny_ip='{action.target}')"]
            rollback = f"gcp.compute.firewalls.delete(deny_ip='{action.target}')"
            detail = f"Block remote IP {action.target} in GCP Cloud Armor / Firewall"

        else:
            calls = [f"gcp.unknown_action('{action.target}')"]
            rollback = "gcp.noop()"
            detail = f"Unknown GCP action class {action.action_class}"

        return calls, rollback, detail

    async def perform(self, action: ProposedAction) -> tuple[str, str]:
        # Fail loudly rather than reporting a containment that did not happen.
        # The executor catches this and records EXECUTION FAILED, so an operator
        # sees that the credential is still live and can act on it.
        if not self._simulate:
            raise NotImplementedError(
                f"live GCP execution for {action.action_class.value} is not implemented — "
                f"the action was NOT performed. Plan it in dry-run, or contain this "
                f"resource by another route."
            )

        # Simulated path: tests only. Never reached in a deployment.
        await asyncio.sleep(0.01)

        if action.action_class == ActionClass.DISABLE_SERVICE_ACCOUNT_KEY:
            self.disabled_keys.add(action.target)
            return (
                f"GCP service account key {action.target} set to disabled",
                f"gcp.iam.serviceAccountKeys.enable(keyId='{action.target}')"
            )

        elif action.action_class == ActionClass.DISABLE_SERVICE_ACCOUNT:
            self.disabled_accounts.add(action.target)
            return (
                f"GCP service account {action.target} set to disabled",
                f"gcp.iam.serviceAccounts.enable(name='{action.target}')"
            )

        elif action.action_class == ActionClass.STOP_VM_INSTANCE:
            self.stopped_instances.add(action.target)
            return (
                f"GCP Compute Engine instance {action.target} stopped",
                f"gcp.compute.instances.start(instance='{action.target}')"
            )

        elif action.action_class == ActionClass.BLOCK_IP:
            self.blocked_ips.add(action.target)
            return (
                f"GCP firewall rule created blocking remote IP {action.target}",
                f"gcp.compute.firewalls.delete(deny_ip='{action.target}')"
            )

        raise NotImplementedError(f"GCP containment for action class {action.action_class} is not implemented.")
