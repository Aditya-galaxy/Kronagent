"""
Azure provider: Microsoft Defender for Cloud normalization + Compute/Entra containment.

Owns everything vendor-specific about Azure:
  * the Defender for Cloud alert wire schema (tolerant of unmodeled fields),
  * normalize_defender(): Defender alert dict -> provider-neutral Finding,
  * plan_azure_actions(): Finding -> candidate ProposedActions (targets read
    from the finding, never from the LLM),
  * AzureContainmentAdapter: ProposedAction -> concrete Azure API plan / execution.

Azure SDK imports are lazy (inside the adapter), so this module — and the whole
pipeline — imports and runs in dry-run with no Azure libraries installed.

A note on the entity model: Defender delivers implicated resources two ways —
`resourceIdentifiers` (ARM resource IDs) and `entities` (a typed list covering
hosts, IPs, and accounts). Both are read, because real alerts populate them
inconsistently depending on the detection that fired.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import asyncio
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from ..model import Finding, ResourceRef
from ..schemas import ActionClass, ProposedAction

PROVIDER = "azure"

# Defender for Cloud severities -> the platform's normalized 0-10 scale.
_SEVERITY_MAP: dict[str, float] = {
    "HIGH": 8.0,
    "MEDIUM": 5.0,
    "LOW": 2.5,
    "INFORMATIONAL": 1.0,
}


# --------------------------------------------------------------------------- #
# Defender for Cloud wire schema (real-schema subset, tolerant of extra fields)
# --------------------------------------------------------------------------- #

class DefenderEntity(BaseModel):
    model_config = ConfigDict(extra="allow")
    type: Optional[str] = None          # "host" | "ip" | "account" | ...
    hostName: Optional[str] = None
    address: Optional[str] = None       # for type == "ip"
    name: Optional[str] = None          # for type == "account"
    aadUserId: Optional[str] = None
    upnSuffix: Optional[str] = None


class DefenderResourceId(BaseModel):
    model_config = ConfigDict(extra="allow")
    type: Optional[str] = None
    azureResourceId: Optional[str] = None


class DefenderProperties(BaseModel):
    model_config = ConfigDict(extra="allow")
    alertType: Optional[str] = None
    alertDisplayName: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    timeGenerated: Optional[str] = None
    compromisedEntity: Optional[str] = None
    entities: list[DefenderEntity] = Field(default_factory=list)
    resourceIdentifiers: list[DefenderResourceId] = Field(default_factory=list)
    extendedProperties: dict[str, Any] = Field(default_factory=dict)


class DefenderAlert(BaseModel):
    """Subset of the Defender for Cloud alert schema."""

    model_config = ConfigDict(extra="allow")
    id: Optional[str] = None
    name: Optional[str] = None
    properties: DefenderProperties = Field(default_factory=DefenderProperties)


def _arm_segment(resource_id: str, segment: str) -> str:
    """Pull the value following `segment` out of an ARM resource id.

    ARM ids are '/key/value/key/value/...' so a segment's value is the element
    immediately after it. Returns "" when absent rather than raising — alerts
    routinely omit pieces.
    """
    parts = [p for p in resource_id.split("/") if p]
    for i, part in enumerate(parts):
        if part.lower() == segment.lower() and i + 1 < len(parts):
            return parts[i + 1]
    return ""


# --------------------------------------------------------------------------- #
# Normalization: Defender alert -> provider-neutral Finding
# --------------------------------------------------------------------------- #

def normalize_defender(payload: dict) -> Finding:
    alert = DefenderAlert.model_validate(payload)
    props = alert.properties

    finding_id = alert.name or (alert.id.split("/")[-1] if alert.id else "azure-finding-unknown")
    severity = _SEVERITY_MAP.get((props.severity or "").upper(), 5.0)
    finding_type = props.alertType or props.alertDisplayName or "Azure Threat Detected"

    resources: list[ResourceRef] = []
    remote_ip: Optional[str] = None
    seen: set[tuple[str, str]] = set()

    def add(kind: str, rid: str, **attributes: Any) -> None:
        if not rid or (kind, rid) in seen:
            return
        seen.add((kind, rid))
        resources.append(ResourceRef(kind=kind, id=rid, attributes=attributes))

    # 1. ARM resource identifiers — the authoritative source when present.
    for ident in props.resourceIdentifiers:
        arm_id = ident.azureResourceId or ""
        if "/virtualMachines/" in arm_id:
            add(
                "azure.vm",
                _arm_segment(arm_id, "virtualMachines"),
                subscription=_arm_segment(arm_id, "subscriptions"),
                resource_group=_arm_segment(arm_id, "resourceGroups"),
                arm_id=arm_id,
            )

    # 2. Typed entities — hosts, IPs and accounts.
    for entity in props.entities:
        etype = (entity.type or "").lower()
        if etype == "host" and entity.hostName:
            add("azure.vm", entity.hostName)
        elif etype == "ip" and entity.address and remote_ip is None:
            remote_ip = entity.address
        elif etype == "account":
            principal = entity.name or entity.aadUserId or ""
            if principal:
                upn = f"{principal}@{entity.upnSuffix}" if entity.upnSuffix else principal
                add("azure.principal", principal, aad_object_id=entity.aadUserId or "", upn=upn)

    # 3. compromisedEntity is a last-resort hint when nothing above matched.
    if not resources and props.compromisedEntity:
        add("azure.vm", props.compromisedEntity)

    return Finding(
        provider=PROVIDER,
        finding_id=finding_id,
        finding_type=finding_type,
        severity=severity,
        title=props.alertDisplayName or finding_type,
        description=props.description or "",
        resources=resources,
        remote_ip=remote_ip,
        raw=payload,
    )


# --------------------------------------------------------------------------- #
# Planning: Finding -> candidate ProposedActions. Targets come from the
# normalized resources, never from model output.
# --------------------------------------------------------------------------- #

def plan_azure_actions(finding: Finding) -> list[ProposedAction]:
    actions: list[ProposedAction] = []

    for r in finding.resources:
        if r.kind == "azure.vm":
            params = {
                "resource_group": r.attributes.get("resource_group", ""),
                "subscription": r.attributes.get("subscription", ""),
            }
            actions.append(ProposedAction(
                provider=PROVIDER, action_class=ActionClass.ISOLATE_VM_NSG,
                target=r.id, parameters=params,
                rationale="Apply a deny-all NSG to the VM's NIC, isolating it while "
                          "leaving it running for forensics.",
            ))
            actions.append(ProposedAction(
                provider=PROVIDER, action_class=ActionClass.DEALLOCATE_VM,
                target=r.id, parameters=params,
                rationale="Deallocate the VM if isolation is insufficient "
                          "(takes the workload down; approval-gated).",
            ))
        elif r.kind == "azure.principal":
            params = {"aad_object_id": r.attributes.get("aad_object_id", "")}
            actions.append(ProposedAction(
                provider=PROVIDER, action_class=ActionClass.DISABLE_ENTRA_PRINCIPAL,
                target=r.id, parameters=params,
                rationale="Disable the compromised Entra ID principal to stop further sign-ins.",
            ))
            actions.append(ProposedAction(
                provider=PROVIDER, action_class=ActionClass.REVOKE_ENTRA_SESSIONS,
                target=r.id, parameters=params,
                rationale="Revoke refresh tokens so existing sessions cannot survive the "
                          "account being disabled (approval-gated).",
            ))

    if finding.remote_ip:
        actions.append(ProposedAction(
            provider=PROVIDER, action_class=ActionClass.BLOCK_IP,
            target=finding.remote_ip,
            rationale="Block the remote IP observed driving the malicious activity.",
        ))

    return actions


# --------------------------------------------------------------------------- #
# Containment adapter: plan (pure) + perform (real Azure SDK).
# --------------------------------------------------------------------------- #

class AzureContainmentAdapter:
    provider = PROVIDER

    def __init__(self, *, subscription_id: str = "", quarantine_nsg_id: str = "") -> None:
        self._subscription_id = subscription_id
        self._quarantine_nsg = quarantine_nsg_id
        self._compute = None
        self._network = None
        self._graph = None

    def _credential(self):
        from azure.identity import DefaultAzureCredential
        return DefaultAzureCredential()

    def _compute_client(self):
        if self._compute is None:
            from azure.mgmt.compute import ComputeManagementClient
            self._compute = ComputeManagementClient(self._credential(), self._subscription_id)
        return self._compute

    def _network_client(self):
        if self._network is None:
            from azure.mgmt.network import NetworkManagementClient
            self._network = NetworkManagementClient(self._credential(), self._subscription_id)
        return self._network

    def plan(self, action: ProposedAction) -> tuple[list[str], str, str]:
        ac = action.action_class
        t = action.target
        rg = action.parameters.get("resource_group", "") or "<resource_group unset>"

        if ac == ActionClass.ISOLATE_VM_NSG:
            nsg = self._quarantine_nsg or "<KRONAGENT_AZURE_QUARANTINE_NSG_ID unset>"
            return (
                [
                    f"network.network_interfaces.get(resource_group_name='{rg}', "
                    f"network_interface_name=<nic of {t}>)  # capture original NSG for rollback",
                    f"network.network_interfaces.begin_create_or_update(resource_group_name='{rg}', "
                    f"network_interface_name=<nic of {t}>, parameters={{'networkSecurityGroup': {{'id': '{nsg}'}}}})",
                ],
                f"network.network_interfaces.begin_create_or_update(resource_group_name='{rg}', "
                f"network_interface_name=<nic of {t}>, parameters=<original NSG captured at execution>)",
                f"isolate VM {t} behind quarantine NSG {nsg}",
            )
        if ac == ActionClass.DEALLOCATE_VM:
            return (
                [f"compute.virtual_machines.begin_deallocate(resource_group_name='{rg}', vm_name='{t}')"],
                f"compute.virtual_machines.begin_start(resource_group_name='{rg}', vm_name='{t}')",
                f"deallocate VM {t}",
            )
        if ac == ActionClass.DISABLE_ENTRA_PRINCIPAL:
            oid = action.parameters.get("aad_object_id", "") or t
            return (
                [f"graph.PATCH /users/{oid} {{'accountEnabled': false}}"],
                f"graph.PATCH /users/{oid} {{'accountEnabled': true}}",
                f"disable Entra ID principal {t}",
            )
        if ac == ActionClass.REVOKE_ENTRA_SESSIONS:
            oid = action.parameters.get("aad_object_id", "") or t
            return (
                [f"graph.POST /users/{oid}/revokeSignInSessions"],
                "IRREVERSIBLE — sessions cannot be un-revoked; the principal must sign in again",
                f"revoke Entra ID sign-in sessions for {t}",
            )
        if ac == ActionClass.BLOCK_IP:
            nsg = self._quarantine_nsg or "<KRONAGENT_AZURE_QUARANTINE_NSG_ID unset>"
            return (
                [
                    f"network.security_rules.begin_create_or_update(network_security_group_name='{nsg}', "
                    f"security_rule_name='kronagent-deny-{t}', parameters={{'access': 'Deny', "
                    f"'direction': 'Inbound', 'sourceAddressPrefix': '{t}', 'priority': <next free>}})",
                ],
                f"network.security_rules.begin_delete(network_security_group_name='{nsg}', "
                f"security_rule_name='kronagent-deny-{t}')",
                f"block remote IP {t} at NSG {nsg}",
            )
        return ([f"# no Azure planner for {ac.value}"], "unknown", f"unhandled action {ac.value}")

    async def perform(self, action: ProposedAction) -> tuple[str, str]:
        return await asyncio.to_thread(self._perform_sync, action)

    def _perform_sync(self, action: ProposedAction) -> tuple[str, str]:
        ac = action.action_class
        t = action.target
        rg = action.parameters.get("resource_group", "")

        if ac == ActionClass.DEALLOCATE_VM:
            if not rg:
                raise RuntimeError(f"resource_group unknown for VM {t}; cannot deallocate")
            self._compute_client().virtual_machines.begin_deallocate(rg, t).result()
            return (f"VM {t} deallocated",
                    f"compute.virtual_machines.begin_start(resource_group_name='{rg}', vm_name='{t}')")

        if ac == ActionClass.ISOLATE_VM_NSG:
            if not self._quarantine_nsg:
                raise RuntimeError("KRONAGENT_AZURE_QUARANTINE_NSG_ID is not configured")
            if not rg:
                raise RuntimeError(f"resource_group unknown for VM {t}; cannot isolate")
            # Resolving the VM's NIC and swapping its NSG requires the live
            # topology; not enabled in this slice rather than guessed at.
            raise NotImplementedError(
                "live Azure NSG isolation requires NIC resolution — not enabled in this slice"
            )

        # Entra ID actions go through Microsoft Graph, which is a separate
        # credential/consent path from ARM. Deliberately not wired up blind.
        if ac in (ActionClass.DISABLE_ENTRA_PRINCIPAL, ActionClass.REVOKE_ENTRA_SESSIONS):
            raise NotImplementedError(
                f"live Microsoft Graph execution for {ac.value} not enabled in this slice"
            )

        raise NotImplementedError(f"real Azure execution for {ac.value} not enabled in this slice")
