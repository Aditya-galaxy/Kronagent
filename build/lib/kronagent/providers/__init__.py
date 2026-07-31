"""
Provider registry — the seam that lets one platform defend many substrates.

A provider contributes three things, registered here by name:
  * normalize:  native event dict -> provider-neutral Finding
  * planner:    Finding -> candidate ProposedActions (targets from the finding)
  * containment factory: build the provider's ContainmentAdapter from Settings

Everything above this seam (triage, policy, approval, audit, allowlist) is
provider-agnostic. Adding a source — Azure Defender, GCP SCC, an in-house
syslog detector, another cluster runtime — is a new module here plus an entry
in these tables; nothing else changes.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

from typing import Callable

from ..config import Settings
from ..model import Finding
from ..schemas import ProposedAction
from . import aws, azure, gcp, k8s, onprem

# native payload dict -> Finding
NORMALIZERS: dict[str, Callable[[dict], Finding]] = {
    aws.PROVIDER: aws.normalize_guardduty,
    azure.PROVIDER: azure.normalize_defender,
    gcp.PROVIDER: gcp.normalize_gcp_scc,
    k8s.PROVIDER: k8s.normalize_k8s,
    onprem.PROVIDER: onprem.normalize_onprem,
}

# Finding -> candidate ProposedActions
PLANNERS: dict[str, Callable[[Finding], list[ProposedAction]]] = {
    aws.PROVIDER: aws.plan_aws_actions,
    azure.PROVIDER: azure.plan_azure_actions,
    gcp.PROVIDER: gcp.plan_gcp_actions,
    k8s.PROVIDER: k8s.plan_k8s_actions,
    onprem.PROVIDER: onprem.plan_onprem_actions,
}


def build_containment_adapters(settings: Settings) -> dict[str, object]:
    """Construct one containment adapter per provider. Adapters are lazy about
    their cloud/cluster clients, so this is cheap and credential-free."""
    return {
        aws.PROVIDER: aws.AwsContainmentAdapter(
            region=settings.aws_region,
            quarantine_security_group_id=settings.quarantine_security_group_id,
            quarantine_nacl_id=settings.quarantine_nacl_id,
        ),
        azure.PROVIDER: azure.AzureContainmentAdapter(
            subscription_id=settings.azure_subscription_id,
            quarantine_nsg_id=settings.azure_quarantine_nsg_id,
        ),
        gcp.PROVIDER: gcp.GcpContainmentAdapter(),
        k8s.PROVIDER: k8s.K8sContainmentAdapter(
            kubeconfig=settings.kubeconfig_path,
            context=settings.kube_context,
        ),
        onprem.PROVIDER: onprem.OnPremContainmentAdapter(
            control_plane_url=settings.onprem_control_plane_url,
            quarantine_vlan=settings.onprem_quarantine_vlan,
        ),
    }


def plan_actions(finding: Finding) -> list[ProposedAction]:
    planner = PLANNERS.get(finding.provider)
    if planner is None:
        return []
    return planner(finding)
