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

from __future__ import annotations

from typing import Callable

from ..config import Settings
from ..model import Finding
from ..schemas import ProposedAction
from . import aws, k8s

# native payload dict -> Finding
NORMALIZERS: dict[str, Callable[[dict], Finding]] = {
    aws.PROVIDER: aws.normalize_guardduty,
    k8s.PROVIDER: k8s.normalize_k8s,
}

# Finding -> candidate ProposedActions
PLANNERS: dict[str, Callable[[Finding], list[ProposedAction]]] = {
    aws.PROVIDER: aws.plan_aws_actions,
    k8s.PROVIDER: k8s.plan_k8s_actions,
}


def build_containment_adapters(settings: Settings) -> dict[str, object]:
    """Construct one containment adapter per provider. Adapters are lazy about
    their cloud/cluster clients, so this is cheap and credential-free."""
    return {
        aws.PROVIDER: aws.AwsContainmentAdapter(
            region=settings.aws_region,
            quarantine_security_group_id=settings.quarantine_security_group_id,
        ),
        k8s.PROVIDER: k8s.K8sContainmentAdapter(
            kubeconfig=settings.kubeconfig_path,
            context=settings.kube_context,
        ),
    }


def plan_actions(finding: Finding) -> list[ProposedAction]:
    planner = PLANNERS.get(finding.provider)
    if planner is None:
        return []
    return planner(finding)
