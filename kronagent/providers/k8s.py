"""
Kubernetes provider: audit-event normalization + kubectl-based containment.

This is the second source, and the reason the provider boundary exists rather
than being assumed from AWS alone. It ingests Kubernetes API-server audit events
(the same shape Falco / audit-webhook pipelines emit) and contains threats via
the Kubernetes API.

Structurally it is the opposite of AWS: no IAM users or EC2 instances, but pods,
nodes, deployments, and namespaces. Yet everything above the provider boundary —
triage, the policy engine's reversible/blast-radius classification, approval,
audit, the earn-trust allowlist — treats a K8s action exactly like an AWS one.

Kubernetes audit events carry no severity field, so severity is assigned here
from the detected behavior (privilege escalation, secret enumeration, exec into
a running pod, ...), normalized onto the same 0-10 scale AWS uses so the single
containment threshold means the same thing across providers.

The kubernetes client is imported lazily inside the adapter; the module and
pipeline run in dry-run with nothing installed.
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

PROVIDER = "kubernetes"


# --------------------------------------------------------------------------- #
# Audit-event wire schema (subset of the k8s audit.k8s.io Event, tolerant).
# --------------------------------------------------------------------------- #

class ObjectRef(BaseModel):
    model_config = ConfigDict(extra="allow")
    resource: Optional[str] = None       # "pods", "secrets", "nodes", ...
    namespace: Optional[str] = None
    name: Optional[str] = None
    subresource: Optional[str] = None     # "exec", "log", ...


class K8sUser(BaseModel):
    model_config = ConfigDict(extra="allow")
    username: Optional[str] = None
    groups: Optional[list[str]] = None


class K8sAuditEvent(BaseModel):
    """Subset of a Kubernetes API-server audit event."""

    model_config = ConfigDict(extra="allow")

    auditID: str
    verb: Optional[str] = None            # "create", "get", "delete", ...
    user: K8sUser = Field(default_factory=K8sUser)
    sourceIPs: Optional[list[str]] = None
    objectRef: ObjectRef = Field(default_factory=ObjectRef)
    # Kronagent-side detection annotations (what a Falco rule / detector attached):
    detected_rule: Optional[str] = None   # e.g. "privilege_escalation_exec"
    detected_severity: Optional[float] = None  # 0-10 if the detector set it
    node_name: Optional[str] = None       # node the pod runs on, if known


# Rule -> (normalized severity, human threat type). The detector's rule name is
# the deterministic signal; severity is assigned here so the containment
# threshold is uniform with AWS.
_RULE_SEVERITY: dict[str, tuple[float, str]] = {
    "privilege_escalation_exec": (8.5, "Privilege Escalation via pod exec"),
    "secret_enumeration": (7.5, "Cluster-wide secret enumeration"),
    "sensitive_mount": (7.0, "Sensitive host path / docker.sock mount"),
    "crypto_mining_pod": (7.5, "Cryptomining workload"),
    "benign_scan": (2.0, "Background scanning / noise"),
}


def normalize_k8s(payload: dict) -> Finding:
    ev = K8sAuditEvent.model_validate(payload)
    rule = ev.detected_rule or "unknown"
    sev, threat_type = _RULE_SEVERITY.get(rule, (ev.detected_severity or 5.0, rule))
    if ev.detected_severity is not None:
        sev = ev.detected_severity  # detector-provided severity wins

    resources: list[ResourceRef] = []
    ref = ev.objectRef
    ns = ref.namespace or "default"

    if ref.resource == "pods" and ref.name:
        resources.append(ResourceRef(
            kind="k8s.pod", id=ref.name,
            attributes={"namespace": ns, "node": ev.node_name or ""},
        ))
        if ev.node_name:
            resources.append(ResourceRef(
                kind="k8s.node", id=ev.node_name, attributes={},
            ))
    elif ref.resource == "deployments" and ref.name:
        resources.append(ResourceRef(
            kind="k8s.deployment", id=ref.name, attributes={"namespace": ns},
        ))

    source_ip = ev.sourceIPs[0] if ev.sourceIPs else None
    subres = f"/{ref.subresource}" if ref.subresource else ""

    return Finding(
        provider=PROVIDER,
        finding_id=ev.auditID,
        finding_type=f"k8s:{rule}",
        severity=sev,
        title=threat_type,
        description=(
            f"user={ev.user.username or 'unknown'} verb={ev.verb or '?'} "
            f"target={ref.resource or '?'}/{ref.name or '?'}{subres} in ns/{ns}"
        ),
        resources=resources,
        remote_ip=source_ip,
        raw=payload,
    )


def plan_k8s_actions(finding: Finding) -> list[ProposedAction]:
    actions: list[ProposedAction] = []

    for r in finding.resources:
        if r.kind == "k8s.pod":
            ns = r.attributes.get("namespace", "default")
            actions.append(ProposedAction(
                provider=PROVIDER, action_class=ActionClass.ISOLATE_POD,
                target=r.id,
                rationale="Apply a deny-all NetworkPolicy to cut the pod's traffic while preserving it for forensics.",
                parameters={"namespace": ns},
            ))
            actions.append(ProposedAction(
                provider=PROVIDER, action_class=ActionClass.DELETE_POD,
                target=r.id,
                rationale="Kill the compromised pod; its controller reschedules a clean replacement (disruptive; approval-gated).",
                parameters={"namespace": ns},
            ))
        elif r.kind == "k8s.node":
            actions.append(ProposedAction(
                provider=PROVIDER, action_class=ActionClass.CORDON_NODE,
                target=r.id,
                rationale="Cordon the node to stop new scheduling onto a possibly-compromised host (non-disruptive, reversible).",
            ))
        elif r.kind == "k8s.deployment":
            ns = r.attributes.get("namespace", "default")
            actions.append(ProposedAction(
                provider=PROVIDER, action_class=ActionClass.SCALE_DEPLOYMENT_ZERO,
                target=r.id,
                rationale="Scale the workload to zero replicas to halt active exploitation (destructive; approval-gated).",
                parameters={"namespace": ns},
            ))

    return actions


class K8sContainmentAdapter:
    provider = PROVIDER

    _DENY_ALL_NETPOL = "kronagent-quarantine-deny-all"

    def __init__(self, *, kubeconfig: str = "", context: str = "") -> None:
        self._kubeconfig = kubeconfig
        self._context = context
        self._api = None

    def _apis(self):
        """Lazily build (CoreV1Api, AppsV1Api, NetworkingV1Api)."""
        if self._api is None:
            from kubernetes import client, config  # local import
            if self._kubeconfig:
                config.load_kube_config(config_file=self._kubeconfig, context=self._context or None)
            else:
                config.load_kube_config(context=self._context or None)
            self._api = (client.CoreV1Api(), client.AppsV1Api(), client.NetworkingV1Api())
        return self._api

    def plan(self, action: ProposedAction) -> tuple[list[str], str, str]:
        ac = action.action_class
        t = action.target
        ns = action.parameters.get("namespace", "default")
        if ac == ActionClass.ISOLATE_POD:
            return (
                [
                    f"kubectl label pod {t} -n {ns} kronagent-quarantine=true --overwrite",
                    f"kubectl apply -f - # NetworkPolicy '{self._DENY_ALL_NETPOL}' selecting kronagent-quarantine=true in ns/{ns}, deny all ingress+egress",
                ],
                f"kubectl label pod {t} -n {ns} kronagent-quarantine- ; kubectl delete networkpolicy {self._DENY_ALL_NETPOL} -n {ns}",
                f"isolate pod {ns}/{t} with a deny-all NetworkPolicy",
            )
        if ac == ActionClass.CORDON_NODE:
            return (
                [f"kubectl cordon {t}"],
                f"kubectl uncordon {t}",
                f"cordon node {t} (stop new scheduling; running pods untouched)",
            )
        if ac == ActionClass.DELETE_POD:
            return (
                [f"kubectl delete pod {t} -n {ns} --grace-period=30"],
                f"controller reschedules automatically; no manual rollback (bare pods must be recreated from manifest)",
                f"delete pod {ns}/{t}",
            )
        if ac == ActionClass.SCALE_DEPLOYMENT_ZERO:
            return (
                [
                    f"kubectl get deployment {t} -n {ns} -o jsonpath='{{.spec.replicas}}'  # capture original replica count for rollback",
                    f"kubectl scale deployment {t} -n {ns} --replicas=0",
                ],
                f"kubectl scale deployment {t} -n {ns} --replicas=<original count captured at execution>",
                f"scale deployment {ns}/{t} to 0 replicas",
            )
        return ([f"# no k8s planner for {ac.value}"], "unknown", f"unhandled action {ac.value}")

    async def perform(self, action: ProposedAction) -> tuple[str, str]:
        return await asyncio.to_thread(self._perform_sync, action)

    def _perform_sync(self, action: ProposedAction) -> tuple[str, str]:
        ac = action.action_class
        t = action.target
        ns = action.parameters.get("namespace", "default")
        core, apps, net = self._apis()

        if ac == ActionClass.CORDON_NODE:
            core.patch_node(t, {"spec": {"unschedulable": True}})
            return (f"node {t} cordoned", f"kubectl uncordon {t}")

        if ac == ActionClass.SCALE_DEPLOYMENT_ZERO:
            dep = apps.read_namespaced_deployment(t, ns)
            original = dep.spec.replicas
            apps.patch_namespaced_deployment_scale(t, ns, {"spec": {"replicas": 0}})
            return (f"deployment {ns}/{t} scaled 0 (was {original})",
                    f"kubectl scale deployment {t} -n {ns} --replicas={original}")

        if ac == ActionClass.DELETE_POD:
            core.delete_namespaced_pod(t, ns, grace_period_seconds=30)
            return (f"pod {ns}/{t} deletion requested",
                    "controller reschedules; recreate bare pods from manifest")

        if ac == ActionClass.ISOLATE_POD:
            core.patch_namespaced_pod(
                t, ns, {"metadata": {"labels": {"kronagent-quarantine": "true"}}}
            )
            from kubernetes import client
            policy_name = self._DENY_ALL_NETPOL
            policy = client.V1NetworkPolicy(
                metadata=client.V1ObjectMeta(name=policy_name, namespace=ns),
                spec=client.V1NetworkPolicySpec(
                    pod_selector=client.V1LabelSelector(match_labels={"kronagent-quarantine": "true"}),
                    policy_types=["Ingress", "Egress"],
                    ingress=[],
                    egress=[]
                )
            )
            try:
                net.read_namespaced_network_policy(policy_name, ns)
            except client.exceptions.ApiException as exc:
                if exc.status == 404:
                    net.create_namespaced_network_policy(ns, policy)
                else:
                    raise
            return (
                f"pod {ns}/{t} isolated with deny-all NetworkPolicy '{policy_name}'",
                f"kubectl label pod {t} -n {ns} kronagent-quarantine- ; kubectl delete networkpolicy {policy_name} -n {ns}"
            )
        raise NotImplementedError(f"real k8s execution for {ac.value} not enabled in this slice")
