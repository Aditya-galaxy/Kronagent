"""
Platform configuration and the safety-critical control switches.

Every field that governs whether the platform can touch production
infrastructure lives here, defaults to the *safe* value, and is overridable
from the environment. The two load-bearing safety controls are:

  * dry_run           — when True (the default), NO containment action is
                        actually executed; the platform produces the exact
                        API calls it *would* make and records them.
  * kill_switch       — when True, the platform halts all containment
                        entirely (not even dry-run planning proceeds to
                        execution). A single global stop.

Graduated autonomy is expressed by the allowlist (see allowlist.py): an action
class executes automatically ONLY if it is (a) classified AUTO_ELIGIBLE by the
policy engine AND (b) explicitly present in the allowlist. The allowlist is a
persisted, audited store — promote/demote it with promote.py, not by editing
this file or its env var. `auto_execute_allowlist` below is consulted ONLY to
seed that store the first time it's created (so an existing deployment isn't
silently reset to empty); once the store file exists, this env var is ignored.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_set(name: str) -> frozenset[str]:
    raw = os.getenv(name, "")
    return frozenset(x.strip() for x in raw.split(",") if x.strip())


@dataclass(frozen=True)
class Settings:
    # --- Safety controls (fail safe) ---
    dry_run: bool = True
    kill_switch: bool = False
    # First-run seed only — see the module docstring. Live state lives in
    # AllowlistStore at allowlist_store_path; manage it with promote.py.
    auto_execute_allowlist: frozenset[str] = field(default_factory=frozenset)

    # Findings at or above this GuardDuty severity are eligible for
    # autonomous containment at all; below it, the platform only alerts.
    min_severity_for_containment: float = 4.0

    # --- AWS ---
    aws_region: str = "us-east-1"
    # Name of the pre-provisioned, deny-all quarantine security group used for
    # EC2 isolation. Created once by ops, referenced here.
    quarantine_security_group_id: str = ""
    # Optional SQS endpoint override. Empty = the real AWS endpoint. Set it to
    # point the SQS ingestion at a local emulator (moto server / ElasticMQ) for
    # the testbed, or at a VPC/PrivateLink SQS endpoint in production. This is
    # the one knob that lets the *live* ingestion path run with no AWS account.
    sqs_endpoint_url: str = ""
    # SQS long-poll wait (seconds). 20 (the AWS max) is the right production
    # default — fewer empty receives, lower cost. Lower it for fast shutdown
    # responsiveness (an in-flight long-poll can't be interrupted by the stop
    # signal, so this bounds shutdown latency) — the testbed/demo use ~2.
    sqs_wait_seconds: int = 20

    # --- Kubernetes ---
    # Empty kubeconfig_path uses the default resolution (KUBECONFIG / ~/.kube/config
    # / in-cluster). Empty context uses the current-context.
    kubeconfig_path: str = ""
    kube_context: str = ""

    # --- Audit, approvals & governance ---
    audit_log_path: str = "aegis_audit.jsonl"
    approval_store_path: str = "aegis_approvals.json"
    allowlist_store_path: str = "aegis_allowlist.json"

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            dry_run=_env_bool("AEGIS_DRY_RUN", True),
            kill_switch=_env_bool("AEGIS_KILL_SWITCH", False),
            auto_execute_allowlist=_env_set("AEGIS_AUTO_EXECUTE_ALLOWLIST"),
            min_severity_for_containment=float(
                os.getenv("AEGIS_MIN_SEVERITY", "4.0")
            ),
            aws_region=os.getenv("AWS_REGION", "us-east-1"),
            quarantine_security_group_id=os.getenv("AEGIS_QUARANTINE_SG_ID", ""),
            sqs_endpoint_url=os.getenv("AEGIS_SQS_ENDPOINT_URL", ""),
            sqs_wait_seconds=int(os.getenv("AEGIS_SQS_WAIT_SECONDS", "20")),
            kubeconfig_path=os.getenv("AEGIS_KUBECONFIG", ""),
            kube_context=os.getenv("AEGIS_KUBE_CONTEXT", ""),
            audit_log_path=os.getenv("AEGIS_AUDIT_PATH", "aegis_audit.jsonl"),
            approval_store_path=os.getenv("AEGIS_APPROVAL_PATH", "aegis_approvals.json"),
            allowlist_store_path=os.getenv("AEGIS_ALLOWLIST_PATH", "aegis_allowlist.json"),
        )
