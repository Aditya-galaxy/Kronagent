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

import json
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
    # ID of the pre-provisioned, quarantine network ACL used for blocking IPs.
    quarantine_nacl_id: str = ""
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
    # Operator registry for identity + RBAC. Empty (default) = unauthenticated
    # mode: approvals/promotions use free-text --by and are audited as
    # identity_verified=false. Point this at a registry (see operators.py /
    # aegis.identity) to enforce authenticated, authorized, non-repudiable
    # operator decisions.
    operator_registry_path: str = ""
    db_path: str = ""
    max_workers: int = 1
    kms_key_id: str = ""
    require_agent_signatures: bool = False
    require_view_auth: bool = False

    # --- Behavioral-trajectory guard (the automatic kill switch) ---
    # Aegis is itself an autonomous agent system holding production credentials.
    # This guard watches Aegis's OWN action stream — not the telemetry it
    # ingests — and latches a halt on a runaway burst of autonomous executions
    # or repeated out-of-scope targeting (an action-redirection attack). It is
    # deterministic (no LLM), so the backstop itself cannot be prompt-injected.
    # On by default; scope enforcement blocks any action aimed at a resource not
    # implicated by its own finding.
    trajectory_guard_enabled: bool = True
    trajectory_window_seconds: float = 60.0
    trajectory_max_auto_executions: int = 25
    trajectory_max_scope_violations: int = 3
    trajectory_enforce_scope: bool = True

    # --- OIDC / SAML SSO ---
    oidc_issuer: str = ""
    oidc_audience: str = ""
    oidc_jwks_uri: str = ""
    oidc_verify_signature: bool = True
    oidc_roles_claim: str = "roles"

    # --- ChatOps (Slack / Teams) ---
    slack_bot_token: str = ""
    slack_signing_secret: str = ""
    slack_channel_id: str = ""
    slack_user_mapping: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> "Settings":
        approval_path = os.getenv("AEGIS_APPROVAL_PATH", "aegis_approvals.json")
        db_path = os.getenv("AEGIS_DB_PATH", "")
        if not db_path and approval_path.endswith(".db"):
            db_path = approval_path

        slack_user_mapping_str = os.getenv("AEGIS_SLACK_USER_MAPPING", "")
        slack_user_mapping = {}
        if slack_user_mapping_str:
            try:
                slack_user_mapping = json.loads(slack_user_mapping_str)
            except json.JSONDecodeError:
                pass

        return cls(
            dry_run=_env_bool("AEGIS_DRY_RUN", True),
            kill_switch=_env_bool("AEGIS_KILL_SWITCH", False),
            auto_execute_allowlist=_env_set("AEGIS_AUTO_EXECUTE_ALLOWLIST"),
            min_severity_for_containment=float(
                os.getenv("AEGIS_MIN_SEVERITY", "4.0")
            ),
            aws_region=os.getenv("AWS_REGION", "us-east-1"),
            quarantine_security_group_id=os.getenv("AEGIS_QUARANTINE_SG_ID", ""),
            quarantine_nacl_id=os.getenv("AEGIS_QUARANTINE_NACL_ID", ""),
            sqs_endpoint_url=os.getenv("AEGIS_SQS_ENDPOINT_URL", ""),
            sqs_wait_seconds=int(os.getenv("AEGIS_SQS_WAIT_SECONDS", "20")),
            kubeconfig_path=os.getenv("AEGIS_KUBECONFIG", ""),
            kube_context=os.getenv("AEGIS_KUBE_CONTEXT", ""),
            audit_log_path=os.getenv("AEGIS_AUDIT_PATH", "aegis_audit.jsonl"),
            approval_store_path=approval_path,
            allowlist_store_path=os.getenv("AEGIS_ALLOWLIST_PATH", "aegis_allowlist.json"),
            operator_registry_path=os.getenv("AEGIS_OPERATOR_REGISTRY", ""),
            db_path=db_path,
            max_workers=int(os.getenv("AEGIS_MAX_WORKERS", "1")),
            kms_key_id=os.getenv("AEGIS_KMS_KEY_ID", ""),
            require_agent_signatures=_env_bool("AEGIS_REQUIRE_AGENT_SIGNATURES", False),
            require_view_auth=_env_bool("AEGIS_REQUIRE_VIEW_AUTH", False),
            trajectory_guard_enabled=_env_bool("AEGIS_TRAJECTORY_GUARD", True),
            trajectory_window_seconds=float(os.getenv("AEGIS_TRAJECTORY_WINDOW_SECONDS", "60")),
            trajectory_max_auto_executions=int(os.getenv("AEGIS_TRAJECTORY_MAX_AUTO", "25")),
            trajectory_max_scope_violations=int(os.getenv("AEGIS_TRAJECTORY_MAX_SCOPE_VIOLATIONS", "3")),
            trajectory_enforce_scope=_env_bool("AEGIS_TRAJECTORY_ENFORCE_SCOPE", True),
            oidc_issuer=os.getenv("AEGIS_OIDC_ISSUER", ""),
            oidc_audience=os.getenv("AEGIS_OIDC_AUDIENCE", ""),
            oidc_jwks_uri=os.getenv("AEGIS_OIDC_JWKS_URI", ""),
            oidc_verify_signature=_env_bool("AEGIS_OIDC_VERIFY_SIGNATURE", True),
            oidc_roles_claim=os.getenv("AEGIS_OIDC_ROLES_CLAIM", "roles"),
            slack_bot_token=os.getenv("AEGIS_SLACK_BOT_TOKEN", ""),
            slack_signing_secret=os.getenv("AEGIS_SLACK_SIGNING_SECRET", ""),
            slack_channel_id=os.getenv("AEGIS_SLACK_CHANNEL_ID", ""),
            slack_user_mapping=slack_user_mapping,
        )
