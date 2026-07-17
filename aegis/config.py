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

Graduated autonomy is expressed by `auto_execute_allowlist`: an action class
executes automatically ONLY if it is (a) classified AUTO_ELIGIBLE by the
policy engine AND (b) explicitly present in this allowlist. The allowlist
starts empty — operators add action classes one at a time as each earns
trust. Everything else routes to human approval.
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
    # Action classes (by value of ActionClass) approved for autonomous
    # execution. Empty = every action requires human approval. Earn-trust:
    # operators grow this list deliberately.
    auto_execute_allowlist: frozenset[str] = field(default_factory=frozenset)

    # Findings at or above this GuardDuty severity are eligible for
    # autonomous containment at all; below it, the platform only alerts.
    min_severity_for_containment: float = 4.0

    # --- AWS ---
    aws_region: str = "us-east-1"
    # Name of the pre-provisioned, deny-all quarantine security group used for
    # EC2 isolation. Created once by ops, referenced here.
    quarantine_security_group_id: str = ""

    # --- Audit & approvals ---
    audit_log_path: str = "aegis_audit.jsonl"
    approval_store_path: str = "aegis_approvals.json"

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
            audit_log_path=os.getenv("AEGIS_AUDIT_PATH", "aegis_audit.jsonl"),
            approval_store_path=os.getenv("AEGIS_APPROVAL_PATH", "aegis_approvals.json"),
        )
