"""
Graduated-autonomy policy engine.

This is the gate between "the response layer proposed an action" and "the
platform is allowed to execute it autonomously." It is deliberately pure,
deterministic logic — no LLM, no I/O — so its decisions are auditable,
testable, and cannot be influenced by prompt injection in the telemetry.

Decision procedure for each proposed action:

  1. Kill switch on              -> blocked
  2. Below containment severity  -> blocked (alert-only)
  3. Look up the action class's intrinsic properties (reversible?, blast radius).
  4. An action is AUTO_ELIGIBLE iff it is reversible AND single-resource AND
     not in the intrinsically-destructive set.
  5. It actually auto-executes iff it is AUTO_ELIGIBLE **and** its class is in
     the operator-maintained auto_execute_allowlist (earn-trust).
  6. Otherwise -> requires_approval.

The allowlist is the earn-trust dial: it starts empty (everything needs a
human), and operators promote one action class at a time as it proves safe.
"""

from __future__ import annotations

from .config import Settings
from .schemas import ActionClass, BlastRadius, PolicyDecision, ProposedAction

# Intrinsic properties of each containment capability. This table is the
# security-reviewed classification of "how dangerous is this action" and is the
# single source of truth the auto/approval decision is derived from.
_ACTION_PROPERTIES: dict[ActionClass, dict] = {
    ActionClass.DISABLE_ACCESS_KEY: {
        "reversible": True,   # re-activate the key
        "blast_radius": BlastRadius.SINGLE_RESOURCE,
        "destructive": False,
    },
    ActionClass.ISOLATE_INSTANCE_SG: {
        "reversible": True,   # restore the instance's original security groups
        "blast_radius": BlastRadius.SINGLE_RESOURCE,
        "destructive": False,
    },
    ActionClass.BLOCK_IP: {
        "reversible": True,   # remove the deny rule from the quarantine group
        "blast_radius": BlastRadius.SINGLE_RESOURCE,
        "destructive": False,
    },
    ActionClass.ATTACH_DENY_ALL_TO_PRINCIPAL: {
        "reversible": True,   # detach the inline deny policy
        "blast_radius": BlastRadius.SINGLE_RESOURCE,
        "destructive": False,
    },
    ActionClass.REVOKE_ROLE_SESSIONS: {
        # Reversible in the sense that new sessions can be issued, but it
        # forcibly kills in-flight legitimate sessions too -> treat as
        # destructive so it never auto-executes.
        "reversible": True,
        "blast_radius": BlastRadius.SINGLE_RESOURCE,
        "destructive": True,
    },
    ActionClass.TERMINATE_INSTANCE: {
        "reversible": False,  # cannot un-terminate an instance
        "blast_radius": BlastRadius.SINGLE_RESOURCE,
        "destructive": True,
    },
}


class PolicyEngine:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def _properties(self, action_class: ActionClass) -> dict:
        # Unknown action classes default to the most restrictive posture.
        return _ACTION_PROPERTIES.get(
            action_class,
            {"reversible": False, "blast_radius": BlastRadius.ACCOUNT, "destructive": True},
        )

    def is_auto_eligible(self, action_class: ActionClass) -> bool:
        p = self._properties(action_class)
        return (
            p["reversible"]
            and p["blast_radius"] == BlastRadius.SINGLE_RESOURCE
            and not p["destructive"]
        )

    def decide(self, action: ProposedAction, *, severity: float) -> PolicyDecision:
        s = self._settings
        props = self._properties(action.action_class)
        reversible = props["reversible"]
        blast = props["blast_radius"]

        if s.kill_switch:
            return PolicyDecision(
                action_class=action.action_class,
                disposition="blocked",
                reason="kill switch engaged — all containment halted",
                reversible=reversible,
                blast_radius=blast,
            )

        if severity < s.min_severity_for_containment:
            return PolicyDecision(
                action_class=action.action_class,
                disposition="blocked",
                reason=(
                    f"severity {severity:.1f} below containment threshold "
                    f"{s.min_severity_for_containment:.1f} — alert only"
                ),
                reversible=reversible,
                blast_radius=blast,
            )

        auto_eligible = self.is_auto_eligible(action.action_class)
        allowlisted = action.action_class.value in s.auto_execute_allowlist

        if auto_eligible and allowlisted:
            return PolicyDecision(
                action_class=action.action_class,
                disposition="auto_execute",
                reason="reversible, single-resource, and operator-allowlisted for autonomy",
                reversible=reversible,
                blast_radius=blast,
            )

        if not auto_eligible:
            reason = "destructive or wide blast radius — human approval required"
        else:
            reason = "auto-eligible but not yet in the earn-trust allowlist — human approval required"

        return PolicyDecision(
            action_class=action.action_class,
            disposition="requires_approval",
            reason=reason,
            reversible=reversible,
            blast_radius=blast,
        )
