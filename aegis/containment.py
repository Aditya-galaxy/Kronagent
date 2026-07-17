"""
Containment executor — the layer that actually touches AWS.

Design principle: the *plan* (the exact API calls that would be made, plus the
precise rollback) is computed for every action, always, and recorded — even
when the action is not executed. Execution happens only when the policy engine
returned `auto_execute` AND the global dry_run flag is off. This means:

  * dry-run and approval-pending actions still produce a fully concrete,
    auditable plan (no hand-waving), and
  * the exact reversal is captured at execution time, so rollback is real.

boto3 is imported lazily and only touched on real execution, so the whole
pipeline runs and is testable with no AWS credentials in dry-run mode.
"""

from __future__ import annotations

import asyncio
import json

from .config import Settings
from .schemas import ActionClass, ActionOutcome, PolicyDecision, ProposedAction

_DENY_ALL_POLICY = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]},
    separators=(",", ":"),
)


class ContainmentExecutor:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._ec2 = None
        self._iam = None

    # --- lazy boto3 clients (only created on real execution) ---
    def _ec2_client(self):
        if self._ec2 is None:
            import boto3  # local import: not needed for dry-run
            self._ec2 = boto3.client("ec2", region_name=self._settings.aws_region)
        return self._ec2

    def _iam_client(self):
        if self._iam is None:
            import boto3
            self._iam = boto3.client("iam", region_name=self._settings.aws_region)
        return self._iam

    async def execute(self, action: ProposedAction, decision: PolicyDecision) -> ActionOutcome:
        """Compute the plan; execute only if authorized and not in dry-run."""
        api_calls, rollback_hint, detail = self._plan(action)

        if decision.disposition == "blocked":
            return ActionOutcome(
                action_class=action.action_class, target=action.target,
                executed=False, dry_run=self._settings.dry_run,
                detail=f"BLOCKED — {decision.reason}", rollback_hint=rollback_hint,
                api_calls=api_calls,
            )

        if decision.disposition == "requires_approval":
            return ActionOutcome(
                action_class=action.action_class, target=action.target,
                executed=False, dry_run=self._settings.dry_run,
                detail=f"AWAITING APPROVAL — {decision.reason}. Plan ready to run on approval.",
                rollback_hint=rollback_hint, api_calls=api_calls,
            )

        # disposition == auto_execute
        if self._settings.dry_run:
            return ActionOutcome(
                action_class=action.action_class, target=action.target,
                executed=False, dry_run=True,
                detail=f"DRY-RUN — would auto-execute: {detail}",
                rollback_hint=rollback_hint, api_calls=api_calls,
            )

        # Real execution.
        try:
            executed_detail, executed_rollback = await self._perform(action)
            return ActionOutcome(
                action_class=action.action_class, target=action.target,
                executed=True, dry_run=False,
                detail=f"EXECUTED — {executed_detail}",
                rollback_hint=executed_rollback or rollback_hint, api_calls=api_calls,
            )
        except Exception as exc:  # noqa: BLE001 - surface execution failures, never crash
            return ActionOutcome(
                action_class=action.action_class, target=action.target,
                executed=False, dry_run=False,
                detail=f"EXECUTION FAILED — {type(exc).__name__}: {exc}",
                rollback_hint=rollback_hint, api_calls=api_calls,
                error=str(exc),
            )

    # ------------------------------------------------------------------ #
    # Planning — pure, no AWS. Returns (api_calls, rollback_hint, detail).
    # ------------------------------------------------------------------ #
    def _plan(self, action: ProposedAction) -> tuple[list[str], str, str]:
        ac = action.action_class
        t = action.target

        if ac == ActionClass.DISABLE_ACCESS_KEY:
            user = action.parameters.get("user_name", "")
            return (
                [f"iam.update_access_key(UserName='{user}', AccessKeyId='{t}', Status='Inactive')"],
                f"iam.update_access_key(UserName='{user}', AccessKeyId='{t}', Status='Active')",
                f"deactivate access key {t}",
            )
        if ac == ActionClass.ATTACH_DENY_ALL_TO_PRINCIPAL:
            return (
                [f"iam.put_user_policy(UserName='{t}', PolicyName='aegis-quarantine-deny-all', PolicyDocument=<deny-all>)"],
                f"iam.delete_user_policy(UserName='{t}', PolicyName='aegis-quarantine-deny-all')",
                f"attach deny-all inline policy to user {t}",
            )
        if ac == ActionClass.ISOLATE_INSTANCE_SG:
            sg = self._settings.quarantine_security_group_id or "<AEGIS_QUARANTINE_SG_ID unset>"
            return (
                [
                    f"ec2.describe_instances(InstanceIds=['{t}'])  # capture original SGs for rollback",
                    f"ec2.modify_instance_attribute(InstanceId='{t}', Groups=['{sg}'])",
                ],
                f"ec2.modify_instance_attribute(InstanceId='{t}', Groups=<original SGs captured at execution>)",
                f"isolate instance {t} into quarantine SG {sg}",
            )
        if ac == ActionClass.BLOCK_IP:
            return (
                [f"ec2.create_network_acl_entry(quarantine NACL, deny {t}/32, ingress+egress)"],
                f"ec2.delete_network_acl_entry(quarantine NACL, the deny rule for {t}/32)",
                f"block remote IP {t} at the quarantine NACL",
            )
        if ac == ActionClass.REVOKE_ROLE_SESSIONS:
            return (
                [f"iam.put_role_policy(RoleName='{t}', PolicyName='aegis-revoke-sessions', <deny before now>)"],
                f"iam.delete_role_policy(RoleName='{t}', PolicyName='aegis-revoke-sessions')",
                f"revoke active sessions for role {t}",
            )
        if ac == ActionClass.TERMINATE_INSTANCE:
            return (
                [f"ec2.terminate_instances(InstanceIds=['{t}'])"],
                "IRREVERSIBLE — instance cannot be un-terminated; restore from AMI/snapshot",
                f"terminate instance {t}",
            )
        return ([f"# no planner for {ac.value}"], "unknown", f"unhandled action {ac.value}")

    # ------------------------------------------------------------------ #
    # Execution — real boto3 calls. Returns (detail, rollback_hint).
    # boto3 calls are sync; run them off the event loop.
    # ------------------------------------------------------------------ #
    async def _perform(self, action: ProposedAction) -> tuple[str, str]:
        return await asyncio.to_thread(self._perform_sync, action)

    def _perform_sync(self, action: ProposedAction) -> tuple[str, str]:
        ac = action.action_class
        t = action.target

        if ac == ActionClass.DISABLE_ACCESS_KEY:
            user = action.parameters.get("user_name", "")
            self._iam_client().update_access_key(UserName=user, AccessKeyId=t, Status="Inactive")
            return (f"access key {t} set Inactive",
                    f"iam.update_access_key(UserName='{user}', AccessKeyId='{t}', Status='Active')")

        if ac == ActionClass.ATTACH_DENY_ALL_TO_PRINCIPAL:
            self._iam_client().put_user_policy(
                UserName=t, PolicyName="aegis-quarantine-deny-all", PolicyDocument=_DENY_ALL_POLICY
            )
            return (f"deny-all policy attached to {t}",
                    f"iam.delete_user_policy(UserName='{t}', PolicyName='aegis-quarantine-deny-all')")

        if ac == ActionClass.ISOLATE_INSTANCE_SG:
            sg = self._settings.quarantine_security_group_id
            if not sg:
                raise RuntimeError("AEGIS_QUARANTINE_SG_ID is not configured")
            ec2 = self._ec2_client()
            # Capture original SGs so the rollback is exact.
            desc = ec2.describe_instances(InstanceIds=[t])
            original = [
                g["GroupId"]
                for r in desc["Reservations"] for i in r["Instances"]
                for g in i.get("SecurityGroups", [])
            ]
            ec2.modify_instance_attribute(InstanceId=t, Groups=[sg])
            return (f"instance {t} moved to quarantine SG {sg} (was {original})",
                    f"ec2.modify_instance_attribute(InstanceId='{t}', Groups={original})")

        if ac == ActionClass.TERMINATE_INSTANCE:
            self._ec2_client().terminate_instances(InstanceIds=[t])
            return (f"instance {t} termination requested",
                    "IRREVERSIBLE — restore from AMI/snapshot")

        # BLOCK_IP / REVOKE_ROLE_SESSIONS require pre-provisioned quarantine
        # NACL / role-policy plumbing; wire to your account specifics before
        # enabling real execution for these classes.
        raise NotImplementedError(f"real execution for {ac.value} not enabled in this slice")
