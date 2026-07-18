"""
AWS provider: GuardDuty normalization + IAM/EC2 containment.

Owns everything vendor-specific about AWS:
  * the GuardDuty finding wire schema (tolerant of unmodeled fields),
  * normalize_guardduty(): GuardDuty finding dict -> provider-neutral Finding,
  * plan_aws_actions(): Finding -> candidate ProposedActions (targets read from
    the finding, never from the LLM),
  * AwsContainmentAdapter: ProposedAction -> concrete boto3 plan / execution.

boto3 is imported lazily inside the adapter so the module (and the whole
pipeline) imports and runs in dry-run with no AWS installed.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from ..model import Finding, ResourceRef
from ..schemas import ActionClass, ProposedAction

PROVIDER = "aws"

_DENY_ALL_POLICY = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]},
    separators=(",", ":"),
)


# --------------------------------------------------------------------------- #
# GuardDuty wire schema (real-schema subset, tolerant of extra fields).
# Nested class names deliberately differ from the JSON field names they type —
# Pydantic degrades a field's annotation to None if a field name shadows a
# same-named class in scope, so field name and type name must never match.
# --------------------------------------------------------------------------- #

class RemoteIp(BaseModel):
    model_config = ConfigDict(extra="allow")
    IpAddressV4: Optional[str] = None
    Organization: Optional[dict[str, Any]] = None
    Country: Optional[dict[str, Any]] = None


class ApiCallAction(BaseModel):
    model_config = ConfigDict(extra="allow")
    Api: Optional[str] = None
    CallerType: Optional[str] = None
    RemoteIpDetails: Optional[RemoteIp] = None


class FindingAction(BaseModel):
    model_config = ConfigDict(extra="allow")
    ActionType: Optional[str] = None
    AwsApiCallAction: Optional[ApiCallAction] = None


class ServiceInfo(BaseModel):
    model_config = ConfigDict(extra="allow")
    Action: Optional[FindingAction] = None
    Count: Optional[int] = None
    ResourceRole: Optional[str] = None
    EventFirstSeen: Optional[str] = None
    EventLastSeen: Optional[str] = None
    Archived: Optional[bool] = None


class AccessKey(BaseModel):
    model_config = ConfigDict(extra="allow")
    AccessKeyId: Optional[str] = None
    UserName: Optional[str] = None
    UserType: Optional[str] = None


class InstanceInfo(BaseModel):
    model_config = ConfigDict(extra="allow")
    InstanceId: Optional[str] = None
    NetworkInterfaces: Optional[list[dict[str, Any]]] = None


class ResourceBlock(BaseModel):
    model_config = ConfigDict(extra="allow")
    ResourceType: Optional[str] = None
    AccessKeyDetails: Optional[AccessKey] = None
    InstanceDetails: Optional[InstanceInfo] = None
    S3BucketDetails: Optional[list[dict[str, Any]]] = None


class GuardDutyFinding(BaseModel):
    """Subset of the GuardDuty finding schema, tolerant of unmodeled fields."""

    model_config = ConfigDict(extra="allow")

    Id: str
    AccountId: Optional[str] = None
    Region: Optional[str] = None
    Type: str
    Severity: float  # GuardDuty scale (0.1–8.9+); higher is worse
    Title: Optional[str] = None
    Description: Optional[str] = None
    CreatedAt: Optional[str] = None
    UpdatedAt: Optional[str] = None
    Resource: ResourceBlock = Field(default_factory=ResourceBlock)
    Service: ServiceInfo = Field(default_factory=ServiceInfo)

    @property
    def remote_ip(self) -> Optional[str]:
        act = self.Service.Action
        if act and act.AwsApiCallAction and act.AwsApiCallAction.RemoteIpDetails:
            return act.AwsApiCallAction.RemoteIpDetails.IpAddressV4
        return None


# --------------------------------------------------------------------------- #
# Normalization: GuardDuty dict -> provider-neutral Finding
# --------------------------------------------------------------------------- #

def normalize_guardduty(payload: dict) -> Finding:
    gd = GuardDutyFinding.model_validate(payload)
    resources: list[ResourceRef] = []
    res = gd.Resource
    rtype = (res.ResourceType or "").lower()

    if rtype == "accesskey" and res.AccessKeyDetails:
        akd = res.AccessKeyDetails
        if akd.AccessKeyId:
            resources.append(ResourceRef(
                kind="aws.iam.access_key", id=akd.AccessKeyId,
                attributes={"user_name": akd.UserName or ""},
            ))
        if akd.UserName:
            resources.append(ResourceRef(
                kind="aws.iam.user", id=akd.UserName, attributes={},
            ))
    elif rtype == "instance" and res.InstanceDetails and res.InstanceDetails.InstanceId:
        resources.append(ResourceRef(
            kind="aws.ec2.instance", id=res.InstanceDetails.InstanceId, attributes={},
        ))

    return Finding(
        provider=PROVIDER,
        finding_id=gd.Id,
        finding_type=gd.Type,
        severity=gd.Severity,  # GuardDuty is already ~0-9; no rescale needed
        title=gd.Title or "",
        description=gd.Description or "",
        resources=resources,
        remote_ip=gd.remote_ip,
        raw=payload,
    )


# --------------------------------------------------------------------------- #
# Planning: Finding -> candidate ProposedActions. Targets come from the
# normalized resources, never from model output.
# --------------------------------------------------------------------------- #

def plan_aws_actions(finding: Finding) -> list[ProposedAction]:
    actions: list[ProposedAction] = []

    for r in finding.resources:
        if r.kind == "aws.iam.access_key":
            actions.append(ProposedAction(
                provider=PROVIDER, action_class=ActionClass.DISABLE_ACCESS_KEY,
                target=r.id,
                rationale="Deactivate the compromised access key to stop credential abuse.",
                parameters={"user_name": r.attributes.get("user_name", "")},
            ))
        elif r.kind == "aws.iam.user":
            actions.append(ProposedAction(
                provider=PROVIDER, action_class=ActionClass.ATTACH_DENY_ALL_TO_PRINCIPAL,
                target=r.id,
                rationale="Attach an explicit deny-all policy to halt all further API activity by the principal.",
            ))
        elif r.kind == "aws.ec2.instance":
            actions.append(ProposedAction(
                provider=PROVIDER, action_class=ActionClass.ISOLATE_INSTANCE_SG,
                target=r.id,
                rationale="Swap the instance to a deny-all quarantine security group, preserving it for forensics.",
            ))
            actions.append(ProposedAction(
                provider=PROVIDER, action_class=ActionClass.TERMINATE_INSTANCE,
                target=r.id,
                rationale="Terminate the instance if isolation is insufficient (destructive; approval-gated).",
            ))

    if finding.remote_ip:
        actions.append(ProposedAction(
            provider=PROVIDER, action_class=ActionClass.BLOCK_IP,
            target=finding.remote_ip,
            rationale="Block the remote IP observed driving the malicious API activity.",
        ))

    return actions


# --------------------------------------------------------------------------- #
# Containment adapter: plan (pure) + perform (real boto3).
# --------------------------------------------------------------------------- #

class AwsContainmentAdapter:
    provider = PROVIDER

    def __init__(self, *, region: str, quarantine_security_group_id: str = "") -> None:
        self._region = region
        self._quarantine_sg = quarantine_security_group_id
        self._ec2 = None
        self._iam = None

    def _ec2_client(self):
        if self._ec2 is None:
            import boto3
            self._ec2 = boto3.client("ec2", region_name=self._region)
        return self._ec2

    def _iam_client(self):
        if self._iam is None:
            import boto3
            self._iam = boto3.client("iam", region_name=self._region)
        return self._iam

    def plan(self, action: ProposedAction) -> tuple[list[str], str, str]:
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
            sg = self._quarantine_sg or "<AEGIS_QUARANTINE_SG_ID unset>"
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
        return ([f"# no AWS planner for {ac.value}"], "unknown", f"unhandled action {ac.value}")

    async def perform(self, action: ProposedAction) -> tuple[str, str]:
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
            if not self._quarantine_sg:
                raise RuntimeError("AEGIS_QUARANTINE_SG_ID is not configured")
            ec2 = self._ec2_client()
            desc = ec2.describe_instances(InstanceIds=[t])
            original = [
                g["GroupId"]
                for r in desc["Reservations"] for i in r["Instances"]
                for g in i.get("SecurityGroups", [])
            ]
            ec2.modify_instance_attribute(InstanceId=t, Groups=[self._quarantine_sg])
            return (f"instance {t} moved to quarantine SG {self._quarantine_sg} (was {original})",
                    f"ec2.modify_instance_attribute(InstanceId='{t}', Groups={original})")
        if ac == ActionClass.TERMINATE_INSTANCE:
            self._ec2_client().terminate_instances(InstanceIds=[t])
            return (f"instance {t} termination requested", "IRREVERSIBLE — restore from AMI/snapshot")
        raise NotImplementedError(f"real AWS execution for {ac.value} not enabled in this slice")
