"""
Typed contracts for the pipeline.

`GuardDutyFinding` models the subset of the real Amazon GuardDuty finding
schema the platform reasons over (extra fields are tolerated, so live findings
parse without loss). Everything downstream — triage verdict, proposed
containment actions, policy decisions, audit records — is a strict internal
model.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# GuardDuty finding (real-schema subset, tolerant of extra fields)
# --------------------------------------------------------------------------- #

# NOTE: nested class names are deliberately DIFFERENT from the JSON field names
# they're used for (e.g. field `RemoteIpDetails` has type `RemoteIp`). Pydantic
# resolves a field's type annotation in a namespace where the field name shadows
# a same-named class, silently degrading the type to None — so field name and
# type name must never match.

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

    # --- Convenience accessors used by triage/containment ---

    @property
    def severity_band(self) -> Literal["low", "medium", "high", "critical"]:
        s = self.Severity
        if s >= 9.0:
            return "critical"
        if s >= 7.0:
            return "high"
        if s >= 4.0:
            return "medium"
        return "low"

    @property
    def remote_ip(self) -> Optional[str]:
        act = self.Service.Action
        if act and act.AwsApiCallAction and act.AwsApiCallAction.RemoteIpDetails:
            return act.AwsApiCallAction.RemoteIpDetails.IpAddressV4
        return None


# --------------------------------------------------------------------------- #
# Internal pipeline types
# --------------------------------------------------------------------------- #

class ActionClass(str, Enum):
    """Every containment capability the platform has, as a stable identifier.
    Values double as the keys in the auto-execute allowlist."""

    DISABLE_ACCESS_KEY = "disable_access_key"
    ATTACH_DENY_ALL_TO_PRINCIPAL = "attach_deny_all_to_principal"
    ISOLATE_INSTANCE_SG = "isolate_instance_sg"
    TERMINATE_INSTANCE = "terminate_instance"
    BLOCK_IP = "block_ip"
    REVOKE_ROLE_SESSIONS = "revoke_role_sessions"


class BlastRadius(str, Enum):
    SINGLE_RESOURCE = "single_resource"  # affects exactly one principal/instance
    SUBNET = "subnet"                    # affects a subnet / shared NACL
    ACCOUNT = "account"                  # account-wide effect


class TriageVerdict(BaseModel):
    """Result of fusing GuardDuty's deterministic detection with LLM triage."""

    model_config = ConfigDict(frozen=True)

    finding_id: str
    is_actionable_threat: bool
    threat_category: str
    confidence: float = Field(ge=0.0, le=1.0)
    severity: float
    justification: str
    correlated_signals: list[str] = Field(default_factory=list)


class ProposedAction(BaseModel):
    """A single containment step the triage/response layer wants to take."""

    model_config = ConfigDict(frozen=True)

    action_class: ActionClass
    target: str                    # the concrete resource id / arn / ip
    rationale: str
    parameters: dict[str, Any] = Field(default_factory=dict)


class PolicyDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    action_class: ActionClass
    disposition: Literal["auto_execute", "requires_approval", "blocked"]
    reason: str
    reversible: bool
    blast_radius: BlastRadius


class ActionOutcome(BaseModel):
    model_config = ConfigDict(frozen=True)

    action_class: ActionClass
    target: str
    executed: bool           # False when dry-run or awaiting approval
    dry_run: bool
    detail: str
    rollback_hint: str       # exactly how to reverse this action
    api_calls: list[str] = Field(default_factory=list)  # the concrete calls made / planned
    error: Optional[str] = None


class AuditRecord(BaseModel):
    """One immutable audit entry. Hash-chained in the audit log."""

    model_config = ConfigDict(extra="allow")

    ts: str = Field(default_factory=utcnow_iso)
    finding_id: str
    stage: str               # "triage" | "policy" | "containment"
    payload: dict[str, Any]
