"""
Triage engine: fuse deterministic detection with LLM reasoning.

GuardDuty is the detector — it already decided *something* is wrong and assigned
a severity and finding type. This engine does two things:

  1. Deterministic action mapping (grounded, no LLM): from the finding's
     resource type and finding type, derive the concrete candidate containment
     actions, with targets read straight from the parsed finding. This is what
     keeps containment aimed at the real compromised resource.

  2. LLM enrichment (Gemini, structured output): reason about the finding —
     categorize the threat, assign a response confidence, explain the
     rationale, note correlated signals. The LLM's judgment gates *whether* to
     proceed, never *which resource* is targeted.

If the LLM is unavailable, triage degrades to a deterministic verdict driven by
GuardDuty severity, so the pipeline never stalls waiting on the model.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from .llm import GeminiTriageClient, LLMUnavailableError
from .schemas import (
    ActionClass,
    GuardDutyFinding,
    ProposedAction,
    TriageVerdict,
)

_SYSTEM = (
    "You are a senior cloud SOC analyst reviewing a confirmed Amazon GuardDuty "
    "finding. GuardDuty has already detected suspicious activity; your job is to "
    "reason about it: categorize the threat, judge how confident you are that "
    "autonomous containment is warranted, and explain why. Be conservative — "
    "reserve high confidence for unambiguous evidence. Respond ONLY with the "
    "required JSON object."
)


class _LLMTriageOutput(BaseModel):
    """Schema the LLM must fill. Deliberately excludes any target/resource id —
    targets are never taken from model output."""

    is_actionable_threat: bool = Field(
        description="True if this finding warrants active containment (not just monitoring)."
    )
    threat_category: str = Field(description="Concise threat classification.")
    confidence: float = Field(ge=0.0, le=1.0)
    justification: str = Field(description="1-3 sentence rationale for the incident record.")
    correlated_signals: list[str] = Field(
        default_factory=list,
        description="Notable corroborating signals from the finding (IPs, API patterns, counts).",
    )


# Deterministic map: GuardDuty resource type -> candidate containment actions.
# Targets are filled from the finding, not chosen by the model.
def _candidate_actions(finding: GuardDutyFinding) -> list[ProposedAction]:
    actions: list[ProposedAction] = []
    res = finding.Resource
    rtype = (res.ResourceType or "").lower()

    if rtype == "accesskey" and res.AccessKeyDetails:
        akd = res.AccessKeyDetails
        if akd.AccessKeyId:
            actions.append(ProposedAction(
                action_class=ActionClass.DISABLE_ACCESS_KEY,
                target=akd.AccessKeyId,
                rationale="Deactivate the compromised access key to stop credential abuse.",
                parameters={"user_name": akd.UserName or ""},
            ))
        if akd.UserName:
            actions.append(ProposedAction(
                action_class=ActionClass.ATTACH_DENY_ALL_TO_PRINCIPAL,
                target=akd.UserName,
                rationale="Attach an explicit deny-all policy to halt all further API activity by the principal.",
            ))

    elif rtype == "instance" and res.InstanceDetails and res.InstanceDetails.InstanceId:
        iid = res.InstanceDetails.InstanceId
        actions.append(ProposedAction(
            action_class=ActionClass.ISOLATE_INSTANCE_SG,
            target=iid,
            rationale="Swap the instance to a deny-all quarantine security group, preserving it for forensics.",
        ))
        actions.append(ProposedAction(
            action_class=ActionClass.TERMINATE_INSTANCE,
            target=iid,
            rationale="Terminate the instance if isolation is insufficient (destructive; approval-gated).",
        ))

    # If the finding carries a remote attacker IP, offer to block it regardless
    # of resource type.
    ip = finding.remote_ip
    if ip:
        actions.append(ProposedAction(
            action_class=ActionClass.BLOCK_IP,
            target=ip,
            rationale="Block the remote IP observed driving the malicious API activity.",
        ))

    return actions


class TriageEngine:
    def __init__(self, llm: GeminiTriageClient | None) -> None:
        self._llm = llm

    async def assess(self, finding: GuardDutyFinding) -> tuple[TriageVerdict, list[ProposedAction]]:
        candidates = _candidate_actions(finding)

        prompt = (
            "Review this GuardDuty finding.\n\n"
            f"Finding ID: {finding.Id}\n"
            f"Type: {finding.Type}\n"
            f"Severity (GuardDuty scale): {finding.Severity} ({finding.severity_band})\n"
            f"Title: {finding.Title or 'n/a'}\n"
            f"Description: {finding.Description or 'n/a'}\n"
            f"Resource type: {finding.Resource.ResourceType or 'n/a'}\n"
            f"Remote IP: {finding.remote_ip or 'n/a'}\n"
            f"Repeat count: {finding.Service.Count if finding.Service else 'n/a'}\n"
        )

        if self._llm is not None:
            try:
                out = await self._llm.structured(
                    system=_SYSTEM, prompt=prompt, schema=_LLMTriageOutput
                )
                verdict = TriageVerdict(
                    finding_id=finding.Id,
                    is_actionable_threat=out.is_actionable_threat,
                    threat_category=out.threat_category,
                    confidence=out.confidence,
                    severity=finding.Severity,
                    justification=out.justification,
                    correlated_signals=out.correlated_signals,
                )
                return verdict, candidates
            except (LLMUnavailableError, Exception):  # noqa: BLE001 - fall back deterministically
                pass

        # Deterministic fallback: GuardDuty severity alone drives the verdict.
        verdict = TriageVerdict(
            finding_id=finding.Id,
            is_actionable_threat=finding.Severity >= 4.0,
            threat_category=finding.Type.split(":")[0] if ":" in finding.Type else finding.Type,
            confidence=min(1.0, finding.Severity / 8.9),
            severity=finding.Severity,
            justification=(
                "FALLBACK (LLM unavailable): verdict derived from GuardDuty severity "
                f"{finding.Severity} and finding type {finding.Type}."
            ),
            correlated_signals=[s for s in [finding.remote_ip] if s],
        )
        return verdict, candidates
