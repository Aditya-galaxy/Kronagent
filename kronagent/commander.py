"""
Incident Commander Agent — the roster's "Orchestrator / Planner Agent".

Naming: the architecture doc calls this the "Orchestrator Agent," but the
codebase already has a deterministic `Orchestrator` class that sequences the
pipeline (ingest -> triage -> policy -> containment -> audit). To avoid a
collision — and because the two are genuinely different things — the LLM
synthesis/escalation agent is named the Incident Commander (real SOC term for
the role that owns an incident: pulls the specialists' findings together,
declares severity, and decides who to wake up).

  * The deterministic `Orchestrator` decides the *control flow* (what stage
    runs next) and is safety-critical, so it stays code.
  * The `IncidentCommanderAgent` decides the *human-facing judgment* (how bad
    is this, as one story, and does someone need to be paged now) and is
    advisory, so it's an LLM.

Per agent-team-architecture.md §3, this is only worth building once there are
≥2 intelligence agents to synthesize — which there now are (threat-intel +
correlation). Its job is to turn three separate structured assessments
(triage verdict, ATT&CK mapping, campaign correlation) into ONE incident
narrative plus an escalation decision, so a human sees a coherent "here is
what is happening and whether to act now" instead of three disconnected
enrichments.

Design constraints (identical safety envelope to the other intelligence
agents — non-negotiable):
  * PURELY ADVISORY. Zero execution authority. The commander never selects a
    target, never picks an action class, never changes a policy decision. Its
    escalation flag pages a human; it does not — and cannot — cause a
    containment action. The deterministic policy gate is unaffected.
  * Reasons over the already-NORMALIZED, already-ENRICHED assessments produced
    by the other agents — NOT raw telemetry. This is the lowest injection-risk
    agent in the team: its input is other agents' structured output, not
    attacker-influenced data.
  * The output schema structurally cannot express a containment target or
    action class (asserted in tests), so it literally cannot emit one.
  * Degrades gracefully: no LLM means no synthesis and the pipeline proceeds
    unchanged. Escalation defaults to the conservative "not escalated" —
    the human queue still holds every approval regardless.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from .correlation import CorrelationAssessment
from .intel import ThreatIntelAssessment
from .llm import GeminiTriageClient, LLMUnavailableError
from .model import Finding
from .schemas import TriageVerdict

# Advisory priority bands. P1 = wake someone now; P4 = record and move on.
Priority = Literal["P1", "P2", "P3", "P4"]

_SYSTEM = (
    "You are the incident commander in a security operations center. Several "
    "specialist analysts have already assessed a confirmed threat: a triage "
    "analyst graded it, a threat-intelligence analyst mapped it to MITRE ATT&CK, "
    "and an investigation analyst checked whether it is part of a larger campaign. "
    "Your job is to synthesize their findings into a single incident assessment: a "
    "clear narrative of what is happening, an advisory priority (P1 most urgent to "
    "P4 least), and a decision on whether a human responder must be paged right now. "
    "Weigh campaign correlation heavily — a finding that is one stage of an active "
    "multi-stage campaign is more urgent than an isolated alert of the same "
    "severity. Your assessment is advisory: it informs and prioritizes the human "
    "response, it does NOT choose or authorize any containment action. Respond ONLY "
    "with the required JSON object."
)


class IncidentAssessment(BaseModel):
    """The internal, provider-neutral incident-command record. `available=False`
    means the LLM couldn't synthesize; escalation then defaults to False (safe:
    the approval queue still holds everything, nothing is auto-paged wrongly)."""

    finding_id: str
    available: bool
    incident_narrative: str = ""          # one coherent story across all specialists
    priority: str = ""                    # P1..P4 advisory band
    escalate_to_human_now: bool = False   # should a responder be paged immediately
    escalation_reason: str = ""           # why (or why not)
    key_risks: list[str] = Field(default_factory=list)      # what's at stake
    recommended_posture: str = ""         # advisory prose — NOT an action selection


class _LLMCommanderOutput(BaseModel):
    """Schema the model fills. By construction there is no target/action/
    resource/command field — the incident commander cannot express a containment
    decision, only a human-facing assessment and an escalation signal."""

    incident_narrative: str = Field(
        description="One coherent paragraph synthesizing the specialists' findings into what is happening."
    )
    priority: Priority = Field(
        description="Advisory urgency band: P1 (page now) to P4 (record only)."
    )
    escalate_to_human_now: bool = Field(
        description="True if a human responder should be paged immediately, not just queued."
    )
    escalation_reason: str = Field(
        description="Brief justification for the escalation decision."
    )
    key_risks: list[str] = Field(
        default_factory=list,
        description="The concrete things at stake if this is not contained (data, blast radius, progression).",
    )
    recommended_posture: str = Field(
        description="Advisory prose on the appropriate response posture. NOT a specific command or resource."
    )


def _fmt_intel(intel: ThreatIntelAssessment) -> str:
    if not intel.available:
        return "  (threat-intel unavailable)"
    techniques = ", ".join(
        f"{t.technique_id} {t.technique_name} [{t.tactic}]"
        for t in intel.mitre_techniques if t.technique_id
    ) or "none mapped"
    return (
        f"  ATT&CK techniques: {techniques}\n"
        f"  Attack lifecycle stage: {intel.attack_lifecycle_stage or 'n/a'}\n"
        f"  IOC assessment: {intel.ioc_assessment or 'n/a'}\n"
        f"  Summary: {intel.intel_summary or 'n/a'}"
    )


def _fmt_correlation(corr: CorrelationAssessment) -> str:
    if not corr.available:
        return "  (correlation unavailable — no prior findings, or first in window)"
    if not corr.part_of_campaign:
        return "  No campaign link found against recent prior findings (isolated alert)."
    return (
        f"  PART OF A CAMPAIGN. Related prior findings: {corr.related_finding_ids}\n"
        f"  Campaign narrative: {corr.campaign_narrative or 'n/a'}\n"
        f"  Summary: {corr.correlation_summary or 'n/a'}"
    )


class IncidentCommanderAgent:
    def __init__(self, llm: GeminiTriageClient | None) -> None:
        self._llm = llm

    async def assess(
        self,
        finding: Finding,
        verdict: TriageVerdict,
        intel: ThreatIntelAssessment,
        correlation: CorrelationAssessment,
    ) -> IncidentAssessment:
        if self._llm is None:
            return IncidentAssessment(finding_id=finding.finding_id, available=False)

        from .sanitization import sanitize_finding
        sanitized = sanitize_finding(finding)

        prompt = (
            "Synthesize the specialist assessments into one incident assessment.\n\n"
            "=== Finding ===\n"
            f"Provider: {sanitized.provider}\n"
            f"Finding ID: {sanitized.finding_id}\n"
            f"Type: {sanitized.finding_type}\n"
            f"Severity (0-10 normalized): {sanitized.severity} ({sanitized.severity_band})\n"
            f"Title: {sanitized.title or 'n/a'}\n\n"
            "=== Triage analyst ===\n"
            f"  Actionable threat: {verdict.is_actionable_threat}\n"
            f"  Category: {verdict.threat_category}\n"
            f"  Confidence: {verdict.confidence:.2f}\n"
            f"  Justification: {verdict.justification}\n\n"
            "=== Threat-intelligence analyst ===\n"
            f"{_fmt_intel(intel)}\n\n"
            "=== Investigation / correlation analyst ===\n"
            f"{_fmt_correlation(correlation)}\n"
        )

        try:
            out = await self._llm.structured(
                system=_SYSTEM, prompt=prompt, schema=_LLMCommanderOutput
            )
        except (LLMUnavailableError, Exception):  # noqa: BLE001 - synthesis is best-effort
            return IncidentAssessment(finding_id=finding.finding_id, available=False)

        return IncidentAssessment(
            finding_id=finding.finding_id,
            available=True,
            incident_narrative=out.incident_narrative,
            priority=out.priority,
            escalate_to_human_now=out.escalate_to_human_now,
            escalation_reason=out.escalation_reason,
            key_risks=out.key_risks,
            recommended_posture=out.recommended_posture,
        )
