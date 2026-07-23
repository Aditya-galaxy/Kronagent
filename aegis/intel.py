"""
Threat Intelligence Agent — the first specialist beyond triage.

Where the triage agent answers "is this a real threat" (a yes/no gate), the
threat-intel agent answers "what IS this" — it maps the finding to MITRE ATT&CK
tactics/techniques, assesses the observed indicators of compromise, and places
the activity in the attack lifecycle. This is what upgrades an entry in the log
from "an alert" to "an analyst's assessment," and it enriches the context a human
sees when approving containment.

Design constraints (from agent-team-architecture.md — non-negotiable):
  * PURELY ADVISORY. This agent adds ZERO execution authority. Its output never
    touches a policy decision, never selects a containment target, never picks an
    action class. It only annotates the incident record and the approval context.
    So even a fully attacker-controlled response here cannot cause an action.
  * Reasons over the NORMALIZED finding, never raw telemetry — same
    prompt-injection discipline as triage.
  * Degrades gracefully: if the LLM is unavailable, enrichment is simply absent
    and the pipeline proceeds unchanged. Intelligence is a bonus, never a
    dependency.

Cost note: this runs only for findings triage already deemed actionable AND that
have candidate containment actions — i.e. the ones heading toward a human
decision, where enrichment has value. Most findings in a real stream are noise
and never reach this agent, so we don't pay per-finding intel cost on them. The
architecture permits running triage and intel in parallel; we sequence them
deliberately so intel cost is only incurred when it will actually inform a
decision.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from .llm import GeminiTriageClient, LLMUnavailableError
from .model import Finding

_SYSTEM = (
    "You are a cyber threat intelligence analyst. You receive a security finding "
    "that has already been confirmed as an actionable threat. Your job is to "
    "characterize it: map it to the MITRE ATT&CK framework (tactics and "
    "techniques), assess the observed indicators of compromise, and identify where "
    "in the attack lifecycle this activity sits. Be precise and cite real ATT&CK "
    "technique IDs (e.g. T1552.005) where they genuinely apply — do not invent IDs. "
    "This assessment is advisory: it informs a human analyst, it does not choose "
    "any response action. Respond ONLY with the required JSON object."
)


class MitreTechnique(BaseModel):
    technique_id: str = Field(description="MITRE ATT&CK technique ID, e.g. T1552.005. Empty if none applies.")
    technique_name: str = Field(description="Human-readable technique name.")
    tactic: str = Field(description="The ATT&CK tactic, e.g. 'Credential Access', 'Exfiltration'.")


class ThreatIntelAssessment(BaseModel):
    """The internal, provider-neutral threat-intel record. `available=False` means
    the LLM couldn't produce an assessment; every other field is then empty."""

    finding_id: str
    available: bool
    mitre_techniques: list[MitreTechnique] = Field(default_factory=list)
    attack_lifecycle_stage: str = ""     # e.g. "Initial Access", "Exfiltration"
    ioc_assessment: str = ""             # analyst reasoning about the observed IOCs
    intel_summary: str = ""              # 1-2 sentence characterization for the record

    def technique_ids(self) -> list[str]:
        return [t.technique_id for t in self.mitre_techniques if t.technique_id]


class _LLMIntelOutput(BaseModel):
    """Schema the model fills. No target/resource/action field exists here by
    construction — this agent cannot express a containment decision."""

    mitre_techniques: list[MitreTechnique] = Field(
        default_factory=list,
        description="ATT&CK techniques this activity maps to. Omit if genuinely none apply.",
    )
    attack_lifecycle_stage: str = Field(
        description="Where in the attack lifecycle this sits (e.g. 'Initial Access', 'Exfiltration')."
    )
    ioc_assessment: str = Field(
        description="Assessment of the observed indicators of compromise (IPs, patterns, counts)."
    )
    intel_summary: str = Field(
        description="1-2 sentence threat characterization for the incident record."
    )


class ThreatIntelAgent:
    def __init__(self, llm: GeminiTriageClient | None) -> None:
        self._llm = llm

    async def assess(self, finding: Finding) -> ThreatIntelAssessment:
        if self._llm is None:
            return ThreatIntelAssessment(finding_id=finding.finding_id, available=False)

        from .sanitization import sanitize_finding
        sanitized = sanitize_finding(finding)

        resource_lines = "\n".join(
            f"  - {r.kind} {r.id}" + (f" ({r.attributes})" if r.attributes else "")
            for r in sanitized.resources
        ) or "  (none)"
        prompt = (
            "Characterize this confirmed threat.\n\n"
            f"Provider: {sanitized.provider}\n"
            f"Finding ID: {sanitized.finding_id}\n"
            f"Type: {sanitized.finding_type}\n"
            f"Severity (0-10 normalized): {sanitized.severity} ({sanitized.severity_band})\n"
            f"Title: {sanitized.title or 'n/a'}\n"
            f"Description: {sanitized.description or 'n/a'}\n"
            f"Remote IP: {sanitized.remote_ip or 'n/a'}\n"
            f"Implicated resources:\n{resource_lines}\n"
        )

        try:
            out = await self._llm.structured(
                system=_SYSTEM, prompt=prompt, schema=_LLMIntelOutput
            )
        except (LLMUnavailableError, Exception):  # noqa: BLE001 - enrichment is best-effort
            return ThreatIntelAssessment(finding_id=finding.finding_id, available=False)

        return ThreatIntelAssessment(
            finding_id=finding.finding_id,
            available=True,
            mitre_techniques=out.mitre_techniques,
            attack_lifecycle_stage=out.attack_lifecycle_stage,
            ioc_assessment=out.ioc_assessment,
            intel_summary=out.intel_summary,
        )
