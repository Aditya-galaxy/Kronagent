"""
Triage engine: fuse deterministic detection with LLM reasoning — provider-neutral.

The detector (GuardDuty, a Kubernetes audit rule, Falco, ...) already decided
something is wrong and, after normalization, handed us a `Finding` with a
severity and concrete resources. This engine does two things:

  1. Deterministic action mapping (grounded, no LLM): delegate to the finding's
     provider planner to derive candidate containment actions, with targets read
     straight from the normalized finding. This is what keeps containment aimed
     at the real compromised resource, on any substrate.

  2. LLM enrichment (Gemini, structured output): reason about the finding —
     categorize the threat, assign a response confidence, explain the rationale.
     The LLM's judgment gates *whether* to proceed, never *which resource* is
     targeted, so a prompt-injection payload in telemetry cannot redirect an
     action onto an attacker-chosen resource.

If the LLM is unavailable, triage degrades to a deterministic verdict driven by
the normalized severity, so the pipeline never stalls waiting on the model.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from .llm import GeminiTriageClient, LLMUnavailableError
from .model import Finding
from .providers import plan_actions
from .schemas import ProposedAction, TriageVerdict

_SYSTEM = (
    "You are a senior SOC analyst reviewing a confirmed security finding from a "
    "cloud, cluster, or endpoint detector. The detector has already flagged "
    "suspicious activity; your job is to reason about it: categorize the threat, "
    "judge how confident you are that autonomous containment is warranted, and "
    "explain why. Be conservative — reserve high confidence for unambiguous "
    "evidence. Respond ONLY with the required JSON object."
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


class TriageEngine:
    def __init__(self, llm: GeminiTriageClient | None) -> None:
        self._llm = llm

    async def assess(self, finding: Finding) -> tuple[TriageVerdict, list[ProposedAction]]:
        # Candidate actions come from the provider planner — targets from the
        # normalized finding, not the model.
        candidates = plan_actions(finding)

        resource_lines = "\n".join(
            f"  - {r.kind} {r.id}" + (f" ({r.attributes})" if r.attributes else "")
            for r in finding.resources
        ) or "  (none)"
        prompt = (
            "Review this security finding.\n\n"
            f"Provider: {finding.provider}\n"
            f"Finding ID: {finding.finding_id}\n"
            f"Type: {finding.finding_type}\n"
            f"Severity (0-10 normalized): {finding.severity} ({finding.severity_band})\n"
            f"Title: {finding.title or 'n/a'}\n"
            f"Description: {finding.description or 'n/a'}\n"
            f"Remote IP: {finding.remote_ip or 'n/a'}\n"
            f"Implicated resources:\n{resource_lines}\n"
        )

        if self._llm is not None:
            try:
                out = await self._llm.structured(
                    system=_SYSTEM, prompt=prompt, schema=_LLMTriageOutput
                )
                verdict = TriageVerdict(
                    finding_id=finding.finding_id,
                    is_actionable_threat=out.is_actionable_threat,
                    threat_category=out.threat_category,
                    confidence=out.confidence,
                    severity=finding.severity,
                    justification=out.justification,
                    correlated_signals=out.correlated_signals,
                )
                return verdict, candidates
            except (LLMUnavailableError, Exception):  # noqa: BLE001 - fall back deterministically
                pass

        # Deterministic fallback: normalized severity alone drives the verdict.
        verdict = TriageVerdict(
            finding_id=finding.finding_id,
            is_actionable_threat=finding.severity >= 4.0,
            threat_category=finding.title or finding.finding_type,
            confidence=min(1.0, finding.severity / 10.0),
            severity=finding.severity,
            justification=(
                "FALLBACK (LLM unavailable): verdict derived from normalized severity "
                f"{finding.severity} and finding type {finding.finding_type}."
            ),
            correlated_signals=[s for s in [finding.remote_ip] if s],
        )
        return verdict, candidates
