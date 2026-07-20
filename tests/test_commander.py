"""
Incident Commander Agent — synthesis + escalation.

The safety property under test is the same one every intelligence agent must
hold: the commander can raise urgency for a human, but it has zero execution
authority and its output schema structurally cannot express a containment
target or action. Escalation pages a person; it never authorizes an action.
"""

from __future__ import annotations

import pytest

from aegis.commander import (
    IncidentAssessment,
    IncidentCommanderAgent,
    _fmt_correlation,
    _fmt_intel,
    _LLMCommanderOutput,
)
from aegis.correlation import CorrelationAssessment
from aegis.intel import MitreTechnique, ThreatIntelAssessment
from aegis.model import Finding
from aegis.schemas import TriageVerdict


def _finding(finding_id: str = "f-1", severity: float = 8.0) -> Finding:
    return Finding(provider="aws", finding_id=finding_id, finding_type="Test", severity=severity)


def _verdict(finding_id: str = "f-1") -> TriageVerdict:
    return TriageVerdict(
        finding_id=finding_id, is_actionable_threat=True, threat_category="Credential Exfiltration",
        confidence=0.95, severity=8.0, justification="clear exfiltration pattern",
    )


def _intel(available: bool = True) -> ThreatIntelAssessment:
    if not available:
        return ThreatIntelAssessment(finding_id="f-1", available=False)
    return ThreatIntelAssessment(
        finding_id="f-1", available=True,
        mitre_techniques=[MitreTechnique(technique_id="T1552.005",
                                         technique_name="Cloud Instance Metadata API",
                                         tactic="Credential Access")],
        attack_lifecycle_stage="Exfiltration",
        ioc_assessment="Tor exit node source IP.",
        intel_summary="Credential theft via metadata service.",
    )


def _correlation(campaign: bool = True, available: bool = True) -> CorrelationAssessment:
    if not available:
        return CorrelationAssessment(finding_id="f-1", available=False)
    return CorrelationAssessment(
        finding_id="f-1", available=True, part_of_campaign=campaign,
        related_finding_ids=["f-0"] if campaign else [],
        campaign_narrative="Actor pivoting from recon." if campaign else "",
        correlation_summary="Linked to f-0." if campaign else "No link found.",
    )


class ScriptedLLM:
    def __init__(self, output: _LLMCommanderOutput) -> None:
        self._output = output
        self.calls = 0
        self.last_prompt = ""

    async def structured(self, *, system, prompt, schema):
        self.calls += 1
        self.last_prompt = prompt
        return self._output


def _output(**overrides) -> _LLMCommanderOutput:
    defaults = dict(
        incident_narrative="Actor stole credentials and is exfiltrating data.",
        priority="P1",
        escalate_to_human_now=True,
        escalation_reason="Active exfiltration in progress.",
        key_risks=["S3 data loss", "lateral movement"],
        recommended_posture="Contain the principal and preserve evidence.",
    )
    defaults.update(overrides)
    return _LLMCommanderOutput(**defaults)


# --------------------------------------------------------------------------- #
# Structural safety
# --------------------------------------------------------------------------- #

def test_commander_output_schema_cannot_express_an_action() -> None:
    """The commander must be structurally incapable of selecting a containment
    target or action -- this is what makes escalation safe to trust."""
    fields = set(_LLMCommanderOutput.model_fields)
    forbidden = {"target", "action", "action_class", "resource", "provider",
                 "command", "api_call", "execute"}
    assert fields.isdisjoint(forbidden)
    assert fields == {
        "incident_narrative", "priority", "escalate_to_human_now",
        "escalation_reason", "key_risks", "recommended_posture",
    }


def test_priority_is_constrained_to_known_bands() -> None:
    with pytest.raises(Exception):
        _LLMCommanderOutput(
            incident_narrative="x", priority="P99", escalate_to_human_now=False,
            escalation_reason="x", key_risks=[], recommended_posture="x",
        )


# --------------------------------------------------------------------------- #
# Degradation
# --------------------------------------------------------------------------- #

async def test_no_llm_returns_unavailable_and_does_not_escalate() -> None:
    """Fail-safe direction: with no LLM there is no synthesis, and crucially no
    spurious escalation. The approval queue still holds everything."""
    agent = IncidentCommanderAgent(llm=None)
    result = await agent.assess(_finding(), _verdict(), _intel(), _correlation())
    assert result.available is False
    assert result.escalate_to_human_now is False
    assert result.priority == ""


async def test_llm_exception_degrades_without_escalating() -> None:
    class RaisingLLM:
        async def structured(self, **kwargs):
            raise RuntimeError("model exploded")

    agent = IncidentCommanderAgent(llm=RaisingLLM())
    result = await agent.assess(_finding(), _verdict(), _intel(), _correlation())
    assert result.available is False
    assert result.escalate_to_human_now is False


# --------------------------------------------------------------------------- #
# Synthesis
# --------------------------------------------------------------------------- #

async def test_synthesizes_all_specialists_into_one_assessment() -> None:
    llm = ScriptedLLM(_output())
    agent = IncidentCommanderAgent(llm=llm)
    result = await agent.assess(_finding(), _verdict(), _intel(), _correlation())

    assert result.available is True
    assert result.priority == "P1"
    assert result.escalate_to_human_now is True
    assert "exfiltrating" in result.incident_narrative
    assert result.key_risks == ["S3 data loss", "lateral movement"]


async def test_prompt_includes_every_specialist_assessment() -> None:
    """The commander's value is synthesis -- so all three specialists' outputs
    must actually reach the prompt, not just the finding."""
    llm = ScriptedLLM(_output())
    agent = IncidentCommanderAgent(llm=llm)
    await agent.assess(_finding(), _verdict(), _intel(), _correlation())

    p = llm.last_prompt
    assert "Triage analyst" in p
    assert "Credential Exfiltration" in p          # triage category
    assert "Threat-intelligence analyst" in p
    assert "T1552.005" in p                        # intel technique
    assert "Investigation / correlation analyst" in p
    assert "PART OF A CAMPAIGN" in p               # correlation result
    assert "f-0" in p                              # the related finding


async def test_unavailable_specialists_are_marked_not_silently_dropped() -> None:
    """If intel/correlation didn't run, the commander must be told so explicitly
    rather than shown a blank -- otherwise it may infer 'nothing found'."""
    llm = ScriptedLLM(_output())
    agent = IncidentCommanderAgent(llm=llm)
    await agent.assess(_finding(), _verdict(), _intel(available=False),
                       _correlation(available=False))

    p = llm.last_prompt
    assert "threat-intel unavailable" in p
    assert "correlation unavailable" in p


def test_formatter_distinguishes_campaign_from_isolated_alert() -> None:
    assert "PART OF A CAMPAIGN" in _fmt_correlation(_correlation(campaign=True))
    assert "isolated alert" in _fmt_correlation(_correlation(campaign=False))
    assert "unavailable" in _fmt_correlation(_correlation(available=False))


def test_formatter_handles_intel_with_no_mapped_techniques() -> None:
    empty = ThreatIntelAssessment(finding_id="f-1", available=True,
                                  mitre_techniques=[], attack_lifecycle_stage="Unknown")
    assert "none mapped" in _fmt_intel(empty)
