"""
Threat Intelligence Agent — MITRE ATT&CK enrichment.

Two properties matter most and are the focus here:
  1. Graceful degradation: no LLM, or an LLM that errors, must yield an
     `available=False` assessment and never raise -- intelligence is a bonus,
     never a dependency that can stall the pipeline.
  2. Advisory-only: the agent's output schema has no target/action field by
     construction, so it structurally cannot express a containment decision.
No network / no real LLM: a fake client returns scripted structured output.
"""

from __future__ import annotations


from kronagent.intel import (
    MitreTechnique,
    ThreatIntelAgent,
    ThreatIntelAssessment,
    _LLMIntelOutput,
)
from kronagent.model import Finding, ResourceRef


class FakeLLM:
    """Stands in for GeminiTriageClient. Returns a scripted _LLMIntelOutput, or
    raises if configured to -- mirrors the real .structured() surface."""

    def __init__(self, output: _LLMIntelOutput | None = None, raise_exc: Exception | None = None) -> None:
        self._output = output
        self._raise = raise_exc
        self.calls = 0

    async def structured(self, *, system: str, prompt: str, schema):
        self.calls += 1
        if self._raise is not None:
            raise self._raise
        return self._output


def _finding() -> Finding:
    return Finding(
        provider="aws", finding_id="f-1",
        finding_type="UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        severity=8.0, title="Credential exfiltration", remote_ip="185.220.101.7",
        resources=[ResourceRef(kind="aws.iam.access_key", id="AKIA1", attributes={"user_name": "svc"})],
    )


def _scripted_output() -> _LLMIntelOutput:
    return _LLMIntelOutput(
        mitre_techniques=[
            MitreTechnique(technique_id="T1552.004", technique_name="Private Keys", tactic="Credential Access"),
            MitreTechnique(technique_id="T1530", technique_name="Data from Cloud Storage", tactic="Exfiltration"),
        ],
        attack_lifecycle_stage="Exfiltration",
        ioc_assessment="Tor exit node source, 412 sequential GetObject calls.",
        intel_summary="Credential theft followed by S3 data exfiltration via Tor.",
    )


async def test_no_llm_returns_unavailable_assessment() -> None:
    agent = ThreatIntelAgent(None)
    result = await agent.assess(_finding())
    assert result.available is False
    assert result.finding_id == "f-1"
    assert result.mitre_techniques == []
    assert result.technique_ids() == []


async def test_successful_assessment_maps_techniques() -> None:
    agent = ThreatIntelAgent(FakeLLM(output=_scripted_output()))
    result = await agent.assess(_finding())

    assert result.available is True
    assert result.attack_lifecycle_stage == "Exfiltration"
    assert result.technique_ids() == ["T1552.004", "T1530"]
    assert "exfiltration" in result.intel_summary.lower()


async def test_llm_error_degrades_gracefully_never_raises() -> None:
    agent = ThreatIntelAgent(FakeLLM(raise_exc=RuntimeError("model exploded")))
    result = await agent.assess(_finding())  # must not raise
    assert result.available is False
    assert result.mitre_techniques == []


async def test_technique_ids_skips_empty_ids() -> None:
    assessment = ThreatIntelAssessment(
        finding_id="f-1", available=True,
        mitre_techniques=[
            MitreTechnique(technique_id="T1496", technique_name="Resource Hijacking", tactic="Impact"),
            MitreTechnique(technique_id="", technique_name="", tactic=""),  # model returned a blank
        ],
    )
    assert assessment.technique_ids() == ["T1496"]


def test_intel_output_schema_has_no_action_or_target_field() -> None:
    """Structural safety guarantee: the agent literally cannot express a
    containment decision -- there is no field for a target, resource, or
    action class in the schema the model fills."""
    forbidden = {"target", "resource", "action", "action_class", "resource_id"}
    assert forbidden.isdisjoint(_LLMIntelOutput.model_fields.keys())


async def test_agent_is_called_once_per_assess() -> None:
    fake = FakeLLM(output=_scripted_output())
    agent = ThreatIntelAgent(fake)
    await agent.assess(_finding())
    assert fake.calls == 1
