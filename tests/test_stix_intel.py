import pytest
from aegis.model import Finding, ResourceRef
from aegis.intel import ThreatIntelAgent, StixFeedDb, StixIndicator

@pytest.mark.asyncio
async def test_stix_feed_matching():
    db = StixFeedDb([
        StixIndicator(
            id="indicator--1",
            name="C2 Server IP",
            pattern="[ipv4-addr:value = '198.51.100.99']",
            description="Malicious C2 IP",
            confidence=90
        )
    ])
    agent = ThreatIntelAgent(llm=None, stix_db=db)

    finding = Finding(
        finding_id="f-stix-1",
        provider="gcp",
        finding_type="Unusual API Calls",
        severity=8.0,
        remote_ip="198.51.100.99",
        resources=[]
    )

    assessment = await agent.assess(finding)

    assert assessment.available is True
    assert len(assessment.stix_matches) == 1
    assert assessment.stix_matches[0].name == "C2 Server IP"
    assert "STIX threat intel indicator match" in assessment.intel_summary

@pytest.mark.asyncio
async def test_stix_feed_no_match():
    db = StixFeedDb()
    agent = ThreatIntelAgent(llm=None, stix_db=db)

    finding = Finding(
        finding_id="f-stix-2",
        provider="gcp",
        finding_type="Unusual API Calls",
        severity=8.0,
        remote_ip="10.0.0.1",
        resources=[]
    )

    assessment = await agent.assess(finding)

    assert assessment.available is False
    assert len(assessment.stix_matches) == 0
