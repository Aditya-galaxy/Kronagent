"""Provider-neutral Finding model: severity bands and immutability."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from kronagent.model import Finding, ResourceRef


@pytest.mark.parametrize(
    "severity,expected_band",
    [
        (0.0, "low"),
        (3.9, "low"),
        (4.0, "medium"),
        (6.9, "medium"),
        (7.0, "high"),
        (8.9, "high"),
        (9.0, "critical"),
        (10.0, "critical"),
    ],
)
def test_severity_band_boundaries(severity: float, expected_band: str) -> None:
    f = Finding(provider="aws", finding_id="f-1", finding_type="Test", severity=severity)
    assert f.severity_band == expected_band


def test_finding_is_frozen() -> None:
    f = Finding(provider="aws", finding_id="f-1", finding_type="Test", severity=5.0)
    with pytest.raises(ValidationError):
        f.severity = 9.0  # type: ignore[misc]


def test_resource_ref_is_frozen() -> None:
    r = ResourceRef(kind="aws.iam.user", id="alice")
    with pytest.raises(ValidationError):
        r.id = "bob"  # type: ignore[misc]


def test_finding_defaults() -> None:
    f = Finding(provider="kubernetes", finding_id="k-1", finding_type="k8s:test", severity=5.0)
    assert f.resources == []
    assert f.remote_ip is None
    assert f.raw == {}
    assert f.title == ""
