"""
Unit and integration tests for the Cloud Connect Web Console REST API endpoints.
"""

from __future__ import annotations

from tests.test_web import test_env  # noqa: F401


def test_aws_connect_link_and_status(test_env) -> None:  # noqa: F811
    client, _, _, _ = test_env

    # 1. Create a 1-click CloudFormation launch link
    res = client.post("/api/connect/aws/link", json={
        "account_id": "123456789012",
        "region": "us-east-1",
        "grant": "observe"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["account_id"] == "123456789012"
    assert data["grant"] == "observe"
    assert "https://us-east-1.console.aws.amazon.com/cloudformation" in data["launch_url"]
    assert "kronagent-observe-role.json" in data["launch_url"]
    assert data["external_id"].startswith("kronagent-")

    # 2. Check status endpoint
    res_status = client.get("/api/connect/status")
    assert res_status.status_code == 200
    conns = res_status.json()
    assert len(conns) >= 1
    assert any(c["account_id"] == "123456789012" for c in conns)
