"""
Unit and integration tests for AWS and Kubernetes live containment execution paths.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from kronagent.providers.aws import AwsContainmentAdapter
from kronagent.providers.k8s import K8sContainmentAdapter
from kronagent.schemas import ActionClass, ProposedAction


# --------------------------------------------------------------------------- #
# AWS / boto3 mocks
# --------------------------------------------------------------------------- #

@patch("boto3.client")
def test_aws_block_ip_success(mock_boto_client) -> None:
    mock_ec2 = MagicMock()
    # Mock describe_network_acls to return existing rule numbers 100 (ingress) and 101 (egress)
    mock_ec2.describe_network_acls.return_value = {
        "NetworkAcls": [{
            "Entries": [
                {"RuleNumber": 100, "Egress": False},
                {"RuleNumber": 101, "Egress": True},
                {"RuleNumber": 32767, "Egress": False}, # default deny
            ]
        }]
    }

    adapter = AwsContainmentAdapter(region="us-east-1", quarantine_nacl_id="nacl-123")
    adapter._ec2 = mock_ec2

    action = ProposedAction(
        provider="aws",
        action_class=ActionClass.BLOCK_IP,
        target="185.220.101.7",
        rationale="Block attacker IP",
    )

    detail, rollback = adapter._perform_sync(action)

    # Ingress rule 100 is taken, so the first free is 101.
    # Egress rule 101 is taken, so the first free is 100.
    assert "remote IP 185.220.101.7 blocked at quarantine NACL nacl-123" in detail
    assert "RuleNumber=101, Egress=False" in rollback
    assert "RuleNumber=100, Egress=True" in rollback

    mock_ec2.create_network_acl_entry.assert_any_call(
        NetworkAclId="nacl-123",
        RuleNumber=101,
        Protocol="-1",
        RuleAction="deny",
        Egress=False,
        CidrBlock="185.220.101.7/32",
    )
    mock_ec2.create_network_acl_entry.assert_any_call(
        NetworkAclId="nacl-123",
        RuleNumber=100,
        Protocol="-1",
        RuleAction="deny",
        Egress=True,
        CidrBlock="185.220.101.7/32",
    )


@patch("boto3.client")
def test_aws_revoke_role_sessions_success(mock_boto_client) -> None:
    mock_iam = MagicMock()
    adapter = AwsContainmentAdapter(region="us-east-1")
    adapter._iam = mock_iam

    action = ProposedAction(
        provider="aws",
        action_class=ActionClass.REVOKE_ROLE_SESSIONS,
        target="svc-backup-role",
        rationale="Revoke sessions for compromised role",
    )

    detail, rollback = adapter._perform_sync(action)

    assert "active sessions revoked for role svc-backup-role" in detail
    assert "iam.delete_role_policy(RoleName='svc-backup-role', PolicyName='kronagent-revoke-sessions')" in rollback

    mock_iam.put_role_policy.assert_called_once()
    kwargs = mock_iam.put_role_policy.call_args[1]
    assert kwargs["RoleName"] == "svc-backup-role"
    assert kwargs["PolicyName"] == "kronagent-revoke-sessions"

    policy = json.loads(kwargs["PolicyDocument"])
    assert policy["Statement"][0]["Effect"] == "Deny"
    assert policy["Statement"][0]["Action"] == "*"
    assert "aws:TokenIssueTime" in policy["Statement"][0]["Condition"]["DateLessThan"]


# --------------------------------------------------------------------------- #
# Kubernetes
# --------------------------------------------------------------------------- #

@patch("kubernetes.config.load_kube_config")
def test_k8s_isolate_pod_success(mock_load_config) -> None:
    mock_core = MagicMock()
    mock_apps = MagicMock()
    mock_net = MagicMock()

    adapter = K8sContainmentAdapter()
    adapter._api = (mock_core, mock_apps, mock_net)

    # Mock read_namespaced_network_policy to raise 404 ApiException, prompting policy creation
    from kubernetes.client.exceptions import ApiException
    mock_net.read_namespaced_network_policy.side_effect = ApiException(status=404)

    action = ProposedAction(
        provider="kubernetes",
        action_class=ActionClass.ISOLATE_POD,
        target="payments-api-7f9c8d",
        rationale="Isolate pod from rest of the network",
        parameters={"namespace": "payments"},
    )

    detail, rollback = adapter._perform_sync(action)

    assert "pod payments/payments-api-7f9c8d isolated with deny-all NetworkPolicy" in detail
    assert "kubectl label pod payments-api-7f9c8d -n payments kronagent-quarantine-" in rollback

    mock_core.patch_namespaced_pod.assert_called_once_with(
        "payments-api-7f9c8d",
        "payments",
        {"metadata": {"labels": {"kronagent-quarantine": "true"}}},
    )

    mock_net.create_namespaced_network_policy.assert_called_once()
    args = mock_net.create_namespaced_network_policy.call_args[0]
    assert args[0] == "payments"
    assert args[1].metadata.name == "kronagent-quarantine-deny-all"
