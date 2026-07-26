"""
Integration/high-fidelity testing of AWS containment actions using Moto.
"""

from __future__ import annotations

import json

import boto3
from moto import mock_aws

from kronagent.providers.aws import AwsContainmentAdapter
from kronagent.schemas import ActionClass, ProposedAction


@mock_aws
def test_moto_block_ip_success() -> None:
    # 1. Setup mock AWS environment (VPC and NACL)
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]

    nacl = ec2_client.create_network_acl(VpcId=vpc_id)
    nacl_id = nacl["NetworkAcl"]["NetworkAclId"]

    # 2. Initialize our containment adapter targeting the mock NACL
    adapter = AwsContainmentAdapter(region="us-east-1", quarantine_nacl_id=nacl_id)

    action = ProposedAction(
        provider="aws",
        action_class=ActionClass.BLOCK_IP,
        target="198.51.100.42",
        rationale="Block command-and-control IP",
    )

    # 3. Perform the containment action
    detail, rollback = adapter._perform_sync(action)

    assert "blocked at quarantine NACL" in detail
    assert nacl_id in detail

    # 4. Query the mock NACL state to verify the entries are actually created in Moto!
    acls = ec2_client.describe_network_acls(NetworkAclIds=[nacl_id])
    entries = acls["NetworkAcls"][0]["Entries"]

    # Check for ingress block rule
    ingress_entries = [e for e in entries if not e["Egress"] and e["CidrBlock"] == "198.51.100.42/32"]
    assert len(ingress_entries) == 1
    assert ingress_entries[0]["RuleAction"] == "deny"

    # Check for egress block rule
    egress_entries = [e for e in entries if e["Egress"] and e["CidrBlock"] == "198.51.100.42/32"]
    assert len(egress_entries) == 1
    assert egress_entries[0]["RuleAction"] == "deny"


@mock_aws
def test_moto_revoke_role_sessions_success() -> None:
    # 1. Setup mock AWS environment (IAM Role)
    iam_client = boto3.client("iam", region_name="us-east-1")
    role_name = "test-compromised-role"

    # Assume role policy document
    assume_role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }

    iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(assume_role_policy),
    )

    # 2. Initialize our containment adapter
    adapter = AwsContainmentAdapter(region="us-east-1")

    action = ProposedAction(
        provider="aws",
        action_class=ActionClass.REVOKE_ROLE_SESSIONS,
        target=role_name,
        rationale="Revoke sessions for compromised role",
    )

    # 3. Perform the containment action
    detail, rollback = adapter._perform_sync(action)

    assert "active sessions revoked for role" in detail
    assert role_name in detail

    # 4. Verify that the inline revocation policy was actually attached to the IAM role in Moto!
    policies = iam_client.list_role_policies(RoleName=role_name)
    assert "kronagent-revoke-sessions" in policies["PolicyNames"]

    policy_detail = iam_client.get_role_policy(
        RoleName=role_name, PolicyName="kronagent-revoke-sessions"
    )
    policy_doc = policy_detail["PolicyDocument"]
    if isinstance(policy_doc, str):
        import urllib.parse
        doc = json.loads(urllib.parse.unquote(policy_doc))
    else:
        doc = policy_doc

    # Assert policy denies everything
    assert doc["Statement"][0]["Effect"] == "Deny"
    assert doc["Statement"][0]["Action"] == "*"
    assert doc["Statement"][0]["Resource"] == "*"
    assert "DateLessThan" in doc["Statement"][0]["Condition"]
