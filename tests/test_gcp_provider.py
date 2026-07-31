import pytest
from kronagent.model import Finding, ResourceRef
from kronagent.schemas import ActionClass, ProposedAction, PolicyDecision
from kronagent.providers.gcp import (
    normalize_gcp_scc,
    plan_gcp_actions,
    GcpContainmentAdapter
)
from kronagent.containment import ContainmentExecutor
from kronagent.config import Settings

def test_normalize_gcp_scc_nested():
    raw_payload = {
        "finding": {
            "name": "organizations/123/sources/456/findings/f-gcp-001",
            "resourceName": "//compute.googleapis.com/projects/demo-project/zones/us-central1-a/instances/vm-compromised-01",
            "category": "Persistence: IAM Anomalous Grant",
            "severity": "HIGH",
            "description": "Anomalous IAM grant detected on VM instance",
            "sourceProperties": {
                "callerIp": "198.51.100.45",
                "serviceAccountEmail": "sec-ops@demo-project.iam.gserviceaccount.com"
            }
        }
    }

    finding = normalize_gcp_scc(raw_payload)

    assert finding.finding_id == "f-gcp-001"
    assert finding.provider == "gcp"
    assert finding.severity == 7.5
    assert finding.remote_ip == "198.51.100.45"
    
    kinds = [r.kind for r in finding.resources]
    assert "gcp.instance" in kinds
    assert "gcp.service_account" in kinds
    
    inst_res = next(r for r in finding.resources if r.kind == "gcp.instance")
    assert inst_res.id == "vm-compromised-01"
    assert inst_res.attributes["project"] == "demo-project"
    assert inst_res.attributes["zone"] == "us-central1-a"

def test_plan_gcp_actions():
    finding = Finding(
        finding_id="f-gcp-002",
        provider="gcp",
        finding_type="Exfiltration: SA Key Created",
        severity=9.0,
        remote_ip="203.0.113.88",
        resources=[
            ResourceRef(
                kind="gcp.service_account_key",
                id="key-998877",
                attributes={"service_account": "exfil-sa@demo-project.iam.gserviceaccount.com"}
            ),
            ResourceRef(
                kind="gcp.service_account",
                id="exfil-sa@demo-project.iam.gserviceaccount.com",
                attributes={}
            ),
            ResourceRef(
                kind="gcp.instance",
                id="miner-vm-02",
                attributes={}
            )
        ]
    )

    actions = plan_gcp_actions(finding)
    action_classes = [a.action_class for a in actions]

    assert ActionClass.DISABLE_SERVICE_ACCOUNT_KEY in action_classes
    assert ActionClass.DISABLE_SERVICE_ACCOUNT in action_classes
    assert ActionClass.STOP_VM_INSTANCE in action_classes
    assert ActionClass.BLOCK_IP in action_classes

@pytest.mark.asyncio
async def test_gcp_containment_adapter_perform_and_rollback():
    adapter = GcpContainmentAdapter(project_id="demo-project")

    # 1. Plan & Perform DISABLE_SERVICE_ACCOUNT_KEY
    action_key = ProposedAction(
        action_class=ActionClass.DISABLE_SERVICE_ACCOUNT_KEY,
        target="key-998877 (exfil-sa@demo-project.iam.gserviceaccount.com)",
        provider="gcp",
        rationale="Disable key"
    )
    calls, rollback_hint, detail = adapter.plan(action_key)
    assert "gcp.iam.serviceAccountKeys.disable" in calls[0]
    assert "gcp.iam.serviceAccountKeys.enable" in rollback_hint

    exec_detail, exec_rollback = await adapter.perform(action_key)
    assert action_key.target in adapter.disabled_keys
    assert "set to disabled" in exec_detail

    # 2. Plan & Perform STOP_VM_INSTANCE
    action_vm = ProposedAction(
        action_class=ActionClass.STOP_VM_INSTANCE,
        target="miner-vm-02",
        provider="gcp",
        rationale="Stop VM"
    )
    exec_detail, exec_rollback = await adapter.perform(action_vm)
    assert "miner-vm-02" in adapter.stopped_instances
    assert "stopped" in exec_detail

@pytest.mark.asyncio
async def test_gcp_containment_executor_integration():
    settings = Settings(dry_run=False)
    adapter = GcpContainmentAdapter()
    executor = ContainmentExecutor(settings, {"gcp": adapter})

    action = ProposedAction(
        action_class=ActionClass.DISABLE_SERVICE_ACCOUNT,
        target="malicious-sa@demo-project.iam.gserviceaccount.com",
        provider="gcp",
        rationale="Disable SA"
    )
    decision = PolicyDecision(
        action_class=ActionClass.DISABLE_SERVICE_ACCOUNT,
        disposition="auto_execute",
        reason="allowlisted",
        reversible=True,
        blast_radius="single_resource"
    )

    outcome = await executor.execute(action, decision)
    assert outcome.executed is True
    assert "set to disabled" in outcome.detail
    assert "malicious-sa@demo-project.iam.gserviceaccount.com" in adapter.disabled_accounts
