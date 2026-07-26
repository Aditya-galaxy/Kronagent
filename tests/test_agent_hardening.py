import pytest
import json
import base64
from kronagent.config import Settings
from kronagent.orchestrator import Orchestrator
from kronagent.triage import TriageEngine
from kronagent.model import Finding
from kronagent.schemas import ProposedAction, ActionClass, TriageVerdict, AuditRecord
from kronagent.crypto import get_signer, LocalAsymmetricSigner
from kronagent.identity import hash_token
from kronagent.audit import AuditLog
from kronagent.allowlist import AllowlistStore
from kronagent.policy import PolicyEngine
from kronagent.containment import ContainmentExecutor
from kronagent.providers import build_containment_adapters

class FakeTriageEngine:
    def __init__(self, verdict: TriageVerdict):
        self.verdict = verdict

    async def assess(self, finding: Finding):
        return self.verdict, []

def read_audit_records(audit_path: str) -> list[AuditRecord]:
    records = []
    with open(audit_path, "r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                data = json.loads(line)
                records.append(AuditRecord(**data["record"]))
    return records

@pytest.fixture
def base_settings(tmp_path):
    return Settings(
        dry_run=True,
        require_agent_signatures=True,
        audit_log_path=str(tmp_path / "audit.jsonl"),
        allowlist_store_path=str(tmp_path / "allowlist.json"),
        approval_store_path=str(tmp_path / "approvals.json"),
        db_path="",
    )

@pytest.mark.asyncio
async def test_agent_signature_success(base_settings) -> None:
    # 1. Setup components
    signer = get_signer(base_settings)
    verdict = TriageVerdict(
        finding_id="f-1",
        is_actionable_threat=True,
        threat_category="Unusual API Calls",
        confidence=0.9,
        severity=8.0,
        justification="Legitimate SOC verdict",
    ).with_signature(signer)

    triage = FakeTriageEngine(verdict)
    audit = AuditLog(base_settings.audit_log_path)
    allowlist = AllowlistStore(base_settings.allowlist_store_path)
    policy = PolicyEngine(base_settings, allowlist)
    containment = ContainmentExecutor(base_settings, build_containment_adapters(base_settings))

    orch = Orchestrator(
        base_settings,
        triage=triage,
        policy=policy,
        containment=containment,
        audit=audit,
    )

    finding = Finding(
        finding_id="f-1",
        provider="aws",
        finding_type="UnauthorizedAccess",
        severity=8.0,
        resources=[]
    )

    # 2. Should handle successfully
    await orch._handle(finding)

    # 3. Verify audit log has triage record and NO security alerts
    records = read_audit_records(base_settings.audit_log_path)
    stages = [r.stage for r in records]
    assert "triage" in stages
    assert "security_alert" not in stages

@pytest.mark.asyncio
async def test_agent_signature_tampered_fails(base_settings, tmp_path) -> None:
    # 1. Sign using a different key
    bad_key_path = str(tmp_path / "bad_key.pem")
    bad_signer = LocalAsymmetricSigner(bad_key_path)
    
    verdict = TriageVerdict(
        finding_id="f-1",
        is_actionable_threat=True,
        threat_category="Unusual API Calls",
        confidence=0.9,
        severity=8.0,
        justification="SOC verdict",
    ).with_signature(bad_signer) # Signed with wrong key!

    triage = FakeTriageEngine(verdict)
    audit = AuditLog(base_settings.audit_log_path)
    allowlist = AllowlistStore(base_settings.allowlist_store_path)
    policy = PolicyEngine(base_settings, allowlist)
    containment = ContainmentExecutor(base_settings, build_containment_adapters(base_settings))

    orch = Orchestrator(
        base_settings,
        triage=triage,
        policy=policy,
        containment=containment,
        audit=audit,
    )

    finding = Finding(
        finding_id="f-1",
        provider="aws",
        finding_type="UnauthorizedAccess",
        severity=8.0,
        resources=[]
    )

    # 2. Execution must raise ValueError due to verification failure
    with pytest.raises(ValueError, match="Triage verdict signature verification failed"):
        await orch._handle(finding)

    # 3. Verify audit log contains a security_alert record
    records = read_audit_records(base_settings.audit_log_path)
    stages = [r.stage for r in records]
    assert "security_alert" in stages
    
    alert_record = next(r for r in records if r.stage == "security_alert")
    assert "signature validation failed" in alert_record.payload["detail"]

@pytest.mark.asyncio
async def test_agent_signature_unsigned_fails(base_settings) -> None:
    # 1. Unsigned verdict
    verdict = TriageVerdict(
        finding_id="f-1",
        is_actionable_threat=True,
        threat_category="Unusual API Calls",
        confidence=0.9,
        severity=8.0,
        justification="SOC verdict",
    ) # No signature!

    triage = FakeTriageEngine(verdict)
    audit = AuditLog(base_settings.audit_log_path)
    allowlist = AllowlistStore(base_settings.allowlist_store_path)
    policy = PolicyEngine(base_settings, allowlist)
    containment = ContainmentExecutor(base_settings, build_containment_adapters(base_settings))

    orch = Orchestrator(
        base_settings,
        triage=triage,
        policy=policy,
        containment=containment,
        audit=audit,
    )

    finding = Finding(
        finding_id="f-1",
        provider="aws",
        finding_type="UnauthorizedAccess",
        severity=8.0,
        resources=[]
    )

    # 2. Must fail validation
    with pytest.raises(ValueError, match="Triage verdict signature verification failed"):
        await orch._handle(finding)

    # 3. Verify audit log security alert
    records = read_audit_records(base_settings.audit_log_path)
    stages = [r.stage for r in records]
    assert "security_alert" in stages

def test_web_view_permissions_enforced(tmp_path):
    from fastapi.testclient import TestClient
    from kronagent import web
    
    # 1. Configure registry
    registry_data = {
        "alice": {
            "display_name": "Alice",
            "roles": ["viewer"],
            "token_sha256": hash_token("secret123"),
            "active": True
        },
        "bob": {
            "display_name": "Bob",
            "roles": [], # No roles, so no VIEW permission
            "token_sha256": hash_token("secret456"),
            "active": True
        }
    }
    registry_file = tmp_path / "registry.json"
    registry_file.write_text(json.dumps(registry_data))
    
    # 2. Patch web.settings operator_registry_path and require_view_auth
    orig_registry = web.settings.operator_registry_path
    orig_require_view_auth = web.settings.require_view_auth
    web.settings = web.settings.__class__(
        **{**web.settings.__dict__, "operator_registry_path": str(registry_file), "require_view_auth": True}
    )
    
    client = TestClient(web.app)
    
    try:
        # Request without headers -> 403 Forbidden
        response = client.get("/api/approvals")
        assert response.status_code == 403
        assert "VIEW permission required" in response.json()["detail"]
        
        # Request with Bob (no roles) -> 403 Forbidden
        response = client.get("/api/approvals", headers={
            "X-Operator-ID": "bob",
            "X-Operator-Token": "secret456"
        })
        assert response.status_code == 403
        assert "lacks the 'view' permission" in response.json()["detail"]
        
        # Request with Alice (viewer role) -> 200 OK
        response = client.get("/api/approvals", headers={
            "X-Operator-ID": "alice",
            "X-Operator-Token": "secret123"
        })
        assert response.status_code == 200
        
    finally:
        # Restore settings
        web.settings = web.settings.__class__(
            **{**web.settings.__dict__, "operator_registry_path": orig_registry, "require_view_auth": orig_require_view_auth}
        )
