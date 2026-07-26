"""
Unit tests for the EU AI Act compliance report exporter.
"""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock
import pytest

from kronagent.audit import AuditLog, _canonical, _hash_entry
from kronagent.compliance import ComplianceExporter
from kronagent.schemas import AuditRecord


def test_compliance_exporter_empty(tmp_path) -> None:
    log_path = str(tmp_path / "empty_audit.jsonl")
    exporter = ComplianceExporter(log_path)
    report = exporter.generate_report()

    assert report["audit_integrity"]["verified"] is True
    assert report["compliance_summary"]["total_findings"] == 0
    assert len(report["findings"]) == 0


def test_compliance_exporter_valid_flow(tmp_path) -> None:
    log_path = str(tmp_path / "valid_audit.jsonl")
    audit = AuditLog(log_path)

    # 1. Record triage
    import asyncio
    asyncio.run(audit.record(AuditRecord(
        finding_id="f1", stage="triage",
        payload={"severity": 8.5, "rationale": "Compromised S3 bucket detected"}
    )))

    # 2. Record intel
    asyncio.run(audit.record(AuditRecord(
        finding_id="f1", stage="intel",
        payload={"threat_intel_summary": "IP matched Tor exit node", "mitre_techniques": ["T1020"]}
    )))

    # 3. Record forensics
    asyncio.run(audit.record(AuditRecord(
        finding_id="f1", stage="forensics",
        payload={"items": [{"kind": "s3_bucket_acl", "custody_sha256": "abc123xyz"}]}
    )))

    # 4. Record policy
    asyncio.run(audit.record(AuditRecord(
        finding_id="f1", stage="policy",
        payload={
            "action": {"action_class": "block_ip", "target": "1.1.1.1"},
            "decision": {"disposition": "requires_approval", "reason": "blast radius limit", "reversible": True, "blast_radius": "medium"}
        }
    )))

    # 5. Record approval
    asyncio.run(audit.record(AuditRecord(
        finding_id="f1", stage="approval",
        payload={
            "request_id": "req-100", "decision": "approved", "by": "operator-alice", "reason": "Authorized via chat",
            "action_class": "block_ip", "target": "1.1.1.1"
        }
    )))

    # 6. Record containment
    asyncio.run(audit.record(AuditRecord(
        finding_id="f1", stage="containment",
        payload={
            "action_class": "block_ip", "target": "1.1.1.1", "executed": True, "dry_run": False,
            "detail": "blocked at NACL", "rollback_hint": "delete rule", "request_id": "req-100"
        }
    )))

    exporter = ComplianceExporter(log_path)
    report = exporter.generate_report()

    # Integrity verification checks
    assert report["audit_integrity"]["verified"] is True
    assert report["compliance_summary"]["total_findings"] == 1
    assert report["compliance_summary"]["total_human_overridden_actions"] == 1

    # Detailed finding telemetry
    findings = report["findings"]
    assert len(findings) == 1
    f = findings[0]
    assert f["finding_id"] == "f1"
    assert f["triage"]["severity"] == 8.5
    assert f["intel"]["mitre_techniques"] == ["T1020"]
    assert len(f["forensics"]) == 1
    assert f["forensics"][0]["kind"] == "s3_bucket_acl"
    assert len(f["policy_decisions"]) == 1
    assert f["policy_decisions"][0]["disposition"] == "requires_approval"
    assert len(f["approval_decisions"]) == 1
    assert f["approval_decisions"][0]["by"] == "operator-alice"
    assert len(f["containment_executions"]) == 1
    assert f["containment_executions"][0]["executed"] is True

    # Check markdown construction
    md = exporter.generate_markdown(report)
    assert "# EU AI Act Article 12/14 Compliance Manifest" in md
    assert "✅ VERIFIED" in md
    assert "operator-alice" in md
    assert "f1" in md
    assert "abc123xyz" in md


def test_compliance_exporter_tampered_integrity(tmp_path) -> None:
    log_path = str(tmp_path / "tampered_audit.jsonl")
    audit = AuditLog(log_path)

    import asyncio
    asyncio.run(audit.record(AuditRecord(
        finding_id="f1", stage="triage",
        payload={"severity": 5.0, "rationale": "Initial finding"}
    )))
    asyncio.run(audit.record(AuditRecord(
        finding_id="f1", stage="containment",
        payload={"action_class": "terminate", "target": "host-1", "executed": True, "dry_run": False, "detail": "done", "rollback_hint": ""}
    )))

    # Verify original is fine
    exporter = ComplianceExporter(log_path)
    report = exporter.generate_report()
    assert report["audit_integrity"]["verified"] is True

    # Tamper with line 1 record content
    with open(log_path, "r", encoding="utf-8") as fh:
        lines = fh.readlines()

    envelope = json.loads(lines[0])
    envelope["record"]["payload"]["severity"] = 9.9 # Modified severity!
    lines[0] = json.dumps(envelope) + "\n"

    with open(log_path, "w", encoding="utf-8") as fh:
        fh.writelines(lines)

    # Re-run report and verify failure
    report_tampered = exporter.generate_report()
    assert report_tampered["audit_integrity"]["verified"] is False
    assert report_tampered["audit_integrity"]["first_broken_line"] == 1
