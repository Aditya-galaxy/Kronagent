"""
Unit and integration tests for OCSF normalization and SIEM export.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import pytest

from aegis.ocsf import iso_to_epoch_ms, severity_to_ocsf, to_ocsf_event
from aegis.audit import AuditLog
from aegis.schemas import AuditRecord


def test_iso_to_epoch_ms() -> None:
    # Standard format
    assert iso_to_epoch_ms("2026-07-17T12:00:00.000Z") == 1784289600000
    # Standard format with tz offset
    assert iso_to_epoch_ms("2026-07-17T12:00:00.000+00:00") == 1784289600000
    # Malformed format falls back to current epoch time without raising
    assert isinstance(iso_to_epoch_ms("invalid-timestamp"), int)
    assert iso_to_epoch_ms("invalid-timestamp") > 0


def test_severity_to_ocsf() -> None:
    assert severity_to_ocsf(9.5) == (5, "Critical")
    assert severity_to_ocsf(8.0) == (4, "High")
    assert severity_to_ocsf(5.5) == (3, "Medium")
    assert severity_to_ocsf(2.0) == (2, "Low")


def test_to_ocsf_event_triage() -> None:
    record = {
        "ts": "2026-07-17T12:00:00.000Z",
        "finding_id": "f-1",
        "stage": "triage",
        "payload": {
            "severity": 8.0,
            "threat_category": "Credential Abuse",
            "justification": "compromised keys detected",
            "confidence": 0.9
        }
    }
    
    event = to_ocsf_event(record)
    assert event is not None
    assert event["class_uid"] == 2004
    assert event["class_name"] == "Detection Finding"
    assert event["category_uid"] == 2
    assert event["severity_id"] == 4
    assert event["severity"] == "High"
    assert event["finding_info"]["uid"] == "f-1"
    assert event["finding_info"]["title"] == "Credential Abuse"
    assert event["finding_info"]["desc"] == "compromised keys detected"
    assert event["confidence"] == 90


def test_to_ocsf_event_policy() -> None:
    record = {
        "ts": "2026-07-17T12:00:00.000Z",
        "finding_id": "f-1",
        "stage": "policy",
        "payload": {
            "action": {
                "action_class": "disable_access_key",
                "target": "AKIAEXAMPLE"
            },
            "decision": {
                "disposition": "auto_execute",
                "reason": "reversible and allowlisted"
            }
        }
    }
    
    event = to_ocsf_event(record)
    assert event is not None
    assert event["class_uid"] == 7001
    assert event["class_name"] == "Remediation Activity"
    assert event["category_uid"] == 7
    assert event["remediation"]["action"] == "disable_access_key"
    assert event["remediation"]["target"] == "AKIAEXAMPLE"
    assert event["remediation"]["status"] == "Success"
    assert event["remediation"]["status_id"] == 1


def test_to_ocsf_event_containment() -> None:
    record = {
        "ts": "2026-07-17T12:00:00.000Z",
        "finding_id": "f-1",
        "stage": "containment",
        "payload": {
            "action_class": "isolate_pod",
            "target": "pod-123",
            "executed": True,
            "dry_run": False,
            "detail": "Pod pod-123 isolated with NetworkPolicy",
            "rollback_hint": "kubectl delete networkpolicy aegis-quarantine"
        }
    }
    
    event = to_ocsf_event(record)
    assert event is not None
    assert event["class_uid"] == 7001
    assert event["remediation"]["status"] == "Success"
    assert event["remediation"]["status_id"] == 1
    assert event["remediation"]["kb_article_list"] == ["kubectl delete networkpolicy aegis-quarantine"]


def test_to_ocsf_event_approval() -> None:
    record = {
        "ts": "2026-07-17T12:00:00.000Z",
        "finding_id": "f-1",
        "stage": "approval",
        "payload": {
            "action_class": "terminate_instance",
            "target": "i-0123",
            "decision": "approved",
            "by": "alice",
            "reason": "compromised host verified"
        }
    }
    
    event = to_ocsf_event(record)
    assert event is not None
    assert event["class_uid"] == 7001
    assert event["actor"]["user"]["name"] == "alice"
    assert event["remediation"]["status"] == "Success"
    assert event["remediation"]["status_id"] == 1


def test_to_ocsf_event_governance() -> None:
    record = {
        "ts": "2026-07-17T12:00:00.000Z",
        "finding_id": "_governance",
        "stage": "governance",
        "payload": {
            "decision": "allowlist_add",
            "action_class": "disable_access_key",
            "by": "bob",
            "reason": "safe key deactivation"
        }
    }
    
    event = to_ocsf_event(record)
    assert event is not None
    assert event["class_uid"] == 2003
    assert event["class_name"] == "Compliance Finding"
    assert event["actor"]["user"]["name"] == "bob"
    assert "bob" in event["compliance"]["desc"]


def test_to_ocsf_event_forensics() -> None:
    record = {
        "ts": "2026-07-17T12:00:00.000Z",
        "finding_id": "f-1",
        "stage": "forensics",
        "payload": {
            "items": [
                {"kind": "k8s.pod.logs"},
                {"kind": "k8s.pod.manifest"}
            ]
        }
    }
    
    event = to_ocsf_event(record)
    assert event is not None
    assert event["class_uid"] == 7001
    assert "k8s.pod.logs" in event["remediation"]["desc"]


def test_to_ocsf_event_error() -> None:
    record = {
        "ts": "2026-07-17T12:00:00.000Z",
        "finding_id": "f-1",
        "stage": "error",
        "payload": {
            "error": "Failed to connect to cluster API"
        }
    }
    
    event = to_ocsf_event(record)
    assert event is not None
    assert event["class_uid"] == 2004
    assert event["severity_id"] == 5
    assert event["finding_info"]["desc"] == "Failed to connect to cluster API"


# --------------------------------------------------------------------------- #
# CLI Integration Tests
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_siem_export_cli_and_integrity_gate() -> None:
    # Setup temporary directory and audit log
    with tempfile.TemporaryDirectory(dir=".") as temp_dir:
        log_path = os.path.join(temp_dir, "test_audit.jsonl")
        export_path = os.path.join(temp_dir, "ocsf_export.jsonl")
        
        # 1. Write a valid chained audit log
        audit = AuditLog(log_path)
        await audit.record(AuditRecord(
            finding_id="f-1",
            stage="triage",
            payload={"severity": 8.0, "threat_category": "Recon", "justification": "alert"}
        ))
        await audit.record(AuditRecord(
            finding_id="f-1",
            stage="containment",
            payload={"action_class": "block_ip", "target": "1.1.1.1", "executed": True, "detail": "blocked"}
        ))
        
        # Verify CLI execution on valid log
        result = subprocess.run(
            [sys.executable, "run_siem_export.py", "--audit-log", log_path, "--output", export_path],
            capture_output=True,
            text=True
        )
        assert result.returncode == 0
        assert "Audit log integrity verified" in result.stdout
        assert "Detection Finding (2004): 1" in result.stdout
        assert "Remediation Activity (7001): 1" in result.stdout
        
        # Verify export file content
        assert os.path.exists(export_path)
        with open(export_path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
            assert len(lines) == 2
            ev1 = json.loads(lines[0])
            ev2 = json.loads(lines[1])
            assert ev1["class_uid"] == 2004
            assert ev2["class_uid"] == 7001
            
        # 2. Tamper with the audit log post-record
        with open(log_path, "a", encoding="utf-8") as fh:
            # Append a raw unchained line bypassing AuditLog.record
            fh.write('{"_prev":"bad_prev","_hash":"bad_hash","record":{"ts":"2026-07-23","finding_id":"f-2","stage":"triage","payload":{}}}\n')
            
        # Verify CLI rejects tampered log
        tamper_result = subprocess.run(
            [sys.executable, "run_siem_export.py", "--audit-log", log_path, "--output", export_path],
            capture_output=True,
            text=True
        )
        assert tamper_result.returncode == 1
        assert "SECURITY ALERT: Cryptographic verification of the audit log FAILED" in tamper_result.stdout
        assert "SIEM export aborted" in tamper_result.stdout
