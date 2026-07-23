"""
OCSF Schema Normalization Module.

Aligns Aegis internal audit log events with the Open Cybersecurity Schema Framework.
Maps:
  * triage, threat_intel, correlation, command -> Detection Finding (class_uid: 2004)
  * policy, containment, approvals, forensics -> Remediation Activity (class_uid: 7001)
  * governance -> Compliance Finding (class_uid: 2003)
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional


def iso_to_epoch_ms(ts_str: str) -> int:
    """Parses an ISO 8601 string and returns epoch milliseconds."""
    try:
        clean = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean)
        return int(dt.timestamp() * 1000)
    except Exception:
        # Fallback to current time
        return int(datetime.now().timestamp() * 1000)


def severity_to_ocsf(severity: float) -> tuple[int, str]:
    """Maps normalized severity (0.0 - 10.0) to OCSF severity_id and severity name."""
    if severity >= 9.0:
        return 5, "Critical"
    if severity >= 7.0:
        return 4, "High"
    if severity >= 4.0:
        return 3, "Medium"
    return 2, "Low"


def to_ocsf_event(audit_line: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Maps a raw audit line to a schema-compliant OCSF event dictionary.
    Returns None if the record cannot be parsed or mapped.
    """
    record = audit_line.get("record", audit_line)
    ts = record.get("ts", "")
    finding_id = record.get("finding_id", "")
    stage = record.get("stage", "")
    payload = record.get("payload", {})

    if not stage:
        return None

    time_ms = iso_to_epoch_ms(ts)
    
    metadata = {
        "version": "1.1.0",
        "product": {
            "vendor_name": "Aegis",
            "name": "Aegis Autonomous Responder",
            "version": "1.0.0"
        }
    }

    base_event = {
        "metadata": metadata,
        "time": time_ms,
    }

    # Map based on stage type
    if stage == "triage":
        severity = payload.get("severity", 5.0)
        sev_id, sev_name = severity_to_ocsf(severity)
        return {
            **base_event,
            "class_uid": 2004,
            "class_name": "Detection Finding",
            "category_uid": 2,
            "category_name": "Findings",
            "severity_id": sev_id,
            "severity": sev_name,
            "finding_info": {
                "uid": finding_id,
                "title": payload.get("threat_category", "Triage Decision"),
                "desc": payload.get("justification", ""),
                "created_time": time_ms,
            },
            "analytic": {
                "name": "Aegis Triage Engine",
                "uid": "aegis-triage",
                "type": "Rule"
            },
            "confidence": int(payload.get("confidence", 0.5) * 100)
        }

    elif stage == "threat_intel":
        # Extract MITRE techniques
        techniques = payload.get("mitre_techniques", [])
        return {
            **base_event,
            "class_uid": 2004,
            "class_name": "Detection Finding",
            "category_uid": 2,
            "category_name": "Findings",
            "severity_id": 1,  # Info
            "severity": "Info",
            "finding_info": {
                "uid": finding_id,
                "title": "Threat Intelligence Enrichment",
                "desc": payload.get("threat_intel_summary", "") or payload.get("intel_summary", ""),
            },
            "analytic": {
                "name": "Aegis Threat Intel Agent",
                "uid": "aegis-intel",
                "type": "Enrichment"
            },
            "kb_article_list": techniques
        }

    elif stage == "correlation":
        return {
            **base_event,
            "class_uid": 2004,
            "class_name": "Detection Finding",
            "category_uid": 2,
            "category_name": "Findings",
            "severity_id": 1,
            "severity": "Info",
            "finding_info": {
                "uid": finding_id,
                "title": "Campaign Correlation Analysis",
                "desc": payload.get("correlation_summary", ""),
            },
            "analytic": {
                "name": "Aegis Correlation Agent",
                "uid": "aegis-correlation",
                "type": "Correlation"
            },
            "comment": f"part_of_campaign={payload.get('part_of_campaign', False)}, related_ids={payload.get('related_finding_ids', [])}"
        }

    elif stage == "command":
        priority = payload.get("priority", "P3")
        escalate = payload.get("escalate_to_human_now", False)
        sev_id = 4 if priority == "P1" else (3 if priority == "P2" else 2)
        sev_name = "High" if priority == "P1" else ( "Medium" if priority == "P2" else "Low")
        
        return {
            **base_event,
            "class_uid": 2004,
            "class_name": "Detection Finding",
            "category_uid": 2,
            "category_name": "Findings",
            "severity_id": sev_id,
            "severity": sev_name,
            "finding_info": {
                "uid": finding_id,
                "title": f"Incident Command Assessment - {priority}",
                "desc": payload.get("incident_narrative", ""),
            },
            "analytic": {
                "name": "Aegis Incident Commander",
                "uid": "aegis-commander",
                "type": "Synthesis"
            },
            "comment": f"escalated_to_human={escalate}"
        }

    elif stage == "policy":
        action = payload.get("action", {})
        decision = payload.get("decision", {})
        action_class = action.get("action_class", "")
        target = action.get("target", "")
        disposition = decision.get("disposition", "")
        reason = decision.get("reason", "")
        
        return {
            **base_event,
            "class_uid": 7001,
            "class_name": "Remediation Activity",
            "category_uid": 7,
            "category_name": "Remediation",
            "severity_id": 1,
            "severity": "Info",
            "finding_info": {
                "uid": finding_id
            },
            "remediation": {
                "action": action_class,
                "target": target,
                "desc": f"Policy decision: {disposition}. Reason: {reason}",
                "status": "Pending" if disposition == "requires_approval" else ("Success" if disposition == "auto_execute" else "Denied"),
                "status_id": 1 if disposition == "auto_execute" else (0 if disposition == "requires_approval" else 2)
            },
            "activity_id": 1,
            "activity_name": "Policy Evaluation"
        }

    elif stage == "containment":
        executed = payload.get("executed", False)
        dry_run = payload.get("dry_run", True)
        error = payload.get("error")
        
        status = "Success" if (executed and not error) else ("Dry-Run" if dry_run else "Failure")
        status_id = 1 if (executed and not error) else (0 if dry_run else 2)
        
        return {
            **base_event,
            "class_uid": 7001,
            "class_name": "Remediation Activity",
            "category_uid": 7,
            "category_name": "Remediation",
            "severity_id": 4 if error else 2,
            "severity": "High" if error else "Low",
            "finding_info": {
                "uid": finding_id
            },
            "remediation": {
                "action": payload.get("action_class", ""),
                "target": payload.get("target", ""),
                "desc": payload.get("detail", ""),
                "status": status,
                "status_id": status_id,
                "kb_article_list": [payload.get("rollback_hint", "")] if payload.get("rollback_hint") else []
            },
            "activity_id": 2,
            "activity_name": "Remediation Execution",
            "comment": f"dry_run={dry_run}, request_id={payload.get('request_id', '')}"
        }

    elif stage == "approval":
        decision = payload.get("decision", "")
        by = payload.get("by", "")
        reason = payload.get("reason", "")
        
        return {
            **base_event,
            "class_uid": 7001,
            "class_name": "Remediation Activity",
            "category_uid": 7,
            "category_name": "Remediation",
            "severity_id": 2,
            "severity": "Low",
            "finding_info": {
                "uid": finding_id
            },
            "remediation": {
                "action": payload.get("action_class", ""),
                "target": payload.get("target", ""),
                "desc": f"Human approval decision: {decision}. Reason: {reason}",
                "status": "Success" if decision == "approved" else "Denied",
                "status_id": 1 if decision == "approved" else 2
            },
            "actor": {
                "user": {
                    "name": by,
                    "type": "User"
                }
            },
            "activity_id": 3,
            "activity_name": "Operator Review"
        }

    elif stage == "governance":
        decision = payload.get("decision", "")
        action_class = payload.get("action_class", "")
        by = payload.get("by", "")
        reason = payload.get("reason", "")
        
        return {
            **base_event,
            "class_uid": 2003,
            "class_name": "Compliance Finding",
            "category_uid": 2,
            "category_name": "Findings",
            "severity_id": 2,
            "severity": "Low",
            "finding_info": {
                "uid": finding_id
            },
            "compliance": {
                "control": "Access Control policy change",
                "desc": f"Allowlist change: {decision} of {action_class} by {by}. Reason: {reason}",
                "status": "Success"
            },
            "actor": {
                "user": {
                    "name": by,
                    "type": "User"
                }
            }
        }

    elif stage == "forensics":
        items = payload.get("items", [])
        desc = f"Evidence collection. Preserved items: {', '.join(item.get('kind', '') for item in items)}"
        return {
            **base_event,
            "class_uid": 7001,
            "class_name": "Remediation Activity",
            "category_uid": 7,
            "category_name": "Remediation",
            "severity_id": 2,
            "severity": "Low",
            "finding_info": {
                "uid": finding_id
            },
            "remediation": {
                "action": "Evidence Collection",
                "target": finding_id,
                "desc": desc,
                "status": "Success",
                "status_id": 1
            },
            "activity_id": 2,
            "activity_name": "Evidence Gathering"
        }

    elif stage == "error":
        return {
            **base_event,
            "class_uid": 2004,
            "class_name": "Detection Finding",
            "category_uid": 2,
            "category_name": "Findings",
            "severity_id": 5,
            "severity": "Critical",
            "finding_info": {
                "uid": finding_id,
                "title": "Pipeline Execution Error",
                "desc": payload.get("error", "Unknown pipeline error"),
            },
            "analytic": {
                "name": "Aegis Orchestrator",
                "uid": "aegis-orchestrator",
                "type": "Error"
            }
        }

    return None
