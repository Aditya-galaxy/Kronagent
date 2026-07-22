"""
Compliance engine for exporting EU AI Act Article 12/14 compliance report manifests.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Optional

from .audit import AuditLog


class ComplianceExporter:
    """Parses hash-chained audit log records and compiles EU AI Act compliance telemetry."""

    def __init__(self, audit_log_path: str) -> None:
        self.audit_log_path = audit_log_path

    def generate_report(self) -> dict[str, Any]:
        """Verify the integrity of the audit log chain and extract high-risk AI governance events."""
        # 1. Cryptographic chain integrity check (Article 12)
        verified, broken_line = AuditLog.verify(self.audit_log_path)

        findings: dict[str, dict[str, Any]] = {}

        if not os.path.exists(self.audit_log_path):
            return {
                "audit_integrity": {
                    "verified": True,
                    "reason": "Audit log file not found (empty log is verified)",
                    "timestamp_verified": datetime.now(timezone.utc).isoformat(),
                },
                "compliance_summary": {
                    "total_findings": 0,
                    "total_autonomous_actions": 0,
                    "total_human_overridden_actions": 0,
                },
                "findings": [],
            }

        with open(self.audit_log_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    envelope = json.loads(line)
                except json.JSONDecodeError:
                    continue

                rec = envelope.get("record", {})
                fid = rec.get("finding_id")
                if not fid:
                    continue

                stage = rec.get("stage")
                ts = rec.get("ts")
                payload = rec.get("payload", {})

                if fid not in findings:
                    findings[fid] = {
                        "finding_id": fid,
                        "ingested_at": ts,
                        "triage": None,
                        "intel": None,
                        "correlation": None,
                        "command": None,
                        "forensics": [],
                        "policy_decisions": [],
                        "containment_executions": [],
                        "approval_decisions": [],
                    }

                if stage == "triage":
                    findings[fid]["triage"] = {
                        "timestamp": ts,
                        "severity": payload.get("severity"),
                        "rationale": payload.get("rationale"),
                    }
                elif stage == "intel":
                    findings[fid]["intel"] = {
                        "timestamp": ts,
                        "threat_intel_summary": payload.get("threat_intel_summary"),
                        "mitre_techniques": payload.get("mitre_techniques", []),
                    }
                elif stage == "correlation":
                    findings[fid]["correlation"] = {
                        "timestamp": ts,
                        "part_of_campaign": payload.get("part_of_campaign", False),
                        "related_finding_ids": payload.get("related_finding_ids", []),
                        "correlation_summary": payload.get("correlation_summary"),
                    }
                elif stage == "command":
                    findings[fid]["command"] = {
                        "timestamp": ts,
                        "priority": payload.get("priority"),
                        "escalate_to_human_now": payload.get("escalate_to_human_now", False),
                        "incident_narrative": payload.get("incident_narrative"),
                    }
                elif stage == "forensics":
                    # Collect preserved forensic telemetry
                    items = payload.get("items", [])
                    for item in items:
                        findings[fid]["forensics"].append({
                            "timestamp": ts,
                            "kind": item.get("kind"),
                            "custody_sha256": item.get("custody_sha256"),
                        })
                elif stage == "policy":
                    action = payload.get("action", {})
                    decision = payload.get("decision", {})
                    findings[fid]["policy_decisions"].append({
                        "timestamp": ts,
                        "action_class": action.get("action_class"),
                        "target": action.get("target"),
                        "disposition": decision.get("disposition"),
                        "reason": decision.get("reason"),
                        "reversible": decision.get("reversible"),
                        "blast_radius": decision.get("blast_radius"),
                    })
                elif stage == "approval":
                    findings[fid]["approval_decisions"].append({
                        "timestamp": ts,
                        "request_id": payload.get("request_id"),
                        "decision": payload.get("decision"),
                        "by": payload.get("by"),
                        "reason": payload.get("reason"),
                        "action_class": payload.get("action_class"),
                        "target": payload.get("target"),
                    })
                elif stage == "containment":
                    findings[fid]["containment_executions"].append({
                        "timestamp": ts,
                        "action_class": payload.get("action_class"),
                        "target": payload.get("target"),
                        "executed": payload.get("executed", False),
                        "dry_run": payload.get("dry_run", True),
                        "detail": payload.get("detail"),
                        "rollback_hint": payload.get("rollback_hint"),
                        "request_id": payload.get("request_id"),
                    })

        # Compile summaries
        total_autonomous = 0
        total_human_overridden = 0

        for f in findings.values():
            # Check policy dispositions
            for pol in f["policy_decisions"]:
                if pol.get("disposition") == "auto_execute":
                    total_autonomous += 1
                elif pol.get("disposition") == "requires_approval":
                    # Check if an approval exists for this target
                    approvals = [
                        app for app in f["approval_decisions"]
                        if app.get("action_class") == pol.get("action_class")
                        and app.get("target") == pol.get("target")
                    ]
                    if approvals and any(a.get("decision") == "approved" for a in approvals):
                        total_human_overridden += 1

        return {
            "audit_integrity": {
                "verified": verified,
                "first_broken_line": broken_line,
                "timestamp_verified": datetime.now(timezone.utc).isoformat(),
            },
            "compliance_summary": {
                "total_findings": len(findings),
                "total_autonomous_actions": total_autonomous,
                "total_human_overridden_actions": total_human_overridden,
            },
            "findings": list(findings.values()),
        }

    def generate_markdown(self, report: dict[str, Any]) -> str:
        """Constructs a clean human-readable compliance manifest in Markdown."""
        md = []
        md.append("# EU AI Act Article 12/14 Compliance Manifest")
        md.append("")
        md.append(f"**Report Generated At:** {datetime.now(timezone.utc).isoformat()}")
        md.append("")

        # Article 12 Chain Audit
        integrity = report["audit_integrity"]
        md.append("## 1. Audit Chain Integrity Verification (Article 12)")
        md.append("")
        if integrity["verified"]:
            md.append("> [!NOTE]")
            md.append("> **✅ VERIFIED:** The append-only, SHA-256 hash-chained audit trail is fully intact.")
            md.append("> No modifications, deletions, or insertions have been detected.")
        else:
            md.append("> [!CAUTION]")
            md.append(f"> **❌ INTEGRITY VIOLATION:** Verification failed at line {integrity.get('first_broken_line')}.")
            md.append("> Telemetry data has been modified post-record.")
        md.append("")

        # Metrics
        summary = report["compliance_summary"]
        md.append("## 2. Platform Summary Metrics")
        md.append("")
        md.append(f"| Metric | Count |")
        md.append(f"| :--- | :--- |")
        md.append(f"| Total Security Findings Logged | {summary['total_findings']} |")
        md.append(f"| Autonomous Actions Executed | {summary['total_autonomous_actions']} |")
        md.append(f"| Human-Overseen Actions Approved | {summary['total_human_overridden_actions']} |")
        md.append("")

        # Article 14 Human Oversight Log
        md.append("## 3. Incident Lifecycles & Human Oversight Log (Article 14)")
        md.append("")
        if not report["findings"]:
            md.append("No incident findings recorded in this audit log.")
            return "\n".join(md)

        for idx, f in enumerate(report["findings"], start=1):
            md.append(f"### Finding {idx}: `{f['finding_id']}`")
            md.append(f"- **Ingested Timestamp:** `{f['ingested_at']}`")

            # Triage & Threat Intel
            tr = f["triage"]
            intel = f["intel"]
            if tr:
                md.append(f"  * **Triage Analysis:** Severity `{tr['severity']}` — Rationale: *{tr['rationale']}*")
            if intel:
                md.append(f"  * **Threat Intelligence:** {intel['threat_intel_summary']}")
                if intel.get("mitre_techniques"):
                    md.append(f"    * MITRE ATT&CK: {', '.join(intel['mitre_techniques'])}")

            # Correlation
            corr = f["correlation"]
            if corr and corr.get("part_of_campaign"):
                md.append(f"  * **Campaign Linkage:** Part of campaign (Related: `{corr['related_finding_ids']}`)")
                md.append(f"    * Context: *{corr['correlation_summary']}*")

            # Forensics Custody Chain
            forensics = f["forensics"]
            if forensics:
                md.append("  * **Forensic Evidence Gathered (Article 12):**")
                for item in forensics:
                    md.append(f"    * `[{item['kind']}]` Custody SHA-256: `{item['custody_sha256'][:16]}...`")

            # Policy Decisions
            policy = f["policy_decisions"]
            if policy:
                md.append("  * **Policy Decisions & Human Oversight:**")
                for pol in policy:
                    mode = "Autonomous" if pol["disposition"] == "auto_execute" else "Human-in-the-Loop Gated"
                    md.append(f"    * **Action:** `{pol['action_class']}` on `{pol['target']}`")
                    md.append(f"    * **Handoff Mode:** {mode} (Reason: *{pol['reason']}*)")
                    md.append(f"    * **Blast Radius:** `{pol['blast_radius']}` | **Reversible:** `{pol['reversible']}`")

            # Approvals (Human override details)
            approvals = f["approval_decisions"]
            if approvals:
                md.append("  * **Operator Overrides (Article 14 Human Sign-off):**")
                for app in approvals:
                    md.append(f"    * **Decision:** `{app['decision'].upper()}` by operator `{app['by']}`")
                    md.append(f"    * **Rationale:** *{app['reason']}*")
                    md.append(f"    * **Decision Time:** `{app['timestamp']}`")

            # Executed containment outcome
            executions = f["containment_executions"]
            if executions:
                md.append("  * **Executed Containment Actions:**")
                for ex in executions:
                    status = "Success" if ex["executed"] else "Dry-Run / Pending"
                    md.append(f"    * **Target:** `{ex['action_class']}` against `{ex['target']}`")
                    md.append(f"    * **Execution Status:** `{status}`")
                    md.append(f"    * **Details:** *{ex['detail']}*")
                    if ex.get("rollback_hint"):
                        md.append(f"    * **Rollback Target:** `{ex['rollback_hint']}`")

            md.append("")
            md.append("---")
            md.append("")

        return "\n".join(md)
