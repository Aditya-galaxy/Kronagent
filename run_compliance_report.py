#!/usr/bin/env python3
"""
CLI script to generate EU AI Act Article 12/14 compliance report manifests.
"""

from __future__ import annotations

import argparse
import json
import sys

from aegis.config import Settings
from aegis.compliance import ComplianceExporter


def main() -> int:
    settings = Settings.from_env()

    parser = argparse.ArgumentParser(description="Generate EU AI Act compliance manifests.")
    parser.add_argument(
        "--audit-log",
        default=settings.audit_log_path,
        help="Path to the SHA-256 hash-chained JSONL audit log."
    )
    parser.add_argument(
        "--json-output",
        help="Path to write structured JSON report."
    )
    parser.add_argument(
        "--markdown-output",
        help="Path to write formatted Markdown compliance manifest."
    )
    args = parser.parse_args()

    exporter = ComplianceExporter(args.audit_log)
    report = exporter.generate_report()

    # Print summary to stdout
    integrity = report["audit_integrity"]
    summary = report["compliance_summary"]

    print("=" * 60)
    print("EU AI ACT ARTICLE 12/14 COMPLIANCE REPORT GENERATOR")
    print("=" * 60)

    if integrity["verified"]:
        print("✅ Cryptographic Chain Integrity: VERIFIED (Intact)")
    else:
        print(f"❌ Cryptographic Chain Integrity: COMPROMISED (Broken at line {integrity.get('first_broken_line')})")

    print(f"Total Findings Logged: {summary['total_findings']}")
    print(f"Autonomous Actions Executed: {summary['total_autonomous_actions']}")
    print(f"Human-Overseen Actions Approved: {summary['total_human_overridden_actions']}")
    print("=" * 60)

    # Write outputs
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"Structured JSON written to: {args.json_output}")

    if args.markdown_output:
        md = exporter.generate_markdown(report)
        with open(args.markdown_output, "w", encoding="utf-8") as fh:
            fh.write(md)
        print(f"Formatted Markdown manifest written to: {args.markdown_output}")

    return 0 if integrity["verified"] else 1


if __name__ == "__main__":
    sys.exit(main())
