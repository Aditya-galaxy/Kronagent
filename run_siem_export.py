#!/usr/bin/env python3
"""
Aegis — SIEM OCSF Export Utility.

Parses the cryptographic, hash-chained audit log and exports it as an 
OCSF-compliant JSONL file ready for ingestion into SIEMs like Splunk or Sentinel.
Verifies log chain integrity before execution to ensure no tampered logs are exported.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter

from aegis.audit import AuditLog
from aegis.config import Settings
from aegis.ocsf import to_ocsf_event


def main() -> int:
    parser = argparse.ArgumentParser(description="Export Aegis audit logs to OCSF JSONL format.")
    parser.add_argument(
        "--audit-log",
        type=str,
        default="",
        help="Path to the input hash-chained audit log. Defaults to active configuration log."
    )
    parser.add_argument(
        "--output",
        type=str,
        default="aegis_ocsf_export.jsonl",
        help="Path to write the OCSF-compliant export. Defaults to 'aegis_ocsf_export.jsonl'."
    )
    
    args = parser.parse_args()
    
    # Resolve input audit log path
    settings = Settings.from_env()
    log_path = args.audit_log or settings.audit_log_path
    
    if not os.path.exists(log_path):
        print(f"[-] Error: Audit log file '{log_path}' not found.")
        return 1
        
    print(f"[*] Verifying audit log cryptographic integrity: {log_path} ...")
    
    # 1. Verify log chain integrity
    verified, broken_line = AuditLog.verify(log_path)
    if not verified:
        print("\n" + "!" * 60)
        print(" [!] SECURITY ALERT: Cryptographic verification of the audit log FAILED!")
        print(f"     Tampering detected at log line: {broken_line}")
        print("     SIEM export aborted to prevent propagation of compromised logs.")
        print("!" * 60 + "\n")
        return 1
        
    print("[+] Audit log integrity verified. Generating OCSF export...")
    
    total_read = 0
    total_written = 0
    class_counts = Counter()
    
    try:
        with open(log_path, "r", encoding="utf-8") as infile, open(args.output, "w", encoding="utf-8") as outfile:
            for line in infile:
                line = line.strip()
                if not line:
                    continue
                total_read += 1
                try:
                    audit_line = json.loads(line)
                except json.JSONDecodeError as exc:
                    print(f"[-] Skipping corrupted JSON at line {total_read}: {exc}")
                    continue
                    
                ocsf_event = to_ocsf_event(audit_line)
                if ocsf_event is not None:
                    outfile.write(json.dumps(ocsf_event) + "\n")
                    total_written += 1
                    
                    class_name = ocsf_event.get("class_name", "Unknown Class")
                    class_uid = ocsf_event.get("class_uid", 0)
                    class_counts[f"{class_name} ({class_uid})"] += 1
            
            # Flush and sync
            outfile.flush()
            os.fsync(outfile.fileno())
        
    except Exception as exc:
        print(f"[-] Export failed: {exc}")
        return 1
        
    # Print metrics report
    print("\n" + "=" * 60)
    print("                      SIEM OCSF EXPORT REPORT")
    print("=" * 60)
    print(f"Audit Log verified: {log_path}")
    print(f"Export file written: {args.output}")
    print(f"Total audit lines read: {total_read}")
    print(f"Total OCSF events written: {total_written}")
    print("-" * 60)
    print("OCSF Event Classes Exported:")
    if not class_counts:
        print("  (None)")
    else:
        for cls_info, count in sorted(class_counts.items()):
            print(f"  * {cls_info}: {count}")
    print("=" * 60 + "\n")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
