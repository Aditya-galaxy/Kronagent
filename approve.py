#!/usr/bin/env python3
"""
Aegis operator CLI — the human end of the earn-trust loop.

An action the policy engine could not clear for autonomy waits in the approval
store. An operator reviews it here and either authorizes execution (with
attribution and a reason, both audited) or denies it.

    python3 approve.py list                       # pending actions
    python3 approve.py list --all                 # every request, any status
    python3 approve.py show <request_id>          # full detail + planned calls
    python3 approve.py approve <request_id> --by alice --reason "confirmed malicious"
    python3 approve.py deny    <request_id> --by alice --reason "false positive"

Approval executes the action through the same containment executor the
autonomous path uses, so it honors dry_run and the kill switch: in dry-run,
approval validates the flow without touching AWS; with the kill switch on,
execution is refused outright.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from aegis.approvals import ApprovalStore, now_iso
from aegis.audit import AuditLog
from aegis.config import Settings
from aegis.containment import ContainmentExecutor
from aegis.providers import build_containment_adapters
from aegis.schemas import AuditRecord, BlastRadius, PolicyDecision


def _fmt(r) -> str:
    return (f"{r.request_id}  [{r.status}]  {r.action_class.value} on {r.target}\n"
            f"    finding {r.finding_id} ({r.finding_type}), severity {r.severity}\n"
            f"    reason: {r.policy_reason}\n"
            f"    reversible={r.reversible} blast={r.blast_radius}")


def cmd_list(store: ApprovalStore, args: argparse.Namespace) -> int:
    items = store.list(status=None if args.all else "pending")
    if not items:
        print("No pending approval requests." if not args.all else "No approval requests.")
        return 0
    for r in items:
        print(_fmt(r))
        print()
    return 0


def cmd_show(store: ApprovalStore, args: argparse.Namespace) -> int:
    r = store.get(args.request_id)
    if r is None:
        print(f"No such request: {args.request_id}", file=sys.stderr)
        return 2
    print(_fmt(r))
    if r.threat_intel_summary or r.mitre_techniques:
        techniques = ", ".join(r.mitre_techniques) or "none mapped"
        print(f"    threat intel: {r.threat_intel_summary}")
        print(f"    MITRE ATT&CK: {techniques}")
    print("    planned API calls:")
    for c in r.planned_api_calls:
        print(f"      $ {c}")
    print(f"    rollback: {r.rollback_hint}")
    if r.decided_by:
        print(f"    decided by {r.decided_by} at {r.decided_at}: {r.decision_reason}")
    if r.execution_detail:
        print(f"    execution: {r.execution_detail}")
    return 0


def cmd_deny(store: ApprovalStore, audit: AuditLog, args: argparse.Namespace) -> int:
    r = store.get(args.request_id)
    if r is None:
        print(f"No such request: {args.request_id}", file=sys.stderr)
        return 2
    if r.status != "pending":
        print(f"Request {r.request_id} is '{r.status}', not pending — cannot deny.", file=sys.stderr)
        return 2
    r.status = "denied"
    r.decided_by = args.by
    r.decided_at = now_iso()
    r.decision_reason = args.reason
    store.update(r)
    asyncio.run(audit.record(AuditRecord(
        finding_id=r.finding_id, stage="approval",
        payload={"request_id": r.request_id, "decision": "denied",
                 "by": args.by, "reason": args.reason,
                 "action_class": r.action_class.value, "target": r.target},
    )))
    print(f"Denied {r.request_id} ({r.action_class.value} on {r.target}) — recorded.")
    return 0


def cmd_approve(store: ApprovalStore, audit: AuditLog, settings: Settings,
                args: argparse.Namespace) -> int:
    r = store.get(args.request_id)
    if r is None:
        print(f"No such request: {args.request_id}", file=sys.stderr)
        return 2
    if r.status != "pending":
        print(f"Request {r.request_id} is '{r.status}', not pending — cannot approve.", file=sys.stderr)
        return 2

    if settings.kill_switch:
        print("KILL SWITCH ENGAGED — execution refused. Disengage AEGIS_KILL_SWITCH to proceed.",
              file=sys.stderr)
        return 3

    # Human authorization is the grant: synthesize an auto_execute decision.
    decision = PolicyDecision(
        action_class=r.action_class,
        disposition="auto_execute",
        reason=f"human-approved by {args.by}: {args.reason}",
        reversible=r.reversible,
        blast_radius=BlastRadius(r.blast_radius),
    )
    action = r.to_proposed_action()
    containment = ContainmentExecutor(settings, build_containment_adapters(settings))

    # Record the approval decision BEFORE execution, then the outcome after.
    async def _run():
        await audit.record(AuditRecord(
            finding_id=r.finding_id, stage="approval",
            payload={"request_id": r.request_id, "decision": "approved",
                     "by": args.by, "reason": args.reason,
                     "action_class": r.action_class.value, "target": r.target},
        ))
        outcome = await containment.execute(action, decision)
        await audit.record(AuditRecord(
            finding_id=r.finding_id, stage="containment",
            payload={"request_id": r.request_id, **outcome.model_dump()},
        ))
        return outcome

    outcome = asyncio.run(_run())

    r.decided_by = args.by
    r.decided_at = now_iso()
    r.decision_reason = args.reason
    r.execution_detail = outcome.detail
    if outcome.executed:
        r.status = "executed"
    elif outcome.error:
        r.status = "failed"
    else:
        # dry-run: authorized but not actually executed
        r.status = "approved"
    store.update(r)

    print(f"Approved {r.request_id} by {args.by}.")
    print(f"  {outcome.detail}")
    print(f"  rollback: {outcome.rollback_hint}")
    if r.status == "approved":
        print("  (DRY-RUN active — action authorized but not executed. "
              "Set AEGIS_DRY_RUN=false to execute for real.)")
    return 0


def main() -> int:
    settings = Settings.from_env()
    store = ApprovalStore(settings.approval_store_path)
    audit = AuditLog(settings.audit_log_path)

    parser = argparse.ArgumentParser(description="Aegis approval CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="list pending (or all) approval requests")
    p_list.add_argument("--all", action="store_true", help="show requests of every status")

    p_show = sub.add_parser("show", help="show one request in full")
    p_show.add_argument("request_id")

    p_appr = sub.add_parser("approve", help="authorize and execute an action")
    p_appr.add_argument("request_id")
    p_appr.add_argument("--by", required=True, help="operator identity (audited)")
    p_appr.add_argument("--reason", required=True, help="justification (audited)")

    p_deny = sub.add_parser("deny", help="reject an action")
    p_deny.add_argument("request_id")
    p_deny.add_argument("--by", required=True, help="operator identity (audited)")
    p_deny.add_argument("--reason", required=True, help="justification (audited)")

    args = parser.parse_args()
    if args.command == "list":
        return cmd_list(store, args)
    if args.command == "show":
        return cmd_show(store, args)
    if args.command == "approve":
        return cmd_approve(store, audit, settings, args)
    if args.command == "deny":
        return cmd_deny(store, audit, args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
