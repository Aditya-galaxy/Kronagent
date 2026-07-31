#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com
"""
Kronagent kill-switch CLI — the operator's release valve.

The behavioral-trajectory guard latches a halt when it sees a runaway burst of
autonomous executions or repeated out-of-scope targeting. Latching is
deliberate: a halt that clears itself the moment the burst subsides is a speed
bump, not a kill switch. But a latch with no release procedure is an
availability risk of its own — and it undercuts the human-oversight story the
guard exists to strengthen. This CLI is that release procedure.

    python3 halt.py status
    python3 halt.py clear  --by alice --reason "investigated: runaway caused by a duplicated SQS batch, source fixed"
    python3 halt.py engage --by alice --reason "suspected compromise of the deploy pipeline; stopping all containment"

`clear` requires the PROMOTE permission — the same admin-only gate as granting
an action class autonomy. Releasing a platform-wide halt is at least as
consequential, so it is held to the same bar rather than to the approver bar.

Every engage and clear is written to the hash-chained audit log with who, when
and why. `engage` is the manual counterpart to an automatic halt: unlike the
`KRONAGENT_KILL_SWITCH` setting it needs no restart, and unlike that setting it
carries attribution.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

from kronagent.audit import AuditLog
from kronagent.config import Settings
from kronagent.identity import AuthContext, AuthorizationError, Permission, resolve_actor
from kronagent.schemas import AuditRecord
from kronagent.trajectory import TrajectoryStateStore


def _resolve(settings: Settings, audit: AuditLog, args: argparse.Namespace,
             required: Permission) -> AuthContext:
    """Resolve + authorize the acting operator; audit + exit(4) on failure."""
    try:
        return resolve_actor(
            registry_path=settings.operator_registry_path,
            required=required,
            by=getattr(args, "by", None),
            operator_id=getattr(args, "as_operator", None),
            token=getattr(args, "token", None) or os.getenv("KRONAGENT_OPERATOR_TOKEN"),
            oidc_issuer=settings.oidc_issuer,
            oidc_audience=settings.oidc_audience,
            oidc_jwks_uri=settings.oidc_jwks_uri,
            oidc_verify_signature=settings.oidc_verify_signature,
            oidc_roles_claim=settings.oidc_roles_claim,
        )
    except AuthorizationError as exc:
        asyncio.run(audit.record(AuditRecord(
            finding_id="_governance", stage="access_denied",
            payload={"command": args.command, "required": required.value,
                     "operator_id": getattr(args, "as_operator", None) or getattr(args, "by", None),
                     "error": str(exc)},
        )))
        print(f"ACCESS DENIED: {exc}", file=sys.stderr)
        raise SystemExit(4)


def _cmd_status(store: TrajectoryStateStore, settings: Settings) -> int:
    record = store.read()
    if record is None:
        print("trajectory guard: RUNNING — containment is not halted")
        print(f"  state file: {settings.trajectory_state_path or '(in-memory only)'}")
        return 0

    print("trajectory guard: ⛔ HALTED — all containment is blocked")
    print(f"  reason:      {record.reason}")
    print(f"  kind:        {record.kind}")
    print(f"  engaged at:  {record.engaged_at}")
    print(f"  engaged by:  {record.engaged_by}")
    if record.finding_id:
        print(f"  finding:     {record.finding_id}")
    if record.action_class:
        print(f"  action:      {record.action_class}")
    print()
    print("  Investigate before clearing. Release with:")
    print("    python3 halt.py clear --by <you> --reason \"<what you found>\"")
    # Non-zero so monitoring can alert on a halted platform without parsing text.
    return 1


def _cmd_clear(store: TrajectoryStateStore, audit: AuditLog, actor: AuthContext,
               reason: str) -> int:
    record = store.read()
    if record is None:
        print("nothing to clear — the trajectory guard is not halted")
        return 0

    store.clear()
    asyncio.run(audit.record(AuditRecord(
        finding_id="_governance", stage="governance",
        payload={
            "decision": "trajectory_halt_cleared",
            "cleared_reason": reason,
            "halt_reason": record.reason,
            "halt_kind": record.kind,
            "halt_engaged_at": record.engaged_at,
            "halt_finding_id": record.finding_id,
            **actor.audit_fields(),
        },
    )))
    print("✓ trajectory halt CLEARED — containment resumes")
    print(f"  was halted for: {record.reason}")
    print(f"  cleared by:     {actor.label}")
    print(f"  reason:         {reason}")
    print()
    print("  A running orchestrator picks this up on its next action — no restart needed.")
    return 0


def _cmd_engage(store: TrajectoryStateStore, audit: AuditLog, actor: AuthContext,
                reason: str) -> int:
    from kronagent.trajectory import HaltRecord

    existing = store.read()
    if existing is not None:
        print("already halted — leaving the existing halt in place")
        print(f"  reason: {existing.reason}")
        return 0

    record = store.engage(HaltRecord(reason=reason, kind="manual", engaged_by=actor.label))
    asyncio.run(audit.record(AuditRecord(
        finding_id="_governance", stage="governance",
        payload={"decision": "trajectory_halt_engaged", "reason": reason,
                 "kind": "manual", **actor.audit_fields()},
    )))
    print("⛔ trajectory halt ENGAGED — all containment is now blocked")
    print(f"  engaged by: {record.engaged_by}")
    print(f"  reason:     {reason}")
    print()
    print("  Release with:  python3 halt.py clear --by <you> --reason \"<...>\"")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inspect, engage or clear the Kronagent trajectory kill switch."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="show whether containment is halted, and why")

    for name, help_text in [
        ("clear", "release a latched halt (admin only)"),
        ("engage", "manually halt all containment (admin only)"),
    ]:
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--reason", required=True,
                       help="why (audited — this is the record an auditor reads)")
        p.add_argument("--by", help="operator identity, unauthenticated mode (audited)")
        p.add_argument("--as", dest="as_operator", help="authenticated operator id (enforced mode)")
        p.add_argument("--token", help="operator token (or set KRONAGENT_OPERATOR_TOKEN)")

    args = parser.parse_args()
    settings = Settings.from_env()
    audit = AuditLog(settings.audit_log_path)

    if not settings.trajectory_state_path:
        print("KRONAGENT_TRAJECTORY_STATE_PATH is empty — the guard is running in "
              "memory-only mode, so its halt cannot be inspected or cleared from "
              "another process.", file=sys.stderr)
        return 2

    store = TrajectoryStateStore(settings.trajectory_state_path)

    if args.command == "status":
        return _cmd_status(store, settings)

    actor = _resolve(settings, audit, args, Permission.PROMOTE)
    if args.command == "clear":
        return _cmd_clear(store, audit, actor, args.reason)
    if args.command == "engage":
        return _cmd_engage(store, audit, actor, args.reason)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
