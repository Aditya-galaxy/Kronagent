#!/usr/bin/env python3
"""
Aegis governance CLI — the earn-trust dial.

Promotes or demotes an action class between "always needs human approval" and
"executes autonomously when auto-eligible." This is the single most
consequential decision the platform's operators make — it's what decides
whether a class of action runs unattended against production — so every
change here is written to the hash-chained audit log with who made it and why,
same as an approval decision.

    python3 promote.py list
    python3 promote.py add    disable_access_key --by alice --reason "30 days incident-free, low blast radius"
    python3 promote.py remove disable_access_key --by alice --reason "false-positive rate too high"

A promotion only has effect for action classes the policy engine already
classifies AUTO_ELIGIBLE (reversible, single-resource, non-destructive) — see
policy.py. Promoting a destructive or wide-blast-radius class is accepted (the
store doesn't second-guess an operator) but has no effect: the policy engine's
own classification is the hard ceiling, so an operator error here degrades to
"still requires approval," not "now executes something dangerous."
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from aegis.allowlist import AllowlistStore
from aegis.audit import AuditLog
from aegis.config import Settings
from aegis.policy import PolicyEngine
from aegis.schemas import ActionClass


def _parse_action_class(raw: str) -> ActionClass:
    try:
        return ActionClass(raw)
    except ValueError:
        valid = ", ".join(ac.value for ac in ActionClass)
        print(f"Unknown action class '{raw}'. Valid values: {valid}", file=sys.stderr)
        raise SystemExit(2)


def cmd_list(store: AllowlistStore, settings: Settings) -> int:
    entries = store.list()
    if not entries:
        print("Allowlist is EMPTY — every action requires human approval.")
        return 0
    policy = PolicyEngine(settings, store)
    print("Auto-execute allowlist:")
    for e in entries:
        ac = ActionClass(e.action_class)
        eligible = policy.is_auto_eligible(ac)
        flag = "" if eligible else "  ⚠ NOT auto-eligible (policy engine overrides — still requires approval)"
        print(f"  {e.action_class:32} added by {e.added_by} at {e.added_at}{flag}")
        print(f"      reason: {e.reason}")
    return 0


def cmd_add(store: AllowlistStore, audit: AuditLog, settings: Settings, args: argparse.Namespace) -> int:
    ac = _parse_action_class(args.action_class)
    policy = PolicyEngine(settings, store)
    entry = asyncio.run(store.add(ac, by=args.by, reason=args.reason, audit=audit))
    print(f"Promoted {entry.action_class} to autonomous execution (by {entry.added_by}).")
    if not policy.is_auto_eligible(ac):
        print(f"  ⚠ WARNING: {ac.value} is classified destructive or wide-blast-radius by the "
              f"policy engine — it will still route to human approval regardless of this "
              f"allowlist entry. The promotion is recorded but has no effect.")
    return 0


def cmd_remove(store: AllowlistStore, audit: AuditLog, args: argparse.Namespace) -> int:
    ac = _parse_action_class(args.action_class)
    existed = asyncio.run(store.remove(ac, by=args.by, reason=args.reason, audit=audit))
    if existed:
        print(f"Demoted {ac.value} — now requires human approval again.")
    else:
        print(f"{ac.value} was not on the allowlist (no-op, still recorded for the audit trail).")
    return 0


def main() -> int:
    settings = Settings.from_env()
    store = AllowlistStore(settings.allowlist_store_path, seed=settings.auto_execute_allowlist)
    audit = AuditLog(settings.audit_log_path)

    parser = argparse.ArgumentParser(description="Aegis earn-trust governance CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="show the current auto-execute allowlist")

    p_add = sub.add_parser("add", help="promote an action class to autonomous execution")
    p_add.add_argument("action_class")
    p_add.add_argument("--by", required=True, help="operator identity (audited)")
    p_add.add_argument("--reason", required=True, help="why this class has earned trust (audited)")

    p_rm = sub.add_parser("remove", help="demote an action class back to requiring approval")
    p_rm.add_argument("action_class")
    p_rm.add_argument("--by", required=True, help="operator identity (audited)")
    p_rm.add_argument("--reason", required=True, help="why this class is being demoted (audited)")

    args = parser.parse_args()
    if args.command == "list":
        return cmd_list(store, settings)
    if args.command == "add":
        return cmd_add(store, audit, settings, args)
    if args.command == "remove":
        return cmd_remove(store, audit, args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
