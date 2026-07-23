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
import os
import sys

from aegis.allowlist import AllowlistStore
from aegis.audit import AuditLog
from aegis.config import Settings
from aegis.identity import AuthContext, AuthorizationError, Permission, resolve_actor
from aegis.policy import PolicyEngine
from aegis.schemas import ActionClass, AuditRecord


def _resolve(settings: Settings, audit: AuditLog, args: argparse.Namespace,
             required: Permission) -> AuthContext:
    """Resolve + authorize the acting operator; audit + exit(4) on failure."""
    try:
        return resolve_actor(
            registry_path=settings.operator_registry_path,
            required=required,
            by=getattr(args, "by", None),
            operator_id=getattr(args, "as_operator", None),
            token=getattr(args, "token", None) or os.getenv("AEGIS_OPERATOR_TOKEN"),
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
                     "action_class": getattr(args, "action_class", None),
                     "operator_id": getattr(args, "as_operator", None) or getattr(args, "by", None),
                     "error": str(exc)},
        )))
        print(f"ACCESS DENIED: {exc}", file=sys.stderr)
        raise SystemExit(4)


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


def cmd_add(store: AllowlistStore, audit: AuditLog, settings: Settings,
            actor: AuthContext, args: argparse.Namespace) -> int:
    ac = _parse_action_class(args.action_class)
    policy = PolicyEngine(settings, store)
    entry = asyncio.run(store.add(ac, by=actor.operator_id, reason=args.reason, audit=audit,
                                  actor_fields=actor.audit_fields()))
    print(f"Promoted {entry.action_class} to autonomous execution (by {actor.label}).")
    if not policy.is_auto_eligible(ac):
        print(f"  ⚠ WARNING: {ac.value} is classified destructive or wide-blast-radius by the "
              f"policy engine — it will still route to human approval regardless of this "
              f"allowlist entry. The promotion is recorded but has no effect.")
    return 0


def cmd_remove(store: AllowlistStore, audit: AuditLog, actor: AuthContext,
               args: argparse.Namespace) -> int:
    ac = _parse_action_class(args.action_class)
    existed = asyncio.run(store.remove(ac, by=actor.operator_id, reason=args.reason, audit=audit,
                                       actor_fields=actor.audit_fields()))
    if existed:
        print(f"Demoted {ac.value} (by {actor.label}) — now requires human approval again.")
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

    # Governance is the most consequential action in the system, so it requires
    # the PROMOTE permission (admin) in enforced mode. In unauthenticated mode
    # (no registry) it falls back to free-text --by, audited as unverified.
    def _add_identity(p: argparse.ArgumentParser) -> None:
        p.add_argument("--by", help="operator identity, unauthenticated mode (audited)")
        p.add_argument("--as", dest="as_operator", help="authenticated operator id (enforced mode)")
        p.add_argument("--token", help="operator token (or set AEGIS_OPERATOR_TOKEN)")

    p_add = sub.add_parser("add", help="promote an action class to autonomous execution")
    p_add.add_argument("action_class")
    _add_identity(p_add)
    p_add.add_argument("--reason", required=True, help="why this class has earned trust (audited)")

    p_rm = sub.add_parser("remove", help="demote an action class back to requiring approval")
    p_rm.add_argument("action_class")
    _add_identity(p_rm)
    p_rm.add_argument("--reason", required=True, help="why this class is being demoted (audited)")

    args = parser.parse_args()
    if args.command == "list":
        return cmd_list(store, settings)
    if args.command == "add":
        actor = _resolve(settings, audit, args, Permission.PROMOTE)
        return cmd_add(store, audit, settings, actor, args)
    if args.command == "remove":
        actor = _resolve(settings, audit, args, Permission.PROMOTE)
        return cmd_remove(store, audit, actor, args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
