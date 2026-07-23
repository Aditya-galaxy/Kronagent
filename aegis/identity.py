"""
Operator identity and role-based access control for the human-decision surface.

The platform's whole trust story rests on "a human decided this." Until now that
human was a free-text `--by alice` string: the hash-chained audit log faithfully
recorded *that* "alice" approved, but not that alice was really alice, or that
alice was *authorized* to approve. For an audited-human-oversight product (EU AI
Act Article 14) that's a hole in the load-bearing claim. This module closes it:

  * **Authentication** — an operator proves who they are (a token checked against
    a registry). The `IdentityProvider` protocol is the seam: the shipped
    `LocalIdentityProvider` is a registry + hashed tokens; a SAML/OIDC provider
    for enterprise SSO is a drop-in implementing the same protocol, no caller
    change.
  * **Authorization (RBAC)** — roles carry permissions. Approving an action needs
    APPROVE; promoting an action class to autonomy (the most consequential
    decision in the system) needs PROMOTE. Reading needs VIEW.
  * **Non-repudiation** — the decision is attributed in the tamper-evident audit
    log to a *verified, authorized* principal, and the record states whether the
    identity was verified or merely self-asserted.

Enforcement is registry-gated, so nothing breaks that doesn't opt in:
  * A registry is configured (AEGIS_OPERATOR_REGISTRY / settings.operator_registry_path)
    → **enforced mode**: every command authenticates, mutating commands are
    authorized, and audit records carry `identity_verified: true`.
  * No registry → **unauthenticated mode** (dev/demo/back-compat): the old
    free-text `--by` flow, and audit records carry `identity_verified: false`.
    The audit trail is honest about the strength of the identity behind each
    decision rather than silently treating a string as proof.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Permission(str, Enum):
    VIEW = "view"        # list / show the approval queue and allowlist
    APPROVE = "approve"  # approve or deny a pending containment action
    PROMOTE = "promote"  # promote/demote an action class (earn-trust governance)


# Roles are named permission bundles. Adding a role is adding an entry here;
# separation of duty is expressed by which permissions a role does NOT carry
# (an 'approver' can authorize an action but cannot grant a class autonomy).
_ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    "viewer": frozenset({Permission.VIEW}),
    "approver": frozenset({Permission.VIEW, Permission.APPROVE}),
    "admin": frozenset({Permission.VIEW, Permission.APPROVE, Permission.PROMOTE}),
}


def role_permissions(role: str) -> frozenset[Permission]:
    return _ROLE_PERMISSIONS.get(role, frozenset())


def known_roles() -> list[str]:
    return sorted(_ROLE_PERMISSIONS)


class Operator(BaseModel):
    operator_id: str
    display_name: str
    roles: list[str] = Field(default_factory=list)
    active: bool = True

    def permissions(self) -> frozenset[Permission]:
        perms: set[Permission] = set()
        for r in self.roles:
            perms |= role_permissions(r)
        return frozenset(perms)

    def can(self, permission: Permission) -> bool:
        return permission in self.permissions()


class AuthContext(BaseModel):
    """The resolved actor behind a command — verified or self-asserted. This is
    what gets written into the audit record, so the log carries the full
    provenance of every human decision."""

    operator_id: str
    display_name: str
    roles: list[str] = Field(default_factory=list)
    identity_verified: bool
    auth_method: str  # "local_token" | "unauthenticated"

    @property
    def label(self) -> str:
        """The `by=` attribution string used in human-facing output."""
        suffix = "" if self.identity_verified else " (unverified)"
        return f"{self.operator_id}{suffix}"

    def audit_fields(self) -> dict:
        return {
            "operator_id": self.operator_id,
            "display_name": self.display_name,
            "roles": self.roles,
            "identity_verified": self.identity_verified,
            "auth_method": self.auth_method,
        }


class AuthorizationError(Exception):
    """Authentication failed, or the operator lacks the required permission."""


# --------------------------------------------------------------------------- #
# Token hashing — tokens are stored only as salted-free SHA-256 hex; the raw
# token is never persisted. Comparison is constant-time.
# --------------------------------------------------------------------------- #

def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class LocalIdentityProvider:
    """Registry-backed identity provider. The registry is a JSON object:

        {
          "alice": {
            "display_name": "Alice Ng",
            "roles": ["admin"],
            "token_sha256": "<sha256 hex of the operator's token>",
            "active": true
          }
        }
    """

    def __init__(self, registry_path: str) -> None:
        self._path = registry_path

    def _load(self) -> dict[str, dict]:
        if not os.path.exists(self._path):
            return {}
        with open(self._path, "r", encoding="utf-8") as fh:
            try:
                return json.load(fh)
            except json.JSONDecodeError:
                return {}

    def authenticate(self, operator_id: str, token: Optional[str]) -> Optional[Operator]:
        record = self._load().get(operator_id)
        if record is None or not record.get("active", True):
            return None
        expected = record.get("token_sha256", "")
        if not token or not expected:
            return None
        # Constant-time comparison to avoid leaking the hash via timing.
        if not hmac.compare_digest(hash_token(token), expected):
            return None
        return Operator(
            operator_id=operator_id,
            display_name=record.get("display_name", operator_id),
            roles=list(record.get("roles", [])),
            active=bool(record.get("active", True)),
        )


def registry_configured(registry_path: str) -> bool:
    return bool(registry_path) and os.path.exists(registry_path)


def resolve_actor(
    *,
    registry_path: str,
    required: Permission,
    by: Optional[str] = None,
    operator_id: Optional[str] = None,
    token: Optional[str] = None,
) -> AuthContext:
    """Resolve and authorize the operator behind a command.

    Enforced mode (registry configured): authenticate `operator_id` + `token`,
    then require `required`. Raises AuthorizationError on any failure.

    Unauthenticated mode (no registry): return a self-asserted context from
    `by`, marked identity_verified=False. No permission is enforced because
    there is no identity to enforce it against — the audit record makes that
    explicit rather than pretending otherwise.
    """
    if registry_configured(registry_path):
        if not operator_id:
            raise AuthorizationError(
                "authentication required — an operator registry is configured. "
                "Pass --as <operator_id> and a token (--token or AEGIS_OPERATOR_TOKEN)."
            )
        operator = LocalIdentityProvider(registry_path).authenticate(operator_id, token)
        if operator is None:
            raise AuthorizationError(f"authentication failed for operator '{operator_id}'.")
        if not operator.can(required):
            raise AuthorizationError(
                f"operator '{operator_id}' (roles: {operator.roles or 'none'}) "
                f"lacks the '{required.value}' permission required for this action."
            )
        return AuthContext(
            operator_id=operator.operator_id,
            display_name=operator.display_name,
            roles=operator.roles,
            identity_verified=True,
            auth_method="local_token",
        )

    # Unauthenticated fallback.
    if not by:
        raise AuthorizationError(
            "--by <operator> is required (no operator registry configured)."
        )
    return AuthContext(
        operator_id=by,
        display_name=by,
        roles=[],
        identity_verified=False,
        auth_method="unauthenticated",
    )
