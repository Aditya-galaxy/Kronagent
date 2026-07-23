"""
Operator identity + RBAC.

The load-bearing properties: authentication actually verifies the token, RBAC
actually gates by permission (an approver cannot promote), and the resolved
AuthContext honestly records whether the identity was verified — which is what
makes the audit log's attribution trustworthy rather than a free-text claim.
"""

from __future__ import annotations

import json

import pytest

from aegis.identity import (
    AuthContext,
    AuthorizationError,
    LocalIdentityProvider,
    Operator,
    Permission,
    hash_token,
    known_roles,
    resolve_actor,
    role_permissions,
)


def _write_registry(path, operators: dict) -> str:
    path.write_text(json.dumps(operators))
    return str(path)


def _registry(tmp_path, **ops) -> str:
    """ops: operator_id -> (roles, token, active=True)."""
    data = {}
    for oid, spec in ops.items():
        roles, token = spec[0], spec[1]
        active = spec[2] if len(spec) > 2 else True
        data[oid] = {"display_name": oid.title(), "roles": roles,
                     "token_sha256": hash_token(token), "active": active}
    return _write_registry(tmp_path / "ops.json", data)


# --------------------------------------------------------------------------- #
# Roles / permissions
# --------------------------------------------------------------------------- #

def test_role_permission_matrix() -> None:
    assert Permission.PROMOTE in role_permissions("admin")
    assert Permission.APPROVE in role_permissions("approver")
    assert Permission.PROMOTE not in role_permissions("approver")   # the key SoD line
    assert role_permissions("viewer") == frozenset({Permission.VIEW})
    assert role_permissions("nonexistent-role") == frozenset()


def test_operator_permissions_union_across_roles() -> None:
    op = Operator(operator_id="x", display_name="X", roles=["viewer", "approver"])
    assert op.can(Permission.VIEW)
    assert op.can(Permission.APPROVE)
    assert not op.can(Permission.PROMOTE)


def test_known_roles_stable() -> None:
    assert set(known_roles()) == {"viewer", "approver", "admin"}


# --------------------------------------------------------------------------- #
# Authentication (LocalIdentityProvider)
# --------------------------------------------------------------------------- #

def test_authenticate_success(tmp_path) -> None:
    reg = _registry(tmp_path, alice=(["admin"], "s3cr3t"))
    op = LocalIdentityProvider(reg).authenticate("alice", "s3cr3t")
    assert op is not None and op.operator_id == "alice" and "admin" in op.roles


def test_authenticate_wrong_token(tmp_path) -> None:
    reg = _registry(tmp_path, alice=(["admin"], "s3cr3t"))
    assert LocalIdentityProvider(reg).authenticate("alice", "wrong") is None


def test_authenticate_missing_token(tmp_path) -> None:
    reg = _registry(tmp_path, alice=(["admin"], "s3cr3t"))
    assert LocalIdentityProvider(reg).authenticate("alice", None) is None


def test_authenticate_unknown_operator(tmp_path) -> None:
    reg = _registry(tmp_path, alice=(["admin"], "s3cr3t"))
    assert LocalIdentityProvider(reg).authenticate("mallory", "s3cr3t") is None


def test_authenticate_disabled_operator_is_rejected(tmp_path) -> None:
    reg = _registry(tmp_path, bob=(["approver"], "tok", False))
    assert LocalIdentityProvider(reg).authenticate("bob", "tok") is None


def test_raw_token_is_never_stored(tmp_path) -> None:
    reg = _registry(tmp_path, alice=(["admin"], "supersecret"))
    raw = (tmp_path / "ops.json").read_text()
    assert "supersecret" not in raw
    assert hash_token("supersecret") in raw


# --------------------------------------------------------------------------- #
# resolve_actor — the enforcement entry point
# --------------------------------------------------------------------------- #

def test_unauthenticated_mode_uses_by_and_marks_unverified() -> None:
    ctx = resolve_actor(registry_path="", required=Permission.PROMOTE, by="alice")
    assert ctx.identity_verified is False
    assert ctx.operator_id == "alice"
    assert ctx.auth_method == "unauthenticated"
    assert "unverified" in ctx.label


def test_unauthenticated_mode_requires_by() -> None:
    with pytest.raises(AuthorizationError):
        resolve_actor(registry_path="", required=Permission.APPROVE)


def test_enforced_mode_rejects_unauthenticated_attempt(tmp_path) -> None:
    reg = _registry(tmp_path, alice=(["admin"], "tok"))
    # --by with no token, but a registry is configured -> must authenticate.
    with pytest.raises(AuthorizationError, match="authentication required"):
        resolve_actor(registry_path=reg, required=Permission.PROMOTE, by="alice")


def test_enforced_mode_admin_can_promote(tmp_path) -> None:
    reg = _registry(tmp_path, alice=(["admin"], "tok"))
    ctx = resolve_actor(registry_path=reg, required=Permission.PROMOTE,
                        operator_id="alice", token="tok")
    assert ctx.identity_verified is True
    assert ctx.auth_method == "local_token"
    assert ctx.operator_id == "alice"


def test_enforced_mode_approver_cannot_promote(tmp_path) -> None:
    """The RBAC line that matters: authenticating is not the same as being
    authorized. bob is real, but lacks PROMOTE."""
    reg = _registry(tmp_path, bob=(["approver"], "tok"))
    with pytest.raises(AuthorizationError, match="lacks the 'promote' permission"):
        resolve_actor(registry_path=reg, required=Permission.PROMOTE,
                      operator_id="bob", token="tok")


def test_enforced_mode_approver_can_approve(tmp_path) -> None:
    reg = _registry(tmp_path, bob=(["approver"], "tok"))
    ctx = resolve_actor(registry_path=reg, required=Permission.APPROVE,
                        operator_id="bob", token="tok")
    assert ctx.identity_verified is True and ctx.operator_id == "bob"


def test_enforced_mode_bad_token_is_rejected(tmp_path) -> None:
    reg = _registry(tmp_path, alice=(["admin"], "tok"))
    with pytest.raises(AuthorizationError, match="authentication failed"):
        resolve_actor(registry_path=reg, required=Permission.PROMOTE,
                      operator_id="alice", token="WRONG")


def test_verified_context_label_has_no_unverified_suffix(tmp_path) -> None:
    reg = _registry(tmp_path, alice=(["admin"], "tok"))
    ctx = resolve_actor(registry_path=reg, required=Permission.PROMOTE,
                        operator_id="alice", token="tok")
    assert ctx.label == "alice"  # no "(unverified)"


def test_audit_fields_capture_provenance() -> None:
    ctx = AuthContext(operator_id="alice", display_name="Alice", roles=["admin"],
                      identity_verified=True, auth_method="local_token")
    fields = ctx.audit_fields()
    assert fields["operator_id"] == "alice"
    assert fields["roles"] == ["admin"]
    assert fields["identity_verified"] is True
    assert fields["auth_method"] == "local_token"


# --------------------------------------------------------------------------- #
# OIDC SSO Authentication Tests
# --------------------------------------------------------------------------- #

import base64
import time
from aegis.identity import base64url_decode, OidcIdentityProvider

def _encode_jwt_parts(header: dict, payload: dict) -> str:
    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode("utf-8")).decode("utf-8").rstrip("=")
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8").rstrip("=")
    return f"{h_b64}.{p_b64}.dummy_signature"


def test_base64url_decode() -> None:
    # "abc" is encoded as "YWJj"
    assert base64url_decode("YWJj") == "abc"


def test_oidc_authenticate_success() -> None:
    payload = {
        "iss": "https://accounts.google.com",
        "aud": "aegis-cli",
        "sub": "user-123",
        "email": "alice@example.com",
        "exp": int(time.time()) + 3600,
        "roles": ["admin"],
        "name": "Alice SSO"
    }
    token = _encode_jwt_parts({"alg": "none"}, payload)
    
    provider = OidcIdentityProvider(
        issuer="https://accounts.google.com",
        audience="aegis-cli",
        verify_signature=False
    )
    
    # Authenticate via subject sub
    op1 = provider.authenticate("user-123", token)
    assert op1 is not None
    assert op1.operator_id == "user-123"
    assert op1.display_name == "Alice SSO"
    assert "admin" in op1.roles

    # Authenticate via email
    op2 = provider.authenticate("alice@example.com", token)
    assert op2 is not None


def test_oidc_authenticate_expired() -> None:
    payload = {
        "iss": "https://accounts.google.com",
        "aud": "aegis-cli",
        "sub": "user-123",
        "exp": int(time.time()) - 10,
    }
    token = _encode_jwt_parts({"alg": "none"}, payload)
    provider = OidcIdentityProvider(
        issuer="https://accounts.google.com",
        audience="aegis-cli",
        verify_signature=False
    )
    assert provider.authenticate("user-123", token) is None


def test_oidc_authenticate_issuer_mismatch() -> None:
    payload = {
        "iss": "https://mismatched-issuer.com",
        "aud": "aegis-cli",
        "sub": "user-123",
        "exp": int(time.time()) + 3600,
    }
    token = _encode_jwt_parts({"alg": "none"}, payload)
    provider = OidcIdentityProvider(
        issuer="https://accounts.google.com",
        audience="aegis-cli",
        verify_signature=False
    )
    assert provider.authenticate("user-123", token) is None


def test_oidc_authenticate_audience_mismatch() -> None:
    payload = {
        "iss": "https://accounts.google.com",
        "aud": "mismatched-aud",
        "sub": "user-123",
        "exp": int(time.time()) + 3600,
    }
    token = _encode_jwt_parts({"alg": "none"}, payload)
    provider = OidcIdentityProvider(
        issuer="https://accounts.google.com",
        audience="aegis-cli",
        verify_signature=False
    )
    assert provider.authenticate("user-123", token) is None


def test_oidc_authenticate_operator_mismatch() -> None:
    payload = {
        "iss": "https://accounts.google.com",
        "aud": "aegis-cli",
        "sub": "user-123",
        "exp": int(time.time()) + 3600,
    }
    token = _encode_jwt_parts({"alg": "none"}, payload)
    provider = OidcIdentityProvider(
        issuer="https://accounts.google.com",
        audience="aegis-cli",
        verify_signature=False
    )
    assert provider.authenticate("wrong-user", token) is None


def test_oidc_resolve_actor_sso() -> None:
    payload = {
        "iss": "https://accounts.google.com",
        "aud": "aegis-cli",
        "sub": "alice",
        "exp": int(time.time()) + 3600,
        "roles": ["approver"]
    }
    token = _encode_jwt_parts({"alg": "none"}, payload)

    # alice is OIDC-authenticated with role 'approver' -> should succeed for APPROVE
    ctx = resolve_actor(
        registry_path="",
        required=Permission.APPROVE,
        operator_id="alice",
        token=token,
        oidc_issuer="https://accounts.google.com",
        oidc_audience="aegis-cli",
        oidc_verify_signature=False
    )
    assert ctx.identity_verified is True
    assert ctx.operator_id == "alice"
    assert ctx.auth_method == "oidc"
    assert ctx.roles == ["approver"]

    # alice lacks PROMOTE -> should raise AuthorizationError
    with pytest.raises(AuthorizationError, match="lacks the 'promote' permission"):
        resolve_actor(
            registry_path="",
            required=Permission.PROMOTE,
            operator_id="alice",
            token=token,
            oidc_issuer="https://accounts.google.com",
            oidc_audience="aegis-cli",
            oidc_verify_signature=False
        )


def test_oidc_signature_verification(monkeypatch) -> None:
    from cryptography.hazmat.primitives.asymmetric import rsa
    import jwt

    # Generate RS256 keys
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    payload = {
        "iss": "https://accounts.google.com",
        "aud": "aegis-cli",
        "sub": "alice",
        "exp": int(time.time()) + 3600,
        "roles": ["admin"]
    }
    # Encode real signed token
    token = jwt.encode(payload, private_key, algorithm="RS256")

    provider = OidcIdentityProvider(
        issuer="https://accounts.google.com",
        audience="aegis-cli",
        jwks_uri="https://accounts.google.com/keys",
        verify_signature=True
    )

    class MockSigningKey:
        def __init__(self, key):
            self.key = key

    # Mock jwk client signature fetch
    monkeypatch.setattr(
        "jwt.PyJWKClient.get_signing_key_from_jwt",
        lambda self, tok: MockSigningKey(public_key)
    )

    op = provider.authenticate("alice", token)
    assert op is not None
    assert op.operator_id == "alice"
    assert "admin" in op.roles
