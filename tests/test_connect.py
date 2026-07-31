"""
Tests for tenant cloud connection: External ID, CloudFormation rendering,
role assumption and preflight.

The load-bearing test in here is `test_observe_policy_contains_no_write_actions`.
The product's central claim — "it cannot touch anything until you decide it has
earned that" — is only true if the read-only grant really is read-only. That is
an invariant, not a code comment, so it is asserted.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import importlib.util
import json
import urllib.parse
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from kronagent.connect import (
    AwsConnection,
    ConnectionState,
    CredentialBroker,
    Grant,
    PreflightResult,
    _observe_policy,
    launch_stack_url,
    new_external_id,
    preflight,
    render_template,
    template_json,
)

def _installed(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ModuleNotFoundError, ImportError, ValueError):
        return False


# These monkeypatch boto3.client, which means importing boto3 first. The core
# install ships without it by design; the all-extras CI job is where they run.
requires_boto3 = pytest.mark.skipif(not _installed("boto3"), reason="needs the [aws] extra")

KRONAGENT_ACCOUNT = "999988887777"
CUSTOMER_ACCOUNT = "123456789012"


def _conn(**over) -> AwsConnection:
    base = dict(
        tenant_id="acme",
        account_id=CUSTOMER_ACCOUNT,
        region="us-east-1",
        external_id=new_external_id(),
        observe_role_arn=f"arn:aws:iam::{CUSTOMER_ACCOUNT}:role/KronagentObserveRole",
    )
    base.update(over)
    return AwsConnection(**base)


# --------------------------------------------------------------------------- #
# External ID
# --------------------------------------------------------------------------- #

def test_external_ids_are_unique_and_unguessable() -> None:
    ids = {new_external_id() for _ in range(500)}
    assert len(ids) == 500
    assert all(len(i) >= 32 for i in ids)


def test_external_id_is_validated() -> None:
    with pytest.raises(ValueError, match="external_id"):
        _conn(external_id="short")


@pytest.mark.parametrize("bad", ["1234", "12345678901234", "abcdefghijkl", ""])
def test_account_id_must_be_twelve_digits(bad) -> None:
    with pytest.raises(ValueError, match="12 digits"):
        _conn(account_id=bad)


@pytest.mark.parametrize("bad", ["useast1", "US-EAST-1", "somewhere", ""])
def test_region_is_validated(bad) -> None:
    # Interpolated into ARNs and into a console URL handed to a browser.
    with pytest.raises(ValueError, match="region"):
        _conn(region=bad)


# --------------------------------------------------------------------------- #
# The separation of read from write — the product's central claim
# --------------------------------------------------------------------------- #

_WRITE_VERB_PREFIXES = (
    "Create", "Delete", "Modify", "Update", "Put", "Attach", "Detach",
    "Terminate", "Stop", "Start", "Revoke", "Disable", "Enable", "Remove",
    "Set", "Associate", "Disassociate", "Run", "Reboot", "Replace",
)


def test_observe_policy_contains_no_write_actions() -> None:
    """The whole onboarding pitch rests on this being true.

    If a write action ever appears in the observe grant, "this grant cannot
    alter your account" becomes a false statement made to a customer during a
    security review.
    """
    actions: list[str] = []
    for stmt in _observe_policy()["Statement"]:
        a = stmt["Action"]
        actions.extend(a if isinstance(a, list) else [a])

    offenders = [
        act for act in actions
        if act.split(":", 1)[1].startswith(_WRITE_VERB_PREFIXES)
    ]
    assert not offenders, f"write actions found in the read-only grant: {offenders}"

    # Positive form: every action must be a read verb.
    assert all(
        act.split(":", 1)[1].startswith(("Get", "List", "Describe"))
        for act in actions
    ), actions


def test_observe_policy_effect_is_always_allow_never_wildcard_action() -> None:
    for stmt in _observe_policy()["Statement"]:
        assert stmt["Effect"] == "Allow"
        acts = stmt["Action"] if isinstance(stmt["Action"], list) else [stmt["Action"]]
        assert "*" not in acts, "a bare wildcard action defeats the point of the grant"


def test_containment_grant_omits_terminate_by_default() -> None:
    """Terminate is irreversible. It can never auto-execute, but the customer
    should not have to grant it merely to use containment at all."""
    tpl = render_template(_conn(), Grant.CONTAIN, kronagent_account_id=KRONAGENT_ACCOUNT)
    body = json.dumps(tpl)
    assert "TerminateInstances" not in body


def test_can_contain_is_false_until_the_second_stack_is_installed() -> None:
    c = _conn()
    assert c.can_contain is False
    with pytest.raises(ValueError, match="has not granted containment"):
        c.role_arn(Grant.CONTAIN)

    c2 = _conn(contain_role_arn=f"arn:aws:iam::{CUSTOMER_ACCOUNT}:role/KronagentContainRole")
    assert c2.can_contain is True


# --------------------------------------------------------------------------- #
# Trust policy — the confused-deputy defence
# --------------------------------------------------------------------------- #

def test_trust_policy_pins_the_external_id() -> None:
    conn = _conn()
    tpl = render_template(conn, Grant.OBSERVE, kronagent_account_id=KRONAGENT_ACCOUNT)
    trust = tpl["Resources"]["KronagentRole"]["Properties"]["AssumeRolePolicyDocument"]
    stmt = trust["Statement"][0]

    assert stmt["Principal"]["AWS"] == f"arn:aws:iam::{KRONAGENT_ACCOUNT}:root"
    assert stmt["Condition"]["StringEquals"]["sts:ExternalId"] == conn.external_id


def test_two_tenants_get_different_external_ids_in_their_templates() -> None:
    """Without this, any Kronagent customer could assume any other's role."""
    a, b = _conn(tenant_id="a"), _conn(tenant_id="b")
    ta = render_template(a, Grant.OBSERVE, kronagent_account_id=KRONAGENT_ACCOUNT)
    tb = render_template(b, Grant.OBSERVE, kronagent_account_id=KRONAGENT_ACCOUNT)
    cond = lambda t: (t["Resources"]["KronagentRole"]["Properties"]
                       ["AssumeRolePolicyDocument"]["Statement"][0]
                       ["Condition"]["StringEquals"]["sts:ExternalId"])
    assert cond(ta) != cond(tb)


def test_containment_policy_is_scoped_to_the_customer_account_and_region() -> None:
    conn = _conn(region="eu-west-2")
    tpl = render_template(conn, Grant.CONTAIN, kronagent_account_id=KRONAGENT_ACCOUNT,
                          quarantine_nacl_id="acl-0abc")
    doc = tpl["Resources"]["KronagentRole"]["Properties"]["Policies"][0]["PolicyDocument"]
    resources = [s["Resource"] for s in doc["Statement"]]

    assert all(CUSTOMER_ACCOUNT in r for r in resources), resources
    assert any("eu-west-2" in r for r in resources)
    # The NACL statement must be pinned to one ACL, not every ACL in the account.
    nacl = [r for r in resources if "network-acl" in r][0]
    assert nacl.endswith("acl-0abc")


def test_template_is_valid_json_and_readable() -> None:
    body = template_json(_conn(), Grant.OBSERVE, kronagent_account_id=KRONAGENT_ACCOUNT)
    parsed = json.loads(body)
    assert parsed["AWSTemplateFormatVersion"] == "2010-09-09"
    assert "\n  " in body, "template should be indented — the customer has to read it"


# --------------------------------------------------------------------------- #
# Launch URL
# --------------------------------------------------------------------------- #

def _console_params(url: str) -> dict[str, list[str]]:
    """The CloudFormation console is a single-page app, so its parameters live
    *inside* the fragment rather than in the query string. Parsing `.query`
    finds only `region=` and misses everything that matters."""
    fragment = urllib.parse.urlparse(url).fragment
    _, _, qs = fragment.partition("?")
    return urllib.parse.parse_qs(qs)


def test_launch_url_targets_the_connection_region_and_prefills_the_template() -> None:
    conn = _conn(region="ap-south-1")
    url = launch_stack_url(conn, Grant.OBSERVE,
                           template_url="https://s3.amazonaws.com/kronagent/observe.json")
    assert "ap-south-1.console.aws.amazon.com" in url

    q = _console_params(url)
    assert q["templateURL"] == ["https://s3.amazonaws.com/kronagent/observe.json"]
    assert q["stackName"] == ["kronagent-observe"]


def test_launch_url_puts_params_in_the_fragment_not_the_query_string() -> None:
    """Regression guard. Params in the real query string produce a link that
    opens an empty stack wizard — indistinguishable from working until the
    customer wonders what to paste."""
    url = launch_stack_url(_conn(), Grant.CONTAIN,
                           template_url="https://s3.amazonaws.com/kronagent/contain.json")
    parsed = urllib.parse.urlparse(url)
    assert "templateURL" not in parsed.query
    assert "templateURL" in parsed.fragment
    assert _console_params(url)["stackName"] == ["kronagent-contain"]


@pytest.mark.parametrize("bad", [
    "http://s3.amazonaws.com/t.json",
    "file:///tmp/t.json",
    "s3://bucket/t.json",
])
def test_launch_url_rejects_non_https_templates(bad) -> None:
    """The console fetches this from the customer's browser; anything but https
    either fails to load or is a downgrade."""
    with pytest.raises(ValueError, match="https"):
        launch_stack_url(_conn(), Grant.OBSERVE, template_url=bad)


# --------------------------------------------------------------------------- #
# Credential broker
# --------------------------------------------------------------------------- #

def _sts_response(expires_in_minutes: int = 60) -> dict:
    return {"Credentials": {
        "AccessKeyId": "ASIAEXAMPLE",
        "SecretAccessKey": "secret",
        "SessionToken": "token",
        "Expiration": datetime.now(timezone.utc) + timedelta(minutes=expires_in_minutes),
    }}


def test_assume_role_passes_the_external_id_and_names_the_session() -> None:
    broker = CredentialBroker()
    sts = MagicMock()
    sts.assume_role.return_value = _sts_response()
    broker._sts = sts

    conn = _conn()
    broker.credentials(conn, Grant.OBSERVE)

    kwargs = sts.assume_role.call_args.kwargs
    assert kwargs["ExternalId"] == conn.external_id
    assert kwargs["RoleArn"] == conn.observe_role_arn
    # The session name lands in the customer's CloudTrail — it should identify
    # the tenant and the grant without them having to ask us.
    assert "acme" in kwargs["RoleSessionName"]
    assert "observe" in kwargs["RoleSessionName"]


def test_credentials_are_cached_not_reassumed_every_call() -> None:
    broker = CredentialBroker()
    sts = MagicMock()
    sts.assume_role.return_value = _sts_response()
    broker._sts = sts

    conn = _conn()
    for _ in range(10):
        broker.credentials(conn, Grant.OBSERVE)
    assert sts.assume_role.call_count == 1


def test_credentials_are_refreshed_before_they_expire() -> None:
    """A credential that dies mid-containment is worse than a slightly early
    refresh, so anything inside the margin counts as stale."""
    broker = CredentialBroker()
    sts = MagicMock()
    sts.assume_role.return_value = _sts_response(expires_in_minutes=2)
    broker._sts = sts

    conn = _conn()
    broker.credentials(conn, Grant.OBSERVE)
    broker.credentials(conn, Grant.OBSERVE)
    assert sts.assume_role.call_count == 2


def test_observe_and_contain_are_cached_separately() -> None:
    broker = CredentialBroker()
    sts = MagicMock()
    sts.assume_role.return_value = _sts_response()
    broker._sts = sts

    conn = _conn(contain_role_arn=f"arn:aws:iam::{CUSTOMER_ACCOUNT}:role/KronagentContainRole")
    broker.credentials(conn, Grant.OBSERVE)
    broker.credentials(conn, Grant.CONTAIN)
    assert sts.assume_role.call_count == 2
    assert {c.kwargs["RoleArn"] for c in sts.assume_role.call_args_list} == {
        conn.observe_role_arn, conn.contain_role_arn
    }


def test_invalidate_forces_a_fresh_assume() -> None:
    broker = CredentialBroker()
    sts = MagicMock()
    sts.assume_role.return_value = _sts_response()
    broker._sts = sts

    conn = _conn()
    broker.credentials(conn, Grant.OBSERVE)
    broker.invalidate(conn.tenant_id)
    broker.credentials(conn, Grant.OBSERVE)
    assert sts.assume_role.call_count == 2


def test_requesting_containment_without_the_role_raises_rather_than_falling_back() -> None:
    """Falling back to ambient credentials here would run containment against
    Kronagent's own account instead of the customer's, and look like success."""
    broker = CredentialBroker()
    broker._sts = MagicMock()
    with pytest.raises(ValueError, match="has not granted containment"):
        broker.credentials(_conn(), Grant.CONTAIN)


# --------------------------------------------------------------------------- #
# Preflight
# --------------------------------------------------------------------------- #

def test_preflight_reports_failure_when_the_role_cannot_be_assumed() -> None:
    broker = CredentialBroker()
    sts = MagicMock()
    sts.assume_role.side_effect = RuntimeError("AccessDenied")
    broker._sts = sts

    result = preflight(_conn(), broker)
    assert result.ok is False
    assert "AccessDenied" in result.error
    assert result.as_state() is ConnectionState.FAILED


@requires_boto3
def test_preflight_catches_a_role_belonging_to_the_wrong_account(monkeypatch) -> None:
    """A role ARN recorded against the wrong account means our record and the
    customer's reality disagree — report it rather than silently protecting
    someone else's account."""
    broker = CredentialBroker()
    sts = MagicMock()
    sts.assume_role.return_value = _sts_response()
    broker._sts = sts

    import boto3
    client = MagicMock()
    client.get_caller_identity.return_value = {"Account": "111122223333"}
    monkeypatch.setattr(boto3, "client", lambda *a, **k: client)

    result = preflight(_conn(), broker)
    assert result.ok is False
    assert "111122223333" in result.error
    assert CUSTOMER_ACCOUNT in result.error


@requires_boto3
def test_preflight_names_the_specific_missing_permissions(monkeypatch) -> None:
    """"Something went wrong" is not actionable; "you are missing
    guardduty:ListDetectors" is."""
    broker = CredentialBroker()
    sts = MagicMock()
    sts.assume_role.return_value = _sts_response()
    broker._sts = sts

    import boto3

    def fake_client(service, **kwargs):
        c = MagicMock()
        if service == "sts":
            c.get_caller_identity.return_value = {"Account": CUSTOMER_ACCOUNT}
        elif service == "guardduty":
            c.list_detectors.side_effect = RuntimeError("AccessDenied")
        return c

    monkeypatch.setattr(boto3, "client", fake_client)

    result = preflight(_conn(), broker)
    assert result.ok is True                    # the role works…
    assert result.missing == ["guardduty:ListDetectors"]   # …but not completely
    assert result.as_state() is ConnectionState.DEGRADED


@requires_boto3
def test_preflight_healthy_when_every_probe_passes(monkeypatch) -> None:
    broker = CredentialBroker()
    sts = MagicMock()
    sts.assume_role.return_value = _sts_response()
    broker._sts = sts

    import boto3
    client = MagicMock()
    client.get_caller_identity.return_value = {"Account": CUSTOMER_ACCOUNT}
    monkeypatch.setattr(boto3, "client", lambda *a, **k: client)

    result = preflight(_conn(), broker)
    assert result.ok is True
    assert result.missing == []
    assert result.as_state() is ConnectionState.HEALTHY
    assert result.account_id == CUSTOMER_ACCOUNT


def test_preflight_result_state_mapping() -> None:
    assert PreflightResult(ok=False).as_state() is ConnectionState.FAILED
    assert PreflightResult(ok=True).as_state() is ConnectionState.HEALTHY
    assert PreflightResult(ok=True, missing=["x"]).as_state() is ConnectionState.DEGRADED


# --------------------------------------------------------------------------- #
# Tenant isolation in the containment adapter
#
# The connection model in this module is only worth anything if containment
# actually uses it. These assert the wiring: an action carries a tenant, the
# adapter resolves credentials for exactly that tenant, and two tenants never
# share a client.
# --------------------------------------------------------------------------- #

@requires_boto3
def test_action_runs_with_its_own_tenants_credentials(monkeypatch) -> None:
    from kronagent.providers.aws import AwsContainmentAdapter
    from kronagent.schemas import ActionClass, ProposedAction

    creds = {
        "acme":  {"aws_access_key_id": "ACME", "aws_secret_access_key": "s", "aws_session_token": "t"},
        "globex": {"aws_access_key_id": "GLOBEX", "aws_secret_access_key": "s", "aws_session_token": "t"},
    }
    seen: list[tuple[str, str]] = []

    import boto3

    def fake_client(service, region_name=None, **kw):
        seen.append((service, kw.get("aws_access_key_id", "AMBIENT")))
        return MagicMock()

    monkeypatch.setattr(boto3, "client", fake_client)

    adapter = AwsContainmentAdapter(region="us-east-1",
                                    credentials_for=lambda t: creds.get(t))

    for tenant in ("acme", "globex"):
        adapter._perform_sync(ProposedAction(
            provider="aws", tenant_id=tenant,
            action_class=ActionClass.DISABLE_ACCESS_KEY,
            target="AKIAEXAMPLE", rationale="test",
            parameters={"user_name": "victim"},
        ))

    assert ("iam", "ACME") in seen
    assert ("iam", "GLOBEX") in seen


@requires_boto3
def test_clients_are_never_shared_between_tenants(monkeypatch) -> None:
    """A boto3 client carries its credentials. One shared client would silently
    apply the first tenant's role to every tenant after it — containment
    executing in the wrong customer's account, reported as success."""
    from kronagent.providers.aws import AwsContainmentAdapter

    import boto3
    monkeypatch.setattr(boto3, "client", lambda *a, **k: MagicMock())

    adapter = AwsContainmentAdapter(
        region="us-east-1",
        credentials_for=lambda t: {"aws_access_key_id": t.upper(),
                                   "aws_secret_access_key": "s",
                                   "aws_session_token": "t"},
    )
    a = adapter._iam_client("acme")
    b = adapter._iam_client("globex")
    again = adapter._iam_client("acme")

    assert a is not b, "two tenants must not share a client"
    assert a is again, "the same tenant should reuse its cached client"


@requires_boto3
def test_invalidate_forces_credential_refresh(monkeypatch) -> None:
    """Assumed-role credentials expire. Without invalidation a cached client
    keeps using the dead ones until it fails mid-containment."""
    from kronagent.providers.aws import AwsContainmentAdapter

    import boto3
    monkeypatch.setattr(boto3, "client", lambda *a, **k: MagicMock())

    adapter = AwsContainmentAdapter(region="us-east-1",
                                    credentials_for=lambda t: None)
    first = adapter._iam_client("acme")
    adapter.invalidate("acme")
    assert adapter._iam_client("acme") is not first


@requires_boto3
def test_without_a_resolver_the_adapter_uses_ambient_credentials(monkeypatch) -> None:
    """Local development and single-tenant installs must keep working
    unchanged — the resolver is additive, not required."""
    from kronagent.providers.aws import AwsContainmentAdapter

    captured: dict = {}
    import boto3

    def fake_client(service, region_name=None, **kw):
        captured.update(kw)
        return MagicMock()

    monkeypatch.setattr(boto3, "client", fake_client)
    AwsContainmentAdapter(region="us-east-1")._iam_client()
    assert captured == {}, "no credentials should be passed when no resolver is set"


def test_planner_stamps_the_findings_tenant_onto_every_action() -> None:
    """22 places construct actions across five providers. Stamping centrally is
    what stops a future provider from forgetting and inheriting 'default'."""
    from kronagent.model import Finding, ResourceRef
    from kronagent.providers import plan_actions

    finding = Finding(
        provider="aws", finding_id="f-1", finding_type="UnauthorizedAccess",
        severity=8.0, tenant_id="acme",
        resources=[ResourceRef(kind="aws.ec2.instance", id="i-0abc", attributes={})],
        remote_ip="185.220.101.7",
    )
    actions = plan_actions(finding)
    assert actions, "expected the AWS planner to propose something"
    assert all(a.tenant_id == "acme" for a in actions), [a.tenant_id for a in actions]


def test_actions_default_to_the_default_tenant() -> None:
    from kronagent.schemas import ActionClass, ProposedAction
    a = ProposedAction(provider="aws", action_class=ActionClass.BLOCK_IP,
                       target="1.2.3.4", rationale="r")
    assert a.tenant_id == "default"
