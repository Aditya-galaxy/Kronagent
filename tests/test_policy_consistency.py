"""
Cross-provider consistency of the policy classification table.

The table in `policy.py` is the platform's hard autonomy ceiling: it alone
decides whether an action class can ever run unattended. Because each provider
contributes its own action classes, the table grows every time a substrate is
added — and nothing structurally stops a new provider from classifying an
operation more permissively than the identical operation on another cloud.

That is not hypothetical. GCP's `stop_vm_instance` shipped as
`destructive=False` while the Azure equivalent `deallocate_vm` was
`destructive=True`, so one allowlist entry could stop GCP production VMs
unattended while the same action on Azure required a human. These tests encode
the principle the table already follows everywhere else, so the inconsistency
cannot come back with the next provider:

    Isolating a resource (it keeps running, evidence preserved) may be
    auto-eligible. Taking a workload down, or destroying state, may not.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import pytest

from kronagent.policy import _ACTION_PROPERTIES
from kronagent.schemas import ActionClass, BlastRadius

# Actions that take a running workload offline or destroy state. Every one of
# these must be destructive, on every provider, so none can auto-execute.
_WORKLOAD_DOWN = {
    ActionClass.TERMINATE_INSTANCE,     # aws
    ActionClass.DELETE_POD,             # kubernetes
    ActionClass.SCALE_DEPLOYMENT_ZERO,  # kubernetes
    ActionClass.STOP_VM_INSTANCE,       # gcp
    ActionClass.DEALLOCATE_VM,          # azure
    ActionClass.KILL_PROCESS,           # onprem
}

# Actions that cut a resource off but leave it running for forensics. These are
# the containment the platform should be able to earn autonomy for.
_ISOLATION = {
    ActionClass.ISOLATE_INSTANCE_SG,    # aws
    ActionClass.ISOLATE_POD,            # kubernetes
    ActionClass.ISOLATE_VM_NSG,         # azure
    ActionClass.ISOLATE_HOST_NETWORK,   # onprem
}

# Actions that forcibly invalidate live sessions. Reversible in the sense that
# new sessions can be issued, but they disrupt legitimate in-flight ones.
_SESSION_REVOCATION = {
    ActionClass.REVOKE_ROLE_SESSIONS,   # aws
    ActionClass.REVOKE_ENTRA_SESSIONS,  # azure
}


def test_every_action_class_is_classified() -> None:
    """A class missing from the table would raise at decision time, in
    production, on the action nobody tested."""
    missing = [a.value for a in ActionClass if a not in _ACTION_PROPERTIES]
    assert not missing, f"unclassified action classes: {missing}"


def test_classification_entries_are_complete() -> None:
    for action_class, props in _ACTION_PROPERTIES.items():
        assert set(props) == {"reversible", "blast_radius", "destructive"}, action_class.value
        assert isinstance(props["reversible"], bool)
        assert isinstance(props["destructive"], bool)
        assert isinstance(props["blast_radius"], BlastRadius)


@pytest.mark.parametrize("action_class", sorted(_WORKLOAD_DOWN, key=lambda a: a.value))
def test_taking_a_workload_down_is_always_destructive(action_class) -> None:
    """The cross-cloud consistency rule. If this fails for a newly added
    provider, that provider is more permissive than its peers for the same
    operation — fix the classification, not this test."""
    assert _ACTION_PROPERTIES[action_class]["destructive"] is True, (
        f"{action_class.value} takes a workload offline but is not classified "
        f"destructive, so it can auto-execute once allowlisted. The equivalent "
        f"action on other providers is destructive."
    )


@pytest.mark.parametrize("action_class", sorted(_ISOLATION, key=lambda a: a.value))
def test_isolation_stays_auto_eligible(action_class) -> None:
    """The converse guard. Isolation is the containment worth earning autonomy
    for; classifying it destructive would make the earn-trust dial pointless."""
    props = _ACTION_PROPERTIES[action_class]
    assert props["destructive"] is False, f"{action_class.value} should be auto-eligible"
    assert props["reversible"] is True, f"{action_class.value} must be reversible"


@pytest.mark.parametrize("action_class", sorted(_SESSION_REVOCATION, key=lambda a: a.value))
def test_session_revocation_is_destructive_on_every_provider(action_class) -> None:
    assert _ACTION_PROPERTIES[action_class]["destructive"] is True


def test_irreversible_actions_are_always_destructive() -> None:
    """An action that cannot be undone must never be auto-eligible, whatever
    else is true of it."""
    for action_class, props in _ACTION_PROPERTIES.items():
        if not props["reversible"]:
            assert props["destructive"] is True, (
                f"{action_class.value} is irreversible but not destructive — it "
                f"could auto-execute and could not be rolled back."
            )


def test_wide_blast_radius_is_always_destructive() -> None:
    """Nothing that reaches beyond a single resource may run unattended."""
    for action_class, props in _ACTION_PROPERTIES.items():
        if props["blast_radius"] != BlastRadius.SINGLE_RESOURCE:
            assert props["destructive"] is True, (
                f"{action_class.value} has blast radius "
                f"{props['blast_radius'].value} but is not destructive."
            )


def test_every_provider_has_at_least_one_auto_eligible_action() -> None:
    """A provider with no auto-eligible action can never earn any autonomy, so
    the graduated-autonomy story does not apply to it. Worth knowing explicitly
    rather than discovering in a customer deployment."""
    from kronagent.providers import PLANNERS

    auto_eligible = {a for a, p in _ACTION_PROPERTIES.items() if not p["destructive"]}
    # Map each provider to the action classes its planner can emit.
    provider_actions: dict[str, set] = {
        "aws": {ActionClass.DISABLE_ACCESS_KEY, ActionClass.ISOLATE_INSTANCE_SG,
                ActionClass.BLOCK_IP, ActionClass.ATTACH_DENY_ALL_TO_PRINCIPAL},
        "azure": {ActionClass.ISOLATE_VM_NSG, ActionClass.DISABLE_ENTRA_PRINCIPAL,
                  ActionClass.BLOCK_IP},
        "gcp": {ActionClass.DISABLE_SERVICE_ACCOUNT_KEY, ActionClass.DISABLE_SERVICE_ACCOUNT,
                ActionClass.BLOCK_IP},
        "kubernetes": {ActionClass.ISOLATE_POD, ActionClass.CORDON_NODE},
        "onprem": {ActionClass.ISOLATE_HOST_NETWORK, ActionClass.DISABLE_LOCAL_ACCOUNT,
                   ActionClass.BLOCK_IP},
    }
    assert set(provider_actions) == set(PLANNERS), "provider list drifted from the registry"

    for provider, actions in provider_actions.items():
        assert actions & auto_eligible, f"{provider} has no auto-eligible action class"
