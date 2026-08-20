"""
Unit tests for live Azure containment execution dispatch in kronagent/providers/azure.py.
"""

from __future__ import annotations

import pytest

from kronagent.providers.azure import AzureContainmentAdapter
from kronagent.schemas import ActionClass, ProposedAction


@pytest.mark.asyncio
async def test_azure_containment_adapter_perform_entra_disable() -> None:
    adapter = AzureContainmentAdapter()
    action = ProposedAction(
        provider="azure",
        action_class=ActionClass.DISABLE_ENTRA_PRINCIPAL,
        target="user-oid-12345",
        parameters={"aad_object_id": "user-oid-12345"},
        rationale="Disable compromised Entra ID user",
    )
    detail, rollback = await adapter.perform(action)
    assert "user-oid-12345 disabled" in detail
    assert "accountEnabled" in rollback


@pytest.mark.asyncio
async def test_azure_containment_adapter_perform_entra_revoke_sessions() -> None:
    adapter = AzureContainmentAdapter()
    action = ProposedAction(
        provider="azure",
        action_class=ActionClass.REVOKE_ENTRA_SESSIONS,
        target="user-oid-12345",
        parameters={"aad_object_id": "user-oid-12345"},
        rationale="Revoke active Entra ID user sessions",
    )
    detail, rollback = await adapter.perform(action)
    assert "revoked for user-oid-12345" in detail
    assert "IRREVERSIBLE" in rollback


@pytest.mark.asyncio
async def test_azure_containment_adapter_perform_block_ip() -> None:
    adapter = AzureContainmentAdapter(quarantine_nsg_id="nsg-quarantine-01")
    action = ProposedAction(
        provider="azure",
        action_class=ActionClass.BLOCK_IP,
        target="198.51.100.99",
        parameters={},
        rationale="Block attacker IP in quarantine NSG",
    )
    detail, rollback = await adapter.perform(action)
    assert "Blocked IP 198.51.100.99" in detail
    assert "nsg-quarantine-01" in detail
