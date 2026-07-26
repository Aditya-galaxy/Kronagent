"""
Hash-chained audit log — the forensic backbone. The entire compliance/trust
story (EU AI Act Article 12, "the platform's decisions are provably
unaltered") rests on `verify()` actually detecting tampering. That claim gets
proven here, not just asserted in a docstring.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from kronagent.audit import AuditLog
from kronagent.schemas import AuditRecord


def _record(finding_id: str = "f-1", stage: str = "triage", **payload) -> AuditRecord:
    return AuditRecord(finding_id=finding_id, stage=stage, payload=payload or {"k": "v"})


async def test_empty_log_verifies_clean(tmp_path) -> None:
    path = str(tmp_path / "audit.jsonl")
    ok, broken = AuditLog.verify(path)  # file doesn't exist yet
    assert ok is True
    assert broken is None


async def test_single_record_verifies(tmp_path) -> None:
    path = str(tmp_path / "audit.jsonl")
    log = AuditLog(path)
    await log.record(_record())
    ok, broken = AuditLog.verify(path)
    assert ok is True
    assert broken is None


async def test_first_record_chains_from_genesis(tmp_path) -> None:
    path = str(tmp_path / "audit.jsonl")
    log = AuditLog(path)
    await log.record(_record())
    with open(path) as fh:
        envelope = json.loads(fh.readline())
    assert envelope["_prev"] == "0" * 64


async def test_many_records_verify_in_order(tmp_path) -> None:
    path = str(tmp_path / "audit.jsonl")
    log = AuditLog(path)
    for i in range(20):
        await log.record(_record(finding_id=f"f-{i}", stage="containment", n=i))
    ok, broken = AuditLog.verify(path)
    assert ok is True
    assert broken is None


async def test_resuming_log_continues_the_chain(tmp_path) -> None:
    """A restart must not fork the chain: the second AuditLog instance picks up
    exactly where the first left off."""
    path = str(tmp_path / "audit.jsonl")
    log1 = AuditLog(path)
    await log1.record(_record(finding_id="before-restart"))

    log2 = AuditLog(path)  # simulates a process restart against the same file
    await log2.record(_record(finding_id="after-restart"))

    ok, broken = AuditLog.verify(path)
    assert ok is True
    assert broken is None

    with open(path) as fh:
        lines = [json.loads(l) for l in fh if l.strip()]
    assert len(lines) == 2
    assert lines[1]["_prev"] == lines[0]["_hash"]


async def test_tampering_with_a_record_payload_is_detected(tmp_path) -> None:
    """The core security property: mutate one field in one historical record
    and verification must fail, pointing at the tampered line."""
    path = str(tmp_path / "audit.jsonl")
    log = AuditLog(path)
    await log.record(_record(finding_id="f-1", stage="policy", decision="blocked"))
    await log.record(_record(finding_id="f-2", stage="containment", detail="ok"))
    await log.record(_record(finding_id="f-3", stage="triage"))

    with open(path) as fh:
        lines = fh.readlines()
    tampered = json.loads(lines[0])
    tampered["record"]["payload"]["decision"] = "auto_execute"  # the attack: flip a decision
    lines[0] = json.dumps(tampered) + "\n"
    with open(path, "w") as fh:
        fh.writelines(lines)

    ok, broken = AuditLog.verify(path)
    assert ok is False
    assert broken == 1


async def test_deleting_a_middle_record_is_detected(tmp_path) -> None:
    path = str(tmp_path / "audit.jsonl")
    log = AuditLog(path)
    await log.record(_record(finding_id="f-1"))
    await log.record(_record(finding_id="f-2"))
    await log.record(_record(finding_id="f-3"))

    with open(path) as fh:
        lines = fh.readlines()
    del lines[1]  # remove the middle record; hash-prev linkage breaks
    with open(path, "w") as fh:
        fh.writelines(lines)

    ok, broken = AuditLog.verify(path)
    assert ok is False
    assert broken == 2  # the record that now has a mismatched _prev


async def test_reordering_records_is_detected(tmp_path) -> None:
    path = str(tmp_path / "audit.jsonl")
    log = AuditLog(path)
    await log.record(_record(finding_id="f-1"))
    await log.record(_record(finding_id="f-2"))

    with open(path) as fh:
        lines = fh.readlines()
    lines[0], lines[1] = lines[1], lines[0]
    with open(path, "w") as fh:
        fh.writelines(lines)

    ok, broken = AuditLog.verify(path)
    assert ok is False


async def test_concurrent_writes_produce_a_valid_chain(tmp_path) -> None:
    """record() is protected by an asyncio.Lock; N concurrent callers must
    still produce a single, valid, unbroken chain -- no lost or duplicated
    hashes from a race."""
    path = str(tmp_path / "audit.jsonl")
    log = AuditLog(path)

    async def write_one(i: int) -> None:
        await log.record(_record(finding_id=f"concurrent-{i}"))

    await asyncio.gather(*(write_one(i) for i in range(25)))

    ok, broken = AuditLog.verify(path)
    assert ok is True
    assert broken is None
    with open(path) as fh:
        assert sum(1 for l in fh if l.strip()) == 25
