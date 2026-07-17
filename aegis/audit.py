"""
Append-only, hash-chained audit log.

Every decision and action the platform takes is recorded here as one JSON line.
Each record carries the SHA-256 of the previous record, forming a chain: any
after-the-fact edit or deletion of a past entry breaks verification of every
later entry. This is the forensic backbone — when the platform acts on
production, you must be able to reconstruct exactly what happened and why, and
prove the record wasn't altered.

In production this backs onto a WORM store (S3 Object Lock / DynamoDB with a
stream to an immutable sink); the local implementation is a plain JSONL file
with identical chaining semantics so the logic is the same and testable.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from typing import Any, Optional

from .schemas import AuditRecord

_GENESIS = "0" * 64


def _canonical(record: dict[str, Any]) -> str:
    """Deterministic serialization the chain hash is computed over."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"))


def _hash_entry(prev_hash: str, canonical_body: str) -> str:
    return hashlib.sha256((prev_hash + canonical_body).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = asyncio.Lock()
        self._last_hash = self._recover_last_hash()

    def _recover_last_hash(self) -> str:
        """Resume the chain from an existing log so restarts don't fork it."""
        if not os.path.exists(self._path):
            return _GENESIS
        last = _GENESIS
        with open(self._path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        last = json.loads(line)["_hash"]
                    except (json.JSONDecodeError, KeyError):
                        continue
        return last

    async def record(self, entry: AuditRecord) -> str:
        """Append one entry durably; returns its chain hash."""
        async with self._lock:
            record = entry.model_dump()
            canonical = _canonical(record)
            entry_hash = _hash_entry(self._last_hash, canonical)
            envelope = {"_prev": self._last_hash, "_hash": entry_hash, "record": record}
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(envelope) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self._last_hash = entry_hash
            return entry_hash

    @staticmethod
    def verify(path: str) -> tuple[bool, Optional[int]]:
        """Verify the whole chain. Returns (ok, first_broken_line_or_None)."""
        prev = _GENESIS
        if not os.path.exists(path):
            return True, None
        with open(path, "r", encoding="utf-8") as fh:
            for n, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                env = json.loads(line)
                recomputed = _hash_entry(env["_prev"], _canonical(env["record"]))
                if env["_prev"] != prev or env["_hash"] != recomputed:
                    return False, n
                prev = env["_hash"]
        return True, None
