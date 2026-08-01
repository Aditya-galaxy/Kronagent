"""
The earn-trust dial, made real and audited.

Before this module, "graduating" an action class to autonomous execution meant
editing KRONAGENT_AUTO_EXECUTE_ALLOWLIST and restarting the process — a change with
zero record of who made it or why. For a platform whose entire safety case
rests on "nothing executes unattended until a human decided it should," that
gap was the biggest inconsistency in the system: the single most consequential
decision it makes had no audit trail.

AllowlistStore fixes that:
  * persisted to disk (JSON, atomic write) so it survives restarts without
    redeploying a new env var,
  * every add/remove is written to the hash-chained AuditLog as a "governance"
    stage record — the same forensic backbone containment and approval
    decisions already use,
  * read live by PolicyEngine on every decision — promoting or demoting an
    action class takes effect immediately, no restart.

Seeded on first use from KRONAGENT_AUTO_EXECUTE_ALLOWLIST (if set) so existing
deployments aren't silently reset to empty.

Autonomy is *earned*, so it also has to be *re-earned*. Without that, an
allowlist only ever grows: adding one more entry is always cheaper than
auditing whether the previous twelve still apply, and six months in nobody can
answer why `terminate_instance` was promoted or whether it has fired since.
That is firewall-rule sprawl and IAM-policy rot, applied to the one decision
this platform's safety case rests on. Three mechanisms close it:

  * **Expiry.** An entry may carry a TTL (`expires_at`). Past it, the entry is
    no longer auto-eligible and the class routes back to human approval. The
    read path (`is_allowed`) enforces this on its own, so the demotion is
    immediate and does not depend on any sweep having run; `expire_due()` is
    the sweep that *records* the lapse in the audit chain and clears the entry.
  * **Ownership.** `owner` is whoever is accountable for the entry *now* — the
    person asked when it is about to lapse, and the one who says yes again.
    That is a different fact from `promoted_by`/`promoted_at`, which record a
    decision someone made once and cannot un-make. Owners are reassigned as
    people change teams (`set_owner`); the promotion history never changes.
  * **Last-fired tracking.** `record_fired()` is called when an entry actually
    authorizes an autonomous execution. An entry that never fires is standing
    authority with no benefit — the worst kind to leave lying around.
  * **Review.** Everything a periodic review needs (who owns it, who promoted
    it, when, why, when it last fired, when it lapses) travels on the entry, so
    `promote.py review` can ask "does this still apply?" with the context in
    hand.

Why a TTL and not just a recurring review prompt: **a review fails open, an
expiry fails closed.** In a review, silence reads as approval — the entry
survives because nobody got to it, which is the exact failure being designed
against. An expiry inverts that: the entry lapses unless a named person
actively says yes again, so inattention withdraws autonomy instead of
extending it. The review command still exists, because someone has to be
handed the context to decide — but it is the prompt, not the control. This is
how badge permissions work on regulated physical sites: an owner and an
expiry, and it is the expiry that does the real work.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Optional

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, model_validator

from .audit import AuditLog
from .schemas import ActionClass, AuditRecord, utcnow_iso

# An entry that has not fired in this long is flagged by `promote.py review`.
# Not enforced — a stale entry keeps working — because "unused" is a prompt to
# ask a human whether it is still wanted, not grounds for the system to decide.
DEFAULT_STALE_AFTER_DAYS = 30

_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_DURATION_RE = re.compile(r"^\s*(\d+)\s*([smhdw])\s*$", re.IGNORECASE)


class DurationError(ValueError):
    """A TTL/window string that isn't of the form <integer><s|m|h|d|w>."""


def parse_duration(raw: str) -> timedelta:
    """'90d' -> 90 days. Suffix is required: a bare '90' is ambiguous, and
    guessing wrong on a governance TTL means autonomy lapses (or persists) for
    the wrong length of time."""
    match = _DURATION_RE.match(raw or "")
    if not match:
        raise DurationError(
            f"Invalid duration '{raw}'. Expected <number><unit>, unit one of "
            f"s/m/h/d/w — e.g. 90d, 12h, 2w."
        )
    amount = int(match.group(1))
    if amount <= 0:
        raise DurationError(f"Invalid duration '{raw}': must be greater than zero.")
    return timedelta(seconds=amount * _DURATION_UNITS[match.group(2).lower()])


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_ts(raw: Optional[str]) -> Optional[datetime]:
    """Parse a stored ISO timestamp, tolerating hand-edited values. A naive
    timestamp is read as UTC; an unparseable one yields None, which every
    caller treats as 'no reliable time here' rather than crashing the read
    path that gates containment."""
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw)
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


class AllowlistEntry(BaseModel):
    """One promoted action class.

    Two different facts about people live here and must not be collapsed:
    `promoted_by`/`promoted_at` are immutable history — a decision someone made
    on a date, which no later event changes — while `owner` is who is
    accountable for the entry today and gets asked to renew it. The promoter
    may have left the company; the owner is by definition someone who hasn't.

    `promoted_by`/`promoted_at` also load from the older `added_by`/`added_at`
    keys, so a store written before ownership existed reads without migration.
    """

    model_config = ConfigDict(populate_by_name=True)

    action_class: str
    promoted_by: str = Field(validation_alias=AliasChoices("promoted_by", "added_by"))
    promoted_at: str = Field(default_factory=utcnow_iso,
                             validation_alias=AliasChoices("promoted_at", "added_at"))
    reason: str
    # Defaults to the promoter: whoever promoted it owns it until they hand it
    # over. An entry with no owner at all would be exactly the orphan this
    # field exists to prevent.
    owner: str = ""
    # None = no TTL: standing authority until an operator demotes it. Explicit,
    # not the absence of a decision — `promote.py review` reports it as such.
    expires_at: Optional[str] = None
    # Set by record_fired() when this entry authorizes an autonomous execution.
    last_fired_at: Optional[str] = None
    fire_count: int = 0

    @model_validator(mode="after")
    def _default_owner_to_promoter(self) -> "AllowlistEntry":
        if not self.owner:
            self.owner = self.promoted_by
        return self

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        expiry = parse_ts(self.expires_at)
        if expiry is None:
            # No TTL, or a corrupt one. A corrupt expiry must not read as
            # "never expires" — that would turn a typo into permanent
            # autonomy — so fail closed and treat it as already lapsed.
            return bool(self.expires_at)
        return (now or _utcnow()) >= expiry

    def is_stale(self, *, after_days: int = DEFAULT_STALE_AFTER_DAYS,
                 now: Optional[datetime] = None) -> bool:
        """True if this entry has not authorized an execution in `after_days`.
        An entry that has never fired is stale once it is itself that old —
        a promotion made yesterday hasn't had a chance yet."""
        reference = parse_ts(self.last_fired_at) or parse_ts(self.promoted_at)
        if reference is None:
            return False
        return (now or _utcnow()) - reference >= timedelta(days=after_days)


class AllowlistStore:
    def __init__(self, path: str, *, seed: frozenset[str] = frozenset()) -> None:
        self._path = path
        if not os.path.exists(self._path) and seed:
            self._write_all({
                ac: AllowlistEntry(
                    action_class=ac, promoted_by="system",
                    reason="seeded from KRONAGENT_AUTO_EXECUTE_ALLOWLIST",
                ).model_dump()
                for ac in seed
            })

    # --- persistence (same atomic-replace pattern as ApprovalStore) ---
    def _read_all(self) -> dict[str, dict]:
        if not os.path.exists(self._path):
            return {}
        with open(self._path, "r", encoding="utf-8") as fh:
            try:
                return json.load(fh)
            except json.JSONDecodeError:
                return {}

    def _write_all(self, data: dict[str, dict]) -> None:
        directory = os.path.dirname(os.path.abspath(self._path)) or "."
        fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._path)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    # --- read path used by PolicyEngine on every decision ---
    def is_allowed(self, action_class: ActionClass, *, now: Optional[datetime] = None) -> bool:
        """An expired entry is not allowed, whether or not the expiry sweep has
        run yet. The lapse of autonomy is enforced here, at the gate; the sweep
        only records it. Nothing about production safety waits on a cron."""
        raw = self._read_all().get(action_class.value)
        if raw is None:
            return False
        try:
            entry = AllowlistEntry.model_validate(raw)
        except Exception:
            return False  # unreadable entry grants nothing
        return not entry.is_expired(now)

    def list(self) -> list[AllowlistEntry]:
        """Every entry on file, expired ones included — `promote.py review`
        needs to see a lapsed entry to ask whether it should be renewed. Use
        `active()` for the set that is actually authorizing autonomy."""
        entries = []
        for value in self._read_all().values():
            try:
                entries.append(AllowlistEntry.model_validate(value))
            except Exception:
                continue
        return sorted(entries, key=lambda e: e.action_class)

    def active(self, *, now: Optional[datetime] = None) -> list[AllowlistEntry]:
        return [e for e in self.list() if not e.is_expired(now)]

    def expired(self, *, now: Optional[datetime] = None) -> list[AllowlistEntry]:
        return [e for e in self.list() if e.is_expired(now)]

    # --- write path: operator-driven, always audited ---
    async def add(
        self, action_class: ActionClass, *, by: str, reason: str, audit: AuditLog,
        actor_fields: Optional[dict] = None, expires_in: Optional[timedelta] = None,
        owner: Optional[str] = None, now: Optional[datetime] = None,
    ) -> AllowlistEntry:
        expires_at = ((now or _utcnow()) + expires_in).isoformat() if expires_in else None
        entry = AllowlistEntry(
            action_class=action_class.value, promoted_by=by, reason=reason,
            expires_at=expires_at, owner=owner or by,
        )
        data = self._read_all()
        previous = data.get(action_class.value)
        # Re-promoting the same class is the renewal path: it takes a fresh
        # reason and a fresh TTL, which is exactly the "re-earn it" motion.
        # Carry the firing history across so a renewal doesn't reset the
        # evidence of whether the entry was ever used, and keep the existing
        # owner unless this renewal names a new one — renewing on someone's
        # behalf shouldn't quietly move the accountability to the renewer.
        if previous:
            entry.last_fired_at = previous.get("last_fired_at")
            entry.fire_count = previous.get("fire_count") or 0
            if not owner:
                entry.owner = previous.get("owner") or by
        data[action_class.value] = entry.model_dump()
        self._write_all(data)
        await audit.record(AuditRecord(
            finding_id="_governance", stage="governance",
            payload={
                "decision": "allowlist_add", "action_class": action_class.value,
                "by": by, "reason": reason, "already_present": previous is not None,
                "expires_at": expires_at, "owner": entry.owner,
                **(actor_fields or {}),
            },
        ))
        return entry

    async def set_owner(
        self, action_class: ActionClass, *, owner: str, by: str, reason: str, audit: AuditLog,
        actor_fields: Optional[dict] = None,
    ) -> Optional[AllowlistEntry]:
        """Hand an entry to a new accountable owner.

        People change teams; the decision they made in March does not. So this
        moves `owner` and leaves `promoted_by`/`promoted_at`/`reason` exactly as
        they were — the history stays true, and there is still a named person
        to ask at renewal time. Audited like any other governance change, since
        it changes who can say yes.
        """
        data = self._read_all()
        raw = data.get(action_class.value)
        previous_owner = (raw or {}).get("owner") or (raw or {}).get("promoted_by") or ""
        if raw is not None:
            raw["owner"] = owner
            self._write_all(data)
        await audit.record(AuditRecord(
            finding_id="_governance", stage="governance",
            payload={
                "decision": "allowlist_reassign", "action_class": action_class.value,
                "by": by, "reason": reason, "owner": owner,
                "previous_owner": previous_owner, "existed": raw is not None,
                **(actor_fields or {}),
            },
        ))
        return AllowlistEntry.model_validate(raw) if raw is not None else None

    async def remove(
        self, action_class: ActionClass, *, by: str, reason: str, audit: AuditLog,
        actor_fields: Optional[dict] = None,
    ) -> bool:
        data = self._read_all()
        existed = data.pop(action_class.value, None) is not None
        if existed:
            self._write_all(data)
        await audit.record(AuditRecord(
            finding_id="_governance", stage="governance",
            payload={
                "decision": "allowlist_remove", "action_class": action_class.value,
                "by": by, "reason": reason, "existed": existed,
                **(actor_fields or {}),
            },
        ))
        return existed

    async def expire_due(
        self, *, audit: AuditLog, now: Optional[datetime] = None,
    ) -> list[AllowlistEntry]:
        """Clear entries whose TTL has lapsed, recording each in the audit chain.

        A lapse is a governance event with no human behind it, so it gets the
        same treatment as a demotion an operator typed: its own hash-chained
        record, carrying the promotion it reverses (who, when, why) and whether
        the entry ever actually fired. Six months on, that record — not
        somebody's memory — is what says the authority ended and what it was
        for.

        Idempotent: the entry is gone afterwards, so one lapse produces exactly
        one record no matter how many callers sweep.
        """
        now = now or _utcnow()
        data = self._read_all()
        lapsed = [e for e in self.list() if e.is_expired(now)]
        if not lapsed:
            return []
        for entry in lapsed:
            data.pop(entry.action_class, None)
        self._write_all(data)
        for entry in lapsed:
            await audit.record(AuditRecord(
                finding_id="_governance", stage="governance",
                payload={
                    "decision": "allowlist_expired", "action_class": entry.action_class,
                    "by": "system", "reason": "TTL elapsed — autonomy not renewed",
                    "expires_at": entry.expires_at,
                    # The owner is who to ask about renewing; the promoter is
                    # who decided it in the first place. Both, so the record
                    # answers "who let this lapse" and "whose call was it".
                    "owner": entry.owner,
                    "promoted_by": entry.promoted_by, "promoted_at": entry.promoted_at,
                    "promotion_reason": entry.reason,
                    "last_fired_at": entry.last_fired_at, "fire_count": entry.fire_count,
                    "identity_verified": False, "auth_method": "system",
                },
            ))
        return lapsed

    def record_fired(self, action_class: ActionClass, *, now: Optional[datetime] = None) -> None:
        """Note that this entry authorized an autonomous execution.

        Not audited: the execution itself already lands in the audit chain as a
        containment record, and mirroring every firing into the governance
        stage would bury the promote/demote/expire decisions that stage exists
        to make findable. This is a usage counter for review, not evidence.
        """
        data = self._read_all()
        raw = data.get(action_class.value)
        if raw is None:
            return
        raw["last_fired_at"] = (now or _utcnow()).isoformat()
        raw["fire_count"] = (raw.get("fire_count") or 0) + 1
        self._write_all(data)
