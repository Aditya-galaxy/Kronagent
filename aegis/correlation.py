"""
Investigation / Correlation Agent — the agent that has memory.

Triage and threat-intel look at one finding in isolation. This agent is the
first that looks *across* findings and asks: is this part of something larger?
Real intrusions are campaigns — a credential-exfil finding and a crypto-mining
finding an hour later can be the same actor moving through the kill chain. An
analyst who sees them as one incident responds very differently from one who
sees two unrelated alerts. This agent is what makes multi-agent genuinely beat
single-call triage: the value comes from state the individual calls don't have.

Memory model:
  * CorrelationMemory is a bounded, in-process rolling window of the recent
    findings the pipeline has handled (compact summaries, not full payloads).
    The orchestrator records each finding into it after handling.
  * It is SESSION-SCOPED. This is deliberate and honest: cross-restart / cross-
    replica campaign memory needs a shared persistent store (the audit log is
    the durable substrate; a real deployment would rehydrate the window from it
    or from a datastore). We don't fake that here — the window is what the
    current process has seen, and the docstring says so rather than implying
    more.

Design constraints (from agent-team-architecture.md — non-negotiable, same as
the threat-intel agent):
  * PURELY ADVISORY. Zero execution authority. Correlation never selects a
    target, never picks an action, never changes a policy decision. It annotates
    the incident record and the approval context a human sees. A fully attacker-
    controlled response here still cannot cause an action.
  * Reasons over NORMALIZED finding summaries, never raw telemetry — same
    prompt-injection discipline as the other agents.
  * Degrades gracefully: no LLM, or an empty history, means no correlation and
    the pipeline proceeds unchanged.
"""

from __future__ import annotations

from collections import deque
from typing import Deque, Iterable, Optional

from pydantic import BaseModel, Field

from .llm import GeminiTriageClient, LLMUnavailableError
from .model import Finding

# How many recent findings the correlation window holds. Bounded so the prompt
# stays small and cost is predictable; the newest evict the oldest.
DEFAULT_WINDOW = 25


class FindingSummary(BaseModel):
    """A compact, provider-neutral record of a past finding — everything the
    correlation agent needs to reason about a relationship, nothing more."""

    finding_id: str
    provider: str
    finding_type: str
    severity: float
    title: str = ""
    remote_ip: Optional[str] = None
    resource_ids: list[str] = Field(default_factory=list)

    @classmethod
    def from_finding(cls, finding: Finding) -> "FindingSummary":
        return cls(
            finding_id=finding.finding_id,
            provider=finding.provider,
            finding_type=finding.finding_type,
            severity=finding.severity,
            title=finding.title,
            remote_ip=finding.remote_ip,
            resource_ids=[r.id for r in finding.resources],
        )


class CorrelationMemory:
    """Bounded rolling window of recent finding summaries."""

    def __init__(self, db_path: str = "", maxlen: int = DEFAULT_WINDOW) -> None:
        self._db_path = db_path
        self._maxlen = maxlen
        if self._db_path:
            import sqlite3
            conn = sqlite3.connect(self._db_path, timeout=30.0)
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS correlation_findings (
                        finding_id TEXT PRIMARY KEY,
                        provider TEXT NOT NULL,
                        finding_type TEXT NOT NULL,
                        severity REAL NOT NULL,
                        title TEXT NOT NULL,
                        remote_ip TEXT,
                        resource_ids TEXT NOT NULL, -- JSON list
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.commit()
            finally:
                conn.close()
        else:
            self._items: Deque[FindingSummary] = deque(maxlen=maxlen)

    def add(self, finding: Finding) -> None:
        if not self._db_path:
            self._items.append(FindingSummary.from_finding(finding))
            return

        import json
        import sqlite3
        conn = sqlite3.connect(self._db_path, timeout=30.0)
        try:
            cursor = conn.cursor()
            summary = FindingSummary.from_finding(finding)
            cursor.execute(
                """
                INSERT OR REPLACE INTO correlation_findings 
                (finding_id, provider, finding_type, severity, title, remote_ip, resource_ids)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    summary.finding_id,
                    summary.provider,
                    summary.finding_type,
                    summary.severity,
                    summary.title,
                    summary.remote_ip,
                    json.dumps(summary.resource_ids),
                )
            )
            # Enforce rolling window: keep only the newest maxlen entries
            cursor.execute("SELECT COUNT(*) FROM correlation_findings")
            count = cursor.fetchone()[0]
            if count > self._maxlen:
                cursor.execute(
                    "SELECT rowid FROM correlation_findings ORDER BY rowid DESC LIMIT 1 OFFSET ?",
                    (self._maxlen - 1,)
                )
                res = cursor.fetchone()
                if res:
                    boundary = res[0]
                    cursor.execute("DELETE FROM correlation_findings WHERE rowid < ?", (boundary,))
            conn.commit()
        finally:
            conn.close()

    def prior_to(self, finding_id: str) -> list[FindingSummary]:
        """All remembered findings except the one being assessed (so an in-flight
        finding already recorded doesn't 'correlate with itself')."""
        if not self._db_path:
            return [s for s in self._items if s.finding_id != finding_id]

        import json
        import sqlite3
        conn = sqlite3.connect(self._db_path, timeout=30.0)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT finding_id, provider, finding_type, severity, title, remote_ip, resource_ids 
                FROM correlation_findings 
                WHERE finding_id != ? 
                ORDER BY rowid ASC 
                LIMIT ?
                """,
                (finding_id, self._maxlen)
            )
            rows = cursor.fetchall()
            return [
                FindingSummary(
                    finding_id=row[0],
                    provider=row[1],
                    finding_type=row[2],
                    severity=row[3],
                    title=row[4],
                    remote_ip=row[5],
                    resource_ids=json.loads(row[6]),
                )
                for row in rows
            ]
        finally:
            conn.close()

    def __len__(self) -> int:
        if not self._db_path:
            return len(self._items)
        import sqlite3
        conn = sqlite3.connect(self._db_path, timeout=30.0)
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM correlation_findings")
            return cursor.fetchone()[0]
        finally:
            conn.close()


class RelatedFinding(BaseModel):
    finding_id: str = Field(description="The prior finding_id this one correlates with.")
    relationship: str = Field(description="How they relate, e.g. 'same source IP', 'same actor, kill-chain progression'.")


class CorrelationAssessment(BaseModel):
    """Internal, provider-neutral correlation record. `available=False` means the
    agent didn't run (no LLM, or nothing to correlate against)."""

    finding_id: str
    available: bool
    part_of_campaign: bool = False
    related_finding_ids: list[str] = Field(default_factory=list)
    related: list[RelatedFinding] = Field(default_factory=list)
    campaign_narrative: str = ""   # the incident story tying the findings together
    correlation_summary: str = ""  # 1-2 sentence summary for the record

    def related_ids(self) -> list[str]:
        return [r.finding_id for r in self.related if r.finding_id]


class _LLMCorrelationOutput(BaseModel):
    """Schema the model fills. No target/action/resource field by construction —
    this agent cannot express a containment decision."""

    part_of_campaign: bool = Field(
        description="True if this finding appears related to one or more prior findings."
    )
    related: list[RelatedFinding] = Field(
        default_factory=list,
        description="Prior findings this one correlates with. Empty if genuinely unrelated.",
    )
    campaign_narrative: str = Field(
        description="If part of a campaign, the incident story tying the findings together. Else empty."
    )
    correlation_summary: str = Field(
        description="1-2 sentence summary of the correlation finding for the incident record."
    )


_SYSTEM = (
    "You are a SOC investigation analyst correlating security findings into "
    "incidents. You receive a confirmed threat plus a list of recent prior "
    "findings the platform has seen. Your job: determine whether the current "
    "finding is part of a larger campaign — the same actor, a shared indicator "
    "(source IP, targeted resource), or a progression through the attack "
    "lifecycle. Only assert a relationship when the evidence genuinely supports "
    "it; unrelated findings are common and a false link is worse than none. Cite "
    "the specific prior finding_id(s) you correlate with. This assessment is "
    "advisory: it informs a human analyst and does not choose any response "
    "action. Respond ONLY with the required JSON object."
)


def _summarize_history(prior: Iterable[FindingSummary]) -> str:
    lines = []
    for s in prior:
        ip = f" ip={s.remote_ip}" if s.remote_ip else ""
        res = f" resources={s.resource_ids}" if s.resource_ids else ""
        lines.append(
            f"  - {s.finding_id} [{s.provider}] {s.finding_type} sev={s.severity}{ip}{res}"
        )
    return "\n".join(lines) or "  (no prior findings)"


class CorrelationAgent:
    def __init__(self, llm: GeminiTriageClient | None) -> None:
        self._llm = llm

    async def assess(self, finding: Finding, prior: list[FindingSummary]) -> CorrelationAssessment:
        # No LLM, or nothing to correlate against -> not available, pipeline
        # proceeds unchanged. Correlation is meaningless with an empty history.
        if self._llm is None or not prior:
            return CorrelationAssessment(finding_id=finding.finding_id, available=False)

        from .sanitization import sanitize_finding
        sanitized = sanitize_finding(finding)

        resource_lines = "\n".join(
            f"  - {r.kind} {r.id}" for r in sanitized.resources
        ) or "  (none)"
        prompt = (
            "Correlate this confirmed threat against recent prior findings.\n\n"
            "=== Current finding ===\n"
            f"Finding ID: {sanitized.finding_id}\n"
            f"Provider: {sanitized.provider}\n"
            f"Type: {sanitized.finding_type}\n"
            f"Severity (0-10): {sanitized.severity}\n"
            f"Title: {sanitized.title or 'n/a'}\n"
            f"Remote IP: {sanitized.remote_ip or 'n/a'}\n"
            f"Implicated resources:\n{resource_lines}\n\n"
            "=== Recent prior findings (most recent last) ===\n"
            f"{_summarize_history(prior)}\n"
        )

        try:
            out = await self._llm.structured(
                system=_SYSTEM, prompt=prompt, schema=_LLMCorrelationOutput
            )
        except (LLMUnavailableError, Exception):  # noqa: BLE001 - best-effort enrichment
            return CorrelationAssessment(finding_id=finding.finding_id, available=False)

        # Defensive: the model can only reference finding_ids that are actually
        # in the history we gave it. Drop any hallucinated id so the correlation
        # record can never point at a finding that doesn't exist.
        known_ids = {s.finding_id for s in prior}
        related = [r for r in out.related if r.finding_id in known_ids]

        return CorrelationAssessment(
            finding_id=finding.finding_id,
            available=True,
            part_of_campaign=out.part_of_campaign and bool(related),
            related=related,
            related_finding_ids=[r.finding_id for r in related],
            campaign_narrative=out.campaign_narrative,
            correlation_summary=out.correlation_summary,
        )
