#!/usr/bin/env python3
"""
Aegis — behavioral-trajectory guard demo (the automatic kill switch).

The guard is a NEGATIVE control: on healthy traffic it does nothing at all,
which is exactly the desired behavior and exactly what makes it hard to show.
So this script stages three scenarios against the REAL pipeline:

  1. HEALTHY   — an in-scope action flows through normally; the guard is silent.
  2. REDIRECTED — a compromised/prompt-injected planner emits an action aimed at
                  a production database the finding never mentioned. The guard
                  blocks it BEFORE the policy engine sees it.
  3. RUNAWAY   — the same compromised planner floods the pipeline with autonomous
                  executions. The guard latches an automatic halt, and every
                  subsequent action is blocked for the rest of the session.

What is real vs. simulated (stated plainly, because it matters for a demo):
  * REAL: the Orchestrator, the PolicyEngine, the ContainmentExecutor (dry-run),
    the hash-chained AuditLog, and the TrajectoryGuard itself.
  * SIMULATED: only the ATTACKER — a triage stage that returns attacker-chosen
    candidate actions, standing in for a planner subverted by prompt injection.
    The defense is not mocked; the attack is.

Everything runs in dry-run. Nothing touches any cloud or cluster.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

from aegis.allowlist import AllowlistStore
from aegis.audit import AuditLog
from aegis.config import Settings
from aegis.containment import ContainmentExecutor
from aegis.ingestion import QueuedFinding
from aegis.model import Finding, ResourceRef
from aegis.orchestrator import Orchestrator
from aegis.policy import PolicyEngine
from aegis.providers import build_containment_adapters
from aegis.schemas import ActionClass, ProposedAction, TriageVerdict
from aegis.trajectory import TrajectoryConfig, TrajectoryGuard

BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"
CYAN, GREEN, YELLOW, RED = "\033[36m", "\033[32m", "\033[33m", "\033[31m"

AUDIT_PATH = "aegis_trajectory_demo.jsonl"


def banner(text: str) -> None:
    print(f"\n{BOLD}{CYAN}{'─' * 72}{RESET}")
    print(f"{BOLD}  {text}{RESET}")
    print(f"{BOLD}{CYAN}{'─' * 72}{RESET}")


def say(text: str = "") -> None:
    print(f"{DIM}  {text}{RESET}")


class ScriptedTriage:
    """Stands in for a triage/planning stage that an attacker has subverted.

    The real TriageEngine derives candidate targets from the normalized finding.
    This one returns whatever the attacker chose — which is precisely the
    failure mode the trajectory guard exists to catch.
    """

    def __init__(self, candidates: list[ProposedAction]) -> None:
        self._candidates = candidates

    async def assess(self, finding: Finding):
        verdict = TriageVerdict(
            finding_id=finding.finding_id,
            is_actionable_threat=True,
            threat_category="Credential Compromise",
            confidence=0.95,
            severity=finding.severity,
            justification="Compromised credential observed exfiltrating data.",
        )
        return verdict, self._candidates


def compromised_finding() -> Finding:
    """A legitimate finding: it implicates exactly ONE EC2 instance."""
    return Finding(
        provider="aws",
        finding_id="aegis-finding-demo-0001",
        finding_type="UnauthorizedAccess:EC2/MaliciousIPCaller",
        severity=8.0,
        title="EC2 instance communicating with a known malicious IP",
        resources=[ResourceRef(kind="aws.ec2.instance", id="i-0a1b2c3d4e5f60789", attributes={})],
        remote_ip="185.220.101.7",
    )


def build(guard: TrajectoryGuard, candidates: list[ProposedAction], settings: Settings):
    audit = AuditLog(settings.audit_log_path)
    # seed= matters: Settings.auto_execute_allowlist only SEEDS the store on
    # first creation (see config.py). Omit it and the allowlist is empty, every
    # action routes to approval, and the auto-execution rate limiter never runs.
    allowlist = AllowlistStore(settings.allowlist_store_path, seed=settings.auto_execute_allowlist)
    policy = PolicyEngine(settings, allowlist)
    containment = ContainmentExecutor(settings, build_containment_adapters(settings))
    orch = Orchestrator(
        settings,
        triage=ScriptedTriage(candidates),
        policy=policy,
        containment=containment,
        audit=audit,
        trajectory=guard,
    )
    return orch


async def drive(orch: Orchestrator, finding: Finding, *, only: tuple[str, ...] = ()) -> None:
    """Run one finding through the real orchestrator. `only` filters the
    pipeline's stdout to the named stages so a flood stays readable on screen."""
    async def _ack() -> None:
        return None

    queue: "asyncio.Queue[QueuedFinding]" = asyncio.Queue()
    await queue.put(QueuedFinding(finding=finding, _ack=_ack))
    done = asyncio.Event()
    done.set()

    if not only:
        await orch.run(queue, done)
        return

    import contextlib
    import io

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        await orch.run(queue, done)
    for line in buf.getvalue().splitlines():
        if any(f"[{stage}]" in line for stage in only):
            print(line)


def check(label: str, condition: bool) -> None:
    """Report a demo assertion honestly. A demo that congratulates itself on an
    outcome it did not actually observe is worse than no demo."""
    if condition:
        print(f"{DIM}  {GREEN}✓ {label}{RESET}")
    else:
        print(f"{DIM}  {RED}✗ DEMO CHECK FAILED — {label}{RESET}")


def audit_stages() -> list[str]:
    if not os.path.exists(AUDIT_PATH):
        return []
    with open(AUDIT_PATH) as fh:
        return [json.loads(line)["record"]["stage"] for line in fh if line.strip()]


async def main() -> int:
    # Fresh, isolated state — never touches the real runtime files.
    for path in (AUDIT_PATH, "aegis_trajectory_demo_allow.json"):
        if os.path.exists(path):
            os.remove(path)

    settings = Settings(
        dry_run=True,
        kill_switch=False,
        audit_log_path=AUDIT_PATH,
        allowlist_store_path="aegis_trajectory_demo_allow.json",
        # Auto-execute isolate_instance_sg so the runaway scenario has something
        # the pipeline will actually commit to autonomously.
        auto_execute_allowlist=frozenset({"isolate_instance_sg"}),
    )
    finding = compromised_finding()

    banner("SCENARIO 1 — Healthy traffic: the guard stays out of the way")
    say("The finding implicates exactly one instance: i-0a1b2c3d4e5f60789.")
    say("The planner proposes isolating THAT instance. Perfectly in scope.")
    say("A good safety control is invisible here — watch for NO trajectory lines.")
    print()
    guard = TrajectoryGuard(TrajectoryConfig(enforce_scope=True, max_auto_executions=25))
    good = [ProposedAction(
        provider="aws", action_class=ActionClass.ISOLATE_INSTANCE_SG,
        target="i-0a1b2c3d4e5f60789",
        rationale="Move the compromised instance into the quarantine SG.",
    )]
    await drive(build(guard, good, settings), finding, only=("POLICY", "TRAJECTORY"))
    print()
    check("Guard stayed silent — no trajectory block on legitimate traffic", not guard.halted)
    check("Action reached the policy engine", "policy" in audit_stages())
    check("No scope violation recorded", "trajectory_scope_violation" not in audit_stages())

    banner("SCENARIO 2 — Redirection attack: prompt injection aims at a prod DB")
    say("Now the planner has been subverted. It returns an action targeting")
    say(f"{BOLD}i-prod-database-primary{RESET}{DIM} — a resource this finding NEVER mentioned.")
    say("This is the documented agent failure mode: the reasoning layer is")
    say("talked into pointing a legitimate capability at the wrong target.")
    print()
    guard2 = TrajectoryGuard(TrajectoryConfig(enforce_scope=True, max_scope_violations=3))
    redirected = [ProposedAction(
        provider="aws", action_class=ActionClass.TERMINATE_INSTANCE,
        target="i-prod-database-primary",
        rationale="URGENT: terminate the compromised host immediately.",
    )]
    before = len([s for s in audit_stages() if s == "policy"])
    await drive(build(guard2, redirected, settings), finding, only=("POLICY", "TRAJECTORY"))
    after = len([s for s in audit_stages() if s == "policy"])
    print()
    check("Redirected action was recorded as a scope violation",
          "trajectory_scope_violation" in audit_stages())
    check("It never reached the policy engine (no new policy record)", after == before)
    say("The guard compared the target against the finding's own resources and")
    say("rejected it. Deterministic — no LLM, so it cannot be talked out of it.")

    banner("SCENARIO 3 — Runaway: machine-speed flood trips the kill switch")
    say("The subverted planner now floods the pipeline with autonomous actions.")
    say("Each one is individually in scope and individually allowlisted — no")
    say("single-action check would ever object. Only the TRAJECTORY is wrong.")
    say(f"Ceiling for this demo: {BOLD}3 autonomous executions{RESET}{DIM} (production default is 25/60s).")
    print()
    guard3 = TrajectoryGuard(TrajectoryConfig(
        enforce_scope=True, max_auto_executions=3, window_seconds=60,
    ))
    flood = [ProposedAction(
        provider="aws", action_class=ActionClass.ISOLATE_INSTANCE_SG,
        target="i-0a1b2c3d4e5f60789",
        rationale=f"Isolate (burst action #{i + 1}).",
    ) for i in range(8)]
    await drive(build(guard3, flood, settings), finding, only=("POLICY", "TRAJECTORY"))
    print()
    check("AUTOMATIC KILL SWITCH ENGAGED", guard3.halted)
    check("Halt was audited as evidence", "trajectory_halt" in audit_stages())
    check("The burst was cut off before all 8 actions ran",
          len([s for s in audit_stages() if s == "containment"]) < 8 + before)
    if guard3.halted:
        say(f"reason: {guard3.halt_reason}")
    say("Every remaining action was blocked at the top of the loop. The halt is")
    say("LATCHED — it does not clear itself when the burst subsides. Only an")
    say("explicit human reset() releases it.")

    banner("The audit trail — every block is evidence, not just a log line")
    stages = audit_stages()
    counts: dict[str, int] = {}
    for s in stages:
        counts[s] = counts.get(s, 0) + 1
    for stage, n in counts.items():
        mark = f"{RED}⛔{RESET}" if stage.startswith("trajectory") else "  "
        print(f"   {mark} {stage:<32} {n}")
    ok, broken = AuditLog.verify(AUDIT_PATH)
    print()
    say(f"hash-chain verification: {GREEN}OK — intact{RESET}" if ok else f"BROKEN at line {broken}")
    say("Each trajectory_scope_violation / trajectory_halt record names the action,")
    say("the target, and why it was refused — defensible under EU AI Act Art. 12.")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
