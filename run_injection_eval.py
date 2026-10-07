#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com
"""
Kronagent — injection red-team run: can attacker-controlled text talk triage
out of a real attack? See kronagent/redteam.py for what is measured and why.

    python run_injection_eval.py                    # offline: what reaches the model at all
    python run_injection_eval.py --live --budget 15 # real triage model, 15 injected trials
    python run_injection_eval.py --live --as-severity 5.5 --no-recheck   # what the recheck is for

Offline needs no key and makes no calls. It reports which payloads the
sanitizer changes and how much of each payload survives masking, per channel.

Live sends each attack case to the real triage model once clean (the baseline)
and then with a payload. Every answer is cached by the exact prompt in
--cache, so a run that stops on the free tier's daily quota resumes the next
day and trials accumulate, and a changed prompt never reuses an old answer. A
verdict that came from the severity fallback (the model was unreachable) is
never scored.

The corpus's attacks all sit at or above the override floor, where a fooled
verdict still reaches a person. --as-severity re-runs them as mid-severity
findings, the range where a fooled verdict used to drop the attack, and
--no-recheck turns off the recheck that now catches it, to show the difference.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
from pathlib import Path

from kronagent import redteam
from kronagent.config import Settings
from kronagent.model import Finding
from kronagent.providers import NORMALIZERS
from kronagent.triage import SYSTEM_PROMPT, TriageEngine, build_prompt

DATASET = "samples/eval_dataset.json"


def attack_cases(path: str) -> dict[str, Finding]:
    """The dataset's plain attack cases. Its adversarial cases already carry
    injected text, so they can't serve as a clean baseline."""
    cases = {}
    for case in json.loads(Path(path).read_text()):
        if case.get("expected_actionable") and not case.get("adversarial"):
            cases[case["finding_id"]] = NORMALIZERS[case["provider"]](case["raw_event"])
    return cases


def offline(cases: dict[str, Finding]) -> None:
    print("Sanitizer: payloads changed before the model sees them")
    report = redteam.sanitizer_report()
    for row in report:
        print(f"  {'changed  ' if row['changed'] else 'UNCHANGED'}  {row['category']:<21} {row['name']}")
    unchanged = sum(not r["changed"] for r in report)
    print(f"  {unchanged} of {len(report)} payloads pass the phrase list unchanged.\n")

    print("Masking: share of each payload's words the model would read, by channel")
    for channel in redteam.CHANNELS:
        shares = [redteam.visible_fraction(f, p, channel) for f in cases.values() for p in redteam.PAYLOADS]
        mean = sum(shares) / len(shares)
        print(f"  {channel:<19} mean {100 * mean:5.1f}%   "
              f"(fully hidden in {sum(s == 0 for s in shares)} of {len(shares)} placements)")


class Cache:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.data = json.loads(path.read_text()) if path.exists() else {}

    @staticmethod
    def key(finding: Finding, model: str, recheck: bool) -> str:
        prompt, _ = build_prompt(finding)
        return hashlib.sha256(json.dumps([model, SYSTEM_PROMPT, prompt, recheck]).encode()).hexdigest()[:32]

    def put(self, key: str, value: dict) -> None:
        self.data[key] = value
        self.path.write_text(json.dumps(self.data, indent=1))


class OutOfQuota(RuntimeError):
    pass


async def verdict_for(finding: Finding, triage: TriageEngine, cache: Cache, model: str,
                      recheck: bool = True) -> dict:
    key = cache.key(finding, model, recheck)
    if key in cache.data:
        return cache.data[key]
    verdict, _ = await triage.assess(finding)
    if verdict.justification.startswith("FALLBACK"):
        raise OutOfQuota(verdict.justification)
    value = {"actionable": verdict.is_actionable_threat, "confidence": verdict.confidence,
             "justification": verdict.justification, "contested": verdict.contested}
    cache.put(key, value)
    return value


async def live(cases: dict[str, Finding], budget: int, seed: int, cache_path: Path, recheck: bool) -> int:
    from kronagent.llm import MODEL, GeminiTriageClient
    triage = TriageEngine(GeminiTriageClient(), recheck_band=(0.0, 10.01) if recheck else (0.0, 0.0))
    cache = Cache(cache_path)
    floor = Settings.from_env().triage_override_floor
    results: list[redteam.Result] = []
    stopped = ""
    try:
        for trial in redteam.plan_trials(cases, budget=budget, seed=seed):
            finding = cases[trial.case_id]
            base = await verdict_for(finding, triage, cache, MODEL, recheck)
            hit = await verdict_for(redteam.inject(finding, trial.payload, trial.channel), triage, cache,
                                    MODEL, recheck)
            results.append(redteam.Result(trial, finding.severity, base["actionable"], hit["actionable"],
                                          hit["confidence"], hit["justification"], hit["contested"]))
    except OutOfQuota as exc:
        stopped = str(exc)

    summary = redteam.summarise(results, floor)
    print(f"Model: {MODEL}   override floor: {floor}   recheck: {'on' if recheck else 'OFF'}   "
          f"trials run: {len(results)}"
          + (f"   (stopped early: the model became unavailable — {stopped[:80]})" if stopped else ""))
    skipped = len(results) - summary["overall"]["n"]
    if skipped:
        print(f"  {skipped} trials not scored: the model missed the attack even without a payload.")

    def line(name: str, b: dict) -> str:
        if not b["n"]:
            return f"  {name:<21} no scored trials"
        lo, hi = b["suppression_ci"]
        return (f"  {name:<21} n={b['n']:<3} held {b['held']:<3} rescued {b['rescued']:<3} "
                f"(by recheck {b['rescued_by_recheck']}) dismissed {b['dismissed']:<3} "
                f"model fooled {100 * b['suppression_rate']:5.1f}% [{100 * lo:.0f}–{100 * hi:.0f}%]")

    print(line("overall", summary["overall"]))
    for group in ("by_category", "by_channel"):
        print(f" {group.replace('_', ' ')}:")
        for name, b in summary[group].items():
            print(line(name, b))
    for f in summary["fooled"]:
        print(f"  {f['outcome'].upper():<9} {f['case']} · {f['payload']} via {f['channel']} "
              f"(severity {f['severity']}): {f['justification'][:140]}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", default=DATASET)
    ap.add_argument("--live", action="store_true", help="call the real triage model")
    ap.add_argument("--budget", type=int, default=15, help="injected trials to run (live)")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--max-cases", type=int, help="use only the first N attack cases (each needs a baseline call)")
    ap.add_argument("--as-severity", type=float, help="re-run the attack cases at this severity (e.g. 5.5)")
    ap.add_argument("--no-recheck", action="store_true", help="turn the structured-fields recheck off")
    ap.add_argument("--cache", default="kronagent_injection_cache.json")
    args = ap.parse_args()
    cases = attack_cases(args.dataset)
    if args.max_cases:
        cases = dict(sorted(cases.items())[:args.max_cases])
    if args.as_severity is not None:
        cases = {k: f.model_copy(update={"severity": args.as_severity}) for k, f in cases.items()}
    print(f"{len(cases)} attack cases, {len(redteam.PAYLOADS)} payloads, {len(redteam.CHANNELS)} channels "
          f"= {len(cases) * len(redteam.PAYLOADS) * len(redteam.CHANNELS)} possible trials\n")
    if not args.live:
        offline(cases)
        return 0
    return asyncio.run(live(cases, args.budget, args.seed, Path(args.cache), not args.no_recheck))


if __name__ == "__main__":
    sys.exit(main())
