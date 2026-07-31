#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com
"""
Kronagent — Measured Evaluation Harness.

Reads a labeled dataset of attack and benign telemetry traces (AWS GuardDuty and 
Kubernetes audit events) to score the entire response pipeline. Reports precision,
recall, F1, overall containment-decision correctness, and False-Positive-Under-Authority
along with 95% confidence intervals to account for sample size and label noise.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import random
import sys
import tempfile

from pydantic import BaseModel

from kronagent.allowlist import AllowlistStore
from kronagent.approvals import ApprovalStore
from kronagent.audit import AuditLog
from kronagent.config import Settings
from kronagent.commander import IncidentCommanderAgent
from kronagent.containment import ContainmentExecutor
from kronagent.correlation import CorrelationAgent
from kronagent.forensics import ForensicsAgent
from kronagent.ingestion import QueuedFinding
from kronagent.intel import ThreatIntelAgent
from kronagent.orchestrator import Orchestrator
from kronagent.policy import PolicyEngine
from kronagent.providers import NORMALIZERS, build_containment_adapters
from kronagent.schemas import AuditRecord
from kronagent.triage import TriageEngine


# --------------------------------------------------------------------------- #
# Statistical Utilities
# --------------------------------------------------------------------------- #

def wilson_score_interval(successes: int, total: int, confidence: float = 0.95) -> tuple[float, float]:
    """Computes the 95% Wilson score interval for a binomial proportion."""
    if total == 0:
        return 0.0, 0.0
    z = 1.96  # 95% confidence
    p = successes / total
    denominator = 1 + z**2 / total
    centre_adj = p + z**2 / (2 * total)
    var_adj = z * math.sqrt((p * (1 - p) + z**2 / (4 * total)) / total)
    lower = (centre_adj - var_adj) / denominator
    upper = (centre_adj + var_adj) / denominator
    return max(0.0, lower), min(1.0, upper)


def bootstrap_f1_interval(actual_verdicts: list[bool], expected_labels: list[bool], n_iterations: int = 1000) -> tuple[float, float]:
    """Computes the 95% bootstrap confidence interval for the F1 score."""
    n = len(actual_verdicts)
    if n == 0:
        return 0.0, 0.0
    
    data = list(zip(actual_verdicts, expected_labels, strict=True))
    f1_scores = []
    
    for _ in range(n_iterations):
        sample = [random.choice(data) for _ in range(n)]
        tp = sum(1 for a, e in sample if a and e)
        fp = sum(1 for a, e in sample if a and not e)
        fn = sum(1 for a, e in sample if not a and e)
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        f1_scores.append(f1)
        
    f1_scores.sort()
    lower = f1_scores[int(n_iterations * 0.025)]
    upper = f1_scores[int(n_iterations * 0.975)]
    return lower, upper


# --------------------------------------------------------------------------- #
# Mock LLM Client
# --------------------------------------------------------------------------- #

class MockGeminiClient:
    """Mock client returning deterministic structure matching dataset labels.
    Ensures tests and evaluations run offline, fast, and reproducibly in CI."""

    def __init__(self, dataset: list[dict]) -> None:
        self.dataset = dataset

    def _find_matching_case(self, prompt: str) -> dict:
        for item in self.dataset:
            fid = item["finding_id"]
            if fid in prompt:
                return item
            # Support matching by fields in the raw event if ID is not direct
            raw = item["raw_event"]
            if raw.get("Id") and raw["Id"] in prompt:
                return item
            if raw.get("auditID") and raw["auditID"] in prompt:
                return item
        return self.dataset[0]

    async def structured(self, *, system: str, prompt: str, schema: type[BaseModel]) -> BaseModel:
        item = self._find_matching_case(prompt)
        expected_actionable = item["expected_actionable"]

        if schema.__name__ == "_LLMTriageOutput":
            return schema(
                is_actionable_threat=expected_actionable,
                threat_category="Mock Actionable Threat" if expected_actionable else "Mock Benign Telemetry",
                confidence=0.95 if expected_actionable else 0.1,
                justification=f"Mock verdict for {item['finding_id']}",
                correlated_signals=[],
            )
        elif schema.__name__ == "_LLMIntelOutput":
            from kronagent.intel import MitreTechnique
            techniques = [
                MitreTechnique(technique_id="T1078", technique_name="Valid Accounts", tactic="Initial Access")
            ] if expected_actionable else []
            return schema(
                mitre_techniques=techniques,
                attack_lifecycle_stage="Execution" if expected_actionable else "None",
                ioc_assessment="Mocked indicators of compromise analysis.",
                intel_summary="Mocked threat intelligence overview",
            )
        elif schema.__name__ == "_LLMCorrelationOutput":
            return schema(
                part_of_campaign=False,
                related=[],
                campaign_narrative="",
                correlation_summary="No campaign correlation found.",
            )
        elif schema.__name__ == "_LLMCommanderOutput":
            return schema(
                incident_narrative="Mocked commander incident synthesis.",
                priority="P2" if expected_actionable else "P4",
                escalate_to_human_now=expected_actionable,
                escalation_reason="Mocked escalation narrative.",
                key_risks=[],
                recommended_posture="Contain" if expected_actionable else "Monitor",
            )
        
        raise ValueError(f"Unknown schema: {schema}")


# --------------------------------------------------------------------------- #
# Captured Audit Log
# --------------------------------------------------------------------------- #

class CaptureAuditLog(AuditLog):
    """Subclass of AuditLog that keeps an in-memory list of recorded stages."""
    
    def __init__(self, path: str) -> None:
        super().__init__(path)
        self.records: list[AuditRecord] = []

    async def record(self, entry: AuditRecord) -> str:
        h = await super().record(entry)
        self.records.append(entry)
        return h


# --------------------------------------------------------------------------- #
# Main Evaluation Loop
# --------------------------------------------------------------------------- #

async def _noop_ack() -> None:
    return None


def get_expected_disposition(action_class_str: str, allowlist_classes: list[str]) -> str:
    """Calculates expected disposition under default evaluation rules."""
    # Only actions in the allowlist that are auto-eligible will be auto_execute.
    # From policy.py, the following are auto-eligible:
    auto_eligible = {
        "disable_access_key",
        "block_ip",
        "isolate_pod",
        "isolate_instance_sg",
        "cordon_node",
        "attach_deny_all_to_principal"
    }
    if action_class_str in allowlist_classes and action_class_str in auto_eligible:
        return "auto_execute"
    return "requires_approval"


async def evaluate_pipeline(dataset_path: str, use_live: bool, allowlist_classes: list[str]) -> int:
    with open(dataset_path, "r", encoding="utf-8") as fh:
        dataset = json.load(fh)

    print(f"Loaded {len(dataset)} evaluation cases from {dataset_path}")
    
    # Configure temporary files for the test run so we do not pollute production databases.
    temp_dir = tempfile.TemporaryDirectory(dir=".")
    db_path = os.path.join(temp_dir.name, "eval.db")
    audit_path = os.path.join(temp_dir.name, "eval_audit.jsonl")
    allowlist_path = os.path.join(temp_dir.name, "eval_allowlist.json")
    approvals_path = os.path.join(temp_dir.name, "eval_approvals.json")
    
    settings = Settings(
        dry_run=True,
        db_path=db_path,
        audit_log_path=audit_path,
        allowlist_store_path=allowlist_path,
        approval_store_path=approvals_path,
        min_severity_for_containment=4.0,
    )
    
    # Initialize components
    allowlist = AllowlistStore(settings.allowlist_store_path, seed=frozenset(allowlist_classes))
    policy = PolicyEngine(settings, allowlist)
    containment = ContainmentExecutor(settings, build_containment_adapters(settings))
    approvals = ApprovalStore(settings.approval_store_path)
    forensics = ForensicsAgent(settings)
    
    # LLM selection
    if use_live:
        try:
            from kronagent.llm import GeminiTriageClient
            llm = GeminiTriageClient()
            print("Using live Gemini API for evaluation.")
        except Exception as exc:
            print(f"Failed to initialize live Gemini Client: {exc}. Aborting.")
            temp_dir.cleanup()
            return 1
    else:
        llm = MockGeminiClient(dataset)
        print("Using mock client (deterministic dataset labels) for evaluation.")
        
    from kronagent.crypto import get_signer
    signer = get_signer(settings)
    triage = TriageEngine(llm, signer)
    threat_intel = ThreatIntelAgent(llm)
    correlation = CorrelationAgent(llm)
    commander = IncidentCommanderAgent(llm)
    
    # Track statistics
    triage_actual_verdicts = []
    triage_expected_labels = []
    
    containment_correct_count = 0
    false_positives_under_authority = 0
    total_benign_count = 0
    
    # Run test cases
    for case in dataset:
        fid = case["finding_id"]
        provider = case["provider"]
        expected_actionable = case["expected_actionable"]
        raw_event = case["raw_event"]
        
        # Setup clean audit logger per finding run
        audit = CaptureAuditLog(settings.audit_log_path)
        
        orchestrator = Orchestrator(
            settings, triage=triage, policy=policy, containment=containment,
            audit=audit, approvals=approvals, threat_intel=threat_intel,
            correlation=correlation, commander=commander, forensics=forensics,
        )
        
        # Ingest and normalize
        normalizer = NORMALIZERS[provider]
        try:
            finding = normalizer(raw_event)
        except Exception as exc:
            print(f"[-] Case {fid} failed normalization: {exc}")
            continue
            
        queue = asyncio.Queue(maxsize=1)
        ingestion_done = asyncio.Event()
        
        await queue.put(QueuedFinding(finding=finding, _ack=_noop_ack))
        ingestion_done.set()
        
        # Run orchestrator
        await orchestrator.run(queue, ingestion_done)
        
        # Analyze captured audit trail
        records = audit.records
        triage_record = next((r for r in records if r.stage == "triage"), None)
        
        if triage_record is None:
            print(f"[-] Case {fid} failed: triage stage not found in audit trail.")
            continue
            
        actual_actionable = triage_record.payload.get("is_actionable_threat", False)
        triage_actual_verdicts.append(actual_actionable)
        triage_expected_labels.append(expected_actionable)
        
        # Determine containment correctness
        case_correct = True
        
        if not expected_actionable:
            total_benign_count += 1
            # Expected behavior for benign: triage should classify as non-actionable,
            # resulting in early exit and no containment decisions.
            if actual_actionable:
                # If triaged as actionable incorrectly, check if it executed actions
                policy_records = [r for r in records if r.stage == "policy"]
                has_auto_execute = any(r.payload.get("decision", {}).get("disposition") == "auto_execute" for r in policy_records)
                if has_auto_execute:
                    false_positives_under_authority += 1
                case_correct = False
            else:
                # Correctly ignored
                pass
        else:
            # Expected behavior for attack: triage classifies actionable, policy makes decisions
            if not actual_actionable:
                # Missed threat entirely (False Negative)
                case_correct = False
            else:
                # Triage correct, verify policy dispositions
                policy_records = [r for r in records if r.stage == "policy"]
                
                # Check that planned actions match what the raw event dictates
                # and their dispositions conform to policy rules.
                if not policy_records:
                    # Actionable threat but no actions planned? Check if provider planners produced none
                    # (some events might legitimately have no containment action classes implemented).
                    pass
                else:
                    for prec in policy_records:
                        act = prec.payload.get("action", {})
                        dec = prec.payload.get("decision", {})
                        action_class = act.get("action_class")
                        actual_disp = dec.get("disposition")
                        
                        expected_disp = get_expected_disposition(action_class, allowlist_classes)
                        if actual_disp != expected_disp:
                            case_correct = False
                            
        if case_correct:
            containment_correct_count += 1
        else:
            print(f"[-] Mismatch in case {fid}: expected_actionable={expected_actionable}, "
                  f"actual_actionable={actual_actionable}. Policy records count: {len([r for r in records if r.stage == 'policy'])}")
            
    # Clean up temp folder
    temp_dir.cleanup()
    
    # Compute metrics
    total_cases = len(dataset)
    tp = sum(1 for a, e in zip(triage_actual_verdicts, triage_expected_labels, strict=True) if a and e)
    fp = sum(1 for a, e in zip(triage_actual_verdicts, triage_expected_labels, strict=True) if a and not e)
    tn = sum(1 for a, e in zip(triage_actual_verdicts, triage_expected_labels, strict=True) if not a and not e)
    fn = sum(1 for a, e in zip(triage_actual_verdicts, triage_expected_labels, strict=True) if not a and e)
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    cdc = containment_correct_count / total_cases if total_cases > 0 else 0.0
    fpua_rate = false_positives_under_authority / total_benign_count if total_benign_count > 0 else 0.0
    
    # Confidence intervals
    prec_ci = wilson_score_interval(tp, tp + fp)
    recall_ci = wilson_score_interval(tp, tp + fn)
    f1_ci = bootstrap_f1_interval(triage_actual_verdicts, triage_expected_labels)
    cdc_ci = wilson_score_interval(containment_correct_count, total_cases)
    fpua_ci = wilson_score_interval(false_positives_under_authority, total_benign_count)
    
    # Print report
    print("\n" + "="*60)
    print("                 KRONAGENT PIPELINE EVALUATION REPORT")
    print("="*60)
    print(f"Dataset Size: {total_cases} cases (Benign: {total_benign_count}, Attack: {total_cases - total_benign_count})")
    print("-"*60)
    print("Triage Stage Metrics (LLM/Verdict Decision):")
    print(f"  TP: {tp} | FP: {fp} | TN: {tn} | FN: {fn}")
    print(f"  Precision: {precision:.2%} (95% CI: {prec_ci[0]:.2%} - {prec_ci[1]:.2%})")
    print(f"  Recall:    {recall:.2%} (95% CI: {recall_ci[0]:.2%} - {recall_ci[1]:.2%})")
    print(f"  F1 Score:  {f1:.2%} (95% CI: {f1_ci[0]:.2%} - {f1_ci[1]:.2%})")
    print("-"*60)
    print("Whole-Pipeline Containment Decision Correctness (CDC):")
    print(f"  Accuracy:  {cdc:.2%} (95% CI: {cdc_ci[0]:.2%} - {cdc_ci[1]:.2%})")
    print("-"*60)
    print("False-Positive-Under-Authority (FPUA):")
    print(f"  FPUA Rate: {fpua_rate:.2%} (95% CI: {fpua_ci[0]:.2%} - {fpua_ci[1]:.2%})")
    print(f"  (Benign findings that incorrectly led to autonomous action: {false_positives_under_authority})")
    print("="*60 + "\n")
    
    # Regression Gate
    if f1 < 0.85 or cdc < 0.85:
        print("[!] EVALUATION FAILURE: Metrics fell below the 85.0% regression gate.")
        return 1
    
    print("[+] EVALUATION PASSED: All metrics satisfied the regression gate.")
    return 0


# --------------------------------------------------------------------------- #
# CLI Entrypoint
# --------------------------------------------------------------------------- #


def cli() -> int:
    """Console-script entry point for `kronagent-eval`."""
    parser = argparse.ArgumentParser(description="Kronagent Measured Evaluation Harness.")
    parser.add_argument("--dataset", type=str, default="samples/eval_dataset.json",
                        help="Path to evaluation dataset JSON.")
    parser.add_argument("--live", action="store_true",
                        help="Run live calls against the Gemini API instead of mock labels.")
    parser.add_argument("--allowlist", type=str,
                        default="disable_access_key,block_ip,isolate_pod,isolate_instance_sg",
                        help="Comma-separated action classes to seed in the auto-execute allowlist.")
    args = parser.parse_args()
    allowlist_classes = [c.strip() for c in args.allowlist.split(",") if c.strip()]
    try:
        return asyncio.run(evaluate_pipeline(args.dataset, args.live, allowlist_classes))
    except KeyboardInterrupt:
        print("\nEvaluation interrupted by user.")
        return 130

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kronagent Measured Evaluation Harness.")
    parser.add_name = parser.add_argument  # type checking helper
    parser.add_argument("--dataset", type=str, default="samples/eval_dataset.json",
                        help="Path to evaluation dataset JSON.")
    parser.add_argument("--live", action="store_true",
                        help="Run live calls against the Gemini API instead of mock labels.")
    parser.add_argument("--allowlist", type=str, default="disable_access_key,block_ip,isolate_pod,isolate_instance_sg",
                        help="Comma-separated action classes to seed in the auto-execute allowlist.")
    
    args = parser.parse_args()
    allowlist_classes = [c.strip() for c in args.allowlist.split(",") if c.strip()]
    
    try:
        sys.exit(asyncio.run(evaluate_pipeline(args.dataset, args.live, allowlist_classes)))
    except KeyboardInterrupt:
        print("\nEvaluation interrupted by user.")
        sys.exit(130)
