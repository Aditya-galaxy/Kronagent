"""
The evaluation harness's own correctness.

An accuracy gate that cannot fail is worse than no gate: it shows a green check
and asserts nothing. Two such weaknesses were found in this harness and are
pinned here so they cannot come back.

  1. **A duplicated policy table.** `get_expected_disposition` carried its own
     hardcoded copy of the auto-eligible action classes. It had already drifted
     — it listed none of the Azure, GCP or on-premises classes — so CDC would
     have scored correct behaviour on those providers as wrong. It now asks the
     policy engine.

  2. **A vacuous F1 gate.** The offline mock answers triage with the dataset's
     own `expected_actionable` label, so triage F1 is ~100% by construction and
     measures the harness, not the system. It is therefore reported but NOT
     gated offline; CDC and FPUA are, because they score the deterministic
     policy path the mock does not supply.

Note what CDC deliberately does *not* cover: because expected and actual both
derive from the policy table, a misclassification moves both together and CDC
stays flat. That table's oracle is `test_policy_consistency.py`, which is
principle-based and independent. These tests assert that division of labour
rather than pretending either one covers both.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import json

import pytest

from kronagent.allowlist import AllowlistStore
from kronagent.config import Settings
from kronagent.policy import PolicyEngine
from kronagent.schemas import ActionClass

from run_eval import (
    CDC_GATE_LIVE,
    CDC_GATE_OFFLINE,
    DEFAULT_EVAL_ALLOWLIST,
    F1_GATE,
    FPUA_GATE,
    get_expected_disposition,
    wilson_score_interval,
)

from .conftest import SAMPLES_DIR


@pytest.fixture
def policy(tmp_path) -> PolicyEngine:
    settings = Settings(allowlist_store_path=str(tmp_path / "allow.json"))
    return PolicyEngine(settings, AllowlistStore(settings.allowlist_store_path))


# --------------------------------------------------------------------------- #
# The expected-disposition oracle must derive from the policy engine
# --------------------------------------------------------------------------- #

def test_auto_eligible_and_allowlisted_expects_auto_execute(policy) -> None:
    assert get_expected_disposition("isolate_pod", ["isolate_pod"], policy) == "auto_execute"


def test_auto_eligible_but_not_allowlisted_expects_approval(policy) -> None:
    assert get_expected_disposition("isolate_pod", [], policy) == "requires_approval"


def test_destructive_action_never_expects_auto_execute_even_if_allowlisted(policy) -> None:
    """The autonomy ceiling, restated as an expectation the harness scores
    against. If the harness expected auto_execute here it would score the
    platform's most important safety property as a failure."""
    for destructive in ["terminate_instance", "delete_pod", "kill_process",
                        "deallocate_vm", "stop_vm_instance"]:
        assert get_expected_disposition(destructive, [destructive], policy) == "requires_approval"


def test_unknown_action_class_expects_approval(policy) -> None:
    """The engine treats an unknown class as maximally dangerous; the oracle
    must agree, or every new action class would score as a CDC failure before
    it is classified."""
    assert get_expected_disposition("not_a_real_action", ["not_a_real_action"],
                                    policy) == "requires_approval"


@pytest.mark.parametrize("action_class", [
    # One auto-eligible class from every provider — the set the old hardcoded
    # copy was missing, which is what made it drift.
    ActionClass.ISOLATE_INSTANCE_SG,     # aws
    ActionClass.ISOLATE_VM_NSG,          # azure
    ActionClass.DISABLE_ENTRA_PRINCIPAL, # azure
    ActionClass.DISABLE_SERVICE_ACCOUNT, # gcp
    ActionClass.ISOLATE_POD,             # kubernetes
    ActionClass.ISOLATE_HOST_NETWORK,    # onprem
    ActionClass.DISABLE_LOCAL_ACCOUNT,   # onprem
])
def test_every_providers_auto_eligible_classes_are_recognised(action_class, policy) -> None:
    """The regression test for the drift itself: an auto-eligible class from any
    provider, once allowlisted, must be expected to auto-execute."""
    assert get_expected_disposition(action_class.value, [action_class.value],
                                    policy) == "auto_execute"


def test_oracle_tracks_the_policy_engine_not_a_copy(policy) -> None:
    """Whatever the engine considers auto-eligible is what the oracle expects.
    Asserted over the whole action taxonomy so a new class cannot be added to
    one and forgotten in the other."""
    for action_class in ActionClass:
        expected = get_expected_disposition(action_class.value, [action_class.value], policy)
        should_auto = policy.is_auto_eligible(action_class)
        assert (expected == "auto_execute") == should_auto, action_class.value


# --------------------------------------------------------------------------- #
# Gate thresholds
# --------------------------------------------------------------------------- #

def test_fpua_gate_is_zero_tolerance() -> None:
    """FPUA counts benign findings that led to an autonomous action. The
    platform's claim is that this cannot happen, so any tolerance band would be
    accepting a broken invariant as normal."""
    assert FPUA_GATE == 0.0


def test_offline_cdc_gate_is_exact() -> None:
    """Offline the mock removes every source of variance, so CDC is a
    deterministic property, not a measurement. Any tolerance band there is dead
    space a regression hides in: an entire provider losing its containment
    planning moves CDC by only ~4% on a 26-case dataset, which an 85% gate waves
    through."""
    assert CDC_GATE_OFFLINE == 1.0


def test_live_cdc_gate_allows_for_real_variance() -> None:
    """Live runs have genuine triage variance, so a statistical bar is right —
    but it must still be a demanding one."""
    assert 0.8 <= CDC_GATE_LIVE < 1.0


def test_gates_are_meaningful_thresholds() -> None:
    assert 0.0 < F1_GATE <= 1.0


# --------------------------------------------------------------------------- #
# The dataset the gate scores against
# --------------------------------------------------------------------------- #

def test_eval_dataset_is_labeled_and_balanced() -> None:
    """A dataset of only attacks would let a 'contain everything' pipeline score
    perfectly. Benign cases are what make FPUA measurable at all."""
    dataset = json.loads((SAMPLES_DIR / "eval_dataset.json").read_text())
    assert dataset, "evaluation dataset is empty"

    for case in dataset:
        assert "finding_id" in case
        assert "provider" in case
        assert "raw_event" in case
        assert isinstance(case["expected_actionable"], bool)

    benign = [c for c in dataset if not c["expected_actionable"]]
    attack = [c for c in dataset if c["expected_actionable"]]
    assert benign, "no benign cases — FPUA would be undefined"
    assert attack, "no attack cases — recall would be undefined"


def test_eval_dataset_covers_every_provider() -> None:
    """The dataset was AWS + Kubernetes only, so CDC said nothing about three of
    the five substrates while still reporting a single confident number."""
    from kronagent.providers import PLANNERS

    dataset = json.loads((SAMPLES_DIR / "eval_dataset.json").read_text())
    covered = {c["provider"] for c in dataset}
    assert covered == set(PLANNERS), f"providers with no evaluation cases: {set(PLANNERS) - covered}"


def test_every_provider_has_both_an_attack_and_a_benign_case() -> None:
    """One-sided coverage is not coverage: attack-only cases cannot measure
    FPUA, and benign-only cases cannot measure recall."""
    dataset = json.loads((SAMPLES_DIR / "eval_dataset.json").read_text())
    for provider in {c["provider"] for c in dataset}:
        cases = [c for c in dataset if c["provider"] == provider]
        assert any(c["expected_actionable"] for c in cases), f"{provider}: no attack case"
        assert any(not c["expected_actionable"] for c in cases), f"{provider}: no benign case"


def test_actionable_cases_declare_their_expected_actions() -> None:
    """Without a declared action set, CDC scores only the dispositions of
    whatever happened to be planned — so a planner that silently stops emitting
    an action scores as correct. Verified: dropping Azure's NSG isolation left
    CDC at 100% before this field existed."""
    dataset = json.loads((SAMPLES_DIR / "eval_dataset.json").read_text())
    for case in dataset:
        if case["expected_actionable"]:
            assert "expected_action_classes" in case, case["finding_id"]
            assert isinstance(case["expected_action_classes"], list)


def test_declared_expected_actions_match_the_planners() -> None:
    """The declared sets are a golden snapshot, so they must stay true of the
    real planners — otherwise the harness scores against a stale expectation."""
    from kronagent.providers import NORMALIZERS, plan_actions

    dataset = json.loads((SAMPLES_DIR / "eval_dataset.json").read_text())
    for case in dataset:
        if not case["expected_actionable"]:
            continue
        finding = NORMALIZERS[case["provider"]](case["raw_event"])
        planned = sorted({a.action_class.value for a in plan_actions(finding)})
        assert planned == sorted(case["expected_action_classes"]), case["finding_id"]


def test_default_allowlist_exercises_every_provider() -> None:
    """With only the AWS and Kubernetes classes seeded, the Azure, GCP and
    on-premises cases could only ever take the approval route, so CI would never
    exercise their autonomous path — the one that touches production."""
    from kronagent.providers import PLANNERS

    seeded = {c.strip() for c in DEFAULT_EVAL_ALLOWLIST.split(",") if c.strip()}
    per_provider = {
        "aws": {"disable_access_key", "isolate_instance_sg"},
        "azure": {"isolate_vm_nsg", "disable_entra_principal"},
        "gcp": {"disable_service_account", "disable_service_account_key"},
        "kubernetes": {"isolate_pod", "cordon_node"},
        "onprem": {"isolate_host_network", "disable_local_account"},
    }
    assert set(per_provider) == set(PLANNERS)
    for provider, classes in per_provider.items():
        assert classes & seeded, f"{provider} has no auto-eligible class in the eval allowlist"


def test_eval_dataset_finding_ids_are_unique() -> None:
    """The mock matches a case by locating its finding id in the prompt. Two
    cases sharing an id would silently score one against the other's label."""
    dataset = json.loads((SAMPLES_DIR / "eval_dataset.json").read_text())
    ids = [c["finding_id"] for c in dataset]
    assert len(ids) == len(set(ids))


# --------------------------------------------------------------------------- #
# Statistics
# --------------------------------------------------------------------------- #

def test_wilson_interval_brackets_the_point_estimate() -> None:
    lower, upper = wilson_score_interval(8, 10)
    assert lower < 0.8 < upper


def test_wilson_interval_is_wide_on_small_samples() -> None:
    """The reason the report shows intervals at all: 10/10 is not evidence of
    100% accuracy, and a point estimate would imply it is."""
    lower, upper = wilson_score_interval(10, 10)
    assert lower < 0.8
    assert upper == 1.0


def test_wilson_interval_handles_zero_samples() -> None:
    assert wilson_score_interval(0, 0) == (0.0, 0.0)
