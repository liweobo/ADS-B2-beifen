from __future__ import annotations

import json
from pathlib import Path

from adsb.checkpoints import code_fingerprint
from posthoc_tools.p2a_reaggregation import Candidate
from posthoc_tools.p2b_reaggregation import (
    _canonical_decision_hash,
    choose_prefix_success,
    min_candidate,
)


ROOT = Path(__file__).resolve().parents[1]


def candidate(restart: int, ce: float, probability: float) -> Candidate:
    return Candidate(
        sample_id="sample",
        aircraft_id="aircraft",
        restart_id=restart,
        step=20,
        p_anomaly=probability,
        target_ce=ce,
        target_margin=-ce,
        active=True,
        source_valid=True,
        budget_valid=True,
        kinematic_valid=True,
        post_valid=True,
        projection_converged=True,
        projection_status="not_required",
    )


def test_frozen_p2b_matrix_and_fingerprint() -> None:
    path = ROOT / "outputs" / "attack_audit_c001" / "p2" / "p2b_configuration_freeze.json"
    frozen = json.loads(path.read_text(encoding="utf-8"))
    assert len(frozen["base_tasks"]) == 160
    assert len({task["logical_config_id"] for task in frozen["base_tasks"]}) == 160
    assert {task["restarts"] for task in frozen["base_tasks"]} == {1, 5}
    assert {task["alpha_rule"] for task in frozen["base_tasks"]} == {"two_eps_over_k"}
    assert code_fingerprint(ROOT) == frozen["original_p2a_attack_code_fingerprint"]


def test_prefix_selection_is_monotonic_and_success_preserving() -> None:
    r0 = candidate(0, 0.8, 0.6)
    r1 = candidate(1, 0.4, 0.2)
    assert min_candidate([r0, r1]) is r1
    assert choose_prefix_success([], r0, False) is r0
    assert choose_prefix_success([r1], r0, False) is r1


def test_decision_hash_ignores_no_fields_implicitly() -> None:
    left = {"rule": "frozen", "per_attack": {"norm_pgd": {"trigger": False}}}
    right = {"rule": "frozen", "per_attack": {"norm_pgd": {"trigger": True}}}
    assert _canonical_decision_hash(left) != _canonical_decision_hash(right)
