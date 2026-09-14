from __future__ import annotations

import numpy as np

from posthoc_tools.p2c_reaggregation import (
    _capture_recapture,
    _family_adequacy,
)


def _synthetic_state() -> dict[str, object]:
    individual = np.zeros((20, 4), dtype=bool)
    individual[0, 0] = True
    individual[6, 0:2] = True
    individual[12, 1:3] = True
    cumulative = np.logical_or.accumulate(individual, axis=0)
    return {
        "config_id": "c" * 64,
        "seed": 42,
        "model": "BiLSTM-ERM",
        "attack": "norm_pgd",
        "K": 20,
        "restart_count": 20,
        "sample_id": np.asarray(["a", "b", "c", "d"]),
        "individual_success_by_restart": individual,
        "success_by_prefix": cumulative,
    }


def _rows(*, ce_gain: float) -> list[dict[str, object]]:
    return [
        {
            "config_id": f"{index:064x}",
            "attack": "norm_pgd",
            "success_preserving_asr_increment": 0.001,
            "feasible_success_asr_increment": None,
            "median_relative_target_ce_gain": ce_gain,
            "max_relative_target_ce_gain": ce_gain,
            "new_successes": 1,
            "new_feasible_successes": None,
        }
        for index in range(20)
    ]


def _decision() -> dict[str, object]:
    return {
        "per_family": {
            "norm_pgd": {"trigger": False},
            "phys_projection_pgd": {"trigger": False},
            "phys_penalty_pgd": {"trigger": False},
            "phys_hybrid_pgd": {"trigger": False},
        }
    }


def test_capture_recapture_uses_exact_batch_incidence() -> None:
    rows, payload = _capture_recapture([_synthetic_state()])
    by_batch = {row["batch"]: row for row in rows}
    assert by_batch["0-4"]["batch_successes"] == 1
    assert by_batch["5-9"]["batch_successes"] == 2
    assert by_batch["10-19"]["batch_successes"] == 2
    assert by_batch["10-19"]["cumulative_unique_successes"] == 3
    assert by_batch["5-9"]["overlap_with_previous_batch"] == 1
    assert payload["diagnostic_only"] is True
    assert payload["configurations"][0]["observed_unique_successes"] == 3


def test_unit_ce_gate_is_strictly_below_one_percent() -> None:
    decision = _decision()
    passing = _family_adequacy(
        decision=decision,
        r20_rows=_rows(ce_gain=0.0099),
        r40_rows=[],
        integrity_blocker=False,
    )
    assert passing["families"]["norm_pgd"]["verdict"] == "PASS AT R20"

    failing = _family_adequacy(
        decision=decision,
        r20_rows=_rows(ce_gain=0.01),
        r40_rows=[],
        integrity_blocker=False,
    )
    assert (
        failing["families"]["norm_pgd"]["verdict"]
        == "FAIL — RESTARTS NOT STABLE"
    )
