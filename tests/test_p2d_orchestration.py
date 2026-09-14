from collections import Counter
from pathlib import Path

import numpy as np

from audit_tools.p2c_orchestration import orchestration_self_test
from audit_tools.p2d_runner import (
    EXPECTED_ATTACK_CODE_FINGERPRINT,
    R80_IDS,
    R160_IDS,
    _freeze_rows,
    _orchestration_fingerprint,
)
from posthoc_tools.p2d_reaggregation import _relative_ce_gain


PROJECT_ROOT = Path(r"E:\ads-b\ADS-B2 -beifen")


def test_p2d_restart_ranges_are_exact_and_disjoint() -> None:
    assert R80_IDS == tuple(range(40, 80))
    assert R160_IDS == tuple(range(80, 160))
    assert set(R80_IDS).isdisjoint(range(40))
    assert set(R160_IDS).isdisjoint(range(80))
    assert set(R80_IDS).isdisjoint(R160_IDS)


def test_p2d_frozen_templates_cover_the_full_matrix() -> None:
    r80 = _freeze_rows(PROJECT_ROOT, "r80")
    r160 = _freeze_rows(PROJECT_ROOT, "r160")
    assert len(r80) == len(r160) == 80
    assert len({row["config_id"] for row in r80}) == 80
    assert Counter(row["attack"] for row in r80) == {
        "norm_pgd": 20,
        "phys_projection_pgd": 20,
        "phys_penalty_pgd": 20,
        "phys_hybrid_pgd": 20,
    }
    assert all(row["executed_restart_start"] == 40 for row in r80)
    assert all(row["executed_restart_end"] == 79 for row in r80)
    assert all(row["executed_restart_start"] == 80 for row in r160)
    assert all(row["executed_restart_end"] == 159 for row in r160)


def test_p2d_reuses_p2c_seed_and_range_semantics() -> None:
    result = orchestration_self_test()
    assert result["status"] == "PASS"
    assert result["checks"]["late_seed_reproduction"]
    assert result["checks"]["late_native_ids"]


def test_p2d_orchestration_fingerprint_keeps_attack_code_frozen() -> None:
    result = _orchestration_fingerprint(PROJECT_ROOT)
    assert result["attack_code_unchanged"]
    assert result["attack_code_fingerprint"] == EXPECTED_ATTACK_CODE_FINGERPRINT


def test_target_ce_stability_matches_frozen_p2c_formula() -> None:
    previous = np.asarray([1.0, 2.0, np.nan, 0.0005])
    current = np.asarray([0.5, 1.5, 3.0, 0.00025])
    result = _relative_ce_gain(previous, current)
    expected = np.asarray([0.5, 0.25, 0.25])
    assert result["common_active_support"] == 3
    assert result["median_relative_target_ce_gain"] == float(np.median(expected))
    assert result["max_relative_target_ce_gain"] == float(np.max(expected))
