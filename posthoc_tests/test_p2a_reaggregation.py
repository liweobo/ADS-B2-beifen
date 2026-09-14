from __future__ import annotations

import csv
import gzip
import tempfile
import unittest
from pathlib import Path

from adsb.checkpoints import code_fingerprint
from posthoc_tools.p2a_reaggregation import (
    STEP_FIELDS,
    SampleState,
    alpha_value,
    choose_final,
    choose_success_preserving,
    iter_member,
    select_alpha,
    transition_support_complete,
    update_state,
)


ROOT = Path(__file__).resolve().parents[1]
FROZEN = "afd1389066e1c87fec8d6f9da42e4f7e2fb3384343f214d31c8eccf79bdbcf4f"


def step_row(
    *,
    sample_id: str = "s0",
    restart: int = 0,
    step: int = 0,
    ce: float = 0.5,
    margin: float = 1.0,
    probability: float = 0.3,
    p_normal: float | None = None,
    threshold_success: bool | None = None,
    active: bool = True,
    source_valid: bool = True,
    budget_valid: bool = True,
    kinematic_valid: bool = True,
    post_valid: bool = True,
    projection_converged: bool = True,
    projection_status: str = "success",
) -> dict[str, str]:
    row = {field: "" for field in STEP_FIELDS}
    row.update(
        {
            "sample_id": sample_id,
            "aircraft_id": "a0",
            "restart_id": str(restart),
            "step": str(step),
            "target_ce": str(ce),
            "target_margin": str(margin),
            "p_anomaly": str(probability),
            "p_normal": str(1.0 - probability if p_normal is None else p_normal),
            "threshold_success": str(
                int(probability < 0.8) if threshold_success is None else int(threshold_success)
            ),
            "argmax_success": str(int(probability < 0.5)),
            "candidate_active": str(int(active)),
            "source_valid": str(int(source_valid)),
            "budget_valid": str(int(budget_valid)),
            "kinematic_valid": str(int(kinematic_valid)),
            "post_valid": str(int(post_valid)),
            "projection_converged": str(int(projection_converged)),
            "projection_status": projection_status,
            "initialization_success": "1",
        }
    )
    return row


class CandidateSemanticsTests(unittest.TestCase):
    def test_valid_final_is_in_best_loss_support(self) -> None:
        state = SampleState("s0", "a0")
        for row in (
            step_row(step=0, ce=0.4, probability=0.25),
            step_row(step=1, ce=0.3, probability=0.20),
            step_row(step=2, ce=0.5, probability=0.35),
        ):
            update_state(state, row, physical=True, final_step=2, threshold=0.1)
        final = choose_final(state, physical=True)
        self.assertIsNotNone(final)
        self.assertIsNotNone(state.best_loss)
        assert final is not None and state.best_loss is not None
        self.assertLessEqual(state.best_loss.target_ce, final.target_ce)
        self.assertEqual(final.step, 2)

    def test_inactive_final_is_not_replaced_by_clean(self) -> None:
        state = SampleState("s0", "a0")
        update_state(state, step_row(step=0), physical=True, final_step=2, threshold=0.8)
        update_state(state, step_row(step=1), physical=True, final_step=2, threshold=0.8)
        update_state(state, step_row(step=2, active=False), physical=True, final_step=2, threshold=0.8)
        self.assertIsNone(choose_final(state, physical=True))
        self.assertIsNotNone(state.best_loss)

    def test_success_selector_prefers_feasible_success(self) -> None:
        state = SampleState("s0", "a0")
        update_state(
            state,
            step_row(step=0, ce=0.1, probability=0.05, post_valid=False, kinematic_valid=False),
            physical=True,
            final_step=2,
            threshold=0.8,
        )
        update_state(
            state,
            step_row(step=1, ce=0.2, probability=0.10),
            physical=True,
            final_step=2,
            threshold=0.8,
        )
        chosen = choose_success_preserving(state)
        self.assertIsNotNone(chosen)
        assert chosen is not None
        self.assertEqual(chosen.step, 1)
        self.assertTrue(chosen.feasible(True))
        self.assertEqual(state.best_feasible_success, chosen)

    def test_duplicate_native_step_is_counted(self) -> None:
        state = SampleState("s0", "a0")
        row = step_row(step=0)
        update_state(state, row, physical=False, final_step=2, threshold=0.8)
        update_state(state, row, physical=False, final_step=2, threshold=0.8)
        self.assertEqual(state.duplicate_steps, 1)

    def test_saturated_margin_is_not_falsely_rejected(self) -> None:
        state = SampleState("s0", "a0")
        update_state(
            state,
            step_row(probability=1.0, p_normal=0.0, margin=-50.0, threshold_success=False),
            physical=False,
            final_step=0,
            threshold=0.8,
        )
        self.assertEqual(state.margin_probability_not_reconstructable, 1)
        self.assertEqual(state.margin_probability_gate_mismatch, 0)

    def test_reconstructable_margin_contradiction_is_rejected(self) -> None:
        state = SampleState("s0", "a0")
        update_state(
            state,
            step_row(probability=0.2, p_normal=0.8, margin=5.0),
            physical=False,
            final_step=0,
            threshold=0.8,
        )
        self.assertEqual(state.margin_probability_gate_mismatch, 1)

    def test_threshold_rounding_boundary_is_reported_not_failed(self) -> None:
        threshold = 0.8
        state = SampleState("s0", "a0")
        update_state(
            state,
            step_row(
                probability=threshold + 0.5e-6,
                p_normal=1.0 - (threshold + 0.5e-6),
                threshold_success=True,
            ),
            physical=False,
            final_step=0,
            threshold=threshold,
        )
        self.assertEqual(state.threshold_flag_mismatch, 1)
        self.assertEqual(state.threshold_flag_boundary_ambiguous, 1)
        self.assertEqual(state.threshold_flag_gate_mismatch, 0)

    def test_transition_coverage_includes_explicit_missing_candidate(self) -> None:
        from collections import Counter

        counts = Counter({"tp_to_fn": 2, "unchanged_tp": 3, "missing": 1})
        self.assertTrue(transition_support_complete(counts, attacked=6))
        self.assertFalse(transition_support_complete(counts, attacked=7))


class MemberReaderTests(unittest.TestCase):
    def test_header_and_headerless_members(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first.gz"
            second = root / "second.gz"
            aggregate = root / "aggregate.gz"
            with gzip.open(first, "wt", encoding="utf-8", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=STEP_FIELDS, lineterminator="\n")
                writer.writeheader()
                writer.writerow(step_row(sample_id="s0"))
            with gzip.open(second, "wt", encoding="utf-8", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=STEP_FIELDS, lineterminator="\n")
                writer.writerow(step_row(sample_id="s1"))
            aggregate.write_bytes(first.read_bytes() + second.read_bytes())
            first_end = first.stat().st_size
            rows0 = list(iter_member(aggregate, 0, first_end, STEP_FIELDS))
            rows1 = list(iter_member(aggregate, first_end, aggregate.stat().st_size, STEP_FIELDS))
            self.assertEqual([row["sample_id"] for row in rows0], ["s0"])
            self.assertEqual([row["sample_id"] for row in rows1], ["s1"])


class FreezeTests(unittest.TestCase):
    def test_posthoc_module_does_not_change_frozen_execution_fingerprint(self) -> None:
        self.assertEqual(code_fingerprint(ROOT), FROZEN)

    def test_alpha_values(self) -> None:
        self.assertEqual(alpha_value("fixed_003", 20), 0.03)
        self.assertEqual(alpha_value("eps_over_k", 20), 0.005)
        self.assertEqual(alpha_value("two_eps_over_k", 50), 0.004)
        self.assertEqual(alpha_value("eps_over_4", 50), 0.025)

    def test_frozen_selection_uses_exact_success_count_tie(self) -> None:
        rules = {
            "rules": {
                "scope": "one_rule_per_attack_family_shared_across_models_seeds_steps_and_random_initialization",
                "ordered_criteria": [
                    "exclude_nan_numeric_error_or_large_scale_projection_failure",
                    "maximize_pooled_per_sample_best_asr_across_both_models_and_all_seeds",
                    "if_tied_minimize_target_ce_then_maximize_target_margin",
                    "if_still_tied_minimize_final_best_gap_and_oscillation",
                    "lexicographic_rule_id_only_as_final_deterministic_tie_break",
                ],
            }
        }
        base = {
            "attack": "norm_pgd",
            "attacked_support": 100,
            "best_target_margin_mean": 1.0,
            "final_success_preserving_gap": 0.0,
            "target_loss_rebound_rate_mean": 0.0,
            "numeric_error_configs": 0,
            "large_scale_projection_failure_configs": 0,
        }
        rows = [
            {**base, "alpha_rule": "a", "success_preserving_successes": 80, "best_target_ce_mean": 0.2},
            {**base, "alpha_rule": "b", "success_preserving_successes": 81, "best_target_ce_mean": 0.3},
        ]
        selected = select_alpha(rows, rules)
        self.assertEqual(selected["selected"]["norm_pgd"]["alpha_rule"], "b")


if __name__ == "__main__":
    unittest.main()
