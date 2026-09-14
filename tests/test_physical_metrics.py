from __future__ import annotations

import math
import unittest
from unittest import mock

import numpy as np
import torch

import adsb.attacks as attacks_module
import adsb.training as training_module
from adsb.attacks import (
    apply_pgd_malicious_only,
    pgd,
    pgd_phys,
    pgd_phys_penalty,
    pgd_phys_hybrid,
    physical_proj,
    physical_feasibility_sample_flags,
)
from adsb.training import _metrics_at_threshold, evaluate_with_threshold


def _heading(degrees: float) -> tuple[float, float]:
    radians = math.radians(degrees)
    return math.sin(radians), math.cos(radians)


class PhysicalMetricsTest(unittest.TestCase):
    def test_apply_pgd_malicious_only_preserves_normal_samples(self) -> None:
        x = torch.arange(12, dtype=torch.float32).reshape(3, 2, 2)
        y = torch.tensor([0, 1, 0], dtype=torch.long)
        captured: dict[str, torch.Tensor] = {}

        def fake_attack(model, x_malicious, y_malicious, scale):
            captured["x"] = x_malicious.clone()
            captured["y"] = y_malicious.clone()
            return x_malicious + scale

        out = apply_pgd_malicious_only(object(), x, y, fake_attack, 10.0)

        self.assertTrue(torch.equal(out[0], x[0]))
        self.assertTrue(torch.equal(out[2], x[2]))
        self.assertTrue(torch.equal(out[1], x[1] + 10.0))
        self.assertTrue(torch.equal(captured["x"], x[1:2]))
        self.assertTrue(torch.equal(captured["y"], torch.tensor([1], dtype=torch.long)))

    def test_default_pgd_moves_malicious_sample_toward_normal_target(self) -> None:
        class NormalTargetModel(torch.nn.Module):
            def forward(self, x):
                score = x.reshape(x.shape[0], -1).sum(dim=1)
                return torch.stack([score, -score], dim=1)

        model = NormalTargetModel()
        x = torch.zeros((1, 2, 2), dtype=torch.float32)
        y = torch.tensor([1], dtype=torch.long)

        before = model(x)[0, 0] - model(x)[0, 1]
        adv = pgd(model, x, y, eps=0.2, alpha=0.05, steps=1)
        after = model(adv)[0, 0] - model(adv)[0, 1]

        self.assertGreater(after.item(), before.item())
        self.assertLessEqual(float((adv - x).abs().max()), 0.200001)

    def test_default_pgd_multistep_strengthens_target_margin_until_budget(self) -> None:
        class NormalTargetModel(torch.nn.Module):
            def forward(self, x):
                score = x.reshape(x.shape[0], -1).sum(dim=1)
                return torch.stack([score, -score], dim=1)

        model = NormalTargetModel()
        x = torch.zeros((1, 2, 2), dtype=torch.float32)
        y = torch.tensor([1], dtype=torch.long)

        before = model(x)[0, 0] - model(x)[0, 1]
        adv_one = pgd(model, x, y, eps=0.2, alpha=0.05, steps=1)
        adv_four = pgd(model, x, y, eps=0.2, alpha=0.05, steps=4)
        after_one = model(adv_one)[0, 0] - model(adv_one)[0, 1]
        after_four = model(adv_four)[0, 0] - model(adv_four)[0, 1]

        self.assertGreater(after_one.item(), before.item())
        self.assertGreater(after_four.item(), after_one.item())
        self.assertLessEqual(float((adv_four - x).abs().max()), 0.200001)
        self.assertAlmostEqual(float((adv_four - x).abs().max()), 0.2, places=5)

    def test_attack_grad_context_freezes_and_restores_dropout_state(self) -> None:
        class DropoutProbe(torch.nn.Module):
            def __init__(self) -> None:
                super().__init__()
                self.input_dropout = torch.nn.Dropout(p=0.25)
                self.lstm = torch.nn.LSTM(
                    input_size=2,
                    hidden_size=3,
                    num_layers=2,
                    dropout=0.35,
                    batch_first=True,
                )

            def forward(self, x):
                out, _ = self.lstm(self.input_dropout(x))
                score = out[:, -1, :].sum(dim=1)
                return torch.stack([score, -score], dim=1)

        model = DropoutProbe()
        model.train()
        self.assertTrue(model.training)
        self.assertTrue(model.input_dropout.training)
        self.assertAlmostEqual(float(model.lstm.dropout), 0.35)

        with attacks_module._attack_grad_context(model):
            self.assertTrue(model.training)
            self.assertFalse(model.input_dropout.training)
            self.assertAlmostEqual(float(model.lstm.dropout), 0.0)

        self.assertTrue(model.training)
        self.assertTrue(model.input_dropout.training)
        self.assertAlmostEqual(float(model.lstm.dropout), 0.35)

        model.eval()
        with attacks_module._attack_grad_context(model):
            self.assertTrue(model.training)
            self.assertFalse(model.input_dropout.training)
            self.assertAlmostEqual(float(model.lstm.dropout), 0.0)

        self.assertFalse(model.training)
        self.assertFalse(model.input_dropout.training)
        self.assertAlmostEqual(float(model.lstm.dropout), 0.35)

    def test_pgd_phys_projection_path_invokes_physical_projection(self) -> None:
        class NormalTargetModel(torch.nn.Module):
            def forward(self, x):
                score = x.reshape(x.shape[0], -1).sum(dim=1)
                return torch.stack([score, -score], dim=1)

        model = NormalTargetModel()
        x = torch.zeros((1, 2, 6), dtype=torch.float32)
        y = torch.tensor([1], dtype=torch.long)
        mean = torch.zeros(6, dtype=torch.float32)
        std = torch.ones(6, dtype=torch.float32)

        def passthrough_projection(raw, **_kwargs):
            return raw

        with mock.patch.object(attacks_module, "physical_proj", side_effect=passthrough_projection) as projected:
            pgd_phys(model, x, y, mean, std, eps=0.2, alpha=0.05, steps=1, project_physical=True)
        self.assertGreaterEqual(projected.call_count, 1)

        with mock.patch.object(attacks_module, "physical_proj", side_effect=passthrough_projection) as projected:
            pgd_phys(model, x, y, mean, std, eps=0.2, alpha=0.05, steps=1, project_physical=False)
        self.assertEqual(projected.call_count, 0)

    def test_pgd_phys_penalty_returns_diagnostics_and_respects_linf_budget(self) -> None:
        class NormalTargetModel(torch.nn.Module):
            def forward(self, x):
                score = x.reshape(x.shape[0], -1).sum(dim=1)
                return torch.stack([score, -score], dim=1)

        model = NormalTargetModel()
        x = torch.zeros((1, 2, 6), dtype=torch.float32)
        y = torch.tensor([1], dtype=torch.long)
        mean = torch.zeros(6, dtype=torch.float32)
        std = torch.ones(6, dtype=torch.float32)

        adv, diagnostics = pgd_phys_penalty(
            model,
            x,
            y,
            mean,
            std,
            eps=0.2,
            alpha=0.05,
            steps=2,
            lambda_phys_max=0.0,
            return_diagnostics=True,
        )

        self.assertEqual(tuple(adv.shape), tuple(x.shape))
        self.assertLessEqual(float((adv - x).abs().max()), 0.200001)
        expected_keys = {
            "mean_loss_target",
            "mean_loss_phys",
            "mean_lambda_phys",
            "speed_penalty",
            "altitude_penalty",
            "latlon_penalty",
            "heading_penalty",
        }
        self.assertEqual(set(diagnostics), expected_keys)
        for value in diagnostics.values():
            self.assertTrue(math.isfinite(float(value)))
            self.assertGreaterEqual(float(value), 0.0)

    def test_pgd_phys_penalty_keeps_targeted_normal_direction_without_physical_weight(self) -> None:
        class NormalTargetModel(torch.nn.Module):
            def forward(self, x):
                score = x.reshape(x.shape[0], -1).sum(dim=1)
                return torch.stack([score, -score], dim=1)

        model = NormalTargetModel()
        x = torch.zeros((1, 2, 6), dtype=torch.float32)
        y = torch.tensor([1], dtype=torch.long)
        mean = torch.zeros(6, dtype=torch.float32)
        std = torch.ones(6, dtype=torch.float32)

        before = model(x)[0, 0] - model(x)[0, 1]
        adv = pgd_phys_penalty(
            model,
            x,
            y,
            mean,
            std,
            eps=0.2,
            alpha=0.05,
            steps=1,
            lambda_phys_max=0.0,
        )
        after = model(adv)[0, 0] - model(adv)[0, 1]

        self.assertGreater(after.item(), before.item())
        self.assertLessEqual(float((adv - x).abs().max()), 0.200001)

    def test_asr_counts_targeted_anomalous_to_normal_evasion(self) -> None:
        y_true = np.array([1, 1, 0, 0], dtype=np.int64)
        prob_malicious = np.array([0.10, 0.80, 0.70, 0.20], dtype=np.float64)

        metrics = _metrics_at_threshold(y_true, prob_malicious, threshold=0.5)

        self.assertAlmostEqual(metrics["asr"], 0.5)
        self.assertAlmostEqual(metrics["far"], 0.5)
        self.assertAlmostEqual(metrics["accuracy"], 0.5)

    def test_pv_asr_is_exact_per_sample_not_product_approximation(self) -> None:
        sample_details = {
            "physical_any_violation": np.array([False, True, False, True], dtype=bool),
            "pre_attack_physical_any_violation": np.array([False, False, True, True], dtype=bool),
            "physical_position_violation": np.array([False, True, False, False], dtype=bool),
            "physical_altitude_violation": np.array([False, False, False, True], dtype=bool),
            "physical_speed_violation": np.array([False, False, False, False], dtype=bool),
            "physical_heading_violation": np.array([False, False, False, False], dtype=bool),
            "prob_malicious": np.array([0.40, 0.30, 0.70, 0.20], dtype=np.float64),
        }
        collect_return = (
            np.array([1, 1, 1, 1, 0], dtype=np.int64),
            np.array([0.40, 0.30, 0.70, 0.20, 0.80], dtype=np.float64),
            {},
            sample_details,
        )

        with mock.patch.object(training_module, "_collect_malicious_probs", return_value=collect_return):
            metrics = evaluate_with_threshold(object(), [], torch.device("cpu"), threshold=0.5)

        self.assertAlmostEqual(metrics["asr"], 0.75)
        self.assertAlmostEqual(metrics["pvr"], 0.5)
        self.assertAlmostEqual(metrics["pre_attack_pvr"], 0.5)
        self.assertAlmostEqual(metrics["start_valid_rate"], 0.5)
        self.assertEqual(metrics["start_valid_count"], 2)
        self.assertEqual(metrics["physical_malicious_count"], 4)
        self.assertAlmostEqual(metrics["conditional_asr_start_valid"], 1.0)
        self.assertAlmostEqual(metrics["conditional_pv_asr_start_valid"], 0.5)
        self.assertAlmostEqual(metrics["introduced_pvr_start_valid"], 0.5)
        self.assertAlmostEqual(metrics["pv_asr"], 0.25)
        self.assertNotAlmostEqual(metrics["pv_asr"], metrics["asr"] * (1.0 - metrics["pvr"]))
        self.assertEqual(metrics["physical_scope"], "paired pre/post attacked anomalous samples")
        self.assertEqual(metrics["pv_asr_method"], "exact_per_sample")
        self.assertEqual(metrics["conditional_physical_method"], "conditioned_on_pre_attack_validity")

    def test_conditional_physical_metrics_are_nan_without_valid_starts(self) -> None:
        sample_details = {
            "physical_any_violation": np.array([True, True], dtype=bool),
            "pre_attack_physical_any_violation": np.array([True, True], dtype=bool),
            "physical_position_violation": np.array([True, False], dtype=bool),
            "physical_altitude_violation": np.array([False, True], dtype=bool),
            "physical_speed_violation": np.array([False, False], dtype=bool),
            "physical_heading_violation": np.array([False, False], dtype=bool),
            "prob_malicious": np.array([0.10, 0.20], dtype=np.float64),
        }
        collect_return = (
            np.array([1, 1], dtype=np.int64),
            np.array([0.10, 0.20], dtype=np.float64),
            {},
            sample_details,
        )

        with mock.patch.object(training_module, "_collect_malicious_probs", return_value=collect_return):
            metrics = evaluate_with_threshold(object(), [], torch.device("cpu"), threshold=0.5)

        self.assertEqual(metrics["start_valid_count"], 0)
        self.assertEqual(metrics["start_valid_rate"], 0.0)
        self.assertTrue(math.isnan(metrics["conditional_asr_start_valid"]))
        self.assertTrue(math.isnan(metrics["conditional_pv_asr_start_valid"]))
        self.assertTrue(math.isnan(metrics["introduced_pvr_start_valid"]))

    def test_physical_feasibility_flags_are_trajectory_level(self) -> None:
        h0 = _heading(0.0)
        h3 = _heading(3.0)
        h10 = _heading(10.0)
        raw = torch.tensor(
            [
                [[0.00, 0.00, 1000.0, 250.0, h0[0], h0[1]], [0.01, 0.01, 1100.0, 260.0, h3[0], h3[1]]],
                [[0.00, 0.00, 1000.0, 250.0, h0[0], h0[1]], [0.10, 0.01, 1100.0, 260.0, h3[0], h3[1]]],
                [[0.00, 0.00, 1000.0, 250.0, h0[0], h0[1]], [0.01, 0.01, 2501.0, 260.0, h3[0], h3[1]]],
                [[0.00, 0.00, 1000.0, 250.0, h0[0], h0[1]], [0.01, 0.01, 1100.0, 290.1, h3[0], h3[1]]],
                [[0.00, 0.00, 1000.0, 250.0, h0[0], h0[1]], [0.01, 0.01, 1100.0, 260.0, h10[0], h10[1]]],
            ],
            dtype=torch.float32,
        )

        flags = physical_feasibility_sample_flags(raw)

        self.assertEqual(flags["physical_any_violation"].tolist(), [False, True, True, True, True])
        self.assertEqual(flags["physical_position_violation"].tolist(), [False, True, False, False, False])
        self.assertEqual(flags["physical_altitude_violation"].tolist(), [False, False, True, False, False])
        self.assertEqual(flags["physical_speed_violation"].tolist(), [False, False, False, True, False])
        self.assertEqual(flags["physical_heading_violation"].tolist(), [False, False, False, False, True])

    def test_hard_physical_projection_eliminates_all_trajectory_violations(self) -> None:
        h0 = _heading(0.0)
        h90 = _heading(90.0)
        raw_prev = torch.tensor([[10.0, 20.0, 1000.0, 200.0, h0[0], h0[1]]], dtype=torch.float32)
        raw = torch.tensor(
            [
                [
                    [10.20, 20.20, 3000.0, 260.0, h90[0], h90[1]],
                    [10.40, 20.40, 5000.0, 320.0, h0[0], h0[1]],
                ]
            ],
            dtype=torch.float32,
        )

        projected = physical_proj(raw, raw_prev=raw_prev, soft_limit=False, use_direction=False)
        flags = physical_feasibility_sample_flags(projected, raw_prev=raw_prev)

        self.assertEqual(flags["physical_any_violation"].tolist(), [False])
        self.assertFalse(torch.equal(projected, raw))

    def test_physical_attack_outputs_satisfy_the_audited_constraints(self) -> None:
        class NormalTargetModel(torch.nn.Module):
            def forward(self, x):
                score = x.reshape(x.shape[0], -1).sum(dim=1)
                return torch.stack([score, -score], dim=1)

        h0 = _heading(0.0)
        x = torch.tensor(
            [
                [
                    [10.00, 20.00, 1000.0, 200.0, h0[0], h0[1]],
                    [10.01, 20.01, 1100.0, 205.0, h0[0], h0[1]],
                    [10.02, 20.02, 1200.0, 210.0, h0[0], h0[1]],
                ]
            ],
            dtype=torch.float32,
        )
        y = torch.ones(1, dtype=torch.long)
        mean = torch.zeros(6, dtype=torch.float32)
        std = torch.ones(6, dtype=torch.float32)
        model = NormalTargetModel()

        projection_adv = pgd_phys(
            model, x, y, mean, std, eps=2.0, alpha=1.0, steps=2, project_physical=True
        )
        penalty_adv = pgd_phys_hybrid(
            model,
            x,
            y,
            mean,
            std,
            eps=2.0,
            alpha=1.0,
            steps=2,
            lambda_phys_max=1.0,
            final_projection=True,
        )

        for attacked in (projection_adv, penalty_adv):
            flags = physical_feasibility_sample_flags(attacked)
            self.assertEqual(flags["physical_any_violation"].tolist(), [False])


if __name__ == "__main__":
    unittest.main()
