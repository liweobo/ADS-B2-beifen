from __future__ import annotations

import unittest
from unittest import mock

import numpy as np
import torch

from adsb.attack_audit import (
    AttackConfig,
    attack_malicious_only,
    run_attack,
    strict_intersection_project,
    targeted_losses,
)
from adsb.model import LSTMDetector


class _ToyDetector(torch.nn.Module):
    def __init__(self):
        super().__init__()
        self.scale = torch.nn.Parameter(torch.tensor(1.0))

    def forward(self, x):
        score = x[..., 0].mean(dim=1) * self.scale
        return torch.stack([-score, score], dim=1)


def _clean(batch=3, time=4):
    x = torch.zeros(batch, time, 12)
    x[..., 0] = 0.05
    x[..., 2] = 1000.0
    x[..., 3] = 100.0
    x[..., 5] = 1.0
    # First difference is zero because raw_prev is reconstructed as raw-diff.
    return x


def _config(**overrides):
    values = dict(
        attack_id="norm_pgd",
        loss="targeted_ce",
        steps=3,
        alpha=0.03,
        epsilon=0.1,
        initialization="uniform_budget",
        restarts=1,
        seed=91,
    )
    values.update(overrides)
    return AttackConfig(**values)


class AttackAuditTests(unittest.TestCase):
    def setUp(self):
        self.model = _ToyDetector()
        self.mean = np.zeros((1, 1, 12), dtype=np.float32)
        self.std = np.ones((1, 1, 12), dtype=np.float32)
        self.x = _clean()
        self.y = torch.ones(len(self.x), dtype=torch.long)

    def _run(self, config):
        return run_attack(
            self.model,
            self.x,
            self.y,
            norm_mean=self.mean,
            norm_std=self.std,
            frozen_threshold=0.4,
            config=config,
        )

    def test_best_iterate_not_weaker_than_final_and_logs_both_success_definitions(self):
        result = self._run(_config())
        final_loss = targeted_losses(self.model(result.final_iterate), "targeted_ce")["objective"]
        self.assertTrue(torch.all(result.best_target_loss <= final_loss + 1e-7))
        self.assertIn("threshold_success", result.per_step_diagnostics[0])
        self.assertIn("argmax_success", result.per_step_diagnostics[0])
        self.assertIn("linf_raw6_normalized", result.per_step_diagnostics[0])
        self.assertIn("projection_reason", result.per_step_diagnostics[0])

    def test_r5_contains_r1_and_cannot_be_weaker(self):
        r1 = self._run(_config(restarts=1))
        r5 = self._run(_config(restarts=5))
        self.assertEqual(_config(restarts=1).restart_seed(0), _config(restarts=5).restart_seed(0))
        self.assertTrue(torch.all(r5.best_target_loss <= r1.best_target_loss + 1e-7))
        r1_final = targeted_losses(self.model(r1.final_iterate), "targeted_ce")["objective"]
        r5_final = targeted_losses(self.model(r5.final_iterate), "targeted_ce")["objective"]
        self.assertTrue(torch.all(r5_final <= r1_final + 1e-7))
        self.assertTrue(torch.all(r5.final_restart_id >= 0))

    def test_p2_native_diagnostics_include_projection_margin_and_boundary_fields(self):
        result = self._run(_config(restarts=2))
        diagnostics = result.per_step_diagnostics
        self.assertEqual(
            [(row["restart_id"], row["step"]) for row in diagnostics],
            [(restart, step) for restart in range(2) for step in range(4)],
        )
        required = {
            "pre_projection_target_ce",
            "post_projection_target_ce",
            "pre_projection_margin",
            "post_projection_margin",
            "raw_boundary_saturation_rate",
            "raw_latitude_saturated",
            "initialization_status",
            "source_valid",
            "post_valid",
            "feasible_success",
        }
        self.assertTrue(required.issubset(diagnostics[0]))

    def test_penalty_only_never_calls_hard_projector_and_hybrid_id_is_distinct(self):
        penalty = _config(attack_id="phys_penalty_pgd", projection_schedule="none")
        with mock.patch("adsb.attack_audit.strict_intersection_project", side_effect=AssertionError("hard projector called")):
            result = self._run(penalty)
        self.assertIsNotNone(result.best_target_loss_iterate)
        hybrid = _config(
            attack_id="phys_hybrid_pgd",
            projection_schedule="final_only",
            projection_tolerance=1e-5,
            maximum_alternating_projection_iterations=8,
        )
        self.assertNotEqual(penalty.config_hash, hybrid.config_hash)

    def test_normal_samples_are_bitwise_unchanged(self):
        labels = torch.tensor([0, 1, 0])
        output, _ = attack_malicious_only(
            self.model,
            self.x,
            labels,
            norm_mean=self.mean,
            norm_std=self.std,
            frozen_threshold=0.4,
            config=_config(),
        )
        self.assertTrue(torch.equal(output[labels == 0], self.x[labels == 0]))

    def test_strict_projection_success_and_explicit_failure(self):
        ctx_clean = self.x[..., :6]
        raw_prev = ctx_clean[:, 0].clone()
        candidate = ctx_clean.clone()
        candidate[..., 3] += 50.0
        success = strict_intersection_project(
            candidate,
            ctx_clean,
            epsilon=100.0,
            mean_raw=torch.zeros(1, 1, 6),
            std_raw=torch.ones(1, 1, 6),
            raw_prev=raw_prev,
            tolerance=1e-5,
            maximum_iterations=8,
        )
        self.assertTrue(all(status.success and status.independently_checked for status in success.statuses))
        invalid = ctx_clean.clone()
        invalid[:, 1:, 2] += 5000.0
        failure = strict_intersection_project(
            invalid,
            invalid,
            epsilon=0.0,
            mean_raw=torch.zeros(1, 1, 6),
            std_raw=torch.ones(1, 1, 6),
            raw_prev=raw_prev,
            tolerance=0.0,
            maximum_iterations=2,
        )
        self.assertTrue(all(not status.success for status in failure.statuses))
        self.assertTrue(all("source_invalid" in status.reason for status in failure.statuses))
        self.assertTrue(all("infeasible_fixed_point" in status.reason for status in failure.statuses))
        self.assertTrue(all(status.iterations < 2 for status in failure.statuses))

    def test_strict_projection_tracks_mixed_batch_convergence_per_sample(self):
        clean = _clean(batch=2, time=4)[..., :6]
        raw_prev = clean[:, 0].clone()
        candidate = clean.clone()
        candidate[1, ..., 3] += 50.0
        result = strict_intersection_project(
            candidate,
            clean,
            epsilon=100.0,
            mean_raw=torch.zeros(1, 1, 6),
            std_raw=torch.ones(1, 1, 6),
            raw_prev=raw_prev,
            tolerance=1e-5,
            maximum_iterations=8,
        )
        self.assertTrue(all(status.success for status in result.statuses))
        self.assertEqual(result.statuses[0].iterations, 1)
        self.assertGreater(result.statuses[1].iterations, result.statuses[0].iterations)

    def test_unresolved_author_projection_parameters_refuse_execution(self):
        with self.assertRaisesRegex(ValueError, "AUTHOR VERIFY"):
            self._run(_config(attack_id="phys_projection_pgd", projection_schedule="strict_every_step"))

    def test_threshold_and_argmax_are_distinct_and_cw_ranks_untruncated(self):
        logits = torch.tensor([[0.0, 0.2], [2.0, -2.0]])
        values = targeted_losses(logits, "targeted_cw_margin", kappa=0.0)
        self.assertEqual(values["objective"][1].item(), 0.0)
        self.assertLess(values["ranking_margin"][1].item(), 0.0)
        p_anomaly = torch.softmax(logits, 1)[:, 1]
        self.assertTrue(bool((p_anomaly[0] < 0.6) and (logits[0].argmax() == 1)))

    @unittest.skipUnless(torch.cuda.is_available(), "CUDA/cuDNN regression test")
    def test_cuda_lstm_attack_uses_dropout_free_training_mode_for_backward(self):
        device = torch.device("cuda")
        model = LSTMDetector(input_dim=12, hidden_dim=4, num_layers=1, dropout=0.0, bidirectional=False).to(device)
        model.eval()
        x = _clean(batch=2, time=3).to(device)
        y = torch.ones(2, dtype=torch.long, device=device)
        result = run_attack(
            model,
            x,
            y,
            norm_mean=self.mean,
            norm_std=self.std,
            frozen_threshold=0.5,
            config=_config(steps=1, initialization="clean"),
        )
        self.assertIsNotNone(result.best_target_loss_iterate)
        self.assertFalse(model.training)


if __name__ == "__main__":
    unittest.main()
